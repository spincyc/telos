"""Bounded, passive Controller-side Samba authentication diagnostic.

This diagnostic is supplemental context only.  It has no nonce-bearing Samba
event and therefore can neither authorize nor veto GUI identity acceptance.
The Controller parses the root-private audit sink; only closed, secret-free
coordinates cross the shared serial console.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import datetime, timezone
from enum import Enum
import argparse
import base64
import ipaddress
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import tempfile
import time
from typing import Mapping
import uuid

try:
    from .signal_cleanup import RunInterrupted
except ImportError:
    # The Controller executes this file standalone from /opt/telos-factory,
    # where no package exists. Host-side run interruption can never fire
    # there, so a local stand-in keeps _INTERRUPTIONS coherent. The
    # relative import crashing standalone execution (exit 1 before ARMED)
    # is what produced receipt-unavailable on eleven consecutive attempts.
    class RunInterrupted(BaseException):  # type: ignore[no-redef]
        """Stand-in for standalone Controller-side execution."""


MAX_AUDIT_BYTES = 256 * 1024
MAX_AUDIT_RECORDS = 256
AUDIT_QUIET_SECONDS = 0.5
AUDIT_DIRECTORY = "/run/telos-factory-auth-audit"
AUDIT_PATH = AUDIT_DIRECTORY + "/auth.jsonl"
SMB_CONFIG_PATH = "/etc/samba/smb.conf"
AUTH_JSON_COMPONENT = "auth_json_audit"
AUTH_JSON_LEVEL = 3
AUTH_JSON_ROUTE = f"{AUTH_JSON_COMPONENT}:{AUTH_JSON_LEVEL}@{AUDIT_PATH}"
AUTH_JSON_CONFIG_LINE = f"\tlog level = 0 {AUTH_JSON_ROUTE}"
MAX_OBSERVATION_SECONDS = 30
MIN_OBSERVATION_SECONDS = 1
# The guest owns the complete observation window.  Reserve a separate bounded
# interval for its terminal receipt to cross the serial transport after that
# window closes; otherwise a result produced exactly at the guest deadline
# races an equal host deadline.
RESULT_RECEIPT_SECONDS = 2
# Cleanup's explicitly bounded operations can spend three sequential
# five-second subprocess timeouts (_remove_persistent_route, disable, and
# verification), then five seconds checking descriptor release.  This is a
# protocol reserve, not a hard wall-clock worst case: filesystem operations
# and process timeout teardown do not expose strict latency bounds.
CLEANUP_BOUNDED_OPERATIONS_SECONDS = 20
CLEANUP_RECEIPT_SECONDS = 1
CLEANUP_RESERVE_SECONDS = (
    CLEANUP_BOUNDED_OPERATIONS_SECONDS + CLEANUP_RECEIPT_SECONDS)

_ACCOUNT = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}")
_DOMAIN = re.compile(r"[A-Z0-9][A-Z0-9-]{0,14}")
_SID = re.compile(r"S-1-5-21-(?:[0-9]{1,10}-){2}[0-9]{1,10}-[0-9]{1,10}")
_RECEIPT_LINE_START = rb"(?:^|[\r\n])"
_RECEIPT_LINE_END = rb"[^\S\r\n]*(?:\r\n|[\r\n]|$)"


def _live_auth_json_level(output: str, expected: int) -> bool:
    occurrences = re.findall(
        rf"(?<![A-Za-z0-9_]){re.escape(AUTH_JSON_COMPONENT)}:",
        output,
    )
    levels = re.findall(
        rf"(?<![A-Za-z0-9_]){re.escape(AUTH_JSON_COMPONENT)}:"
        r"[ \t]*([^\s,;()\[\]{}]+)",
        output,
    )
    return (
        bool(occurrences)
        and len(levels) == len(occurrences)
        and all(level == str(expected) for level in levels)
    )


class ControllerAuthCode(Enum):
    """Complete non-authoritative Samba outcome vocabulary."""

    AUTHENTICATED = "authenticated"
    REJECTED = "rejected"
    NO_EVENT = "no-event"
    UNCORRELATED = "uncorrelated"
    AMBIGUOUS = "ambiguous"


class ControllerAuthCollection(Enum):
    """Closed audit collection failures."""

    CONFIGURATION_INVALID = "configuration-invalid"
    SINK_INVALID = "sink-invalid"
    ROTATED = "rotated"
    TRUNCATED = "truncated"
    OVERSIZED = "oversized"
    MALFORMED = "malformed"
    CANCELLED = "cancelled"
    RECEIPT_UNAVAILABLE = "receipt-unavailable"


class ControllerAuthReceiptOrigin(Enum):
    """Closed, host-side origin of an unavailable result receipt.

    `receipt-unavailable` is both a value the Controller may report and the
    value the host records when its own bounded wait expires. Those are
    different failures with different next actions, so the host labels which
    one it observed. There is deliberately no wire vocabulary for this: the
    Controller supplies the collection value, never the label.
    """

    HOST_WAIT_EXPIRED = "host-wait-expired"
    CONTROLLER_REPORTED = "controller-reported"
    # The armed window lapsed before the submission fence was ever sent, so
    # the Controller was never asked. This is a host-side scheduling failure
    # distinct from a wait that began and expired: the fix is arming later or
    # budgeting the window for the real GUI phase, not extending a wait.
    ARM_WINDOW_EXPIRED = "arm-window-expired"
    # No producing site declared an origin. This is applied automatically so
    # the gap is visible in the rendered failure instead of silent: an
    # unavailable receipt always says where it came from, even when the answer
    # is "nowhere in particular".
    UNATTRIBUTED = "unattributed"


class ControllerAuthCleanup(Enum):
    """Closed sink destruction failures."""

    CONFIGURATION_UNPROVED = "configuration-unproved"
    LIVE_ROUTE_UNPROVED = "live-route-unproved"
    SINK_ABSENCE_UNPROVED = "sink-absence-unproved"


class ControllerAuthArmSubphase(Enum):
    """Closed, secret-free arm failure location."""

    PREFLIGHT = "preflight"
    COMMAND_DISPATCH = "command-dispatch"
    SUDO_PROMPT = "sudo-prompt"
    SUDO_CREDENTIAL_HANDOFF = "sudo-credential-handoff"
    # Reserved for fail-closed normalization of untrusted/generic adapter
    # failures.  The diagnostic session emits the finer launch coordinates.
    LAUNCH = "launch"
    RECEIVE = "receive"
    PARSE = "parse"


class ControllerAuthReceiveObservation(Enum):
    """Closed, secret-free evidence observed while awaiting the arm receipt."""

    SUDO_REJECTED_OR_REPROMPTED = "sudo-rejected-or-reprompted"
    COMMAND_LAUNCH_ERROR = "command-launch-error"
    COMMAND_EXIT_ZERO = "command-exit-zero"
    COMMAND_EXIT_NONZERO = "command-exit-nonzero"
    SERIAL_CLOSED = "serial-closed"
    TOKEN_NONSTANDALONE = "token-nonstandalone"
    TIMEOUT = "timeout"
    TIMEOUT_AFTER_PAYLOAD_VALID = "timeout-after-payload-valid"
    TIMEOUT_AFTER_CONFIGURATION_VALID = "timeout-after-configuration-valid"
    TIMEOUT_AFTER_SINK_READY = "timeout-after-sink-ready"
    TIMEOUT_AFTER_SID_READY = "timeout-after-sid-ready"
    UNCLASSIFIED = "unclassified"


class ControllerAuthDiagnosticError(RuntimeError):
    """Host protocol failure with explicit Controller cleanup status."""

    def __init__(
        self, *,
        controller_auth_result: "ControllerAuthResult | None" = None,
        cleanup_proved: bool,
        arm_subphase: ControllerAuthArmSubphase | None = None,
        receive_observation: ControllerAuthReceiveObservation | None = None,
    ) -> None:
        super().__init__("Controller auth diagnostic protocol failed")
        if controller_auth_result is None:
            controller_auth_result = ControllerAuthResult(
                collection=ControllerAuthCollection.RECEIPT_UNAVAILABLE)
        if type(controller_auth_result) is not ControllerAuthResult:
            raise TypeError("Controller auth diagnostic result is invalid")
        controller_auth_result._validate()
        if type(cleanup_proved) is not bool:
            raise TypeError("Controller auth cleanup proof is invalid")
        if cleanup_proved != (controller_auth_result.cleanup is None):
            raise ValueError(
                "Controller auth cleanup proof contradicts result")
        if (
            arm_subphase is not None
            and type(arm_subphase) is not ControllerAuthArmSubphase
        ):
            raise TypeError("Controller auth arm subphase is invalid")
        if (
            arm_subphase is not None
            and controller_auth_result.collection
            is not ControllerAuthCollection.RECEIPT_UNAVAILABLE
        ):
            raise ValueError(
                "Controller auth arm subphase needs unavailable receipt")
        if (
            receive_observation is not None
            and type(receive_observation)
            is not ControllerAuthReceiveObservation
        ):
            raise TypeError(
                "Controller auth receive observation is invalid")
        if (
            receive_observation is not None
            and arm_subphase is not ControllerAuthArmSubphase.RECEIVE
        ):
            raise ValueError(
                "Controller auth receive observation needs receive subphase")
        if (
            arm_subphase is ControllerAuthArmSubphase.RECEIVE
            and receive_observation is None
        ):
            raise ValueError(
                "Controller auth receive subphase needs observation")
        self.controller_auth_result = controller_auth_result
        self.cleanup_proved = cleanup_proved
        self.arm_subphase = arm_subphase
        self.receive_observation = receive_observation


@dataclass(frozen=True)
class ControllerAuthResult:
    """Secret-free result returned by the disposable Controller."""

    code: ControllerAuthCode | None = None
    collection: ControllerAuthCollection | None = None
    cleanup: ControllerAuthCleanup | None = None
    # Host-side only. The Controller has no wire vocabulary for this, so a
    # forged or replayed frame can never claim it: a discarded host exception
    # is a fact the host observes about itself. It carries an exception type
    # name, never a message, because messages can quote paths or secrets.
    host_error: str | None = None
    receipt_origin: "ControllerAuthReceiptOrigin | None" = None

    def __post_init__(self) -> None:
        self._validate()

    def _validate(self) -> None:
        if self.code is not None and type(self.code) is not ControllerAuthCode:
            raise TypeError("Controller auth code coordinate is invalid")
        if (
            self.collection is not None
            and type(self.collection) is not ControllerAuthCollection
        ):
            raise TypeError("Controller auth collection coordinate is invalid")
        if (self.code is None) == (self.collection is None):
            raise ValueError(
                "Controller auth result needs exactly one primary coordinate")
        if self.cleanup is not None and type(
                self.cleanup) is not ControllerAuthCleanup:
            raise TypeError("Controller auth cleanup coordinate is invalid")
        if self.host_error is not None and (
            type(self.host_error) is not str
            or not self.host_error.isidentifier()
            or len(self.host_error) > 64
        ):
            raise ValueError(
                "Controller auth host error must be one bounded type name")
        if self.receipt_origin is not None:
            if type(self.receipt_origin) is not ControllerAuthReceiptOrigin:
                raise TypeError("Controller auth receipt origin is invalid")
            if (
                self.collection
                is not ControllerAuthCollection.RECEIPT_UNAVAILABLE
            ):
                raise ValueError(
                    "Controller auth receipt origin needs unavailable receipt")
        elif self.collection is ControllerAuthCollection.RECEIPT_UNAVAILABLE:
            # Every unavailable receipt carries an origin. Sites that know
            # theirs pass it; the rest are labelled rather than left silent,
            # which is what let this value mean several different failures.
            object.__setattr__(
                self, "receipt_origin",
                ControllerAuthReceiptOrigin.UNATTRIBUTED)


_CODE_BY_WIRE = {
    b"authenticated": ControllerAuthCode.AUTHENTICATED,
    b"rejected": ControllerAuthCode.REJECTED,
    b"no-event": ControllerAuthCode.NO_EVENT,
    b"uncorrelated": ControllerAuthCode.UNCORRELATED,
    b"ambiguous": ControllerAuthCode.AMBIGUOUS,
}
_COLLECTION_BY_WIRE = {
    b"configuration-invalid": ControllerAuthCollection.CONFIGURATION_INVALID,
    b"sink-invalid": ControllerAuthCollection.SINK_INVALID,
    b"rotated": ControllerAuthCollection.ROTATED,
    b"truncated": ControllerAuthCollection.TRUNCATED,
    b"oversized": ControllerAuthCollection.OVERSIZED,
    b"malformed": ControllerAuthCollection.MALFORMED,
    b"cancelled": ControllerAuthCollection.CANCELLED,
    b"receipt-unavailable": ControllerAuthCollection.RECEIPT_UNAVAILABLE,
}
_CLEANUP_BY_WIRE = {
    b"configuration-unproved": ControllerAuthCleanup.CONFIGURATION_UNPROVED,
    b"live-route-unproved": ControllerAuthCleanup.LIVE_ROUTE_UNPROVED,
    b"sink-absence-unproved":
        ControllerAuthCleanup.SINK_ABSENCE_UNPROVED,
}
if (
    set(_CODE_BY_WIRE.values()) != set(ControllerAuthCode)
    or set(_COLLECTION_BY_WIRE.values()) != set(ControllerAuthCollection)
    or set(_CLEANUP_BY_WIRE.values()) != set(ControllerAuthCleanup)
):
    raise RuntimeError("Controller auth wire vocabulary snapshot is stale")
_INTERRUPTIONS = (KeyboardInterrupt, SystemExit, RunInterrupted)


@dataclass(frozen=True)
class ControllerAuthExpectation:
    """Exact public correlation values fixed before credential retrieval."""

    account: str
    domain: str
    workstation_ip: str
    staged_sid: str | None = None

    def __post_init__(self) -> None:
        if type(self.account) is not str or _ACCOUNT.fullmatch(
                self.account) is None:
            raise ValueError("Controller auth account is invalid")
        if type(self.domain) is not str or _DOMAIN.fullmatch(
                self.domain) is None:
            raise ValueError("Controller auth domain is invalid")
        try:
            address = ipaddress.ip_address(self.workstation_ip)
        except ValueError:
            raise ValueError("Controller auth address is invalid") from None
        if address.version != 4 or not address.is_private:
            raise ValueError("Controller auth address is invalid")
        if (
            self.staged_sid is not None
            and (
                type(self.staged_sid) is not str
                or _SID.fullmatch(self.staged_sid) is None
            )
        ):
            raise ValueError("Controller auth SID is invalid")


_SERVICES = frozenset({
    "authentication", "kdc", "kerberos", "ldap", "sam", "winbind",
})
_AUTH_METHODS = frozenset({
    "enc-ts pre-authentication", "kerberos", "ntlm", "ntlmssp",
    "sam", "simple bind", "simple bind/tls", "winbind",
})


def classify_auth_events(
    events: tuple[Mapping[str, object], ...],
    expectation: ControllerAuthExpectation,
) -> ControllerAuthCode:
    """Classify already Controller-parsed JSON without returning event data.

    Samba versions use slightly different field names.  Every accepted alias
    remains exact and allowlisted; unknown services, authentication methods,
    or incomplete records are ignored rather than broadened heuristically.
    """
    matches: list[bool] = []
    for event in events:
        if type(event) is not dict:
            raise ValueError("Controller auth event is not an object")
        event_type = event.get("type")
        if event_type != "Authentication":
            continue
        body = event.get(event_type)
        if type(body) is not dict:
            body = event
        account = (
            body.get("clientAccount") or body.get("account")
            or body.get("username"))
        domain = (
            body.get("clientDomain") or body.get("domain")
            or body.get("workgroup"))
        remote = body.get("remoteAddress") or body.get("clientAddress")
        service = body.get("serviceDescription") or body.get("service")
        method = body.get("authDescription") or body.get("authMethod")
        status = body.get("status")
        sid = (
            body.get("becameSid") or body.get("sid")
            or body.get("accountSid"))
        if (
            type(account) is not str
            or type(domain) is not str
            or type(remote) is not str
            or type(service) is not str
            or type(method) is not str
            or type(status) is not str
        ):
            continue
        try:
            if remote.startswith("ipv4:"):
                remote_ip = remote.removeprefix("ipv4:").rsplit(":", 1)[0]
            elif remote.startswith("[") and "]" in remote:
                remote_ip = remote[1:remote.index("]")]
            else:
                remote_ip = remote
            remote_ip = str(ipaddress.ip_address(remote_ip))
        except ValueError:
            continue
        if (
            account.casefold() != expectation.account.casefold()
            or domain.upper() != expectation.domain
            or remote_ip != expectation.workstation_ip
            or service.casefold() not in _SERVICES
            or method.casefold() not in _AUTH_METHODS
        ):
            continue
        accepted = status in {"NT_STATUS_OK", "0x00000000"}
        if accepted and expectation.staged_sid is not None:
            if sid != expectation.staged_sid:
                continue
        matches.append(accepted)
    if not events:
        return ControllerAuthCode.NO_EVENT
    if not matches:
        return ControllerAuthCode.UNCORRELATED
    if len(matches) != 1:
        return ControllerAuthCode.AMBIGUOUS
    return (
        ControllerAuthCode.AUTHENTICATED
        if matches[0]
        else ControllerAuthCode.REJECTED
    )


def supplemental_only(
    gui_accepted: bool,
    result: ControllerAuthResult,
) -> bool:
    """Return GUI authority unchanged, making non-authority executable."""
    if type(gui_accepted) is not bool or type(result) is not ControllerAuthResult:
        raise ValueError("Controller auth authority inputs are invalid")
    return gui_accepted


def _complete_json_records(
    raw: bytes, *, deadline_reached: bool,
) -> tuple[tuple[Mapping[str, object], ...], bool]:
    """Parse complete JSONL records while retaining a concurrent tail."""
    if raw and not raw.endswith(b"\n"):
        complete, _separator, partial = raw.rpartition(b"\n")
        if deadline_reached:
            raise ValueError("partial audit record at deadline")
    else:
        complete = raw
        partial = b""
    lines = complete.splitlines()
    if len(lines) > MAX_AUDIT_RECORDS:
        raise OverflowError("audit record bound exceeded")
    parsed = tuple(
        json.loads(line.decode("utf-8"))
        for line in lines if line
    )
    if any(type(item) is not dict for item in parsed):
        raise ValueError("audit record is not an object")
    return parsed, bool(partial)


def _observation_complete(
    code: ControllerAuthCode,
    *,
    partial: bool,
    now: float,
    last_size_change: float,
    deadline: float,
) -> bool:
    """Require a stable complete tail before finalizing any correlation."""
    if partial:
        return False
    return (
        now >= deadline
        or (
            code not in {
                ControllerAuthCode.NO_EVENT,
                ControllerAuthCode.UNCORRELATED,
            }
            and now - last_size_change >= AUDIT_QUIET_SECONDS
        )
    )


def _safe_sink() -> tuple[int, os.stat_result]:
    directory = Path(AUDIT_DIRECTORY)
    path = Path(AUDIT_PATH)
    directory_info = directory.lstat()
    if (
        stat.S_ISLNK(directory_info.st_mode)
        or not stat.S_ISDIR(directory_info.st_mode)
        or directory_info.st_uid != 0
        or directory_info.st_gid != 0
        or stat.S_IMODE(directory_info.st_mode) != 0o700
    ):
        raise RuntimeError("sink-invalid")
    path_info = path.lstat()
    descriptor = os.open(
        path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        opened = os.fstat(descriptor)
        if (
            stat.S_ISLNK(path_info.st_mode)
            or not stat.S_ISREG(opened.st_mode)
            or opened.st_uid != 0
            or opened.st_gid != 0
            or stat.S_IMODE(opened.st_mode) != 0o600
            or opened.st_nlink != 1
            or (opened.st_dev, opened.st_ino)
            != (path_info.st_dev, path_info.st_ino)
        ):
            raise RuntimeError("sink-invalid")
        return descriptor, opened
    except BaseException:
        os.close(descriptor)
        raise


def _effective_configuration() -> bool:
    try:
        config_lines = Path(SMB_CONFIG_PATH).read_text(
            encoding="utf-8",
        ).splitlines()
    except (OSError, UnicodeError, subprocess.SubprocessError):
        return False
    active_routes = [
        line for line in config_lines
        if AUTH_JSON_COMPONENT in line
        and not line.lstrip().startswith(("#", ";"))
    ]
    if active_routes != [AUTH_JSON_CONFIG_LINE]:
        return False

    try:
        syntax = subprocess.run(
            ["testparm", "-s", SMB_CONFIG_PATH],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
            timeout=5,
        )
    except (OSError, subprocess.SubprocessError):
        return False
    if syntax.returncode != 0:
        return False

    # `smbcontrol all` broadcasts to every registered process and hangs on
    # this converged AD controller waiting for one that never answers; the
    # uncaught TimeoutExpired killed the watcher after PAYLOAD_VALID on
    # every attempt. A probe that cannot answer is a failed check, never a
    # crash, and the file-server destination answers when the broadcast
    # does not.
    for destination in ("all", "smbd"):
        try:
            live = subprocess.run(
                ["smbcontrol", destination, "debuglevel"],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                check=False,
                text=True,
                timeout=5,
            )
        except (OSError, subprocess.SubprocessError):
            continue
        if live.returncode == 0 and _live_auth_json_level(
                live.stdout, AUTH_JSON_LEVEL):
            return True
    return False


def _staged_sid(account: str) -> str:
    try:
        result = subprocess.run(
            ["samba-tool", "user", "show", account,
             "--attributes=objectSid"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            check=False,
            text=True,
            timeout=5,
        )
    except (OSError, subprocess.SubprocessError):
        raise RuntimeError("sink-invalid") from None
    values = [
        line.partition(":")[2].strip()
        for line in result.stdout.splitlines()
        if line.startswith("objectSid:")
    ]
    if (
        result.returncode != 0
        or len(values) != 1
        or _SID.fullmatch(values[0]) is None
    ):
        raise RuntimeError("sink-invalid")
    return values[0]


def _remove_persistent_route() -> bool:
    path = Path(SMB_CONFIG_PATH)
    temporary_name: str | None = None
    try:
        info = path.lstat()
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
            return False
        original = path.read_bytes()
        lines = original.decode("utf-8").splitlines(keepends=True)
        active = [
            line.rstrip("\r\n") for line in lines
            if AUTH_JSON_COMPONENT in line
            and not line.lstrip().startswith(("#", ";"))
        ]
        if active != [AUTH_JSON_CONFIG_LINE]:
            return False
        retained = [
            line for line in lines
            if line.rstrip("\r\n") != AUTH_JSON_CONFIG_LINE
        ]
        descriptor, temporary_name = tempfile.mkstemp(
            prefix=".telos-smb-conf-", dir=path.parent)
        try:
            os.fchmod(descriptor, stat.S_IMODE(info.st_mode))
            os.fchown(descriptor, info.st_uid, info.st_gid)
            with os.fdopen(descriptor, "w", encoding="utf-8") as output:
                output.writelines(retained)
                output.flush()
                os.fsync(output.fileno())
            syntax = subprocess.run(
                ["testparm", "-s", temporary_name],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=False,
                timeout=5,
            )
            if syntax.returncode != 0:
                return False
            current = path.lstat()
            if (
                (current.st_dev, current.st_ino)
                != (info.st_dev, info.st_ino)
                or path.read_bytes() != original
            ):
                return False
            os.replace(temporary_name, path)
            temporary_name = None
            directory = os.open(
                path.parent, os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
        except BaseException:
            try:
                os.close(descriptor)
            except OSError:
                pass
            raise
        return not any(
            AUTH_JSON_COMPONENT in line
            and not line.lstrip().startswith(("#", ";"))
            for line in path.read_text(encoding="utf-8").splitlines()
        )
    except (OSError, UnicodeError, subprocess.SubprocessError):
        return False
    finally:
        if temporary_name is not None:
            try:
                os.unlink(temporary_name)
            except OSError:
                pass


def _disable_and_destroy_sink(
    descriptor: int | None, identity: tuple[int, int] | None,
) -> ControllerAuthCleanup | None:
    persistent_removed = _remove_persistent_route()
    try:
        disabled = subprocess.run(
            ["smbcontrol", "all", "debug", "0 auth_json_audit:0"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
            timeout=5,
        ).returncode == 0
    except (OSError, subprocess.SubprocessError):
        disabled = False
    if not disabled:
        if descriptor is not None:
            os.close(descriptor)
        return ControllerAuthCleanup.LIVE_ROUTE_UNPROVED
    try:
        verified = subprocess.run(
            ["smbcontrol", "all", "debuglevel"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            check=False,
            text=True,
            timeout=5,
        )
    except (OSError, subprocess.SubprocessError):
        if descriptor is not None:
            os.close(descriptor)
        return ControllerAuthCleanup.LIVE_ROUTE_UNPROVED
    if (
        verified.returncode != 0
        or not _live_auth_json_level(verified.stdout, 0)
    ):
        if descriptor is not None:
            os.close(descriptor)
        return ControllerAuthCleanup.LIVE_ROUTE_UNPROVED
    if descriptor is None or identity is None:
        return (
            ControllerAuthCleanup.CONFIGURATION_UNPROVED
            if not persistent_removed
            else ControllerAuthCleanup.SINK_ABSENCE_UNPROVED
        )
    opened = os.fstat(descriptor)
    if (
        (opened.st_dev, opened.st_ino) != identity
        or not stat.S_ISREG(opened.st_mode)
        or opened.st_nlink != 1
    ):
        os.close(descriptor)
        return ControllerAuthCleanup.SINK_ABSENCE_UNPROVED
    deadline = time.monotonic() + 5
    own_fd = str(descriptor)
    while time.monotonic() < deadline:
        held = False
        if identity is not None:
            for fd_path in Path("/proc").glob("[0-9]*/fd/[0-9]*"):
                if (
                    fd_path.parts[-3] == str(os.getpid())
                    and fd_path.name == own_fd
                ):
                    continue
                try:
                    info = fd_path.stat()
                except OSError:
                    continue
                if (info.st_dev, info.st_ino) == identity:
                    held = True
                    break
        if not held:
            break
        time.sleep(0.05)
    else:
        os.close(descriptor)
        return ControllerAuthCleanup.SINK_ABSENCE_UNPROVED
    path = Path(AUDIT_PATH)
    quarantine = path.with_name(
        f".{path.name}.telos-delete-{os.getpid()}")
    try:
        if quarantine.exists() or quarantine.is_symlink():
            return ControllerAuthCleanup.SINK_ABSENCE_UNPROVED
        current = path.lstat()
        if (
            (current.st_dev, current.st_ino) != identity
            or not stat.S_ISREG(current.st_mode)
            or current.st_uid != 0
            or current.st_gid != 0
            or stat.S_IMODE(current.st_mode) != 0o600
            or current.st_nlink != 1
        ):
            return ControllerAuthCleanup.SINK_ABSENCE_UNPROVED
        path.rename(quarantine)
        moved = quarantine.lstat()
        if (
            (moved.st_dev, moved.st_ino) != identity
            or moved.st_nlink != 1
        ):
            if not path.exists() and not path.is_symlink():
                quarantine.rename(path)
            return ControllerAuthCleanup.SINK_ABSENCE_UNPROVED
        quarantine.unlink()
        captured = os.fstat(descriptor)
        if captured.st_nlink != 0 or path.exists():
            return ControllerAuthCleanup.SINK_ABSENCE_UNPROVED
        if not persistent_removed:
            return ControllerAuthCleanup.CONFIGURATION_UNPROVED
        return None
    except OSError:
        return ControllerAuthCleanup.SINK_ABSENCE_UNPROVED
    finally:
        os.close(descriptor)


def _controller_session(encoded: str) -> int:
    """Run inside the disposable Controller; emit closed coordinates only."""
    descriptor: int | None = None
    identity: tuple[int, int] | None = None
    cleanup = ControllerAuthCleanup.SINK_ABSENCE_UNPROVED
    try:
        try:
            payload = json.loads(base64.b64decode(
                encoded, validate=True).decode("utf-8"))
            if type(payload) is not dict or set(payload) != {
                "account", "domain", "workstation_ip", "arm", "submit", "cancel",
                "result", "cleanup", "prearm", "observation_seconds",
            }:
                raise ValueError
            expectation = ControllerAuthExpectation(
                payload["account"], payload["domain"],
                payload["workstation_ip"],
            )
            markers = {
                key: payload[key]
                for key in (
                    "arm", "submit", "cancel", "result", "cleanup", "prearm")
            }
            observation_seconds = payload["observation_seconds"]
            if (
                type(observation_seconds) is not int
                or not MIN_OBSERVATION_SECONDS
                <= observation_seconds <= MAX_OBSERVATION_SECONDS
            ):
                raise ValueError
            if any(
                type(value) is not str
                or re.fullmatch(r"[0-9a-f]{32}", value) is None
                for value in markers.values()
            ):
                raise ValueError
        except (ValueError, TypeError, UnicodeError, json.JSONDecodeError):
            return 2
        def prearm(phase: str) -> None:
            print(
                f"__TELOS_AUTH_PREARM_{phase}_{markers['prearm']}__",
                flush=True,
            )

        prearm("PAYLOAD_VALID")
        primary: ControllerAuthCode | ControllerAuthCollection
        if not _effective_configuration():
            primary = ControllerAuthCollection.CONFIGURATION_INVALID
        else:
            prearm("CONFIGURATION_VALID")
            try:
                descriptor, opened = _safe_sink()
                identity = (opened.st_dev, opened.st_ino)
                offset = opened.st_size
                observation_start = time.time()
                prearm("SINK_READY")
                expectation = ControllerAuthExpectation(
                    expectation.account, expectation.domain,
                    expectation.workstation_ip,
                    _staged_sid(expectation.account),
                )
                prearm("SID_READY")
            except (OSError, RuntimeError):
                primary = ControllerAuthCollection.SINK_INVALID
            else:
                print(f"__TELOS_AUTH_ARMED_{markers['arm']}__", flush=True)
                submitted = input()
                if submitted == f"__TELOS_AUTH_CANCEL_{markers['cancel']}__":
                    primary = ControllerAuthCollection.CANCELLED
                elif submitted != f"__TELOS_AUTH_SUBMIT_{markers['submit']}__":
                    primary = ControllerAuthCollection.MALFORMED
                else:
                    deadline = time.monotonic() + observation_seconds
                    last_size = offset
                    last_size_change = time.monotonic()
                    events: tuple[Mapping[str, object], ...] = ()
                    while True:
                        current = os.stat(AUDIT_PATH, follow_symlinks=False)
                        if (current.st_dev, current.st_ino) != identity:
                            primary = ControllerAuthCollection.ROTATED
                            break
                        if current.st_size < offset:
                            primary = ControllerAuthCollection.TRUNCATED
                            break
                        if current.st_size != last_size:
                            last_size = current.st_size
                            last_size_change = time.monotonic()
                        length = current.st_size - offset
                        if length > MAX_AUDIT_BYTES:
                            primary = ControllerAuthCollection.OVERSIZED
                            break
                        raw = os.pread(descriptor, length, offset)
                        if len(raw) != length:
                            primary = ControllerAuthCollection.MALFORMED
                            break
                        try:
                            parsed, partial = _complete_json_records(
                                raw,
                                deadline_reached=(
                                    time.monotonic() >= deadline),
                            )
                            observation_end = time.time()
                            windowed = []
                            for item in parsed:
                                timestamp = item.get("timestamp")
                                if type(timestamp) is not str:
                                    raise ValueError
                                instant = datetime.fromisoformat(
                                    timestamp.replace("Z", "+00:00"))
                                if instant.tzinfo is None:
                                    raise ValueError
                                seconds = instant.astimezone(
                                    timezone.utc).timestamp()
                                if (
                                    observation_start - 2
                                    <= seconds <= observation_end + 2
                                ):
                                    windowed.append(item)
                        except OverflowError:
                            primary = ControllerAuthCollection.OVERSIZED
                            break
                        except (
                            UnicodeError, ValueError, json.JSONDecodeError,
                        ):
                            primary = ControllerAuthCollection.MALFORMED
                            break
                        events = tuple(windowed)
                        code = classify_auth_events(events, expectation)
                        now = time.monotonic()
                        if _observation_complete(
                            code,
                            partial=partial,
                            now=now,
                            last_size_change=last_size_change,
                            deadline=deadline,
                        ):
                            primary = code
                            break
                        time.sleep(0.1)
        kind = "code" if type(primary) is ControllerAuthCode else "collection"
        print(
            f"__TELOS_AUTH_RESULT_{markers['result']}__="
            f"{kind}:{primary.value}",
            flush=True,
        )
    finally:
        try:
            cleanup = _disable_and_destroy_sink(descriptor, identity)
        except BaseException:
            cleanup = ControllerAuthCleanup.SINK_ABSENCE_UNPROVED
            if descriptor is not None:
                try:
                    os.close(descriptor)
                except OSError:
                    pass
        if 'markers' in locals():
            cleanup_value = (
                "ok" if cleanup is None else cleanup.value)
            print(
                f"__TELOS_AUTH_CLEANUP_{markers['cleanup']}__="
                f"{cleanup_value}",
                flush=True,
            )
    return 0


class ControllerAuthDiagnosticSession:
    """Bounded shared-console arm/submit protocol for the Controller watcher."""

    def __init__(
        self, console, expectation: ControllerAuthExpectation,
        *, timeout: float = 45.0, post_arm_timeout: float = 45.0,
        clock=time.monotonic,
    ) -> None:
        if not CLEANUP_RESERVE_SECONDS + MIN_OBSERVATION_SECONDS <= timeout <= 60:
            raise ValueError("Controller auth timeout is invalid")
        # The armed Controller watcher blocks on its submit/cancel fence with
        # no timeout of its own, and its observation baseline is captured at
        # arm time, so a longer armed window changes nothing on the
        # Controller. The cap only bounds how long the shared console may
        # stay occupied; 60 was shorter than the real GUI submission phase
        # and made every reauthentication attempt expire the window before
        # the fence was sent.
        if not MIN_OBSERVATION_SECONDS <= post_arm_timeout <= 300:
            raise ValueError("Controller auth post-arm timeout is invalid")
        self.console = console
        self.expectation = expectation
        self._clock = clock
        self._arm_deadline = clock() + timeout
        self._deadline = self._arm_deadline
        self._post_arm_timeout = post_arm_timeout
        self._armed_deadline: float | None = None
        self._observation_seconds = MAX_OBSERVATION_SECONDS
        self._tokens = {
            name: uuid.uuid4().hex
            for name in (
                "arm", "submit", "cancel", "result", "cleanup", "prearm",
                "exit",
            )
        }
        self._state = "new"
        self._result: ControllerAuthResult | None = None
        self._last_prearm_phase: str | None = None

    @property
    def armed(self) -> bool:
        return self._state == "armed"

    @property
    def active(self) -> bool:
        return self._state in {"armed", "collecting"}

    def _wait(
        self, pattern: bytes, label: str, *, deadline: float | None = None,
    ):
        wait_deadline = self._deadline if deadline is None else min(
            deadline, self._deadline)
        remaining = wait_deadline - self._clock()
        if remaining <= 0:
            raise TimeoutError("Controller auth deadline expired")
        original = self.console.timeout
        self.console.timeout = remaining
        try:
            return self.console._wait(pattern, label)
        finally:
            self.console.timeout = original

    def _receive_observation(
        self, error: BaseException, armed_marker: bytes,
        result_marker: bytes,
    ) -> ControllerAuthReceiveObservation:
        """Reduce private console state to one closed observation coordinate."""
        raw = getattr(self.console, "buffer", b"")
        buffer = raw if type(raw) is bytes else b""

        prearm_prefix = b"__TELOS_AUTH_PREARM_"
        armed_prefix = b"__TELOS_AUTH_ARMED_"
        result_prefix = b"__TELOS_AUTH_RESULT_"
        exit_prefix = b"__TELOS_AUTH_EXIT_"
        receipt_line = re.compile(
            rb"(?:"
            + re.escape(armed_prefix) + rb"[0-9a-f]{32}__|"
            + re.escape(result_prefix)
            + rb"[0-9a-f]{32}__=(?:code|collection):[a-z-]+|"
            + re.escape(prearm_prefix)
            + rb"[A-Z_]{1,32}_[0-9a-f]{32}__|"
            + re.escape(exit_prefix)
            + rb"[0-9a-f]{32}__=(?:zero|nonzero))"
            + rb"[^\S\r\n]*")
        exit_candidate = re.compile(
            re.escape(exit_prefix) + rb"[0-9a-f]{32}__=")
        for line in re.split(rb"[\r\n]", buffer):
            if (
                armed_prefix in line
                or result_prefix in line
                or prearm_prefix in line
                or exit_candidate.search(line) is not None
            ) and receipt_line.fullmatch(line) is None:
                return ControllerAuthReceiveObservation.TOKEN_NONSTANDALONE

        prompt = (
            b"__TELOS_AUTH_SUDO_" + self._sudo_prompt_token + b"__")
        if (
            prompt in buffer
            or re.search(
                rb"(?:^|\n)(?:Sorry, try again\.|"
                rb"sudo: [0-9]+ incorrect password attempt(?:s)?|"
                rb"sudo: (?:a password is required|no password was provided))"
                rb"\s*(?:\n|$)",
                buffer,
                re.MULTILINE,
            ) is not None
        ):
            return (
                ControllerAuthReceiveObservation
                .SUDO_REJECTED_OR_REPROMPTED)

        if re.search(
            rb"(?:^|\n)(?:"
            rb"sudo: /usr/bin/python3: command not found|"
            rb"/usr/bin/python3: can't open file "
            rb"'/opt/telos-factory/controller-auth-diagnostic\.py': "
            rb"\[Errno 2\] No such file or directory|"
            rb"sudo: unable to execute "
            rb"(?:/usr/bin/python3|"
            rb"/opt/telos-factory/controller-auth-diagnostic\.py): "
            rb"No such file or directory)"
            rb"\s*(?:\n|$)",
            buffer,
            re.MULTILINE,
        ) is not None:
            return ControllerAuthReceiveObservation.COMMAND_LAUNCH_ERROR

        message = str(error)
        if (
            message.startswith("serial closed while waiting for ")
            or isinstance(error, (EOFError, BrokenPipeError, ConnectionError))
        ):
            return ControllerAuthReceiveObservation.SERIAL_CLOSED
        if (
            isinstance(error, TimeoutError)
            or message.startswith("timed out waiting for ")
            or message == "Controller auth deadline expired"
        ):
            return {
                None: ControllerAuthReceiveObservation.TIMEOUT,
                "PAYLOAD_VALID": (
                    ControllerAuthReceiveObservation
                    .TIMEOUT_AFTER_PAYLOAD_VALID),
                "CONFIGURATION_VALID": (
                    ControllerAuthReceiveObservation
                    .TIMEOUT_AFTER_CONFIGURATION_VALID),
                "SINK_READY": (
                    ControllerAuthReceiveObservation.TIMEOUT_AFTER_SINK_READY),
                "SID_READY": (
                    ControllerAuthReceiveObservation.TIMEOUT_AFTER_SID_READY),
            }[self._last_prearm_phase]
        return ControllerAuthReceiveObservation.UNCLASSIFIED

    def _recover_cleanup(self) -> ControllerAuthCleanup | None:
        if self._state not in {
            "launching", "sudo-prompt", "credential-sent",
            "armed", "collecting",
        }:
            return (
                None
                if self._state == "finished"
                else ControllerAuthCleanup.SINK_ABSENCE_UNPROVED
            )
        try:
            marker = (
                f"__TELOS_AUTH_CLEANUP_{self._tokens['cleanup']}__=".encode())
            if self._state in {
                "launching", "sudo-prompt", "credential-sent",
            }:
                # Before an armed receipt, sudo or its child may still own the
                # terminal.  A cancellation token could be consumed as
                # credential input or shell text.  Interrupt first and accept
                # only the diagnostic's typed cleanup receipt as proof;
                # reaching a shell prompt merely proves console resynchrony.
                self.console._send(
                    b"\x03", "controller-auth-launch-interrupted")
                match = self._wait(
                    _RECEIPT_LINE_START + rb"(?:"
                    + re.escape(marker)
                    + rb"(ok|[a-z-]+)" + _RECEIPT_LINE_END + rb"|"
                    + rb"[^\r\n]*\$[^\S\r\n]*(?=[\r\n]|$))",
                    "controller-auth-launch-resynchronized")
                cleanup_value = match.group(1)
                if cleanup_value is None:
                    self._state = "poisoned"
                    return ControllerAuthCleanup.SINK_ABSENCE_UNPROVED
                self._state = "finished"
                if cleanup_value == b"ok":
                    return None
                cleanup = _CLEANUP_BY_WIRE.get(cleanup_value)
                if cleanup is None:
                    self._state = "poisoned"
                    return ControllerAuthCleanup.SINK_ABSENCE_UNPROVED
                return cleanup
            self.console._send(
                f"__TELOS_AUTH_CANCEL_{self._tokens['cancel']}__".encode(),
                "controller-auth-abort-sent")
            match = self._wait(
                _RECEIPT_LINE_START + re.escape(marker)
                + rb"(ok|[a-z-]+)" + _RECEIPT_LINE_END,
                "controller-auth-abort-cleanup")
            self._state = "finished"
            cleanup_value = match.group(1)
            if cleanup_value == b"ok":
                return None
            cleanup = _CLEANUP_BY_WIRE.get(cleanup_value)
            if cleanup is None:
                self._state = "poisoned"
                return ControllerAuthCleanup.SINK_ABSENCE_UNPROVED
            return cleanup
        except _INTERRUPTIONS:
            self._state = "poisoned"
            raise
        except BaseException:
            self._state = "poisoned"
            return ControllerAuthCleanup.SINK_ABSENCE_UNPROVED

    def _recover_after_interruption(self) -> None:
        """Attempt cleanup without replacing the interruption being handled."""
        try:
            self._recover_cleanup()
        except _INTERRUPTIONS:
            pass

    @staticmethod
    def _closed_result(kind: bytes, value: bytes) -> ControllerAuthResult:
        if kind == b"code" and value in _CODE_BY_WIRE:
            return ControllerAuthResult(code=_CODE_BY_WIRE[value])
        if kind == b"collection" and value in _COLLECTION_BY_WIRE:
            collection = _COLLECTION_BY_WIRE[value]
            return ControllerAuthResult(
                collection=collection,
                # The Controller answered; it just had nothing to give. The
                # host attaches this label, so the value stays the
                # Controller's and the attribution stays the host's.
                receipt_origin=(
                    ControllerAuthReceiptOrigin.CONTROLLER_REPORTED
                    if collection
                    is ControllerAuthCollection.RECEIPT_UNAVAILABLE
                    else None
                ),
            )
        raise ValueError("Controller auth result coordinate is invalid")

    def _terminal_cleanup(
        self, result: ControllerAuthResult, label: str,
    ) -> tuple[ControllerAuthResult, bool]:
        cleanup_marker = (
            f"__TELOS_AUTH_CLEANUP_{self._tokens['cleanup']}__=".encode())
        try:
            cleanup_match = self._wait(
                _RECEIPT_LINE_START + re.escape(cleanup_marker)
                + rb"(ok|[a-z-]+)" + _RECEIPT_LINE_END,
                label)
        except _INTERRUPTIONS:
            self._recover_after_interruption()
            raise
        except BaseException:
            self._state = "poisoned"
            # replace() keeps every other coordinate, in particular the
            # receipt origin and host error, which a field-by-field rebuild
            # silently stripped and _validate then restamped unattributed.
            return (
                replace(
                    result,
                    cleanup=ControllerAuthCleanup.SINK_ABSENCE_UNPROVED,
                ),
                False,
            )
        cleanup_value = cleanup_match.group(1)
        cleanup_proved = cleanup_value == b"ok"
        if not cleanup_proved:
            cleanup = _CLEANUP_BY_WIRE.get(cleanup_value)
            if cleanup is None:
                self._state = "poisoned"
                cleanup = ControllerAuthCleanup.SINK_ABSENCE_UNPROVED
            result = replace(result, cleanup=cleanup)
        self._result = result
        self._state = "finished"
        return result, cleanup_proved

    def arm(self) -> None:
        if self._state != "new":
            raise RuntimeError("Controller auth diagnostic cannot be armed")
        try:
            payload = {
                "account": self.expectation.account,
                "domain": self.expectation.domain,
                "workstation_ip": self.expectation.workstation_ip,
                "observation_seconds": self._observation_seconds,
                **{
                    name: self._tokens[name]
                    for name in (
                        "arm", "submit", "cancel", "result", "cleanup",
                        "prearm",
                    )
                },
            }
            encoded = base64.b64encode(json.dumps(
                payload, sort_keys=True, separators=(",", ":"),
            ).encode()).decode("ascii")
            prompt_prefix = b"__TELOS_AUTH_SUDO_"
            prompt_token = uuid.uuid4().hex.encode()
            self._sudo_prompt_token = prompt_token
            prompt_suffix = b"__"
            prompt = prompt_prefix + prompt_token + prompt_suffix
            # Adjacent single-quoted shell fragments reconstruct the exact
            # prompt without placing its full marker in echoed command bytes.
            prompt_argument = (
                b"'" + prompt_prefix + b"''"
                + prompt_token + prompt_suffix + b"'")
            sudo = (
                b"sudo -k -n "
                if self.console.password is None
                else b"sudo -k -S -p " + prompt_argument + b" "
            )
            command = sudo + (
                b"/usr/bin/python3 "
                b"/opt/telos-factory/controller-auth-diagnostic.py "
                b"--controller-session " + encoded.encode("ascii"))
            exit_prefix = b"__TELOS_AUTH_EXIT_"
            exit_token = self._tokens["exit"].encode("ascii")
            # The login shell, rather than sudo or the diagnostic child,
            # reports that the whole privileged command has terminated.
            # Separate printf arguments keep the nonce-bound full marker out
            # of terminal-echoed command text.
            command += (
                b"; _telos_auth_status=$?; "
                b"if [ \"$_telos_auth_status\" -eq 0 ]; then "
                b"_telos_auth_exit=zero; else "
                b"_telos_auth_exit=nonzero; fi; "
                b"printf '\\n%s%s%s%s\\n' '"
                + exit_prefix + b"' '" + exit_token
                + b"' '__=' \"$_telos_auth_exit\"")
            self.console._send(b"", "controller-auth-shell-requested")
            self._wait(
                rb"(?:^|\n)[^\n]*\$\s*$", "controller-auth-shell-ready")
        except _INTERRUPTIONS:
            self._recover_after_interruption()
            raise
        except BaseException:
            raise ControllerAuthDiagnosticError(
                cleanup_proved=True,
                arm_subphase=ControllerAuthArmSubphase.PREFLIGHT,
            ) from None
        self._state = "launching"
        try:
            self.console._send(command, "controller-auth-command-sent")
        except _INTERRUPTIONS:
            self._recover_after_interruption()
            raise
        except BaseException:
            cleanup = self._recover_cleanup()
            raise ControllerAuthDiagnosticError(
                controller_auth_result=ControllerAuthResult(
                    collection=ControllerAuthCollection.RECEIPT_UNAVAILABLE,
                    cleanup=cleanup,
                ),
                cleanup_proved=cleanup is None,
                arm_subphase=ControllerAuthArmSubphase.COMMAND_DISPATCH,
            ) from None
        if self.console.password is not None:
            self._state = "sudo-prompt"
            try:
                self._wait(
                    rb"(?:^|[\r\n])" + re.escape(prompt)
                    + rb"[^\S\r\n]*(?=[\r\n]|$)",
                    "controller-auth-sudo-password-prompt",
                    deadline=self._arm_deadline - CLEANUP_RESERVE_SECONDS)
            except BaseException:
                cleanup = self._recover_cleanup()
                raise ControllerAuthDiagnosticError(
                    controller_auth_result=ControllerAuthResult(
                        collection=(
                            ControllerAuthCollection.RECEIPT_UNAVAILABLE),
                        cleanup=cleanup,
                    ),
                    cleanup_proved=cleanup is None,
                    arm_subphase=ControllerAuthArmSubphase.SUDO_PROMPT,
                ) from None
            try:
                self.console._send(
                    self.console.password, "controller-auth-sudo-password-sent")
            except BaseException:
                cleanup = self._recover_cleanup()
                raise ControllerAuthDiagnosticError(
                    controller_auth_result=ControllerAuthResult(
                        collection=(
                            ControllerAuthCollection.RECEIPT_UNAVAILABLE),
                        cleanup=cleanup,
                    ),
                    cleanup_proved=cleanup is None,
                    arm_subphase=(
                        ControllerAuthArmSubphase.SUDO_CREDENTIAL_HANDOFF),
                ) from None
            self._state = "credential-sent"
        try:
            armed_marker = (
                f"__TELOS_AUTH_ARMED_{self._tokens['arm']}__".encode())
            result_marker = (
                f"__TELOS_AUTH_RESULT_{self._tokens['result']}__=".encode())
            expected_phases = (
                b"PAYLOAD_VALID",
                b"CONFIGURATION_VALID",
                b"SINK_READY",
                b"SID_READY",
            )
            prearm_token = self._tokens["prearm"].encode()
            match = None
            invalid_prearm = False
            for expected_phase in expected_phases + (b"ARMED",):
                match = self._wait(
                    _RECEIPT_LINE_START + rb"(?:"
                    + rb"(__TELOS_AUTH_PREARM_([A-Z_]{1,32})_"
                    + rb"([0-9a-f]{32})__)"
                    + _RECEIPT_LINE_END + rb"|"
                    + rb"(__TELOS_AUTH_ARMED_([0-9a-f]{32})__)"
                    + _RECEIPT_LINE_END + rb"|"
                    + rb"(__TELOS_AUTH_RESULT_([0-9a-f]{32})__)="
                    + rb"(code|collection):([a-z-]+)"
                    + _RECEIPT_LINE_END + rb"|"
                    + rb"(__TELOS_AUTH_EXIT_([0-9a-f]{32})__)="
                    + rb"(zero|nonzero)"
                    + _RECEIPT_LINE_END + rb"|"
                    + rb"([^\r\n]*__TELOS_AUTH_EXIT_[0-9a-f]{32}__="
                    + rb"(?:zero|nonzero)[^\r\n]*)"
                    + _RECEIPT_LINE_END + rb")",
                    "controller-auth-armed",
                    deadline=(
                        self._arm_deadline - CLEANUP_RESERVE_SECONDS))
                if self._receive_observation(
                    RuntimeError("closed receipt inspection"),
                    armed_marker,
                    result_marker,
                ) is ControllerAuthReceiveObservation.TOKEN_NONSTANDALONE:
                    invalid_prearm = True
                    break
                exit_value = (
                    match.group(12)
                    if len(match.groups()) >= 12
                    else None
                )
                if exit_value in {b"zero", b"nonzero"}:
                    if match.group(11) != self._tokens["exit"].encode():
                        invalid_prearm = True
                    break
                if match.group(8) in {b"code", b"collection"}:
                    if (
                        match.group(7)
                        != self._tokens["result"].encode()
                    ):
                        invalid_prearm = True
                    break
                if expected_phase == b"ARMED":
                    if (
                        match.group(5)
                        != self._tokens["arm"].encode()
                    ):
                        invalid_prearm = True
                    break
                if (
                    match.group(2) != expected_phase
                    or match.group(3) != prearm_token
                ):
                    invalid_prearm = True
                    break
                self._last_prearm_phase = expected_phase.decode("ascii")
        except _INTERRUPTIONS:
            self._recover_after_interruption()
            raise
        except BaseException as error:
            try:
                observation = self._receive_observation(
                    error, armed_marker, result_marker)
            except BaseException:
                observation = ControllerAuthReceiveObservation.UNCLASSIFIED
            cleanup = self._recover_cleanup()
            raise ControllerAuthDiagnosticError(
                controller_auth_result=ControllerAuthResult(
                    collection=ControllerAuthCollection.RECEIPT_UNAVAILABLE,
                    cleanup=cleanup,
                ),
                cleanup_proved=cleanup is None,
                arm_subphase=ControllerAuthArmSubphase.RECEIVE,
                receive_observation=observation,
            ) from None
        try:
            if invalid_prearm:
                raise ValueError(
                    "Controller auth pre-arm order is invalid")
            exit_value = (
                match.group(12)
                if len(match.groups()) >= 12
                else None
            )
            if exit_value in {b"zero", b"nonzero"}:
                observation = {
                    b"zero": (
                        ControllerAuthReceiveObservation.COMMAND_EXIT_ZERO),
                    b"nonzero": (
                        ControllerAuthReceiveObservation.COMMAND_EXIT_NONZERO),
                }[exit_value]
                # The child emits PAYLOAD_VALID immediately after successful
                # parsing and before any mutable pre-arm operation.  A
                # nonce-bound wrapper exit before that receipt therefore
                # proves this invocation could not have created a sink or
                # changed live Samba configuration.
                cleanup = (
                    None
                    if self._last_prearm_phase is None
                    else ControllerAuthCleanup.SINK_ABSENCE_UNPROVED
                )
                self._state = (
                    "finished" if cleanup is None else "poisoned")
                raise ControllerAuthDiagnosticError(
                    controller_auth_result=ControllerAuthResult(
                        collection=(
                            ControllerAuthCollection.RECEIPT_UNAVAILABLE),
                        cleanup=cleanup,
                    ),
                    cleanup_proved=cleanup is None,
                    arm_subphase=ControllerAuthArmSubphase.RECEIVE,
                    receive_observation=observation,
                )
            if match.group(8) in {b"code", b"collection"}:
                result = self._closed_result(
                    match.group(8), match.group(9))
                allowed = {
                    "PAYLOAD_VALID": {
                        ControllerAuthCollection.CONFIGURATION_INVALID},
                    "CONFIGURATION_VALID": {
                        ControllerAuthCollection.SINK_INVALID},
                    "SINK_READY": {
                        ControllerAuthCollection.SINK_INVALID},
                }
                if (
                    result.code is not None
                    or result.collection
                    not in allowed.get(self._last_prearm_phase, set())
                ):
                    raise ValueError(
                        "Controller auth pre-arm coordinate is invalid")
                result, cleanup_proved = self._terminal_cleanup(
                    result, "controller-auth-prearm-cleanup")
                raise ControllerAuthDiagnosticError(
                    controller_auth_result=result,
                    cleanup_proved=cleanup_proved)
            self._state = "armed"
            self._armed_deadline = self._clock() + self._post_arm_timeout
        except ControllerAuthDiagnosticError:
            raise
        except _INTERRUPTIONS:
            self._recover_after_interruption()
            raise
        except BaseException:
            cleanup = self._recover_cleanup()
            raise ControllerAuthDiagnosticError(
                controller_auth_result=ControllerAuthResult(
                    collection=ControllerAuthCollection.RECEIPT_UNAVAILABLE,
                    cleanup=cleanup,
                ),
                cleanup_proved=cleanup is None,
                arm_subphase=ControllerAuthArmSubphase.PARSE,
            ) from None

    def begin_submission(self) -> None:
        """Release the armed watcher without waiting for its result."""
        if self._state != "armed":
            raise RuntimeError("Controller auth submission is out of order")
        if (
            self._armed_deadline is None
            or self._clock() >= self._armed_deadline
        ):
            self._deadline = self._clock() + CLEANUP_RESERVE_SECONDS
            cleanup = self._recover_cleanup()
            raise ControllerAuthDiagnosticError(
                controller_auth_result=ControllerAuthResult(
                    collection=ControllerAuthCollection.RECEIPT_UNAVAILABLE,
                    cleanup=cleanup,
                    receipt_origin=(
                        ControllerAuthReceiptOrigin.ARM_WINDOW_EXPIRED),
                ),
                cleanup_proved=cleanup is None,
            )
        self._deadline = (
            self._clock() + self._observation_seconds
            + RESULT_RECEIPT_SECONDS
            + CLEANUP_RESERVE_SECONDS)
        self._state = "collecting"
        try:
            self.console._send(
                f"__TELOS_AUTH_SUBMIT_{self._tokens['submit']}__".encode(),
                "controller-auth-submitted")
        except _INTERRUPTIONS:
            self._recover_after_interruption()
            raise
        except BaseException:
            cleanup = self._recover_cleanup()
            raise ControllerAuthDiagnosticError(
                controller_auth_result=ControllerAuthResult(
                    collection=ControllerAuthCollection.RECEIPT_UNAVAILABLE,
                    cleanup=cleanup,
                ),
                cleanup_proved=cleanup is None,
            ) from None

    def result(self) -> ControllerAuthResult:
        """Collect the result after every observer has received its fence."""
        if self._state != "collecting":
            raise RuntimeError("Controller auth result is out of order")
        result_marker = (
            f"__TELOS_AUTH_RESULT_{self._tokens['result']}__=".encode())
        try:
            match = self._wait(
                _RECEIPT_LINE_START + re.escape(result_marker)
                + rb"(code|collection):([a-z-]+)"
                + _RECEIPT_LINE_END,
                "controller-auth-result",
                deadline=self._deadline - CLEANUP_RESERVE_SECONDS)
        except _INTERRUPTIONS:
            self._recover_after_interruption()
            raise
        except BaseException:
            cleanup = self._recover_cleanup()
            raise ControllerAuthDiagnosticError(
                controller_auth_result=ControllerAuthResult(
                    collection=ControllerAuthCollection.RECEIPT_UNAVAILABLE,
                    cleanup=cleanup,
                    # No receipt line arrived before the bounded deadline, so
                    # the Controller never answered at all.
                    receipt_origin=(
                        ControllerAuthReceiptOrigin.HOST_WAIT_EXPIRED),
                ),
                cleanup_proved=cleanup is None,
            ) from None
        try:
            result = self._closed_result(match.group(1), match.group(2))
            result, cleanup_proved = self._terminal_cleanup(
                result, "controller-auth-cleanup")
            if not cleanup_proved:
                raise ControllerAuthDiagnosticError(
                    controller_auth_result=result,
                    cleanup_proved=False)
            return result
        except ControllerAuthDiagnosticError:
            raise
        except _INTERRUPTIONS:
            self._recover_after_interruption()
            raise
        except BaseException as error:
            cleanup = self._recover_cleanup()
            raise ControllerAuthDiagnosticError(
                controller_auth_result=ControllerAuthResult(
                    collection=ControllerAuthCollection.RECEIPT_UNAVAILABLE,
                    cleanup=cleanup,
                    # A receipt line arrived but could not be processed; the
                    # exception type is the only secret-free record of why.
                    host_error=type(error).__name__,
                ),
                cleanup_proved=cleanup is None,
            ) from None

    def cancel(self) -> ControllerAuthResult:
        if self._state == "collecting":
            self._deadline = self._clock() + CLEANUP_RESERVE_SECONDS
            cleanup = self._recover_cleanup()
            result = ControllerAuthResult(
                collection=ControllerAuthCollection.RECEIPT_UNAVAILABLE,
                cleanup=cleanup,
            )
            if cleanup is not None:
                raise ControllerAuthDiagnosticError(
                    controller_auth_result=result,
                    cleanup_proved=False,
                )
            return result
        if self._state != "armed":
            raise RuntimeError("Controller auth cancellation is out of order")
        # Cancellation may be required precisely because the post-arm GUI
        # deadline expired.  Establish a fresh bounded cleanup phase so that
        # earlier arm or GUI work cannot consume its reserve.
        self._deadline = self._clock() + CLEANUP_RESERVE_SECONDS
        self.console._send(
            f"__TELOS_AUTH_CANCEL_{self._tokens['cancel']}__".encode(),
            "controller-auth-cancelled")
        result_marker = (
            f"__TELOS_AUTH_RESULT_{self._tokens['result']}__=".encode())
        try:
            self._wait(
                _RECEIPT_LINE_START + re.escape(result_marker)
                + rb"collection:cancelled" + _RECEIPT_LINE_END,
                "controller-auth-cancel-result",
                deadline=self._deadline - CLEANUP_BOUNDED_OPERATIONS_SECONDS)
            result = ControllerAuthResult(
                collection=ControllerAuthCollection.CANCELLED,
            )
            result, cleanup_proved = self._terminal_cleanup(
                result, "controller-auth-cancel-cleanup")
            if not cleanup_proved:
                raise ControllerAuthDiagnosticError(
                    controller_auth_result=result,
                    cleanup_proved=False)
            return result
        except ControllerAuthDiagnosticError:
            raise
        except BaseException:
            cleanup = self._recover_cleanup()
            raise ControllerAuthDiagnosticError(
                controller_auth_result=ControllerAuthResult(
                    collection=ControllerAuthCollection.RECEIPT_UNAVAILABLE,
                    cleanup=cleanup,
                ),
                cleanup_proved=cleanup is None,
            ) from None


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--controller-session")
    args = parser.parse_args()
    if args.controller_session is None:
        parser.error("--controller-session is required")
    return _controller_session(args.controller_session)


if __name__ == "__main__":
    raise SystemExit(main())
