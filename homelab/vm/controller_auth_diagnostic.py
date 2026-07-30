"""Bounded, passive Controller-side Samba authentication diagnostic.

This diagnostic is supplemental context only.  It has no nonce-bearing Samba
event and therefore can neither authorize nor veto GUI identity acceptance.
The Controller parses the root-private audit sink; only closed, secret-free
coordinates cross the shared serial console.
"""

from __future__ import annotations

from dataclasses import dataclass
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
CLEANUP_MARGIN_SECONDS = 16

_ACCOUNT = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}")
_DOMAIN = re.compile(r"[A-Z0-9][A-Z0-9-]{0,14}")
_SID = re.compile(r"S-1-5-21-(?:[0-9]{1,10}-){2}[0-9]{1,10}-[0-9]{1,10}")


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
    SERIAL_CLOSED = "serial-closed"
    TOKEN_NONSTANDALONE = "token-nonstandalone"
    TIMEOUT = "timeout"
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
_PREARM_COLLECTIONS = frozenset({
    ControllerAuthCollection.CONFIGURATION_INVALID,
    ControllerAuthCollection.SINK_INVALID,
})


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

    syntax = subprocess.run(
        ["testparm", "-s", SMB_CONFIG_PATH],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
        timeout=5,
    )
    if syntax.returncode != 0:
        return False

    live = subprocess.run(
        ["smbcontrol", "all", "debuglevel"],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        check=False,
        text=True,
        timeout=5,
    )
    if live.returncode != 0:
        return False
    return _live_auth_json_level(live.stdout, AUTH_JSON_LEVEL)


def _staged_sid(account: str) -> str:
    result = subprocess.run(
        ["samba-tool", "user", "show", account, "--attributes=objectSid"],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        check=False,
        text=True,
        timeout=5,
    )
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
                "result", "cleanup", "observation_seconds",
            }:
                raise ValueError
            expectation = ControllerAuthExpectation(
                payload["account"], payload["domain"],
                payload["workstation_ip"],
            )
            markers = {
                key: payload[key]
                for key in ("arm", "submit", "cancel", "result", "cleanup")
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
        primary: ControllerAuthCode | ControllerAuthCollection
        if not _effective_configuration():
            primary = ControllerAuthCollection.CONFIGURATION_INVALID
        else:
            try:
                descriptor, opened = _safe_sink()
                identity = (opened.st_dev, opened.st_ino)
                offset = opened.st_size
                observation_start = time.time()
                expectation = ControllerAuthExpectation(
                    expectation.account, expectation.domain,
                    expectation.workstation_ip,
                    _staged_sid(expectation.account),
                )
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
        *, timeout: float = 45.0, clock=time.monotonic,
    ) -> None:
        if not CLEANUP_MARGIN_SECONDS + MIN_OBSERVATION_SECONDS <= timeout <= 60:
            raise ValueError("Controller auth timeout is invalid")
        self.console = console
        self.expectation = expectation
        self._clock = clock
        self._deadline = clock() + timeout
        self._observation_seconds = min(
            MAX_OBSERVATION_SECONDS,
            int(timeout - CLEANUP_MARGIN_SECONDS),
        )
        self._tokens = {name: uuid.uuid4().hex for name in (
            "arm", "submit", "cancel", "result", "cleanup")}
        self._state = "new"
        self._result: ControllerAuthResult | None = None

    @property
    def armed(self) -> bool:
        return self._state == "armed"

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

        marker_pattern = (
            rb"(?:^|\n)(?:"
            + re.escape(armed_marker)
            + rb"\s*(?:\n|$)|"
            + re.escape(result_marker)
            + rb"(?:code|collection):[a-z-]+\s*(?:\n|$))")
        if (
            (armed_marker in buffer or result_marker in buffer)
            and re.search(marker_pattern, buffer, re.MULTILINE) is None
        ):
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
            return ControllerAuthReceiveObservation.TIMEOUT
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
                    rb"(?:^|[\r\n])(?:"
                    + re.escape(marker)
                    + rb"(ok|[a-z-]+)[^\S\r\n]*(?:[\r\n]|$)|"
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
                rb"(?:^|\n)" + re.escape(marker)
                + rb"(ok|[a-z-]+)\s*(?:\n|$)",
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
        except BaseException:
            self._state = "poisoned"
            return ControllerAuthCleanup.SINK_ABSENCE_UNPROVED

    @staticmethod
    def _closed_result(kind: bytes, value: bytes) -> ControllerAuthResult:
        if kind == b"code" and value in _CODE_BY_WIRE:
            return ControllerAuthResult(code=_CODE_BY_WIRE[value])
        if kind == b"collection" and value in _COLLECTION_BY_WIRE:
            return ControllerAuthResult(collection=_COLLECTION_BY_WIRE[value])
        raise ValueError("Controller auth result coordinate is invalid")

    def _terminal_cleanup(
        self, result: ControllerAuthResult, label: str,
    ) -> tuple[ControllerAuthResult, bool]:
        cleanup_marker = (
            f"__TELOS_AUTH_CLEANUP_{self._tokens['cleanup']}__=".encode())
        try:
            cleanup_match = self._wait(
                rb"(?:^|\n)" + re.escape(cleanup_marker)
                + rb"(ok|[a-z-]+)\s*(?:\n|$)",
                label)
        except BaseException:
            self._state = "poisoned"
            return (
                ControllerAuthResult(
                    code=result.code,
                    collection=result.collection,
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
            result = ControllerAuthResult(
                code=result.code,
                collection=result.collection,
                cleanup=cleanup,
            )
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
                **self._tokens,
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
            self.console._send(b"", "controller-auth-shell-requested")
            self._wait(
                rb"(?:^|\n)[^\n]*\$\s*$", "controller-auth-shell-ready")
        except BaseException:
            raise ControllerAuthDiagnosticError(
                cleanup_proved=True,
                arm_subphase=ControllerAuthArmSubphase.PREFLIGHT,
            ) from None
        self._state = "launching"
        try:
            self.console._send(command, "controller-auth-command-sent")
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
                    deadline=self._deadline - CLEANUP_MARGIN_SECONDS)
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
            match = self._wait(
                rb"(?:^|\n)(?:"
                + re.escape(armed_marker)
                + rb"\s*(?:\n|$)|"
                + re.escape(result_marker)
                + rb"(code|collection):([a-z-]+)\s*(?:\n|$))",
                "controller-auth-armed",
                deadline=self._deadline - CLEANUP_MARGIN_SECONDS)
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
            if match.group(1) in {b"code", b"collection"}:
                result = self._closed_result(
                    match.group(1), match.group(2))
                if (
                    result.code is not None
                    or result.collection not in _PREARM_COLLECTIONS
                ):
                    raise ValueError(
                        "Controller auth pre-arm coordinate is invalid")
                result, cleanup_proved = self._terminal_cleanup(
                    result, "controller-auth-prearm-cleanup")
                raise ControllerAuthDiagnosticError(
                    controller_auth_result=result,
                    cleanup_proved=cleanup_proved)
            self._state = "armed"
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
                arm_subphase=ControllerAuthArmSubphase.PARSE,
            ) from None

    def submitted(self) -> ControllerAuthResult:
        if self._state != "armed":
            raise RuntimeError("Controller auth submission is out of order")
        self._state = "collecting"
        self.console._send(
            f"__TELOS_AUTH_SUBMIT_{self._tokens['submit']}__".encode(),
            "controller-auth-submitted")
        result_marker = (
            f"__TELOS_AUTH_RESULT_{self._tokens['result']}__=".encode())
        try:
            match = self._wait(
                rb"(?:^|\n)" + re.escape(result_marker)
                + rb"(code|collection):([a-z-]+)\s*(?:\n|$)",
                "controller-auth-result")
        except BaseException:
            cleanup = self._recover_cleanup()
            raise ControllerAuthDiagnosticError(
                controller_auth_result=ControllerAuthResult(
                    collection=ControllerAuthCollection.RECEIPT_UNAVAILABLE,
                    cleanup=cleanup,
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
        except BaseException:
            cleanup = self._recover_cleanup()
            raise ControllerAuthDiagnosticError(
                controller_auth_result=ControllerAuthResult(
                    collection=ControllerAuthCollection.RECEIPT_UNAVAILABLE,
                    cleanup=cleanup,
                ),
                cleanup_proved=cleanup is None,
            ) from None

    def cancel(self) -> ControllerAuthResult:
        if self._state != "armed":
            raise RuntimeError("Controller auth cancellation is out of order")
        self.console._send(
            f"__TELOS_AUTH_CANCEL_{self._tokens['cancel']}__".encode(),
            "controller-auth-cancelled")
        result_marker = (
            f"__TELOS_AUTH_RESULT_{self._tokens['result']}__=".encode())
        try:
            self._wait(
                rb"(?:^|\n)" + re.escape(result_marker)
                + rb"collection:cancelled\s*(?:\n|$)",
                "controller-auth-cancel-result")
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
