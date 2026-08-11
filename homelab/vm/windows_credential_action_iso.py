#!/usr/bin/env python3
"""One-use private media for fixed Windows credential checks."""

from __future__ import annotations

import json
import math
import os
from pathlib import Path
import re
import shutil
import socket
import stat
import subprocess
import tempfile
import time
from enum import Enum
from typing import Callable, Mapping, Protocol

from .windows_identity_contract import (
    PRIVATE_MEDIA_CHILD_DEVICE,
    PRIVATE_MEDIA_CONTROLLER_BUS,
    PRIVATE_MEDIA_PARENT_DEVICE,
    PRIVATE_MEDIA_PORT,
)
from .windows_public_command import bounded_media_launch_command


class WindowsCredentialActionError(RuntimeError):
    """The private credential-action channel failed closed."""


SCRIPT = (
    Path(__file__).with_name("windows_credential_action_control")
    / "TelosCredential.ps1"
)
NONCE = re.compile(r"[a-f0-9]{32}")
ACCOUNT = re.compile(r"[A-Za-z0-9_.@-]{1,256}")
DOMAIN = re.compile(r"(?:\.|[A-Za-z0-9][A-Za-z0-9.-]{0,252})")
ACTIONS = frozenset({
    "connected-domain-login",
    "cached-domain-login",
    "local-rescue-login",
    "operator-local-administrators-check",
    "uncached-domain-user-denied",
})
ACTION_NODE = "telos-credential-action-media"
ACTION_DEVICE = "telos-credential-action-cd"
ACTION_PARENT = "telos-credential-action-bot"
ACTION_BUS = f"{ACTION_PARENT}.0"
# Fixed diagnostic-only lines the guest script emits around its risky work.
# They carry no nonce and no authority -- media destruction is still gated
# exclusively on the nonce-bound material marker -- but they split a silent
# COM1 timeout into "script never reported" (raw TimeoutError), "script
# started then died" and "script failed mid-way" (typed), which attempt 37
# (20260811T134831Z) could not distinguish from a clean-desktop frame.
SCRIPT_STARTED_EVENT = '{"schema_version":1,"event":"credential-script-started"}'
SCRIPT_FAILED_EVENT = '{"schema_version":1,"event":"credential-script-failed"}'
# Closed guest failure-stage vocabulary. Attempt 38 (20260811T142143Z)
# proved the guest died within one second of the material release, but the
# bare failed line could not say where; the script now names its stage from
# these literals and the bounded Win32 logon error code.
_SCRIPT_FAILED_STAGES = frozenset({
    "material", "release-wait", "post-release-setup",
    "logon", "child-wait", "result-read",
})


def _script_failed_detail(line: str) -> tuple[str, int] | None:
    """Parse a fixed-form guest failed line; None when it is not one.

    Diagnostic only, never authority: an unparseable stage or code
    degrades to unclassified/0 instead of changing any behavior.
    """
    try:
        record = json.loads(line)
    except json.JSONDecodeError:
        return None
    if (
        not isinstance(record, dict)
        or record.get("schema_version") != 1
        or record.get("event") != "credential-script-failed"
        or not set(record) <= {"schema_version", "event", "stage", "code"}
    ):
        return None
    stage = record.get("stage")
    if not isinstance(stage, str) or stage not in _SCRIPT_FAILED_STAGES:
        stage = "unclassified"
    code = record.get("code")
    if (
        isinstance(code, bool)
        or not isinstance(code, int)
        or not 0 <= code <= 0xFFFFFFFF
    ):
        code = 0
    return stage, code


def _raise_script_failed(
    position: str, detail: tuple[str, int],
) -> None:
    stage, code = detail
    error = WindowsCredentialActionError(
        f"credential-action script failed {position}; "
        f"guest_stage={stage}; guest_code={code}")
    error.guest_stage = stage
    error.guest_code = code
    raise error
_RESULT_KEYS = {
    "schema_version", "event", "nonce", "action", "result",
    "principal", "authenticated", "local_administrators_member",
    "authentication_type", "authentication_semantics", "cache_evidence",
    "login_elapsed_seconds", "local_profile_available",
    "domain_reachable", "controller_reachable", "gateway_reachable",
    "failure_classification",
}
_AUTHENTICATION_SEMANTICS = frozenset({
    "connected-domain",
    "cached-domain",
    "local-account",
    "domain-logon-denied",
})
_CACHE_EVIDENCE = frozenset({
    "online-interactive-logon",
    "offline-cache-proven",
    "offline-cache-miss-proven",
    "not-applicable",
})


class Qmp(Protocol):
    def execute(
        self, command: str, arguments: dict | None = None,
    ) -> Mapping[str, object]: ...


class CredentialActionMediaState(Enum):
    DETACHED = "detached"
    ATTACHED = "attached"
    DESTROYED_AWAITING_RELEASE = "destroyed-awaiting-release"
    RELEASED = "released"


class DuplexCredentialActionSerial:
    """One bounded duplex COM1 connection for marker, release, and result."""

    def __init__(
        self,
        connection: socket.socket,
        *,
        maximum_line: int = 4096,
        timeout: float = 120.0,
        clock: Callable[[], float] = time.monotonic,
    ):
        if not 128 <= maximum_line <= 16384:
            raise WindowsCredentialActionError("serial line bound is invalid")
        if not 0 < timeout <= 300:
            raise WindowsCredentialActionError("serial timeout is invalid")
        self.connection = connection
        self.maximum_line = maximum_line
        self._clock = clock
        self._deadline = clock() + timeout
        self.closed = False

    @classmethod
    def connect(
        cls, path: Path, *, timeout: float = 120.0,
    ) -> "DuplexCredentialActionSerial":
        connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        serial = cls(connection, timeout=timeout)
        try:
            serial._set_operation_timeout()
            connection.connect(str(Path(path)))
        except Exception:
            connection.close()
            raise
        return serial

    def _set_operation_timeout(self) -> None:
        remaining = self._deadline - self._clock()
        if remaining <= 0:
            raise WindowsCredentialActionError(
                "credential-action serial deadline expired")
        self.connection.settimeout(remaining)

    def read_line(self) -> str:
        if self.closed:
            raise WindowsCredentialActionError(
                "credential-action serial is closed")
        data = bytearray()
        while len(data) <= self.maximum_line:
            self._set_operation_timeout()
            chunk = self.connection.recv(1)
            if not chunk:
                raise WindowsCredentialActionError(
                    "credential-action serial closed before record")
            if chunk == b"\n":
                try:
                    return data.decode("utf-8") + "\n"
                except UnicodeDecodeError as error:
                    raise WindowsCredentialActionError(
                        "credential-action serial record is not UTF-8"
                    ) from error
            if chunk == b"\r":
                raise WindowsCredentialActionError(
                    "credential-action serial record contains CR")
            data.extend(chunk)
        raise WindowsCredentialActionError(
            "credential-action serial record exceeds bound")

    def send_release(self, line: str) -> None:
        if self.closed:
            raise WindowsCredentialActionError(
                "credential-action serial is closed")
        encoded = (line + "\n").encode("ascii")
        if len(encoded) > self.maximum_line:
            raise WindowsCredentialActionError(
                "credential-action release exceeds bound")
        self._set_operation_timeout()
        self.connection.sendall(encoded)

    def close(self) -> None:
        if not self.closed:
            self.connection.close()
            self.closed = True


def _private_parent(path: Path) -> Path:
    parent = path.resolve()
    if (path.is_symlink() or not parent.is_dir()
            or stat.S_IMODE(parent.stat().st_mode) != 0o700):
        raise WindowsCredentialActionError(
            "credential-action ISO parent must be a private mode-0700 directory")
    return parent


def _validate_material(material: Mapping[str, str]) -> dict[str, str]:
    required = {"nonce", "action", "username", "domain", "password"}
    if set(material) != required:
        raise WindowsCredentialActionError(
            "credential-action material fields are invalid")
    values = dict(material)
    if not NONCE.fullmatch(values["nonce"]):
        raise WindowsCredentialActionError(
            "credential-action nonce is invalid")
    if values["action"] not in ACTIONS:
        raise WindowsCredentialActionError(
            "credential action is not allowlisted")
    if not ACCOUNT.fullmatch(values["username"]):
        raise WindowsCredentialActionError(
            "credential-action username is invalid")
    if not DOMAIN.fullmatch(values["domain"]):
        raise WindowsCredentialActionError(
            "credential-action domain is invalid")
    password = values["password"]
    if (not isinstance(password, str) or not password or len(password) > 512
            or "\r" in password or "\n" in password):
        raise WindowsCredentialActionError(
            "credential-action password is invalid")
    if (values["action"] in {
            "connected-domain-login", "cached-domain-login",
            "uncached-domain-user-denied"}
            and values["domain"] == "."):
        raise WindowsCredentialActionError(
            "domain login requires a domain")
    return values


def build_credential_action_iso(
    output: Path,
    material: Mapping[str, str],
    *,
    runner=subprocess.run,
) -> Path:
    """Build private one-use media without putting credentials in argv."""
    output = Path(output)
    if output.exists() or output.is_symlink():
        raise WindowsCredentialActionError(
            "credential-action ISO destination must be absent")
    parent = _private_parent(output.parent)
    values = _validate_material(material)
    if SCRIPT.is_symlink() or not SCRIPT.is_file():
        raise WindowsCredentialActionError(
            "credential-action script is unavailable")
    with tempfile.TemporaryDirectory(
            prefix=".windows-credential-action-", dir=parent) as temporary:
        root = Path(temporary)
        root.chmod(0o700)
        stage = root / "payload"
        stage.mkdir(mode=0o700)
        target_script = stage / SCRIPT.name
        shutil.copyfile(SCRIPT, target_script)
        target_script.chmod(0o400)
        document = stage / "action.json"
        descriptor = os.open(
            document, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
            0o400)
        try:
            with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
                json.dump(
                    {"schema_version": 1, **values}, stream,
                    separators=(",", ":"), sort_keys=True)
                stream.write("\n")
        except BaseException:
            try:
                os.close(descriptor)
            except OSError:
                pass
            raise
        partial = root / "credential-action.iso"
        runner([
            "xorriso", "-as", "mkisofs", "-quiet",
            "-V", "TELOS_CRED", "-J", "-r",
            "-o", str(partial), str(stage),
        ], check=True)
        if partial.is_symlink() or not partial.is_file():
            raise WindowsCredentialActionError(
                "xorriso did not create the credential-action ISO")
        partial.chmod(0o600)
        partial.replace(output)
    output.chmod(0o600)
    return output


def launch_credential_action_command() -> str:
    """Return fixed secret-free PowerShell suitable for GUI injection."""
    return bounded_media_launch_command(
        "TELOS_CRED", "TelosCredential.ps1",
    )


def parse_action_result(
    line: str,
    *,
    nonce: str,
    action: str,
    expected_principal: str,
    allowed_authentication_types: frozenset[str],
) -> dict[str, object]:
    """Accept exactly one bounded, public credential-action result."""
    if not NONCE.fullmatch(nonce) or action not in ACTIONS:
        raise WindowsCredentialActionError(
            "credential-action result expectation is invalid")
    if (len(line.encode("utf-8")) > 4096 or "\r" in line
            or not line.endswith("\n")):
        raise WindowsCredentialActionError(
            "credential-action result is invalid")
    if line.count("\n") != 1:
        raise WindowsCredentialActionError(
            "credential-action result must be one JSONL record")
    try:
        result = json.loads(line)
    except json.JSONDecodeError as error:
        raise WindowsCredentialActionError(
            "credential-action result is invalid JSON") from error
    if not isinstance(result, dict) or set(result) != _RESULT_KEYS:
        raise WindowsCredentialActionError(
            "credential-action result schema is invalid")
    expected = {
        "schema_version": 1,
        "event": "credential-action-result",
        "nonce": nonce,
        "action": action,
        "result": "pass",
    }
    if any(result.get(key) != value for key, value in expected.items()):
        raise WindowsCredentialActionError(
            "credential-action result identity is invalid")
    for key in (
            "principal", "authentication_type", "authentication_semantics",
            "cache_evidence", "failure_classification"):
        if (not isinstance(result[key], str) or not result[key]
                or len(result[key]) > 256):
            raise WindowsCredentialActionError(
                "credential-action result schema is invalid")
    for key in (
            "authenticated", "local_administrators_member",
            "local_profile_available", "domain_reachable",
            "controller_reachable", "gateway_reachable"):
        if not isinstance(result[key], bool):
            raise WindowsCredentialActionError(
                "credential-action result schema is invalid")
    elapsed = result["login_elapsed_seconds"]
    if (isinstance(elapsed, bool) or not isinstance(elapsed, (int, float))
            or not math.isfinite(elapsed) or elapsed < 0 or elapsed > 120):
        raise WindowsCredentialActionError(
            "credential-action result schema is invalid")
    if (result["authentication_semantics"] not in _AUTHENTICATION_SEMANTICS
            or result["cache_evidence"] not in _CACHE_EVIDENCE
            or result["domain_reachable"] != result["controller_reachable"]):
        raise WindowsCredentialActionError(
            "credential-action result measurement is invalid")
    if action == "uncached-domain-user-denied":
        if (result["principal"].casefold() != expected_principal.casefold()
                or result["authenticated"]
                or result["local_administrators_member"]
                or result["local_profile_available"]
                or result["authentication_type"] != "None"
                or result["domain_reachable"]
                or result["authentication_semantics"] != "domain-logon-denied"
                or result["cache_evidence"] != "offline-cache-miss-proven"
                or result["failure_classification"] != "windows-logon-failure"):
            raise WindowsCredentialActionError(
                "uncached domain login denial proof is invalid")
        return result
    if (result["principal"].casefold() != expected_principal.casefold()
            or not result["authenticated"]
            or not result["local_profile_available"]
            or result["authentication_type"] not in allowed_authentication_types
            or result["failure_classification"] != "none"):
        raise WindowsCredentialActionError(
            "credential-action principal proof is invalid")
    if (action == "connected-domain-login"
            and (not result["domain_reachable"]
                 or result["authentication_semantics"] != "connected-domain"
                 or result["cache_evidence"]
                 != "online-interactive-logon")):
        raise WindowsCredentialActionError(
            "connected domain login measurement is invalid")
    if (action == "cached-domain-login"
            and (result["domain_reachable"]
                 or result["authentication_semantics"] != "cached-domain"
                 or result["cache_evidence"] != "offline-cache-proven")):
        raise WindowsCredentialActionError(
            "cached domain login measurement is invalid")
    if (action == "local-rescue-login"
            and (result["authentication_semantics"] != "local-account"
                 or result["cache_evidence"] != "not-applicable")):
        raise WindowsCredentialActionError(
            "local rescue login measurement is invalid")
    if (action == "operator-local-administrators-check"
            and (result["authentication_semantics"] not in {
                    "connected-domain", "cached-domain"}
                 or result["cache_evidence"] not in {
                    "online-interactive-logon", "offline-cache-proven"}
                 or (result["authentication_semantics"]
                     == "connected-domain") != result["controller_reachable"]
                 or (result["cache_evidence"]
                     == "online-interactive-logon")
                    != result["controller_reachable"])):
        raise WindowsCredentialActionError(
            "operator authentication measurement is invalid")
    if (action == "operator-local-administrators-check"
            and not result["local_administrators_member"]):
        raise WindowsCredentialActionError(
            "operator local Administrators membership proof is invalid")
    return result


class CredentialActionMediaChannel:
    """Own QMP attachment and exact destruction of one private ISO."""

    def __init__(self, qmp: Qmp, iso: Path, nonce: str) -> None:
        if not NONCE.fullmatch(nonce):
            raise WindowsCredentialActionError(
                "credential-action nonce is invalid")
        self.qmp = qmp
        self.iso = Path(iso)
        self.nonce = nonce
        self._identity: tuple[int, int] | None = None
        self._descriptor: int | None = None
        self.node_added = False
        self.parent_added = False
        self.child_added = False
        self.attached = False
        # High-water mark: the release path resets `attached` and every
        # *_added flag while tearing the devices down, which made attempt
        # 38's post-mortem breadcrumb read as "never attached" for a media
        # lifecycle that had in fact completed. This flag only ever rises.
        self.ever_attached = False
        self.destroyed = False
        self.state = CredentialActionMediaState.DETACHED

    def _audit_iso(self) -> os.stat_result:
        if self.iso.is_symlink() or not self.iso.is_file():
            raise WindowsCredentialActionError(
                "credential-action ISO is not a regular file")
        info = self.iso.stat()
        if stat.S_IMODE(info.st_mode) != 0o600:
            raise WindowsCredentialActionError(
                "credential-action ISO must be mode 0600")
        if stat.S_IMODE(self.iso.parent.stat().st_mode) != 0o700:
            raise WindowsCredentialActionError(
                "credential-action ISO parent must be mode 0700")
        return info

    def _prove_qemu_inode(self, expected: bool) -> None:
        verifier = getattr(self.qmp, "holds_inode", None)
        if callable(verifier):
            held = verifier(*self._identity) if self._identity else False
            if held is not expected:
                raise WindowsCredentialActionError(
                    "QEMU credential ISO inode ownership proof failed")
            return
        pid = getattr(self.qmp, "qemu_pid", None)
        if pid is None:
            raise WindowsCredentialActionError(
                "QEMU media ownership proof is unavailable")
        if not isinstance(pid, int) or pid <= 0 or self._identity is None:
            raise WindowsCredentialActionError(
                "QEMU media ownership is unavailable")
        held = False
        try:
            entries = Path(f"/proc/{pid}/fd").iterdir()
            for entry in entries:
                try:
                    info = entry.stat()
                except FileNotFoundError:
                    continue
                if (info.st_dev, info.st_ino) == self._identity:
                    held = True
                    break
        except OSError as error:
            raise WindowsCredentialActionError(
                "QEMU media ownership cannot be inspected") from error
        if held is not expected:
            raise WindowsCredentialActionError(
                "QEMU credential ISO inode ownership proof failed")

    def attach(self) -> None:
        if self.attached or self.destroyed:
            raise WindowsCredentialActionError(
                "credential-action ISO ownership state is invalid")
        info = self._audit_iso()
        try:
            descriptor = os.open(
                self.iso, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
        except OSError as error:
            raise WindowsCredentialActionError(
                "credential-action ISO ownership open failed") from error
        opened = os.fstat(descriptor)
        if (opened.st_dev, opened.st_ino) != (info.st_dev, info.st_ino):
            os.close(descriptor)
            raise WindowsCredentialActionError(
                "credential-action ISO identity changed")
        self._descriptor = descriptor
        self._identity = (opened.st_dev, opened.st_ino)
        try:
            self.qmp.execute("blockdev-add", {
                "node-name": ACTION_NODE,
                "driver": "raw",
                "read-only": True,
                "file": {"driver": "file", "filename": str(self.iso.resolve())},
            })
            self.node_added = True
            self._prove_qemu_inode(True)
            self.qmp.execute("device_add", {
                "driver": PRIVATE_MEDIA_PARENT_DEVICE, "id": ACTION_PARENT,
                "bus": PRIVATE_MEDIA_CONTROLLER_BUS,
                "port": PRIVATE_MEDIA_PORT,
                "attached": False,
            })
            self.parent_added = True
            self.qmp.execute("device_add", {
                "driver": PRIVATE_MEDIA_CHILD_DEVICE, "id": ACTION_DEVICE,
                "bus": ACTION_BUS,
                "drive": ACTION_NODE,
            })
            self.child_added = True
            self.qmp.execute("qom-set", {
                "path": f"/machine/peripheral/{ACTION_PARENT}",
                "property": "attached",
                "value": True,
            })
        except Exception as error:
            raise WindowsCredentialActionError(
                "credential-action ISO attach failed: "
                f"{type(error).__name__}") from None
        self.attached = True
        self.ever_attached = True
        self.state = CredentialActionMediaState.ATTACHED

    def _destroy_owned_iso(self) -> None:
        if self._identity is None or self._descriptor is None:
            raise WindowsCredentialActionError(
                "credential-action ISO ownership is unavailable")
        opened = os.fstat(self._descriptor)
        if (opened.st_dev, opened.st_ino) != self._identity:
            raise WindowsCredentialActionError(
                "credential-action ISO descriptor identity changed")
        matches: list[Path] = []
        for entry in self.iso.parent.iterdir():
            try:
                info = entry.lstat()
            except FileNotFoundError:
                continue
            if stat.S_ISREG(info.st_mode) and (
                    info.st_dev, info.st_ino) == self._identity:
                matches.append(entry)
        if len(matches) != 1:
            raise WindowsCredentialActionError(
                "exact credential-action ISO name is not uniquely owned")
        matches[0].unlink()
        os.close(self._descriptor)
        self._descriptor = None

    def release_after_marker(
        self,
        marker_line: str,
        *,
        await_device_deleted: Callable[[str], None],
        send_release: Callable[[str], None],
    ) -> None:
        expected = {
            "schema_version": 1,
            "event": "credential-material-loaded",
            "nonce": self.nonce,
        }
        try:
            marker = json.loads(marker_line)
        except json.JSONDecodeError as error:
            raise WindowsCredentialActionError(
                "credential-action marker is invalid") from error
        if marker != expected or not self.attached or self._identity is None:
            raise WindowsCredentialActionError(
                "credential-action marker or ownership is invalid")
        try:
            self.qmp.execute("qom-set", {
                "path": f"/machine/peripheral/{ACTION_PARENT}",
                "property": "attached",
                "value": False,
            })
            self.attached = False
            self.qmp.execute("device_del", {"id": ACTION_DEVICE})
            await_device_deleted(ACTION_DEVICE)
            self.child_added = False
            self.qmp.execute("device_del", {"id": ACTION_PARENT})
            await_device_deleted(ACTION_PARENT)
            self.parent_added = False
            self.qmp.execute("blockdev-del", {"node-name": ACTION_NODE})
            self.node_added = False
            self._prove_qemu_inode(False)
            self._destroy_owned_iso()
            self.destroyed = True
            self.state = (
                CredentialActionMediaState.DESTROYED_AWAITING_RELEASE)
            self.retry_release(send_release)
        except WindowsCredentialActionError:
            raise
        except Exception as error:
            raise WindowsCredentialActionError(
                "credential-action ISO destruction failed: "
                f"{type(error).__name__}") from None

    def retry_release(self, send_release: Callable[[str], None]) -> None:
        if self.state is CredentialActionMediaState.RELEASED:
            return
        if self.state is not (
                CredentialActionMediaState.DESTROYED_AWAITING_RELEASE):
            raise WindowsCredentialActionError(
                "credential-action release is not awaiting delivery")
        try:
            send_release(
                f"TELOS_CREDENTIAL_ACTION_MEDIA_DESTROYED {self.nonce}")
        except Exception as error:
            raise WindowsCredentialActionError(
                "credential-action release failed: "
                f"{type(error).__name__}") from None
        self.state = CredentialActionMediaState.RELEASED

    def cleanup(
        self, *, await_device_deleted: Callable[[str], None],
    ) -> None:
        failures: list[str] = []
        if self.attached:
            try:
                self.qmp.execute("qom-set", {
                    "path": f"/machine/peripheral/{ACTION_PARENT}",
                    "property": "attached",
                    "value": False,
                })
                self.attached = False
            except Exception as error:
                failures.append(f"detach: {type(error).__name__}")
        if self.child_added and not self.attached:
            try:
                self.qmp.execute("device_del", {"id": ACTION_DEVICE})
                await_device_deleted(ACTION_DEVICE)
                self.child_added = False
            except Exception as error:
                failures.append(f"device: {type(error).__name__}")
        if self.parent_added and not self.attached and not self.child_added:
            try:
                self.qmp.execute("device_del", {"id": ACTION_PARENT})
                await_device_deleted(ACTION_PARENT)
                self.parent_added = False
            except Exception as error:
                failures.append(f"parent: {type(error).__name__}")
        if (self.node_added and not self.attached
                and not self.child_added and not self.parent_added):
            try:
                self.qmp.execute("blockdev-del", {"node-name": ACTION_NODE})
                self.node_added = False
                self._prove_qemu_inode(False)
            except Exception as error:
                failures.append(f"node: {type(error).__name__}")
        if (not self.attached and not self.node_added
                and self._descriptor is not None):
            try:
                self._destroy_owned_iso()
                self.destroyed = True
                self.state = (
                    CredentialActionMediaState.DESTROYED_AWAITING_RELEASE)
            except Exception as error:
                failures.append(f"ISO: {type(error).__name__}")
        if failures:
            raise WindowsCredentialActionError(
                "credential-action ISO cleanup failed; " + "; ".join(failures))


def execute_credential_action(
    *,
    channel: CredentialActionMediaChannel,
    serial: DuplexCredentialActionSerial,
    action: str,
    expected_principal: str,
    allowed_authentication_types: frozenset[str],
    launch_guest: Callable[[str], None],
    await_device_deleted: Callable[[str], None],
) -> dict[str, object]:
    """Run one complete private handoff and public proof on one COM1 session."""
    try:
        channel.attach()
        # A channel that reaches the guest launch unattached would leave
        # the guest polling for a volume that never existed; fail closed
        # BEFORE the launch instead of letting the poll die.
        if not getattr(channel, "attached", False):
            raise WindowsCredentialActionError(
                "credential-action media is not attached before launch")
        launch_guest(launch_credential_action_command())
        # The first read stays a raw timeout when nothing ever arrives:
        # that is the "launcher or script never reported" class.
        marker = serial.read_line()
        script_started = False
        if marker.rstrip("\n") == SCRIPT_STARTED_EVENT:
            script_started = True
            try:
                marker = serial.read_line()
            except TimeoutError:
                raise WindowsCredentialActionError(
                    "credential-action script started but delivered "
                    "no material marker") from None
        failed = _script_failed_detail(marker.rstrip("\n"))
        if failed is not None:
            _raise_script_failed(
                "before releasing material"
                + (" after starting" if script_started else ""),
                failed,
            )
        channel.release_after_marker(
            marker,
            await_device_deleted=await_device_deleted,
            send_release=serial.send_release,
        )
        result_line = serial.read_line()
        failed = _script_failed_detail(result_line.rstrip("\n"))
        if failed is not None:
            _raise_script_failed("after material release", failed)
        result = parse_action_result(
            result_line,
            nonce=channel.nonce,
            action=action,
            expected_principal=expected_principal,
            allowed_authentication_types=allowed_authentication_types,
        )
    except BaseException as error:
        serial.close()
        try:
            channel.cleanup(await_device_deleted=await_device_deleted)
        except Exception as cleanup:
            raise WindowsCredentialActionError(
                "credential action and private cleanup failed: "
                f"{type(error).__name__}; {type(cleanup).__name__}"
            ) from None
        raise
    serial.close()
    return result
