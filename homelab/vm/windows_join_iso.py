#!/usr/bin/env python3
"""One-use private ISO and destruction-before-domain-join protocol."""

from __future__ import annotations

import json
import os
from pathlib import Path
import re
import shutil
import socket
import stat
import subprocess
import tempfile
import time
from dataclasses import dataclass
from enum import Enum
from typing import Callable, Mapping, Protocol

from .windows_identity_contract import (
    PRIVATE_MEDIA_CHILD_DEVICE,
    PRIVATE_MEDIA_CONTROLLER_BUS,
    PRIVATE_MEDIA_PARENT_DEVICE,
    PRIVATE_MEDIA_PORT,
)
from .windows_public_command import bounded_media_launch_command
from .windows_postsubmit_diagnostic import (
    PostSubmitDiagnosticCleanup,
    PostSubmitDiagnosticCode,
    PostSubmitDiagnosticCollection,
)
from .controller_auth_diagnostic import (
    ControllerAuthArmSubphase,
    ControllerAuthCollection,
    ControllerAuthReceiveObservation,
    ControllerAuthResult,
)

UAC_CONSENT_SETTLE_DELAY = 3.0
UAC_NAVIGATION_SETTLE_DELAY = 0.25


@dataclass(frozen=True)
class WindowsJoinFailureCoordinate:
    """Allowlisted, secret-free guest join protocol failure location."""

    phase: str
    error_type: str
    post_submit_diagnostic: str | None = None
    post_submit_collection: str | None = None
    post_submit_cleanup: str | None = None
    controller_auth: ControllerAuthResult | None = None
    controller_auth_arm_subphase: ControllerAuthArmSubphase | None = None
    controller_auth_receive_observation: (
        ControllerAuthReceiveObservation | None) = None

    _PHASES = frozenset({
        "serial-connect", "prepare", "attach", "launch",
        "elevation-receive", "elevation-parse", "marker-receive",
        "media-destroy", "release", "result-receive", "result-parse",
        "result-ack", "accepted-receive", "accepted-parse",
        "result", "reboot-reauth",
        "reboot-probe", "cleanup",
        "result-guest-add-computer", "result-guest-operator-resolution",
        "result-guest-operator-mutation",
        "result-guest-operator-verification",
        "marker-guest-diagnostic-source",
        "result-guest-join-authorization",
        "result-guest-join-authentication",
        "result-guest-join-domain-discovery",
        "result-guest-join-account-conflict",
        "result-guest-join-unclassified",
        "result-guest-policy-mutation", "result-guest-policy-readback",
        "result-guest-policy-verification", "result-guest-reboot-ack",
    }) | frozenset(
        f"reboot-reauth-{operation}"
        for operation in (
            "wake", "calibration-capture", "calibration-required",
            "select-local-account", "type-public-username",
            "prove-password-target", "submit-focus-calibration",
            "controller-auth-arm",
            "diagnostic-arm", "diagnostic-arm-preflight",
            "diagnostic-arm-connect", "diagnostic-arm-launch",
            "diagnostic-arm-receive", "diagnostic-arm-parse",
            "diagnostic-arm-guest", "diagnostic-cleanup", "type-secret",
            "submit", "desktop",
            "desktop-near-reference",
            "desktop-sign-in-persisted",
            "desktop-sign-in-near-reference",
        )
    )
    _ERROR_TYPES = frozenset({
        "OSError", "TimeoutError", "WindowsJoinIsoError",
        "WindowsIdentityAdapterError", "WindowsIdentityGuiError",
        "WindowsIdentityOrchestratorError",
        "WindowsLocalReauthenticationError", "WindowsPublicCommandError",
        "UnexpectedError",
    })

    def __post_init__(self) -> None:
        if self.phase not in self._PHASES or self.error_type not in self._ERROR_TYPES:
            raise ValueError("Windows join failure coordinate is invalid")
        if (
            self.post_submit_diagnostic is not None
            and (
                type(self.post_submit_diagnostic) is not str
                or self.post_submit_diagnostic not in {
                    code.value for code in PostSubmitDiagnosticCode
                }
                or self.phase not in {
                    "reboot-reauth-desktop",
                    "reboot-reauth-diagnostic-cleanup",
                    "reboot-reauth-desktop-near-reference",
                    "reboot-reauth-desktop-sign-in-persisted",
                    "reboot-reauth-desktop-sign-in-near-reference",
                }
                or self.error_type
                != "WindowsLocalReauthenticationError"
            )
        ):
            raise ValueError("Windows join diagnostic is invalid")
        if (
            self.post_submit_collection is not None
            and (
                type(self.post_submit_collection) is not str
                or self.post_submit_collection not in {
                    code.value for code in PostSubmitDiagnosticCollection
                }
                or self.phase not in {
                    "reboot-reauth-desktop",
                    "reboot-reauth-diagnostic-cleanup",
                    "reboot-reauth-desktop-near-reference",
                    "reboot-reauth-desktop-sign-in-persisted",
                    "reboot-reauth-desktop-sign-in-near-reference",
                }
                or self.error_type
                != "WindowsLocalReauthenticationError"
            )
        ):
            raise ValueError("Windows join collection is invalid")
        if (
            self.post_submit_cleanup is not None
            and (
                type(self.post_submit_cleanup) is not str
                or self.post_submit_cleanup not in {
                    code.value for code in PostSubmitDiagnosticCleanup
                }
                or self.phase not in {
                    "reboot-reauth-desktop",
                    "reboot-reauth-diagnostic-cleanup",
                    "reboot-reauth-desktop-near-reference",
                    "reboot-reauth-desktop-sign-in-persisted",
                    "reboot-reauth-desktop-sign-in-near-reference",
                }
                or self.error_type
                != "WindowsLocalReauthenticationError"
            )
        ):
            raise ValueError("Windows join cleanup is invalid")
        if (
            self.controller_auth is not None
            and (
                type(self.controller_auth) is not ControllerAuthResult
                or self.phase not in {
                    "reboot-reauth-controller-auth-arm",
                    "reboot-reauth-diagnostic-cleanup",
                    "reboot-reauth-desktop",
                    "reboot-reauth-desktop-near-reference",
                    "reboot-reauth-desktop-sign-in-persisted",
                    "reboot-reauth-desktop-sign-in-near-reference",
                }
                or self.error_type
                != "WindowsLocalReauthenticationError"
            )
        ):
            raise ValueError("Controller auth diagnostic is invalid")
        if (
            self.controller_auth_arm_subphase is not None
            and (
                type(self.controller_auth_arm_subphase)
                is not ControllerAuthArmSubphase
                or (
                    self.phase != "reboot-reauth-controller-auth-arm"
                    # A proved-cleanup arm failure lets the GUI continue
                    # without a watcher; the subphase then explains the
                    # unavailable receipt at the coordinate the attempt
                    # actually reached.
                    and not (
                        self.controller_auth is not None
                        and self.controller_auth.collection
                        is ControllerAuthCollection.RECEIPT_UNAVAILABLE
                    )
                )
                or self.error_type
                != "WindowsLocalReauthenticationError"
            )
        ):
            raise ValueError("Controller auth arm subphase is invalid")
        if (
            self.controller_auth_receive_observation is not None
            and (
                type(self.controller_auth_receive_observation)
                is not ControllerAuthReceiveObservation
                or self.controller_auth_arm_subphase
                is not ControllerAuthArmSubphase.RECEIVE
            )
        ):
            raise ValueError(
                "Controller auth receive observation is invalid")
        if (
            self.controller_auth_arm_subphase
            is ControllerAuthArmSubphase.RECEIVE
            and self.controller_auth_receive_observation is None
        ):
            raise ValueError(
                "Controller auth receive observation is missing")


class WindowsJoinIsoError(RuntimeError):
    """The private join channel failed closed."""

    def __init__(
        self,
        message: str,
        *,
        coordinate: WindowsJoinFailureCoordinate | None = None,
        cleanup_coordinate: WindowsJoinFailureCoordinate | None = None,
        diagnostic: object | None = None,
    ) -> None:
        super().__init__(message)
        self.coordinate = coordinate
        self.cleanup_coordinate = cleanup_coordinate
        self.diagnostic = diagnostic


def _join_error(phase: str, error: BaseException) -> WindowsJoinIsoError:
    error_type = type(error).__name__
    if isinstance(error, (TimeoutError, socket.timeout)):
        error_type = "TimeoutError"
    elif isinstance(error, OSError):
        error_type = "OSError"
    if error_type not in WindowsJoinFailureCoordinate._ERROR_TYPES:
        error_type = "UnexpectedError"
    coordinate = WindowsJoinFailureCoordinate(phase, error_type)
    return WindowsJoinIsoError(
        f"Windows join protocol failed; phase={phase}; error={error_type}",
        coordinate=coordinate,
    )


CONTROL_ROOT = Path(__file__).with_name("windows_join_control")
SCRIPT = CONTROL_ROOT / "TelosJoin.ps1"
POST_SUBMIT_DIAGNOSTIC_SCRIPT = (
    CONTROL_ROOT / "TelosPostSubmitDiagnostic.ps1"
)
NONCE = re.compile(r"[a-f0-9]{32}")
DOMAIN = re.compile(
    r"(?=.{1,253}\Z)(?![-.])(?:[A-Za-z0-9-]+\.)*[A-Za-z0-9-]+"
)
REALM = re.compile(
    r"(?=.{1,253}\Z)(?![-.])(?:[A-Z0-9-]+\.)*[A-Z0-9-]+"
)
OPERATOR = re.compile(
    r"operator@(?=.{1,253}\Z)(?![-.])(?:[A-Z0-9-]+\.)*[A-Z0-9-]+"
)
JOIN_USERNAME = re.compile(
    r"tj-[a-f0-9]{16}@(?=.{1,253}\Z)(?![-.])"
    r"(?:[A-Z0-9-]+\.)*[A-Z0-9-]+"
)
JOIN_NODE = "telos-join-media"
JOIN_DEVICE = "telos-join-cd"
JOIN_PARENT = "telos-join-bot"
JOIN_BUS = f"{JOIN_PARENT}.0"


class Qmp(Protocol):
    def execute(
        self, command: str, arguments: dict | None = None,
    ) -> Mapping[str, object]: ...


class JoinMediaState(Enum):
    DETACHED = "detached"
    ATTACHED = "attached"
    DESTROYED_AWAITING_RELEASE = "destroyed-awaiting-release"
    RELEASED = "released"
    REBOOT_READY = "reboot-ready"
    REBOOT_ACCEPTED = "reboot-accepted"


class DuplexJoinSerial:
    """One bounded duplex COM1 connection for marker and release."""

    def __init__(
        self,
        connection: socket.socket,
        *,
        maximum_line: int = 1024,
        timeout: float = 120.0,
        clock: Callable[[], float] = time.monotonic,
    ):
        if not 64 <= maximum_line <= 4096:
            raise WindowsJoinIsoError("serial line bound is invalid")
        if not 0 < timeout <= 300:
            raise WindowsJoinIsoError("serial timeout is invalid")
        self.connection = connection
        self.maximum_line = maximum_line
        self._clock = clock
        self._deadline = clock() + timeout
        self.closed = False

    @classmethod
    def connect(
        cls, path: Path, *, timeout: float = 120.0,
    ) -> "DuplexJoinSerial":
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
            raise WindowsJoinIsoError("join serial deadline expired")
        self.connection.settimeout(remaining)

    def _read_line(self, kind: str) -> str:
        if self.closed:
            raise WindowsJoinIsoError("join serial is closed")
        data = bytearray()
        while len(data) <= self.maximum_line:
            self._set_operation_timeout()
            chunk = self.connection.recv(1)
            if not chunk:
                raise WindowsJoinIsoError(
                    f"join serial closed before {kind}")
            if chunk == b"\n":
                try:
                    return data.rstrip(b"\r").decode("ascii")
                except UnicodeDecodeError as error:
                    raise WindowsJoinIsoError(
                        f"join {kind} is not ASCII") from error
            data.extend(chunk)
        raise WindowsJoinIsoError(f"join {kind} exceeds bound")

    def read_marker(self) -> str:
        return self._read_line("marker")

    def read_result(self) -> str:
        return self._read_line("result")

    def send_release(self, line: str) -> None:
        if self.closed:
            raise WindowsJoinIsoError("join serial is closed")
        encoded = (line + "\n").encode("ascii")
        if len(encoded) > self.maximum_line:
            raise WindowsJoinIsoError("join release exceeds bound")
        self._set_operation_timeout()
        self.connection.sendall(encoded)

    def send_reboot_ack(self, nonce: str) -> None:
        self.send_release(f"TELOS_JOIN_REBOOT_ACK {nonce}")

    def close(self) -> None:
        if not self.closed:
            self.connection.close()
            self.closed = True

    def __enter__(self) -> "DuplexJoinSerial":
        return self

    def __exit__(self, *_args: object) -> None:
        self.close()


def _regular_private_parent(path: Path) -> Path:
    parent = path.resolve()
    if (path.is_symlink() or not parent.is_dir()
            or stat.S_IMODE(parent.stat().st_mode) != 0o700):
        raise WindowsJoinIsoError(
            "join ISO parent must be a private mode-0700 directory")
    return parent


def _validate_material(material: Mapping[str, str]) -> dict[str, str]:
    if set(material) != {
        "nonce", "domain", "realm", "username", "password", "operator",
    }:
        raise WindowsJoinIsoError("join material fields are invalid")
    values = dict(material)
    if not NONCE.fullmatch(values["nonce"]):
        raise WindowsJoinIsoError("join nonce is invalid")
    if not DOMAIN.fullmatch(values["domain"]):
        raise WindowsJoinIsoError("join domain is invalid")
    if (not REALM.fullmatch(values["realm"])
            or values["realm"] != values["domain"].upper()):
        raise WindowsJoinIsoError("join realm is invalid")
    if (not OPERATOR.fullmatch(values["operator"])
            or values["operator"] != f"operator@{values['realm']}"):
        raise WindowsJoinIsoError("join operator is invalid")
    if (
        not isinstance(values["username"], str)
        or not JOIN_USERNAME.fullmatch(values["username"])
        or values["username"].rsplit("@", 1)[1] != values["realm"]
    ):
        raise WindowsJoinIsoError("join username is invalid")
    password = values["password"]
    if (not isinstance(password, str) or not password
            or len(password) > 512 or "\r" in password or "\n" in password):
        raise WindowsJoinIsoError("join password is invalid")
    return values


def build_join_iso(
    output: Path,
    material: Mapping[str, str],
    *,
    runner=subprocess.run,
) -> Path:
    """Build a mode-0600 ISO without exposing join material in argv."""
    output = Path(output)
    if output.exists() or output.is_symlink():
        raise WindowsJoinIsoError("join ISO destination must be absent")
    parent = _regular_private_parent(output.parent)
    values = _validate_material(material)
    assets = (SCRIPT, POST_SUBMIT_DIAGNOSTIC_SCRIPT)
    if any(asset.is_symlink() or not asset.is_file() for asset in assets):
        raise WindowsJoinIsoError("join script assets are unavailable")
    with tempfile.TemporaryDirectory(
            prefix=".windows-join-", dir=parent) as temporary:
        temporary_root = Path(temporary)
        temporary_root.chmod(0o700)
        stage = temporary_root / "payload"
        stage.mkdir(mode=0o700)
        for asset in assets:
            shutil.copyfile(asset, stage / asset.name)
            (stage / asset.name).chmod(0o400)
        join = stage / "join.json"
        descriptor = os.open(
            join, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o400)
        try:
            with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
                json.dump(
                    {"schema_version": 2, **values},
                    stream, separators=(",", ":"), sort_keys=True)
                stream.write("\n")
        except BaseException:
            try:
                os.close(descriptor)
            except OSError:
                pass
            raise
        partial = temporary_root / "join.iso"
        # Only non-secret paths and fixed switches cross the process boundary.
        runner([
            "xorriso", "-as", "mkisofs", "-quiet",
            "-V", "TELOS_JOIN", "-J", "-r",
            "-o", str(partial), str(stage),
        ], check=True)
        if partial.is_symlink() or not partial.is_file():
            raise WindowsJoinIsoError("xorriso did not create the join ISO")
        partial.chmod(0o600)
        partial.replace(output)
    output.chmod(0o600)
    return output


def launch_join_command() -> str:
    """Return fixed, secret-free PowerShell suitable for GUI injection."""
    return bounded_media_launch_command(
        "TELOS_JOIN", "TelosJoin.ps1",
    )


class JoinMediaChannel:
    """Own attachment and exact destruction of one private join ISO."""

    def __init__(self, qmp: Qmp, iso: Path, nonce: str) -> None:
        self.qmp = qmp
        self.iso = Path(iso)
        if not NONCE.fullmatch(nonce):
            raise WindowsJoinIsoError("join nonce is invalid")
        self.nonce = nonce
        self._identity: tuple[int, int] | None = None
        self._descriptor: int | None = None
        self.node_added = False
        self.parent_added = False
        self.child_added = False
        self.attached = False
        self.destroyed = False
        self.state = JoinMediaState.DETACHED

    def _audit_iso(self) -> os.stat_result:
        if self.iso.is_symlink() or not self.iso.is_file():
            raise WindowsJoinIsoError("join ISO is not a regular file")
        info = self.iso.stat()
        if stat.S_IMODE(info.st_mode) != 0o600:
            raise WindowsJoinIsoError("join ISO must be mode 0600")
        if stat.S_IMODE(self.iso.parent.stat().st_mode) != 0o700:
            raise WindowsJoinIsoError("join ISO parent must be mode 0700")
        return info

    def _prove_qemu_inode(self, expected: bool) -> None:
        verifier = getattr(self.qmp, "holds_inode", None)
        if callable(verifier):
            held = verifier(*self._identity) if self._identity else False
            if held is not expected:
                raise WindowsJoinIsoError(
                    "QEMU join ISO inode ownership proof failed")
            return
        pid = getattr(self.qmp, "qemu_pid", None)
        if pid is None:
            raise WindowsJoinIsoError(
                "QEMU media ownership proof is unavailable")
        if not isinstance(pid, int) or pid <= 0 or self._identity is None:
            raise WindowsJoinIsoError("QEMU media ownership is unavailable")
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
            raise WindowsJoinIsoError(
                "QEMU media ownership cannot be inspected") from error
        if held is not expected:
            raise WindowsJoinIsoError(
                "QEMU join ISO inode ownership proof failed")

    def attach(self) -> None:
        if self.attached or self.destroyed:
            raise WindowsJoinIsoError("join ISO ownership state is invalid")
        info = self._audit_iso()
        try:
            descriptor = os.open(
                self.iso, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
        except OSError as error:
            raise WindowsJoinIsoError("join ISO ownership open failed") from error
        opened = os.fstat(descriptor)
        if (opened.st_dev, opened.st_ino) != (info.st_dev, info.st_ino):
            os.close(descriptor)
            raise WindowsJoinIsoError("join ISO identity changed")
        self._descriptor = descriptor
        self._identity = (opened.st_dev, opened.st_ino)
        try:
            self.qmp.execute("blockdev-add", {
                "node-name": JOIN_NODE,
                "driver": "raw",
                "read-only": True,
                "file": {
                    "driver": "file",
                    "filename": str(self.iso.resolve()),
                },
            })
            self.node_added = True
            self._prove_qemu_inode(True)
            self.qmp.execute("device_add", {
                "driver": PRIVATE_MEDIA_PARENT_DEVICE,
                "id": JOIN_PARENT,
                "bus": PRIVATE_MEDIA_CONTROLLER_BUS,
                "port": PRIVATE_MEDIA_PORT,
                "attached": False,
            })
            self.parent_added = True
            self.qmp.execute("device_add", {
                "driver": PRIVATE_MEDIA_CHILD_DEVICE,
                "id": JOIN_DEVICE,
                "bus": JOIN_BUS,
                "drive": JOIN_NODE,
            })
            self.child_added = True
            self.qmp.execute("qom-set", {
                "path": f"/machine/peripheral/{JOIN_PARENT}",
                "property": "attached",
                "value": True,
            })
        except Exception as error:
            # Ownership remains with this object so the caller can retry
            # teardown.  Never include QMP text, which may contain paths.
            raise WindowsJoinIsoError(
                f"join ISO attach failed: {type(error).__name__}") from None
        self.attached = True
        self.state = JoinMediaState.ATTACHED

    def _destroy_owned_iso(self) -> None:
        """Unlink the held inode by its exact name inside the private parent."""
        if self._identity is None or self._descriptor is None:
            raise WindowsJoinIsoError("join ISO ownership is unavailable")
        opened = os.fstat(self._descriptor)
        if (opened.st_dev, opened.st_ino) != self._identity:
            raise WindowsJoinIsoError("join ISO descriptor identity changed")
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
            raise WindowsJoinIsoError(
                "exact join ISO name is not uniquely owned")
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
        """Destroy exact media, then and only then release guest mutation."""
        expected = {
            "schema_version": 1,
            "event": "join-material-loaded",
            "nonce": self.nonce,
        }
        try:
            marker = json.loads(marker_line)
        except json.JSONDecodeError as error:
            raise WindowsJoinIsoError("join marker is invalid") from error
        failure = {
            "schema_version": 1,
            "event": "join-material-failed",
            "nonce": self.nonce,
            "phase": "diagnostic-source",
        }
        if marker == failure and self.attached and self._identity is not None:
            raise WindowsJoinIsoError(
                "guest failed to load the post-submit diagnostic source",
                coordinate=WindowsJoinFailureCoordinate(
                    "marker-guest-diagnostic-source",
                    "WindowsJoinIsoError",
                ),
            )
        if marker != expected or not self.attached or self._identity is None:
            raise WindowsJoinIsoError("join marker or ownership is invalid")
        try:
            self.qmp.execute("qom-set", {
                "path": f"/machine/peripheral/{JOIN_PARENT}",
                "property": "attached",
                "value": False,
            })
            self.attached = False
            self.qmp.execute("device_del", {"id": JOIN_DEVICE})
            await_device_deleted(JOIN_DEVICE)
            self.child_added = False
            self.qmp.execute("device_del", {"id": JOIN_PARENT})
            await_device_deleted(JOIN_PARENT)
            self.parent_added = False
            self.qmp.execute("blockdev-del", {"node-name": JOIN_NODE})
            self.node_added = False
            self._prove_qemu_inode(False)
            self._destroy_owned_iso()
            self.destroyed = True
            self.state = JoinMediaState.DESTROYED_AWAITING_RELEASE
            self.retry_release(send_release)
        except WindowsJoinIsoError:
            raise
        except Exception as error:
            raise WindowsJoinIsoError(
                f"join ISO destruction failed: {type(error).__name__}"
            ) from None

    def accept_elevation_requested(self, line: str) -> None:
        """Bind public UAC input to the exact non-elevated bootstrap."""
        try:
            event = json.loads(line)
        except json.JSONDecodeError as error:
            raise WindowsJoinIsoError(
                "join elevation request is invalid") from error
        if event != {
            "schema_version": 1,
            "event": "join-elevation-requested",
            "nonce": self.nonce,
        } or not self.attached:
            raise WindowsJoinIsoError("join elevation request is invalid")

    def retry_release(self, send_release: Callable[[str], None]) -> None:
        """Idempotently retry only the public release after exact destruction."""
        if self.state is JoinMediaState.RELEASED:
            return
        if self.state is not JoinMediaState.DESTROYED_AWAITING_RELEASE:
            raise WindowsJoinIsoError(
                "join release is not awaiting delivery")
        try:
            send_release(f"TELOS_JOIN_MEDIA_DESTROYED {self.nonce}")
        except Exception as error:
            raise WindowsJoinIsoError(
                f"join release failed: {type(error).__name__}") from None
        self.state = JoinMediaState.RELEASED

    def cleanup(
        self, *, await_device_deleted: Callable[[str], None],
    ) -> None:
        """Tear down owned media after a failed or interrupted protocol."""
        failures: list[str] = []
        if self.attached:
            try:
                self.qmp.execute("qom-set", {
                    "path": f"/machine/peripheral/{JOIN_PARENT}",
                    "property": "attached",
                    "value": False,
                })
                self.attached = False
            except Exception as error:
                failures.append(f"detach: {type(error).__name__}")
        if self.child_added and not self.attached:
            try:
                self.qmp.execute("device_del", {"id": JOIN_DEVICE})
                await_device_deleted(JOIN_DEVICE)
                self.child_added = False
            except Exception as error:
                failures.append(f"device: {type(error).__name__}")
        if self.parent_added and not self.attached and not self.child_added:
            try:
                self.qmp.execute("device_del", {"id": JOIN_PARENT})
                await_device_deleted(JOIN_PARENT)
                self.parent_added = False
            except Exception as error:
                failures.append(f"parent: {type(error).__name__}")
        if (self.node_added and not self.attached
                and not self.child_added and not self.parent_added):
            try:
                self.qmp.execute("blockdev-del", {"node-name": JOIN_NODE})
                self.node_added = False
                self._prove_qemu_inode(False)
            except Exception as error:
                failures.append(f"node: {type(error).__name__}")
        if (not self.attached and not self.node_added
                and self._descriptor is not None):
            try:
                self._destroy_owned_iso()
                self.destroyed = True
                self.state = JoinMediaState.DESTROYED_AWAITING_RELEASE
            except Exception as error:
                failures.append(f"ISO: {type(error).__name__}")
        if failures:
            raise WindowsJoinIsoError(
                "join ISO cleanup failed; " + "; ".join(failures))

    def prove_join_and_reboot(
        self,
        probe: Callable[[], Mapping[str, object]],
        *,
        expected_domain: str,
    ) -> dict[str, object]:
        """Accept only a post-reboot, static-probe domain-membership proof."""
        if self.state is not JoinMediaState.REBOOT_ACCEPTED:
            raise WindowsJoinIsoError(
                "join result cannot be proved before reboot acceptance")
        try:
            result = dict(probe())
        except BaseException as error:
            if (
                isinstance(error, WindowsJoinIsoError)
                and (
                    error.coordinate is not None
                    or error.diagnostic is not None
                )
            ):
                raise error from None
            raise _join_error("reboot-probe", error) from None
        if result != {
            "schema_version": 2,
            "boot_completed": True,
            "domain_joined": True,
            "domain": expected_domain,
            "operator": f"operator@{expected_domain.upper()}",
            "operator_local_administrator": True,
        }:
            raise _join_error(
                "result", WindowsJoinIsoError(
                    "join/reboot proof is invalid")) from None
        return {
            "schema_version": 1,
            "join_media_destroyed": True,
            "joined_after_reboot": True,
            "domain": expected_domain,
            "operator": f"operator@{expected_domain.upper()}",
            "operator_local_administrator": True,
        }

    def accept_reboot_ready(self, result_line: str) -> None:
        """Accept the nonce-bound guest result only after media release."""
        if self.state is not JoinMediaState.RELEASED:
            raise WindowsJoinIsoError(
                "join reboot readiness cannot precede mutation release")
        try:
            result = json.loads(result_line)
        except json.JSONDecodeError as error:
            raise WindowsJoinIsoError(
                "join reboot-ready result is invalid") from error
        expected = {
            "schema_version": 1,
            "event": "join-reboot-ready",
            "nonce": self.nonce,
        }
        if result == expected:
            self.state = JoinMediaState.REBOOT_READY
            return
        guest_failure = {
            "schema_version": 1,
            "event": "join-reboot-failed",
            "nonce": self.nonce,
        }
        phase = result.get("phase")
        if (
            set(result) == {*guest_failure, "phase"}
            and all(result[name] == value for name, value in guest_failure.items())
            and phase in {
                "add-computer", "operator-resolution", "operator-mutation",
                "operator-verification", "diagnostic-staging",
                "policy-mutation",
                "policy-readback", "policy-verification",
                "join-authorization", "join-authentication",
                "join-domain-discovery", "join-account-conflict",
                "join-unclassified",
            }
        ):
            coordinate = WindowsJoinFailureCoordinate(
                f"result-guest-{phase}", "WindowsJoinIsoError")
            raise WindowsJoinIsoError(
                "guest reported a pre-reboot join failure",
                coordinate=coordinate,
            )
        else:
            raise WindowsJoinIsoError(
                "join reboot-ready result is invalid")

    def accept_reboot_confirmation(self, result_line: str) -> None:
        """Prove that the guest consumed the host's exact reboot ACK."""
        if self.state is not JoinMediaState.REBOOT_READY:
            raise WindowsJoinIsoError(
                "join reboot acceptance cannot precede reboot readiness")
        try:
            result = json.loads(result_line)
        except json.JSONDecodeError as error:
            raise WindowsJoinIsoError(
                "join reboot-accepted result is invalid") from error
        if result == {
            "schema_version": 1,
            "event": "join-reboot-accepted",
            "nonce": self.nonce,
        }:
            self.state = JoinMediaState.REBOOT_ACCEPTED
            return
        if result == {
            "schema_version": 1,
            "event": "join-reboot-failed",
            "nonce": self.nonce,
            "phase": "reboot-ack",
        }:
            raise WindowsJoinIsoError(
                "guest rejected the reboot acknowledgment",
                coordinate=WindowsJoinFailureCoordinate(
                    "result-guest-reboot-ack", "WindowsJoinIsoError"),
            )
        raise WindowsJoinIsoError(
            "join reboot-accepted result is invalid")


def execute_join_channel(
    *,
    channel: JoinMediaChannel,
    serial: DuplexJoinSerial,
    launch_guest: Callable[[str], None],
    await_device_deleted: Callable[[str], None],
    pause: Callable[[float], None] | None = None,
) -> None:
    """Run the production handoff over one exclusive duplex COM1 session."""
    if pause is None:
        pause = time.sleep
    try:
        channel.attach()
    except BaseException as error:
        raise _join_error("attach", error) from None
    try:
        try:
            launch_guest(launch_join_command())
        except BaseException as error:
            raise _join_error("launch", error) from None
        try:
            elevation = serial.read_marker()
        except BaseException as error:
            raise _join_error("elevation-receive", error) from None
        try:
            channel.accept_elevation_requested(elevation)
        except BaseException as error:
            raise _join_error("elevation-parse", error) from None
        try:
            # RunAs switches to the secure desktop asynchronously after the
            # exact bootstrap receipt. Give that transition a bounded settle
            # interval before navigating from the default No button to Yes.
            pause(UAC_CONSENT_SETTLE_DELAY)
            channel.qmp.execute("send-key", {
                "keys": [{"type": "qcode", "data": "left"}],
                "hold-time": 60,
            })
            pause(UAC_NAVIGATION_SETTLE_DELAY)
            channel.qmp.execute("send-key", {
                "keys": [{"type": "qcode", "data": "ret"}],
                "hold-time": 60,
            })
        except BaseException as error:
            raise _join_error("launch", error) from None
        try:
            marker = serial.read_marker()
        except BaseException as error:
            raise _join_error("marker-receive", error) from None
        try:
            channel.release_after_marker(
                marker,
                await_device_deleted=await_device_deleted,
                send_release=serial.send_release,
            )
        except BaseException as error:
            if (
                isinstance(error, WindowsJoinIsoError)
                and error.coordinate is not None
            ):
                raise error from None
            phase = (
                "release"
                if channel.state is JoinMediaState.DESTROYED_AWAITING_RELEASE
                else "media-destroy"
            )
            raise _join_error(phase, error) from None
        try:
            result = serial.read_result()
        except BaseException as error:
            raise _join_error("result-receive", error) from None
        try:
            channel.accept_reboot_ready(result)
        except BaseException as error:
            if (
                isinstance(error, WindowsJoinIsoError)
                and error.coordinate is not None
            ):
                raise error from None
            raise _join_error("result-parse", error) from None
        try:
            serial.send_reboot_ack(channel.nonce)
        except BaseException as error:
            raise _join_error("result-ack", error) from None
        try:
            accepted = serial.read_result()
        except BaseException as error:
            raise _join_error("accepted-receive", error) from None
        try:
            channel.accept_reboot_confirmation(accepted)
        except BaseException as error:
            if (
                isinstance(error, WindowsJoinIsoError)
                and error.coordinate is not None
            ):
                raise error from None
            raise _join_error("accepted-parse", error) from None
        # The guest emits readiness after proving every pre-reboot mutation.
        # Release COM1 before Restart-Computer and the later probes reuse it.
        serial.close()
    except BaseException:
        # The caller still owns channel and serial and may invoke cleanup or
        # retry_release.  This helper never opens a second COM1 connection.
        raise


def execute_join_and_prove(
    *,
    channel: JoinMediaChannel,
    serial: DuplexJoinSerial,
    launch_guest: Callable[[str], None],
    await_device_deleted: Callable[[str], None],
    probe_after_reboot: Callable[[], Mapping[str, object]],
    expected_domain: str,
    pause: Callable[[float], None] | None = None,
) -> dict[str, object]:
    """Serialize private COM1 handoff before the public reboot proof."""
    execute_join_channel(
        channel=channel,
        serial=serial,
        launch_guest=launch_guest,
        await_device_deleted=await_device_deleted,
        pause=pause,
    )
    if not serial.closed:
        raise WindowsJoinIsoError(
            "private COM1 session remains open before public probe")
    try:
        return channel.prove_join_and_reboot(
            probe_after_reboot, expected_domain=expected_domain)
    except BaseException as error:
        if (
            isinstance(error, WindowsJoinIsoError)
            and (
                error.coordinate is not None
                or error.diagnostic is not None
            )
        ):
            raise error from None
        phase = "reboot-probe"
        raise _join_error(phase, error) from None
