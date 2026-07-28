#!/usr/bin/env python3
"""One-use private ISO and destruction-before-domain-join protocol."""

from __future__ import annotations

import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import tempfile
from typing import Callable, Mapping, Protocol


class WindowsJoinIsoError(RuntimeError):
    """The private join channel failed closed."""


SCRIPT = (
    Path(__file__).with_name("windows_join_control")
    / "Invoke-TelosDomainJoin.ps1"
)
NONCE = re.compile(r"[a-f0-9]{32}")
DOMAIN = re.compile(
    r"(?=.{1,253}\Z)(?![-.])(?:[A-Za-z0-9-]+\.)*[A-Za-z0-9-]+"
)
JOIN_NODE = "telos-join-media"
JOIN_DEVICE = "telos-join-cd"
JOIN_BUS = "controlbus.0"


class Qmp(Protocol):
    def execute(
        self, command: str, arguments: dict | None = None,
    ) -> Mapping[str, object]: ...


def _regular_private_parent(path: Path) -> Path:
    parent = path.resolve()
    if (path.is_symlink() or not parent.is_dir()
            or stat.S_IMODE(parent.stat().st_mode) != 0o700):
        raise WindowsJoinIsoError(
            "join ISO parent must be a private mode-0700 directory")
    return parent


def _validate_material(material: Mapping[str, str]) -> dict[str, str]:
    if set(material) != {"nonce", "domain", "username", "password"}:
        raise WindowsJoinIsoError("join material fields are invalid")
    values = dict(material)
    if not NONCE.fullmatch(values["nonce"]):
        raise WindowsJoinIsoError("join nonce is invalid")
    if not DOMAIN.fullmatch(values["domain"]):
        raise WindowsJoinIsoError("join domain is invalid")
    for name in ("username", "password"):
        value = values[name]
        if (not isinstance(value, str) or not value
                or len(value) > 512 or "\r" in value or "\n" in value):
            raise WindowsJoinIsoError(f"join {name} is invalid")
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
    if SCRIPT.is_symlink() or not SCRIPT.is_file():
        raise WindowsJoinIsoError("join script is unavailable")
    with tempfile.TemporaryDirectory(
            prefix=".windows-join-", dir=parent) as temporary:
        temporary_root = Path(temporary)
        temporary_root.chmod(0o700)
        stage = temporary_root / "payload"
        stage.mkdir(mode=0o700)
        shutil.copyfile(SCRIPT, stage / SCRIPT.name)
        (stage / SCRIPT.name).chmod(0o400)
        join = stage / "join.json"
        descriptor = os.open(
            join, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o400)
        try:
            with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
                json.dump(
                    {"schema_version": 1, **values},
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
    return (
        "powershell.exe -NoLogo -NoProfile -NonInteractive "
        "-ExecutionPolicy Bypass -Command \"& { "
        "$v=(Get-Volume -FileSystemLabel 'TELOS_JOIN' | "
        "Select-Object -First 1).DriveLetter; "
        "if (-not $v) { throw 'TELOS_JOIN volume missing' }; "
        "& ($v + ':\\Invoke-TelosDomainJoin.ps1') }\""
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
        self.node_added = False
        self.attached = False
        self.destroyed = False

    def _audit_iso(self) -> os.stat_result:
        if self.iso.is_symlink() or not self.iso.is_file():
            raise WindowsJoinIsoError("join ISO is not a regular file")
        info = self.iso.stat()
        if stat.S_IMODE(info.st_mode) != 0o600:
            raise WindowsJoinIsoError("join ISO must be mode 0600")
        if stat.S_IMODE(self.iso.parent.stat().st_mode) != 0o700:
            raise WindowsJoinIsoError("join ISO parent must be mode 0700")
        return info

    def attach(self) -> None:
        if self.attached or self.destroyed:
            raise WindowsJoinIsoError("join ISO ownership state is invalid")
        info = self._audit_iso()
        self._identity = (info.st_dev, info.st_ino)
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
            self.qmp.execute("device_add", {
                "driver": "scsi-cd",
                "id": JOIN_DEVICE,
                "bus": JOIN_BUS,
                "drive": JOIN_NODE,
            })
        except Exception as error:
            # Ownership remains with this object so the caller can retry
            # teardown.  Never include QMP text, which may contain paths.
            raise WindowsJoinIsoError(
                f"join ISO attach failed: {type(error).__name__}") from None
        self.attached = True

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
        if marker != expected or not self.attached or self._identity is None:
            raise WindowsJoinIsoError("join marker or ownership is invalid")
        try:
            self.qmp.execute("device_del", {"id": JOIN_DEVICE})
            await_device_deleted(JOIN_DEVICE)
            self.attached = False
            self.qmp.execute("blockdev-del", {"node-name": JOIN_NODE})
            self.node_added = False
            current = self._audit_iso()
            if (current.st_dev, current.st_ino) != self._identity:
                raise WindowsJoinIsoError("join ISO identity changed")
            self.iso.unlink()
            self.destroyed = True
            send_release(f"TELOS_JOIN_MEDIA_DESTROYED {self.nonce}")
        except WindowsJoinIsoError:
            raise
        except Exception as error:
            raise WindowsJoinIsoError(
                f"join ISO destruction failed: {type(error).__name__}"
            ) from None

    def cleanup(
        self, *, await_device_deleted: Callable[[str], None],
    ) -> None:
        """Tear down owned media after a failed or interrupted protocol."""
        failures: list[str] = []
        if self.attached:
            try:
                self.qmp.execute("device_del", {"id": JOIN_DEVICE})
                await_device_deleted(JOIN_DEVICE)
                self.attached = False
            except Exception as error:
                failures.append(f"device: {type(error).__name__}")
        if self.node_added and not self.attached:
            try:
                self.qmp.execute("blockdev-del", {"node-name": JOIN_NODE})
                self.node_added = False
            except Exception as error:
                failures.append(f"node: {type(error).__name__}")
        if not self.attached and not self.node_added and self.iso.exists():
            try:
                current = self._audit_iso()
                if self._identity is not None and (
                        current.st_dev, current.st_ino) != self._identity:
                    raise WindowsJoinIsoError("join ISO identity changed")
                self.iso.unlink()
                self.destroyed = True
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
        if not self.destroyed:
            raise WindowsJoinIsoError(
                "join result cannot be proved before media destruction")
        result = dict(probe())
        if result != {
            "schema_version": 1,
            "boot_completed": True,
            "domain_joined": True,
            "domain": expected_domain,
        }:
            raise WindowsJoinIsoError("join/reboot proof is invalid")
        return {
            "schema_version": 1,
            "join_media_destroyed": True,
            "joined_after_reboot": True,
            "domain": expected_domain,
        }
