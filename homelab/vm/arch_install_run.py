#!/usr/bin/env python3
"""Run one prepared Arch-second installation bundle on the loopback fabric.

The persistent Windows disk is exposed through the authorized qcow2 overlay; a
disposable Controller PXE-publishes the selected Arch archiso release; the
workstation one-shot PXE-boots the Arch live shell, and this runner drives the
Windows-preserving installer over the serial console.  Nothing here touches a
physical disk, host networking, or UniFi.

The installer's synthetic-realm machine join is supplied host-side, mirroring
the Windows lane: a per-run disposable join account is staged on the
Controller over its retained serial console (``ControllerJoinSerial``), the
credential is sealed into a run-built, mode-0600 ``TELOS_JOIN`` ISO that is
QMP-attached read-only into the cold-plugged empty join root port, and the
media is hot-removed and destroyed by exact inode as soon as the guest prints
``TELOS ARCH JOIN MEDIA CONSUMED``.  The credential never appears in argv,
logs, evidence, or the retained serial transcript; the DC-side account is
destroyed with proof whether the run succeeds or fails.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import socket
import stat
import subprocess
import tempfile
import time
from typing import Callable, Mapping

try:
    from .arch_install_prepare import (
        DISK_PORT_ID, DISK_SERIAL, INSTALLER_NAME, JOIN_PORT_ID, OVERLAY_NAME,
        VARS_NAME, VERIFY_NAME, audit_arch_boot_boundary, inspect_overlay)
    from .automated_controller import DisposableBootDisk
    from .bootstrap_dc import DEFAULT_STATE, paths
    from .controller_join_material import (
        ControllerJoinSerial, OneUseDomainJoinMaterial)
    from .factory_publication import stage as stage_publication
    from .factory_runner import (
        DEFAULT_SEED_ISO, GATEWAY_MAC, PUBLICATION_LABEL, _at_root_prompt,
        gateway_command, qemu_commands,
        switch_command, wait_for_switch_port)
    from .serial_automation import SerialAutomation, SerialAutomationError
    from .signal_cleanup import SignalGuard, terminate_children
    from .simulation_evidence import private_file, redact
    from .simulated_topology import audit_live_process
    from .windows_gui import QmpClient, WindowsGuiError
    from .windows_install_contract import sha256
except ImportError:  # Direct execution from homelab/vm.
    from arch_install_prepare import (
        DISK_PORT_ID, DISK_SERIAL, INSTALLER_NAME, JOIN_PORT_ID, OVERLAY_NAME,
        VARS_NAME, VERIFY_NAME, audit_arch_boot_boundary, inspect_overlay)
    from automated_controller import DisposableBootDisk
    from bootstrap_dc import DEFAULT_STATE, paths
    from homelab.vm.controller_join_material import (
        ControllerJoinSerial, OneUseDomainJoinMaterial)
    from factory_publication import stage as stage_publication
    from factory_runner import (
        DEFAULT_SEED_ISO, GATEWAY_MAC, PUBLICATION_LABEL, _at_root_prompt,
        gateway_command, qemu_commands,
        switch_command, wait_for_switch_port)
    from homelab.vm.serial_automation import (
        SerialAutomation, SerialAutomationError)
    from signal_cleanup import SignalGuard, terminate_children
    from simulation_evidence import private_file, redact
    from simulated_topology import audit_live_process
    from windows_gui import QmpClient, WindowsGuiError
    from windows_install_contract import sha256

from homelab.workstations.arch_second import (
    JOIN_MEDIA_CONSUMED_MARKER, JOIN_MEDIA_LABEL, JOIN_VERIFIED_MARKER,
    SYNTHETIC_DOMAIN)


MAX_DURATION = 10800
GUEST_VERIFY_PATH = "/usr/local/lib/telos/arch-second-verify.py"
GUEST_INSTALLER_PATH = "/root/arch-install.sh"
BEGIN_MARKER = "TELOS ARCH INSTALL BEGIN"
COMPLETE_MARKER = "TELOS ARCH INSTALL COMPLETE"
FAIL_MARKER = "TELOS ARCH INSTALL FAIL"
DISK_ATTACHED_MARKER = "TELOS ARCH DISK ATTACHED"
DISK_DEVICE_ID = "osdisk-blk"
DISK_BACKEND_ID = "osdisk"
ATTACH_TIMEOUT = 30.0
# One-use domain-join media: a run-built, mode-0600 TELOS_JOIN ISO exposed to
# the guest as a read-only virtio-blk device in the cold-plugged empty join
# port, then destroyed by exact inode after the guest's consumed marker.  The
# credential travels only inside the ISO block device, never over serial.
JOIN_ISO_NAME = "join.iso"
JOIN_NODE_ID = "joinmedia"
JOIN_DEVICE_ID = "joinmedia-blk"
JOIN_USERNAME = re.compile(
    r"tj-[0-9a-f]{16}@[A-Z0-9](?:[A-Z0-9.-]{0,251}[A-Z0-9])?")
CONTROLLER_CONSOLE_TIMEOUT = 300.0
VERIFY_PASS_MARKER = (
    "PASS: Windows-first GPT matches the approved Arch install contract")
PRESERVED_MARKER = (
    "Arch installed; Windows partitions and filesystems were not modified.")
ARCH_LIVE_MARKERS = ("Welcome to Arch Linux", "archiso login:")


def _bundle(path: Path) -> tuple[dict, list[str]]:
    if path.is_symlink():
        raise RuntimeError("Arch bundle must be a private non-symlink directory")
    path = path.resolve(strict=True)
    if path.stat().st_mode & 0o077:
        raise RuntimeError("Arch bundle must be a private non-symlink directory")
    authorization = json.loads(
        (path / "authorization.json").read_text(encoding="utf-8"))
    command = json.loads(
        (path / "qemu-command.json").read_text(encoding="utf-8"))["argv"]
    authorized = authorization["authorization"]
    serial = authorized["disk_serial"]
    if _argv_digest(command) != authorized["qemu_argv_sha256"]:
        raise RuntimeError("Arch QEMU command differs from authorization")
    overlay = path / OVERLAY_NAME
    info = inspect_overlay(overlay)
    if info["sha256"] != authorized["overlay"]["sha256"]:
        raise RuntimeError("Arch overlay differs from authorization")
    if info["backing"] != authorized["backing_windows_disk"]["path"]:
        raise RuntimeError("Arch overlay backs a different disk than authorized")
    # Proving the retained base digest is what preserves Windows: the run
    # refuses to boot if the persistent disk changed since authorization.
    backing = Path(info["backing"])
    if backing.is_symlink() or not backing.is_file():
        raise RuntimeError("persistent Windows disk is missing or unsafe")
    if sha256(backing) != authorized["backing_windows_disk"]["sha256"]:
        raise RuntimeError("persistent Windows disk differs from authorization")
    audit_arch_boot_boundary(command, disk=overlay, serial=serial)
    for entry in authorization["guest_inputs"]:
        staged = path / entry["name"]
        if staged.is_symlink() or not staged.is_file():
            raise RuntimeError("Arch bundle is missing an authorized guest input")
        if sha256(staged) != entry["sha256"]:
            raise RuntimeError("Arch guest input differs from authorization")
    required = (
        overlay, path / VARS_NAME, path / VERIFY_NAME, path / INSTALLER_NAME)
    if any(item.is_symlink() or not item.is_file() for item in required):
        raise RuntimeError("Arch bundle is incomplete or unsafe")
    return authorization, command


def _argv_digest(command: list[str]) -> str:
    return hashlib.sha256(
        json.dumps(command, separators=(",", ":")).encode()).hexdigest()


def _qmp_socket_path(command: list[str]) -> Path:
    """Recover the pinned QMP socket path from the authorized argv."""
    try:
        value = command[command.index("-qmp") + 1]
    except (ValueError, IndexError):
        raise RuntimeError("authorized command carries no QMP socket")
    if not value.startswith("unix:") or ",server=on" not in value:
        raise RuntimeError("authorized QMP socket shape is invalid")
    path = Path(value[len("unix:"):].split(",", 1)[0])
    if not path.is_absolute() or len(str(path).encode()) > 100:
        raise RuntimeError("authorized QMP socket path is invalid")
    return path


def _switch_port(command: list[str]) -> int:
    """Recover the loopback switch port the workstation NIC connects to."""
    for index, item in enumerate(command):
        if item != "-netdev" or index + 1 >= len(command):
            continue
        match = re.fullmatch(
            r"socket,id=factory,connect=127\.0\.0\.1:([1-9][0-9]{0,4})",
            command[index + 1])
        if match:
            return int(match.group(1))
    raise RuntimeError("authorized command has no loopback switch port")


def _connect_qmp(
        path: Path, *, expected_peer_pid: int, timeout: float = 30,
) -> QmpClient:
    """Connect the codebase QMP client to the pinned, bounded socket."""
    deadline = time.monotonic() + timeout
    last_error: BaseException | None = None
    while time.monotonic() < deadline:
        try:
            return QmpClient.connect(
                path, timeout=1, expected_peer_pid=expected_peer_pid)
        except (OSError, WindowsGuiError) as error:
            last_error = error
            time.sleep(0.05)
    raise RuntimeError("Arch QMP socket did not become ready") from last_error


def hot_attach_disk(
    qmp: QmpClient, serial: str, *, timeout: float = ATTACH_TIMEOUT,
) -> None:
    """Hot-attach the install-target disk once archiso is live.

    The overlay is already present as the detached ``osdisk`` block backend
    (the boot argv carries no disk device).  A single bounded ``device_add``
    realises it as a virtio-blk device exposing *serial*, which is exactly the
    serial the arch_second installer greps out of lsblk.  The device is
    targeted at the cold-plugged ``pcie-root-port`` (``bus``) rather than the
    q35 root complex ``pcie.0``, which does not support PCIe hotplug.

    virtio-blk deliberately replaced NVMe here: QEMU's NVMe namespace carries
    identifiers the kernel logs as bogus, and any later namespace revalidation
    (one fired per rescan attempt) tears the enumerated partitions back down —
    the live runs showed ``nvme0n1: p1 p2 p3 p4`` at attach and an empty
    partition list by installer time.  virtio-blk hotplug has no namespace
    revalidation semantics, so the GPT enumerated at attach stays enumerated.
    Any QMP fault raises, so the caller tears the run down fail-closed.
    """
    try:
        qmp.execute("device_add", {
            "driver": "virtio-blk-pci",
            "bus": DISK_PORT_ID,
            "drive": DISK_BACKEND_ID,
            "serial": serial,
            "id": DISK_DEVICE_ID,
        }, timeout=timeout)
    except WindowsGuiError as error:
        raise RuntimeError(
            "install-target disk hot-attach failed") from error


def establish_publication_console(
    process: subprocess.Popen[bytes], *, password: bytes,
    timeout: float = CONTROLLER_CONSOLE_TIMEOUT,
) -> SerialAutomation:
    """Publish the PXE release, then keep an authenticated Controller shell.

    ``factory_runner.activate_publication`` hands the Controller serial
    console to a daemon drain thread once services are ready, which forfeits
    the channel this runner later needs for ``ControllerJoinSerial``.  This
    variant runs the same disposable-init publication protocol through one
    ``SerialAutomation`` owner: it awaits the init shell, publishes from the
    verified media (requiring ``TELOS PXE PUBLICATION PASS``), then reuses
    the proven ``establish_disposable_controller_session`` login and finally
    requires ``TELOS PXE SERVICES READY``.  The returned console holds the
    attempt-local credential and remains the sole reader of the serial
    channel, so join-account staging and destruction can reuse it.
    """
    if process.stdin is None or process.stdout is None:
        raise RuntimeError(
            "Controller publication requires captured serial I/O")
    console = SerialAutomation(
        process.stdout, process.stdin, password, timeout=timeout)
    try:
        console._wait(rb"(?:^|\n)[^\n]*#\s*$", "arch-controller-init-shell")
        console._send(
            b"/usr/bin/mount -o remount,rw / && "
            b"/usr/bin/mkdir -p /run/telos-pxe-release && "
            b"/usr/bin/mount -L " + PUBLICATION_LABEL.encode("ascii")
            + b" /run/telos-pxe-release && "
            b"/run/telos-pxe-release/publish",
            "arch-publication-command-sent")
        console._wait(
            rb"(?:^|\n)TELOS PXE PUBLICATION PASS\s*(?:\n|$)",
            "arch-publication-pass")
        console.establish_disposable_controller_session()
        if b"TELOS PXE READINESS FAIL" in console.transcript:
            raise RuntimeError("Controller PXE readiness failed")
        if b"TELOS PXE SERVICES READY" not in console.transcript:
            console._wait(
                rb"(?:^|\n)TELOS PXE SERVICES READY\s*(?:\n|$)",
                "arch-publication-services-ready")
    except SerialAutomationError as error:
        console.release_password()
        raise RuntimeError(
            "Controller PXE publication console failed") from error
    except BaseException:
        console.release_password()
        raise
    return console


def build_arch_join_iso(
    output: Path, material: Mapping[str, str], *, runner=subprocess.run,
) -> Path:
    """Build the mode-0600 one-use Arch join ISO without secrets in argv.

    The ISO carries only ``join.json`` (``username``/``password``), the exact
    shape the arch_second installer reads from ``/dev/disk/by-label/`` +
    ``JOIN_MEDIA_LABEL`` into tmpfs.  Only fixed switches and non-secret
    paths cross the xorriso process boundary; the credential exists solely
    inside the private staging directory and the resulting private ISO.
    """
    output = Path(output)
    if output.exists() or output.is_symlink():
        raise RuntimeError("join ISO destination must be absent")
    parent = output.parent.resolve()
    if (output.parent.is_symlink() or not parent.is_dir()
            or stat.S_IMODE(parent.stat().st_mode) != 0o700):
        raise RuntimeError(
            "join ISO parent must be a private mode-0700 directory")
    if set(material) != {"username", "password"}:
        raise RuntimeError("join material fields are invalid")
    username = material["username"]
    password = material["password"]
    if not isinstance(username, str) or not JOIN_USERNAME.fullmatch(username):
        raise RuntimeError("join username is invalid")
    if (not isinstance(password, str) or not password or len(password) > 512
            or any(ord(character) < 32 for character in password)):
        raise RuntimeError("join password is invalid")
    with tempfile.TemporaryDirectory(
            prefix=".arch-join-", dir=parent) as temporary:
        temporary_root = Path(temporary)
        temporary_root.chmod(0o700)
        staging = temporary_root / "payload"
        staging.mkdir(mode=0o700)
        join = staging / "join.json"
        descriptor = os.open(
            join, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o400)
        try:
            with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
                json.dump(
                    {
                        "schema_version": 1,
                        "username": username,
                        "password": password,
                    },
                    stream, separators=(",", ":"), sort_keys=True)
                stream.write("\n")
        except BaseException:
            try:
                os.close(descriptor)
            except OSError:
                pass
            raise
        partial = temporary_root / JOIN_ISO_NAME
        # Only non-secret paths and fixed switches cross the process boundary.
        runner([
            "xorriso", "-as", "mkisofs", "-quiet",
            "-V", JOIN_MEDIA_LABEL, "-J", "-r",
            "-o", str(partial), str(staging),
        ], check=True, capture_output=True)
        if partial.is_symlink() or not partial.is_file():
            raise RuntimeError("xorriso did not create the join ISO")
        partial.chmod(0o600)
        partial.replace(output)
    output.chmod(0o600)
    return output


class ArchJoinMedia:
    """Own attachment and exact-inode destruction of one Arch join ISO.

    Mirrors the Windows lane's ``JoinMediaChannel`` ownership discipline: the
    ISO's inode is captured at attach through an ``O_NOFOLLOW`` descriptor,
    QEMU is proved to hold exactly that inode while attached and to have
    released it before the file is unlinked, and destruction removes only the
    uniquely owned name inside the private parent.  The guest sees the media
    as a read-only virtio-blk device realised into the cold-plugged empty
    ``JOIN_PORT_ID`` root port.
    """

    def __init__(self, qmp, iso: Path, *, qemu_pid: int) -> None:
        if type(qemu_pid) is not int or qemu_pid <= 0:
            raise RuntimeError("join media requires the QEMU pid")
        self.qmp = qmp
        self.iso = Path(iso)
        self.qemu_pid = qemu_pid
        self._descriptor: int | None = None
        self._identity: tuple[int, int] | None = None
        self.node_added = False
        self.device_added = False
        self.destroyed = False

    def _audit_iso(self) -> os.stat_result:
        if self.iso.is_symlink() or not self.iso.is_file():
            raise RuntimeError("join ISO is not a regular file")
        info = self.iso.stat()
        if stat.S_IMODE(info.st_mode) != 0o600:
            raise RuntimeError("join ISO must be mode 0600")
        if stat.S_IMODE(self.iso.parent.stat().st_mode) != 0o700:
            raise RuntimeError("join ISO parent must be mode 0700")
        return info

    def _prove_qemu_inode(self, expected: bool) -> None:
        if self._identity is None:
            raise RuntimeError("join ISO ownership is unavailable")
        verifier = getattr(self.qmp, "holds_inode", None)
        if callable(verifier):
            held = verifier(*self._identity)
        else:
            held = False
            try:
                for entry in Path(f"/proc/{self.qemu_pid}/fd").iterdir():
                    try:
                        info = entry.stat()
                    except FileNotFoundError:
                        continue
                    if (info.st_dev, info.st_ino) == self._identity:
                        held = True
                        break
            except OSError as error:
                raise RuntimeError(
                    "QEMU join media ownership cannot be inspected"
                ) from error
        if held is not expected:
            raise RuntimeError("QEMU join ISO inode ownership proof failed")

    def attach(self) -> None:
        """Expose the audited ISO read-only in the empty join root port."""
        if self.node_added or self.device_added or self.destroyed:
            raise RuntimeError("join media ownership state is invalid")
        info = self._audit_iso()
        try:
            descriptor = os.open(
                self.iso, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
        except OSError as error:
            raise RuntimeError("join ISO ownership open failed") from error
        opened = os.fstat(descriptor)
        if (opened.st_dev, opened.st_ino) != (info.st_dev, info.st_ino):
            os.close(descriptor)
            raise RuntimeError("join ISO identity changed")
        self._descriptor = descriptor
        self._identity = (opened.st_dev, opened.st_ino)
        # Ownership remains with this object on failure so the caller can
        # clean up the partially attached media.
        self._execute("attach", "blockdev-add", {
            "node-name": JOIN_NODE_ID,
            "driver": "raw",
            "read-only": True,
            "file": {
                "driver": "file",
                "filename": str(self.iso.resolve()),
            },
        })
        self.node_added = True
        self._prove_qemu_inode(True)
        self._execute("attach", "device_add", {
            "driver": "virtio-blk-pci",
            "bus": JOIN_PORT_ID,
            "drive": JOIN_NODE_ID,
            "id": JOIN_DEVICE_ID,
        })
        self.device_added = True

    def _execute(self, phase: str, command: str, arguments: dict) -> None:
        try:
            self.qmp.execute(command, arguments, timeout=ATTACH_TIMEOUT)
        except Exception as error:
            # Never include QMP text, which may contain paths.
            raise RuntimeError(
                f"join media {phase} failed: {type(error).__name__}"
            ) from None

    def _await_device_deleted(self) -> None:
        awaiter = getattr(self.qmp, "await_device_deleted", None)
        if not callable(awaiter):
            raise RuntimeError("QMP deletion-event boundary is unavailable")
        try:
            event = awaiter(JOIN_DEVICE_ID, timeout=ATTACH_TIMEOUT)
        except Exception as error:
            raise RuntimeError(
                f"join media hot-remove failed: {type(error).__name__}"
            ) from None
        if (
            not isinstance(event, Mapping)
            or event.get("event") != "DEVICE_DELETED"
            or not isinstance(event.get("data"), Mapping)
            or event["data"].get("device") != JOIN_DEVICE_ID
        ):
            raise RuntimeError("QMP deletion event is invalid")

    def _destroy_owned_iso(self) -> None:
        """Unlink the held inode by its exact name inside the private parent."""
        if self._identity is None or self._descriptor is None:
            raise RuntimeError("join ISO ownership is unavailable")
        opened = os.fstat(self._descriptor)
        if (opened.st_dev, opened.st_ino) != self._identity:
            raise RuntimeError("join ISO descriptor identity changed")
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
            raise RuntimeError("exact join ISO name is not uniquely owned")
        matches[0].unlink()
        os.close(self._descriptor)
        self._descriptor = None

    def destroy(self) -> None:
        """Hot-remove the media and destroy exactly the attached inode."""
        if not self.device_added or self.destroyed:
            raise RuntimeError("join media ownership state is invalid")
        self._execute("hot-remove", "device_del", {"id": JOIN_DEVICE_ID})
        self._await_device_deleted()
        self.device_added = False
        self._execute(
            "hot-remove", "blockdev-del", {"node-name": JOIN_NODE_ID})
        self.node_added = False
        self._prove_qemu_inode(False)
        self._destroy_owned_iso()
        self.destroyed = True

    def cleanup(self) -> list[str]:
        """Best-effort teardown after a failed run; never raises."""
        failures: list[str] = []
        if self.device_added:
            try:
                self.qmp.execute(
                    "device_del", {"id": JOIN_DEVICE_ID},
                    timeout=ATTACH_TIMEOUT)
                self._await_device_deleted()
                self.device_added = False
            except Exception as error:
                failures.append(f"device: {type(error).__name__}")
        if self.node_added and not self.device_added:
            try:
                self.qmp.execute(
                    "blockdev-del", {"node-name": JOIN_NODE_ID},
                    timeout=ATTACH_TIMEOUT)
                self.node_added = False
            except Exception as error:
                failures.append(f"node: {type(error).__name__}")
        if (self._descriptor is not None and not self.node_added
                and not self.device_added):
            try:
                self._prove_qemu_inode(False)
                self._destroy_owned_iso()
                self.destroyed = True
            except Exception as error:
                failures.append(f"iso: {type(error).__name__}")
        return failures


def run_join_install(
    *,
    material: Mapping[str, str],
    iso: Path,
    qmp,
    qemu_pid: int,
    drive: Callable[[Callable[[], None], Callable[[], None]], str],
    facts: dict | None = None,
) -> tuple[str, dict]:
    """Carry one-use join media through build, attach, consumption, destruction.

    *material* is the per-run mapping staged by ``OneUseDomainJoinMaterial``
    (``principal``/``credential``/``realm``).  *drive* receives the
    ``(attach_media, consume_media)`` callables and runs the installer: it
    must invoke ``attach_media`` once archiso is live and ``consume_media``
    when the guest prints ``TELOS ARCH JOIN MEDIA CONSUMED`` (the guest has
    unmounted the media by then), which destroys the media by exact inode
    before the guest performs the join.  A run whose media was never
    consumed, or any failure, tears down best-effort and fails closed.  The
    returned facts are secret-free lifecycle booleans for evidence.
    """
    if facts is None:
        facts = {}
    facts.update(
        {"built": False, "attached": False,
         "consumed": False, "destroyed": False})
    build_arch_join_iso(iso, {
        "username": f"{material['principal']}@{material['realm']}",
        "password": material["credential"],
    })
    facts["built"] = True
    media = ArchJoinMedia(qmp, iso, qemu_pid=qemu_pid)

    def attach_media() -> None:
        media.attach()
        facts["attached"] = True

    def consume_media() -> None:
        facts["consumed"] = True
        media.destroy()
        facts["destroyed"] = True

    try:
        transcript = drive(attach_media, consume_media)
    except BaseException:
        failures = media.cleanup()
        if failures:
            facts["cleanup_failures"] = failures
        facts["destroyed"] = media.destroyed
        raise
    if not media.destroyed:
        failures = media.cleanup()
        if failures:
            facts["cleanup_failures"] = failures
        facts["destroyed"] = media.destroyed
        if FAIL_MARKER not in transcript:
            raise RuntimeError(
                "join media was not consumed and destroyed before the "
                "installer completed")
        # The guest failed before consuming the media: the media is torn
        # down here, and the caller's lifecycle validation reports the
        # honest installer failure instead of a masking media error.
    return transcript, facts


def _destroy_leftover_join_iso(path: Path) -> str | None:
    """Remove any join ISO that outlived its media lifecycle."""
    try:
        if path.is_symlink():
            return "leftover join ISO became a symlink"
        path.unlink(missing_ok=True)
    except OSError as error:
        return f"leftover join ISO cleanup failed: {type(error).__name__}"
    return None


def _sanitize_log(path: Path, *, maximum: int = 4 * 1024 * 1024) -> None:
    """Retain a bounded, redacted tail after all writers have stopped."""
    try:
        data = path.read_bytes()
    except FileNotFoundError:
        return
    private_file(path, redact(data[-maximum:]))


def _destroy_runtime_publication(path: Path) -> str | None:
    """Remove the runtime-built Arch publication ISO."""
    try:
        if path.is_symlink():
            return "runtime publication became a symlink"
        path.unlink(missing_ok=True)
    except OSError as error:
        return f"runtime publication cleanup failed: {type(error).__name__}"
    return None


def _validate_lifecycle(serial: str, disk_serial: str = DISK_SERIAL) -> None:
    """Accept only a one-PXE, disk-detached, Windows-preserving transcript."""
    if FAIL_MARKER in serial:
        raise RuntimeError("Arch installer reported failure")
    attached = f"{DISK_ATTACHED_MARKER} serial={disk_serial}"
    required = (
        BEGIN_MARKER,
        attached,
        JOIN_MEDIA_CONSUMED_MARKER,
        JOIN_VERIFIED_MARKER,
        VERIFY_PASS_MARKER,
        PRESERVED_MARKER,
        COMPLETE_MARKER,
        "Windows Boot Manager",
        "Linux Boot Manager",
        "default auto-windows",
    )
    missing = [marker for marker in required if marker not in serial]
    if missing:
        raise RuntimeError(
            "Arch install lifecycle markers missing: " + ", ".join(missing))
    # The one-use join media must be consumed and the machine join verified
    # strictly between the disk attach and install completion: consumption
    # before the attach would mean the credential media was exposed to a
    # pre-live environment, and a verification after completion would mean
    # the installer finished without a proven join.
    ordered = (
        attached, JOIN_MEDIA_CONSUMED_MARKER, JOIN_VERIFIED_MARKER,
        COMPLETE_MARKER)
    positions = [serial.index(marker) for marker in ordered]
    if positions != sorted(positions):
        raise RuntimeError(
            "Arch join lifecycle markers are out of order")
    live_positions = [
        serial.index(marker) for marker in ARCH_LIVE_MARKERS if marker in serial
    ]
    if not live_positions:
        raise RuntimeError("Arch live environment was not observed")
    # The install target must appear only AFTER archiso is live: a disk-serial
    # detection that precedes the live environment would mean the NVMe was
    # cold-plugged into the boot path rather than hot-attached.
    if serial.index(attached) < min(live_positions):
        raise RuntimeError(
            "install target was detected before archiso was live")
    pxe_starts = sum(
        line.startswith("BdsDxe: starting ") and '"UEFI PXEv4' in line
        for line in serial.splitlines()
    )
    if pxe_starts != 1:
        raise RuntimeError(
            "workstation did not use exactly one PXE firmware boot")


# archiso's PXE image reaches a getty `login:` prompt on ttyS0 with no serial
# autologin drop-in; its live root has an empty password. These matchers mirror
# _at_root_prompt (end-of-transcript anchored, no MULTILINE) so login is only
# answered while the prompt is the last thing the guest emitted.
_LOGIN_PROMPT = re.compile(rb"[\w.-]+ login:[ \t]*$")
_PASSWORD_PROMPT = re.compile(rb"[Pp]assword:[ \t]*$")


def _at_login_prompt(transcript: bytes | bytearray) -> bool:
    """Match a getty ``<hostname> login:`` prompt awaiting a username."""
    return _LOGIN_PROMPT.search(transcript) is not None


def _at_password_prompt(transcript: bytes | bytearray) -> bool:
    """Match a login ``Password:`` prompt awaiting the (empty) live password."""
    return _PASSWORD_PROMPT.search(transcript) is not None


def _heredoc(target: str, payload: str) -> bytes:
    """Deliver an exact file into the guest via a base64 heredoc."""
    encoded = base64.b64encode(payload.encode("utf-8")).decode("ascii")
    body = "\n".join(
        encoded[offset:offset + 76] for offset in range(0, len(encoded), 76))
    return (
        f"base64 -d > {target} <<'TELOS_B64_EOF'\n{body}\nTELOS_B64_EOF\n"
    ).encode("ascii")


def drive_installer(
    process: subprocess.Popen[bytes], capture: Path, *,
    verify_script: str, installer_script: str, serial: str,
    attach: Callable[[], None], timeout: float,
    consume_media: Callable[[], None] | None = None,
) -> str:
    """Drive the Arch live shell and return the captured serial transcript.

    The PXE archiso boots to a getty ``archiso login:`` prompt on ttyS0 with no
    serial autologin, so this first answers that login (username ``root``; the
    live root has an empty password).  Shell readiness is then proven with a
    sentinel-echo handshake rather than an end-of-transcript prompt match: the
    kernel console shares ttyS0 and keeps printing audit/printk lines after the
    prompt, so an end-anchored matcher would never fire.  An image that already
    dropped straight to a root shell is honoured without a spurious login.
    Once the sentinel surfaces the install-target NVMe is still absent (it was
    never cold-plugged).  *attach*
    hot-plugs it over QMP before any installer step runs; a bounded in-guest
    lsblk gate then proves the authorized serial is present, so the destructive
    installer only ever sees the one intended target.  An *attach* failure
    propagates for fail-closed teardown, and a login that never yields a shell
    within *timeout* fails closed with a clear error.

    When *consume_media* is provided it is invoked exactly once, as soon as
    the guest prints ``TELOS ARCH JOIN MEDIA CONSUMED`` (the installer has
    unmounted the one-use join media and copied the credential into tmpfs):
    the callback hot-removes and destroys the media before the installer
    proceeds, and its failure propagates for fail-closed teardown.
    """
    import select
    if process.stdin is None or process.stdout is None:
        raise RuntimeError("Arch install requires captured serial I/O")
    deadline = time.monotonic() + timeout
    transcript = bytearray()
    capture.touch(mode=0o600)
    capture.chmod(0o600)
    # After the PCIe hotplug the kernel usually enumerates the GPT at attach;
    # when it has not yet, a partition-table re-read plus a udev settle is
    # sufficient for virtio-blk (no NVMe namespace revalidation exists to tear
    # the enumeration back down). The gate below requires the authorized serial
    # AND visible partitions before the installer is allowed to run, so a disk
    # that never surfaces its GPT fails here rather than inside the installer.
    confirm_disk = (
        f"for _ in $(seq 1 30); do "
        f"lsblk -dno SERIAL | grep -qx {serial} && break; sleep 1; done; "
        f"dev=$(lsblk -dno NAME,SERIAL | "
        f"awk -v s={serial} '$2==s{{print \"/dev/\"$1}}'); "
        f"if [ -n \"$dev\" ]; then "
        f"for _ in $(seq 1 20); do "
        f"lsblk -rno NAME,TYPE \"$dev\" | grep -qw part && break; "
        f"partprobe \"$dev\" 2>/dev/null || "
        f"blockdev --rereadpt \"$dev\" 2>/dev/null || true; "
        f"udevadm settle 2>/dev/null || true; "
        f"sleep 1; done; fi; "
        f"[ -n \"$dev\" ] "
        f"&& lsblk -rno NAME,TYPE \"$dev\" | grep -qw part "
        f"&& echo {DISK_ATTACHED_MARKER} serial={serial} "
        f"|| echo {FAIL_MARKER} rc=disk-serial-missing\n"
    ).encode("ascii")
    steps = [
        f"echo {BEGIN_MARKER}\n".encode("ascii"),
        b"mkdir -p /usr/local/lib/telos\n",
        confirm_disk,
        _heredoc(GUEST_VERIFY_PATH, verify_script),
        _heredoc(GUEST_INSTALLER_PATH, installer_script),
        (
            f"bash {GUEST_INSTALLER_PATH} "
            f"&& echo {COMPLETE_MARKER} "
            f"|| echo {FAIL_MARKER} rc=$?\n"
        ).encode("ascii"),
        b"efibootmgr || true\n",
        b"grep -H '^default' /mnt/boot/loader/loader.conf || true\n",
        b"echo TELOS ARCH TEARDOWN; sync; systemctl poweroff -i "
        b"|| poweroff -f\n",
    ]
    # Shell readiness is proven with a sentinel-echo handshake, never with an
    # end-of-transcript prompt match: archiso boots the kernel console on the
    # same ttyS0, so audit/printk lines keep printing AFTER the root prompt and
    # a prompt anchored to end-of-transcript would never be the last bytes. We
    # echo a unique nonce and substring-search for it anywhere in the buffer,
    # which interleaved kernel spam cannot defeat. The sentinel resolves to
    # ``...=ready``; the echoed command carries ``...=%s``, so the command's own
    # terminal echo can never be mistaken for the shell's ``ready`` output.
    token = os.urandom(16).hex()
    sentinel = f"TELOS_ARCH_SHELL_READY_{token}=ready"
    probe = (
        f"printf '\\nTELOS_ARCH_SHELL_READY_{token}=%s\\n' ready\n"
    ).encode("ascii")
    began = False
    dispatched = False
    login_sent = False
    password_sent = False
    media_consumed = False
    probe_last = None
    while time.monotonic() < deadline:
        if process.poll() is not None:
            break
        ready, _, _ = select.select(
            [process.stdout], [], [], min(0.25, deadline - time.monotonic()))
        if ready:
            chunk = os.read(process.stdout.fileno(), 4096)
            if chunk:
                transcript.extend(chunk)
                if len(transcript) > 8 * 1024 * 1024:
                    del transcript[:-8 * 1024 * 1024]
                capture.write_bytes(transcript)
                capture.chmod(0o600)
        text = transcript.decode("utf-8", errors="replace")
        if not began:
            if probe_last is not None and sentinel in text:
                # The sentinel proves the root shell is live and reading
                # stdin despite interleaved kernel spam: hot-attach the
                # install target before any step so its serial is present
                # when the installer greps lsblk, then drive the installer.
                attach()
                for command in steps:
                    process.stdin.write(command)
                process.stdin.flush()
                began = True
                dispatched = True
            elif not login_sent and _at_login_prompt(transcript):
                # Answer the getty login; the live root has no password, so this
                # yields the root shell the sentinel handshake then confirms.
                process.stdin.write(b"root\n")
                process.stdin.flush()
                login_sent = True
            elif (login_sent and not password_sent
                    and _at_password_prompt(transcript)):
                # The PXE live image should not ask for a password, but if a
                # variant does the live root's password is empty: answer with a
                # bare line rather than stalling until the deadline.
                process.stdin.write(b"\n")
                process.stdin.flush()
                password_sent = True
            elif login_sent or _at_root_prompt(transcript):
                # The getty login was answered (or an autologin image dropped
                # straight to a root shell): echo the readiness sentinel and
                # wait for it to surface anywhere in the transcript. A single
                # probe sent right after ``root`` is consumed as login echo
                # before the shell exists, so re-send it on an interval until
                # the shell actually executes it and prints ``...=ready``.
                # Ordering stays root -> ready -> attach -> installer.
                now = time.monotonic()
                if probe_last is None or now - probe_last >= 3.0:
                    process.stdin.write(probe)
                    process.stdin.flush()
                    probe_last = now
        if (dispatched and consume_media is not None and not media_consumed
                and JOIN_MEDIA_CONSUMED_MARKER in text):
            # The guest has unmounted the one-use media and holds the
            # credential only in tmpfs: hot-remove and destroy the media
            # before the installer proceeds to the join itself.
            media_consumed = True
            consume_media()
        if dispatched and (COMPLETE_MARKER in text or FAIL_MARKER in text):
            # Give the boot-entry proof and teardown lines a brief moment to
            # arrive before the guest powers off.
            grace = time.monotonic() + 15
            while time.monotonic() < grace and process.poll() is None:
                more, _, _ = select.select([process.stdout], [], [], 0.25)
                if not more:
                    continue
                chunk = os.read(process.stdout.fileno(), 4096)
                if not chunk:
                    break
                transcript.extend(chunk)
                capture.write_bytes(transcript)
                capture.chmod(0o600)
            break
    capture.write_bytes(transcript)
    capture.chmod(0o600)
    if not began:
        raise RuntimeError(
            "Arch live root shell was never reached: the archiso getty login "
            "was answered but the readiness sentinel never surfaced in the "
            "serial transcript before the deadline")
    return transcript.decode("utf-8", errors="replace")


def run(
    bundle: Path, *, controller_state: Path, releases: Path, seed_iso: Path,
    duration: float, apply: bool,
) -> int:
    if not 60 <= duration <= MAX_DURATION:
        raise RuntimeError(
            f"duration must be between 60 and {MAX_DURATION} seconds")
    authorization, workstation_command = _bundle(bundle)
    bundle = bundle.resolve()
    authorized = authorization["authorization"]
    print("Boundary: loopback-only switch; no host or UniFi changes")
    print(f"Bundle: {bundle}")
    print(
        "Workstation: PXE-boots disk-detached; the authorized NVMe overlay is "
        "hot-attached once archiso is live; Windows preserved")
    print(f"Arch release: {authorized['release_version']}")
    print(
        "Domain join: per-run disposable DC account; one-use TELOS_JOIN "
        "media destroyed after the consumed marker")
    print(f"Maximum runtime: {duration:g} seconds")
    if not apply:
        print("dry run; repeat with --apply")
        return 0

    evidence = bundle / "evidence"
    if evidence.exists():
        raise RuntimeError("bundle already has execution evidence")
    evidence.mkdir(mode=0o700)
    qmp_socket = _qmp_socket_path(workstation_command)
    port = _switch_port(workstation_command)
    owned_qmp_root: Path | None = None
    if qmp_socket.parent != bundle:
        qmp_socket.parent.mkdir(mode=0o700, exist_ok=False)
        owned_qmp_root = qmp_socket.parent
    elif qmp_socket.exists():
        raise RuntimeError("bundle QMP socket path is already occupied")

    verify_script = (bundle / VERIFY_NAME).read_text(encoding="utf-8")
    installer_script = (bundle / INSTALLER_NAME).read_text(encoding="utf-8")
    canonical = paths(controller_state)
    processes: dict[str, subprocess.Popen[bytes]] = {}
    listener = socket.socket()
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", port))
    listener.listen(3)
    publication_iso = evidence / "publication.iso"
    join_iso = evidence / JOIN_ISO_NAME
    join_facts: dict = {}
    console: SerialAutomation | None = None
    result = {"schema": 1, "status": "fail", "phase": "starting"}
    try:
        with SignalGuard(), DisposableBootDisk(
                canonical["disk"], canonical["vars"],
                run_root=evidence / "controller") as overlay:
            publication = evidence / "publication"
            receipt = stage_publication(
                releases, publication, seed_iso=seed_iso,
                target="arch-workstation")
            if (receipt["version"] != authorized["release_version"]
                    or receipt["selected_manifest_sha256"]
                    != authorized["release_manifest_sha256"]):
                raise RuntimeError(
                    "published Arch release differs from the authorized release")
            subprocess.run([
                "xorriso", "-as", "mkisofs", "-quiet", "-iso-level", "3",
                "-V", PUBLICATION_LABEL, "-o", str(publication_iso),
                str(publication),
            ], check=True, capture_output=True)
            publication_iso.chmod(0o600)

            controller_command = qemu_commands(
                overlay.disk, overlay.vars,
                bundle / OVERLAY_NAME, bundle / VARS_NAME,
                port, None, publication_iso)["controller"]
            processes["switch"] = subprocess.Popen(
                switch_command(
                    listener.fileno(), evidence / "switch.jsonl",
                    accept_timeout=360, idle_timeout=duration + 60),
                stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                stderr=subprocess.STDOUT, pass_fds=(listener.fileno(),))
            listener.close()
            processes["gateway"] = subprocess.Popen(
                gateway_command(port), stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)
            wait_for_switch_port(
                evidence / "switch.jsonl", "gateway", GATEWAY_MAC)
            processes["controller"] = subprocess.Popen(
                controller_command, stdin=subprocess.PIPE,
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            audit_live_process(
                processes["controller"].pid, "controller",
                disposable_disk=overlay.disk, disposable_vars=overlay.vars,
                forbidden_paths=(canonical["disk"], canonical["vars"]))
            # One SerialAutomation owner both publishes the PXE release and
            # keeps the authenticated Controller shell; the join-material
            # protocol later reuses exactly this console.
            controller_password = (
                "Synthetic-Controller-" + secrets.token_urlsafe(24) + "-47!"
            ).encode("ascii")
            console = establish_publication_console(
                processes["controller"], password=controller_password)
            result["phase"] = "arch-publication-ready"
            disk_serial = authorized["disk_serial"]
            join_serial = ControllerJoinSerial(
                processes["controller"].stdout, processes["controller"].stdin,
                timeout=CONTROLLER_CONSOLE_TIMEOUT)
            join_serial.console = console
            join_material = OneUseDomainJoinMaterial(
                SYNTHETIC_DOMAIN,
                stage=join_serial.stage, destroy=join_serial.destroy)

            def consume(material: Mapping[str, str]) -> tuple[str, dict]:
                # The per-run join account exists on the disposable DC now;
                # boot the workstation and carry the one-use media through
                # build -> attach -> consumed -> destroyed around the install.
                processes["workstation"] = subprocess.Popen(
                    workstation_command, stdin=subprocess.PIPE,
                    stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
                audit_live_process(
                    processes["workstation"].pid, "client",
                    allowed_nic_models=("e1000e",))
                result["phase"] = "arch-install-driving"
                qmp = _connect_qmp(
                    qmp_socket,
                    expected_peer_pid=processes["workstation"].pid)
                try:
                    def drive(
                        attach_media: Callable[[], None],
                        consume_media: Callable[[], None],
                    ) -> str:
                        def attach() -> None:
                            hot_attach_disk(qmp, disk_serial)
                            attach_media()
                        return drive_installer(
                            processes["workstation"],
                            evidence / "workstation-serial.log",
                            verify_script=verify_script,
                            installer_script=installer_script,
                            serial=disk_serial,
                            attach=attach,
                            consume_media=consume_media,
                            timeout=duration)
                    return run_join_install(
                        material=material, iso=join_iso, qmp=qmp,
                        qemu_pid=processes["workstation"].pid,
                        drive=drive, facts=join_facts)
                finally:
                    qmp.close()

            # use() stages the per-run principal before the consumer runs and
            # proves its destruction on the DC afterwards, success or failure.
            (serial, _), destruction = join_material.use(consume)
            failed = [
                role for role, process in processes.items()
                if role != "workstation" and process.poll() not in (None, 0)
            ]
            if failed:
                raise RuntimeError(
                    "Arch lifecycle process failed: " + ", ".join(failed))
            _validate_lifecycle(serial, disk_serial)
            result = {
                "schema": 1, "status": "observed",
                "phase": "arch-installed-windows-preserved",
                "pxe_firmware_boots": 1,
                "windows_preserved": True,
                "release_version": authorized["release_version"],
                "join_media": dict(join_facts),
                "join_principal_destroyed": destruction.destruction_proved,
            }
            return 0
    except BaseException as error:
        result["error_type"] = type(error).__name__
        result["error"] = redact(
            str(error).encode("utf-8", errors="replace")).decode(
                "utf-8", errors="replace")
        # A teardown raise (an overlay audit, for example) replaces the
        # driving failure during unwinding; keep the original diagnosable
        # instead of letting cleanup mask it.
        context = error.__context__
        if context is not None:
            result["error_context_type"] = type(context).__name__
            result["error_context"] = redact(
                str(context).encode("utf-8", errors="replace")).decode(
                    "utf-8", errors="replace")
        raise
    finally:
        listener.close()
        failures = terminate_children(
            processes.values(), terminate_timeout=8, kill_timeout=3)
        if owned_qmp_root is not None:
            qmp_socket.unlink(missing_ok=True)
            try:
                owned_qmp_root.rmdir()
            except OSError:
                failures.append("QMP runtime root was not removed")
        if console is not None:
            console.release_password()
            try:
                private_file(
                    evidence / "controller-publication.log",
                    console.transcript)
            except (OSError, RuntimeError):
                failures.append("controller console transcript not retained")
        _sanitize_log(evidence / "controller-publication.log")
        _sanitize_log(evidence / "workstation-serial.log")
        publication_failure = _destroy_runtime_publication(publication_iso)
        if publication_failure:
            failures.append(publication_failure)
        result["runtime_publication_destroyed"] = publication_failure is None
        join_iso_failure = _destroy_leftover_join_iso(join_iso)
        if join_iso_failure:
            failures.append(join_iso_failure)
        if join_facts:
            # Secret-free lifecycle booleans; the failure path keeps whatever
            # stage the media lifecycle actually reached.
            result.setdefault("join_media", dict(join_facts))
        result["join_media_destroyed"] = (
            join_iso_failure is None and not join_iso.exists())
        if failures:
            result["cleanup_failures"] = failures
        output = evidence / "result.json"
        output.write_text(
            json.dumps(result, indent=2, sort_keys=True) + "\n",
            encoding="utf-8")
        os.chmod(output, 0o600)


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("--bundle", type=Path, required=True)
    result.add_argument(
        "--controller-state", type=Path, default=DEFAULT_STATE)
    result.add_argument(
        "--releases", type=Path, default=Path("homelab/var/pxe"))
    result.add_argument("--seed-iso", type=Path, default=DEFAULT_SEED_ISO)
    result.add_argument("--duration", type=float, default=1800)
    result.add_argument("--apply", action="store_true")
    return result


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    return run(
        args.bundle, controller_state=args.controller_state,
        releases=args.releases, seed_iso=args.seed_iso,
        duration=args.duration, apply=args.apply)


if __name__ == "__main__":
    raise SystemExit(main())
