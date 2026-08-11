#!/usr/bin/env python3
"""Gate-10 dual-boot acceptance: prepare and run cold-boot proof bundles.

The completed gate-7 bundle retains ``arch.qcow2`` (a dual-boot install
overlaying the persistent gate-5 ``windows.qcow2``).  Prepare overlays that
retained output with a fresh ``dualboot.qcow2`` so acceptance never mutates a
gate artifact, pairs it with pristine OVMF variables, and pins a QEMU command
whose only boot path is the cold-plugged NVMe carrying the authorized serial
(deliberately the inverse of the gate-7 install boundary: here the disk MUST
be firmware-bootable and PXE/media MUST be absent).

Run performs two cold boots against that overlay:

* Boot 1 sends no input and proves the systemd-boot menu appears, lists both
  operating systems plus the firmware recovery choice, and hands off to the
  Windows default within the five-second policy.  Windows prints nothing on
  serial after handoff, so the proof is menu + elimination (no Linux handoff
  markers) + retained framebuffer captures; the evidence says
  ``boot-observed``, never login-proven.
* Boot 2 selects the Arch entry with a systemd-boot digit key over serial and
  watches for the Linux EFI-stub handoff and a bounded ttyS0 getty window.
  The gate-7 installer writes no ``console=ttyS0`` into the Arch entry, so
  the login surface is expected to be honestly absent until that seam moves.

After both boots the overlay's GPT is re-read host-side (``qemu-img dd`` of
the first MiB, CRC-verified parse) and compared against the prepared baseline
and the approved layout, proving no cross-OS partition damage without booting
anything further.  Evidence events are judged by
``homelab/workstations/dualboot_acceptance.py``; a check the run cannot prove
renders ``fail`` or ``not-run`` and the judge refuses the gate.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass, field
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import select
import shutil
import struct
import subprocess
import tempfile
import time
import zlib

try:
    from .arch_install_prepare import (
        DISK_SERIAL, _expected_sizes_mib, inspect_overlay)
    from .bootstrap_dc import ovmf_pair
    from .signal_cleanup import SignalGuard, terminate_children
    from .simulation_evidence import private_file, redact
    from .simulated_topology import _base
    from .windows_gui import QmpClient, WindowsGuiError
    from .windows_install_contract import SAFE_SERIAL, sha256
except ImportError:  # Direct execution from homelab/vm.
    from arch_install_prepare import (
        DISK_SERIAL, _expected_sizes_mib, inspect_overlay)
    from bootstrap_dc import ovmf_pair
    from signal_cleanup import SignalGuard, terminate_children
    from simulation_evidence import private_file, redact
    from simulated_topology import _base
    from windows_gui import QmpClient, WindowsGuiError
    from windows_install_contract import SAFE_SERIAL, sha256

from homelab.workstations import dualboot_acceptance as lifecycle
from homelab.workstations.arch_second import EXPECTED
from homelab.workstations.layout import MIB, build_record


DEFAULT_LAYOUT = Path("homelab/workstations/profiles/default-layout.json")
DEFAULT_WORKSTATION = Path(
    "homelab/workstations/profiles/phase1-windows-primary.json")
DEFAULT_RUNS = Path("homelab/var/factory/dualboot-acceptance")
GATE7_OVERLAY_NAME = "arch.qcow2"
GATE7_PASS_STATUS = "observed"
GATE7_PASS_PHASE = "arch-installed-windows-preserved"
OVERLAY_NAME = "dualboot.qcow2"
VARS_NAME = "OVMF_VARS.fd"
EVENTS_NAME = "dualboot-events.jsonl"
MIN_DURATION = 60
MAX_DURATION = 10800

# systemd-boot entry titles the gate-7 install produces: the sorted config
# entry first, then the auto-detected Windows and firmware-recovery entries.
MENU_WINDOWS_ENTRY = "Windows Boot Manager"
MENU_ARCH_ENTRY = "Arch Linux"
MENU_FIRMWARE_ENTRY = "Reboot Into Firmware Interface"
KNOWN_MENU_ENTRIES = (
    MENU_ARCH_ENTRY, MENU_WINDOWS_ENTRY, MENU_FIRMWARE_ENTRY)
# The Linux EFI stub prints on the OVMF console (and therefore serial) before
# ExitBootServices; Windows Boot Manager prints nothing there.  Any of these
# proves a Linux kernel handoff took place.
ARCH_HANDOFF_MARKERS = (
    "EFI stub", "Loading Linux", "Loading initial ramdisk", "Welcome to Arch")
_LOGIN_PROMPT = re.compile(r"[\w.-]+ login:")
_ANSI = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]|\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)")

CONTRACT = lifecycle.load_json(lifecycle.CONTRACT)
REQUIRED_CHECKS: tuple[str, ...] = tuple(CONTRACT["required_checks"])
POLICY_SECONDS: int = CONTRACT["boot_policy"]["menu_timeout_seconds"]
HANDOFF_MIN, HANDOFF_MAX = CONTRACT["boot_policy"][
    "measured_handoff_bounds_seconds"]

SECTOR = 512
GPT_REGION_BYTES = MIB


class DualbootAcceptanceError(RuntimeError):
    """The dual-boot acceptance cannot prove its narrow boundary."""


# --------------------------------------------------------------------------
# GPT: host-side, CRC-verified partition-table reading.
# --------------------------------------------------------------------------


def _guid_text(raw: bytes) -> str:
    """Render 16 mixed-endian GUID bytes as canonical uppercase text."""
    data1, data2, data3 = struct.unpack_from("<IHH", raw, 0)
    return (
        f"{data1:08X}-{data2:04X}-{data3:04X}-"
        f"{raw[8:10].hex().upper()}-{raw[10:16].hex().upper()}"
    )


def read_gpt_region(disk: Path) -> bytes:
    """Extract the guest-visible first MiB of a qcow2 disk without booting."""
    with tempfile.NamedTemporaryFile(
            prefix="telos-gpt-", suffix=".raw") as raw:
        subprocess.run(
            [
                "qemu-img", "dd", "-f", "qcow2", "-O", "raw",
                f"if={Path(disk).resolve()}", f"of={raw.name}",
                "bs=1M", "count=1",
            ],
            check=True, capture_output=True)
        return Path(raw.name).read_bytes()


def parse_gpt(raw: bytes) -> dict:
    """Parse and CRC-verify a primary GPT from raw disk-head bytes."""
    if len(raw) < 34 * SECTOR:
        raise DualbootAcceptanceError("GPT region is too small to parse")
    header = raw[SECTOR:2 * SECTOR]
    if header[:8] != b"EFI PART":
        raise DualbootAcceptanceError("primary GPT signature is missing")
    header_size = struct.unpack_from("<I", header, 12)[0]
    if not 92 <= header_size <= SECTOR:
        raise DualbootAcceptanceError("GPT header size is implausible")
    stored_crc = struct.unpack_from("<I", header, 16)[0]
    zeroed = bytearray(header[:header_size])
    zeroed[16:20] = b"\x00\x00\x00\x00"
    if zlib.crc32(bytes(zeroed)) != stored_crc:
        raise DualbootAcceptanceError("GPT header CRC mismatch")
    entries_lba = struct.unpack_from("<Q", header, 72)[0]
    count = struct.unpack_from("<I", header, 80)[0]
    entry_size = struct.unpack_from("<I", header, 84)[0]
    array_crc = struct.unpack_from("<I", header, 88)[0]
    if not 1 <= count <= 512 or not 128 <= entry_size <= 4096:
        raise DualbootAcceptanceError("GPT entry geometry is implausible")
    start = entries_lba * SECTOR
    end = start + count * entry_size
    if entries_lba < 2 or end > len(raw):
        raise DualbootAcceptanceError(
            "GPT entry array is outside the extracted region")
    array = raw[start:end]
    if zlib.crc32(array) != array_crc:
        raise DualbootAcceptanceError("GPT partition array CRC mismatch")
    partitions = []
    for index in range(count):
        entry = array[index * entry_size:(index + 1) * entry_size]
        if entry[:16] == b"\x00" * 16:
            continue
        first_lba = struct.unpack_from("<Q", entry, 32)[0]
        last_lba = struct.unpack_from("<Q", entry, 40)[0]
        if last_lba < first_lba:
            raise DualbootAcceptanceError("GPT entry extent is inverted")
        partitions.append({
            "index": index + 1,
            "type_guid": _guid_text(entry[:16]),
            "first_lba": first_lba,
            "last_lba": last_lba,
            "size_bytes": (last_lba - first_lba + 1) * SECTOR,
            "name": entry[56:128].decode(
                "utf-16-le", errors="replace").rstrip("\x00"),
        })
    return {
        "partitions": partitions,
        "entries_sha256": hashlib.sha256(array).hexdigest(),
    }


def compare_gpt_layout(parsed: dict, expected_sizes_mib: list[int]) -> None:
    """Require exactly the five approved roles at their approved sizes."""
    ordered = sorted(parsed["partitions"], key=lambda item: item["first_lba"])
    if len(ordered) != len(EXPECTED):
        raise DualbootAcceptanceError(
            f"expected {len(EXPECTED)} partitions, found {len(ordered)}")
    for position, ((role, guid), expected_mib) in enumerate(
            zip(EXPECTED, expected_sizes_mib)):
        actual = ordered[position]
        if actual["type_guid"] != guid:
            raise DualbootAcceptanceError(
                f"partition {position + 1} is not the approved {role} role")
        if actual["size_bytes"] != expected_mib * MIB:
            raise DualbootAcceptanceError(
                f"{role} partition size differs from the approved layout")


# --------------------------------------------------------------------------
# Prepare: overlay the retained gate-7 output; never mutate an input.
# --------------------------------------------------------------------------


def inspect_gate7_bundle(path: Path) -> dict:
    """Require a completed, Windows-preserving gate-7 bundle to overlay."""
    path = Path(path)
    if path.is_symlink() or not path.is_dir():
        raise DualbootAcceptanceError(
            "gate-7 bundle must be a non-symlink directory")
    path = path.resolve(strict=True)
    result_path = path / "evidence" / "result.json"
    try:
        result = json.loads(result_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise DualbootAcceptanceError(
            "gate-7 bundle has no readable evidence/result.json") from error
    if (result.get("status") != GATE7_PASS_STATUS
            or result.get("phase") != GATE7_PASS_PHASE):
        raise DualbootAcceptanceError(
            "gate-7 run did not prove a Windows-preserving Arch install")
    disk = path / GATE7_OVERLAY_NAME
    if disk.is_symlink() or not disk.is_file():
        raise DualbootAcceptanceError(
            "gate-7 bundle is missing its installed dual-boot disk")
    probe = subprocess.run(
        ["qemu-img", "info", "--output=json", str(disk)],
        check=True, capture_output=True, text=True)
    info = json.loads(probe.stdout)
    if info.get("format") != "qcow2":
        raise DualbootAcceptanceError("gate-7 disk must be qcow2")
    backing = info.get("full-backing-filename") or info.get("backing-filename")
    if not backing:
        raise DualbootAcceptanceError(
            "gate-7 disk must overlay the retained Windows disk")
    backing_path = Path(backing)
    if backing_path.is_symlink() or not backing_path.is_file():
        raise DualbootAcceptanceError(
            "retained Windows backing disk is missing or unsafe")
    virtual_size = info.get("virtual-size")
    if not isinstance(virtual_size, int) or virtual_size <= 0:
        raise DualbootAcceptanceError("gate-7 disk virtual size is invalid")
    return {
        "bundle": str(path),
        "path": str(disk.resolve()),
        "sha256": sha256(disk),
        "virtual_size": virtual_size,
        "backing": str(backing_path.resolve()),
        "backing_sha256": sha256(backing_path),
        "result_status": result["status"],
        "result_phase": result["phase"],
    }


def audit_dualboot_boot_boundary(
    command: list[str], *, disk: Path, serial: str,
) -> None:
    """Prove a disk-only cold boot: bootable NVMe present, no PXE, no media.

    This is deliberately the inverse of gate 7's
    ``audit_arch_boot_boundary``: the acceptance boot MUST cold-plug the NVMe
    so OVMF auto-discovers the ESP bootloader (proven in the gate-7 history),
    and MUST carry no network device or installation media so nothing but the
    installed disk can boot.
    """
    if not SAFE_SERIAL.fullmatch(serial):
        raise DualbootAcceptanceError(
            "synthetic disk serial is not safely representable")
    if "-nodefaults" not in command:
        raise DualbootAcceptanceError("QEMU defaults are not disabled")
    forbidden_options = {
        "-netdev", "-nic", "-net", "-cdrom", "-tap", "-bridge", "-vde",
        "-chardev", "-virtfs", "-fsdev",
    }
    forbidden_text = (
        "tap,", "bridge,", "user,", "slirp", "passt", "vde,", "0.0.0.0",
        "media=cdrom", "netdev=", "ipxe", "tftp", "bootindex=",
    )
    for item in command:
        lowered = item.lower()
        if item in forbidden_options:
            raise DualbootAcceptanceError(
                f"forbidden QEMU option for a disk-only boot: {item}")
        for term in forbidden_text:
            if term in lowered:
                raise DualbootAcceptanceError(
                    f"forbidden boot-path text for a disk-only boot: {term}")
    expected = str(Path(disk).resolve())
    writable = []
    devices = []
    for index, argument in enumerate(command):
        if index + 1 >= len(command):
            continue
        if argument == "-drive":
            fields = dict(
                item.split("=", 1)
                for item in command[index + 1].split(",") if "=" in item)
            if (fields.get("readonly") == "on"
                    or fields.get("if") == "pflash"):
                continue
            writable.append(fields)
        elif argument == "-device":
            devices.append(command[index + 1])
    if len(writable) != 1:
        raise DualbootAcceptanceError(
            "acceptance boot must expose exactly one writable disk backend")
    backend = writable[0]
    exposed = backend.get("file")
    if exposed is None or str(Path(exposed).resolve()) != expected:
        raise DualbootAcceptanceError(
            "writable disk backend differs from the authorized overlay")
    if backend.get("if") != "none" or backend.get("id") != "osdisk":
        raise DualbootAcceptanceError(
            "acceptance disk backend must be the detached osdisk backend")
    nvme = [
        value for value in devices
        if value.split(",", 1)[0] == "nvme"
    ]
    if len(nvme) != 1 or len(devices) != 1:
        raise DualbootAcceptanceError(
            "acceptance boot must cold-plug exactly one NVMe disk device")
    fields = dict(
        item.split("=", 1) for item in nvme[0].split(",") if "=" in item)
    if fields.get("drive") != "osdisk" or fields.get("serial") != serial:
        raise DualbootAcceptanceError(
            "cold-plugged NVMe must expose the authorized overlay and serial")
    if "order=c,menu=off" not in command:
        raise DualbootAcceptanceError(
            "acceptance boot must boot the disk deterministically (order=c)")


def qemu_dualboot_command(
    *, disk: Path, variables: Path, qmp_socket: Path, serial: str,
) -> list[str]:
    """Build the disk-only cold-boot command with a pinned QMP socket."""
    if Path(variables).is_symlink():
        raise DualbootAcceptanceError("OVMF variables must not be a symlink")
    if len(str(Path(qmp_socket).resolve()).encode()) > 100:
        raise DualbootAcceptanceError(
            "QMP socket path exceeds the AF_UNIX length bound")
    command = _base("dualboot-acceptance", variables, 8192)
    command += [
        "-boot", "order=c,menu=off",
        "-monitor", "none",
        "-qmp", f"unix:{Path(qmp_socket).resolve()},server=on,wait=off",
        "-drive",
        (
            "if=none,id=osdisk,format=qcow2,cache=none,"
            f"file={Path(disk).resolve()}"
        ),
        "-device", f"nvme,drive=osdisk,serial={serial}",
    ]
    audit_dualboot_boot_boundary(command, disk=disk, serial=serial)
    return command


def _argv_digest(command: list[str]) -> str:
    return hashlib.sha256(
        json.dumps(command, separators=(",", ":")).encode()).hexdigest()


def prepare(args: argparse.Namespace) -> Path:
    run_root = args.run_root
    if run_root.is_symlink():
        raise DualbootAcceptanceError(
            "dual-boot run root must not be a symlink")
    run_root.mkdir(parents=True, exist_ok=True, mode=0o700)
    run_root.chmod(0o700)

    gate7 = inspect_gate7_bundle(args.gate7_bundle)
    ovmf_source = args.ovmf_vars
    if ovmf_source is None:
        pair = ovmf_pair()
        if pair is None:
            raise DualbootAcceptanceError(
                "pristine OVMF variables template was not found")
        ovmf_source = pair[1]
    if ovmf_source.is_symlink() or not ovmf_source.is_file():
        raise DualbootAcceptanceError(
            "OVMF variables template must be a regular non-symlink file")

    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    run = run_root / f"run-{stamp}-{secrets.token_hex(6)}"
    run.mkdir(mode=0o700)
    try:
        overlay = run / OVERLAY_NAME
        variables = run / VARS_NAME
        qmp_socket = (
            Path(tempfile.gettempdir())
            / f"telos-dualboot-{run.name.rsplit('-', 1)[1]}"
            / "dualboot.qmp"
        )
        subprocess.run(
            [
                "qemu-img", "create", "-f", "qcow2", "-F", "qcow2",
                "-b", gate7["path"], str(overlay),
            ],
            check=True, capture_output=True)
        overlay.chmod(0o600)
        shutil.copyfile(ovmf_source, variables)
        variables.chmod(0o600)

        command = qemu_dualboot_command(
            disk=overlay, variables=variables, qmp_socket=qmp_socket,
            serial=DISK_SERIAL)
        record = build_record(
            gate7["virtual_size"], args.layout, args.workstation_profile)
        sizes = _expected_sizes_mib(record)

        baseline = parse_gpt(read_gpt_region(overlay))
        compare_gpt_layout(baseline, sizes)

        overlay_record = inspect_overlay(overlay)
        if overlay_record["backing"] != gate7["path"]:
            raise DualbootAcceptanceError(
                "prepared overlay does not back the gate-7 dual-boot disk")
        authorization = {
            "schema": 1,
            "status": "prepared",
            "external_access": False,
            "pxe": False,
            "media": False,
            "authorization": {
                "disk_serial": DISK_SERIAL,
                "overlay": overlay_record,
                "gate7": gate7,
                "expected_sizes_mib": sizes,
                "gpt_baseline": baseline,
                "qemu_argv_sha256": _argv_digest(command),
                "layout": record,
                "boot_policy": CONTRACT["boot_policy"],
            },
        }
        private_file(
            run / "authorization.json",
            (json.dumps(authorization, indent=2, sort_keys=True)
             + "\n").encode("utf-8"))
        private_file(
            run / "qemu-command.json",
            (json.dumps({"schema": 1, "argv": command}, indent=2)
             + "\n").encode("utf-8"))
        return run
    except BaseException:
        shutil.rmtree(run, ignore_errors=True)
        raise


# --------------------------------------------------------------------------
# Run: two cold boots, observed fail-closed, evidence judged honestly.
# --------------------------------------------------------------------------


@dataclass
class BootObservation:
    """What one cold boot honestly showed on serial, QMP, and frames."""

    transcript: str = ""
    menu_first: float | None = None
    last_output: float | None = None
    entries: list[str] = field(default_factory=list)
    selection: str | None = None
    selection_at: float | None = None
    kernel_handoff_at: float | None = None
    login_prompt_at: float | None = None
    guest_running: bool = False
    frames: int = 0

    @property
    def measured_menu_seconds(self) -> float | None:
        if self.menu_first is None or self.last_output is None:
            return None
        return max(0.0, self.last_output - self.menu_first)


def _plain(text: str) -> str:
    """Strip terminal escape rendering so entry titles compare as text."""
    return _ANSI.sub("", text).replace("\r", "")


def _menu_entries(plain: str) -> list[str]:
    """Known menu entries in first-render (top-to-bottom) order."""
    found = [
        (plain.find(title), title)
        for title in KNOWN_MENU_ENTRIES if title in plain
    ]
    return [title for _position, title in sorted(found)]


def observe_boot(
    process: subprocess.Popen[bytes], capture: Path, *,
    mode: str, qmp, frames_dir: Path | None, timeout: float,
    quiesce: float = 3.0, confirm: float = 45.0, login_wait: float = 120.0,
    frame_interval: float = 10.0, max_frames: int = 360,
) -> BootObservation:
    """Watch one cold boot on serial without ever guessing an outcome.

    ``mode`` is ``windows-default`` (send no input; prove the menu handed off
    by itself) or ``arch-select`` (send the systemd-boot digit key for the
    Arch entry once the menu lists it, then watch for the Linux EFI-stub
    handoff and a bounded getty window).  Timestamps are host-monotonic; the
    handoff instant for the no-input boot is the last serial output before
    ``quiesce`` seconds of silence, because Windows Boot Manager prints
    nothing to the OVMF serial console after taking over.
    """
    if mode not in ("windows-default", "arch-select"):
        raise DualbootAcceptanceError(f"unknown boot mode: {mode}")
    if process.stdout is None:
        raise DualbootAcceptanceError(
            "dual-boot acceptance requires captured serial output")
    observation = BootObservation()
    transcript = bytearray()
    capture.touch(mode=0o600)
    capture.chmod(0o600)
    started = time.monotonic()
    deadline = started + timeout
    handoff_confirm_until: float | None = None
    login_until: float | None = None
    next_frame = started
    frame_failures = 0
    while time.monotonic() < deadline:
        now = time.monotonic()
        if process.poll() is not None:
            break
        if (frames_dir is not None and now >= next_frame
                and observation.frames < max_frames and frame_failures < 3):
            frame = frames_dir / f"{observation.frames + 1:03d}.ppm"
            try:
                qmp.screenshot(frame)
            except (WindowsGuiError, OSError):
                frame_failures += 1
            else:
                if frame.exists():
                    os.chmod(frame, 0o600)
                    observation.frames += 1
            next_frame = now + frame_interval
        ready, _, _ = select.select(
            [process.stdout], [], [],
            min(0.25, max(0.0, deadline - time.monotonic())))
        now = time.monotonic()
        if ready:
            chunk = os.read(process.stdout.fileno(), 4096)
            if not chunk:
                break
            transcript.extend(chunk)
            if len(transcript) > 8 * 1024 * 1024:
                del transcript[:-8 * 1024 * 1024]
            capture.write_bytes(transcript)
            capture.chmod(0o600)
            observation.last_output = now
        plain = _plain(transcript.decode("utf-8", errors="replace"))
        if observation.menu_first is None and any(
                title in plain for title in KNOWN_MENU_ENTRIES):
            observation.menu_first = now
        observation.entries = _menu_entries(plain)
        if observation.kernel_handoff_at is None and any(
                marker in plain for marker in ARCH_HANDOFF_MARKERS):
            observation.kernel_handoff_at = now
        if (observation.login_prompt_at is None
                and _LOGIN_PROMPT.search(plain)):
            observation.login_prompt_at = now
        if mode == "windows-default":
            if (observation.menu_first is not None
                    and handoff_confirm_until is None
                    and observation.last_output is not None
                    and now - observation.last_output >= quiesce):
                # The menu went quiet without input: the default entry took
                # over.  Keep watching so a late Linux handoff still counts
                # against the Windows-default claim.
                handoff_confirm_until = now + confirm
            if (handoff_confirm_until is not None
                    and now >= handoff_confirm_until):
                break
        else:
            if (observation.selection is None
                    and observation.menu_first is not None
                    and MENU_ARCH_ENTRY in observation.entries
                    and MENU_WINDOWS_ENTRY in observation.entries
                    and process.stdin is not None):
                digit = str(observation.entries.index(MENU_ARCH_ENTRY) + 1)
                process.stdin.write(digit.encode("ascii"))
                process.stdin.flush()
                observation.selection = digit
                observation.selection_at = now
            if (observation.selection is not None and login_until is None
                    and observation.kernel_handoff_at is not None):
                login_until = min(
                    deadline, observation.kernel_handoff_at + login_wait)
            if login_until is not None and (
                    observation.login_prompt_at is not None
                    or now >= login_until):
                break
    capture.write_bytes(transcript)
    capture.chmod(0o600)
    observation.transcript = transcript.decode("utf-8", errors="replace")
    try:
        status = qmp.execute("query-status", timeout=10)
        observation.guest_running = (
            status.get("return", {}).get("status") == "running")
    except (WindowsGuiError, OSError):
        observation.guest_running = process.poll() is None
    return observation


def shutdown_guest(
    qmp, process: subprocess.Popen[bytes], *, timeout: float = 180.0,
) -> bool:
    """Bounded ACPI power-button shutdown; True only when the guest exited.

    Neither boot has an in-guest agent path (the gate-5 Windows image and the
    gate-7 Arch install carry no control channel), so ACPI power management
    over QMP is the only honest clean-shutdown lever.  A guest that ignores
    it is terminated by the caller's teardown and recorded as not-clean.
    """
    try:
        qmp.execute("system_powerdown", timeout=10)
    except (WindowsGuiError, OSError):
        return False
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if process.poll() is not None:
            return True
        time.sleep(0.25)
    return False


def _bundle(path: Path) -> tuple[dict, list[str]]:
    if path.is_symlink():
        raise DualbootAcceptanceError(
            "dual-boot bundle must be a private non-symlink directory")
    path = path.resolve(strict=True)
    if path.stat().st_mode & 0o077:
        raise DualbootAcceptanceError(
            "dual-boot bundle must be a private non-symlink directory")
    authorization = json.loads(
        (path / "authorization.json").read_text(encoding="utf-8"))
    command = json.loads(
        (path / "qemu-command.json").read_text(encoding="utf-8"))["argv"]
    if authorization.get("status") != "prepared":
        raise DualbootAcceptanceError(
            "dual-boot authorization is not in the prepared state")
    if (authorization.get("external_access") is not False
            or authorization.get("pxe") is not False
            or authorization.get("media") is not False):
        raise DualbootAcceptanceError(
            "dual-boot authorization must pin external_access/pxe/media false")
    authorized = authorization["authorization"]
    serial = authorized["disk_serial"]
    if _argv_digest(command) != authorized["qemu_argv_sha256"]:
        raise DualbootAcceptanceError(
            "dual-boot QEMU command differs from authorization")
    overlay = path / OVERLAY_NAME
    info = inspect_overlay(overlay)
    if info["sha256"] != authorized["overlay"]["sha256"]:
        raise DualbootAcceptanceError(
            "dual-boot overlay differs from authorization")
    if info["backing"] != authorized["gate7"]["path"]:
        raise DualbootAcceptanceError(
            "dual-boot overlay backs a different disk than authorized")
    gate7_disk = Path(authorized["gate7"]["path"])
    if gate7_disk.is_symlink() or not gate7_disk.is_file():
        raise DualbootAcceptanceError(
            "gate-7 dual-boot disk is missing or unsafe")
    if sha256(gate7_disk) != authorized["gate7"]["sha256"]:
        raise DualbootAcceptanceError(
            "gate-7 dual-boot disk differs from authorization")
    windows_disk = Path(authorized["gate7"]["backing"])
    if windows_disk.is_symlink() or not windows_disk.is_file():
        raise DualbootAcceptanceError(
            "retained Windows disk is missing or unsafe")
    if sha256(windows_disk) != authorized["gate7"]["backing_sha256"]:
        raise DualbootAcceptanceError(
            "retained Windows disk differs from authorization")
    audit_dualboot_boot_boundary(command, disk=overlay, serial=serial)
    required = (overlay, path / VARS_NAME)
    if any(item.is_symlink() or not item.is_file() for item in required):
        raise DualbootAcceptanceError("dual-boot bundle is incomplete or unsafe")
    return authorization, command


def _qmp_socket_path(command: list[str]) -> Path:
    """Recover the pinned QMP socket path from the authorized argv."""
    try:
        value = command[command.index("-qmp") + 1]
    except (ValueError, IndexError):
        raise DualbootAcceptanceError("authorized command carries no QMP socket")
    if not value.startswith("unix:") or ",server=on" not in value:
        raise DualbootAcceptanceError("authorized QMP socket shape is invalid")
    path = Path(value[len("unix:"):].split(",", 1)[0])
    if not path.is_absolute() or len(str(path).encode()) > 100:
        raise DualbootAcceptanceError("authorized QMP socket path is invalid")
    return path


def _connect_qmp(
    path: Path, *, expected_peer_pid: int, timeout: float = 30,
) -> QmpClient:
    deadline = time.monotonic() + timeout
    last_error: BaseException | None = None
    while time.monotonic() < deadline:
        try:
            return QmpClient.connect(
                path, timeout=1, expected_peer_pid=expected_peer_pid)
        except (OSError, WindowsGuiError) as error:
            last_error = error
            time.sleep(0.05)
    raise DualbootAcceptanceError(
        "dual-boot QMP socket did not become ready") from last_error


def _sanitize_log(path: Path, *, maximum: int = 4 * 1024 * 1024) -> None:
    try:
        data = path.read_bytes()
    except FileNotFoundError:
        return
    private_file(path, redact(data[-maximum:]))


def _boot_once(
    command: list[str], *, processes: dict, label: str, evidence: Path,
    qmp_socket: Path, mode: str, timeout: float,
) -> tuple[BootObservation, bool]:
    """One cold boot: launch, observe, bounded shutdown, reaped before return."""
    frames_dir = evidence / f"{label}-frames"
    frames_dir.mkdir(mode=0o700, exist_ok=False)
    process = subprocess.Popen(
        command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT)
    processes[label] = process
    qmp = _connect_qmp(qmp_socket, expected_peer_pid=process.pid)
    clean = False
    try:
        observation = observe_boot(
            process, evidence / f"{label}-serial.log", mode=mode, qmp=qmp,
            frames_dir=frames_dir, timeout=timeout)
        if process.poll() is None:
            clean = shutdown_guest(qmp, process)
        else:
            clean = process.returncode == 0
    finally:
        qmp.close()
        terminate_children([process], terminate_timeout=8, kill_timeout=3)
        qmp_socket.unlink(missing_ok=True)
    return observation, clean


def build_events(
    *,
    boot1: BootObservation | None,
    boot2: BootObservation | None,
    gpt_baseline: dict,
    gpt_after: dict | None,
    expected_sizes_mib: list[int],
    windows_clean_shutdown: bool = False,
    arch_clean_shutdown: bool = False,
) -> list[dict]:
    """Assemble the ordered evidence stream; never upgrade an observation.

    A stage that never ran renders ``not-run``; a stage that ran and did not
    prove its claim renders ``fail``.  Only a live observation renders
    ``pass``, so the judge can trust every field it validates.
    """
    events: list[dict] = []

    def emit(check: str, result: str, **fields: object) -> None:
        events.append({
            "check": check, "result": result, "external_access": False,
            **fields})

    if boot1 is None:
        emit("windows-default-boot", "not-run",
             reason="windows-default boot never started")
    else:
        windows_listed = MENU_WINDOWS_ENTRY in boot1.entries
        passed = (
            boot1.menu_first is not None
            and boot1.selection is None
            and boot1.kernel_handoff_at is None
            and windows_listed
            and boot1.guest_running
            and boot1.frames >= 1
        )
        emit(
            "windows-default-boot", "pass" if passed else "fail",
            default_os="windows",
            input_sent=boot1.selection is not None,
            linux_handoff_observed=boot1.kernel_handoff_at is not None,
            windows_menu_listed=windows_listed,
            guest_running=boot1.guest_running,
            frames_retained=boot1.frames,
            clean_shutdown=windows_clean_shutdown,
            observation="boot-observed",
            login_proven=False)

    if boot1 is None:
        emit("five-second-policy", "not-run",
             reason="windows-default boot never started")
    else:
        measured = boot1.measured_menu_seconds
        passed = (
            measured is not None
            and boot1.selection is None
            and HANDOFF_MIN <= measured <= HANDOFF_MAX
        )
        emit(
            "five-second-policy", "pass" if passed else "fail",
            policy_seconds=POLICY_SECONDS,
            measured_seconds=(
                None if measured is None else round(measured, 2)),
            input_sent=boot1.selection is not None)

    if boot2 is None:
        emit("arch-menu-selectable", "not-run",
             reason="arch-select boot never started")
        emit("arch-console-login-surface", "not-run",
             reason="arch-select boot never started")
    else:
        handoff = boot2.kernel_handoff_at is not None
        emit(
            "arch-menu-selectable",
            "pass" if boot2.selection is not None and handoff else "fail",
            entry=MENU_ARCH_ENTRY,
            selection_method="menu-digit",
            selection_key=boot2.selection,
            kernel_handoff=handoff,
            clean_shutdown=arch_clean_shutdown)
        prompt = boot2.login_prompt_at is not None
        fields: dict[str, object] = {
            "login_prompt_observed": prompt, "login_driven": False}
        if not prompt:
            # Honest known gap: the gate-7 installer writes no console=ttyS0
            # into the Arch entry, so the installed system presents no serial
            # getty for this run to observe.
            fields["reason"] = (
                "no ttyS0 getty observed; installed Arch boot entry carries "
                "no console=ttyS0")
        emit(
            "arch-console-login-surface", "pass" if prompt else "fail",
            **fields)

    seen: list[str] = []
    for observation in (boot1, boot2):
        if observation is not None:
            for entry in observation.entries:
                if entry not in seen:
                    seen.append(entry)
    if boot1 is None and boot2 is None:
        emit("efi-entries-intact", "not-run", reason="no boot was observed")
    else:
        windows_entry = MENU_WINDOWS_ENTRY in seen
        arch_entry = MENU_ARCH_ENTRY in seen
        recovery = MENU_FIRMWARE_ENTRY in seen
        emit(
            "efi-entries-intact",
            "pass" if windows_entry and arch_entry and recovery else "fail",
            method="systemd-boot-menu",
            windows_entry=windows_entry,
            arch_entry=arch_entry,
            recovery_choice=recovery)

    if gpt_after is None:
        emit("partitions-unchanged", "not-run",
             reason="post-boot GPT was never read")
    else:
        identical = (
            gpt_after["entries_sha256"] == gpt_baseline["entries_sha256"])
        try:
            compare_gpt_layout(gpt_after, expected_sizes_mib)
            roles_verified = True
        except DualbootAcceptanceError:
            roles_verified = False
        emit(
            "partitions-unchanged",
            "pass" if identical and roles_verified else "fail",
            baseline_sha256=gpt_baseline["entries_sha256"],
            post_sha256=gpt_after["entries_sha256"],
            byte_identical=identical,
            roles_verified=roles_verified)

    complete = (
        boot1 is not None and boot2 is not None
        and bool(boot1.transcript) and bool(boot2.transcript)
        and (boot1.frames + boot2.frames) >= 1
        and gpt_after is not None
    )
    emit(
        "evidence-complete", "pass" if complete else "fail",
        serial_boots=sum(
            1 for item in (boot1, boot2)
            if item is not None and item.transcript),
        frames=sum(
            item.frames for item in (boot1, boot2) if item is not None),
        gpt_verified=gpt_after is not None,
        windows_clean_shutdown=windows_clean_shutdown,
        arch_clean_shutdown=arch_clean_shutdown)
    return events


def run(bundle: Path, *, duration: float, apply: bool) -> int:
    if not MIN_DURATION <= duration <= MAX_DURATION:
        raise DualbootAcceptanceError(
            f"duration must be between {MIN_DURATION} and "
            f"{MAX_DURATION} seconds")
    authorization, command = _bundle(bundle)
    bundle = bundle.resolve()
    authorized = authorization["authorization"]
    print("Boundary: disk-only cold boots; no network device, media, or PXE")
    print(f"Bundle: {bundle}")
    print(
        "Boot 1: no input; Windows must boot by the five-second default. "
        "Boot 2: the Arch menu entry is selected over serial.")
    print(
        "Honesty: Windows login is NOT driven; its boot is recorded as "
        "boot-observed only")
    print(f"Maximum runtime: {duration:g} seconds")
    if not apply:
        print("dry run; repeat with --apply")
        return 0

    evidence = bundle / "evidence"
    if evidence.exists():
        raise DualbootAcceptanceError("bundle already has execution evidence")
    evidence.mkdir(mode=0o700)
    qmp_socket = _qmp_socket_path(command)
    owned_qmp_root: Path | None = None
    if qmp_socket.parent != bundle:
        qmp_socket.parent.mkdir(mode=0o700, exist_ok=False)
        owned_qmp_root = qmp_socket.parent

    processes: dict[str, subprocess.Popen[bytes]] = {}
    result: dict = {"schema": 1, "status": "fail", "phase": "starting"}
    boot1: BootObservation | None = None
    boot2: BootObservation | None = None
    gpt_after: dict | None = None
    windows_clean = False
    arch_clean = False
    try:
        with SignalGuard():
            per_boot = duration / 2
            result["phase"] = "boot-windows-default"
            boot1, windows_clean = _boot_once(
                command, processes=processes, label="boot1",
                evidence=evidence, qmp_socket=qmp_socket,
                mode="windows-default", timeout=per_boot)
            result["phase"] = "boot-arch-select"
            boot2, arch_clean = _boot_once(
                command, processes=processes, label="boot2",
                evidence=evidence, qmp_socket=qmp_socket,
                mode="arch-select", timeout=per_boot)
            result["phase"] = "gpt-verify"
            gpt_after = parse_gpt(
                read_gpt_region(bundle / OVERLAY_NAME))
            events = build_events(
                boot1=boot1, boot2=boot2,
                gpt_baseline=authorized["gpt_baseline"],
                gpt_after=gpt_after,
                expected_sizes_mib=authorized["expected_sizes_mib"],
                windows_clean_shutdown=windows_clean,
                arch_clean_shutdown=arch_clean)
            private_file(
                evidence / EVENTS_NAME,
                ("\n".join(
                    json.dumps(event, sort_keys=True) for event in events)
                 + "\n").encode("utf-8"))
            result["phase"] = "judging"
            verdict = lifecycle.judge(CONTRACT, events)
            result = {
                "schema": 1,
                "status": "observed",
                "phase": "dualboot-accepted",
                "checks": verdict["checks"],
                "windows_login_proven": verdict["windows_login_proven"],
                "windows_clean_shutdown": windows_clean,
                "arch_clean_shutdown": arch_clean,
                "partitions_byte_identical": True,
            }
            return 0
    except BaseException as error:
        result["error_type"] = type(error).__name__
        result["error"] = redact(
            str(error).encode("utf-8", errors="replace")).decode(
                "utf-8", errors="replace")
        raise
    finally:
        failures = terminate_children(
            processes.values(), terminate_timeout=8, kill_timeout=3)
        if owned_qmp_root is not None:
            qmp_socket.unlink(missing_ok=True)
            try:
                owned_qmp_root.rmdir()
            except OSError:
                failures.append("QMP runtime root was not removed")
        _sanitize_log(evidence / "boot1-serial.log")
        _sanitize_log(evidence / "boot2-serial.log")
        if failures:
            result["cleanup_failures"] = failures
        output = evidence / "result.json"
        output.write_text(
            json.dumps(result, indent=2, sort_keys=True) + "\n",
            encoding="utf-8")
        os.chmod(output, 0o600)


# --------------------------------------------------------------------------
# CLI: prepare / run / judge subcommands behind one wrapper.
# --------------------------------------------------------------------------


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    commands = result.add_subparsers(dest="command", required=True)

    prepare_parser = commands.add_parser(
        "prepare", help="prepare one private dual-boot acceptance bundle")
    prepare_parser.add_argument(
        "--gate7-bundle", type=Path, required=True,
        help="completed gate-7 run bundle whose arch.qcow2 is overlaid")
    prepare_parser.add_argument(
        "--ovmf-vars", type=Path, default=None,
        help="override the pristine OVMF variables template; defaults to "
        "the firmware's fresh no-boot-entry vars")
    prepare_parser.add_argument("--layout", type=Path, default=DEFAULT_LAYOUT)
    prepare_parser.add_argument(
        "--workstation-profile", type=Path, default=DEFAULT_WORKSTATION)
    prepare_parser.add_argument("--run-root", type=Path, default=DEFAULT_RUNS)
    prepare_parser.add_argument("--apply", action="store_true")

    run_parser = commands.add_parser(
        "run", help="run one prepared dual-boot acceptance bundle")
    run_parser.add_argument("--bundle", type=Path, required=True)
    run_parser.add_argument("--duration", type=float, default=1800)
    run_parser.add_argument("--apply", action="store_true")

    judge_parser = commands.add_parser(
        "judge", help="judge one produced dual-boot evidence stream")
    judge_parser.add_argument(
        "--contract", type=Path, default=lifecycle.CONTRACT)
    judge_parser.add_argument("evidence", type=Path)
    return result


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    if args.command == "prepare":
        print("Boundary: private run state; gate-7 inputs are never mutated")
        print("Disk: fresh dualboot.qcow2 overlay; cold-plugged, bootable")
        print("Network and installation media: absent by construction")
        if ovmf_pair() is None and args.ovmf_vars is None:
            print("note: OVMF firmware was not found on this host")
        if not args.apply:
            print("dry run; repeat with --apply to prepare the private bundle")
            return 0
        print(prepare(args))
        return 0
    if args.command == "run":
        return run(args.bundle, duration=args.duration, apply=args.apply)
    return lifecycle.main(
        ["--contract", str(args.contract), str(args.evidence)])


if __name__ == "__main__":
    raise SystemExit(main())
