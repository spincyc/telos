"""The QEMU/OVMF acceptance lab (ADR 0056).

Builds a virtual isolated network with no router on it, boots virtual machines
under UEFI firmware, and drives the genuine installer over their serial console
using the pty driver.

The key arrangement: QEMU runs with `-nographic -serial stdio`, so the guest's
serial console *is* the QEMU process's stdin and stdout. `pty_driver.drive()`
already knows how to answer prompts on a process's stdio, so it drives a virtual
machine with no changes at all. The installer cannot tell the difference between
this and a person at a console, which is exactly what ADR 0058 requires.

Nothing here needs root. Networking is QEMU's socket transport, which creates a
layer-2 segment between guests without touching the host's networking, so a
virtual Controller can be the sole DHCP authority on it without any risk of
answering on a real network.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

QEMU = "qemu-system-x86_64"
QEMU_IMG = "qemu-img"

# Arch ships OVMF under edk2; other distributions differ. Search rather than
# assume, and say plainly what is missing if none is found.
OVMF_CODE_CANDIDATES = (
    "/usr/share/edk2/x64/OVMF_CODE.4m.fd",
    "/usr/share/edk2/x64/OVMF_CODE.fd",
    "/usr/share/edk2-ovmf/x64/OVMF_CODE.fd",
    "/usr/share/OVMF/OVMF_CODE.fd",
)
OVMF_VARS_CANDIDATES = (
    "/usr/share/edk2/x64/OVMF_VARS.4m.fd",
    "/usr/share/edk2/x64/OVMF_VARS.fd",
    "/usr/share/edk2-ovmf/x64/OVMF_VARS.fd",
    "/usr/share/OVMF/OVMF_VARS.fd",
)

# A fixed port for the virtual segment. Nothing outside the lab connects to it.
LAB_SOCKET_PORT = 12960


def serial_for(name: str) -> str:
    """A stable, obviously-synthetic serial for a lab machine's disk.

    Obviously synthetic on purpose: if one of these ever shows up in a summary
    on real hardware, it should be unmistakable that the wrong thing is being
    installed. Stable so a test can predict what the harness must type.
    """
    return f"LAB-{name.upper()}-0001"


def _first_existing(candidates) -> str | None:
    for candidate in candidates:
        if Path(candidate).is_file():
            return candidate
    return None


def missing_requirements() -> list[str]:
    """What must be installed before the matrix can run."""
    missing = []
    if not shutil.which(QEMU):
        missing.append(f"{QEMU} (pacman -S qemu-base)")
    if not shutil.which(QEMU_IMG):
        missing.append(f"{QEMU_IMG} (pacman -S qemu-base)")
    if not _first_existing(OVMF_CODE_CANDIDATES):
        missing.append("OVMF firmware (pacman -S edk2-ovmf)")
    return missing


def available() -> bool:
    return not missing_requirements()


@dataclass
class Machine:
    """One virtual machine in the lab."""

    name: str
    disk_gib: int = 80
    memory_mb: int = 2048
    cpus: int = 2
    mac: str = "52:54:00:00:00:01"
    # A virtio disk reports no serial unless one is set, and the installer will
    # not offer a disk it cannot confirm at the authorization prompt (ADR 0058)
    # -- so without this the matrix could never install anything. Setting it is
    # also the faithful thing to do: real hardware reports a serial.
    disk_serial: str = ""
    # The first machine listens; the others connect to it, which forms one
    # layer-2 segment among the guests and nothing else.
    listens: bool = False
    boot_kernel: Path | None = None
    boot_initrd: Path | None = None
    kernel_arguments: str = ""

    disk_path: Path | None = field(default=None, init=False)
    vars_path: Path | None = field(default=None, init=False)


class Lab:
    """A temporary directory holding disk images and per-machine UEFI variables.

    Each run gets its own OVMF variable store. Firmware state -- boot entries,
    Secure Boot enrolment -- therefore never leaks from one run into the next,
    which would otherwise make a passing test depend on a previous one.
    """

    def __init__(self, root: Path | None = None) -> None:
        self._temporary = root is None
        self.root = Path(root) if root else Path(tempfile.mkdtemp(prefix="homelab-lab-"))
        self.machines: dict[str, Machine] = {}

    def close(self) -> None:
        if self._temporary and self.root.exists():
            shutil.rmtree(self.root, ignore_errors=True)

    def __enter__(self) -> "Lab":
        return self

    def __exit__(self, *_) -> None:
        self.close()

    def add(self, machine: Machine) -> Machine:
        machine.disk_path = self.root / f"{machine.name}.qcow2"
        if not machine.disk_serial:
            machine.disk_serial = serial_for(machine.name)
        subprocess.run(
            [QEMU_IMG, "create", "-f", "qcow2", str(machine.disk_path), f"{machine.disk_gib}G"],
            check=True, capture_output=True)

        template = _first_existing(OVMF_VARS_CANDIDATES)
        machine.vars_path = self.root / f"{machine.name}-OVMF_VARS.fd"
        if template:
            shutil.copy2(template, machine.vars_path)
        self.machines[machine.name] = machine
        return machine

    def argv(self, machine: Machine) -> list[str]:
        """The exact QEMU command line for one machine."""
        code = _first_existing(OVMF_CODE_CANDIDATES)
        argv = [
            QEMU,
            "-machine", "q35,accel=kvm:tcg",
            "-cpu", "max",
            "-smp", str(machine.cpus),
            "-m", str(machine.memory_mb),
            "-nographic",
            "-serial", "stdio",
            "-monitor", "none",
            # No default NIC or user networking: the lab segment is the only
            # network, and it has no route off itself. ADR 0011's no-routing
            # boundary is enforced by the topology, not by configuration.
            "-nodefaults",
            "-rtc", "base=utc",
            # UEFI only. ADR 0019, and the installer refuses a BIOS target.
            "-drive", f"if=pflash,format=raw,unit=0,readonly=on,file={code}",
        ]
        if machine.vars_path and machine.vars_path.exists():
            argv += ["-drive", f"if=pflash,format=raw,unit=1,file={machine.vars_path}"]

        # Split into a backend and an explicit device so the serial can be set.
        # `if=virtio` shorthand gives no way to do that, and a disk with no
        # serial is one the installer refuses to offer.
        argv += ["-drive", f"file={machine.disk_path},if=none,id=disk0,format=qcow2",
                 "-device", f"virtio-blk-pci,drive=disk0,serial={machine.disk_serial}"]

        transport = (f"socket,id=lab,listen=:{LAB_SOCKET_PORT}" if machine.listens
                     else f"socket,id=lab,connect=127.0.0.1:{LAB_SOCKET_PORT}")
        argv += ["-netdev", transport,
                 "-device", f"virtio-net-pci,netdev=lab,mac={machine.mac}"]

        if machine.boot_kernel:
            argv += ["-kernel", str(machine.boot_kernel)]
            if machine.boot_initrd:
                argv += ["-initrd", str(machine.boot_initrd)]
            arguments = machine.kernel_arguments or "console=ttyS0,115200"
            argv += ["-append", arguments]

        return argv


def describe_plan(lab: Lab) -> list[str]:
    """What the matrix will do, printable without running anything."""
    lines = ["QEMU acceptance lab", f"  working directory: {lab.root}", ""]
    for machine in lab.machines.values():
        role = "listens on the lab segment" if machine.listens else "connects to the lab segment"
        lines.append(f"  {machine.name}")
        lines.append(f"    {machine.cpus} vCPU, {machine.memory_mb} MiB, {machine.disk_gib} GiB disk")
        lines.append(f"    MAC {machine.mac}, {role}")
        lines.append(f"    UEFI, per-run variable store at {machine.vars_path}")
    lines.append("")
    lines.append("  No route off the lab segment: ADR 0011's boundary is the topology.")
    return lines
