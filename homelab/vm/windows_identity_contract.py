"""Fail-closed QEMU and private-input boundaries for Windows identity proof."""

from __future__ import annotations

from pathlib import Path

from .simulated_topology import MACS, _base, audit_qemu_argv
from .windows_install_contract import audit_qemu_disk_boundary

DISK_SERIAL = "TELOS-WIN-0001"


def qemu_identity_command(
    *,
    disk: Path,
    variables: Path,
    qmp_socket: Path,
    switch_port: int,
    control_iso: Path | None = None,
) -> list[str]:
    """Boot only the retained native disk on the isolated factory switch."""
    if not 1 <= switch_port <= 65535:
        raise ValueError("switch port is invalid")
    for path, label in (
            (disk, "identity overlay"),
            (variables, "OVMF variables")):
        if path.is_symlink() or not path.is_file():
            raise ValueError(f"{label} must be a regular non-symlink file")
    command = _base("windows-identity", variables, 8192)
    command[command.index("-serial") + 1] = "stdio"
    command += [
        "-boot", "order=c,menu=off",
        "-monitor", "none",
        "-qmp", f"unix:{qmp_socket.resolve()},server=on,wait=off",
        "-device", "VGA",
        "-drive",
        (
            "if=none,id=osdisk,format=qcow2,cache=none,"
            f"file={disk.resolve()}"
        ),
        "-device", f"nvme,drive=osdisk,serial={DISK_SERIAL}",
    ]
    if control_iso is not None:
        if control_iso.is_symlink() or not control_iso.is_file():
            raise ValueError(
                "control ISO must be a regular non-symlink file")
        command += [
            "-device", "virtio-scsi-pci,id=controlbus",
            "-drive",
            (
                "if=none,id=controlmedia,media=cdrom,readonly=on,"
                f"file={control_iso.resolve()}"
            ),
            "-device", "scsi-cd,bus=controlbus.0,drive=controlmedia",
        ]
    command += [
        "-netdev",
        f"socket,id=factory,connect=127.0.0.1:{switch_port}",
        "-device",
        f"e1000e,netdev=factory,mac={MACS['client']}",
    ]
    audit_qemu_argv("client", command, allowed_nic_models=("e1000e",))
    audit_qemu_disk_boundary(command, disk=disk, serial=DISK_SERIAL)
    joined = " ".join(command)
    if "once=n" in joined or "bootindex=" in joined:
        raise ValueError("identity command must not select PXE")
    return command
