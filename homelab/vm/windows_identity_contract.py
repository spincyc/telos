"""Fail-closed QEMU and private-input boundaries for Windows identity proof."""

from __future__ import annotations

from pathlib import Path

from .guest_progress_collector import (
    attach_planned_progress_port, audit_progress_port)
from .simulated_topology import MACS, _base, audit_qemu_argv
from .windows_control_serial import attach_qemu_serial
from .windows_install_contract import audit_qemu_disk_boundary

DISK_SERIAL = "TELOS-WIN-0001"
STATIC_CONTROL_BUS = "ide.1"
OPTICAL_DEVICE = "ide-cd"
PRIVATE_MEDIA_CONTROLLER = "identityusb"
PRIVATE_MEDIA_CONTROLLER_BUS = f"{PRIVATE_MEDIA_CONTROLLER}.0"
PRIVATE_MEDIA_PORT = "1"
PRIVATE_MEDIA_PARENT_DEVICE = "usb-bot"
PRIVATE_MEDIA_CHILD_DEVICE = "scsi-cd"


def qemu_identity_command(
    *,
    disk: Path,
    variables: Path,
    qmp_socket: Path,
    serial_socket: Path,
    switch_port: int,
    control_iso: Path | None = None,
    require_absent_serial_socket: bool = True,
    progress_socket: Path | None = None,
) -> list[str]:
    """Boot only the retained native disk on the isolated factory switch.

    ``require_absent_serial_socket`` defaults to the launch-time invariant
    (the socket must not yet exist).  The live acceptance secret scan
    re-derives the running argv while QEMU already owns the server socket, so
    it passes ``False`` to require a live private socket instead of absence.

    ``progress_socket`` opt-in arms the diagnostic guest-progress port.  This
    is the one lane that already owns a separately audited character device
    (the private COM1 control socket), so the port is attached after it and
    the finished argv is re-audited against a closed two-value chardev
    allowlist -- strictly more than the pre-serial audit alone proved.  No
    Windows reporter ships, so an armed port here records an absent stream.
    """
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
        "-boot", "menu=off,strict=on",
        "-monitor", "none",
        "-qmp", f"unix:{qmp_socket.resolve()},server=on,wait=off",
        "-device", "VGA",
        "-drive",
        (
            "if=none,id=osdisk,format=qcow2,cache=none,"
            f"file={disk.resolve()}"
        ),
        "-device",
        f"nvme,drive=osdisk,serial={DISK_SERIAL},bootindex=1",
    ]
    if control_iso is not None:
        if control_iso.is_symlink() or not control_iso.is_file():
            raise ValueError(
                "control ISO must be a regular non-symlink file")
        if control_iso.stat().st_mode & 0o222:
            raise ValueError("control ISO must be read-only")
        command += [
            "-drive",
            (
                "if=none,id=controlmedia,media=cdrom,readonly=on,"
                f"file={control_iso.resolve()}"
            ),
            "-device",
            (
                f"{OPTICAL_DEVICE},bus={STATIC_CONTROL_BUS},"
                "drive=controlmedia,id=telos-control-cd"
            ),
        ]
    command += [
        "-device", f"qemu-xhci,id={PRIVATE_MEDIA_CONTROLLER}",
    ]
    command += [
        "-netdev",
        f"socket,id=factory,connect=127.0.0.1:{switch_port}",
        "-device",
        f"e1000e,netdev=factory,mac={MACS['client']},romfile=",
    ]
    audit_qemu_argv("client", command, allowed_nic_models=("e1000e",))
    audit_qemu_disk_boundary(command, disk=disk, serial=DISK_SERIAL)
    joined = " ".join(command)
    if (
        "order=" in command[command.index("-boot") + 1]
        or "once=" in command[command.index("-boot") + 1]
        or joined.count("bootindex=") != 1
        or command[command.index("-boot") + 1]
        != "menu=off,strict=on"
        or not any(
            value
            == f"nvme,drive=osdisk,serial={DISK_SERIAL},bootindex=1"
            for value in command
        )
        or not any(
            value.startswith("e1000e,") and value.endswith(",romfile=")
            for value in command
        )
    ):
        raise ValueError("identity command must not select PXE")
    # The generic topology audit intentionally rejects all host character
    # devices. Add only the separately audited, fixed-purpose serial socket
    # after that broad audit has accepted the rest of the command.
    command = attach_qemu_serial(
        command, serial_socket,
        require_absent_socket=require_absent_serial_socket)
    serial_chardev = command[command.index("-chardev") + 1]
    if progress_socket is not None:
        command, _ = attach_planned_progress_port(command, progress_socket)
    # Re-audit the finished argv, chardevs included: the allowlist holds
    # exactly the private serial socket and, when armed, exactly the
    # canonical progress channel.  Nothing else may be a character device.
    audit_qemu_argv(
        "client", command, allowed_nic_models=("e1000e",),
        allowed_chardevs=(serial_chardev,) + audit_progress_port(command))
    return command
