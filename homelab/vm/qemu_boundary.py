"""Fail-closed audit for the automated controller QEMU boundary."""

from __future__ import annotations

import os
import re
from pathlib import Path


_SOCKET = re.compile(
    r"socket,id=([A-Za-z0-9_.-]+),connect=127\.0\.0\.1:"
    r"([1-9][0-9]{0,4})\Z")
_FORBIDDEN_OPTIONS = {
    "-nic", "-net", "-tap", "-bridge", "-vde", "-virtfs", "-fsdev",
    "-chardev", "-object",
}
_FORBIDDEN_TEXT = (
    "hostfwd", "guestfwd", "slirp", "passt", "tap,", "bridge,", "vde,",
    "virtiofs", "virtio-9p", "9pnet", "org.qemu.guest_agent",
)


def _option_values(argv: list[str], option: str) -> list[str]:
    values: list[str] = []
    for index, item in enumerate(argv):
        if item == option:
            if index + 1 >= len(argv):
                raise ValueError(f"{option} has no value")
            values.append(argv[index + 1])
    return values


def _fields(value: str) -> dict[str, str]:
    result: dict[str, str] = {}
    for field in value.split(","):
        key, separator, content = field.partition("=")
        if separator:
            result[key] = content
        else:
            result[field] = ""
    return result


def audit_disposable_controller(
    argv: list[str],
    *,
    disk: Path,
    vars_file: Path,
    forbidden_paths: tuple[Path, ...] = (),
    qmp_socket: Path | None = None,
    allowed_chardevs: tuple[str, ...] = (),
) -> None:
    """Require one disposable raw disk, disposable vars, and one loopback NIC."""
    if "-nodefaults" not in argv:
        raise ValueError("QEMU defaults are not disabled")
    lowered = [item.lower() for item in argv]
    for index, item in enumerate(lowered):
        if item in _FORBIDDEN_OPTIONS:
            # Same closed semantics as simulated_topology.audit_qemu_argv:
            # each allowlisted chardev value exactly once, nothing else.
            if (
                item == "-chardev"
                and index + 1 < len(argv)
                and argv[index + 1] in allowed_chardevs
                and argv.count("-chardev") == len(allowed_chardevs)
            ):
                continue
            raise ValueError(f"forbidden QEMU option {item}")
        if any(term in item for term in _FORBIDDEN_TEXT):
            raise ValueError("forbidden host integration in QEMU command")

    exact_disk = str(Path(disk).resolve())
    exact_vars = str(Path(vars_file).resolve())
    forbidden = {str(Path(path).resolve()) for path in forbidden_paths}
    if exact_disk in forbidden or exact_vars in forbidden:
        raise ValueError("disposable paths overlap canonical state")
    for item in argv:
        for path in forbidden:
            if path and path in item:
                raise ValueError("canonical state appears in QEMU command")

    qmp = _option_values(argv, "-qmp")
    expected_qmp = (
        [] if qmp_socket is None else [
            f"unix:{Path(qmp_socket).resolve()},server=on,wait=off"
        ]
    )
    if qmp != expected_qmp:
        raise ValueError("Controller QMP differs from the private boundary")

    drives = [_fields(value) for value in _option_values(argv, "-drive")]
    disks = [
        drive for drive in drives
        if drive.get("if") == "virtio" and drive.get("file") == exact_disk
    ]
    if len(disks) != 1:
        raise ValueError("expected exactly one disposable controller disk")
    controller_disk = disks[0]
    if controller_disk.get("format") != "raw":
        raise ValueError("disposable controller disk must be standalone raw")
    if "backing" in controller_disk or "snapshot" in controller_disk:
        raise ValueError("controller disk must not name backing or snapshot state")

    variables = [
        drive for drive in drives
        if drive.get("if") == "pflash" and drive.get("file") == exact_vars
    ]
    if len(variables) != 1 or variables[0].get("readonly") in {"on", "yes"}:
        raise ValueError("expected exactly one writable disposable vars drive")
    writable = [
        drive for drive in drives
        if drive.get("readonly") not in {"on", "yes"}
    ]
    if writable != [variables[0], controller_disk] and writable != [
            controller_disk, variables[0]]:
        raise ValueError("QEMU command contains another writable drive")

    netdevs = _option_values(argv, "-netdev")
    if len(netdevs) != 1:
        raise ValueError("expected exactly one network backend")
    match = _SOCKET.fullmatch(netdevs[0])
    if not match or int(match.group(2)) > 65535:
        raise ValueError("network backend must connect only to host loopback")
    devices = _option_values(argv, "-device")
    approved = [
        value for value in devices
        if value.startswith("virtio-net-pci,")
        and f"netdev={match.group(1)}" in value.split(",")
    ]
    if len(approved) != 1:
        raise ValueError("loopback backend must have one virtio NIC")
    if any(
        value.lower().startswith(
            ("e1000", "rtl8139", "vmxnet", "ne2k", "pcnet", "virtio-net"))
        and value != approved[0]
        for value in devices
    ):
        raise ValueError("QEMU command contains an additional NIC")

    executable = Path(os.fsdecode(argv[0])).name if argv else ""
    if executable not in {"qemu-system-x86_64", "qemu-kvm"}:
        raise ValueError("unapproved QEMU executable")
