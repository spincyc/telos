#!/usr/bin/env python3
"""Prepare one authorized private Arch-second installation run bundle.

The bundle overlays the persistent Windows-installed disk (the gate-5 output)
with a fresh qcow2 overlay so a disposable test never mutates the retained
Windows partitions.  The pinned QEMU command PXE-boots the Arch archiso live
shell against that overlay; the run stage drives the Windows-preserving
installer emitted by ``workstations.arch_second``.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import inspect
import json
import os
from pathlib import Path
import secrets
import shutil
import subprocess
import tempfile

try:
    from .bootstrap_dc import ovmf_pair
    from .simulated_topology import MACS, _base, audit_qemu_argv
    from .windows_install_contract import audit_qemu_disk_boundary, sha256
except ImportError:  # Direct execution from homelab/vm.
    from bootstrap_dc import ovmf_pair
    from simulated_topology import MACS, _base, audit_qemu_argv
    from windows_install_contract import audit_qemu_disk_boundary, sha256

from homelab.workstations import arch_second
from homelab.workstations.layout import GIB, build_record


DEFAULT_RELEASES = Path("homelab/var/pxe")
DEFAULT_SEED = Path("homelab/var/seed/telos-controller-seed.iso")
DEFAULT_LAYOUT = Path("homelab/workstations/profiles/default-layout.json")
DEFAULT_WORKSTATION = Path(
    "homelab/workstations/profiles/phase1-windows-primary.json")
DEFAULT_WINDOWS_DISK = Path(
    "homelab/var/factory/windows-installs/"
    "run-20260728T114233Z-afecdf7cc9d0/windows.qcow2")
DEFAULT_RUNS = Path("homelab/var/factory/arch-installs")
DISK_SERIAL = "TELOS-WIN-0001"
DISK_BYTES = 256 * GIB
GUEST_DISK = "/dev/nvme0n1"
DEFAULT_HOSTNAME = "telos-workstation"
VERIFY_NAME = "arch-second-verify.py"
INSTALLER_NAME = "arch-install.sh"
OVERLAY_NAME = "arch.qcow2"
VARS_NAME = "OVMF_VARS.fd"


class ArchInstallPrepareError(RuntimeError):
    """The proposed Arch-second run cannot prove its narrow boundary."""


def _selected(releases: Path) -> dict:
    value = json.loads(
        (releases / "selected-release-set.json").read_text(encoding="utf-8"))
    if set(value) != {"schema", "version", "manifest_sha256"}:
        raise ArchInstallPrepareError(
            "selected release descriptor has invalid fields")
    return value


def _private_file(path: Path, payload: str) -> None:
    descriptor = os.open(
        path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as stream:
        stream.write(payload)


def inspect_base_windows_disk(path: Path) -> dict:
    """Require a standalone 256 GiB Windows qcow2 to overlay non-destructively."""
    path = Path(path)
    if path.is_symlink() or not path.is_file():
        raise ArchInstallPrepareError(
            "persistent Windows disk must be a regular non-symlink file")
    result = subprocess.run(
        ["qemu-img", "info", "--output=json", str(path)],
        check=True, capture_output=True, text=True)
    info = json.loads(result.stdout)
    if info.get("format") != "qcow2" or info.get("backing-filename"):
        raise ArchInstallPrepareError(
            "persistent Windows disk must be a standalone qcow2 base")
    virtual_size = info.get("virtual-size")
    if not isinstance(virtual_size, int) or virtual_size != DISK_BYTES:
        raise ArchInstallPrepareError(
            "persistent Windows disk is not the expected 256 GiB base")
    return {
        "path": str(path.resolve()),
        "virtual_size": virtual_size,
        "format": "qcow2",
        "sha256": sha256(path),
    }


def inspect_overlay(path: Path) -> dict:
    """Return overlay identity and its resolved backing target."""
    path = Path(path)
    if path.is_symlink() or not path.is_file():
        raise ArchInstallPrepareError(
            "Arch overlay must be a regular non-symlink file")
    result = subprocess.run(
        ["qemu-img", "info", "--output=json", str(path)],
        check=True, capture_output=True, text=True)
    info = json.loads(result.stdout)
    if info.get("format") != "qcow2":
        raise ArchInstallPrepareError("Arch overlay must be qcow2")
    backing = info.get("full-backing-filename") or info.get("backing-filename")
    if not backing:
        raise ArchInstallPrepareError(
            "Arch overlay must be backed by the persistent Windows disk")
    return {
        "path": str(path.resolve()),
        "format": "qcow2",
        "backing": str(Path(backing).resolve()),
        "sha256": sha256(path),
    }


def _expected_sizes_mib(record: dict) -> list[int]:
    partitions = {
        item["type"]: item["size_mib"]
        for item in record["layout"]["partitions"]
    }
    order = ("esp", "msr", "basic-data", "linux-root", "windows-recovery")
    if set(partitions) != set(order):
        raise ArchInstallPrepareError(
            "layout does not describe the five Windows-first roles")
    return [partitions[name] for name in order]


def render_arch_second_verify() -> str:
    """Emit a standalone verify script from the live arch_second symbols.

    Extracting the exact source keeps the guest-side check from drifting away
    from the contract, while dropping the module's package-registry imports so
    it runs inside the archiso live shell with only the standard library.
    """
    parts = [
        "#!/usr/bin/env python3",
        '"""Standalone Windows-preserving Arch verify.',
        "",
        "Generated from workstations.arch_second; do not edit by hand.",
        '"""',
        "from __future__ import annotations",
        "from dataclasses import dataclass",
        "import argparse",
        "import json",
        "import re",
        "import subprocess",
        "from pathlib import Path",
        "from typing import Any, Mapping, Sequence",
        "",
        f"ESP = {arch_second.ESP!r}",
        f"MSR = {arch_second.MSR!r}",
        f"WINDOWS = {arch_second.WINDOWS!r}",
        f"LINUX_ROOT_X86_64 = {arch_second.LINUX_ROOT_X86_64!r}",
        f"WINDOWS_RECOVERY = {arch_second.WINDOWS_RECOVERY!r}",
        f"EXPECTED = {arch_second.EXPECTED!r}",
        f"SAFE_HOSTNAME = re.compile({arch_second.SAFE_HOSTNAME.pattern!r})",
        f"SAFE_SERIAL = re.compile({arch_second.SAFE_SERIAL.pattern!r})",
        f"SAFE_DISK = re.compile({arch_second.SAFE_DISK.pattern!r})",
        "",
        inspect.getsource(arch_second.InstallContractError),
        inspect.getsource(arch_second.Partition),
        inspect.getsource(arch_second.Disk),
        inspect.getsource(arch_second._partition_number),
        inspect.getsource(arch_second.parse_lsblk),
        inspect.getsource(arch_second.validate_windows_first),
        inspect.getsource(arch_second._find_arch_gap),
        inspect.getsource(arch_second.main),
        "",
        'if __name__ == "__main__":',
        "    raise SystemExit(main())",
        "",
    ]
    return "\n".join(parts)


def qemu_arch_install_command(
    *,
    disk: Path,
    variables: Path,
    qmp_socket: Path,
    switch_port: int,
    serial: str,
) -> list[str]:
    """Build the persistent-disk UEFI/NVMe/e1000e network-boot command.

    The install boot is network-only (``order=n``): PXE deterministically wins
    and firmware never falls through to the bootable Windows ESP that the
    overlaid persistent disk still carries.  The NVMe disk stays attached as
    the install target, it is simply outside the boot path.
    """
    if not 1 <= switch_port <= 65535:
        raise ArchInstallPrepareError("switch port is invalid")
    if Path(variables).is_symlink():
        raise ArchInstallPrepareError("OVMF variables must not be a symlink")
    # sun_path is 108 bytes including the terminator; an over-long path would
    # not fail until QMP bind, after the guests are booted.
    if len(str(Path(qmp_socket).resolve()).encode()) > 100:
        raise ArchInstallPrepareError(
            "QMP socket path exceeds the AF_UNIX length bound")
    command = _base("arch-install", variables, 8192)
    command[command.index("-serial") + 1] = "stdio"
    command += [
        "-boot", "order=n,menu=off",
        "-monitor", "none",
        "-qmp", f"unix:{Path(qmp_socket).resolve()},server=on,wait=off",
        "-drive",
        (
            "if=none,id=osdisk,format=qcow2,cache=none,"
            f"file={Path(disk).resolve()}"
        ),
        "-device", f"nvme,drive=osdisk,serial={serial}",
        "-netdev",
        f"socket,id=factory,connect=127.0.0.1:{switch_port}",
        "-device",
        f"e1000e,netdev=factory,mac={MACS['client']}",
    ]
    audit_qemu_argv("client", command, allowed_nic_models=("e1000e",))
    audit_qemu_disk_boundary(command, disk=disk, serial=serial)
    return command


def prepare(args: argparse.Namespace) -> Path:
    run_root = args.run_root
    if run_root.is_symlink():
        raise ArchInstallPrepareError("Arch run root must not be a symlink")
    run_root.mkdir(parents=True, exist_ok=True, mode=0o700)
    run_root.chmod(0o700)

    windows_disk = args.windows_disk
    base = inspect_base_windows_disk(windows_disk)
    # The install boot must PXE, so it must NOT inherit the Windows firmware's
    # NVRAM.  The Windows-installed OVMF_VARS.fd carries a "Windows Boot
    # Manager" boot entry that firmware would prefer over the network, wedging
    # the install.  Copy the pristine OVMF variables template (no boot
    # entries) instead; combined with order=n this makes PXE deterministic.
    ovmf_source = args.ovmf_vars
    if ovmf_source is None:
        pair = ovmf_pair()
        if pair is None:
            raise ArchInstallPrepareError(
                "pristine OVMF variables template was not found")
        ovmf_source = pair[1]
    if ovmf_source.is_symlink() or not ovmf_source.is_file():
        raise ArchInstallPrepareError(
            "OVMF variables template must be a regular non-symlink file")

    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    run = run_root / f"run-{stamp}-{secrets.token_hex(6)}"
    run.mkdir(mode=0o700)
    try:
        overlay = run / OVERLAY_NAME
        variables = run / VARS_NAME
        # A bundle-adjacent socket exceeds the AF_UNIX bound from a deep
        # checkout; pin a short run-unique path the runner creates and
        # removes.  The run token keeps concurrent bundles distinct.
        qmp_socket = (
            Path(tempfile.gettempdir())
            / f"telos-arch-{run.name.rsplit('-', 1)[1]}"
            / "arch.qmp"
        )
        subprocess.run(
            [
                "qemu-img", "create", "-f", "qcow2", "-F", "qcow2",
                "-b", base["path"], str(overlay),
            ],
            check=True, capture_output=True)
        overlay.chmod(0o600)
        shutil.copyfile(ovmf_source, variables)
        variables.chmod(0o600)

        command = qemu_arch_install_command(
            disk=overlay, variables=variables, qmp_socket=qmp_socket,
            switch_port=args.switch_port, serial=DISK_SERIAL)
        selected = _selected(args.releases)
        record = build_record(
            base["virtual_size"], args.layout, args.workstation_profile)
        sizes = _expected_sizes_mib(record)

        verify_path = run / VERIFY_NAME
        installer_path = run / INSTALLER_NAME
        _private_file(verify_path, render_arch_second_verify())
        _private_file(
            installer_path,
            arch_second.render_installer(
                disk_path=GUEST_DISK, disk_serial=DISK_SERIAL,
                hostname=args.hostname, expected_sizes_mib=sizes))

        overlay_record = inspect_overlay(overlay)
        if overlay_record["backing"] != base["path"]:
            raise ArchInstallPrepareError(
                "prepared overlay does not back the persistent Windows disk")
        command_digest = _argv_digest(command)
        authorization = {
            "schema": 1,
            "authorization": {
                "release_version": selected["version"],
                "release_manifest_sha256": selected["manifest_sha256"],
                "disk_serial": DISK_SERIAL,
                "guest_disk": GUEST_DISK,
                "hostname": args.hostname,
                "overlay": overlay_record,
                "backing_windows_disk": base,
                "expected_sizes_mib": sizes,
                "qemu_argv_sha256": command_digest,
                "layout": record,
            },
            "guest_inputs": [
                {"name": path.name, "sha256": sha256(path)}
                for path in (installer_path, verify_path)
            ],
        }
        _private_file(
            run / "authorization.json",
            json.dumps(authorization, indent=2, sort_keys=True) + "\n")
        _private_file(
            run / "qemu-command.json",
            json.dumps({"schema": 1, "argv": command}, indent=2) + "\n")
        return run
    except BaseException:
        shutil.rmtree(run, ignore_errors=True)
        raise


def _argv_digest(command: list[str]) -> str:
    import hashlib
    return hashlib.sha256(
        json.dumps(command, separators=(",", ":")).encode()).hexdigest()


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument(
        "--windows-disk", type=Path, default=DEFAULT_WINDOWS_DISK,
        help="persistent gate-5 Windows-installed qcow2 to preserve")
    result.add_argument(
        "--ovmf-vars", type=Path, default=None,
        help="override the pristine OVMF variables template copied for the "
        "install boot; defaults to the firmware's fresh no-boot-entry vars")
    result.add_argument("--releases", type=Path, default=DEFAULT_RELEASES)
    result.add_argument("--seed", type=Path, default=DEFAULT_SEED)
    result.add_argument("--layout", type=Path, default=DEFAULT_LAYOUT)
    result.add_argument(
        "--workstation-profile", type=Path, default=DEFAULT_WORKSTATION)
    result.add_argument("--run-root", type=Path, default=DEFAULT_RUNS)
    result.add_argument("--hostname", default=DEFAULT_HOSTNAME)
    result.add_argument("--switch-port", type=int, default=31415)
    result.add_argument("--apply", action="store_true")
    return result


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    print("Boundary: private run state and loopback-only QEMU command")
    print(f"Disk: fresh qcow2 overlay over {args.windows_disk}")
    print(f"NVMe serial: {DISK_SERIAL}; Windows partitions are preserved")
    print("Arch release: PXE-published by a disposable Controller at run time")
    print("Physical disks, host networking and UniFi: untouched")
    if ovmf_pair() is None:
        print("note: OVMF firmware was not found on this host")
    if not args.apply:
        print("dry run; repeat with --apply to prepare the private bundle")
        return 0
    print(prepare(args))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
