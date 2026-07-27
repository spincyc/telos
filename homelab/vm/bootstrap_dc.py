#!/usr/bin/env python3
"""Plan and operate the temporary, stateful bootstrap-dc QEMU guest."""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import subprocess
import sys
import tempfile
from datetime import UTC, datetime
from pathlib import Path

try:
    from .network import socket_network_args
except ImportError:  # Direct execution from homelab/.
    from network import socket_network_args


NAME = "bootstrap-dc"
VCPUS = 4
MEMORY_MIB = 8192
DISK_SIZE = "80G"
DISK_SERIAL = "TELOS-BOOTSTRAP-DC1"
DEFAULT_STATE = Path("build/homelab/vm/bootstrap-dc")
OVMF_PAIRS = (
    (
        Path("/usr/share/edk2/x64/OVMF_CODE.4m.fd"),
        Path("/usr/share/edk2/x64/OVMF_VARS.4m.fd"),
    ),
    (
        Path("/usr/share/edk2-ovmf/x64/OVMF_CODE.fd"),
        Path("/usr/share/edk2-ovmf/x64/OVMF_VARS.fd"),
    ),
)


def ovmf_pair() -> tuple[Path, Path] | None:
    return next(((code, vars_) for code, vars_ in OVMF_PAIRS
                 if code.is_file() and vars_.is_file()), None)


def paths(state: Path) -> dict[str, Path]:
    return {
        "state": state,
        "disk": state / "bootstrap-dc.qcow2",
        "vars": state / "OVMF_VARS.fd",
        "manifest": state / "manifest.json",
    }


def _regular_file(path: Path) -> bool:
    return path.is_file() and not path.is_symlink()


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _safe_state_path(state: Path) -> bool:
    """Refuse state paths whose existing components include a symlink."""
    candidate = state.absolute()
    for component in (candidate, *candidate.parents):
        if component.exists() and component.is_symlink():
            return False
    return True


def _private_state(files: dict[str, Path]) -> bool:
    if files["state"].stat().st_mode & 0o077:
        return False
    return all(not (files[key].stat().st_mode & 0o077)
               for key in ("disk", "vars", "manifest"))


def qemu_command(
    state: Path,
    iso: Path | None,
    seed_iso: Path | None = None,
) -> list[str]:
    files = paths(state)
    pair = ovmf_pair()
    code = pair[0] if pair else Path("/usr/share/edk2/x64/OVMF_CODE.4m.fd")
    command = [
        "qemu-system-x86_64",
        "-name", NAME,
        "-machine", "q35,accel=kvm",
        "-cpu", "host",
        "-smp", str(VCPUS),
        "-m", str(MEMORY_MIB),
        "-display", "none",
        "-serial", "mon:stdio",
        "-boot", "strict=on,menu=off",
        "-drive", f"if=pflash,format=raw,readonly=on,file={code}",
        "-drive", f"if=pflash,format=raw,file={files['vars']}",
        "-drive", (
            f"if=none,id=osdisk,format=qcow2,cache=none,"
            f"file={files['disk']}"
        ),
        "-device", (
            f"virtio-blk-pci,drive=osdisk,serial={DISK_SERIAL},"
            f"bootindex={2 if iso else 1}"
        ),
    ]
    command += socket_network_args(
        role="listen", mac="52:54:00:11:11:11")
    if iso:
        command += [
            "-device", "virtio-scsi-pci,id=mediabus",
            "-drive",
            f"if=none,id=installmedia,media=cdrom,readonly=on,"
            f"file={iso.resolve()}",
            "-device",
            "scsi-cd,bus=mediabus.0,drive=installmedia,bootindex=1",
        ]
    if seed_iso:
        if not iso:
            command += ["-device", "virtio-scsi-pci,id=mediabus"]
        command += [
            "-drive",
            f"if=none,id=seedmedia,media=cdrom,readonly=on,"
            f"file={seed_iso.resolve()}",
            "-device", "scsi-cd,bus=mediabus.0,drive=seedmedia,bootindex=3",
        ]
    return command


def create(state: Path, apply: bool) -> int:
    files = paths(state)
    pair = ovmf_pair()
    problems = []
    if not shutil.which("qemu-img"):
        problems.append("qemu-img is not installed")
    if not pair:
        problems.append("OVMF firmware was not found")
    if not _safe_state_path(state):
        problems.append(f"state path includes a symlink: {state}")
    if state.exists():
        problems.append(f"state already exists at {state}")
    if problems:
        for problem in problems:
            print(f"error: {problem}", file=sys.stderr)
        return 2
    print(f"create {files['disk']} ({DISK_SIZE}, qcow2)")
    print(f"copy writable firmware variables to {files['vars']}")
    if not apply:
        print("dry run; repeat with --apply")
        return 0
    state.parent.mkdir(parents=True, exist_ok=True)
    staging = Path(tempfile.mkdtemp(prefix=f".{state.name}.", dir=state.parent))
    try:
        staging.chmod(0o700)
        staging_files = paths(staging)
        subprocess.run(
            ["qemu-img", "create", "-f", "qcow2",
             str(staging_files["disk"]), DISK_SIZE],
            check=True,
        )
        shutil.copyfile(pair[1], staging_files["vars"])
        manifest = {
            "schema": 1,
            "created_utc": datetime.now(UTC).isoformat(),
            "name": NAME,
            "vcpus": VCPUS,
            "memory_mib": MEMORY_MIB,
            "disk": {
                "format": "qcow2",
                "size": DISK_SIZE,
                "serial": DISK_SERIAL,
            },
            "firmware": {
                "code": str(pair[0]),
                "variables_source": str(pair[1]),
                "variables_sha256": _sha256(pair[1]),
            },
            "network": {
                "mode": "qemu-socket-loopback",
                "physical_attachment": "blocked-pending-network-gate",
            },
        }
        staging_files["manifest"].write_text(
            json.dumps(manifest, indent=2) + "\n")
        for key in ("disk", "vars", "manifest"):
            staging_files[key].chmod(0o600)
        staging.rename(state)
    except BaseException:
        shutil.rmtree(staging)
        raise
    print(f"created {NAME}; no VM was started")
    return 0


def status(state: Path) -> int:
    files = paths(state)
    safe = _safe_state_path(state)
    regular = safe and all(
        _regular_file(files[key]) for key in ("disk", "vars", "manifest"))
    ready = regular and _private_state(files)
    print(f"{NAME}: {'ready' if ready else 'absent or incomplete'}")
    print(f"state: {state}")
    print("network: isolated (QEMU socket segment on host loopback)")
    print("convergence: deferred until the physical-network gate is approved")
    return 0 if ready else 1


def run(
    state: Path,
    iso: Path | None,
    apply: bool,
    seed_iso: Path | None = None,
) -> int:
    files = paths(state)
    if not _safe_state_path(state):
        print(f"error: state path includes a symlink: {state}", file=sys.stderr)
        return 2
    if state.is_dir() and all(
            _regular_file(files[key]) for key in ("disk", "vars", "manifest")
    ) and not _private_state(files):
        print("error: state permissions must be 0700 with 0600 files",
              file=sys.stderr)
        return 2
    missing = [str(files[key]) for key in ("disk", "vars", "manifest")
               if not _regular_file(files[key])]
    if not shutil.which("qemu-system-x86_64"):
        missing.append("qemu-system-x86_64")
    if iso and not iso.is_file():
        missing.append(str(iso))
    if seed_iso and not seed_iso.is_file():
        missing.append(str(seed_iso))
    if missing:
        print("error: missing: " + ", ".join(missing), file=sys.stderr)
        return 2
    command = qemu_command(state, iso, seed_iso)
    print(" ".join(str(part) for part in command))
    if not apply:
        print("dry run; repeat with --apply")
        return 0
    return subprocess.run(command, check=False).returncode


def destroy(state: Path, confirm: str | None) -> int:
    if confirm != NAME:
        print(f"refusing: pass --confirm {NAME}", file=sys.stderr)
        return 2
    if not _safe_state_path(state):
        print(f"refusing: state path includes a symlink: {state}",
              file=sys.stderr)
        return 2
    files = paths(state)
    if not state.exists():
        print(f"{NAME}: already absent")
        return 0
    unexpected = [
        entry for entry in state.iterdir()
        if entry not in files.values() or entry.is_symlink()
    ]
    if unexpected:
        print("refusing: state directory contains unexpected files:", file=sys.stderr)
        for entry in unexpected:
            print(f"  {entry}", file=sys.stderr)
        return 2
    for key in ("disk", "vars", "manifest"):
        files[key].unlink(missing_ok=True)
    state.rmdir()
    print(f"destroyed temporary state at {state}")
    return 0


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(
        description="Safe lifecycle for the isolated bootstrap-dc guest")
    result.add_argument("--state-dir", type=Path, default=DEFAULT_STATE)
    commands = result.add_subparsers(dest="command")
    create_parser = commands.add_parser("create")
    create_parser.add_argument("--apply", action="store_true")
    commands.add_parser("status")
    run_parser = commands.add_parser("run")
    run_parser.add_argument("--iso", type=Path)
    run_parser.add_argument(
        "--seed-iso",
        type=Path,
        help="attach a second read-only data CD after the installer and disk",
    )
    run_parser.add_argument("--apply", action="store_true")
    destroy_parser = commands.add_parser("destroy")
    destroy_parser.add_argument("--confirm")
    return result


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    command = args.command or "status"
    if command == "create":
        return create(args.state_dir, args.apply)
    if command == "run":
        return run(args.state_dir, args.iso, args.apply, args.seed_iso)
    if command == "destroy":
        return destroy(args.state_dir, args.confirm)
    return status(args.state_dir)


if __name__ == "__main__":
    raise SystemExit(main())
