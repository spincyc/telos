#!/usr/bin/env python3
"""Plan and operate the temporary, stateful bootstrap-dc QEMU guest."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from datetime import UTC, datetime
from pathlib import Path

try:
    from .network import socket_network_args
    from .preflight_receipt import verify as verify_preflight_receipt
except ImportError:  # Direct execution from homelab/.
    from network import socket_network_args
    from preflight_receipt import verify as verify_preflight_receipt


NAME = "bootstrap-dc"
VCPUS = 4
MEMORY_MIB = 8192
DISK_SIZE = "80G"
DISK_SERIAL = "TELOS-BOOTSTRAP-DC1"
DEFAULT_STATE = Path("build/homelab/vm/bootstrap-dc")
REPOSITORY = Path(__file__).resolve().parents[2]
SYS_CLASS_NET = Path("/sys/class/net")
_NET_NAME = re.compile(r"^[a-zA-Z0-9_.-]{1,15}$")
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


def load_network_config(path: Path) -> dict[str, str]:
    """Load a private config for a host-created tap already on a bridge."""
    if not _regular_file(path):
        raise ValueError("network config must be a regular file, not a symlink")
    stat = path.stat()
    if stat.st_uid != os.getuid() or stat.st_mode & 0o077:
        raise ValueError(
            "network config must be owned by this user and no broader than 0600")
    try:
        raw = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError) as error:
        raise ValueError(f"cannot read network config: {error}") from error
    expected = {"schema", "mode", "tap", "bridge", "uplink", "mac"}
    if not isinstance(raw, dict) or set(raw) != expected:
        raise ValueError(
            "network config requires only schema, mode, tap, bridge, uplink, "
            "and mac")
    if raw["schema"] != 2 or raw["mode"] != "precreated-tap":
        raise ValueError("network config must select schema 2 precreated-tap")
    for key in ("tap", "bridge", "uplink"):
        if not isinstance(raw[key], str) or not _NET_NAME.fullmatch(raw[key]):
            raise ValueError(f"invalid {key} interface name")
    if (not isinstance(raw["mac"], str)
            or not re.fullmatch(
                r"52:54:00:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}",
                raw["mac"].lower())):
        raise ValueError("MAC must use the synthetic 52:54:00 prefix")
    return {key: str(value) for key, value in raw.items() if key != "schema"}


def tap_network_args(config: dict[str, str], *, verify_host: bool) -> list[str]:
    """Attach only a named, pre-created tap with verified bridge membership."""
    tap = config["tap"]
    bridge = config["bridge"]
    uplink = config["uplink"]
    if verify_host:
        tap_path = SYS_CLASS_NET / tap
        bridge_path = SYS_CLASS_NET / bridge
        uplink_path = SYS_CLASS_NET / uplink
        membership = tap_path / "master"
        if not all(path.is_dir()
                   for path in (tap_path, bridge_path, uplink_path)):
            raise ValueError(
                "configured tap, bridge, and uplink must already exist")
        if not (bridge_path / "bridge").is_dir():
            raise ValueError(f"{bridge} is not a Linux bridge")
        if (not membership.is_symlink()
                or membership.resolve() != bridge_path.resolve()):
            raise ValueError(f"{tap} is not attached to configured bridge {bridge}")
        tun_flags = tap_path / "tun_flags"
        if not tun_flags.is_file():
            raise ValueError(f"{tap} is not a TAP interface")
        try:
            flags = int(tun_flags.read_text().strip(), 0)
        except (OSError, ValueError) as error:
            raise ValueError(f"cannot read {tap} TAP flags") from error
        if flags & 0x000f != 0x0002:
            raise ValueError(f"{tap} is not a TAP interface")
        owner = tap_path / "owner"
        try:
            tap_owner = int(owner.read_text().strip())
        except (OSError, ValueError) as error:
            raise ValueError(f"cannot read {tap} owner") from error
        if tap_owner != os.getuid():
            raise ValueError(
                f"{tap} owner {tap_owner} does not match invoking user "
                f"{os.getuid()}")
        for name, path in (
            (tap, tap_path), (bridge, bridge_path), (uplink, uplink_path)
        ):
            try:
                link_flags = int((path / "flags").read_text().strip(), 0)
            except (OSError, ValueError) as error:
                raise ValueError(f"cannot read {name} link flags") from error
            if not link_flags & 0x1:
                raise ValueError(f"{name} is not UP")
        uplink_master = uplink_path / "master"
        if (not uplink_master.is_symlink()
                or uplink_master.resolve() != bridge_path.resolve()):
            raise ValueError(
                f"{uplink} is not attached to configured bridge {bridge}")
        if not (uplink_path / "device").exists():
            raise ValueError(
                f"{uplink} is not an identifiable physical interface")
    return [
        "-nodefaults",
        "-netdev",
        f"tap,id=bootstrap,ifname={tap},script=no,downscript=no",
        "-device",
        f"virtio-net-pci,netdev=bootstrap,mac={config['mac'].lower()}",
    ]


def _private_state(files: dict[str, Path]) -> bool:
    if files["state"].stat().st_mode & 0o077:
        return False
    return all(not (files[key].stat().st_mode & 0o077)
               for key in ("disk", "vars", "manifest"))


def qemu_command(
    state: Path,
    iso: Path | None,
    seed_iso: Path | None = None,
    network_config: dict[str, str] | None = None,
    verify_host_network: bool = False,
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
    if network_config is None:
        command += socket_network_args(
            role="listen", mac="52:54:00:11:11:11")
    else:
        command += tap_network_args(
            network_config, verify_host=verify_host_network)
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
    network_config_path: Path | None = None,
    network_receipt_path: Path | None = None,
    confirm: str | None = None,
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
    network_config = None
    if network_receipt_path is not None and network_config_path is None:
        print("error: --network-receipt requires --network-config",
              file=sys.stderr)
        return 2
    if network_config_path is not None:
        if os.geteuid() == 0:
            print("error: physical-network attachment refuses root",
                  file=sys.stderr)
            return 2
        if iso is not None or seed_iso is not None:
            print("error: physical-network attachment is disk-only; "
                  "installer media are forbidden", file=sys.stderr)
            return 2
        if apply and confirm != "attach-bootstrap-dc":
            print("error: attachment requires "
                  "--confirm attach-bootstrap-dc", file=sys.stderr)
            return 2
        if apply and network_receipt_path is None:
            print("error: physical-network attachment requires a fresh "
                  "--network-receipt", file=sys.stderr)
            return 2
        if apply:
            try:
                expected_commit = subprocess.run(
                    ["git", "-C", str(REPOSITORY), "rev-parse", "HEAD"],
                    check=True, capture_output=True, text=True,
                ).stdout.strip()
                verify_preflight_receipt(
                    network_receipt_path, files["disk"], DISK_SERIAL,
                    expected_commit)
            except (OSError, ValueError, subprocess.CalledProcessError) as error:
                print(f"error: network preflight receipt: {error}",
                      file=sys.stderr)
                return 2
        try:
            network_config = load_network_config(network_config_path)
        except ValueError as error:
            print(f"error: {error}", file=sys.stderr)
            return 2
    try:
        command = qemu_command(
            state, iso, seed_iso, network_config,
            verify_host_network=apply and network_config is not None)
    except ValueError as error:
        print(f"error: {error}", file=sys.stderr)
        return 2
    print(" ".join(str(part) for part in command))
    if network_config is not None:
        print(
            "network: pre-created tap "
            f"{network_config['tap']} on bridge {network_config['bridge']}")
        if not apply:
            print("authorization: dry-run only; applied launch also requires "
                  "a fresh authorized preflight receipt")
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
    run_parser.add_argument(
        "--network-config",
        type=Path,
        help="private 0600 JSON selecting a pre-created bridged tap",
    )
    run_parser.add_argument(
        "--network-receipt",
        type=Path,
        help="private 0600 short-lived guest preflight receipt",
    )
    run_parser.add_argument(
        "--confirm",
        help="required acknowledgement for physical-network attachment",
    )
    destroy_parser = commands.add_parser("destroy")
    destroy_parser.add_argument("--confirm")
    return result


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    command = args.command or "status"
    if command == "create":
        return create(args.state_dir, args.apply)
    if command == "run":
        return run(
            args.state_dir, args.iso, args.apply, args.seed_iso,
            args.network_config, args.network_receipt, args.confirm)
    if command == "destroy":
        return destroy(args.state_dir, args.confirm)
    return status(args.state_dir)


if __name__ == "__main__":
    raise SystemExit(main())
