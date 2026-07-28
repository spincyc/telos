#!/usr/bin/env python3
"""Prepare a private overlay for retained Windows identity acceptance."""

from __future__ import annotations

import argparse
from datetime import UTC, datetime
import hashlib
import json
from pathlib import Path
import secrets
import shutil
import subprocess

from .bootstrap_dc import DEFAULT_STATE
from .simulation_evidence import private_file
from .windows_install_contract import sha256
from .windows_identity_contract import qemu_identity_command

DEFAULT_BUNDLE = Path(
    "homelab/var/factory/windows-installs/"
    "run-20260728T114233Z-afecdf7cc9d0")
DISK_NAME = "windows.qcow2"
VARS_NAME = "OVMF_VARS.fd"
NATIVE_MARKER = "TELOS WINDOWS NATIVE READY"


class WindowsIdentityPrepareError(RuntimeError):
    """The retained candidate cannot be prepared safely."""


def _private_directory(path: Path) -> None:
    path.mkdir(mode=0o700)
    path.chmod(0o700)


def _regular_private(path: Path, label: str) -> None:
    if path.is_symlink() or not path.is_file():
        raise WindowsIdentityPrepareError(
            f"{label} must be a regular non-symlink file")
    if path.stat().st_mode & 0o077:
        raise WindowsIdentityPrepareError(f"{label} must be mode 0600")


def inspect_candidate(bundle: Path) -> dict:
    if bundle.is_symlink() or not bundle.is_dir():
        raise WindowsIdentityPrepareError(
            "retained bundle must be a real directory")
    if bundle.stat().st_mode & 0o077:
        raise WindowsIdentityPrepareError("retained bundle must be mode 0700")
    disk = bundle / DISK_NAME
    variables = bundle / VARS_NAME
    serial = bundle / "evidence/workstation-serial.log"
    for path, label in (
            (disk, "retained Windows disk"),
            (variables, "retained OVMF variables"),
            (serial, "native Windows serial evidence")):
        _regular_private(path, label)
    if NATIVE_MARKER not in serial.read_text(
            encoding="utf-8", errors="replace"):
        raise WindowsIdentityPrepareError(
            "retained evidence lacks native Windows readiness")
    result = subprocess.run(
        ["qemu-img", "check", "--output=json", str(disk)],
        check=True, capture_output=True, text=True)
    check = json.loads(result.stdout)
    if check.get("check-errors") != 0:
        raise WindowsIdentityPrepareError("retained Windows qcow2 is corrupt")
    result = subprocess.run(
        ["qemu-img", "info", "--output=json", str(disk)],
        check=True, capture_output=True, text=True)
    info = json.loads(result.stdout)
    if (info.get("format") != "qcow2"
            or info.get("virtual-size") != 256 * 1024**3
            or info.get("dirty-flag") is not False
            or info.get("backing-filename")):
        raise WindowsIdentityPrepareError(
            "retained Windows qcow2 metadata is unsafe")
    return {
        "bundle": str(bundle.resolve()),
        "disk": {
            "path": str(disk.resolve()),
            "sha256": sha256(disk),
            "virtual_size": info["virtual-size"],
            "dirty": False,
        },
        "firmware": {
            "path": str(variables.resolve()),
            "sha256": sha256(variables),
        },
        "native_marker": NATIVE_MARKER,
    }


def prepare(
    bundle: Path, controller_state: Path, switch_port: int = 31415,
) -> Path:
    bundle = bundle.resolve(strict=True)
    source = inspect_candidate(bundle)
    identity_root = bundle / "identity"
    if identity_root.is_symlink():
        raise WindowsIdentityPrepareError("identity root must not be a symlink")
    identity_root.mkdir(mode=0o700, exist_ok=True)
    identity_root.chmod(0o700)
    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    attempt = identity_root / f"attempt-{stamp}-{secrets.token_hex(6)}"
    _private_directory(attempt)
    try:
        overlay = attempt / DISK_NAME
        variables = attempt / VARS_NAME
        qmp = attempt / "windows.qmp"
        shutil.copyfile(bundle / VARS_NAME, variables)
        variables.chmod(0o600)
        subprocess.run([
            "qemu-img", "create", "-f", "qcow2", "-F", "qcow2",
            "-b", str((bundle / DISK_NAME).resolve()), str(overlay),
        ], check=True, capture_output=True)
        overlay.chmod(0o600)
        command = qemu_identity_command(
            disk=overlay, variables=variables, qmp_socket=qmp,
            switch_port=switch_port)
        command_digest = hashlib.sha256(
            json.dumps(command, separators=(",", ":")).encode()).hexdigest()
        plan = {
            "schema": 1,
            "status": "prepared",
            "external_access": False,
            "source": source,
            "controller_state": str(controller_state.resolve()),
            "overlay": {
                "path": str(overlay.resolve()),
                "backing_path": source["disk"]["path"],
                "format": "qcow2",
            },
            "firmware_copy": {
                "path": str(variables.resolve()),
                "source_sha256": source["firmware"]["sha256"],
            },
            "qmp_socket": str(qmp.resolve()),
            "qemu_argv_sha256": command_digest,
            "installation_media_attached": False,
            "pxe_boot_enabled": False,
        }
        private_file(
            attempt / "authorization.json",
            (json.dumps(plan, indent=2, sort_keys=True) + "\n").encode())
        private_file(
            attempt / "qemu-command.json",
            (json.dumps({"schema": 1, "argv": command}, indent=2) + "\n").encode())
        return attempt
    except BaseException:
        shutil.rmtree(attempt, ignore_errors=True)
        raise


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("--bundle", type=Path, default=DEFAULT_BUNDLE)
    result.add_argument(
        "--controller-state", type=Path, default=DEFAULT_STATE)
    result.add_argument("--switch-port", type=int, default=31415)
    result.add_argument("--apply", action="store_true")
    return result


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    print("Boundary: retained native Windows disk through a fresh qcow2 overlay")
    print(f"Bundle: {args.bundle}")
    print(f"Controller state: {args.controller_state}")
    print("Installation ISO, PXE, host networking and UniFi: disabled")
    if not args.apply:
        print("dry run; repeat with --apply to prepare a private identity attempt")
        return 0
    print(prepare(args.bundle, args.controller_state, args.switch_port))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
