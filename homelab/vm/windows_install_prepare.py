#!/usr/bin/env python3
"""Prepare one serial-authorized private Windows installation run bundle."""

from __future__ import annotations

import argparse
from dataclasses import asdict
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import secrets
import shutil
import subprocess
import tempfile

try:
    from .bootstrap_dc import DEFAULT_STATE, ovmf_pair, paths
    from .factory_publication import stage as stage_publication
    from .windows_install_contract import (
        GIB, PrivateRun, SyntheticIdentity, authorize, qemu_install_command)
except ImportError:
    from bootstrap_dc import DEFAULT_STATE, ovmf_pair, paths
    from factory_publication import stage as stage_publication
    from windows_install_contract import (
        GIB, PrivateRun, SyntheticIdentity, authorize, qemu_install_command)


DEFAULT_RELEASES = Path("homelab/var/pxe")
DEFAULT_SOURCE = Path("homelab/var/media/windows/install-source")
DEFAULT_SEED = Path("homelab/var/seed/telos-controller-seed.iso")
DEFAULT_LAYOUT = Path("homelab/workstations/profiles/default-layout.json")
DEFAULT_WORKSTATION = Path(
    "homelab/workstations/profiles/phase1-windows-primary.json")
DEFAULT_RUNS = Path("homelab/var/factory/windows-installs")
DISK_SERIAL = "TELOS-WIN-0001"
DISK_BYTES = 256 * GIB


def _selected(releases: Path) -> dict:
    value = json.loads(
        (releases / "selected-release-set.json").read_text(encoding="utf-8"))
    if set(value) != {"schema", "version", "manifest_sha256"}:
        raise RuntimeError("selected release descriptor has invalid fields")
    return value


def _private_file(path: Path, payload: str) -> None:
    descriptor = os.open(
        path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
        stream.write(payload)


def prepare(args: argparse.Namespace) -> Path:
    run_root = args.run_root
    if run_root.is_symlink():
        raise RuntimeError("Windows run root must not be a symlink")
    run_root.mkdir(parents=True, exist_ok=True, mode=0o700)
    run_root.chmod(0o700)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    run = run_root / f"run-{stamp}-{secrets.token_hex(6)}"
    run.mkdir(mode=0o700)
    try:
        disk = run / "windows.qcow2"
        variables = run / "OVMF_VARS.fd"
        publication_iso = run / "publication.iso"
        qmp_socket = run / "windows.qmp"
        subprocess.run(
            ["qemu-img", "create", "-f", "qcow2", str(disk), str(DISK_BYTES)],
            check=True, capture_output=True)
        disk.chmod(0o600)
        pair = ovmf_pair()
        if pair is None:
            raise RuntimeError("OVMF firmware was not found")
        shutil.copyfile(pair[1], variables)
        variables.chmod(0o600)
        command = qemu_install_command(
            disk=disk, variables=variables,
            qmp_socket=qmp_socket, switch_port=args.switch_port,
            serial=DISK_SERIAL)
        selected = _selected(args.releases)
        authorization = authorize(
            disk=disk, serial=DISK_SERIAL, command=command,
            release_version=selected["version"],
            release_manifest_sha256=selected["manifest_sha256"],
            layout_profile=args.layout,
            workstation_profile=args.workstation_profile)
        identity = SyntheticIdentity(
            computer_name="TELOS-WIN-01",
            local_user="telosadmin",
            local_password="S-" + secrets.token_urlsafe(18),
            install_user=r".\pxe-install",
            install_password="S-" + secrets.token_urlsafe(18),
        )
        with PrivateRun(run / "inputs") as private, \
                tempfile.TemporaryDirectory(
                    prefix="publication-parent-", dir=run) as publication_name:
            generated = private.render_windows_inputs(
                authorization, identity,
                install_source_unc=r"\\10.1.31.2\windows-release")
            publication = Path(publication_name) / "publication"
            receipt = stage_publication(
                args.releases, publication, seed_iso=args.seed,
                target="windows", private_windows_inputs=private.path,
                windows_source=args.windows_source)
            subprocess.run([
                "xorriso", "-as", "mkisofs", "-quiet", "-iso-level", "3",
                "-V", "TELOS_PXE_RELEASE", "-o", str(publication_iso),
                str(publication),
            ], check=True, capture_output=True)
            publication_iso.chmod(0o600)
            public = private.public_receipt(authorization, generated)
            public["publication"] = {
                "selected_manifest_sha256":
                    receipt["selected_manifest_sha256"],
                "windows_install_source": receipt["windows_install_source"],
            }
            _private_file(
                run / "authorization.json",
                json.dumps(public, indent=2, sort_keys=True) + "\n")
        inputs_root = run / "inputs"
        if inputs_root.exists():
            inputs_root.rmdir()
        _private_file(
            run / "qemu-command.json",
            json.dumps({"schema": 1, "argv": command}, indent=2) + "\n")
        return run
    except BaseException:
        shutil.rmtree(run, ignore_errors=True)
        raise


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("--releases", type=Path, default=DEFAULT_RELEASES)
    result.add_argument(
        "--windows-source", type=Path, default=DEFAULT_SOURCE)
    result.add_argument("--seed", type=Path, default=DEFAULT_SEED)
    result.add_argument("--layout", type=Path, default=DEFAULT_LAYOUT)
    result.add_argument(
        "--workstation-profile", type=Path, default=DEFAULT_WORKSTATION)
    result.add_argument("--run-root", type=Path, default=DEFAULT_RUNS)
    result.add_argument("--switch-port", type=int, default=31415)
    result.add_argument("--apply", action="store_true")
    return result


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    print("Boundary: private run state and loopback-only QEMU command")
    print(f"Disk: fresh {DISK_BYTES // GIB} GiB qcow2, serial {DISK_SERIAL}")
    print("Windows source: receipt-verified, authenticated read-only SMB")
    print("Physical disks, host networking and UniFi: untouched")
    if not args.apply:
        print("dry run; repeat with --apply to prepare the private bundle")
        return 0
    print(prepare(args))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
