#!/usr/bin/env python3
"""Prepare one private, authorized Arch identity (gate 8) bundle.

Takes a *passing* gate-7 Arch install run bundle, proves its recorded result
and serial transcript, and produces the isolated bundle the gate-8 runner
(``arch_identity_run``) validates fail-closed:

* ``arch-workstation.qcow2`` — a fresh qcow2 overlay backed by the gate-7
  ``arch.qcow2`` (which itself overlays the retained Windows disk).  The
  install bundle is only ever read; a gate-8 run mutates its own overlay.
* ``OVMF_VARS.fd`` — pristine firmware variables for the disk boot.  The
  gate-7 blocker history proved OVMF auto-discovers a bootable ESP on a
  cold-plugged NVMe (that is exactly why the install boot had to detach the
  disk), so the identity boot prefers pristine variables plus that proven
  auto-discovery over inheriting the install bundle's PXE-booted NVRAM.
* ``windows-evidence.jsonl`` — the peer Windows lane's lifecycle checks,
  extracted fail-closed from its produced acceptance evidence stream (the
  JSONL published by ``windows_identity_evidence``); only a stream that
  proves every Windows lifecycle check with the exact judged fields is
  accepted, and the events are copied verbatim.
* ``authorization.json`` — the consumer contract
  (``status=prepared``, no external access, no installation media, no PXE,
  ``domain_joined`` with a named realm) plus provenance.

The produced bundle is round-tripped through the consumer's own fail-closed
validation before it is reported, so prepare can never emit a bundle the
runner would refuse.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import secrets
import shutil
import subprocess
import sys

from .arch_identity_run import (
    ArchIdentityBundle,
    ArchIdentityError,
    BUNDLE_AUTHORIZATION,
    BUNDLE_DISK,
    BUNDLE_FIRMWARE,
    BUNDLE_WINDOWS_EVIDENCE,
    lifecycle,
    validate_windows_evidence,
)
from .arch_install_prepare import (
    ArchInstallPrepareError,
    OVERLAY_NAME as INSTALL_OVERLAY_NAME,
    inspect_overlay,
)
from .bootstrap_dc import ovmf_pair
from .controller_factory import FactorySpec
from homelab.workstations.arch_second import JOIN_VERIFIED_MARKER

# The exact pass shape arch_install_run records for a preserving install.
RESULT_RELATIVE = Path("evidence/result.json")
SERIAL_RELATIVE = Path("evidence/workstation-serial.log")
PASS_STATUS = "observed"
PASS_PHASE = "arch-installed-windows-preserved"

# Seam with the gate-7 domain-join provisioning: the installer emitted by
# ``workstations/arch_second.py`` prints this marker only after an in-chroot
# ``net ads join`` succeeded and ``net ads testjoin`` verified it.  A gate-7
# transcript without it belongs to an unjoined disk, which gate 8 cannot
# accept, so the check is strict.  The live ``arch-joined`` probe remains the
# authoritative runtime proof.
ARCH_JOIN_MARKER = JOIN_VERIFIED_MARKER

DEFAULT_RUNS = Path("homelab/var/factory/arch-identity")
#: The realm the disposable converged Controller provides (gate 6).
DEFAULT_REALM = FactorySpec().realm


class ArchIdentityPrepareError(RuntimeError):
    """The gate-8 identity bundle cannot be prepared safely."""


def _private_file(path: Path, payload: str) -> None:
    descriptor = os.open(
        path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as stream:
        stream.write(payload)


def _regular(path: Path, label: str) -> None:
    if path.is_symlink() or not path.is_file():
        raise ArchIdentityPrepareError(
            f"{label} must be a regular non-symlink file")


def inspect_install_bundle(bundle: Path) -> dict:
    """Prove the gate-7 bundle records the Windows-preserving pass shape."""
    if bundle.is_symlink():
        raise ArchIdentityPrepareError(
            "gate-7 install bundle must be a private non-symlink directory")
    try:
        bundle = bundle.resolve(strict=True)
    except OSError as error:
        raise ArchIdentityPrepareError(
            f"gate-7 install bundle is missing: {bundle}") from error
    if not bundle.is_dir() or bundle.stat().st_mode & 0o077:
        raise ArchIdentityPrepareError(
            "gate-7 install bundle must be a private non-symlink directory")

    result_path = bundle / RESULT_RELATIVE
    _regular(result_path, "gate-7 execution result")
    try:
        result = json.loads(result_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise ArchIdentityPrepareError(
            "gate-7 execution result is unreadable") from error
    if not isinstance(result, dict):
        raise ArchIdentityPrepareError(
            "gate-7 execution result is not an object")
    if result.get("status") != PASS_STATUS:
        raise ArchIdentityPrepareError(
            f"gate-7 result status must be {PASS_STATUS!r}; "
            f"found {result.get('status')!r}")
    if result.get("phase") != PASS_PHASE:
        raise ArchIdentityPrepareError(
            f"gate-7 result phase must be {PASS_PHASE!r}; "
            f"found {result.get('phase')!r}")
    if result.get("windows_preserved") is not True:
        raise ArchIdentityPrepareError(
            "gate-7 result does not prove Windows preservation")

    disk = bundle / INSTALL_OVERLAY_NAME
    _regular(disk, "gate-7 installed Arch disk")
    try:
        overlay = inspect_overlay(disk)
    except ArchInstallPrepareError as error:
        raise ArchIdentityPrepareError(
            f"gate-7 installed Arch disk is unsafe: {error}") from error

    serial_path = bundle / SERIAL_RELATIVE
    _regular(serial_path, "gate-7 serial transcript")
    transcript = serial_path.read_text(encoding="utf-8", errors="replace")
    if ARCH_JOIN_MARKER not in transcript:
        raise ArchIdentityPrepareError(
            "gate-7 transcript lacks the verified join marker "
            f"{ARCH_JOIN_MARKER!r}; the installed disk is not a joined "
            "identity client")
    return {
        "bundle": str(bundle),
        "disk": overlay,
        "result": {
            "status": result["status"],
            "phase": result["phase"],
            "windows_preserved": True,
        },
        "join_marker_observed": True,
    }


def load_windows_lifecycle_evidence(path: Path) -> list[dict[str, object]]:
    """Extract the ordered Windows lifecycle checks from a produced stream.

    The source is the Windows identity lane's published acceptance evidence
    (or an already-extracted lifecycle subset).  Extraction is fail-closed:
    every Windows lifecycle check must be present exactly once, passing,
    external-access-free, and carrying the exact judged fields.  Matching
    events are returned verbatim, in contract order.
    """
    _regular(path, "Windows lifecycle evidence")
    try:
        with path.open(encoding="utf-8") as source:
            events = lifecycle.load_events(source)
    except (OSError, lifecycle.EvidenceError) as error:
        raise ArchIdentityPrepareError(
            f"Windows lifecycle evidence is unreadable: {error}") from error
    try:
        return validate_windows_evidence(events)
    except ArchIdentityError as error:
        raise ArchIdentityPrepareError(
            f"Windows lifecycle evidence is not a passing stream: {error}"
        ) from error


def prepare(
    install_bundle: Path,
    windows_evidence: Path,
    *,
    run_root: Path = DEFAULT_RUNS,
    realm: str = DEFAULT_REALM,
    ovmf_vars: Path | None = None,
) -> Path:
    """Produce one private gate-8 bundle; the install bundle is never written."""
    if not isinstance(realm, str) or not realm:
        raise ArchIdentityPrepareError("a non-empty Kerberos realm is required")
    source = inspect_install_bundle(install_bundle)
    events = load_windows_lifecycle_evidence(windows_evidence)

    vars_source = ovmf_vars
    if vars_source is None:
        pair = ovmf_pair()
        if pair is None:
            raise ArchIdentityPrepareError(
                "pristine OVMF variables template was not found")
        vars_source = pair[1]
    _regular(vars_source, "OVMF variables template")

    if run_root.is_symlink():
        raise ArchIdentityPrepareError(
            "identity run root must not be a symlink")
    run_root.mkdir(parents=True, exist_ok=True, mode=0o700)
    run_root.chmod(0o700)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    run = run_root / f"run-{stamp}-{secrets.token_hex(6)}"
    run.mkdir(mode=0o700)
    try:
        overlay = run / BUNDLE_DISK
        subprocess.run(
            [
                "qemu-img", "create", "-f", "qcow2", "-F", "qcow2",
                "-b", source["disk"]["path"], str(overlay),
            ],
            check=True, capture_output=True)
        overlay.chmod(0o600)
        produced = inspect_overlay(overlay)
        if produced["backing"] != source["disk"]["path"]:
            raise ArchIdentityPrepareError(
                "prepared overlay does not back the gate-7 Arch disk")

        variables = run / BUNDLE_FIRMWARE
        shutil.copyfile(vars_source, variables)
        variables.chmod(0o600)

        _private_file(
            run / BUNDLE_WINDOWS_EVIDENCE,
            "".join(
                json.dumps(item, sort_keys=True) + "\n" for item in events))

        authorization = {
            "schema": 1,
            "status": "prepared",
            "external_access": False,
            "installation_media_attached": False,
            "pxe_boot_enabled": False,
            "domain_joined": True,
            "realm": realm,
            "install_bundle": source["bundle"],
            "install_result": source["result"],
            "join_marker": ARCH_JOIN_MARKER,
            "join_marker_observed": source["join_marker_observed"],
            "overlay": {
                "path": str(overlay.resolve()),
                "format": "qcow2",
                "backing_install_disk": source["disk"],
            },
            "firmware_copy": {
                "path": str(variables.resolve()),
                "source": str(vars_source.resolve()),
                "policy": "pristine-esp-auto-discovery",
            },
            "windows_evidence_source": str(
                Path(windows_evidence).resolve()),
        }
        _private_file(
            run / BUNDLE_AUTHORIZATION,
            json.dumps(authorization, indent=2, sort_keys=True) + "\n")

        # Round-trip the produced bundle through the consumer's own
        # fail-closed validation (the run directory itself stands in for the
        # controller-state privacy check; the real state is chosen at run
        # time), so prepare can never publish a bundle the runner refuses.
        check = ArchIdentityBundle(run, run)
        check.validate()
        check.read_windows_evidence()
        return run
    except BaseException:
        shutil.rmtree(run, ignore_errors=True)
        raise


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    result.add_argument(
        "--install-bundle", type=Path, required=True,
        help="passing gate-7 arch-install run directory")
    result.add_argument(
        "--windows-evidence", type=Path, required=True,
        help="the Windows identity lane's produced acceptance evidence JSONL")
    result.add_argument("--run-root", type=Path, default=DEFAULT_RUNS)
    result.add_argument(
        "--realm", default=DEFAULT_REALM,
        help="Kerberos realm the joined guest authenticates against")
    result.add_argument(
        "--ovmf-vars", type=Path, default=None,
        help="override the pristine OVMF variables template; defaults to the "
        "firmware's fresh no-boot-entry vars (OVMF auto-discovers the ESP)")
    result.add_argument("--apply", action="store_true")
    return result


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    print("Boundary: fresh qcow2 overlay over the gate-7 joined Arch disk")
    print(f"Install bundle: {args.install_bundle} (read-only)")
    print(f"Windows lifecycle evidence: {args.windows_evidence}")
    print(f"Realm: {args.realm}")
    print("Installation media, PXE, host networking and UniFi: disabled")
    if not args.apply:
        print("dry run; repeat with --apply to prepare the private bundle")
        return 0
    try:
        print(prepare(
            args.install_bundle,
            args.windows_evidence,
            run_root=args.run_root,
            realm=args.realm,
            ovmf_vars=args.ovmf_vars,
        ))
    except (ArchIdentityPrepareError, ArchIdentityError) as error:
        print(f"arch identity prepare: {error}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
