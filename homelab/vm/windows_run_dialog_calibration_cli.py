#!/usr/bin/env python3
"""Sign in transiently, then capture a public Run-dialog review candidate."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

from .bootstrap_dc import DEFAULT_STATE
from .windows_identity_reference import GuestProvenance
from .windows_identity_recovery import RecoveredLocalCredential
from .windows_identity_run import NativeProcessBoundary, WindowsIdentityRunError
from .windows_run_dialog_calibration import (
    RunDialogCalibrationPlan,
    WindowsRunDialogCalibrationError,
    capture_run_dialog,
)


def _crop(value: str) -> tuple[int, int, int, int]:
    try:
        parts = tuple(int(item) for item in value.split(","))
    except ValueError as error:
        raise argparse.ArgumentTypeError("crop must contain four integers") from error
    if len(parts) != 4:
        raise argparse.ArgumentTypeError("crop must contain four integers")
    return parts


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("--attempt", type=Path, required=True)
    result.add_argument("--controller-state", type=Path, default=DEFAULT_STATE)
    result.add_argument("--desktop-reference", type=Path, required=True)
    result.add_argument("--sign-in-reference", type=Path, required=True)
    result.add_argument("--guest-provenance", type=Path, required=True)
    result.add_argument("--publication", type=Path, required=True)
    result.add_argument("--recovery-parent", type=Path, required=True)
    result.add_argument("--evidence-root", type=Path, required=True)
    result.add_argument("--crop", type=_crop, required=True)
    result.add_argument("--apply", action="store_true")
    return result


def _guest(path: Path) -> GuestProvenance:
    document = json.loads(path.read_text())
    return GuestProvenance(**document)


def run(args: argparse.Namespace) -> int:
    boundary = NativeProcessBoundary(args.attempt, args.controller_state)
    boundary._validate()
    if not args.apply:
        print("dry run; repeat with --apply to capture public Run-dialog evidence")
        return 0
    receipt = capture_run_dialog(
        boundary,
        sign_in_manifest=args.sign_in_reference,
        desktop_manifest=args.desktop_reference,
        expected_guest=_guest(args.guest_provenance),
        recover_credential=lambda: RecoveredLocalCredential(
            args.publication, args.recovery_parent),
        publication=args.publication,
        evidence_root=args.evidence_root,
        plan=RunDialogCalibrationPlan(crop=args.crop),
    )
    print(f"Candidate image: {receipt.candidate_image}")
    print(f"Candidate provenance: {receipt.candidate_manifest}")
    print("Review is required before promotion to a tracked reference.")
    return 0


def main(argv: list[str] | None = None) -> int:
    try:
        return run(parser().parse_args(argv))
    except (
        OSError,
        UnicodeError,
        json.JSONDecodeError,
        TypeError,
        WindowsIdentityRunError,
        WindowsRunDialogCalibrationError,
    ) as error:
        print(
            f"windows Run-dialog calibration: {type(error).__name__}",
            file=sys.stderr,
        )
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
