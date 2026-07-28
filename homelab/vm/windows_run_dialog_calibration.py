#!/usr/bin/env python3
"""Bounded Windows Run-dialog calibration after a proven private sign-in."""

from __future__ import annotations

from dataclasses import dataclass
from contextlib import AbstractContextManager
import hashlib
import json
import math
import os
from pathlib import Path
import time
from typing import Callable

from .signal_cleanup import SignalGuard
from .windows_gui import (
    Image,
    WindowsGuiError,
    crop_image,
    image_distance,
    read_ppm,
    useful_frame,
)
from .windows_identity_reference import (
    GuestProvenance,
    WindowsIdentityReferenceError,
    load_identity_reference,
)
from .windows_identity_run import NativeProcessBoundary


class WindowsRunDialogCalibrationError(RuntimeError):
    """The public Run-dialog calibration did not close safely."""


def _digest_file(path: Path) -> bytes:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while block := stream.read(1024 * 1024):
            digest.update(block)
    return digest.digest()


@dataclass(frozen=True)
class RunDialogCalibrationPlan:
    """Finite visual bounds for one public-only calibration."""

    crop: tuple[int, int, int, int]
    sign_in_keys: tuple[str, ...] = ("spc",)
    sign_in_delay: float = 60.0
    threshold: float = 6.0
    max_desktop_frames: int = 30
    max_run_frames: int = 90
    interval: float = 1.0


@dataclass(frozen=True)
class RunDialogCalibrationReceipt:
    """Review candidate and secret-free provenance from a closed attempt."""

    candidate_image: Path
    candidate_manifest: Path
    source_frames: tuple[Path, ...]
    credential_submitted: bool
    publication_unchanged: bool
    desktop_proofs: int
    teardown_complete: bool


def _private_root(path: Path) -> Path:
    path = Path(path).absolute()
    if path.exists():
        if path.is_symlink() or not path.is_dir():
            raise WindowsRunDialogCalibrationError(
                "calibration evidence root must be a real directory")
    else:
        path.mkdir(parents=True, mode=0o700)
    if path.stat().st_mode & 0o077:
        raise WindowsRunDialogCalibrationError(
            "calibration evidence root must be private")
    return path


def _capture(boundary: NativeProcessBoundary, path: Path) -> Image:
    if boundary.qmp is None:
        raise WindowsRunDialogCalibrationError("QMP is unavailable")
    boundary.qmp.screenshot(path)
    path.chmod(0o600)
    try:
        return read_ppm(path)
    except (OSError, WindowsGuiError) as error:
        raise WindowsRunDialogCalibrationError(
            "calibration frame is invalid") from error


def _prove_reference_twice(
    boundary: NativeProcessBoundary,
    root: Path,
    reference,
    label: str,
    plan: RunDialogCalibrationPlan,
    pause: Callable[[float], None],
) -> None:
    consecutive = 0
    for sequence in range(1, plan.max_desktop_frames + 1):
        path = root / f"{label}-proof-{sequence:04d}.ppm"
        full = _capture(boundary, path)
        if (full.width, full.height) == reference.geometry:
            selected = crop_image(full, reference.crop)
            if (
                useful_frame(selected)
                and image_distance(selected, reference.image) <= plan.threshold
            ):
                consecutive += 1
                if consecutive == 2:
                    return
            else:
                consecutive = 0
        else:
            consecutive = 0
        pause(plan.interval)
    raise WindowsRunDialogCalibrationError(
        f"failed to prove the tracked {label} twice")


def _stable_run_frames(
    boundary: NativeProcessBoundary,
    root: Path,
    plan: RunDialogCalibrationPlan,
    geometry: tuple[int, int],
    pause: Callable[[float], None],
) -> tuple[tuple[Path, ...], Image]:
    stable: list[tuple[bytes, Path]] = []
    selected_image: Image | None = None
    for sequence in range(1, plan.max_run_frames + 1):
        path = root / f"run-dialog-{sequence:04d}.ppm"
        full = _capture(boundary, path)
        if (full.width, full.height) != geometry:
            stable.clear()
            path.unlink(missing_ok=True)
            pause(plan.interval)
            continue
        try:
            selected = crop_image(full, plan.crop)
        except WindowsGuiError as error:
            raise WindowsRunDialogCalibrationError(
                "Run-dialog crop is outside the prepared display") from error
        if not useful_frame(selected):
            stable.clear()
            path.unlink(missing_ok=True)
            pause(plan.interval)
            continue
        digest = hashlib.sha256(selected.pixels).digest()
        if stable and stable[-1][0] != digest:
            stable.clear()
        stable.append((digest, path))
        selected_image = selected
        if len(stable) == 3:
            return tuple(item[1] for item in stable), selected_image
        pause(plan.interval)
    raise WindowsRunDialogCalibrationError(
        "failed to capture three stable public Run-dialog frames")


def _write_candidate(
    root: Path,
    frames: tuple[Path, ...],
    image: Image,
    reference,
    attempt: Path,
    source_bundle: str,
    crop: tuple[int, int, int, int],
) -> tuple[Path, Path]:
    candidate = root / "run-dialog-candidate.ppm"
    candidate.write_bytes(
        f"P6\n{image.width} {image.height}\n255\n".encode() + image.pixels)
    candidate.chmod(0o600)
    source_hashes = [
        hashlib.sha256(path.read_bytes()).hexdigest() for path in frames
    ]
    crop_hash = hashlib.sha256(image.pixels).hexdigest()
    manifest = root / "run-dialog-candidate.json"
    document = {
        "schema": 1,
        "review_status": "candidate",
        "state": "Windows Run dialog with empty Open field",
        "state_kind": "run-dialog",
        "captured_after_private_input": True,
        "contains_private_material": False,
        "guest": reference.guest.__dict__,
        "capture": {
            "source_bundle": source_bundle,
            "attempt": attempt.name,
            "geometry": list(reference.geometry),
            "crop": list(crop),
            "source_frames": [path.name for path in frames],
            "source_frame_sha256": source_hashes,
            "stable_crop_pixel_sha256": [crop_hash] * len(frames),
        },
        "candidate": {
            "file": candidate.name,
            "sha256": hashlib.sha256(candidate.read_bytes()).hexdigest(),
        },
    }
    manifest.write_text(json.dumps(document, indent=2) + "\n")
    manifest.chmod(0o600)
    return candidate, manifest


def capture_run_dialog(
    boundary: NativeProcessBoundary,
    *,
    sign_in_manifest: Path,
    desktop_manifest: Path,
    expected_guest: GuestProvenance,
    recover_credential: Callable[[], AbstractContextManager[str]],
    publication: Path,
    evidence_root: Path,
    plan: RunDialogCalibrationPlan,
    pause: Callable[[float], None] = time.sleep,
) -> RunDialogCalibrationReceipt:
    """Open only Run after a double desktop proof and retain review evidence."""
    if (
        type(plan.max_desktop_frames) is not int
        or not 2 <= plan.max_desktop_frames <= 120
        or type(plan.max_run_frames) is not int
        or not 3 <= plan.max_run_frames <= 240
        or type(plan.threshold) not in (int, float)
        or not math.isfinite(plan.threshold)
        or not 0 <= plan.threshold <= 32
        or type(plan.interval) not in (int, float)
        or not math.isfinite(plan.interval)
        or not 0 < plan.interval <= 10
        or type(plan.sign_in_delay) not in (int, float)
        or not math.isfinite(plan.sign_in_delay)
        or not 0 <= plan.sign_in_delay <= 300
        or any(key not in {"spc"} for key in plan.sign_in_keys)
    ):
        raise WindowsRunDialogCalibrationError(
            "Run-dialog calibration plan is invalid")
    try:
        sign_in = load_identity_reference(
            Path(sign_in_manifest), expected_guest=expected_guest)
        desktop = load_identity_reference(
            Path(desktop_manifest), expected_guest=expected_guest)
        source_bundle = json.loads(
            Path(desktop_manifest).read_text())["capture"]["source_bundle"]
    except (OSError, UnicodeError, WindowsIdentityReferenceError) as error:
        raise WindowsRunDialogCalibrationError(
            "tracked desktop reference is invalid") from error
    if desktop.state_kind != "desktop":
        raise WindowsRunDialogCalibrationError(
            "tracked reference does not prove a desktop")
    if (
        sign_in.state_kind != "sign-in"
        or sign_in.state != "focused password field for local account telosadmin"
    ):
        raise WindowsRunDialogCalibrationError(
            "tracked reference does not prove the local sign-in")
    publication = Path(publication)
    if publication.is_symlink() or not publication.is_file():
        raise WindowsRunDialogCalibrationError(
            "private publication must be a regular file")
    publication_stat = publication.stat()
    if publication_stat.st_mode & 0o077:
        raise WindowsRunDialogCalibrationError(
            "private publication must be mode 0600")
    publication_identity = (
        publication_stat.st_dev,
        publication_stat.st_ino,
        publication_stat.st_size,
        _digest_file(publication),
    )
    root = _private_root(evidence_root)
    intended: list[str] = []
    cleanup: list[str] = []
    primary: BaseException | None = None
    result: tuple[tuple[Path, ...], Image] | None = None
    previous_umask = os.umask(0o077)
    signals = SignalGuard()
    entered = False
    try:
        signals.__enter__()
        entered = True
        intended.append("switch")
        boundary.start_switch()
        intended.append("controller")
        boundary.start_controller()
        intended.append("windows")
        boundary.start_windows()
        boundary.authenticate_qmp()
        if plan.sign_in_delay:
            pause(plan.sign_in_delay)
        if boundary.qmp is None:
            raise WindowsRunDialogCalibrationError("QMP is unavailable")
        for key in plan.sign_in_keys:
            boundary.qmp.key(key)
            pause(0.15)
        _prove_reference_twice(
            boundary, root, sign_in, "sign-in", plan, pause)
        try:
            with recover_credential() as credential:
                if (
                    not isinstance(credential, str)
                    or not credential
                    or any(character in credential for character in "\r\n\x00")
                ):
                    raise ValueError("invalid transient credential")
                boundary.qmp.type_text(credential)
                boundary.qmp.key("ret")
        except Exception:
            raise WindowsRunDialogCalibrationError(
                "private sign-in operation failed") from None
        _prove_reference_twice(
            boundary, root, desktop, "desktop", plan, pause)
        if boundary.qmp is None:
            raise WindowsRunDialogCalibrationError("QMP is unavailable")
        boundary.qmp.chord("meta_l", "r")
        result = _stable_run_frames(
            boundary, root, plan, desktop.geometry, pause)
    except BaseException as error:
        primary = error
    finally:
        for role, stop in (
            ("windows", boundary.stop_windows),
            ("controller", boundary.stop_controller),
            ("switch", boundary.stop_switch),
        ):
            if role in intended:
                try:
                    stop()
                except BaseException as error:
                    cleanup.append(f"{role}: {type(error).__name__}")
        try:
            if entered:
                signals.__exit__(None, None, None)
        except BaseException as error:
            cleanup.append(f"signal handlers: {type(error).__name__}")
        os.umask(previous_umask)
    if primary is not None or cleanup or result is None:
        details = (
            ([f"calibration: {type(primary).__name__}"]
             if primary is not None else [])
            + cleanup
        )
        raise WindowsRunDialogCalibrationError(
            "Run-dialog calibration failed; " + "; ".join(details)
        ) from primary
    try:
        final_stat = publication.stat()
        final_identity = (
            final_stat.st_dev,
            final_stat.st_ino,
            final_stat.st_size,
            _digest_file(publication),
        )
    except OSError as error:
        raise WindowsRunDialogCalibrationError(
            "private publication changed during calibration") from error
    if final_identity != publication_identity:
        raise WindowsRunDialogCalibrationError(
            "private publication changed during calibration")
    frames, image = result
    candidate, manifest = _write_candidate(
        root, frames, image, desktop, boundary.attempt, source_bundle, plan.crop)
    return RunDialogCalibrationReceipt(
        candidate, manifest, frames, True, True, 2, True)
