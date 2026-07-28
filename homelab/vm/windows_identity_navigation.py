#!/usr/bin/env python3
"""Bounded progressive calibration of post-login Windows identity states."""

from __future__ import annotations

from contextlib import AbstractContextManager
from dataclasses import dataclass
import hashlib
import os
from pathlib import Path
import time
from typing import Callable

from .windows_gui import (
    SAFE_KEYS,
    Checkpoint,
    Image,
    WindowsGuiError,
    crop_image,
    read_ppm,
    useful_frame,
)
from .windows_identity_gui import WindowsCredentialRotationDriver
from .windows_identity_reference import (
    GuestProvenance,
    WindowsIdentityReferenceError,
    load_identity_reference,
)
from .windows_identity_run import NativeProcessBoundary
from .signal_cleanup import SignalGuard


class WindowsIdentityNavigationError(RuntimeError):
    """Progressive navigation calibration did not close safely."""


@dataclass(frozen=True)
class NavigationCalibrationPlan:
    """Public navigation and stable regions for post-login calibration."""

    desktop_crop: tuple[int, int, int, int]
    security_options_crop: tuple[int, int, int, int]
    change_password_crop: tuple[int, int, int, int]
    change_password_keys: tuple[str, ...]
    timeout: float = 90.0
    interval: float = 1.0


@dataclass(frozen=True, repr=False)
class NavigationCalibrationReceipt:
    """Private artifact paths and secret-free facts from one bounded run."""

    desktop: tuple[Path, ...]
    security_options: tuple[Path, ...]
    change_password: tuple[Path, ...]
    credential_submitted: bool
    teardown_complete: bool

    def __repr__(self) -> str:
        return (
            "NavigationCalibrationReceipt("
            "desktop=<private>, security_options=<private>, "
            "change_password=<private>, credential_submitted="
            f"{self.credential_submitted!r}, "
            f"teardown_complete={self.teardown_complete!r})"
        )


def _bound_sign_in(
    manifest: Path,
    expected: GuestProvenance,
) -> Checkpoint:
    """Load one stable sign-in reference and bind its guest provenance."""
    manifest = Path(manifest)
    try:
        reference = load_identity_reference(
            manifest, expected_guest=expected)
    except (
        OSError,
        UnicodeError,
        WindowsIdentityReferenceError,
    ) as error:
        raise WindowsIdentityNavigationError(
            "trusted sign-in reference is invalid") from error
    if reference.state != (
            "focused password field for local account telosadmin"):
        raise WindowsIdentityNavigationError(
            "trusted reference is not the focused pre-input sign-in state")
    return Checkpoint(
        "sign-in",
        reference.path,
        (),
        timeout=90.0,
        threshold=0.0,
        crop=reference.crop,
    )


def _private_root(path: Path) -> Path:
    path = Path(path).absolute()
    if path.exists():
        if path.is_symlink() or not path.is_dir():
            raise WindowsIdentityNavigationError(
                "navigation evidence root must be a real directory")
    else:
        path.mkdir(parents=True, mode=0o700)
    if path.stat().st_mode & 0o077:
        raise WindowsIdentityNavigationError(
            "navigation evidence root must be private")
    return path


def _stable_frames(
    boundary: NativeProcessBoundary,
    root: Path,
    name: str,
    crop: tuple[int, int, int, int],
    *,
    timeout: float,
    interval: float,
    clock: Callable[[], float],
    pause: Callable[[float], None],
) -> tuple[Path, ...]:
    if boundary.qmp is None:
        raise WindowsIdentityNavigationError("QMP is unavailable")
    deadline = clock() + timeout
    stable: list[tuple[bytes, Path]] = []
    sequence = 0
    while clock() < deadline:
        sequence += 1
        path = root / f"{name}-{sequence:04d}.ppm"
        boundary.qmp.screenshot(path)
        path.chmod(0o600)
        try:
            image = read_ppm(path)
            selected: Image = crop_image(image, crop)
        except (OSError, WindowsGuiError) as error:
            raise WindowsIdentityNavigationError(
                f"{name} calibration frame is invalid") from error
        if useful_frame(selected):
            digest = hashlib.sha256(selected.pixels).digest()
            if stable and stable[-1][0] != digest:
                for _, old_path in stable:
                    old_path.unlink(missing_ok=True)
                stable.clear()
            stable.append((digest, path))
            if len(stable) == 3:
                return tuple(frame for _, frame in stable)
        else:
            path.unlink(missing_ok=True)
        pause(interval)
    raise WindowsIdentityNavigationError(
        f"timed out capturing stable public {name} state")


def capture_navigation(
    boundary: NativeProcessBoundary,
    *,
    sign_in_manifest: Path,
    expected_guest: GuestProvenance,
    recover_credential: Callable[[], AbstractContextManager[str]],
    evidence_root: Path,
    plan: NavigationCalibrationPlan,
    clock: Callable[[], float] = time.monotonic,
    pause: Callable[[float], None] = time.sleep,
) -> NavigationCalibrationReceipt:
    """Capture public navigation states without rotating any credential."""
    if (
        plan.timeout <= 0
        or plan.interval <= 0
        or any(key not in SAFE_KEYS for key in plan.change_password_keys)
    ):
        raise WindowsIdentityNavigationError(
            "navigation calibration plan is invalid")
    sign_in = _bound_sign_in(sign_in_manifest, expected_guest)
    root = _private_root(evidence_root)
    driver: WindowsCredentialRotationDriver | None = None
    desktop: tuple[Path, ...] = ()
    security: tuple[Path, ...] = ()
    change: tuple[Path, ...] = ()
    submitted = False
    primary: BaseException | None = None
    cleanup: list[str] = []
    intended: list[str] = []
    previous_umask = os.umask(0o077)
    try:
        with SignalGuard():
            intended.append("switch")
            boundary.start_switch()
            intended.append("controller")
            boundary.start_controller()
            intended.append("windows")
            boundary.start_windows()
            boundary.authenticate_qmp()
            if boundary.qmp is None:
                raise WindowsIdentityNavigationError(
                    "QMP authentication returned without a client")
            driver = WindowsCredentialRotationDriver(
                boundary.qmp,
                root,
                interval=plan.interval,
                clock=clock,
                pause=pause,
            )
            driver._observe(sign_in)
            try:
                with recover_credential() as credential:
                    driver._validate_secret(credential)
                    boundary.qmp.type_text(credential)
                    boundary.qmp.key("ret")
                    submitted = True
            except Exception:
                raise WindowsIdentityNavigationError(
                    "private sign-in operation failed") from None
            desktop = _stable_frames(
                boundary, root, "desktop", plan.desktop_crop,
                timeout=plan.timeout, interval=plan.interval,
                clock=clock, pause=pause,
            )
            boundary.qmp.chord("ctrl", "alt", "delete")
            security = _stable_frames(
                boundary, root, "security-options",
                plan.security_options_crop,
                timeout=plan.timeout, interval=plan.interval,
                clock=clock, pause=pause,
            )
            for key in plan.change_password_keys:
                boundary.qmp.key(key)
                pause(0.15)
            change = _stable_frames(
                boundary, root, "change-password",
                plan.change_password_crop,
                timeout=plan.timeout, interval=plan.interval,
                clock=clock, pause=pause,
            )
    except BaseException as error:
        primary = error
    finally:
        for role, stop in (
            ("windows", boundary.stop_windows),
            ("controller", boundary.stop_controller),
            ("switch", boundary.stop_switch),
        ):
            if role not in intended:
                continue
            try:
                stop()
            except BaseException as error:
                cleanup.append(f"{role}: {type(error).__name__}")
        os.umask(previous_umask)
    if primary is not None or cleanup:
        details = []
        if primary is not None:
            details.append(f"navigation: {type(primary).__name__}")
        details.extend(cleanup)
        raise WindowsIdentityNavigationError(
            "navigation calibration failed; " + "; ".join(details)
        ) from primary
    return NavigationCalibrationReceipt(
        desktop=desktop,
        security_options=security,
        change_password=change,
        credential_submitted=submitted,
        teardown_complete=True,
    )
