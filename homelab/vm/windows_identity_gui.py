#!/usr/bin/env python3
"""Fail-closed QMP GUI login and local-password rotation for Windows."""

from __future__ import annotations

from dataclasses import dataclass
import os
from pathlib import Path
import re
import time
from typing import Callable

from .windows_gui import (
    SAFE_KEYS,
    Checkpoint,
    QmpClient,
    WindowsGuiError,
    WindowsSetupDriver,
    crop_image,
    image_distance,
    read_ppm,
    useful_frame,
)


class WindowsIdentityGuiError(RuntimeError):
    """The private Windows credential flow could not be proved."""


@dataclass(frozen=True)
class CredentialRotationPlan:
    """Calibrated public visual states and navigation for one rotation.

    References must come from the same installed Windows release and QEMU
    display geometry.  The sign-in and change-password references must show
    their password fields already focused; generic or setup-era images are
    not authority to enter a credential.
    """

    sign_in: Checkpoint
    desktop: Checkpoint
    security_options: Checkpoint
    change_password: Checkpoint
    password_changed: Checkpoint
    final_desktop: Checkpoint
    change_password_keys: tuple[str, ...] = ()
    password_changed_keys: tuple[str, ...] = ("ret",)


class WindowsCredentialRotationDriver:
    """Enter credentials only after observing the expected private GUI state."""

    def __init__(
        self,
        qmp: QmpClient,
        evidence_root: Path,
        *,
        interval: float = 1.0,
        clock: Callable[[], float] = time.monotonic,
        pause: Callable[[float], None] = time.sleep,
    ) -> None:
        self.qmp = qmp
        self.pause = pause
        self.clock = clock
        self.interval = interval
        self.sequence = 0
        self.observer = WindowsSetupDriver(
            qmp,
            evidence_root,
            interval=interval,
            clock=clock,
            pause=pause,
        )
        if self.observer.root.stat().st_mode & 0o077:
            raise WindowsIdentityGuiError(
                "credential evidence root must be private")

    def _observe(self, checkpoint: Checkpoint) -> None:
        # One matching transitional frame is not enough authority to type a
        # credential. The reference must depict the already-focused field.
        reference = crop_image(
            read_ppm(checkpoint.reference), checkpoint.crop)
        deadline = self.clock() + checkpoint.timeout
        consecutive = 0
        best = float("inf")
        while self.clock() < deadline:
            self.sequence += 1
            path = self.observer.root / (
                f"identity-{self.sequence:04d}-{checkpoint.name}.ppm")
            self.qmp.screenshot(path)
            os.chmod(path, 0o600)
            actual = crop_image(read_ppm(path), checkpoint.crop)
            distance = image_distance(actual, reference)
            best = min(best, distance)
            if useful_frame(actual) and distance <= checkpoint.threshold:
                consecutive += 1
                if consecutive == 2:
                    return
            else:
                consecutive = 0
                path.unlink(missing_ok=True)
            self.pause(self.interval)
        raise WindowsIdentityGuiError(
            f"timed out proving {checkpoint.name}; "
            f"best image distance {best:.2f}")

    @staticmethod
    def _validate_secret(value: str) -> None:
        # Keep this deliberately less descriptive than QMP text validation:
        # neither the value nor a derived fragment belongs in an exception.
        if not isinstance(value, str) or not 1 <= len(value) <= 256:
            raise WindowsIdentityGuiError("invalid private credential")
        if "\r" in value or "\n" in value or "\t" in value:
            raise WindowsIdentityGuiError("invalid private credential")

    def _keys(self, names: tuple[str, ...]) -> None:
        for name in names:
            self.qmp.key(name)
            self.pause(0.15)

    def rotate(
        self,
        old_credential: str,
        new_credential: str,
        plan: CredentialRotationPlan,
    ) -> tuple[str, ...]:
        """Prove login and rotate the local password without retaining values."""
        self._validate_secret(old_credential)
        self._validate_secret(new_credential)
        if old_credential == new_credential:
            raise WindowsIdentityGuiError(
                "replacement credential must be distinct")
        checkpoints = (
            plan.sign_in,
            plan.desktop,
            plan.security_options,
            plan.change_password,
            plan.password_changed,
            plan.final_desktop,
        )
        if any(
            re.fullmatch(r"[a-z0-9]+(?:-[a-z0-9]+)*", checkpoint.name)
            is None
            for checkpoint in checkpoints
        ):
            raise WindowsIdentityGuiError("unsafe credential checkpoint name")
        if any(
            name not in SAFE_KEYS
            for names in (
                plan.change_password_keys,
                plan.password_changed_keys,
            )
            for name in names
        ):
            raise WindowsIdentityGuiError("unsafe credential GUI navigation")

        events: list[str] = []
        try:
            self._observe(plan.sign_in)
            events.append("observed:sign-in")
            self.qmp.type_text(old_credential)
            self.qmp.key("ret")
            events.append("submitted:private-sign-in")

            self._observe(plan.desktop)
            events.append("observed:desktop")
            self.qmp.chord("ctrl", "alt", "delete")
            events.append("requested:security-options")

            self._observe(plan.security_options)
            events.append("observed:security-options")
            self._keys(plan.change_password_keys)

            self._observe(plan.change_password)
            events.append("observed:change-password")
            self.qmp.type_text(old_credential)
            self.qmp.key("tab")
            self.qmp.type_text(new_credential)
            self.qmp.key("tab")
            self.qmp.type_text(new_credential)
            self.qmp.key("ret")
            events.append("submitted:credential-rotation")

            self._observe(plan.password_changed)
            events.append("observed:password-changed")
            self._keys(plan.password_changed_keys)
            self._observe(plan.final_desktop)
            events.append("observed:final-desktop")
        except WindowsIdentityGuiError:
            raise
        except WindowsGuiError as error:
            raise WindowsIdentityGuiError(
                "Windows credential GUI proof failed") from error
        except Exception as error:
            # QMP errors are intentionally collapsed at this secret-owning
            # boundary so a backend cannot accidentally echo typed material.
            raise WindowsIdentityGuiError(
                f"Windows credential GUI operation failed: "
                f"{type(error).__name__}") from None
        return tuple(events)
