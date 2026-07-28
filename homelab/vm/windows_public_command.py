#!/usr/bin/env python3
"""Launch a bounded, non-secret PowerShell command through proven QMP states."""

from __future__ import annotations

from dataclasses import dataclass
import math
import os
from pathlib import Path
import re
import time
from typing import Callable

from .windows_gui import (
    QmpClient,
    WindowsGuiError,
    crop_image,
    image_distance,
    read_ppm,
    useful_frame,
)
from .windows_identity_reference import ValidatedIdentityReference


class WindowsPublicCommandError(RuntimeError):
    """A public command was not launched from the calibrated GUI states."""


@dataclass(frozen=True)
class PublicPowerShellLaunchPlan:
    """Public visual authority and finite observation bounds for one launch."""

    desktop: ValidatedIdentityReference
    run_dialog: ValidatedIdentityReference
    threshold: float = 6.0
    max_frames_per_state: int = 30


class WindowsPublicCommandLauncher:
    """Type a public PowerShell command only after two stable GUI proofs."""

    def __init__(
        self,
        qmp: QmpClient,
        evidence_root: Path,
        *,
        interval: float = 1.0,
        pause: Callable[[float], None] = time.sleep,
    ) -> None:
        if evidence_root.is_symlink():
            raise WindowsPublicCommandError(
                "command evidence root must not be a symlink")
        root = evidence_root.resolve()
        if not root.is_dir() or root.stat().st_mode & 0o077:
            raise WindowsPublicCommandError(
                "command evidence root must be a private directory")
        self.qmp = qmp
        self.root = root
        self.interval = interval
        self.pause = pause
        self.sequence = 0

    @staticmethod
    def _validate(plan: PublicPowerShellLaunchPlan, command: str) -> None:
        if plan.desktop.state_kind != "desktop":
            raise WindowsPublicCommandError(
                "desktop reference does not prove a desktop")
        if plan.run_dialog.state_kind != "run-dialog":
            raise WindowsPublicCommandError(
                "Run reference does not prove a Run dialog")
        if plan.desktop.guest != plan.run_dialog.guest:
            raise WindowsPublicCommandError(
                "GUI references describe different guests")
        if plan.desktop.geometry != plan.run_dialog.geometry:
            raise WindowsPublicCommandError(
                "GUI references use different display geometry")
        if (
            type(plan.max_frames_per_state) is not int
            or not 2 <= plan.max_frames_per_state <= 120
            or type(plan.threshold) not in (int, float)
            or not math.isfinite(plan.threshold)
            or not 0 <= plan.threshold <= 32
        ):
            raise WindowsPublicCommandError("invalid GUI observation bounds")
        if (
            not isinstance(command, str)
            or not 1 <= len(command) <= 512
            or "\r" in command
            or "\n" in command
            or "\t" in command
            or not command.isascii()
            or any(ord(character) < 0x20 or ord(character) == 0x7f
                    for character in command)
        ):
            raise WindowsPublicCommandError("invalid public command")
        # This boundary is intentionally command-specific. It cannot be used
        # to type credentials into an arbitrary application or shell.
        if re.fullmatch(r"(?i:powershell(?:\.exe)?(?:\s+.+)?)", command) is None:
            raise WindowsPublicCommandError(
                "public command must invoke PowerShell")

    def _observe(
        self,
        label: str,
        reference: ValidatedIdentityReference,
        *,
        threshold: float,
        max_frames: int,
    ) -> None:
        consecutive = 0
        best = float("inf")
        for _ in range(max_frames):
            self.sequence += 1
            path = self.root / f"public-{self.sequence:04d}-{label}.ppm"
            self.qmp.screenshot(path)
            os.chmod(path, 0o600)
            try:
                full = read_ppm(path)
                if (full.width, full.height) != reference.geometry:
                    distance = float("inf")
                    actual = full
                else:
                    actual = crop_image(full, reference.crop)
                    distance = image_distance(actual, reference.image)
            except (OSError, WindowsGuiError):
                distance = float("inf")
                actual = None
            best = min(best, distance)
            if (
                actual is not None
                and useful_frame(actual)
                and distance <= threshold
            ):
                consecutive += 1
                if consecutive == 2:
                    return
            else:
                consecutive = 0
                path.unlink(missing_ok=True)
            self.pause(self.interval)
        raise WindowsPublicCommandError(
            f"failed to prove {label} within {max_frames} frames; "
            f"best image distance {best:.2f}")

    def launch(
        self,
        command: str,
        plan: PublicPowerShellLaunchPlan,
    ) -> tuple[str, ...]:
        """Open Run and submit a public command after stable visual matches."""
        self._validate(plan, command)
        try:
            self._observe(
                "desktop",
                plan.desktop,
                threshold=plan.threshold,
                max_frames=plan.max_frames_per_state,
            )
            self.qmp.chord("meta_l", "r")
            self._observe(
                "run-dialog",
                plan.run_dialog,
                threshold=plan.threshold,
                max_frames=plan.max_frames_per_state,
            )
            self.qmp.type_text(command)
            self.qmp.key("ret")
        except WindowsPublicCommandError:
            raise
        except Exception as error:
            # Do not include backend messages: they may reflect typed input.
            raise WindowsPublicCommandError(
                f"public command launch failed: {type(error).__name__}") from None
        return (
            "observed:desktop",
            "requested:run-dialog",
            "observed:run-dialog",
            "submitted:public-powershell-command",
        )
