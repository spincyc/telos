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


RUN_DIALOG_REFERENCE_SIZE = (430, 230)
RUN_DIALOG_CHROME_CROP = (0, 0, 430, 110)
MAX_PUBLIC_COMMAND_CHARS = 240
PRIVATE_MEDIA_POLL_ATTEMPTS = 40
_PRIVATE_MEDIA_LABEL = re.compile(r"[A-Z][A-Z0-9_]{0,31}")
_PRIVATE_MEDIA_ENTRYPOINT = re.compile(r"[A-Za-z0-9-]+\.ps1")


def bounded_media_launch_command(label: str, entrypoint: str) -> str:
    """Build one bounded, exact-label private-media launcher."""
    if (
        not isinstance(label, str)
        or _PRIVATE_MEDIA_LABEL.fullmatch(label) is None
        or not isinstance(entrypoint, str)
        or _PRIVATE_MEDIA_ENTRYPOINT.fullmatch(entrypoint) is None
    ):
        raise WindowsPublicCommandError(
            "private-media launcher inputs are invalid")
    command = (
        'powershell -NoP -NonI -EP Bypass -C "'
        f"1..{PRIVATE_MEDIA_POLL_ATTEMPTS}|%{{"
        f"if(!$d){{$v=@(Get-Volume -FileSystemLabel {label}|? DriveLetter);"
        "switch($v.Count){0{sleep 1}1{$d=$v[0]}default{throw 2}}}};"
        f"if(!$d){{throw 1}};&($d.DriveLetter+':\\{entrypoint}')\""
    )
    if len(command) > MAX_PUBLIC_COMMAND_CHARS:
        raise WindowsPublicCommandError(
            "private-media launch command exceeds the public command bound")
    return command


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
        public_key_interval: float = 0.075,
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
        if (
            type(public_key_interval) not in (int, float)
            or not math.isfinite(public_key_interval)
            or not 0.060 <= public_key_interval <= 1.0
        ):
            raise WindowsPublicCommandError(
                "public key interval must be between 60ms and 1s")
        self.interval = interval
        self.public_key_interval = public_key_interval
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
        if (
            plan.run_dialog.image.width,
            plan.run_dialog.image.height,
        ) != RUN_DIALOG_REFERENCE_SIZE:
            raise WindowsPublicCommandError(
                "Run reference does not use reviewed 430x230 crop")
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
            or not 1 <= len(command) <= MAX_PUBLIC_COMMAND_CHARS
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

    def _type_public_command(self, command: str) -> None:
        """Space QMP key events so a long public command cannot overlap."""
        for character in command:
            self.qmp.type_text(character)
            # QmpClient requests a 60ms hold time. Do not issue the following
            # character (or Enter) before that key can have been released.
            self.pause(self.public_key_interval)

    def _observe_run_dialog_departed(
        self,
        reference: ValidatedIdentityReference,
        *,
        threshold: float,
        max_frames: int,
    ) -> None:
        """Prove two useful non-Run frames without retaining their contents."""
        reference_chrome = crop_image(
            reference.image, RUN_DIALOG_CHROME_CROP)
        consecutive = 0
        for _ in range(max_frames):
            self.sequence += 1
            path = self.root / (
                f"public-{self.sequence:04d}-run-dialog-departed.ppm")
            try:
                self.qmp.screenshot(path)
                os.chmod(path, 0o600)
                full = read_ppm(path)
                if (full.width, full.height) != reference.geometry:
                    consecutive = 0
                else:
                    run_crop = crop_image(full, reference.crop)
                    actual_chrome = crop_image(
                        run_crop, RUN_DIALOG_CHROME_CROP)
                    distance = image_distance(
                        actual_chrome, reference_chrome)
                    if useful_frame(actual_chrome) and distance > threshold:
                        consecutive += 1
                        if consecutive == 2:
                            return
                    else:
                        consecutive = 0
            except (OSError, WindowsGuiError):
                consecutive = 0
            finally:
                # A post-submit screen can contain arbitrary console or error
                # output. Only the fixed departure receipt may survive.
                path.unlink(missing_ok=True)
            self.pause(self.interval)
        raise WindowsPublicCommandError(
            f"failed to prove Run dialog departed within {max_frames} frames")

    def launch(
        self,
        command: str,
        plan: PublicPowerShellLaunchPlan,
    ) -> tuple[str, ...]:
        """Open Run and submit a public command after stable visual matches."""
        self._validate(plan, command)
        backend_failed = False
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
            self._type_public_command(command)
            self.qmp.key("ret")
            self._observe_run_dialog_departed(
                plan.run_dialog,
                threshold=plan.threshold,
                max_frames=plan.max_frames_per_state,
            )
        except WindowsPublicCommandError:
            raise
        except Exception:
            # Leave the active exception handler before raising. ``from None``
            # hides context when rendered but still stores it on the exception
            # object, which would retain arbitrary backend material.
            backend_failed = True
        if backend_failed:
            raise WindowsPublicCommandError("public command launch failed")
        return (
            "observed:desktop",
            "requested:run-dialog",
            "observed:run-dialog",
            "submitted:public-powershell-command",
            "observed:run-dialog-departed",
        )
