#!/usr/bin/env python3
"""Trust stages for progressively calibrating Windows identity references.

Calibration is deliberately separate from credential rotation.  A reference
captured after typing private material is not automatically trusted merely
because the runner produced it; an operator must promote it into the tracked
reference set before a later run can rely on it.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from pathlib import Path


class WindowsIdentityCalibrationError(RuntimeError):
    """The proposed reference set breaks the progressive trust chain."""


class CalibrationStage(Enum):
    """The next bounded operation authorized by the trusted references."""

    CAPTURE_SIGN_IN = "capture-sign-in"
    CAPTURE_NAVIGATION = "capture-navigation"
    ROTATE_AND_PROVE = "rotate-and-prove"


@dataclass(frozen=True)
class TrustedIdentityReferences:
    """Reviewed references available before a credential-bearing run.

    ``final_desktop`` intentionally reuses ``desktop``.  A successful
    rotation must return to the same known desktop and then prove a fresh
    sign-in with the replacement credential.  It must not require a
    pre-existing image of a password-changed screen that can only be produced
    by performing the rotation.
    """

    sign_in: Path | None = None
    desktop: Path | None = None
    security_options: Path | None = None
    change_password: Path | None = None

    def stage(self) -> CalibrationStage:
        """Return the only credential-flow stage this trust set authorizes."""
        navigation = (
            self.desktop,
            self.security_options,
            self.change_password,
        )
        if self.sign_in is None:
            if any(reference is not None for reference in navigation):
                raise WindowsIdentityCalibrationError(
                    "navigation references cannot precede sign-in authority")
            return CalibrationStage.CAPTURE_SIGN_IN
        if all(reference is None for reference in navigation):
            return CalibrationStage.CAPTURE_NAVIGATION
        if any(reference is None for reference in navigation):
            raise WindowsIdentityCalibrationError(
                "navigation references must be promoted as one reviewed set")
        return CalibrationStage.ROTATE_AND_PROVE

    def rotation_reference_paths(self) -> tuple[Path, ...]:
        """Return the four pre-rotation references, in observation order."""
        if self.stage() is not CalibrationStage.ROTATE_AND_PROVE:
            raise WindowsIdentityCalibrationError(
                "trusted references do not authorize rotation")
        assert self.sign_in is not None
        assert self.desktop is not None
        assert self.security_options is not None
        assert self.change_password is not None
        return (
            self.sign_in,
            self.desktop,
            self.security_options,
            self.change_password,
        )

    def final_desktop_reference(self) -> Path:
        """Return the known desktop used before and after the rotation."""
        if self.stage() is not CalibrationStage.ROTATE_AND_PROVE:
            raise WindowsIdentityCalibrationError(
                "trusted references do not authorize final desktop proof")
        assert self.desktop is not None
        return self.desktop
