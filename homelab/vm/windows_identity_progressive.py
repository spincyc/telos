#!/usr/bin/env python3
"""Bounded, fail-closed execution of a calibrated Windows password rotation."""

from __future__ import annotations

from contextlib import AbstractContextManager
from dataclasses import dataclass
import os
from pathlib import Path
import time
from typing import Callable, Protocol

from .signal_cleanup import RunInterrupted, SignalGuard
from .windows_gui import (
    SAFE_KEYS,
    Checkpoint,
    QmpClient,
    crop_image,
    image_distance,
    read_ppm,
    useful_frame,
)
from .windows_identity_gui import (
    WindowsCredentialRotationDriver,
    WindowsIdentityGuiError,
)
from .windows_identity_reference import (
    GuestProvenance,
    ValidatedIdentityReference,
    WindowsIdentityReferenceError,
    load_identity_reference,
)
from .windows_identity_run import NativeProcessBoundary


class WindowsIdentityProgressiveError(RuntimeError):
    """The bounded rotation could not be completed and proved."""


class RecoverableCredential(AbstractContextManager[str], Protocol):
    """Transient old credential plus its exact private publication."""

    def destroy_publication(self) -> None: ...


class RotationSession(AbstractContextManager[QmpClient], Protocol):
    """An isolated guest session whose exit performs unconditional teardown."""


class RotationInteraction(Protocol):
    """Secret-owning GUI operations used by the executor."""

    def observe(
        self, reference: ValidatedIdentityReference, timeout: float
    ) -> None: ...

    def observe_departure(
        self, reference: ValidatedIdentityReference, timeout: float
    ) -> None: ...

    def type_secret(self, value: str) -> None: ...

    def key(self, name: str) -> None: ...

    def chord(self, *names: str) -> None: ...


@dataclass(frozen=True)
class ProgressiveRotationPlan:
    """Four reviewed, guest-bound states and bounded public navigation."""

    sign_in_manifest: Path
    desktop_manifest: Path
    security_options_manifest: Path
    change_password_manifest: Path
    expected_guest: GuestProvenance
    evidence_root: Path
    initial_sign_in_keys: tuple[str, ...] = ("spc",)
    change_password_keys: tuple[str, ...] = ()
    wake_after_lock_keys: tuple[str, ...] = ("spc",)
    initial_sign_in_delay: float = 60.0
    lock_settle_delay: float = 2.0
    timeout: float = 360.0
    checkpoint_timeout: float = 60.0


@dataclass(frozen=True)
class ProgressiveRotationReceipt:
    """Non-secret proof milestones from one completed rotation."""

    phases: tuple[str, ...]
    publication_destroyed: bool
    replacement_sign_in_proved: bool


class NativeBoundaryRotationSession(AbstractContextManager[QmpClient]):
    """Production session that owns every native process through teardown."""

    def __init__(self, boundary: NativeProcessBoundary) -> None:
        self.boundary = boundary
        self._intended: list[str] = []

    def __enter__(self) -> QmpClient:
        try:
            self._intended.append("switch")
            self.boundary.start_switch()
            self._intended.append("controller")
            self.boundary.start_controller()
            self._intended.append("windows")
            self.boundary.start_windows()
            self.boundary.authenticate_qmp()
            if self.boundary.qmp is None:
                raise WindowsIdentityProgressiveError(
                    "QMP authentication returned without a client")
            return self.boundary.qmp
        except BaseException as primary:
            try:
                self.__exit__(None, None, None)
            except BaseException as cleanup:
                raise WindowsIdentityProgressiveError(
                    "native identity acquisition and teardown failed: "
                    f"{type(primary).__name__}; "
                    f"{type(cleanup).__name__}") from None
            raise

    def __exit__(self, *_exc: object) -> None:
        failures: list[str] = []
        stops = {
            "windows": self.boundary.stop_windows,
            "controller": self.boundary.stop_controller,
            "switch": self.boundary.stop_switch,
        }
        for role in reversed(self._intended):
            try:
                stops[role]()
            except BaseException as error:
                failures.append(f"{role}: {type(error).__name__}")
            else:
                self._intended.remove(role)
        if failures:
            raise WindowsIdentityProgressiveError(
                "native identity teardown failed; " + "; ".join(failures))


class _GuiInteraction:
    def __init__(self, qmp: QmpClient, evidence_root: Path) -> None:
        self._driver = WindowsCredentialRotationDriver(qmp, evidence_root)
        self._qmp = qmp

    def observe(
        self, reference: ValidatedIdentityReference, timeout: float
    ) -> None:
        checkpoint = Checkpoint(
            reference.state_kind,
            reference.path,
            (),
            timeout=timeout,
            crop=reference.crop,
        )
        self._driver._observe(checkpoint)

    def observe_departure(
        self, reference: ValidatedIdentityReference, timeout: float
    ) -> None:
        deadline = self._driver.clock() + timeout
        consecutive = 0
        while self._driver.clock() < deadline:
            self._driver.sequence += 1
            path = self._driver.observer.root / (
                f"identity-{self._driver.sequence:04d}-"
                f"departed-{reference.state_kind}.ppm")
            self._qmp.screenshot(path)
            os.chmod(path, 0o600)
            actual = crop_image(read_ppm(path), reference.crop)
            distance = image_distance(actual, reference.image)
            if useful_frame(actual) and distance > 6.0:
                consecutive += 1
                if consecutive == 2:
                    return
            else:
                consecutive = 0
                path.unlink(missing_ok=True)
            self._driver.pause(self._driver.interval)
        raise WindowsIdentityGuiError(
            f"timed out proving departure from {reference.state_kind}")

    def type_secret(self, value: str) -> None:
        self._driver._validate_secret(value)
        self._qmp.type_text(value)

    def key(self, name: str) -> None:
        self._qmp.key(name)

    def chord(self, *names: str) -> None:
        self._qmp.chord(*names)


def _load_references(
    plan: ProgressiveRotationPlan,
) -> tuple[ValidatedIdentityReference, ...]:
    paths = (
        plan.sign_in_manifest,
        plan.desktop_manifest,
        plan.security_options_manifest,
        plan.change_password_manifest,
    )
    expected_kinds = (
        "sign-in", "desktop", "security-options", "change-password")
    references = tuple(
        load_identity_reference(path, expected_guest=plan.expected_guest)
        for path in paths
    )
    if tuple(reference.state_kind for reference in references) != expected_kinds:
        raise WindowsIdentityProgressiveError(
            "identity references are not in the required trust order")
    return references


def _private_evidence_root(path: Path) -> Path:
    path = Path(path).absolute()
    if path.exists():
        if (
            path.is_symlink()
            or not path.is_dir()
            or path.stat().st_mode & 0o077
        ):
            raise WindowsIdentityProgressiveError(
                "rotation evidence root must be a private real directory")
    else:
        path.mkdir(parents=True, mode=0o700)
    return path


def execute_progressive_rotation(
    *,
    plan: ProgressiveRotationPlan,
    session: RotationSession,
    recovery: RecoverableCredential,
    generate_credential: Callable[[], str],
    after_rotation: Callable[[str], None] | None = None,
    clock: Callable[[], float] = time.monotonic,
    pause: Callable[[float], None] = time.sleep,
    interaction_factory: Callable[
        [QmpClient, Path], RotationInteraction
    ] = _GuiInteraction,
) -> ProgressiveRotationReceipt:
    """Rotate, consume the publication, and prove a fresh replacement login.

    Publication destruction occurs immediately after a fresh replacement
    login returns to the known desktop. Both context managers exit on every
    success or failure path.
    """
    if (
        plan.timeout <= 0
        or plan.checkpoint_timeout <= 0
        or plan.checkpoint_timeout > plan.timeout
        or plan.initial_sign_in_delay < 0
        or plan.lock_settle_delay < 0
        or any(
            key not in SAFE_KEYS
            for keys in (
                plan.initial_sign_in_keys,
                plan.change_password_keys,
                plan.wake_after_lock_keys,
            )
            for key in keys
        )
    ):
        raise WindowsIdentityProgressiveError("invalid progressive plan")
    try:
        references = _load_references(plan)
    except (OSError, WindowsIdentityReferenceError):
        raise WindowsIdentityProgressiveError(
            "trusted identity reference validation failed") from None

    deadline = clock() + plan.timeout
    phases: list[str] = []

    def remaining() -> float:
        value = min(plan.checkpoint_timeout, deadline - clock())
        if value <= 0:
            raise WindowsIdentityProgressiveError(
                "progressive rotation deadline expired")
        return value

    try:
        # Keep the signal guard outermost. It defers interruption until the
        # recovery and guest-session context managers have both torn down.
        with SignalGuard():
            with recovery as old_credential, session as qmp:
                WindowsCredentialRotationDriver._validate_secret(old_credential)

                sign_in, desktop, security_options, change_password = references
                gui = interaction_factory(
                    qmp, _private_evidence_root(plan.evidence_root))
                if plan.initial_sign_in_delay:
                    pause(plan.initial_sign_in_delay)
                for key in plan.initial_sign_in_keys:
                    gui.key(key)
                gui.observe(sign_in, remaining())
                gui.type_secret(old_credential)
                gui.key("ret")
                gui.observe(desktop, remaining())
                phases.append("old-credential-sign-in-proved")

                gui.chord("ctrl", "alt", "delete")
                gui.observe(security_options, remaining())
                for key in plan.change_password_keys:
                    gui.key(key)
                gui.observe(change_password, remaining())
                # Generate the replacement only at the first operation that
                # needs it. It must not survive initial login or public
                # navigation merely because those phases precede rotation.
                new_credential = generate_credential()
                WindowsCredentialRotationDriver._validate_secret(
                    new_credential)
                if old_credential == new_credential:
                    raise WindowsIdentityProgressiveError(
                        "replacement credential must be distinct")
                gui.type_secret(old_credential)
                gui.key("tab")
                gui.type_secret(new_credential)
                gui.key("tab")
                gui.type_secret(new_credential)
                gui.key("ret")

                # Windows displays a public success confirmation. Prove that
                # the change form departed before acknowledging it.
                gui.observe_departure(change_password, remaining())
                gui.key("ret")
                gui.observe(desktop, remaining())

                gui.chord("meta_l", "l")
                if plan.lock_settle_delay:
                    pause(plan.lock_settle_delay)
                for key in plan.wake_after_lock_keys:
                    gui.key(key)
                gui.observe(sign_in, remaining())
                gui.type_secret(new_credential)
                gui.key("ret")
                gui.observe(desktop, remaining())
                # A fresh login is the first conclusive password-change proof.
                phases.append("replacement-credential-sign-in-proved")
                if after_rotation is not None:
                    # Keep the replacement credential inside the guarded
                    # recovery/session lifetime until all acceptance work
                    # that depends on it has completed. A failed callback
                    # preserves the old publication so a fresh source overlay
                    # remains recoverable.
                    after_rotation(new_credential)
                    phases.append("post-rotation-acceptance-complete")
                recovery.destroy_publication()
                phases.append("private-publication-destroyed")
    except WindowsIdentityProgressiveError:
        raise
    except (KeyboardInterrupt, SystemExit, RunInterrupted):
        raise
    except Exception as error:
        # Do not chain backend, generator, or recovery exceptions: any of them
        # could contain a credential value.
        raise WindowsIdentityProgressiveError(
            f"progressive rotation failed: {type(error).__name__}") from None

    return ProgressiveRotationReceipt(
        phases=tuple(phases),
        publication_destroyed=True,
        replacement_sign_in_proved=True,
    )
