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
from .windows_identity_run import (
    IdentityFailureDiagnostic,
    NativeProcessBoundary,
    WindowsIdentityRunError,
)


@dataclass(frozen=True)
class ProgressiveGuiFailureDiagnostic:
    """Allowlisted GUI coordinates that cannot retain backend details."""

    stage: str
    operation: str
    error_type: str

    _COORDINATES = frozenset({
        ("initial-sign-in", "wake"),
        ("initial-sign-in", "observe"),
        ("old-sign-in", "submit"),
        ("initial-desktop", "observe"),
        ("security-options", "request"),
        ("security-options", "observe"),
        ("change-password", "navigate"),
        ("change-password", "observe"),
        ("credential-rotation", "submit"),
        ("change-password-confirmation", "observe-departure"),
        ("change-password-confirmation", "acknowledge"),
        ("post-rotation-desktop", "observe"),
        ("replacement-sign-in", "lock"),
        ("replacement-sign-in", "wake"),
        ("replacement-sign-in", "observe"),
        ("replacement-sign-in", "submit"),
        ("final-desktop", "observe"),
    })
    _ERROR_TYPES = frozenset({
        "OSError",
        "TimeoutError",
        "WindowsGuiError",
        "WindowsIdentityGuiError",
    })

    @classmethod
    def gui(
        cls,
        stage: str,
        operation: str,
        error: BaseException,
    ) -> "ProgressiveGuiFailureDiagnostic":
        if (stage, operation) not in cls._COORDINATES:
            stage = "unknown-stage"
            operation = "unknown-operation"
        error_type = type(error).__name__
        if error_type not in cls._ERROR_TYPES:
            error_type = "UnexpectedError"
        return cls(stage, operation, error_type)

    def __post_init__(self) -> None:
        if (
            (self.stage, self.operation) not in self._COORDINATES
            and (self.stage, self.operation)
            != ("unknown-stage", "unknown-operation")
        ):
            raise ValueError("progressive GUI failure coordinates are invalid")
        if (
            self.error_type not in self._ERROR_TYPES
            and self.error_type != "UnexpectedError"
        ):
            raise ValueError("progressive GUI failure type is invalid")

    def render(self) -> str:
        return (
            f"stage={self.stage}; operation={self.operation}; "
            f"error={self.error_type}"
        )


class WindowsIdentityProgressiveError(RuntimeError):
    """The bounded rotation could not be completed and proved."""

    def __init__(
        self,
        message: str,
        *,
        diagnostic: (
            IdentityFailureDiagnostic
            | ProgressiveGuiFailureDiagnostic
            | None
        ) = None,
    ) -> None:
        super().__init__(message)
        self.diagnostic = diagnostic


class _ProgressiveGuiOperationError(RuntimeError):
    """Internal carrier whose payload is already fixed and secret-free."""

    def __init__(self, diagnostic: ProgressiveGuiFailureDiagnostic) -> None:
        super().__init__("progressive GUI operation failed")
        self.diagnostic = diagnostic


class _ProgressiveDeadlineError(RuntimeError):
    """Internal marker raised only by the coordinator-owned deadline check."""


def _run_gui_operation(
    stage: str,
    operation: str,
    callback: Callable[[], object],
) -> None:
    """Run one GUI boundary and emit only fixed failure coordinates."""
    failure: ProgressiveGuiFailureDiagnostic | None = None
    try:
        callback()
    except (KeyboardInterrupt, SystemExit, RunInterrupted):
        raise
    except Exception as error:
        failure = ProgressiveGuiFailureDiagnostic.gui(
            stage, operation, error)
    if failure is not None:
        raise _ProgressiveGuiOperationError(failure) from None


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
    post_join_local_account_keys: tuple[str, ...] = ()
    post_join_operator_account_keys: tuple[str, ...] = ()
    post_join_local_account_calibrated: bool = False
    post_join_sign_in_manifest: Path | None = None
    post_join_operator_account_calibrated: bool = False
    post_join_operator_sign_in_manifest: Path | None = None
    post_join_operator_submit_focus_calibration: bool = False
    post_join_operator_submit_focus_tabs: int = 0
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
        self._durable_capture_enabled = True

    def observe(
        self, reference: ValidatedIdentityReference, timeout: float
    ) -> None:
        if not self._durable_capture_enabled:
            raise WindowsIdentityGuiError(
                "durable pixel capture is disabled")
        checkpoint = Checkpoint(
            reference.state_kind,
            reference.path,
            (),
            timeout=timeout,
            crop=reference.crop,
            expected_geometry=reference.geometry,
        )
        self._driver._observe(checkpoint)

    def disable_durable_capture(self) -> None:
        """Irreversibly prohibit retained screenshots after secret entry."""
        self._durable_capture_enabled = False

    def observe_ephemeral(
        self,
        reference: ValidatedIdentityReference,
        timeout: float,
        *,
        alternatives: tuple[
            tuple[str, ValidatedIdentityReference], ...
        ] = (),
    ) -> None:
        """Prove a state while deleting every captured frame immediately."""
        deadline = self._driver.clock() + timeout
        consecutive = 0
        alternative_consecutive = {
            name: 0 for name, _reference in alternatives}
        near_consecutive = 0
        alternative_near_consecutive = {
            name: 0 for name, _reference in alternatives}
        expected = reference.image
        while self._driver.clock() < deadline:
            self._driver.sequence += 1
            path = self._driver.observer.root / (
                f".identity-{self._driver.sequence:04d}-ephemeral.ppm")
            try:
                self._qmp.screenshot(path)
                os.chmod(path, 0o600)
                full_actual = read_ppm(path)
                if (
                    (full_actual.width, full_actual.height)
                    != reference.geometry
                ):
                    raise WindowsIdentityGuiError(
                        "live screenshot geometry differs from reference")
                actual = crop_image(full_actual, reference.crop)
                distance = image_distance(actual, expected)
            finally:
                path.unlink(missing_ok=True)
            if useful_frame(actual) and distance <= 6.0:
                consecutive += 1
                if consecutive == 2:
                    return
            else:
                consecutive = 0
            if useful_frame(actual) and distance <= 12.0:
                near_consecutive += 1
            else:
                near_consecutive = 0
            for name, alternative in alternatives:
                if (
                    (full_actual.width, full_actual.height)
                    != alternative.geometry
                ):
                    raise WindowsIdentityGuiError(
                        "live screenshot geometry differs from reference")
                alternative_actual = crop_image(
                    full_actual, alternative.crop)
                alternative_distance = image_distance(
                    alternative_actual, alternative.image)
                if (
                    useful_frame(alternative_actual)
                    and alternative_distance <= 6.0
                ):
                    alternative_consecutive[name] += 1
                else:
                    alternative_consecutive[name] = 0
                if (
                    useful_frame(alternative_actual)
                    and alternative_distance <= 12.0
                ):
                    alternative_near_consecutive[name] += 1
                else:
                    alternative_near_consecutive[name] = 0
                del alternative_actual, alternative_distance
            del full_actual, actual, distance
            self._driver.pause(self._driver.interval)
        for name, matches in alternative_consecutive.items():
            if matches >= 2:
                raise WindowsIdentityGuiAlternateState(name)
        near_states = [
            name for name, matches
            in alternative_near_consecutive.items()
            if matches >= 2
        ]
        if near_consecutive >= 2 and not near_states:
            raise WindowsIdentityGuiNearReference(reference.state_kind)
        if near_consecutive < 2 and len(near_states) == 1:
            raise WindowsIdentityGuiNearReference(near_states[0])
        raise WindowsIdentityGuiError(
            f"timed out proving {reference.state_kind}")

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

    def type_secret(
            self, value: str, *, timeout: float | None = None) -> None:
        self._driver._validate_secret(value)
        self._qmp.type_text(value, timeout=timeout)

    def key(self, name: str, *, timeout: float | None = None) -> None:
        self._qmp.key(name, timeout=timeout)

    def chord(
            self, *names: str, timeout: float | None = None) -> None:
        self._qmp.chord(*names, timeout=timeout)


class WindowsIdentityGuiAlternateState(WindowsIdentityGuiError):
    """A reviewed alternate state persisted after secret submission."""

    def __init__(self, state: str) -> None:
        self.state = state
        super().__init__("reviewed alternate GUI state persisted")


class WindowsIdentityGuiNearReference(WindowsIdentityGuiError):
    """A terminal pair was near exactly one reviewed reference."""

    def __init__(self, state: str) -> None:
        self.state = state
        super().__init__("terminal frames were near a reviewed GUI state")


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
    after_rotation: Callable[[str], None],
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
        or type(plan.post_join_local_account_calibrated) is not bool
        or type(plan.post_join_operator_account_calibrated) is not bool
        or type(plan.post_join_operator_submit_focus_calibration) is not bool
        or type(plan.post_join_operator_submit_focus_tabs) is not int
        or not 0 <= plan.post_join_operator_submit_focus_tabs <= 4
        or (
            plan.post_join_operator_submit_focus_calibration
            != (plan.post_join_operator_submit_focus_tabs > 0)
        )
        or any(
            key not in SAFE_KEYS
            for keys in (
                plan.initial_sign_in_keys,
                plan.change_password_keys,
                plan.wake_after_lock_keys,
                plan.post_join_local_account_keys,
                plan.post_join_operator_account_keys,
            )
            for key in keys
        )
    ):
        raise WindowsIdentityProgressiveError("invalid progressive plan")
    sanitized_failure: WindowsIdentityProgressiveError | None = None
    try:
        references = _load_references(plan)
    except (OSError, WindowsIdentityReferenceError):
        raise WindowsIdentityProgressiveError(
            "trusted identity reference validation failed") from None

    deadline: float | None = None
    phases: list[str] = []

    def remaining() -> float:
        if deadline is None:
            raise WindowsIdentityProgressiveError(
                "progressive rotation deadline is unavailable")
        value = min(plan.checkpoint_timeout, deadline - clock())
        if value <= 0:
            raise _ProgressiveDeadlineError
        return value

    try:
        # Keep the signal guard outermost. It defers interruption until the
        # recovery and guest-session context managers have both torn down.
        with SignalGuard():
            with recovery as old_credential, session as qmp:
                # Native acquisition has its own bounded Controller, Windows
                # boot, retry, and QMP gates. Start the rotation budget only
                # after those gates have produced the authenticated session.
                deadline = clock() + plan.timeout
                WindowsCredentialRotationDriver._validate_secret(old_credential)

                sign_in, desktop, security_options, change_password = references
                gui = interaction_factory(
                    qmp, _private_evidence_root(plan.evidence_root))
                if plan.initial_sign_in_delay:
                    pause(plan.initial_sign_in_delay)
                for key in plan.initial_sign_in_keys:
                    _run_gui_operation(
                        "initial-sign-in", "wake",
                        lambda key=key: gui.key(key),
                    )
                checkpoint_timeout = remaining()
                _run_gui_operation(
                    "initial-sign-in", "observe",
                    lambda: gui.observe(sign_in, checkpoint_timeout),
                )
                _run_gui_operation(
                    "old-sign-in", "submit",
                    lambda: (
                        gui.type_secret(old_credential),
                        gui.key("ret"),
                    ),
                )
                checkpoint_timeout = remaining()
                _run_gui_operation(
                    "initial-desktop", "observe",
                    lambda: gui.observe(desktop, checkpoint_timeout),
                )
                phases.append("old-credential-sign-in-proved")

                _run_gui_operation(
                    "security-options", "request",
                    lambda: gui.chord("ctrl", "alt", "delete"),
                )
                checkpoint_timeout = remaining()
                _run_gui_operation(
                    "security-options", "observe",
                    lambda: gui.observe(
                        security_options, checkpoint_timeout),
                )
                for key in plan.change_password_keys:
                    _run_gui_operation(
                        "change-password", "navigate",
                        lambda key=key: gui.key(key),
                    )
                checkpoint_timeout = remaining()
                _run_gui_operation(
                    "change-password", "observe",
                    lambda: gui.observe(
                        change_password, checkpoint_timeout),
                )
                # Generate the replacement only at the first operation that
                # needs it. It must not survive initial login or public
                # navigation merely because those phases precede rotation.
                new_credential = generate_credential()
                WindowsCredentialRotationDriver._validate_secret(
                    new_credential)
                if old_credential == new_credential:
                    raise WindowsIdentityProgressiveError(
                        "replacement credential must be distinct")
                _run_gui_operation(
                    "credential-rotation", "submit",
                    lambda: (
                        gui.type_secret(old_credential),
                        gui.key("tab"),
                        gui.type_secret(new_credential),
                        gui.key("tab"),
                        gui.type_secret(new_credential),
                        gui.key("ret"),
                    ),
                )

                # Windows displays a public success confirmation. Prove that
                # the change form departed before acknowledging it.
                checkpoint_timeout = remaining()
                _run_gui_operation(
                    "change-password-confirmation", "observe-departure",
                    lambda: gui.observe_departure(
                        change_password, checkpoint_timeout),
                )
                _run_gui_operation(
                    "change-password-confirmation", "acknowledge",
                    lambda: gui.key("ret"),
                )
                checkpoint_timeout = remaining()
                _run_gui_operation(
                    "post-rotation-desktop", "observe",
                    lambda: gui.observe(desktop, checkpoint_timeout),
                )

                _run_gui_operation(
                    "replacement-sign-in", "lock",
                    lambda: gui.chord("meta_l", "l"),
                )
                if plan.lock_settle_delay:
                    pause(plan.lock_settle_delay)
                for key in plan.wake_after_lock_keys:
                    _run_gui_operation(
                        "replacement-sign-in", "wake",
                        lambda key=key: gui.key(key),
                    )
                checkpoint_timeout = remaining()
                _run_gui_operation(
                    "replacement-sign-in", "observe",
                    lambda: gui.observe(sign_in, checkpoint_timeout),
                )
                _run_gui_operation(
                    "replacement-sign-in", "submit",
                    lambda: (
                        gui.type_secret(new_credential),
                        gui.key("ret"),
                    ),
                )
                checkpoint_timeout = remaining()
                _run_gui_operation(
                    "final-desktop", "observe",
                    lambda: gui.observe(desktop, checkpoint_timeout),
                )
                # A fresh login is the first conclusive password-change proof.
                phases.append("replacement-credential-sign-in-proved")
                # Keep the replacement credential inside the guarded
                # recovery/session lifetime until all acceptance work that
                # depends on it has completed. This continuation is mandatory:
                # a standalone destructive rotation may not discard the only
                # replacement credential. A failed callback preserves the old
                # publication so a fresh source overlay remains recoverable.
                after_rotation(new_credential)
                phases.append("post-rotation-acceptance-complete")
                recovery.destroy_publication()
                phases.append("private-publication-destroyed")
    except _ProgressiveGuiOperationError as error:
        sanitized_failure = WindowsIdentityProgressiveError(
            "progressive GUI phase failed; " + error.diagnostic.render(),
            diagnostic=error.diagnostic,
        )
    except _ProgressiveDeadlineError:
        sanitized_failure = WindowsIdentityProgressiveError(
            "progressive rotation deadline expired")
    except (KeyboardInterrupt, SystemExit, RunInterrupted):
        raise
    except Exception as error:
        # Do not chain backend, generator, or recovery exceptions: any of them
        # could contain a credential value.
        detail = f"progressive rotation failed: {type(error).__name__}"
        if (
            isinstance(error, WindowsIdentityRunError)
            and error.diagnostic is not None
        ):
            detail += "; " + error.diagnostic.render()
        sanitized_failure = WindowsIdentityProgressiveError(
            detail,
            diagnostic=(
                error.diagnostic
                if isinstance(error, WindowsIdentityRunError)
                else None
            ),
        )
    if sanitized_failure is not None:
        raise sanitized_failure from None

    return ProgressiveRotationReceipt(
        phases=tuple(phases),
        publication_destroyed=True,
        replacement_sign_in_proved=True,
    )
