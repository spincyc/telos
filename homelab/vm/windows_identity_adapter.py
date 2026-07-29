#!/usr/bin/env python3
"""Concrete, fail-closed adapters for native Windows identity acceptance."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from contextlib import contextmanager
from pathlib import Path
import os
import socket
import stat
import time
import uuid

from .controller_join_material import ControllerJoinResult, ControllerJoinSerial
from .controller_factory import FactorySpec
from .controller_auth_diagnostic import (
    ControllerAuthCollection,
    ControllerAuthCleanup,
    ControllerAuthDiagnosticError,
    ControllerAuthDiagnosticSession,
    ControllerAuthExpectation,
    ControllerAuthResult,
)
from .controller_principals import (
    ControllerPrincipalResult,
    ControllerPrincipalSerial,
)
from .serial_automation import SerialAutomation
from .simulated_gateway import LEASE_IP
from .signal_cleanup import RunInterrupted
from .windows_control_serial import (
    MAX_RECORD_BYTES,
    WindowsControlSerialError,
    WindowsGuestProbeError,
    control_probe,
    parse_probe_launcher,
    parse_probe_record,
    parse_probe_start,
)
from .windows_credential_action_iso import (
    CredentialActionMediaChannel,
    DuplexCredentialActionSerial,
    build_credential_action_iso,
    execute_credential_action,
)
from .windows_identity_orchestrator import AcceptanceCallbacks
from .windows_identity_progressive import (
    ProgressiveRotationPlan,
    _GuiInteraction,
    _load_references,
    _private_evidence_root,
    WindowsIdentityGuiAlternateState,
    WindowsIdentityGuiNearReference,
)
from .windows_gui import (
    SAFE_KEYS,
    crop_image,
    image_distance,
    read_ppm,
    useful_frame,
)
from .windows_identity_run import (
    IdentityFailureDiagnostic,
    NativeProcessBoundary,
    WindowsLocalReauthenticationError,
    WindowsIdentityRunError,
)
from .windows_identity_reference import load_identity_reference
from .windows_join_iso import DuplexJoinSerial
from .windows_public_command import (
    PublicPowerShellLaunchPlan,
    WindowsPublicCommandLauncher,
)
from .windows_postjoin_calibration import (
    PostJoinCalibrationFrame,
    retain_post_join_calibration,
    retain_submit_focus_calibration,
    sample_post_join_calibration,
)
from .windows_postsubmit_diagnostic import (
    PostSubmitDiagnosticCleanup,
    PostSubmitDiagnosticCode,
    PostSubmitDiagnosticCollection,
)


class WindowsIdentityAdapterError(WindowsIdentityRunError):
    """A required production boundary could not be proved."""


def _run_local_reauthentication_operation(
    operation: str, action: Callable[[], None],
) -> None:
    """Run one private GUI operation without retaining backend exceptions."""
    failure_operation: str | None = None
    try:
        action()
    except (KeyboardInterrupt, SystemExit, RunInterrupted):
        raise
    except BaseException as error:
        post_submit_diagnostic = (
            error.post_submit_diagnostic
            if type(error) is WindowsLocalReauthenticationError
            else None
        )
        post_submit_collection = (
            error.post_submit_collection
            if type(error) is WindowsLocalReauthenticationError
            else None
        )
        post_submit_cleanup = (
            error.post_submit_cleanup
            if type(error) is WindowsLocalReauthenticationError
            else None
        )
        controller_auth_result = (
            error.controller_auth_result
            if type(error) is WindowsLocalReauthenticationError
            else None
        )
        failure_operation = (
            error.reauth_operation
            if (
                type(error) is WindowsLocalReauthenticationError
                and error.reauth_operation
                in WindowsLocalReauthenticationError._OPERATIONS
            )
            else operation
        )
    if failure_operation is not None:
        raise WindowsLocalReauthenticationError(
            failure_operation,
            post_submit_diagnostic=post_submit_diagnostic,
            post_submit_collection=post_submit_collection,
            post_submit_cleanup=post_submit_cleanup,
            controller_auth_result=controller_auth_result,
        ) from None


def _with_controller_auth_result(
    error: WindowsLocalReauthenticationError,
    controller_auth_result: ControllerAuthResult | None,
) -> WindowsLocalReauthenticationError:
    """Copy a safe GUI coordinate after the Controller cleanup converges."""
    return WindowsLocalReauthenticationError(
        error.reauth_operation,
        post_submit_diagnostic=error.post_submit_diagnostic,
        post_submit_collection=error.post_submit_collection,
        post_submit_cleanup=error.post_submit_cleanup,
        controller_auth_result=(
            controller_auth_result
            if controller_auth_result is not None
            else error.controller_auth_result
        ),
    )


_ACTIONS = {
    "windows-standard-online": "connected-domain-login",
    "windows-daily-admin": "operator-local-administrators-check",
    "windows-cached-login": "cached-domain-login",
    "windows-cached-admin-login": "cached-domain-login",
    "windows-uncached-denied": "uncached-domain-user-denied",
    "windows-local-rescue": "local-rescue-login",
    "gateway-offline": "connected-domain-login",
    "update-source-offline": "connected-domain-login",
    "optional-storage-offline": "connected-domain-login",
    "optional-storage-access-denied": "connected-domain-login",
    "ad-dns-offline": "cached-domain-login",
    "combined-dependencies-offline": "cached-domain-login",
}


def _prove_secret_entry_departure(
    qmp,
    evidence: Path,
    reference,
    *,
    timeout: float,
    clock: Callable[[], float],
    pause: Callable[[float], None] = time.sleep,
) -> None:
    """Ephemerally prove two frames departed the empty password target."""
    deadline = clock() + timeout
    consecutive = 0
    previous = None
    while clock() < deadline:
        path = evidence / f".secret-entry-{uuid.uuid4().hex}.ppm"
        try:
            qmp.screenshot(path)
            os.chmod(path, 0o600)
            full_actual = read_ppm(path)
            if (
                (full_actual.width, full_actual.height)
                != reference.geometry
            ):
                raise WindowsIdentityAdapterError(
                    "post-secret screenshot geometry differs from reference")
            actual = crop_image(full_actual, reference.crop)
            departed = (
                useful_frame(actual)
                and image_distance(actual, reference.image) > 6.0
            )
        finally:
            path.unlink(missing_ok=True)
        if departed:
            if previous is not None and image_distance(
                    actual, previous) <= 6.0:
                consecutive += 1
            else:
                consecutive = 1
            previous = actual
            if consecutive == 2:
                del full_actual, actual, previous
                return
        else:
            consecutive = 0
            previous = None
        del full_actual, actual
        remaining = deadline - clock()
        if remaining <= 0:
            break
        pause(min(0.5, remaining))
    raise WindowsIdentityAdapterError(
        "post-secret password-target departure was not proved")


class _LeasedSerial:
    """Release one adapter COM1 lease when the underlying session closes."""

    def __init__(self, serial, release: Callable[[], None]) -> None:
        self._serial = serial
        self._release = release
        self._released = False

    def __getattr__(self, name: str):
        return getattr(self._serial, name)

    @property
    def closed(self) -> bool:
        return self._released or bool(self._serial.closed)

    def close(self) -> None:
        if self._released:
            return
        try:
            self._serial.close()
        finally:
            self._released = True
            self._release()


class NativeWindowsAcceptanceAdapter:
    """Bind the strict callback contract to one live native process boundary."""

    def __init__(
        self,
        boundary: NativeProcessBoundary,
        private_root: Path,
        *,
        realm: str,
        local_principal: str,
        scan_secrets: Callable[
            [tuple[str, ...]], Mapping[str, object]
        ],
        rotation_plan: ProgressiveRotationPlan | None = None,
        command_plan: PublicPowerShellLaunchPlan | None = None,
        post_submit_diagnostic: Callable[..., object] | None = None,
        timeout: float = 120.0,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self.boundary = boundary
        self.private_root = Path(private_root).absolute()
        self.realm = realm.upper()
        self.local_principal = local_principal
        self.local_identity = f"TELOS-WIN-01\\{local_principal}"
        self.scan_secrets = scan_secrets
        self.rotation_plan = rotation_plan
        self.command_plan = command_plan
        self.post_submit_diagnostic = post_submit_diagnostic
        self.timeout = timeout
        self.clock = clock
        self._principal_serial: ControllerPrincipalSerial | None = None
        self._join_material_serial: ControllerJoinSerial | None = None
        self._controller_console: SerialAutomation | None = None
        self._com1_owned = False
        self._static_probe_poisoned = False
        self._post_submit_diagnostic_code: object | None = None
        self._post_submit_diagnostic_collection: object | None = None
        self._post_submit_diagnostic_cleanup: object | None = None
        self._controller_auth_result: ControllerAuthResult | None = None
        self._audit_configuration()

    @property
    def controller_auth_result(self) -> ControllerAuthResult | None:
        """Return supplemental Controller context without changing authority."""
        return self._controller_auth_result

    def _audit_configuration(self) -> None:
        root = self.private_root
        if (
            root.is_symlink()
            or not root.is_dir()
            or stat.S_IMODE(root.stat().st_mode) != 0o700
        ):
            raise WindowsIdentityAdapterError(
                "adapter private root must be a real mode-0700 directory")
        if (
            not isinstance(self.realm, str)
            or not self.realm
            or any(
                not component
                or not component.replace("-", "").isalnum()
                for component in self.realm.split(".")
            )
        ):
            raise WindowsIdentityAdapterError("adapter realm is invalid")
        for value in (self.local_principal, self.local_identity):
            if (
                not isinstance(value, str)
                or not value
                or len(value) > 256
                or any(character in value for character in "\r\n\x00")
            ):
                raise WindowsIdentityAdapterError(
                    "adapter local identity is invalid")
        if not 0 < self.timeout <= 300:
            raise WindowsIdentityAdapterError("adapter timeout is invalid")

    def _qmp(self):
        process = self.boundary.processes.get("windows")
        if (
            process is None
            or process.poll() is not None
            or self.boundary.qmp is None
        ):
            raise WindowsIdentityAdapterError(
                "authenticated live Windows QMP is unavailable")
        return self.boundary.qmp

    def _serial_socket(self) -> Path:
        path = self.boundary.serial_socket
        if path is None:
            raise WindowsIdentityAdapterError(
                "private Windows serial socket is unavailable")
        path = Path(path).absolute()
        parent = path.parent
        try:
            parent_info = parent.lstat()
            socket_info = path.lstat()
        except OSError as error:
            raise WindowsIdentityAdapterError(
                "private Windows serial socket is unavailable") from error
        if (
            stat.S_ISLNK(parent_info.st_mode)
            or not stat.S_ISDIR(parent_info.st_mode)
            or stat.S_IMODE(parent_info.st_mode) != 0o700
            or stat.S_ISLNK(socket_info.st_mode)
            or not stat.S_ISSOCK(socket_info.st_mode)
        ):
            raise WindowsIdentityAdapterError(
                "Windows serial transport is not a private Unix socket")
        return path

    def _claim_com1(self) -> None:
        if self._com1_owned:
            raise WindowsIdentityAdapterError(
                "Windows COM1 already has an exclusive owner")
        self._com1_owned = True

    def _release_com1(self) -> None:
        if not self._com1_owned:
            raise WindowsIdentityAdapterError(
                "Windows COM1 ownership state is invalid")
        self._com1_owned = False

    @contextmanager
    def _com1(self):
        self._claim_com1()
        try:
            yield
        finally:
            self._release_com1()

    def launch_guest(self, command: str) -> None:
        plan = self.command_plan
        if plan is None:
            raise WindowsIdentityAdapterError(
                "calibrated Windows Run-dialog launch is unavailable")
        evidence = self.private_root / "public-command-evidence"
        if not evidence.exists():
            evidence.mkdir(mode=0o700)
        try:
            WindowsPublicCommandLauncher(
                self._qmp(), evidence,
            ).launch(command, plan)
        except Exception as error:
            raise WindowsIdentityAdapterError(
                "calibrated public guest command launch failed: "
                f"{type(error).__name__}") from None

    def await_device_deleted(self, device: str) -> None:
        """Await the exact correlated QMP deletion event."""
        if (
            not isinstance(device, str)
            or not device
            or any(character not in
                   "abcdefghijklmnopqrstuvwxyz0123456789-_."
                   for character in device)
        ):
            raise WindowsIdentityAdapterError("QEMU device id is invalid")
        qmp = self._qmp()
        await_deleted = getattr(qmp, "await_device_deleted", None)
        if not callable(await_deleted):
            raise WindowsIdentityAdapterError(
                "QMP deletion-event boundary is unavailable")
        event = await_deleted(device, timeout=min(self.timeout, 30.0))
        if (
            not isinstance(event, Mapping)
            or event.get("event") != "DEVICE_DELETED"
            or not isinstance(event.get("data"), Mapping)
            or event["data"].get("device") != device
        ):
            raise WindowsIdentityAdapterError(
                "QMP deletion event is invalid")

    def open_join_serial(self) -> DuplexJoinSerial:
        self._claim_com1()
        try:
            serial = DuplexJoinSerial.connect(
                self._serial_socket(), timeout=self.timeout)
        except BaseException:
            self._release_com1()
            raise
        return _LeasedSerial(serial, self._release_com1)  # type: ignore[return-value]

    def reauthenticate_local(self, credential: str) -> None:
        """Re-establish only the exact calibrated local-account session."""
        self._reauthenticate(
            f".\\{self.local_principal}", credential, domain_operator=False)

    def reauthenticate_domain_operator(
        self, principal: str, credential: str, diagnostic_nonce: str,
    ) -> None:
        """Re-establish the exact staged domain-operator session."""
        if principal != f"operator@{self.realm}":
            raise WindowsLocalReauthenticationError(
                "prove-password-target")
        self._reauthenticate(
            principal,
            credential,
            domain_operator=True,
            diagnostic_nonce=diagnostic_nonce,
        )

    def _reauthenticate(
        self,
        principal: str,
        credential: str,
        *,
        domain_operator: bool,
        diagnostic_nonce: str | None = None,
    ) -> None:
        plan = self.rotation_plan
        if plan is None:
            raise WindowsLocalReauthenticationError(
                "prove-password-target")
        try:
            calibration_value = (
                plan.post_join_operator_account_calibrated
                if domain_operator
                else plan.post_join_local_account_calibrated
            )
            selection_calibrated = bool(calibration_value)
            if type(calibration_value) is not bool:
                raise TypeError
        except (KeyboardInterrupt, SystemExit, RunInterrupted):
            raise
        except BaseException:
            raise WindowsLocalReauthenticationError(
                "select-local-account") from None
        deadline = self.clock() + self.timeout

        def remaining(operation: str) -> float:
            budget = deadline - self.clock()
            if budget <= 0:
                raise WindowsLocalReauthenticationError(operation)
            return budget

        reference_failure = False
        try:
            references = _load_references(plan)
            manifest = (
                plan.post_join_operator_sign_in_manifest
                if domain_operator
                else plan.post_join_sign_in_manifest
            )
            if selection_calibrated and manifest is not None:
                references = (
                    load_identity_reference(
                        manifest,
                        expected_guest=plan.expected_guest,
                    ),
                    *references[1:],
                )
        except (KeyboardInterrupt, SystemExit, RunInterrupted):
            raise
        except BaseException:
            reference_failure = True
        if reference_failure:
            raise WindowsLocalReauthenticationError(
                "prove-password-target") from None
        try:
            sign_in, desktop = references[:2]
            reference_valid = not selection_calibrated or (
                sign_in.state_kind == "sign-in"
                and sign_in.state == (
                    "focused password field for domain account "
                    f"{principal}"
                    if domain_operator
                    else "focused password field for local account "
                    f"{self.local_principal}"
                )
            )
        except (KeyboardInterrupt, SystemExit, RunInterrupted):
            raise
        except BaseException:
            reference_valid = False
        if not reference_valid:
            raise WindowsLocalReauthenticationError(
                "prove-password-target") from None
        setup_failure = False
        try:
            evidence = _private_evidence_root(
                self.private_root / "post-join-reauthentication")
            interaction = _GuiInteraction(self._qmp(), evidence)
        except (KeyboardInterrupt, SystemExit, RunInterrupted):
            raise
        except BaseException:
            setup_failure = True
        if setup_failure:
            raise WindowsLocalReauthenticationError(
                "prove-password-target") from None
        selection_failure = False
        try:
            selection_keys = tuple(
                plan.post_join_operator_account_keys
                if domain_operator
                else plan.post_join_local_account_keys
            )
            wake_keys = tuple(plan.wake_after_lock_keys)
            initial_delay = float(plan.initial_sign_in_delay)
            lock_settle_delay = float(plan.lock_settle_delay)
            submit_focus_calibration = (
                getattr(
                    plan,
                    "post_join_operator_submit_focus_calibration",
                    False,
                ) is True
            )
            submit_focus_tabs = (
                getattr(plan, "post_join_operator_submit_focus_tabs", 0)
                if submit_focus_calibration else 0
            )
            submit_focus_authorized = (
                getattr(
                    plan,
                    "post_join_operator_submit_focus_authorized",
                    False,
                ) is True
            )
            submit_focus_reference = (
                getattr(
                    plan,
                    "post_join_operator_submit_focus_reference",
                    None,
                )
                if submit_focus_authorized else None
            )
            if (
                initial_delay < 0
                or lock_settle_delay < 0
                or type(submit_focus_tabs) is not int
                or not 0 <= submit_focus_tabs <= 4
                or (
                    submit_focus_authorized
                    != (submit_focus_reference is not None)
                )
                or (
                    submit_focus_calibration
                    and submit_focus_authorized
                )
                or (submit_focus_authorized and not domain_operator)
                or any(key not in SAFE_KEYS for key in selection_keys)
                or any(key not in SAFE_KEYS for key in wake_keys)
            ):
                selection_failure = True
        except (KeyboardInterrupt, SystemExit, RunInterrupted):
            raise
        except BaseException:
            selection_failure = True
        if selection_failure:
            raise WindowsLocalReauthenticationError(
                "select-local-account") from None

        calibration_baselines: list[PostJoinCalibrationFrame] = []

        def wake() -> None:
            nonlocal deadline
            if initial_delay:
                budget = remaining("wake")
                time.sleep(min(initial_delay, budget))
                remaining("wake")
                deadline = self.clock() + self.timeout
            if not selection_calibrated:
                try:
                    remaining("calibration-capture")
                    calibration_baselines.append(
                        sample_post_join_calibration(self._qmp(), evidence))
                except (KeyboardInterrupt, SystemExit, RunInterrupted):
                    raise
                except BaseException:
                    raise WindowsLocalReauthenticationError(
                        "calibration-capture") from None
            for key in wake_keys:
                interaction.key(key, timeout=remaining("wake"))

        _run_local_reauthentication_operation("wake", wake)

        if calibration_baselines:
            def observe_transition(
                baseline: PostJoinCalibrationFrame,
                state: str,
            ) -> PostJoinCalibrationFrame:
                stable: list[PostJoinCalibrationFrame] = []
                while True:
                    remaining("calibration-capture")
                    candidate = sample_post_join_calibration(
                        self._qmp(), evidence)
                    if (
                        (candidate.image.width, candidate.image.height)
                        == (baseline.image.width, baseline.image.height)
                        and candidate.content != baseline.content
                    ):
                        if (
                            stable
                            and stable[-1].content != candidate.content
                        ):
                            stable.clear()
                        stable.append(candidate)
                        if len(stable) == 3:
                            retain_post_join_calibration(
                                candidate,
                                evidence,
                                plan.expected_guest,
                                state=state,
                                stability_samples=3,
                            )
                            return candidate
                    else:
                        stable.clear()
                    budget = remaining("calibration-capture")
                    if lock_settle_delay:
                        time.sleep(min(lock_settle_delay, budget))
                        remaining("calibration-capture")

            def capture_calibration() -> None:
                generic = observe_transition(
                    calibration_baselines[0],
                    (
                        "operator-generic-prompt"
                        if domain_operator else "generic-prompt"
                    ),
                )
                remaining("calibration-capture")
                self._qmp().type_text(
                    principal, timeout=remaining("calibration-capture"))
                interaction.key(
                    "tab", timeout=remaining("calibration-capture"))
                observe_transition(
                    generic,
                    (
                        "operator-password-target"
                        if domain_operator else "password-target"
                    ),
                )

            _run_local_reauthentication_operation(
                "calibration-capture", capture_calibration)
            raise WindowsLocalReauthenticationError("calibration-required")

        timeout_failure = False
        try:
            checkpoint_timeout = float(plan.checkpoint_timeout)
            if checkpoint_timeout <= 0:
                timeout_failure = True
        except (KeyboardInterrupt, SystemExit, RunInterrupted):
            raise
        except BaseException:
            timeout_failure = True
        if timeout_failure:
            raise WindowsLocalReauthenticationError(
                "prove-password-target") from None

        def select_local_account() -> None:
            for key in selection_keys:
                interaction.key(
                    key, timeout=remaining("select-local-account"))

        _run_local_reauthentication_operation(
            "select-local-account", select_local_account)
        # The account name is public.  Select it before recovering or typing
        # the private credential, then require the exact local-account
        # password-field reference twice.  A wrong focus therefore fails
        # closed without disclosing the credential.
        def normalize_public_username() -> None:
            interaction.chord(
                "ctrl", "a", timeout=remaining("type-public-username"))
            interaction.key(
                "backspace", timeout=remaining("type-public-username"))
            self._qmp().type_text(
                principal, timeout=remaining("type-public-username"))

        _run_local_reauthentication_operation(
            "type-public-username",
            normalize_public_username,
        )

        def prove_password_target() -> None:
            # QMP acknowledges queued key events before the guest has
            # necessarily consumed them. Give the public UPN the same bounded
            # drain interval used for secret input so Tab cannot overtake the
            # final characters. This remains charged to the single
            # reauthentication deadline.
            if lock_settle_delay:
                budget = remaining("prove-password-target")
                time.sleep(min(lock_settle_delay, budget))
                remaining("prove-password-target")
            interaction.key(
                "tab", timeout=remaining("prove-password-target"))
            interaction.observe(
                sign_in,
                min(checkpoint_timeout, remaining("prove-password-target")),
            )
            interaction.observe(
                sign_in,
                min(checkpoint_timeout, remaining("prove-password-target")),
            )

        _run_local_reauthentication_operation(
            "prove-password-target", prove_password_target)

        if submit_focus_calibration:
            if (
                not domain_operator
                or not selection_calibrated
                or plan.post_join_operator_sign_in_manifest is None
                or not 1 <= submit_focus_tabs <= 4
            ):
                raise WindowsLocalReauthenticationError(
                    "submit-focus-calibration")

            def capture_submit_focus() -> None:
                # This literal is public test material, never a credential.
                self._qmp().type_text(
                    "TelosPublicCalibration1",
                    timeout=remaining("submit-focus-calibration"),
                )
                if lock_settle_delay:
                    budget = remaining("submit-focus-calibration")
                    time.sleep(min(lock_settle_delay, budget))
                    remaining("submit-focus-calibration")
                frames: list[PostJoinCalibrationFrame] = []
                for _ in range(submit_focus_tabs):
                    interaction.key(
                        "tab",
                        timeout=remaining("submit-focus-calibration"),
                    )
                    stable: list[PostJoinCalibrationFrame] = []
                    while len(stable) < 3:
                        budget = remaining("submit-focus-calibration")
                        if lock_settle_delay:
                            time.sleep(min(lock_settle_delay, budget))
                            remaining("submit-focus-calibration")
                        candidate = sample_post_join_calibration(
                            self._qmp(), evidence)
                        if (
                            stable
                            and stable[-1].content != candidate.content
                        ):
                            stable.clear()
                        stable.append(candidate)
                    frames.append(stable[-1])
                retain_submit_focus_calibration(
                    tuple(frames), evidence, plan.expected_guest)

            _run_local_reauthentication_operation(
                "submit-focus-calibration", capture_submit_focus)
            raise WindowsLocalReauthenticationError("calibration-required")

        def submit_secret() -> None:
            _run_local_reauthentication_operation(
                "type-secret", interaction.disable_durable_capture)
            _run_local_reauthentication_operation(
                "type-secret", lambda: interaction.type_secret(
                    credential, timeout=remaining("type-secret")))
            _run_local_reauthentication_operation(
                "type-secret",
                lambda: _prove_secret_entry_departure(
                    self._qmp(),
                    evidence,
                    sign_in,
                    timeout=remaining("type-secret"),
                    clock=self.clock,
                ),
            )

            def settle_secret_input() -> None:
                if lock_settle_delay:
                    budget = remaining("submit")
                    time.sleep(min(lock_settle_delay, budget))
                    remaining("submit")

            _run_local_reauthentication_operation(
                "submit", settle_secret_input)
            _run_local_reauthentication_operation(
                "submit",
                lambda: interaction.key(
                    "tab" if submit_focus_authorized else "ret",
                    timeout=remaining("submit"),
                ),
            )
            if submit_focus_authorized:
                # The reviewed, guest-bound production authority is exactly
                # one Tab to the submit arrow followed by one activation.
                # There is deliberately no Enter fallback or retry.
                def settle_submit_focus() -> None:
                    if lock_settle_delay:
                        budget = remaining("submit")
                        time.sleep(min(lock_settle_delay, budget))
                        remaining("submit")

                _run_local_reauthentication_operation(
                    "submit", settle_submit_focus)
                _run_local_reauthentication_operation(
                    "submit",
                    lambda: interaction.key(
                        "ret", timeout=remaining("submit")),
                )

            def settle_submission_input() -> None:
                # QMP acknowledges the Enter key event before Windows has
                # necessarily consumed it.  Let the queued submission drain
                # before releasing the already-armed watcher.  Its baseline
                # predates secret entry, so an event produced during this
                # bounded interval remains in scope.
                if lock_settle_delay:
                    budget = remaining("submit")
                    time.sleep(min(lock_settle_delay, budget))
                    remaining("submit")

            _run_local_reauthentication_operation(
                "submit", settle_submission_input)

        diagnostic_factory = self.post_submit_diagnostic
        self._post_submit_diagnostic_code = None
        self._post_submit_diagnostic_collection = None
        self._post_submit_diagnostic_cleanup = None
        self._controller_auth_result = None
        controller_auth = None
        diagnostic_cleanup_failed = False
        if domain_operator:
            try:
                controller_auth = ControllerAuthDiagnosticSession(
                    self._shared_controller_console(),
                    ControllerAuthExpectation(
                        "operator", FactorySpec().netbios,
                        str(LEASE_IP)),
                    timeout=min(45.0, remaining("diagnostic-arm")),
                )
                controller_auth.arm()
            except (KeyboardInterrupt, SystemExit, RunInterrupted):
                raise
            except ControllerAuthDiagnosticError as error:
                self._controller_auth_result = error.controller_auth_result
                if not error.cleanup_proved:
                    operation = (
                        "controller-auth-arm"
                        if self._controller_auth_result.collection in {
                            ControllerAuthCollection.CONFIGURATION_INVALID,
                            ControllerAuthCollection.SINK_INVALID,
                        }
                        else "diagnostic-arm"
                    )
                    raise WindowsLocalReauthenticationError(
                        operation,
                        controller_auth_result=(
                            self._controller_auth_result)) from None
                controller_auth = None
            except BaseException:
                self._controller_auth_result = ControllerAuthResult(
                    collection=ControllerAuthCollection.RECEIPT_UNAVAILABLE)
                controller_auth = None
        if diagnostic_factory is None or not domain_operator:
            try:
                submit_secret()
                if controller_auth is not None:
                    try:
                        self._controller_auth_result = (
                            controller_auth.submitted())
                    except ControllerAuthDiagnosticError as error:
                        self._controller_auth_result = ControllerAuthResult(
                            collection=(
                                ControllerAuthCollection.RECEIPT_UNAVAILABLE),
                            cleanup=(
                                None if error.cleanup_proved
                                else ControllerAuthCleanup.SINK_ABSENCE_UNPROVED),
                        )
                    except BaseException:
                        self._controller_auth_result = ControllerAuthResult(
                            collection=(
                                ControllerAuthCollection.RECEIPT_UNAVAILABLE),
                            cleanup=ControllerAuthCleanup.SINK_ABSENCE_UNPROVED,
                        )
            except BaseException as error:
                if (
                    controller_auth is not None
                    and controller_auth.armed
                ):
                    try:
                        self._controller_auth_result = (
                            controller_auth.cancel())
                    except ControllerAuthDiagnosticError as cancel_error:
                        self._controller_auth_result = ControllerAuthResult(
                            code=cancel_error.controller_auth_result.code,
                            collection=(
                                cancel_error.controller_auth_result.collection),
                            cleanup=(
                                cancel_error.controller_auth_result.cleanup
                                if cancel_error.cleanup_proved
                                else ControllerAuthCleanup.SINK_ABSENCE_UNPROVED
                            ),
                        )
                    except BaseException:
                        self._controller_auth_result = ControllerAuthResult(
                            collection=(
                                ControllerAuthCollection.RECEIPT_UNAVAILABLE),
                            cleanup=(
                                ControllerAuthCleanup.SINK_ABSENCE_UNPROVED),
                        )
                if type(error) is WindowsLocalReauthenticationError:
                    raise _with_controller_auth_result(
                        error, self._controller_auth_result) from None
                raise
        else:
            manager = None
            session = None
            armed = False
            primary: BaseException | None = None
            with self._com1():
                try:
                    if (
                        not isinstance(diagnostic_nonce, str)
                        or len(diagnostic_nonce) != 32
                        or any(
                            character not in "0123456789abcdef"
                            for character in diagnostic_nonce
                        )
                    ):
                        raise WindowsIdentityAdapterError(
                            "post-submit diagnostic nonce is invalid")
                    manager = diagnostic_factory(
                        nonce=diagnostic_nonce,
                        principal=principal,
                        timeout=min(
                            15.0, remaining("prove-password-target")),
                    )
                    session = manager.__enter__()
                    session.arm()
                    armed = True
                    submit_secret()
                    try:
                        terminal = session.submitted()
                    except (KeyboardInterrupt, SystemExit, RunInterrupted):
                        raise
                    except BaseException:
                        self._post_submit_diagnostic_collection = (
                            PostSubmitDiagnosticCollection.
                            SUBMITTED_RECEIPT_UNAVAILABLE
                        )
                    else:
                        if type(terminal) is PostSubmitDiagnosticCode:
                            self._post_submit_diagnostic_code = terminal
                        else:
                            try:
                                self._post_submit_diagnostic_code = (
                                    session.result())
                            except (
                                KeyboardInterrupt, SystemExit, RunInterrupted,
                            ):
                                raise
                            except BaseException:
                                self._post_submit_diagnostic_collection = (
                                    PostSubmitDiagnosticCollection.
                                    RESULT_RECEIPT_UNAVAILABLE
                                )
                    if controller_auth is not None:
                        try:
                            self._controller_auth_result = (
                                controller_auth.submitted())
                        except (
                            KeyboardInterrupt, SystemExit, RunInterrupted,
                        ):
                            raise
                        except ControllerAuthDiagnosticError as error:
                            self._controller_auth_result = ControllerAuthResult(
                                collection=(
                                    ControllerAuthCollection.
                                    RECEIPT_UNAVAILABLE),
                                cleanup=(
                                    None if error.cleanup_proved
                                    else ControllerAuthCleanup.SINK_ABSENCE_UNPROVED),
                            )
                        except BaseException:
                            self._controller_auth_result = ControllerAuthResult(
                                collection=(
                                    ControllerAuthCollection.
                                    RECEIPT_UNAVAILABLE),
                                cleanup=(
                                    ControllerAuthCleanup.SINK_ABSENCE_UNPROVED),
                            )
                except (KeyboardInterrupt, SystemExit, RunInterrupted):
                    raise
                except BaseException as error:
                    primary = error
                finally:
                    if (
                        controller_auth is not None
                        and controller_auth.armed
                    ):
                        try:
                            self._controller_auth_result = (
                                controller_auth.cancel())
                        except (
                            KeyboardInterrupt, SystemExit, RunInterrupted,
                        ):
                            raise
                        except ControllerAuthDiagnosticError as error:
                            self._controller_auth_result = ControllerAuthResult(
                                code=error.controller_auth_result.code,
                                collection=(
                                    error.controller_auth_result.collection),
                                cleanup=(
                                    error.controller_auth_result.cleanup
                                    if error.cleanup_proved
                                    else (
                                        ControllerAuthCleanup.
                                        SINK_ABSENCE_UNPROVED)
                                ),
                            )
                        except BaseException:
                            self._controller_auth_result = ControllerAuthResult(
                                collection=(
                                    ControllerAuthCollection.
                                    RECEIPT_UNAVAILABLE),
                                cleanup=(
                                    ControllerAuthCleanup.SINK_ABSENCE_UNPROVED),
                            )
                    if manager is not None:
                        try:
                            manager.__exit__(
                                type(primary) if primary is not None else None,
                                primary,
                                primary.__traceback__
                                if primary is not None else None,
                            )
                        except (KeyboardInterrupt, SystemExit, RunInterrupted):
                            raise
                        except BaseException as error:
                            self._static_probe_poisoned = True
                            self._post_submit_diagnostic_cleanup = (
                                PostSubmitDiagnosticCleanup.
                                CLEANUP_RECEIPT_UNAVAILABLE
                            )
                            if primary is None and not armed:
                                primary = error
                            elif armed:
                                diagnostic_cleanup_failed = True
            if primary is not None:
                if not armed:
                    self._static_probe_poisoned = True
                    raise WindowsLocalReauthenticationError(
                        "diagnostic-arm",
                        controller_auth_result=(
                            self._controller_auth_result),
                    ) from None
                if type(primary) is WindowsLocalReauthenticationError:
                    raise _with_controller_auth_result(
                        primary, self._controller_auth_result) from None
                raise primary from None

        def prove_desktop() -> None:
            try:
                interaction.observe_ephemeral(
                    desktop,
                    checkpoint_timeout,
                    alternatives=(("sign-in", sign_in),),
                )
            except WindowsIdentityGuiAlternateState as error:
                if error.state == "sign-in":
                    raise WindowsLocalReauthenticationError(
                        "desktop-sign-in-persisted",
                        post_submit_diagnostic=(
                            self._post_submit_diagnostic_code),
                        post_submit_collection=(
                            self._post_submit_diagnostic_collection),
                        post_submit_cleanup=(
                            self._post_submit_diagnostic_cleanup),
                        controller_auth_result=self._controller_auth_result,
                    ) from None
                raise
            except WindowsIdentityGuiNearReference as error:
                if error.state == "desktop":
                    raise WindowsLocalReauthenticationError(
                        "desktop-near-reference",
                        post_submit_diagnostic=(
                            self._post_submit_diagnostic_code),
                        post_submit_collection=(
                            self._post_submit_diagnostic_collection),
                        post_submit_cleanup=(
                            self._post_submit_diagnostic_cleanup),
                        controller_auth_result=self._controller_auth_result,
                    ) from None
                if error.state == "sign-in":
                    raise WindowsLocalReauthenticationError(
                        "desktop-sign-in-near-reference",
                        post_submit_diagnostic=(
                            self._post_submit_diagnostic_code),
                        post_submit_collection=(
                            self._post_submit_diagnostic_collection),
                        post_submit_cleanup=(
                            self._post_submit_diagnostic_cleanup),
                        controller_auth_result=self._controller_auth_result,
                    ) from None
                raise

        desktop_failure = None
        try:
            _run_local_reauthentication_operation("desktop", prove_desktop)
        except WindowsLocalReauthenticationError as error:
            desktop_failure = error.reauth_operation
        if desktop_failure is not None:
            raise WindowsLocalReauthenticationError(
                desktop_failure,
                post_submit_diagnostic=self._post_submit_diagnostic_code,
                post_submit_collection=(
                    self._post_submit_diagnostic_collection),
                post_submit_cleanup=(
                    self._post_submit_diagnostic_cleanup),
                controller_auth_result=self._controller_auth_result,
            ) from None
        if diagnostic_cleanup_failed:
            raise WindowsLocalReauthenticationError(
                "diagnostic-cleanup",
                post_submit_diagnostic=self._post_submit_diagnostic_code,
                post_submit_collection=(
                    self._post_submit_diagnostic_collection),
                post_submit_cleanup=(
                    self._post_submit_diagnostic_cleanup),
                controller_auth_result=self._controller_auth_result,
            ) from None

    def static_probe(self, action: str) -> Mapping[str, object]:
        if self._static_probe_poisoned:
            raise WindowsIdentityAdapterError(
                "static probe session requires VM teardown")
        request = control_probe(action)
        data = bytearray()
        received = 0
        deadline = self.clock() + self.timeout

        def set_operation_timeout(stream: socket.socket) -> None:
            remaining = deadline - self.clock()
            if remaining <= 0:
                raise TimeoutError("static probe total deadline expired")
            stream.settimeout(remaining)

        def receive_record(stream: socket.socket) -> bytes:
            nonlocal received
            while b"\n" not in data:
                remaining = MAX_RECORD_BYTES - received
                if remaining <= 0:
                    raise WindowsControlSerialError(
                        "probe response exceeds size limit")
                set_operation_timeout(stream)
                chunk = stream.recv(min(4096, remaining))
                if not chunk:
                    raise WindowsControlSerialError(
                        "probe response ended before a complete record")
                data.extend(chunk)
                received += len(chunk)
            newline = data.index(b"\n") + 1
            line = bytes(data[:newline])
            del data[:newline]
            return line

        with self._com1():
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as stream:
                failure: BaseException | None = None
                try:
                    set_operation_timeout(stream)
                    stream.connect(str(self._serial_socket()))
                except Exception as error:
                    failure = error
                if failure is not None:
                    self._raise_static_probe_failure(
                        request.action, "connect", failure)
                failure = None
                try:
                    self.launch_guest(request.command)
                except Exception as error:
                    failure = error
                if failure is not None:
                    self._static_probe_poisoned = True
                    self._raise_static_probe_failure(
                        request.action, "launch", failure)
                failure = None
                try:
                    launcher = receive_record(stream)
                except Exception as error:
                    failure = error
                if failure is not None:
                    self._static_probe_poisoned = True
                    self._raise_static_probe_failure(
                        request.action, "launcher-receive", failure)
                failure = None
                try:
                    parse_probe_launcher(launcher, request.action)
                except Exception as error:
                    failure = error
                if failure is not None:
                    self._static_probe_poisoned = True
                    self._raise_static_probe_failure(
                        request.action, "launcher-parse", failure)
                failure = None
                try:
                    start = receive_record(stream)
                except Exception as error:
                    failure = error
                if failure is not None:
                    self._static_probe_poisoned = True
                    self._raise_static_probe_failure(
                        request.action, "start-receive", failure)
                failure = None
                try:
                    parse_probe_start(start, request.action)
                except Exception as error:
                    failure = error
                if failure is not None:
                    self._static_probe_poisoned = True
                    self._raise_static_probe_failure(
                        request.action, "start-parse", failure)
                failure = None
                try:
                    outcome = receive_record(stream)
                except Exception as error:
                    failure = error
                if failure is not None:
                    self._static_probe_poisoned = True
                    self._raise_static_probe_failure(
                        request.action, "outcome-receive", failure)
        failure = None
        try:
            if data:
                raise WindowsControlSerialError(
                    "probe response contains an extra record")
            return parse_probe_record(outcome, request.action)
        except WindowsGuestProbeError as error:
            failure = error
        except Exception as error:
            failure = error
        if isinstance(failure, WindowsGuestProbeError):
            self._raise_static_probe_failure(
                request.action, "guest", failure)
        if failure is not None:
            self._static_probe_poisoned = True
            self._raise_static_probe_failure(
                request.action, "outcome-parse", failure)
        raise AssertionError("static probe parser returned no result")

    @staticmethod
    def _raise_static_probe_failure(
        action: str, phase: str, error: BaseException,
    ) -> None:
        diagnostic = IdentityFailureDiagnostic.adapter_static_probe(
            action, phase, error)
        failure = WindowsIdentityAdapterError(
            "static probe operation failed; " + diagnostic.render(),
            diagnostic=diagnostic,
        )
        raise failure from None

    def _destroy_unattached_iso(self, iso: Path) -> None:
        """Delete only the exact private regular file created for this action."""
        try:
            info = iso.lstat()
            parent = iso.parent.lstat()
        except FileNotFoundError:
            return
        except OSError as error:
            raise WindowsIdentityAdapterError(
                "private credential media cleanup failed") from error
        if (
            stat.S_ISLNK(info.st_mode)
            or not stat.S_ISREG(info.st_mode)
            or stat.S_IMODE(info.st_mode) != 0o600
            or stat.S_ISLNK(parent.st_mode)
            or not stat.S_ISDIR(parent.st_mode)
            or stat.S_IMODE(parent.st_mode) != 0o700
        ):
            raise WindowsIdentityAdapterError(
                "private credential media cleanup identity changed")
        try:
            iso.unlink()
        except OSError as error:
            raise WindowsIdentityAdapterError(
                "private credential media cleanup failed") from error

    def _expected_principal(self, principal: str, action: str) -> str:
        if action == "local-rescue-login":
            return self.local_identity
        return f"{self.realm.split('.', 1)[0]}\\{principal}"

    def credential_action(
        self, check: str, principal: str, credential: str,
    ) -> Mapping[str, object]:
        try:
            action = _ACTIONS[check]
        except KeyError as error:
            raise WindowsIdentityAdapterError(
                "credential check is not mapped") from error
        if check == "combined-dependencies-offline":
            action = (
                "local-rescue-login"
                if principal == self.local_principal
                else "cached-domain-login"
            )
        nonce = uuid.uuid4().hex
        iso = self.private_root / f"windows-credential-{nonce}.iso"
        domain = "." if action == "local-rescue-login" else self.realm
        qmp = self._qmp()
        self._claim_com1()
        try:
            raw_serial = DuplexCredentialActionSerial.connect(
                self._serial_socket(), timeout=self.timeout)
        except BaseException as error:
            self._release_com1()
            raise WindowsIdentityAdapterError(
                "credential serial acquisition failed: "
                f"{type(error).__name__}") from None
        serial = _LeasedSerial(raw_serial, self._release_com1)
        try:
            try:
                build_credential_action_iso(iso, {
                    "nonce": nonce,
                    "action": action,
                    "username": principal,
                    "domain": domain,
                    "password": credential,
                })
                channel = CredentialActionMediaChannel(qmp, iso, nonce)
            except BaseException as primary:
                cleanup: BaseException | None = None
                try:
                    self._destroy_unattached_iso(iso)
                except BaseException as error:
                    cleanup = error
                serial.close()
                if cleanup is not None:
                    raise WindowsIdentityAdapterError(
                        "credential media creation and cleanup failed: "
                        f"{type(primary).__name__}; "
                        f"{type(cleanup).__name__}") from None
                raise WindowsIdentityAdapterError(
                    "credential media creation failed: "
                    f"{type(primary).__name__}") from None
        except BaseException:
            if not serial.closed:
                serial.close()
            raise
        allowed = (
            frozenset({"NTLM", "Negotiate"})
            if action == "local-rescue-login"
            else frozenset({"Kerberos", "Negotiate", "NTLM"})
        )
        try:
            return execute_credential_action(
                channel=channel,
                serial=serial,
                action=action,
                expected_principal=self._expected_principal(principal, action),
                allowed_authentication_types=allowed,
                launch_guest=self.launch_guest,
                await_device_deleted=self.await_device_deleted,
            )
        finally:
            if not serial.closed:
                serial.close()

    def _controller_streams(self):
        process = self.boundary.processes.get("controller")
        if (
            process is None
            or process.poll() is not None
            or process.stdout is None
            or process.stdin is None
        ):
            raise WindowsIdentityAdapterError(
                "live Controller serial console is unavailable")
        return process.stdout, process.stdin

    def _shared_controller_console(self) -> SerialAutomation:
        if self._controller_console is None:
            console = self.boundary.controller_console
            if console is None:
                raise WindowsIdentityAdapterError(
                    "initialized Controller serial console is unavailable")
            self._controller_console = console
        return self._controller_console

    def stage_principals(
        self, values: dict[str, str],
    ) -> ControllerPrincipalResult:
        reader, writer = self._controller_streams()
        if self._principal_serial is None:
            self._principal_serial = ControllerPrincipalSerial(
                reader, writer, timeout=self.timeout)
            self._principal_serial.console = self._shared_controller_console()
        return self._principal_serial.stage(values)

    def destroy_principals(
        self, names: tuple[str, ...],
    ) -> ControllerPrincipalResult:
        if self._principal_serial is None:
            raise WindowsIdentityAdapterError(
                "Controller principal owner is unavailable")
        return self._principal_serial.destroy(names)

    def stage_join_principal(
        self, credential: str,
    ) -> ControllerJoinResult:
        reader, writer = self._controller_streams()
        if self._join_material_serial is None:
            self._join_material_serial = ControllerJoinSerial(
                reader, writer, timeout=self.timeout)
            self._join_material_serial.console = (
                self._shared_controller_console())
        return self._join_material_serial.stage(credential)

    def destroy_join_principal(self) -> ControllerJoinResult:
        if self._join_material_serial is None:
            raise WindowsIdentityAdapterError(
                "Controller join-principal owner is unavailable")
        return self._join_material_serial.destroy()

    def callbacks(self) -> AcceptanceCallbacks:
        return AcceptanceCallbacks(
            qmp=self._qmp,
            launch_guest=self.launch_guest,
            await_device_deleted=self.await_device_deleted,
            open_join_serial=self.open_join_serial,
            reauthenticate_local=self.reauthenticate_local,
            reauthenticate_domain_operator=(
                self.reauthenticate_domain_operator),
            static_probe=self.static_probe,
            credential_action=self.credential_action,
            scan_secrets=self.scan_secrets,
            local_principal=self.local_principal,
        )
