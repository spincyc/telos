#!/usr/bin/env python3
"""Concrete, fail-closed adapters for native Windows identity acceptance."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from contextlib import contextmanager
from pathlib import Path
import json
import os
import socket
import stat
import time
import uuid

from .controller_join_material import ControllerJoinResult, ControllerJoinSerial
from .controller_factory import FactorySpec
from .controller_auth_diagnostic import (
    ControllerAuthArmSubphase,
    ControllerAuthCollection,
    ControllerAuthCleanup,
    ControllerAuthDiagnosticError,
    ControllerAuthDiagnosticSession,
    ControllerAuthExpectation,
    ControllerAuthReceiveObservation,
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
    WindowsPublicCommandError,
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
    PostSubmitDiagnosticError,
)

CONTROLLER_AUTH_TIMEOUT_SECONDS = 60.0
# The armed window must cover everything between arming the Controller
# watcher and sending the submit fence: guest diagnostic arm, secret typing,
# departure proof, and the settle drains. At 60 it was shorter than that
# phase, so every attempt expired the window and recorded
# receipt-unavailable before the Controller was ever asked. min() against
# the adapter timeout still binds this to the GUI reauthentication budget.
CONTROLLER_AUTH_POST_ARM_TIMEOUT_SECONDS = 240.0

# Candidate-(b) gate-6 fix. The calibrated post-join sign-in crop is an
# account-tile region whose bottom edge bisects the secret-entry row: the
# tracked reference image (post-join-operator-sign-in.ppm, crop
# 460,150,360,360 on 1280x800) shows the "Password" hint truncated at its
# last rows. More than 90% of that crop is static avatar/username content,
# so 32 masked dots move the crop's mean RGB distance by only ~1-2 units --
# below the 6.0 departure threshold -- and the departure proof loops even
# when the keystrokes land. Departure is therefore proved over a horizontal
# band straddling the crop's bottom edge, which contains the whole
# secret-entry row.
SECRET_ENTRY_BAND_HALF_HEIGHT = 48
# Band frames are compared against a live pre-secret baseline of the same
# band captured just after the SAS re-establishes the form. QEMU screendumps
# are pixel-exact (identical screens give distance 0.0) and a blinking caret
# contributes well under one unit over the band, while masked dots
# contribute several, so a small threshold separates them decisively.
SECRET_ENTRY_BASELINE_DISTANCE = 1.0


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
        controller_auth_arm_subphase = (
            error.controller_auth_arm_subphase
            if type(error) is WindowsLocalReauthenticationError
            else None
        )
        controller_auth_receive_observation = (
            error.controller_auth_receive_observation
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
            controller_auth_arm_subphase=controller_auth_arm_subphase,
            controller_auth_receive_observation=(
                controller_auth_receive_observation),
        ) from None


def _redacted_console_excerpt(console, *, limit: int = 16384) -> bytes | None:
    """Bounded console tail with the session credential removed.

    The Controller-side watcher's crash text exists only on the shared
    console; twelve attempts rendered `command-exit-nonzero` without it.
    """
    try:
        # The transcript survives _wait's match consumption; the working
        # buffer does not (attempt fifteen retained two bytes from it).
        source = getattr(console, "transcript", None)
        if not source:
            source = console.buffer
        data = bytes(source)[-limit:]
    except (AttributeError, TypeError):
        return None
    password = getattr(console, "password", None)
    if isinstance(password, (bytes, bytearray)) and password:
        data = data.replace(bytes(password), b"[REDACTED]")
    return data


def _retain_single_frame(qmp, evidence: Path, name: str, enabled) -> None:
    """Best-effort one-shot frame for submit-transition diagnosis; never raises.

    Gated on the same integer frame-count flag as the post-submit capture so
    the test mock plan (which returns a non-int) skips it.
    """
    if not (type(enabled) is int and enabled > 0):
        return
    try:
        evidence.mkdir(mode=0o700, parents=True, exist_ok=True)
        frame = evidence / f"identity-{name}.ppm"
        qmp.screenshot(frame)
        try:
            frame.chmod(0o600)
        except OSError:
            pass
    except (KeyboardInterrupt, SystemExit, RunInterrupted):
        raise
    except BaseException:
        return


def _retain_credential_channel_state(
    evidence: Path, action: str, channel, error=None,
) -> None:
    """Best-effort media-lifecycle breadcrumb; secret-free; never raises.

    Attempt 37 (20260811T134831Z) could not even prove whether the
    credential ISO had been attached. Attempt 38 then showed the CURRENT
    flags mislead post-release (the release path resets them while tearing
    devices down), so the record also carries the high-water
    `ever_attached` mark and the guest's bounded failure stage/code when
    the typed error names them. Booleans, closed enums and one bounded
    integer only.
    """
    try:
        evidence.mkdir(mode=0o700, parents=True, exist_ok=True)
        guest_stage = getattr(error, "guest_stage", None)
        guest_code = getattr(error, "guest_code", None)
        record = {
            "schema_version": 2,
            "action": action,
            "state": getattr(
                getattr(channel, "state", None), "value", None),
            **{
                name: bool(getattr(channel, name, False))
                for name in (
                    "attached", "ever_attached", "node_added",
                    "parent_added", "child_added", "destroyed",
                )
            },
            "guest_stage": (
                guest_stage
                if isinstance(guest_stage, str) and len(guest_stage) <= 32
                else None
            ),
            "guest_code": (
                guest_code
                if type(guest_code) is int and 0 <= guest_code <= 0xFFFFFFFF
                else None
            ),
            # Attempt 43: the guest emitted a well-formed result the host
            # rejected on some field, with no way to see which. The result
            # line is public token metadata (bounded/redacted upstream), so
            # retaining it names the rejected field on the next run.
            "result_line": (
                result_line
                if isinstance(
                    (result_line := getattr(error, "result_line", None)),
                    str,
                )
                and len(result_line) <= 4096
                else None
            ),
        }
        target = evidence / f"credential-action-{action}-channel.json"
        target.write_text(
            json.dumps(record, sort_keys=True) + "\n", encoding="utf-8")
        target.chmod(0o600)
    except (KeyboardInterrupt, SystemExit, RunInterrupted):
        raise
    except BaseException:
        return


def _retain_post_submit_frames(
    qmp, evidence: Path, clock, *, count: int = 10, interval: float = 1.0,
    name: str = "postsubmit",
) -> None:
    """Best-effort bounded capture of the screen after the logon submit.

    The post-submit surface is otherwise invisible: durable capture is
    disabled before the secret is typed and the desktop proof deletes every
    frame it samples, so a failed operator logon leaves no evidence of
    whether Enter produced a spinner, an on-screen "no logon servers" error,
    or an unchanged sign-in. Secret-safe: the secret-entry departure has
    already been proven, so the password field is masked or cleared and no
    plaintext is ever rendered. Diagnostics must never displace the failure.
    """
    try:
        evidence.mkdir(mode=0o700, parents=True, exist_ok=True)
        deadline = clock() + count * interval
        index = 0
        while index < count and clock() < deadline:
            index += 1
            frame = evidence / f"identity-{name}-{index:04d}.ppm"
            qmp.screenshot(frame)
            try:
                frame.chmod(0o600)
            except OSError:
                pass
            if index < count:
                time.sleep(max(0.0, min(interval, deadline - clock())))
    except (KeyboardInterrupt, SystemExit, RunInterrupted):
        raise
    except BaseException:
        return


def _retain_console_excerpt(console, evidence: Path) -> None:
    """Best-effort retention; diagnostics must never displace the failure."""
    try:
        excerpt = _redacted_console_excerpt(console)
        if excerpt is None:
            return
        evidence.mkdir(mode=0o700, parents=True, exist_ok=True)
        target = evidence / "controller-auth-console.txt"
        target.write_bytes(excerpt)
        target.chmod(0o600)
    except (KeyboardInterrupt, SystemExit, RunInterrupted):
        raise
    except BaseException:
        return


def _with_controller_auth_result(
    error: WindowsLocalReauthenticationError,
    controller_auth_result: ControllerAuthResult | None,
    arm_subphase: "ControllerAuthArmSubphase | None" = None,
    receive_observation: "ControllerAuthReceiveObservation | None" = None,
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
        controller_auth_arm_subphase=(
            error.controller_auth_arm_subphase
            if error.controller_auth_arm_subphase is not None
            else arm_subphase
        ),
        controller_auth_receive_observation=(
            error.controller_auth_receive_observation
            if error.controller_auth_receive_observation is not None
            else receive_observation
        ),
    )


def _exact_controller_auth_result(
    value: object,
) -> ControllerAuthResult:
    """Accept only the immutable, exact Controller result carrier."""
    if type(value) is not ControllerAuthResult:
        raise TypeError("Controller auth result carrier is invalid")
    value._validate()
    return value


def _exact_controller_auth_error_result(
    error: object,
) -> ControllerAuthResult:
    """Validate an exact protocol error and its cleanup assertion together."""
    if type(error) is not ControllerAuthDiagnosticError:
        raise TypeError("Controller auth error carrier is invalid")
    result = _exact_controller_auth_result(error.controller_auth_result)
    if type(error.cleanup_proved) is not bool:
        raise TypeError("Controller auth cleanup proof is invalid")
    if error.cleanup_proved != (result.cleanup is None):
        raise ValueError("Controller auth cleanup proof contradicts result")
    if (
        error.arm_subphase is not None
        and type(error.arm_subphase) is not ControllerAuthArmSubphase
    ):
        raise TypeError("Controller auth arm subphase is invalid")
    if (
        error.arm_subphase is not None
        and result.collection
        is not ControllerAuthCollection.RECEIPT_UNAVAILABLE
    ):
        raise ValueError(
            "Controller auth arm subphase needs unavailable receipt")
    if (
        error.receive_observation is not None
        and type(error.receive_observation)
        is not ControllerAuthReceiveObservation
    ):
        raise TypeError("Controller auth receive observation is invalid")
    if (
        (error.arm_subphase is ControllerAuthArmSubphase.RECEIVE)
        != (error.receive_observation is not None)
    ):
        raise ValueError("Controller auth receive observation is invalid")
    return result


def _diagnostic_arm_failure_operation(
    error: BaseException, *, fallback: str,
) -> str:
    """Return one fixed arm coordinate without consulting exception text."""
    subphase = None
    if type(error) is PostSubmitDiagnosticError:
        try:
            candidate = error.arm_subphase
            if (
                type(candidate) is str
                and candidate in PostSubmitDiagnosticError._ARM_SUBPHASES
            ):
                subphase = candidate
        except BaseException:
            pass
    if subphase is None:
        subphase = fallback if fallback in {"connect", "launch"} else "launch"
    return f"diagnostic-arm-{subphase}"


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


def _secret_entry_band(reference) -> tuple[int, int, int, int]:
    """The secret-entry row derived from the calibrated sign-in crop."""
    x, y, width, height = reference.crop
    _frame_width, frame_height = reference.geometry
    top = max(0, y + height - SECRET_ENTRY_BAND_HALF_HEIGHT)
    bottom = min(frame_height, y + height + SECRET_ENTRY_BAND_HALF_HEIGHT)
    return (x, top, width, bottom - top)


def _capture_secret_entry_baseline(qmp, evidence: Path, reference):
    """Best-effort pre-secret band baseline of the re-established form.

    Captured between the SAS and type_secret, so it can never contain
    secret material, and ephemeral: the staging frame is deleted at once.
    Returns None on any failure so the departure proof falls back to the
    calibrated reference comparison instead of displacing the submission;
    never raises (the _retain_single_frame contract).
    """
    path = evidence / f".secret-baseline-{uuid.uuid4().hex}.ppm"
    try:
        try:
            qmp.screenshot(path)
            os.chmod(path, 0o600)
            full = read_ppm(path)
            if (full.width, full.height) != reference.geometry:
                return None
            return crop_image(full, _secret_entry_band(reference))
        finally:
            path.unlink(missing_ok=True)
    except (KeyboardInterrupt, SystemExit, RunInterrupted):
        raise
    except BaseException:
        return None


def _prove_secret_entry_departure(
    qmp,
    evidence: Path,
    reference,
    *,
    timeout: float,
    clock: Callable[[], float],
    pause: Callable[[float], None] = time.sleep,
    baseline=None,
) -> None:
    """Ephemerally prove two frames departed the empty password target.

    With a band baseline (candidate-(b) gate-6 fix), departure means the
    live secret-entry band visibly changed from its just-captured empty
    state; without one, the legacy comparison against the calibrated crop
    applies.
    """
    deadline = clock() + timeout
    consecutive = 0
    previous = None
    if baseline is None:
        crop = reference.crop
        expected = reference.image
        threshold = 6.0
    else:
        crop = _secret_entry_band(reference)
        expected = baseline
        threshold = SECRET_ENTRY_BASELINE_DISTANCE
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
            actual = crop_image(full_actual, crop)
            departed = (
                useful_frame(actual)
                and image_distance(actual, expected) > threshold
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

    @contextmanager
    def _static_probe_com1(self, action: str):
        failure: BaseException | None = None
        try:
            self._claim_com1()
        except BaseException as error:
            failure = error
        if failure is not None:
            self._raise_static_probe_failure(action, "lease", failure)
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
            # A first logon leaves the Start menu OPEN over the desktop
            # ("Get Started -- Welcome to Windows"): attempt 33's
            # interactive-operator probe failed its desktop proof exactly
            # there, and attempt 32's retained desktop-near frame measures
            # 6.49 (> the 6.0 threshold) against the tracked desktop crop
            # (0,0,360,360) because the menu's left edge crosses x 320-360.
            # One Esc dismisses that transient menu and is a no-op on the
            # clean desktop; nothing is trusted blind, because the launcher
            # still begins with its own two-consecutive-frame desktop proof
            # and fails closed if the surface is anything else.
            self._qmp().key("esc")
            WindowsPublicCommandLauncher(
                self._qmp(), evidence,
            ).launch(command, plan)
        except Exception as error:
            if type(error) is WindowsPublicCommandError:
                # Launcher failures are fixed-format public strings (state
                # label, frame bound, best image distance) that never carry
                # command text or GUI contents. Retaining the message names
                # the failing proof: attempt 33 rendered only the bare type
                # name and lost the decisive `best image distance 6.49`.
                raise WindowsIdentityAdapterError(
                    "calibrated public guest command launch failed: "
                    f"{error}") from None
            raise WindowsIdentityAdapterError(
                "calibrated public guest command launch failed: "
                f"{type(error).__name__}") from None

    def reboot_guest(self) -> None:
        """Cleanly reboot the guest from the operator's session, then wait.

        The operator holds SeShutdownPrivilege even in its non-elevated
        session, so Restart-Computer is a proper clean restart: Windows shuts
        down, boots straight back to sign-in and rejoins the network, instead
        of stopping on the post-crash recovery screen an unclean QMP hard reset
        triggers. The public-command launcher only accepts a PowerShell
        invocation, so the reboot is issued as one; the brief Start-Sleep lets
        the launcher's run-dialog-departed proof settle (a PowerShell window is
        open, the Run box has closed) before the restart begins, and the
        boundary waits on the fresh DHCP transaction the reboot produces.
        """
        self.boundary.reboot_and_await_readiness(
            lambda: self.launch_guest(
                "powershell -NoProfile -Command "
                "\"Start-Sleep -Seconds 8; Restart-Computer -Force\""))

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
        operator_desktop_applied = False
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
            # The tracked desktop reference was calibrated on the LOCAL
            # telosadmin desktop; the operator's first-logon desktop proved
            # near, not exact, against it. Once a reviewed operator-desktop
            # reference is minted from the retained desktop-near frames the
            # plan carries it here and the operator path proves against its
            # own desktop. The strict Path type gate keeps mock plans (whose
            # attributes are Mocks) on the tracked reference.
            operator_desktop_manifest = getattr(
                plan, "post_join_operator_desktop_manifest", None)
            if (
                domain_operator
                and selection_calibrated
                and isinstance(operator_desktop_manifest, Path)
            ):
                references = (
                    references[0],
                    load_identity_reference(
                        operator_desktop_manifest,
                        expected_guest=plan.expected_guest,
                    ),
                    *references[2:],
                )
                operator_desktop_applied = True
        except (KeyboardInterrupt, SystemExit, RunInterrupted):
            raise
        except BaseException:
            reference_failure = True
        if reference_failure:
            raise WindowsLocalReauthenticationError(
                "prove-password-target") from None
        try:
            sign_in, desktop = references[:2]
            reference_valid = (
                not operator_desktop_applied
                or desktop.state_kind == "desktop"
            ) and (
                not selection_calibrated or (
                    sign_in.state_kind == "sign-in"
                    and sign_in.state == (
                        "focused password field for domain account "
                        f"{principal}"
                        if domain_operator
                        else "focused password field for local account "
                        f"{self.local_principal}"
                    )
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

        def reestablish_sign_in_form() -> None:
            # Gate-6 root cause fix. On the domain-operator path the
            # Controller (and, on the diagnostic path, the post-submit
            # diagnostic) arm runs between the initial UPN entry above and
            # the secret submission below. That arm is slow -- tens of
            # seconds of sudo prompt, watcher launch and a multi-phase
            # prearm handshake -- and the Windows "Other user" sign-in form
            # times out back to the lock screen inside that window. The
            # secret and its activation then land on the lock screen, not
            # the form, so no interactive logon ever fires.
            #
            # Instrumented frames (attempt 28) proved the exact recovery:
            # a single Ctrl+Alt+Del (the Secure Attention Sequence a
            # domain-joined lock screen requires) instantly restores the
            # form with the operator UPN still present AND the password
            # field focused and empty. Re-running the full establishment
            # after it was actively harmful -- the extra wake/select/UPN
            # keys typed into the focused password field (garbage dots) and
            # their observe waits took long enough to time the form out
            # again. So do exactly the SAS and nothing else, then let
            # submit_secret type the secret straight into the focused,
            # empty password field.
            #
            # This only restores GUI focus: it does not arm, does not touch
            # the watcher and does not move the submission fence, so the
            # watcher's observation window stays anchored to begin_submission.
            frames_enabled = getattr(
                plan, "post_join_retain_submit_frames", 0)
            _run_local_reauthentication_operation(
                "wake",
                lambda: interaction.chord(
                    "ctrl", "alt", "delete", timeout=remaining("wake")))
            _retain_single_frame(
                self._qmp(), evidence, "reestablish-after-cad",
                frames_enabled)

        def submit_secret() -> None:
            departure_baseline = None
            if domain_operator:
                # The arm(s) above can outlast the sign-in form; re-establish
                # it before the secret is typed. See reestablish_sign_in_form.
                reestablish_sign_in_form()
                # Candidate-(b) gate-6 fix: baseline the departure proof on
                # the live post-SAS secret-entry band instead of the
                # calibrated tile crop, whose static avatar/username content
                # dilutes masked dots below the departure threshold (see
                # SECRET_ENTRY_BAND_HALF_HEIGHT). Pre-secret and ephemeral;
                # None on failure falls back to the legacy comparison.
                departure_baseline = _capture_secret_entry_baseline(
                    self._qmp(), evidence, sign_in)
            _run_local_reauthentication_operation(
                "type-secret", interaction.disable_durable_capture)
            _run_local_reauthentication_operation(
                "type-secret", lambda: interaction.type_secret(
                    credential, timeout=remaining("type-secret")))
            # Secret-safe disambiguation frame captured BEFORE the departure
            # proof. The remaining gate-6 question is whether, after the SAS
            # restores the form, the secret keystrokes land: if this frame
            # already shows masked dots the field is receiving input and a
            # looping departure proof implicates a stale reference crop; if it
            # shows an empty field (or the lock screen) the keystrokes are not
            # landing and the fix is a settle/re-focus before type_secret.
            # Additive instrumentation only: no sleep, no budget draw, no change
            # to the submit sequence. Gated on the integer frame-count flag, so
            # the mock-plan tests skip it exactly like the other retain frames.
            _retain_single_frame(
                self._qmp(), evidence, "after-type-secret",
                getattr(plan, "post_join_retain_submit_frames", 0))
            _run_local_reauthentication_operation(
                "type-secret",
                lambda: _prove_secret_entry_departure(
                    self._qmp(),
                    evidence,
                    sign_in,
                    timeout=remaining("type-secret"),
                    clock=self.clock,
                    baseline=departure_baseline,
                ),
            )

            def settle_secret_input() -> None:
                if lock_settle_delay:
                    budget = remaining("submit")
                    time.sleep(min(lock_settle_delay, budget))
                    remaining("submit")

            _run_local_reauthentication_operation(
                "submit", settle_secret_input)
            # Secret-safe transition capture: the field is masked (dots),
            # not plaintext. Shows whether the password is entered and what
            # the activation does — attempt 22 proved no logon event fires,
            # so the submit itself is the suspect.
            _retain_single_frame(
                self._qmp(), evidence, "submit-pre-activation",
                getattr(plan, "post_join_retain_submit_frames", 0))
            _run_local_reauthentication_operation(
                "submit",
                lambda: interaction.key(
                    "tab" if submit_focus_authorized else "ret",
                    timeout=remaining("submit"),
                ),
            )
            _retain_single_frame(
                self._qmp(), evidence, "submit-post-activation",
                getattr(plan, "post_join_retain_submit_frames", 0))
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
            # Retain the post-submit surface so a failed operator logon is
            # diagnosable. Best-effort and secret-safe; never raises. Gated
            # on an explicit integer frame count so tests (mock plan) skip it.
            retain_frames = getattr(
                plan, "post_join_retain_submit_frames", 0)
            if type(retain_frames) is int and retain_frames > 0:
                _retain_post_submit_frames(
                    self._qmp(), evidence, self.clock, count=retain_frames)

        diagnostic_factory = self.post_submit_diagnostic
        self._post_submit_diagnostic_code = None
        self._post_submit_diagnostic_collection = None
        self._post_submit_diagnostic_cleanup = None
        self._controller_auth_result = None
        self._controller_auth_arm_subphase = None
        self._controller_auth_receive_observation = None
        controller_auth = None
        diagnostic_cleanup_failed = False
        if domain_operator:
            try:
                controller_auth = ControllerAuthDiagnosticSession(
                    self._shared_controller_console(),
                    ControllerAuthExpectation(
                        "operator", FactorySpec().netbios,
                        str(LEASE_IP), realm=self.realm),
                    # Controller pre-arm work is a distinct diagnostic
                    # lifecycle.  Give it one immutable budget rather than
                    # inheriting whatever remains of the GUI
                    # reauthentication deadline.  The GUI deadline remains
                    # immutable and is checked again before any secret can
                    # be submitted.
                    timeout=CONTROLLER_AUTH_TIMEOUT_SECONDS,
                    post_arm_timeout=min(
                        self.timeout,
                        CONTROLLER_AUTH_POST_ARM_TIMEOUT_SECONDS,
                    ),
                    clock=self.clock,
                )
            except (KeyboardInterrupt, SystemExit, RunInterrupted):
                raise
            except ValueError:
                self._controller_auth_result = ControllerAuthResult(
                    collection=ControllerAuthCollection.RECEIPT_UNAVAILABLE)
                raise WindowsLocalReauthenticationError(
                    "controller-auth-arm",
                    controller_auth_result=self._controller_auth_result,
                    controller_auth_arm_subphase=(
                        ControllerAuthArmSubphase.PREFLIGHT),
                ) from None
            except BaseException as error:
                # The session could not be constructed, so nothing was ever
                # armed and no receipt could exist. Recording only
                # receipt-unavailable made that indistinguishable from a
                # diagnostic that ran and stayed silent, which is the fork the
                # no-logon-event boundary needs answered.
                self._controller_auth_result = ControllerAuthResult(
                    collection=ControllerAuthCollection.RECEIPT_UNAVAILABLE,
                    host_error=type(error).__name__,
                )
                controller_auth = None
            try:
                if controller_auth is not None:
                    controller_auth.arm()
                    if controller_auth.armed:
                        # Exact ARMED begins a fresh, bounded GUI/submission
                        # phase.  Pre-arm Controller latency cannot deplete
                        # it, while cancel() owns a separate cleanup reserve.
                        deadline = self.clock() + self.timeout
            except (KeyboardInterrupt, SystemExit, RunInterrupted):
                raise
            except ControllerAuthDiagnosticError as error:
                try:
                    normalized_arm_result = (
                        _exact_controller_auth_error_result(error))
                except (TypeError, ValueError, AttributeError):
                    self._controller_auth_result = ControllerAuthResult(
                        collection=(
                            ControllerAuthCollection.RECEIPT_UNAVAILABLE),
                        cleanup=(
                            ControllerAuthCleanup.SINK_ABSENCE_UNPROVED),
                    )
                    raise WindowsLocalReauthenticationError(
                        "controller-auth-arm",
                        controller_auth_result=self._controller_auth_result,
                        controller_auth_arm_subphase=(
                            ControllerAuthArmSubphase.LAUNCH),
                    ) from None
                self._controller_auth_result = normalized_arm_result
                _retain_console_excerpt(
                    self.boundary.controller_console, evidence)
                if not error.cleanup_proved:
                    raise WindowsLocalReauthenticationError(
                        "controller-auth-arm",
                        controller_auth_result=(
                            self._controller_auth_result),
                        controller_auth_arm_subphase=error.arm_subphase,
                        controller_auth_receive_observation=(
                            error.receive_observation),
                    ) from None
                # The GUI continues without a watcher, so the arm subphase
                # is the only record of why no receipt can ever arrive.
                # Losing it here is what rendered the attempt-eight failure
                # as a bare unattributed receipt.
                self._controller_auth_arm_subphase = error.arm_subphase
                self._controller_auth_receive_observation = (
                    error.receive_observation)
                controller_auth = None
            except BaseException:
                self._controller_auth_result = ControllerAuthResult(
                    collection=ControllerAuthCollection.RECEIPT_UNAVAILABLE,
                    cleanup=ControllerAuthCleanup.SINK_ABSENCE_UNPROVED,
                )
                raise WindowsLocalReauthenticationError(
                    "controller-auth-arm",
                    controller_auth_result=self._controller_auth_result,
                    controller_auth_arm_subphase=(
                        ControllerAuthArmSubphase.LAUNCH),
                ) from None
        if diagnostic_factory is None or not domain_operator:
            try:
                submit_secret()
                if controller_auth is not None:
                    try:
                        controller_auth.begin_submission()
                        self._controller_auth_result = (
                            _exact_controller_auth_result(
                                controller_auth.result()))
                    except (KeyboardInterrupt, SystemExit, RunInterrupted):
                        raise
                    except ControllerAuthDiagnosticError as error:
                        _retain_console_excerpt(
                            self.boundary.controller_console, evidence)
                        try:
                            self._controller_auth_result = (
                                _exact_controller_auth_error_result(error))
                        except (TypeError, ValueError, AttributeError):
                            self._controller_auth_result = ControllerAuthResult(
                                collection=(
                                    ControllerAuthCollection.
                                    RECEIPT_UNAVAILABLE),
                                cleanup=(
                                    ControllerAuthCleanup.
                                    SINK_ABSENCE_UNPROVED),
                            )
                    except BaseException as error:
                        _retain_console_excerpt(
                            self.boundary.controller_console, evidence)
                        self._controller_auth_result = ControllerAuthResult(
                            collection=(
                                ControllerAuthCollection.RECEIPT_UNAVAILABLE),
                            cleanup=ControllerAuthCleanup.SINK_ABSENCE_UNPROVED,
                        )
            except BaseException as error:
                if (
                    controller_auth is not None
                    and controller_auth.active
                ):
                    try:
                        self._controller_auth_result = (
                            _exact_controller_auth_result(
                                controller_auth.cancel()))
                    except ControllerAuthDiagnosticError as cancel_error:
                        self._controller_auth_result = ControllerAuthResult(
                            collection=(
                                ControllerAuthCollection.RECEIPT_UNAVAILABLE),
                            cleanup=(
                                ControllerAuthCleanup.SINK_ABSENCE_UNPROVED),
                        )
                        try:
                            self._controller_auth_result = (
                                _exact_controller_auth_error_result(
                                    cancel_error))
                        except (TypeError, ValueError, AttributeError):
                            pass
                    except BaseException as error:
                        self._controller_auth_result = ControllerAuthResult(
                            collection=(
                                ControllerAuthCollection.RECEIPT_UNAVAILABLE),
                            cleanup=(
                                ControllerAuthCleanup.SINK_ABSENCE_UNPROVED),
                        )
                if type(error) is WindowsLocalReauthenticationError:
                    raise _with_controller_auth_result(
                        error, self._controller_auth_result,
                        self._controller_auth_arm_subphase,
                        self._controller_auth_receive_observation) from None
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
                        raise WindowsLocalReauthenticationError(
                            "diagnostic-arm-preflight")
                    try:
                        manager = diagnostic_factory(
                            nonce=diagnostic_nonce,
                            principal=principal,
                            timeout=min(
                                15.0, remaining("prove-password-target")),
                        )
                    except (KeyboardInterrupt, SystemExit, RunInterrupted):
                        raise
                    except BaseException as error:
                        raise WindowsLocalReauthenticationError(
                            _diagnostic_arm_failure_operation(
                                error, fallback="connect")) from None
                    try:
                        session = manager.__enter__()
                        session.arm()
                    except (KeyboardInterrupt, SystemExit, RunInterrupted):
                        raise
                    except BaseException as error:
                        raise WindowsLocalReauthenticationError(
                            _diagnostic_arm_failure_operation(
                                error, fallback="launch")) from None
                    armed = True
                    submit_secret()
                    if controller_auth is not None:
                        try:
                            controller_auth.begin_submission()
                        except (
                            KeyboardInterrupt, SystemExit, RunInterrupted,
                        ):
                            raise
                        except ControllerAuthDiagnosticError as error:
                            try:
                                self._controller_auth_result = (
                                    _exact_controller_auth_error_result(error))
                            except (TypeError, ValueError, AttributeError):
                                self._controller_auth_result = (
                                    ControllerAuthResult(
                                        collection=(
                                            ControllerAuthCollection.
                                            RECEIPT_UNAVAILABLE),
                                        cleanup=(
                                            ControllerAuthCleanup.
                                            SINK_ABSENCE_UNPROVED),
                                    ))
                            controller_auth = None
                        except BaseException as error:
                            self._controller_auth_result = ControllerAuthResult(
                                collection=(
                                    ControllerAuthCollection.
                                    RECEIPT_UNAVAILABLE),
                                cleanup=(
                                    ControllerAuthCleanup.
                                    SINK_ABSENCE_UNPROVED),
                                host_error=type(error).__name__,
                            )
                            controller_auth = None
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
                                _exact_controller_auth_result(
                                    controller_auth.result()))
                        except (
                            KeyboardInterrupt, SystemExit, RunInterrupted,
                        ):
                            raise
                        except ControllerAuthDiagnosticError as error:
                            _retain_console_excerpt(
                                self.boundary.controller_console, evidence)
                            try:
                                self._controller_auth_result = (
                                    _exact_controller_auth_error_result(error))
                            except (TypeError, ValueError, AttributeError):
                                self._controller_auth_result = (
                                    ControllerAuthResult(
                                        collection=(
                                            ControllerAuthCollection.
                                            RECEIPT_UNAVAILABLE),
                                        cleanup=(
                                            ControllerAuthCleanup.
                                            SINK_ABSENCE_UNPROVED),
                                    ))
                        except BaseException:
                            _retain_console_excerpt(
                                self.boundary.controller_console, evidence)
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
                        and controller_auth.active
                    ):
                        try:
                            self._controller_auth_result = (
                                _exact_controller_auth_result(
                                    controller_auth.cancel()))
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
                                    ControllerAuthCleanup.
                                    SINK_ABSENCE_UNPROVED),
                            )
                            try:
                                self._controller_auth_result = (
                                    _exact_controller_auth_error_result(error))
                            except (TypeError, ValueError, AttributeError):
                                pass
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
                if type(primary) is WindowsLocalReauthenticationError:
                    raise _with_controller_auth_result(
                        primary, self._controller_auth_result,
                        self._controller_auth_arm_subphase,
                        self._controller_auth_receive_observation) from None
                if not armed:
                    self._static_probe_poisoned = True
                    raise WindowsLocalReauthenticationError(
                        "diagnostic-arm",
                        controller_auth_result=(
                            self._controller_auth_result),
                    ) from None
                raise primary from None

        def retain_near_desktop_frames() -> None:
            # Seam-1 evidence (attempt 20260811T111019Z): the operator's
            # first-logon desktop proved near (<= 12.0) but not exact
            # (<= 6.0) against the desktop reference calibrated on the LOCAL
            # telosadmin desktop, so the logon succeeded and the proof still
            # failed. Retain a small bounded set of terminal frames -- the
            # post-logon desktop is secret-free -- so the next attempt can
            # mint a reviewed post-join-operator-desktop reference (see
            # plan.post_join_operator_desktop_manifest) or adjust the crop.
            # Gated on the same integer frame-count flag as every other
            # retention; never raises; never displaces the failure.
            retain_frames = getattr(
                plan, "post_join_retain_submit_frames", 0)
            if (
                domain_operator
                and type(retain_frames) is int
                and retain_frames > 0
            ):
                _retain_post_submit_frames(
                    self._qmp(), evidence, self.clock,
                    count=min(retain_frames, 3),
                    name="desktop-near",
                )

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
                        controller_auth_arm_subphase=(
                            self._controller_auth_arm_subphase),
                        controller_auth_receive_observation=(
                            self._controller_auth_receive_observation),
                    ) from None
                raise
            except WindowsIdentityGuiNearReference as error:
                if error.state in {"desktop", "sign-in"}:
                    retain_near_desktop_frames()
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
                        controller_auth_arm_subphase=(
                            self._controller_auth_arm_subphase),
                        controller_auth_receive_observation=(
                            self._controller_auth_receive_observation),
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
                        controller_auth_arm_subphase=(
                            self._controller_auth_arm_subphase),
                        controller_auth_receive_observation=(
                            self._controller_auth_receive_observation),
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
                controller_auth_arm_subphase=(
                    self._controller_auth_arm_subphase),
                controller_auth_receive_observation=(
                    self._controller_auth_receive_observation),
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
                controller_auth_arm_subphase=(
                    self._controller_auth_arm_subphase),
                controller_auth_receive_observation=(
                    self._controller_auth_receive_observation),
            ) from None

    def static_probe(self, action: str) -> Mapping[str, object]:
        if self._static_probe_poisoned:
            diagnostic = IdentityFailureDiagnostic.adapter_static_probe(
                action,
                "preflight",
                WindowsIdentityAdapterError(
                    "static probe session requires VM teardown"),
            )
            raise WindowsIdentityAdapterError(
                "static probe session requires VM teardown; "
                + diagnostic.render(),
                diagnostic=diagnostic,
            ) from None
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

        with self._static_probe_com1(request.action):
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

    # Actions whose LogonUser reaches the domain controller while it is the
    # SIGSTOP-frozen dependency. A frozen controller VM is a silent black
    # hole (no handshake, no RST), so the guest's interactive logon must wait
    # out the whole DC-locator + Kerberos timeout before falling to the local
    # cache; the guest now bounds that call and always reports, but it needs
    # a longer host serial deadline than the DC-reachable actions do.
    # local-rescue-login is excluded: it authenticates a local account
    # (domain '.') and never touches the controller.
    _DC_OFFLINE_ACTIONS = frozenset({
        "cached-domain-login", "uncached-domain-user-denied",
    })
    # Comfortably above the guest's 180s bounded-logon budget and below the
    # DuplexCredentialActionSerial 300s deadline cap, leaving room for the
    # launch, marker, and media-destruction overhead before the result read.
    _DC_OFFLINE_SERIAL_TIMEOUT = 285.0

    def _credential_serial_timeout(self, action: str) -> float:
        if action in self._DC_OFFLINE_ACTIONS:
            return min(
                300.0, max(self.timeout, self._DC_OFFLINE_SERIAL_TIMEOUT))
        return self.timeout

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
                self._serial_socket(),
                timeout=self._credential_serial_timeout(action))
        except BaseException as error:
            self._release_com1()
            raise WindowsIdentityAdapterError(
                "credential serial acquisition failed: "
                f"{type(error).__name__}",
                diagnostic=IdentityFailureDiagnostic.credential_action(
                    check, action, "serial-connect",
                    type(error).__name__),
            ) from None
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
                        f"{type(cleanup).__name__}",
                        diagnostic=(
                            IdentityFailureDiagnostic.credential_action(
                                check, action, "media",
                                type(primary).__name__)),
                    ) from None
                raise WindowsIdentityAdapterError(
                    "credential media creation failed: "
                    f"{type(primary).__name__}",
                    diagnostic=IdentityFailureDiagnostic.credential_action(
                        check, action, "media", type(primary).__name__),
                ) from None
        except BaseException:
            if not serial.closed:
                serial.close()
            raise
        allowed = (
            frozenset({"NTLM", "Negotiate"})
            if action == "local-rescue-login"
            else frozenset({"Kerberos", "Negotiate", "NTLM"})
        )
        evidence = self.private_root / "credential-action-evidence"
        retain_frames = getattr(
            self.rotation_plan, "post_join_retain_submit_frames", 0)

        def launch_and_witness(command: str) -> None:
            # Attempt 37 (20260811T134831Z) timed out against a CLEAN
            # desktop: by frame time the launcher console was long gone, so
            # "Run dialog executed nothing", "media poll exhausted" and
            # "script died early" were indistinguishable. One early frame a
            # fixed 5 s after the launch shows the launcher console while
            # it polls (or its absence). Secret-free -- the credential
            # travels only on the private ISO, never through the GUI -- and
            # gated on the same integer frame flag as every retention. The
            # fixed sleep is charged against the 120 s serial budget; the
            # guest's own lines buffer in the socket meanwhile.
            self.launch_guest(command)
            if type(retain_frames) is int and retain_frames > 0:
                time.sleep(5.0)
                _retain_single_frame(
                    qmp, evidence,
                    f"credential-action-{action}-launch", retain_frames)

        try:
            return execute_credential_action(
                channel=channel,
                serial=serial,
                action=action,
                expected_principal=self._expected_principal(principal, action),
                allowed_authentication_types=allowed,
                launch_guest=launch_and_witness,
                await_device_deleted=self.await_device_deleted,
            )
        except (KeyboardInterrupt, SystemExit, RunInterrupted):
            raise
        except BaseException as error:
            # Attempt 36's first live connected-domain-login died here and
            # rendered nothing. Name the coordinate, and retain one
            # secret-safe terminal frame plus the media-lifecycle
            # breadcrumb so a silent guest is diagnosable next run. Gated
            # on the same integer frame-count flag as every other
            # retention; never displaces the failure.
            _retain_single_frame(
                qmp,
                evidence,
                f"credential-action-{action}",
                retain_frames,
            )
            _retain_credential_channel_state(
                evidence, action, channel, error=error)
            raise WindowsIdentityAdapterError(
                "credential action execution failed: "
                f"{type(error).__name__}",
                diagnostic=IdentityFailureDiagnostic.credential_action(
                    check, action, "execute", type(error).__name__),
            ) from None
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
            reboot_guest=self.reboot_guest,
            static_probe=self.static_probe,
            credential_action=self.credential_action,
            scan_secrets=self.scan_secrets,
            local_principal=self.local_principal,
        )
