#!/usr/bin/env python3
"""Production composition root for strict Windows identity acceptance."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Mapping, Protocol
import uuid

from homelab.workstations.windows_identity_acceptance import FIELD_SETS

from .controller_join_material import (
    ControllerJoinMaterialError,
    ControllerJoinResult,
    OneUseDomainJoinMaterial,
)
from .controller_auth_diagnostic import (
    ControllerAuthArmSubphase,
    ControllerAuthCleanup,
    ControllerAuthCode,
    ControllerAuthCollection,
    ControllerAuthReceiveObservation,
    ControllerAuthResult,
)
from .windows_control_serial import ControlProbe
from .windows_identity_evidence import StrictIdentityEvidenceCollector
from .windows_identity_faults import (
    FaultPhaseOperations,
    FaultPhaseReceipt,
    run_fault_phases,
)
from .windows_identity_operations import (
    ProductionIdentityReceipt,
    execute_production_identity_acceptance,
)
from .windows_identity_observations import (
    ObservationRecords,
    WindowsIdentityObservationError,
    map_exact_observation,
)
from .windows_identity_progressive import ProgressiveRotationPlan
from .windows_identity_run import (
    IdentityFailureDiagnostic,
    NativeProcessBoundary,
    WindowsLocalReauthenticationError,
    WindowsIdentityRunError,
)
from .windows_join_iso import (
    DuplexJoinSerial,
    JoinMediaChannel,
    WindowsJoinFailureCoordinate,
    WindowsJoinIsoError,
    build_join_iso,
    execute_join_and_prove,
)
from .windows_postsubmit_diagnostic import PostSubmitDiagnosticCode
from .windows_postsubmit_diagnostic import PostSubmitDiagnosticCollection
from .windows_postsubmit_diagnostic import PostSubmitDiagnosticCleanup


class WindowsIdentityOrchestratorError(WindowsIdentityRunError):
    """The production acceptance composition failed closed."""


class Qmp(Protocol):
    def execute(
        self, command: str, arguments: dict | None = None,
    ) -> Mapping[str, object]: ...


@dataclass(frozen=True)
class AcceptanceCallbacks:
    """Explicit host/guest boundaries required by the production run.

    Semantic interpretation is owned by the built-in exact-source mapper.
    Callbacks can return only strict raw public records, never asserted
    acceptance fields or source labels.
    """

    qmp: Callable[[], Qmp]
    launch_guest: Callable[[str], None]
    await_device_deleted: Callable[[str], None]
    open_join_serial: Callable[[], DuplexJoinSerial]
    reauthenticate_local: Callable[[str], None]
    reauthenticate_domain_operator: Callable[[str, str, str], None]
    static_probe: Callable[[str], Mapping[str, object]]
    credential_action: Callable[
        [str, str, str], Mapping[str, object]
    ]
    scan_secrets: Callable[
        [tuple[str, ...]], Mapping[str, Any]
    ]
    local_principal: str


@dataclass(frozen=True)
class WindowsAcceptanceReceipt:
    """Secret-free result of one fully published 24-check run."""

    production: ProductionIdentityReceipt
    evidence: Path
    checks: int
    dependencies_restored: bool
    join_material_destroyed: bool


_STATIC_ACTIONS = {
    "controller-ready": ("controller-readiness",),
    "windows-joined": "domain-state",
    "windows-standard-online": ("managed-identity-state",),
    "windows-daily-admin": ("managed-identity-state",),
    "domain-admin-separate": ("managed-identity-state",),
    "windows-rebooted-joined": "domain-state",
    "windows-cached-policy": (
        "cached-logon-policy", "managed-identity-state"),
    "controller-offline": "service-reachability",
    "controller-restored": "service-reachability",
    "windows-secure-channel-restored": "domain-state",
    "windows-update-policy": "update-policy",
    "update-source-offline": "dependency-reachability",
    "optional-storage-offline": "dependency-reachability",
    "optional-storage-access-denied": "dependency-reachability",
    "ad-dns-offline": "service-reachability",
    "combined-dependencies-offline": "dependency-reachability",
    "windows-services-restored": (
        "service-reachability", "domain-state",
        "dependency-reachability"),
}

_LOCAL_REAUTH_OPERATIONS = frozenset({
    "wake",
    "calibration-capture",
    "calibration-required",
    "select-local-account",
    "type-public-username",
    "prove-password-target",
    "submit-focus-calibration",
    "controller-auth-arm",
    "diagnostic-arm",
    "diagnostic-arm-preflight",
    "diagnostic-arm-connect",
    "diagnostic-arm-launch",
    "diagnostic-arm-receive",
    "diagnostic-arm-parse",
    "diagnostic-arm-guest",
    "diagnostic-cleanup",
    "type-secret",
    "submit",
    "desktop",
    "desktop-near-reference",
    "desktop-sign-in-persisted",
    "desktop-sign-in-near-reference",
})


def _local_reauthentication_coordinate(
    error: BaseException,
) -> WindowsJoinFailureCoordinate:
    """Totally map only the fixed adapter carrier to a public coordinate."""
    error_type = type(error).__name__
    phase = "reboot-reauth"
    operation: object = None
    post_submit_diagnostic: object = None
    post_submit_collection: object = None
    post_submit_cleanup: object = None
    controller_auth: object = None
    controller_auth_arm_subphase: object = None
    controller_auth_receive_observation: object = None
    if type(error) is WindowsLocalReauthenticationError:
        try:
            operation = error.reauth_operation
            post_submit_diagnostic = error.post_submit_diagnostic
            post_submit_collection = error.post_submit_collection
            post_submit_cleanup = error.post_submit_cleanup
            controller_auth = error.controller_auth_result
            controller_auth_arm_subphase = (
                error.controller_auth_arm_subphase)
            controller_auth_receive_observation = (
                error.controller_auth_receive_observation)
        except BaseException:
            operation = None
            post_submit_diagnostic = None
            post_submit_collection = None
            post_submit_cleanup = None
            controller_auth = None
            controller_auth_arm_subphase = None
            controller_auth_receive_observation = None
    diagnostic_value = (
        post_submit_diagnostic.value
        if type(post_submit_diagnostic) is PostSubmitDiagnosticCode
        else None
    )
    collection_value = (
        post_submit_collection.value
        if type(post_submit_collection) is PostSubmitDiagnosticCollection
        else None
    )
    cleanup_value = (
        post_submit_cleanup.value
        if type(post_submit_cleanup) is PostSubmitDiagnosticCleanup
        else None
    )
    if type(operation) is str and operation in _LOCAL_REAUTH_OPERATIONS:
        phase = f"reboot-reauth-{operation}"
    else:
        operation = None
    allowed_supplemental_phases = {
        "reboot-reauth-desktop",
        "reboot-reauth-diagnostic-cleanup",
        "reboot-reauth-desktop-near-reference",
        "reboot-reauth-desktop-sign-in-persisted",
        "reboot-reauth-desktop-sign-in-near-reference",
    }
    if phase not in allowed_supplemental_phases:
        diagnostic_value = None
        collection_value = None
        cleanup_value = None
    normalized_controller_auth = None
    if (
        phase in {
            "reboot-reauth-controller-auth-arm",
            *allowed_supplemental_phases,
        }
        and type(controller_auth) is ControllerAuthResult
    ):
        try:
            code = controller_auth.code
            collection = controller_auth.collection
            cleanup = controller_auth.cleanup
            if (
                (code is None or type(code) is ControllerAuthCode)
                and (
                    collection is None
                    or type(collection) is ControllerAuthCollection
                )
                and (cleanup is None or type(cleanup) is ControllerAuthCleanup)
            ):
                # Exercise the invariant constructor, while retaining the
                # already-valid immutable carrier for compatibility.
                ControllerAuthResult(
                    code=code, collection=collection, cleanup=cleanup)
                normalized_controller_auth = controller_auth
        except BaseException:
            normalized_controller_auth = None
    if (
        error_type == "WindowsLocalReauthenticationError"
        and not isinstance(error, WindowsLocalReauthenticationError)
    ):
        error_type = "UnexpectedError"
    if error_type not in WindowsJoinFailureCoordinate._ERROR_TYPES:
        error_type = "UnexpectedError"
    normalized_controller_auth_arm_subphase = (
        controller_auth_arm_subphase
        if (
            (
                phase == "reboot-reauth-controller-auth-arm"
                # A proved-cleanup arm failure lets the GUI continue without
                # a watcher; the subphase then explains the unavailable
                # receipt at whichever coordinate the attempt reached.
                # Dropping it here re-blinded attempt nine after the adapter
                # had already preserved it.
                or (
                    normalized_controller_auth is not None
                    and normalized_controller_auth.collection
                    is ControllerAuthCollection.RECEIPT_UNAVAILABLE
                )
            )
            and type(controller_auth_arm_subphase)
            is ControllerAuthArmSubphase
        )
        else None
    )
    normalized_controller_auth_receive_observation = (
        controller_auth_receive_observation
        if (
            normalized_controller_auth_arm_subphase
            is ControllerAuthArmSubphase.RECEIVE
            and type(controller_auth_receive_observation)
            is ControllerAuthReceiveObservation
        )
        else None
    )
    if (
        normalized_controller_auth_arm_subphase
        is ControllerAuthArmSubphase.RECEIVE
        and normalized_controller_auth_receive_observation is None
    ):
        normalized_controller_auth_arm_subphase = None
    return WindowsJoinFailureCoordinate(
        phase, error_type, diagnostic_value, collection_value, cleanup_value,
        normalized_controller_auth, normalized_controller_auth_arm_subphase,
        normalized_controller_auth_receive_observation)


_CREDENTIAL_ROLES = {
    "windows-standard-online": ("student",),
    "windows-daily-admin": ("operator",),
    "windows-cached-login": ("student",),
    "windows-cached-admin-login": ("operator",),
    "windows-uncached-denied": ("directory-admin",),
    "windows-local-rescue": ("local",),
    "gateway-offline": ("student",),
    "update-source-offline": ("student",),
    "optional-storage-offline": ("student",),
    "optional-storage-access-denied": ("student",),
    "ad-dns-offline": ("student",),
    "combined-dependencies-offline": ("student", "local"),
}


def _call_static_probe(
    callbacks: AcceptanceCallbacks, check: str, action: str,
) -> Mapping[str, object]:
    diagnostic: IdentityFailureDiagnostic | None = None
    try:
        record = dict(callbacks.static_probe(action))
    except Exception as error:
        source_diagnostic = (
            error.diagnostic
            if (
                isinstance(error, WindowsIdentityRunError)
                and isinstance(
                    error.diagnostic, IdentityFailureDiagnostic)
            )
            else None
        )
        if source_diagnostic is not None:
            diagnostic = IdentityFailureDiagnostic.rebind_static_probe(
                check, action, source_diagnostic)
        if diagnostic is None:
            diagnostic = IdentityFailureDiagnostic.static_probe(
                check, action, error)
    if diagnostic is not None:
        raise WindowsIdentityOrchestratorError(
            "identity observation operation failed; "
            + diagnostic.render(),
            diagnostic=diagnostic,
        ) from None
    return record


def _validated_static_probes(
    callbacks: AcceptanceCallbacks, check: str,
) -> Mapping[str, Mapping[str, object]] | None:
    configured = _STATIC_ACTIONS.get(check)
    if configured is None:
        return None
    actions = (configured,) if isinstance(configured, str) else configured
    records: dict[str, Mapping[str, object]] = {}
    for action in actions:
        record = _call_static_probe(callbacks, check, action)
        if (
            record.get("schema_version") != 1
            or record.get("action") != action
            or record.get("result") != "pass"
            or not isinstance(record.get("observation"), dict)
        ):
            raise WindowsIdentityOrchestratorError(
                f"{check} static probe record is invalid")
        records[action] = record
    return records


def _credential_contexts(
    callbacks: AcceptanceCallbacks,
    check: str,
    local_credential: str,
    principals: Mapping[str, str],
) -> Mapping[str, Mapping[str, object]] | None:
    roles = _CREDENTIAL_ROLES.get(check)
    if roles is None:
        return None
    results: dict[str, Mapping[str, object]] = {}
    for role in roles:
        if role == "local":
            principal = callbacks.local_principal
            if not isinstance(principal, str) or not principal:
                raise WindowsIdentityOrchestratorError(
                    f"{check} local principal is unavailable")
            credential = local_credential
        else:
            try:
                credential = principals[role]
            except KeyError:
                raise WindowsIdentityOrchestratorError(
                    f"{check} principal credential is unavailable") from None
            principal = role
        result = dict(callbacks.credential_action(
            check, principal, credential))
        action = result.get("action")
        if (
            result.get("schema_version") != 1
            or not isinstance(action, str)
            or action in results
        ):
            raise WindowsIdentityOrchestratorError(
                f"{check} credential action result is invalid")
        results[action] = result
    return results


def _record(
    collector: StrictIdentityEvidenceCollector,
    callbacks: AcceptanceCallbacks,
    check: str,
    *,
    local_credential: str,
    principals: Mapping[str, str],
    join_proof: Mapping[str, object] | None = None,
    fault_record: Mapping[str, object] | None = None,
    diagnostics_scan: Mapping[str, object] | None = None,
) -> None:
    try:
        context = ObservationRecords(
            static_probes=_validated_static_probes(callbacks, check),
            credential_actions=_credential_contexts(
                callbacks, check, local_credential, principals),
            join_proof=join_proof,
            fault_record=fault_record,
            diagnostics_scan=diagnostics_scan,
        )
        try:
            fields = map_exact_observation(check, context)
        except WindowsIdentityObservationError as error:
            raise WindowsIdentityOrchestratorError(
                f"{check} exact observation is invalid: {error}",
                diagnostic=IdentityFailureDiagnostic.acceptance_check(
                    check, "observe", type(error).__name__),
            ) from error
        collector.record(check, fields)
    except (KeyboardInterrupt, SystemExit):
        raise
    except BaseException as error:
        # Attempt 47: a failure at any check between windows-daily-admin and
        # the aggregate collapsed to scoped-acceptance.acceptance because the
        # exception carried no diagnostic. Every acceptance step now names
        # its check. An inner failure that already carries a precise
        # diagnostic (e.g. a credential action's execute coordinate) is
        # preserved; anything else is bound to this check.
        if (
            isinstance(error, WindowsIdentityRunError)
            and isinstance(error.diagnostic, IdentityFailureDiagnostic)
        ):
            raise
        phase = (
            "credential-action"
            if type(error).__name__ in {
                "WindowsCredentialActionError", "WindowsIdentityAdapterError"}
            else "observe"
        )
        raise WindowsIdentityOrchestratorError(
            f"{check} acceptance step failed",
            diagnostic=IdentityFailureDiagnostic.acceptance_check(
                check, phase, type(error).__name__),
        ) from error


def _post_reboot_proof(
    callbacks: AcceptanceCallbacks,
    expected_operator: str,
) -> Mapping[str, object]:
    def stage_record(action: str) -> Mapping[str, object]:
        diagnostic = None
        try:
            record = _call_static_probe(
                callbacks, "windows-rebooted-joined", action)
        except BaseException as error:
            candidate = (
                error.diagnostic
                if (
                    type(error) is WindowsIdentityOrchestratorError
                    and type(error.diagnostic) is IdentityFailureDiagnostic
                    and error.diagnostic.check == "windows-rebooted-joined"
                    and error.diagnostic.operation.startswith(
                        f"static-probe.{action}")
                )
                else None
            )
            diagnostic = (
                candidate
                if candidate is not None
                else IdentityFailureDiagnostic.static_probe(
                    "windows-rebooted-joined",
                    action,
                    error,
                    phase="validate",
                )
            )
        if diagnostic is not None:
            raise WindowsIdentityOrchestratorError(
                f"post-reboot {action} probe failed",
                diagnostic=diagnostic,
            ) from None
        return record

    identity_record = stage_record("interactive-operator")
    validation_diagnostic = None
    try:
        identity = identity_record.get("observation")
        identity_keys = {
            "principal", "principal_sid", "operator", "operator_sid",
            "console_principal", "console_sid", "authenticated",
            "authentication_type", "session_id", "profile_sid",
            "profile_loaded", "local_profile",
        }
        sid_fields = (
            "principal_sid", "operator_sid", "console_sid", "profile_sid")
        expected_account = expected_operator.partition("@")[0]
        invalid_identity = (
            identity_record.get("schema_version") != 1
            or identity_record.get("action") != "interactive-operator"
            or identity_record.get("result") != "pass"
            or type(identity) is not dict
            or set(identity) != identity_keys
            or any(
                type(identity[field]) is not str or not identity[field]
                for field in (
                    "principal", "operator", "console_principal",
                    "authentication_type", *sid_fields,
                )
            )
            or any(
                not identity[field].startswith("S-1-")
                for field in sid_fields
            )
            or type(identity.get("authenticated")) is not bool
            or type(identity.get("profile_loaded")) is not bool
            or type(identity.get("local_profile")) is not bool
            or type(identity.get("session_id")) is not int
            or identity["session_id"] <= 0
            or identity["operator"] != expected_operator
            or (
                identity["principal"].casefold()
                != identity["console_principal"].casefold()
            )
            or (
                identity["principal"].rpartition("\\")[0] == ""
                or identity["principal"].rpartition("\\")[2].casefold()
                != expected_account.casefold()
            )
            or len({identity[field] for field in sid_fields}) != 1
            or not identity["authenticated"]
            or not identity["profile_loaded"]
            or not identity["local_profile"]
        )
    except BaseException as error:
        validation_diagnostic = IdentityFailureDiagnostic.static_probe(
            "windows-rebooted-joined",
            "interactive-operator",
            error,
            phase="validate",
        )
    if validation_diagnostic is not None:
        raise WindowsIdentityOrchestratorError(
            "post-reboot interactive operator probe is invalid",
            diagnostic=validation_diagnostic,
        ) from None
    if invalid_identity:
        diagnostic = IdentityFailureDiagnostic.static_probe(
            "windows-rebooted-joined",
            "interactive-operator",
            WindowsIdentityOrchestratorError(
                "post-reboot interactive operator probe is invalid"),
            phase="validate",
        )
        raise WindowsIdentityOrchestratorError(
            "post-reboot interactive operator probe is invalid",
            diagnostic=diagnostic,
        )
    record = stage_record("domain-state")
    validation_diagnostic = None
    try:
        observation = record.get("observation")
        invalid_domain = (
            record.get("schema_version") != 1
            or record.get("action") != "domain-state"
            or record.get("result") != "pass"
            or type(observation) is not dict
            or set(observation) != {
                "part_of_domain", "domain", "secure_channel", "operator",
                "operator_local_administrator",
            }
            or any(
                type(observation[field]) is not bool
                for field in (
                    "part_of_domain", "secure_channel",
                    "operator_local_administrator",
                )
            )
            or any(
                type(observation[field]) is not str
                or not observation[field]
                for field in ("domain", "operator")
            )
        )
    except BaseException as error:
        validation_diagnostic = IdentityFailureDiagnostic.static_probe(
            "windows-rebooted-joined",
            "domain-state",
            error,
            phase="validate",
        )
    if validation_diagnostic is not None:
        raise WindowsIdentityOrchestratorError(
            "post-reboot domain-state probe is invalid",
            diagnostic=validation_diagnostic,
        ) from None
    if invalid_domain:
        diagnostic = IdentityFailureDiagnostic.static_probe(
            "windows-rebooted-joined",
            "domain-state",
            WindowsIdentityOrchestratorError(
                "post-reboot domain-state probe is invalid"),
            phase="validate",
        )
        raise WindowsIdentityOrchestratorError(
            "post-reboot domain-state probe is invalid",
            diagnostic=diagnostic,
        )
    return {
        "schema_version": 2,
        # Receiving the static guest probe after Restart-Computer is the
        # boot-completion observation; this is not caller-supplied data.
        "boot_completed": True,
        "domain_joined": (
            observation["part_of_domain"]
            and observation["secure_channel"]
        ),
        "domain": observation["domain"],
        "operator": observation["operator"],
        "operator_local_administrator":
            observation["operator_local_administrator"],
    }


def _execute_join(
    *,
    realm: str,
    private_root: Path,
    operator_credential: str,
    callbacks: AcceptanceCallbacks,
    stage_join_principal: Callable[[str], ControllerJoinResult],
    destroy_join_principal: Callable[[], ControllerJoinResult],
) -> tuple[Mapping[str, object], bool]:
    owner = OneUseDomainJoinMaterial(
        realm,
        stage=stage_join_principal,
        destroy=destroy_join_principal,
    )
    guest_cleanup_diagnostic: IdentityFailureDiagnostic | None = None

    def guest_failure(
        coordinate: WindowsJoinFailureCoordinate,
        cleanup: WindowsJoinFailureCoordinate | None = None,
    ) -> WindowsIdentityOrchestratorError:
        diagnostic = IdentityFailureDiagnostic.join_guest(
            coordinate.phase,
            coordinate.error_type,
            coordinate.post_submit_diagnostic,
            coordinate.post_submit_collection,
            coordinate.post_submit_cleanup,
            coordinate.controller_auth,
            coordinate.controller_auth_arm_subphase,
            coordinate.controller_auth_receive_observation,
        )
        details = ["domain join guest protocol failed", diagnostic.render()]
        if cleanup is not None:
            cleanup_diagnostic = IdentityFailureDiagnostic.join_guest(
                cleanup.phase, cleanup.error_type)
            details.append("cleanup-" + cleanup_diagnostic.render())
        return WindowsIdentityOrchestratorError(
            "; ".join(details), diagnostic=diagnostic)

    def consume(material: Mapping[str, str]) -> Mapping[str, object]:
        nonlocal guest_cleanup_diagnostic
        nonce = uuid.uuid4().hex
        iso = private_root / f"windows-join-{nonce}.iso"
        try:
            serial = callbacks.open_join_serial()
        except BaseException as error:
            error_type = type(error).__name__
            if error_type not in WindowsJoinFailureCoordinate._ERROR_TYPES:
                error_type = "UnexpectedError"
            raise guest_failure(WindowsJoinFailureCoordinate(
                "serial-connect", error_type)) from None
        try:
            build_join_iso(iso, {
                "nonce": nonce,
                "domain": realm,
                "realm": realm.upper(),
                "username": (
                    f"{material['principal']}@{realm.upper()}"
                ),
                "password": material["credential"],
                "operator": f"operator@{realm.upper()}",
            })
            channel = JoinMediaChannel(callbacks.qmp(), iso, nonce)
        except BaseException as primary:
            serial.close()
            coordinate = (
                primary.coordinate
                if isinstance(primary, WindowsJoinIsoError)
                and primary.coordinate is not None
                else WindowsJoinFailureCoordinate(
                    "prepare",
                    (
                        type(primary).__name__
                        if type(primary).__name__
                        in WindowsJoinFailureCoordinate._ERROR_TYPES
                        else "UnexpectedError"
                    ),
                )
            )
            try:
                if iso.exists() or iso.is_symlink():
                    iso.unlink()
            except BaseException as cleanup:
                cleanup_coordinate = WindowsJoinFailureCoordinate(
                    "cleanup",
                    (
                        type(cleanup).__name__
                        if type(cleanup).__name__
                        in WindowsJoinFailureCoordinate._ERROR_TYPES
                        else "UnexpectedError"
                    ),
                )
                raise guest_failure(
                    coordinate, cleanup_coordinate) from None
            raise guest_failure(coordinate) from None
        reauthentication_attempted = False

        def probe_after_reboot() -> Mapping[str, object]:
            nonlocal reauthentication_attempted
            if reauthentication_attempted:
                raise WindowsIdentityOrchestratorError(
                    "post-reboot operator authentication was already attempted")
            reauthentication_attempted = True
            try:
                callbacks.reauthenticate_domain_operator(
                    f"operator@{realm.upper()}",
                    operator_credential,
                    nonce,
                )
            except BaseException as error:
                raise WindowsJoinIsoError(
                    "post-reboot authentication failed",
                    coordinate=_local_reauthentication_coordinate(error),
                ) from None
            try:
                return _post_reboot_proof(
                    callbacks, f"operator@{realm.upper()}")
            except BaseException as error:
                diagnostic = (
                    error.diagnostic
                    if (
                        type(error) is WindowsIdentityOrchestratorError
                        and type(error.diagnostic)
                        is IdentityFailureDiagnostic
                    )
                    else None
                )
                if diagnostic is not None:
                    raise WindowsJoinIsoError(
                        "post-reboot static probe failed",
                        diagnostic=diagnostic,
                    ) from None
                raise WindowsJoinIsoError(
                    "post-reboot probe failed",
                    coordinate=WindowsJoinFailureCoordinate(
                        "reboot-probe",
                        (
                            type(error).__name__
                            if type(error).__name__
                            in WindowsJoinFailureCoordinate._ERROR_TYPES
                            else "UnexpectedError"
                        ),
                    ),
                ) from None

        try:
            return execute_join_and_prove(
                channel=channel,
                serial=serial,
                launch_guest=callbacks.launch_guest,
                await_device_deleted=callbacks.await_device_deleted,
                probe_after_reboot=probe_after_reboot,
                expected_domain=realm,
            )
        except BaseException as primary:
            serial.close()
            carried_diagnostic = (
                primary.diagnostic
                if (
                    isinstance(primary, WindowsJoinIsoError)
                    and type(primary.diagnostic)
                    is IdentityFailureDiagnostic
                )
                else None
            )
            if carried_diagnostic is not None:
                coordinate = None
            else:
                coordinate = (
                    primary.coordinate
                    if isinstance(primary, WindowsJoinIsoError)
                    and primary.coordinate is not None
                    else WindowsJoinFailureCoordinate(
                        "result", "UnexpectedError")
                )
            try:
                channel.cleanup(
                    await_device_deleted=callbacks.await_device_deleted)
            except BaseException as cleanup:
                cleanup_coordinate = (
                    cleanup.coordinate
                    if isinstance(cleanup, WindowsJoinIsoError)
                    and cleanup.coordinate is not None
                    else WindowsJoinFailureCoordinate(
                        "cleanup", "UnexpectedError")
                )
                if carried_diagnostic is not None:
                    guest_cleanup_diagnostic = (
                        IdentityFailureDiagnostic.join_guest(
                            cleanup_coordinate.phase,
                            cleanup_coordinate.error_type,
                        )
                    )
                    details = [
                        "domain join guest protocol failed",
                        carried_diagnostic.render(),
                        "cleanup-" + guest_cleanup_diagnostic.render(),
                    ]
                    raise WindowsIdentityOrchestratorError(
                        "; ".join(details),
                        diagnostic=carried_diagnostic,
                    ) from None
                assert coordinate is not None
                raise guest_failure(
                    coordinate, cleanup_coordinate) from None
            if carried_diagnostic is not None:
                raise WindowsIdentityOrchestratorError(
                    "domain join guest protocol failed; "
                    + carried_diagnostic.render(),
                    diagnostic=carried_diagnostic,
                ) from None
            assert coordinate is not None
            raise guest_failure(coordinate) from None

    join_failure: ControllerJoinMaterialError | None = None
    try:
        proof, destruction = owner.use(consume)
    except ControllerJoinMaterialError as error:
        carried = getattr(error, "diagnostic", None)
        if type(carried) is IdentityFailureDiagnostic:
            details = [
                "domain join guest protocol failed", carried.render()]
            if guest_cleanup_diagnostic is not None:
                details.append(
                    "cleanup-" + guest_cleanup_diagnostic.render())
            if error.cleanup_coordinate is not None:
                cleanup = error.cleanup_coordinate
                cleanup_diagnostic = IdentityFailureDiagnostic.join_material(
                    cleanup.operation, cleanup.phase, cleanup.error_type)
                details.append("cleanup-" + cleanup_diagnostic.render())
            raise WindowsIdentityOrchestratorError(
                "; ".join(details),
                diagnostic=carried,
            ) from None
        if error.coordinate is None and error.cleanup_coordinate is None:
            raise
        join_failure = error
    if join_failure is not None:
        coordinate = (
            join_failure.coordinate or join_failure.cleanup_coordinate)
        assert coordinate is not None
        diagnostic = IdentityFailureDiagnostic.join_material(
            coordinate.operation, coordinate.phase, coordinate.error_type)
        details = ["domain join material failed", diagnostic.render()]
        if (
            join_failure.cleanup_coordinate is not None
            and join_failure.cleanup_coordinate is not coordinate
        ):
            cleanup = join_failure.cleanup_coordinate
            cleanup_diagnostic = IdentityFailureDiagnostic.join_material(
                cleanup.operation, cleanup.phase, cleanup.error_type)
            details.append("cleanup-" + cleanup_diagnostic.render())
        raise WindowsIdentityOrchestratorError(
            "; ".join(details), diagnostic=diagnostic) from None
    if not destruction.destruction_proved:
        raise WindowsIdentityOrchestratorError(
            "Controller join principal destruction was not proved")
    return proof, True


def _run_acceptance_checks(
    *,
    collector: StrictIdentityEvidenceCollector,
    callbacks: AcceptanceCallbacks,
    boundary: NativeProcessBoundary,
    realm: str,
    private_root: Path,
    local_credential: str,
    principals: Mapping[str, str],
    stage_join_principal: Callable[[str], ControllerJoinResult],
    destroy_join_principal: Callable[[], ControllerJoinResult],
) -> tuple[FaultPhaseReceipt, bool]:
    record = lambda check, **extra: _record(  # noqa: E731
        collector, callbacks, check,
        local_credential=local_credential,
        principals=principals,
        **extra,
    )
    record("controller-ready")
    join_proof, join_destroyed = _execute_join(
        realm=realm,
        private_root=private_root,
        operator_credential=principals["operator"],
        callbacks=callbacks,
        stage_join_principal=stage_join_principal,
        destroy_join_principal=destroy_join_principal,
    )
    record("windows-joined", join_proof=join_proof)
    for check in (
        "windows-standard-online",
        "windows-daily-admin",
        "domain-admin-separate",
    ):
        record(check)
    record("windows-rebooted-joined", join_proof=join_proof)
    record("windows-cached-policy")

    offline: set[str] = set()

    def fault_setter(
        dependency: str, setter: Callable[[bool], None],
    ) -> Callable[[bool], None]:
        def apply(available: bool) -> None:
            setter(available)
            if available:
                offline.discard(dependency)
            else:
                offline.add(dependency)
        return apply

    def fault_observe(check: str) -> None:
        try:
            extra: dict[str, object] = {"fault_record": {
                "schema_version": 1,
                "check": check,
                "offline_dependencies": sorted(offline),
            }}
            if check == "update-source-offline":
                extra["diagnostics_scan"] = callbacks.scan_secrets(
                    (local_credential, *principals.values()))
            record(check, **extra)
            if check == "windows-secure-channel-restored":
                record("windows-update-policy")
        except (KeyboardInterrupt, SystemExit):
            raise
        except BaseException as error:
            # The progressive sanitizer severs the cause chain (raise ... from
            # None), so this is the last point the raising exception's own
            # message is reachable. Stash it on the collector so the outer
            # progress write preserves it instead of overwriting with the
            # sanitized coordinate (attempts 58-60 kept only the wrapper).
            try:
                collector.note_failure_detail(
                    f"{type(error).__name__}: {error}")
            except BaseException:
                pass
            # `record` already binds an acceptance_check coordinate to every
            # failure it raises. The one step that ran OUTSIDE that binding
            # was the update-source-offline secret scan: its host-side
            # failure (attempt 51 -- WindowsIdentityFactoryError) carried no
            # diagnostic, so run_fault_phases re-wrapped a diagnostic-less
            # FaultPhaseError and the whole stream collapsed to the generic
            # scoped-acceptance.acceptance/FaultPhaseError coordinate. Bind
            # any diagnostic-less fault observation to its exact check so the
            # coordinate names the check, its phase, and the real exception
            # type; an inner failure that already carries a precise
            # diagnostic (a credential action, or the paired
            # windows-update-policy observation) is preserved untouched.
            if (
                isinstance(error, WindowsIdentityRunError)
                and isinstance(error.diagnostic, IdentityFailureDiagnostic)
            ):
                raise
            raise WindowsIdentityOrchestratorError(
                f"{check} fault observation failed",
                diagnostic=IdentityFailureDiagnostic.acceptance_check(
                    check, "observe", type(error).__name__),
            ) from error

    faults = run_fault_phases(FaultPhaseOperations(
        set_controller_available=fault_setter(
            "controller", boundary.set_controller_available),
        set_gateway_available=fault_setter(
            "gateway", boundary.set_gateway_available),
        set_update_source_available=fault_setter(
            "update-source", boundary.set_update_source_available),
        set_optional_storage_available=fault_setter(
            "optional-storage", boundary.set_optional_storage_available),
        observe=fault_observe,
    ))
    try:
        diagnostics_scan = callbacks.scan_secrets(
            (local_credential, *principals.values()))
    except (KeyboardInterrupt, SystemExit):
        raise
    except BaseException as error:
        # The final secret scan runs outside `_record`, so a host-side scan
        # failure would otherwise escape unbound and collapse to
        # scoped-acceptance.acceptance. Name its exact check and the real
        # exception type instead (mirrors fault_observe's binding).
        raise WindowsIdentityOrchestratorError(
            "windows-diagnostics-sanitized secret scan failed",
            diagnostic=IdentityFailureDiagnostic.acceptance_check(
                "windows-diagnostics-sanitized", "observe",
                type(error).__name__),
        ) from error
    record(
        "windows-diagnostics-sanitized",
        diagnostics_scan=diagnostics_scan)
    record("windows-identity-acceptance")
    if collector.next_check is not None:
        raise WindowsIdentityOrchestratorError(
            f"acceptance ended before {collector.next_check}")
    return faults, join_destroyed


def execute_windows_identity_acceptance(
    *,
    boundary: NativeProcessBoundary,
    rotation_plan: ProgressiveRotationPlan,
    publication: Path,
    private_root: Path,
    evidence: Path,
    realm: str,
    callbacks: AcceptanceCallbacks,
    stage_principals: Callable[[dict[str, str]], None],
    destroy_principals: Callable[[tuple[str, ...]], None],
    stage_join_principal: Callable[[str], ControllerJoinResult],
    destroy_join_principal: Callable[[], ControllerJoinResult],
) -> WindowsAcceptanceReceipt:
    """Rotate credentials, execute 24 observations, then publish exactly once.

    The destination is not published unless rotation, one-use join material,
    every credential action, every fault restoration, the secret scan, and
    the strict 24-event judge all succeed.
    """
    evidence = Path(evidence).absolute()
    if evidence.exists() or evidence.is_symlink():
        raise WindowsIdentityOrchestratorError(
            "acceptance evidence destination must be absent")
    collector: StrictIdentityEvidenceCollector | None = None
    faults: FaultPhaseReceipt | None = None
    join_destroyed = False

    def acceptance(
        local_credential: str, principals: Mapping[str, str],
    ) -> None:
        nonlocal collector, faults, join_destroyed
        collector = StrictIdentityEvidenceCollector(
            evidence,
            known_secrets=(local_credential, *principals.values()),
        )
        faults, join_destroyed = _run_acceptance_checks(
            collector=collector,
            callbacks=callbacks,
            boundary=boundary,
            realm=realm,
            private_root=Path(private_root),
            local_credential=local_credential,
            principals=principals,
            stage_join_principal=stage_join_principal,
            destroy_join_principal=destroy_join_principal,
        )

    progress_path = Path(private_root) / "acceptance-progress.json"
    try:
        production = execute_production_identity_acceptance(
            boundary=boundary,
            plan=rotation_plan,
            publication=publication,
            private_parent=private_root,
            stage_principals=stage_principals,
            destroy_principals=destroy_principals,
            run_acceptance=acceptance,
        )
    except BaseException:
        # Persist how far acceptance got before the raise (public check
        # names/counts only) so a failure deep in the 24-check stream is no
        # longer blind between check 4 and the aggregate (attempt 47). Pass no
        # explicit detail: the top-level error is the sanitized coordinate and
        # its cause chain is severed, so the real message is the one
        # fault_observe already stashed on the collector (which write_progress
        # falls back to). Passing the sanitized text here would override it.
        if collector is not None:
            collector.write_progress(progress_path)
        raise
    if collector is not None:
        collector.write_progress(progress_path)
    if (
        collector is None
        or faults is None
        or not faults.all_dependencies_restored
        or not join_destroyed
    ):
        raise WindowsIdentityOrchestratorError(
            "production acceptance returned without complete proof")
    # Publishing is deliberately outside the credential/principal owner. A
    # principal-destruction or credential-release failure in the production
    # composition therefore leaves the destination absent.
    collector.publish()
    return WindowsAcceptanceReceipt(
        production=production,
        evidence=evidence,
        checks=len(FIELD_SETS),
        dependencies_restored=True,
        join_material_destroyed=True,
    )
