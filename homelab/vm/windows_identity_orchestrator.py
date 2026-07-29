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
    """Map only the fixed adapter carrier to a public reauthentication phase."""
    error_type = type(error).__name__
    phase = "reboot-reauth"
    operation = getattr(error, "reauth_operation", None)
    if (
        isinstance(error, WindowsLocalReauthenticationError)
        and operation in _LOCAL_REAUTH_OPERATIONS
    ):
        phase = f"reboot-reauth-{operation}"
    if (
        error_type == "WindowsLocalReauthenticationError"
        and not isinstance(error, WindowsLocalReauthenticationError)
    ):
        error_type = "UnexpectedError"
    if error_type not in WindowsJoinFailureCoordinate._ERROR_TYPES:
        error_type = "UnexpectedError"
    return WindowsJoinFailureCoordinate(phase, error_type)


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
            f"{check} exact observation is invalid: {error}") from error
    collector.record(check, fields)


def _post_reboot_proof(
    callbacks: AcceptanceCallbacks,
) -> Mapping[str, object]:
    record = _call_static_probe(
        callbacks, "windows-rebooted-joined", "domain-state")
    observation = record.get("observation")
    if (
        record.get("schema_version") != 1
        or record.get("action") != "domain-state"
        or record.get("result") != "pass"
        or not isinstance(observation, dict)
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
            not isinstance(observation[field], str)
            or not observation[field]
            for field in ("domain", "operator")
        )
    ):
        raise WindowsIdentityOrchestratorError(
            "post-reboot domain-state probe is invalid")
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
    local_credential: str,
    callbacks: AcceptanceCallbacks,
    stage_join_principal: Callable[[str], ControllerJoinResult],
    destroy_join_principal: Callable[[], ControllerJoinResult],
) -> tuple[Mapping[str, object], bool]:
    owner = OneUseDomainJoinMaterial(
        realm,
        stage=stage_join_principal,
        destroy=destroy_join_principal,
    )

    def guest_failure(
        coordinate: WindowsJoinFailureCoordinate,
        cleanup: WindowsJoinFailureCoordinate | None = None,
    ) -> WindowsIdentityOrchestratorError:
        diagnostic = IdentityFailureDiagnostic.join_guest(
            coordinate.phase, coordinate.error_type)
        details = ["domain join guest protocol failed", diagnostic.render()]
        if cleanup is not None:
            cleanup_diagnostic = IdentityFailureDiagnostic.join_guest(
                cleanup.phase, cleanup.error_type)
            details.append("cleanup-" + cleanup_diagnostic.render())
        return WindowsIdentityOrchestratorError(
            "; ".join(details), diagnostic=diagnostic)

    def consume(material: Mapping[str, str]) -> Mapping[str, object]:
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
        reauthenticated = False

        def probe_after_reboot() -> Mapping[str, object]:
            nonlocal reauthenticated
            if reauthenticated:
                raise WindowsIdentityOrchestratorError(
                    "post-reboot local session was already authenticated")
            try:
                callbacks.reauthenticate_local(local_credential)
            except BaseException as error:
                raise WindowsJoinIsoError(
                    "post-reboot authentication failed",
                    coordinate=_local_reauthentication_coordinate(error),
                ) from None
            reauthenticated = True
            try:
                return _post_reboot_proof(callbacks)
            except BaseException as error:
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
                raise guest_failure(
                    coordinate, cleanup_coordinate) from None
            raise guest_failure(coordinate) from None

    join_failure: ControllerJoinMaterialError | None = None
    try:
        proof, destruction = owner.use(consume)
    except ControllerJoinMaterialError as error:
        carried = getattr(error, "diagnostic", None)
        if isinstance(carried, IdentityFailureDiagnostic):
            details = [
                "domain join guest protocol failed", carried.render()]
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
        local_credential=local_credential,
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
    record(
        "windows-diagnostics-sanitized",
        diagnostics_scan=callbacks.scan_secrets(
            (local_credential, *principals.values())))
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

    production = execute_production_identity_acceptance(
        boundary=boundary,
        plan=rotation_plan,
        publication=publication,
        private_parent=private_root,
        stage_principals=stage_principals,
        destroy_principals=destroy_principals,
        run_acceptance=acceptance,
    )
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
