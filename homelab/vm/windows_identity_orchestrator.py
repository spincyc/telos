#!/usr/bin/env python3
"""Production composition root for strict Windows identity acceptance."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Mapping, Protocol
import uuid

from homelab.workstations.windows_identity_acceptance import FIELD_SETS

from .controller_join_material import (
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
from .windows_identity_progressive import ProgressiveRotationPlan
from .windows_identity_run import NativeProcessBoundary
from .windows_join_iso import (
    DuplexJoinSerial,
    JoinMediaChannel,
    build_join_iso,
    execute_join_and_prove,
)


class WindowsIdentityOrchestratorError(RuntimeError):
    """The production acceptance composition failed closed."""


class Qmp(Protocol):
    def execute(
        self, command: str, arguments: dict | None = None,
    ) -> Mapping[str, object]: ...


@dataclass(frozen=True)
class ObservationContext:
    """Public inputs available to one exact contract observation."""

    static_probe: Mapping[str, object] | None = None
    credential_action: Mapping[str, object] | None = None
    join_proof: Mapping[str, object] | None = None


@dataclass(frozen=True)
class ExactObservation:
    """One semantic mapping bound to the exact raw sources it consumed."""

    check: str
    sources: frozenset[str]
    fields: Mapping[str, Any]


Observation = Callable[[str, ObservationContext], ExactObservation]


@dataclass(frozen=True)
class AcceptanceCallbacks:
    """Explicit host/guest boundaries required by the production run.

    The observation callback owns semantic interpretation. Static probe and
    credential-action records are supplied as public context, but the
    orchestrator never invents missing fields from either record.
    """

    qmp: Callable[[], Qmp]
    launch_guest: Callable[[str], None]
    await_device_deleted: Callable[[str], None]
    open_join_serial: Callable[[], DuplexJoinSerial]
    static_probe: Callable[[str], Mapping[str, object]]
    credential_action: Callable[
        [str, str, str], Mapping[str, object]
    ]
    observe: Observation
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
    "controller-ready": "service-reachability",
    "windows-joined": "domain-state",
    "windows-standard-online": "current-principal",
    "windows-daily-admin": "current-principal",
    "windows-rebooted-joined": "domain-state",
    "windows-cached-policy": "cached-logon-policy",
    "controller-offline": "service-reachability",
    "controller-restored": "service-reachability",
    "windows-secure-channel-restored": "domain-state",
    "windows-update-policy": "update-policy",
    "update-source-offline": "dependency-reachability",
    "optional-storage-offline": "dependency-reachability",
    "optional-storage-access-denied": "dependency-reachability",
    "ad-dns-offline": "service-reachability",
    "combined-dependencies-offline": "dependency-reachability",
    "windows-services-restored": "service-reachability",
}

_CREDENTIAL_ROLES = {
    "windows-standard-online": "student",
    "windows-daily-admin": "operator",
    "windows-cached-login": "student",
    "windows-cached-admin-login": "operator",
    "windows-uncached-denied": "directory-admin",
    "windows-local-rescue": "local",
    "gateway-offline": "student",
    "optional-storage-offline": "student",
    "optional-storage-access-denied": "student",
    "ad-dns-offline": "student",
    "combined-dependencies-offline": "local",
}


def _validated_static_probe(
    callbacks: AcceptanceCallbacks, check: str,
) -> Mapping[str, object] | None:
    action = _STATIC_ACTIONS.get(check)
    if action is None:
        return None
    record = dict(callbacks.static_probe(action))
    if (
        record.get("schema_version") != 1
        or record.get("action") != action
        or record.get("result") != "pass"
        or not isinstance(record.get("observation"), dict)
    ):
        raise WindowsIdentityOrchestratorError(
            f"{check} static probe record is invalid")
    return record


def _credential_context(
    callbacks: AcceptanceCallbacks,
    check: str,
    local_credential: str,
    principals: Mapping[str, str],
) -> Mapping[str, object] | None:
    role = _CREDENTIAL_ROLES.get(check)
    if role is None:
        return None
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
    if result.get("schema_version") != 1:
        raise WindowsIdentityOrchestratorError(
            f"{check} credential action result is invalid")
    return result


def _record(
    collector: StrictIdentityEvidenceCollector,
    callbacks: AcceptanceCallbacks,
    check: str,
    *,
    local_credential: str,
    principals: Mapping[str, str],
    join_proof: Mapping[str, object] | None = None,
) -> None:
    context = ObservationContext(
        static_probe=_validated_static_probe(callbacks, check),
        credential_action=_credential_context(
            callbacks, check, local_credential, principals),
        join_proof=join_proof,
    )
    mapped = callbacks.observe(check, context)
    expected_sources = {f"guest:{check}"}
    if context.static_probe is not None:
        expected_sources.add(
            f"static:{context.static_probe['action']}")
    if context.credential_action is not None:
        expected_sources.add(f"credential:{check}")
    if context.join_proof is not None:
        expected_sources.add("join:post-reboot")
    if (
        not isinstance(mapped, ExactObservation)
        or mapped.check != check
        or mapped.sources != frozenset(expected_sources)
    ):
        raise WindowsIdentityOrchestratorError(
            f"{check} observation source binding is invalid")
    collector.record(check, mapped.fields)


def _post_reboot_proof(
    callbacks: AcceptanceCallbacks,
) -> Mapping[str, object]:
    record = dict(callbacks.static_probe("domain-state"))
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
    callbacks: AcceptanceCallbacks,
    stage_join_principal: Callable[[str], ControllerJoinResult],
    destroy_join_principal: Callable[[], ControllerJoinResult],
) -> tuple[Mapping[str, object], bool]:
    owner = OneUseDomainJoinMaterial(
        realm,
        stage=stage_join_principal,
        destroy=destroy_join_principal,
    )

    def consume(material: Mapping[str, str]) -> Mapping[str, object]:
        nonce = uuid.uuid4().hex
        iso = private_root / f"windows-join-{nonce}.iso"
        build_join_iso(iso, {
            "nonce": nonce,
            "domain": realm,
            "realm": realm.upper(),
            "username": material["principal"],
            "password": material["credential"],
            "operator": f"operator@{realm.upper()}",
        })
        channel = JoinMediaChannel(callbacks.qmp(), iso, nonce)
        serial = callbacks.open_join_serial()
        try:
            return execute_join_and_prove(
                channel=channel,
                serial=serial,
                launch_guest=callbacks.launch_guest,
                await_device_deleted=callbacks.await_device_deleted,
                probe_after_reboot=lambda: _post_reboot_proof(callbacks),
                expected_domain=realm,
            )
        except BaseException as primary:
            serial.close()
            try:
                channel.cleanup(
                    await_device_deleted=callbacks.await_device_deleted)
            except BaseException as cleanup:
                raise WindowsIdentityOrchestratorError(
                    "domain join and private cleanup failed: "
                    f"{type(primary).__name__}; {type(cleanup).__name__}"
                ) from None
            raise

    proof, destruction = owner.use(consume)
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
        callbacks=callbacks,
        stage_join_principal=stage_join_principal,
        destroy_join_principal=destroy_join_principal,
    )
    record("windows-joined", join_proof=join_proof)
    for check in (
        "windows-standard-online",
        "windows-daily-admin",
        "domain-admin-separate",
        "windows-rebooted-joined",
        "windows-cached-policy",
    ):
        record(check)

    def fault_observe(check: str) -> None:
        record(check)
        if check == "windows-secure-channel-restored":
            record("windows-update-policy")

    faults = run_fault_phases(FaultPhaseOperations(
        set_controller_available=boundary.set_controller_available,
        set_gateway_available=boundary.set_gateway_available,
        set_update_source_available=boundary.set_update_source_available,
        set_optional_storage_available=boundary.set_optional_storage_available,
        observe=fault_observe,
    ))
    diagnostics = callbacks.scan_secrets(
        (local_credential, *principals.values()))
    collector.record("windows-diagnostics-sanitized", diagnostics)
    collector.record("windows-identity-acceptance", {
        "checks": len(FIELD_SETS),
        "firmware_activation_tested": False,
        "live_microsoft_update_tested": False,
        "deferred": ["disable-reenable"],
    })
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
