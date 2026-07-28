#!/usr/bin/env python3
"""Exact-source mapping for Windows identity acceptance observations."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping

from homelab.workstations.windows_identity_acceptance import FIELD_SETS

from .windows_control_serial import (
    WindowsControlSerialError,
    fault_reachability_fields,
)


class WindowsIdentityObservationError(RuntimeError):
    """Available records do not prove one exact acceptance observation."""


@dataclass(frozen=True)
class ObservationRecords:
    """Strict public records available for one acceptance check."""

    static_probes: Mapping[str, Mapping[str, object]] | None = None
    credential_actions: Mapping[str, Mapping[str, object]] | None = None
    join_proof: Mapping[str, object] | None = None
    fault_record: Mapping[str, object] | None = None
    diagnostics_scan: Mapping[str, object] | None = None


_PROBE_KEYS = {
    "schema_version", "action", "result", "observed_at", "observation",
}
_CREDENTIAL_KEYS = {
    "schema_version", "event", "nonce", "action", "result", "principal",
    "authenticated", "local_administrators_member", "authentication_type",
    "authentication_semantics", "cache_evidence", "login_elapsed_seconds",
    "local_profile_available", "domain_reachable", "controller_reachable",
    "gateway_reachable", "failure_classification",
}
_JOIN_KEYS = {
    "schema_version", "join_media_destroyed", "joined_after_reboot", "domain",
    "operator", "operator_local_administrator",
}
_FAULT_KEYS = {"schema_version", "check", "offline_dependencies"}
_DIAGNOSTIC_KEYS = {
    "secrets_found", "reusable_credentials_retained",
    "qemu_arguments_secret_free", "tracked_artifacts_secret_free",
    "logs_secret_free",
}
_PROBE_SCHEMAS = {
    "current-principal": {
        "principal": str, "authenticated": bool, "elevated": bool,
        "authentication_type": str,
    },
    "current-session-state": {
        "authenticated": bool, "identity_resolved": bool,
        "profile_loaded": bool, "local_profile": bool,
        "local_administrator": bool, "domain_administrator": bool,
    },
    "controller-readiness": {
        "samba_ad": bool, "dns": bool, "kerberos": bool, "time": bool,
        "synthetic_directory": bool,
    },
    "domain-state": {
        "part_of_domain": bool, "domain": str, "secure_channel": bool,
        "operator": str, "operator_local_administrator": bool,
    },
    "managed-identity-state": {
        "standard_identity_resolved": bool,
        "standard_profile_present": bool,
        "operator_identity_resolved": bool,
        "operator_profile_present": bool,
        "operator_local_administrator": bool,
        "operator_domain_administrator": bool,
        "directory_admin_identity_resolved": bool,
        "directory_admin_domain_administrator": bool,
        "operator_is_directory_admin": bool,
    },
    "cached-logon-policy": {
        "configured": bool, "cached_logon_count": (int, type(None)),
    },
    "dependency-reachability": {
        "update_source_reachable": bool,
        "optional_storage_reachable": bool,
        "optional_storage_authorization_denied": bool,
    },
    "service-reachability": {
        "domain": str, "dns": bool, "kerberos": bool, "ldap": bool, "smb": bool,
    },
    "update-policy": {
        "policy_present": bool, "automatic_updates_configured": bool,
    },
}
_FAULT_STATES = {
    "windows-cached-login": {"controller"},
    "windows-cached-admin-login": {"controller"},
    "windows-uncached-denied": {"controller"},
    "windows-local-rescue": {"controller"},
    "update-source-offline": {"update-source"},
    "optional-storage-offline": {"optional-storage"},
    "optional-storage-access-denied": set(),
    "ad-dns-offline": {"controller"},
    "combined-dependencies-offline": {
        "controller", "gateway", "update-source", "optional-storage",
    },
    "windows-services-restored": set(),
    "gateway-offline": {"gateway"},
}


def _probe(records: ObservationRecords, action: str) -> Mapping[str, object]:
    record = (
        records.static_probes.get(action)
        if isinstance(records.static_probes, Mapping) else None
    )
    if (
        not isinstance(record, Mapping)
        or set(record) != _PROBE_KEYS
        or record.get("schema_version") != 1
        or record.get("action") != action
        or record.get("result") != "pass"
        or not isinstance(record.get("observation"), Mapping)
    ):
        raise WindowsIdentityObservationError(
            f"exact {action} static probe is unavailable")
    observation = record["observation"]
    schema = _PROBE_SCHEMAS[action]
    if (
        set(observation) != set(schema)  # type: ignore[arg-type]
        or any(
            (expected == (int, type(None)) and isinstance(
                observation[key], bool))  # type: ignore[index]
            or not isinstance(observation[key], expected)  # type: ignore[index]
            for key, expected in schema.items()
        )
    ):
        raise WindowsIdentityObservationError(
            f"exact {action} static probe is invalid")
    return observation  # type: ignore[return-value]


def _credential(
    records: ObservationRecords, action: str,
) -> Mapping[str, object]:
    record = (
        records.credential_actions.get(action)
        if isinstance(records.credential_actions, Mapping) else None
    )
    if (
        not isinstance(record, Mapping)
        or set(record) != _CREDENTIAL_KEYS
        or record.get("schema_version") != 1
        or record.get("event") != "credential-action-result"
        or record.get("action") != action
        or record.get("result") != "pass"
    ):
        raise WindowsIdentityObservationError(
            f"exact {action} credential action is unavailable")
    for key in (
        "authenticated", "local_administrators_member",
        "local_profile_available", "domain_reachable",
        "controller_reachable", "gateway_reachable",
    ):
        if type(record[key]) is not bool:
            raise WindowsIdentityObservationError(
                f"exact {action} credential action is invalid")
    successful = action != "uncached-domain-user-denied"
    if (
        record["authenticated"] is not successful
        or (successful and record["failure_classification"] != "none")
        or (
            not successful
            and record["failure_classification"] != "windows-logon-failure"
        )
        or (
            action == "connected-domain-login"
            and record["domain_reachable"] is not True
        )
        or (
            action in {"cached-domain-login", "uncached-domain-user-denied"}
            and record["domain_reachable"] is not False
        )
        or (
            action == "operator-local-administrators-check"
            and record["local_administrators_member"] is not True
        )
    ):
        raise WindowsIdentityObservationError(
            f"exact {action} credential action is invalid")
    return record


def _fault(records: ObservationRecords, check: str) -> frozenset[str]:
    record = records.fault_record
    if (
        not isinstance(record, Mapping)
        or set(record) != _FAULT_KEYS
        or record.get("schema_version") != 1
        or record.get("check") != check
        or not isinstance(record.get("offline_dependencies"), list)
        or any(
            not isinstance(item, str)
            for item in record["offline_dependencies"]  # type: ignore[index]
        )
    ):
        raise WindowsIdentityObservationError(
            f"exact {check} fault record is unavailable")
    dependencies = record["offline_dependencies"]
    if len(dependencies) != len(set(dependencies)):  # type: ignore[arg-type]
        raise WindowsIdentityObservationError(
            f"exact {check} fault record is invalid")
    result = frozenset(dependencies)  # type: ignore[arg-type]
    expected = _FAULT_STATES.get(check)
    if expected is None or result != expected:
        raise WindowsIdentityObservationError(
            f"exact {check} fault record has the wrong dependency state")
    return result


def _dependency_fields(
    records: ObservationRecords, check: str,
) -> dict[str, Any]:
    if (
        records.static_probes is None
        or "dependency-reachability" not in records.static_probes
    ):
        raise WindowsIdentityObservationError(
            "exact dependency-reachability static probe is unavailable")
    try:
        return fault_reachability_fields(
            records.static_probes["dependency-reachability"], check)
    except WindowsControlSerialError as error:
        raise WindowsIdentityObservationError(str(error)) from error


def _diagnostics(records: ObservationRecords) -> Mapping[str, object]:
    scan = records.diagnostics_scan
    if (
        not isinstance(scan, Mapping)
        or set(scan) != _DIAGNOSTIC_KEYS
        or type(scan["secrets_found"]) is not int
        or scan["secrets_found"] < 0
        or any(
            type(scan[key]) is not bool
            for key in _DIAGNOSTIC_KEYS - {"secrets_found"}
        )
    ):
        raise WindowsIdentityObservationError(
            "exact diagnostics scan is unavailable")
    return scan


def derive_observation(
    check: str, records: ObservationRecords,
) -> dict[str, Any]:
    """Derive only fields directly established by strict public records.

    The result may be partial.  ``map_exact_observation`` is the publication
    boundary and rejects a partial result with the exact missing field names.
    """
    if check not in FIELD_SETS:
        raise WindowsIdentityObservationError(
            f"unknown Windows identity check {check}")
    fields: dict[str, Any] = {}

    if check == "controller-ready":
        readiness = _probe(records, "controller-readiness")
        fields.update(readiness)

    elif check in {"controller-offline", "controller-restored"}:
        service = _probe(records, "service-reachability")
        fields.update({
            "dns_reachable": service["dns"],
            "kerberos_reachable": service["kerberos"],
            "ldap_reachable": service["ldap"],
            "smb_reachable": service["smb"],
        })
        reachable = all(
            service[name] is True for name in ("dns", "kerberos", "ldap", "smb"))
        fields["authority_reachable"] = reachable

    elif check in {"windows-joined", "windows-rebooted-joined"}:
        domain = _probe(records, "domain-state")
        fields.update({
            "domain_joined": domain["part_of_domain"],
            "secure_channel": domain["secure_channel"],
        })
        if check == "windows-joined":
            # A passing machine secure channel is the machine-account proof:
            # NetLogon cannot establish it without the AD machine principal.
            fields["machine_account"] = domain["secure_channel"]
        proof = records.join_proof
        if proof is not None:
            if (
                not isinstance(proof, Mapping)
                or set(proof) != _JOIN_KEYS
                or proof.get("schema_version") != 1
                or proof.get("join_media_destroyed") is not True
                or proof.get("joined_after_reboot") is not True
                or proof.get("operator_local_administrator") is not True
                or not isinstance(proof.get("domain"), str)
                or not isinstance(proof.get("operator"), str)
            ):
                raise WindowsIdentityObservationError(
                    "exact post-reboot join proof is invalid")
            fields["domain_joined"] = (
                fields["domain_joined"] is True
                and proof["joined_after_reboot"] is True
            )
            if check == "windows-joined":
                fields["join_material"] = (
                    "one-use" if proof["join_media_destroyed"] is True else None)
            else:
                fields["native_boot"] = proof["joined_after_reboot"]

    elif check == "windows-standard-online":
        managed = _probe(records, "managed-identity-state")
        login = _credential(records, "connected-domain-login")
        fields.update({
            "principal_role": "standard",
            "elevated": login["local_administrators_member"],
            "identity_resolved": (
                managed["standard_identity_resolved"] is True
                and login["authenticated"] is True
            ),
            "cache_primed": managed["standard_profile_present"],
        })

    elif check == "windows-daily-admin":
        managed = _probe(records, "managed-identity-state")
        login = _credential(records, "operator-local-administrators-check")
        fields.update({
            "principal_role": "daily-administrator",
            "local_admin": (
                login["local_administrators_member"] is True
                and managed["operator_local_administrator"] is True),
            "domain_admin": managed["operator_domain_administrator"],
            "cache_primed": managed["operator_profile_present"],
        })

    elif check == "domain-admin-separate":
        managed = _probe(records, "managed-identity-state")
        if (
            managed["directory_admin_identity_resolved"] is not True
            or managed["directory_admin_domain_administrator"] is not True
        ):
            raise WindowsIdentityObservationError(
                "managed directory administrator proof is invalid")
        fields["same_principal"] = managed["operator_is_directory_admin"]

    elif check == "windows-cached-policy":
        policy = _probe(records, "cached-logon-policy")
        managed = _probe(records, "managed-identity-state")
        roster = sum((
            managed["standard_identity_resolved"] is True,
            managed["operator_identity_resolved"] is True,
        ))
        margin = sum((
            managed["directory_admin_identity_resolved"] is True,
        ))
        count = policy["cached_logon_count"]
        fields.update({
            "cached_logons_configured": policy["configured"],
            "cached_logon_count": count,
            "managed_user_roster": roster,
            "administrative_margin": margin,
            "capacity_sufficient": (
                isinstance(count, int)
                and not isinstance(count, bool)
                and count >= roster + margin),
        })

    elif check in {
        "windows-cached-login", "windows-cached-admin-login",
        "windows-uncached-denied", "windows-local-rescue",
    }:
        action = {
            "windows-cached-login": "cached-domain-login",
            "windows-cached-admin-login": "cached-domain-login",
            "windows-uncached-denied": "uncached-domain-user-denied",
            "windows-local-rescue": "local-rescue-login",
        }[check]
        login = _credential(records, action)
        _fault(records, check)
        fields["controller_online"] = login["domain_reachable"]
        fields["login"] = (
            "allowed" if login["authenticated"] is True else "denied")
        if check == "windows-cached-login":
            fields.update(cached=True, principal_role="standard")
        elif check == "windows-cached-admin-login":
            fields.update(
                cached=True, principal_role="daily-administrator",
                local_admin=login["local_administrators_member"])
        elif check == "windows-uncached-denied":
            fields["principal_role"] = "uncached-domain-user"
        else:
            fields.update(
                scope="local",
                local_admin=login["local_administrators_member"])

    elif check == "windows-secure-channel-restored":
        domain = _probe(records, "domain-state")
        fields["secure_channel"] = domain["secure_channel"]
        fields["rejoin_required"] = not domain["secure_channel"]

    elif check == "windows-update-policy":
        policy = _probe(records, "update-policy")
        fields["automatic_updates_configured"] = (
            policy["policy_present"] is True
            and policy["automatic_updates_configured"] is True)
        fields["policy_source"] = "local-policy-or-domain"
        fields["live_microsoft_update_tested"] = False

    elif check in {
        "update-source-offline", "optional-storage-offline",
        "optional-storage-access-denied", "combined-dependencies-offline",
        "windows-services-restored",
    }:
        _fault(records, check)
        fields.update(_dependency_fields(records, check))
        if check in {
            "update-source-offline", "optional-storage-offline",
            "optional-storage-access-denied",
        }:
            action = (
                "connected-domain-login"
                if check in {
                    "update-source-offline", "optional-storage-offline",
                    "optional-storage-access-denied",
                }
                else "cached-domain-login"
            )
            login = _credential(records, action)
            if check == "update-source-offline":
                fields["login_unaffected"] = login["authenticated"]
                scan = _diagnostics(records)
                fields["diagnostics_secret_free"] = (
                    scan["secrets_found"] == 0
                    and scan["reusable_credentials_retained"] is False
                    and scan["qemu_arguments_secret_free"] is True
                    and scan["tracked_artifacts_secret_free"] is True
                    and scan["logs_secret_free"] is True)
            else:
                fields.update({
                    "login_succeeded": login["authenticated"],
                    "login_seconds": login["login_elapsed_seconds"],
                    "login_bound_seconds": 30,
                    "local_profile": login["local_profile_available"],
                })
        elif check == "combined-dependencies-offline":
            cached = _credential(records, "cached-domain-login")
            local = _credential(records, "local-rescue-login")
            fields.update({
                "controller_reachable": cached["controller_reachable"],
                "gateway_reachable": cached["gateway_reachable"],
                "cached_login": cached["authenticated"],
                "local_rescue": local["authenticated"],
            })
        else:
            service = _probe(records, "service-reachability")
            domain = _probe(records, "domain-state")
            fields.update({
                "dns_reachable": service["dns"],
                "secure_channel": domain["secure_channel"],
                "rejoin_required": not domain["secure_channel"],
                "rebuild_required": not (
                    service["dns"] is True
                    and domain["secure_channel"] is True
                    and fields["optional_storage_reachable"] is True),
            })

    elif check == "ad-dns-offline":
        service = _probe(records, "service-reachability")
        _fault(records, check)
        fields.update({
            "dns_reachable": service["dns"],
            "kerberos_reachable": service["kerberos"],
            "ldap_reachable": service["ldap"],
            "smb_reachable": service["smb"],
        })
        fields["cached_login"] = _credential(
            records, "cached-domain-login")["authenticated"]

    elif check == "gateway-offline":
        _fault(records, check)
        login = _credential(records, "connected-domain-login")
        fields.update({
            "gateway_reachable": login["gateway_reachable"],
            "controller_reachable": login["controller_reachable"],
            "domain_login": login["authenticated"],
        })

    elif check == "windows-diagnostics-sanitized":
        fields.update(_diagnostics(records))

    elif check == "windows-identity-acceptance":
        fields.update({
            "checks": len(FIELD_SETS),
            "firmware_activation_tested": False,
            "live_microsoft_update_tested": False,
            "deferred": ["disable-reenable"],
        })

    return {key: value for key, value in fields.items()
            if key in FIELD_SETS[check]}


def map_exact_observation(
    check: str, records: ObservationRecords,
) -> dict[str, Any]:
    """Return one complete FIELD_SETS mapping or fail with missing facts."""
    fields = derive_observation(check, records)
    missing = sorted(FIELD_SETS[check] - fields.keys())
    if missing:
        raise WindowsIdentityObservationError(
            f"{check} lacks exact source facts: {', '.join(missing)}")
    if set(fields) != FIELD_SETS[check]:
        raise WindowsIdentityObservationError(
            f"{check} produced fields outside the acceptance contract")
    return fields
