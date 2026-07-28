#!/usr/bin/env python3
"""Judge strict, ordered Windows identity and recovery evidence."""

from __future__ import annotations

import argparse
import json
import math
import re
import sys
from pathlib import Path
from typing import Any, Iterable

CONTRACT = Path(__file__).with_name("windows_identity_acceptance.json")
BASE_FIELDS = {
    "schema_version", "sequence", "check", "result", "external_access",
    "observed_at", "run_id",
}
FIELD_SETS = {
    "controller-ready": {
        "samba_ad", "dns", "kerberos", "time", "synthetic_directory"},
    "windows-joined": {
        "domain_joined", "secure_channel", "machine_account", "join_material"},
    "windows-standard-online": {
        "principal_role", "elevated", "identity_resolved", "cache_primed"},
    "windows-daily-admin": {
        "principal_role", "local_admin", "domain_admin", "cache_primed"},
    "domain-admin-separate": {"same_principal"},
    "windows-rebooted-joined": {
        "native_boot", "domain_joined", "secure_channel"},
    "windows-cached-policy": {
        "cached_logons_configured", "cached_logon_count",
        "managed_user_roster", "administrative_margin", "capacity_sufficient"},
    "controller-offline": {
        "authority_reachable", "dns_reachable", "kerberos_reachable",
        "ldap_reachable", "smb_reachable"},
    "windows-cached-login": {
        "controller_online", "cached", "principal_role", "login"},
    "windows-cached-admin-login": {
        "controller_online", "cached", "principal_role", "login", "local_admin"},
    "windows-uncached-denied": {
        "controller_online", "principal_role", "login"},
    "windows-local-rescue": {
        "controller_online", "scope", "local_admin", "login"},
    "controller-restored": {
        "authority_reachable", "dns_reachable", "kerberos_reachable",
        "ldap_reachable", "smb_reachable"},
    "windows-secure-channel-restored": {
        "secure_channel", "rejoin_required"},
    "windows-update-policy": {
        "automatic_updates_configured", "policy_source",
        "live_microsoft_update_tested"},
    "gateway-offline": {
        "gateway_reachable", "controller_reachable", "domain_login"},
    "update-source-offline": {
        "update_source_reachable", "login_unaffected",
        "diagnostics_secret_free"},
    "optional-storage-offline": {
        "storage_reachable", "login_succeeded", "login_seconds",
        "login_bound_seconds", "local_profile"},
    "optional-storage-access-denied": {
        "storage_reachable", "storage_access", "login_succeeded",
        "login_seconds", "login_bound_seconds", "local_profile"},
    "ad-dns-offline": {
        "dns_reachable", "kerberos_reachable", "ldap_reachable",
        "smb_reachable", "cached_login"},
    "combined-dependencies-offline": {
        "controller_reachable", "gateway_reachable",
        "update_source_reachable", "optional_storage_reachable",
        "cached_login", "local_rescue"},
    "windows-services-restored": {
        "dns_reachable", "secure_channel", "optional_storage_reachable",
        "rejoin_required", "rebuild_required"},
    "windows-diagnostics-sanitized": {
        "secrets_found", "reusable_credentials_retained",
        "qemu_arguments_secret_free", "tracked_artifacts_secret_free",
        "logs_secret_free"},
    "windows-identity-acceptance": {
        "checks", "firmware_activation_tested",
        "live_microsoft_update_tested", "deferred"},
}
UTC = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
RUN_ID = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-"
    r"[89ab][0-9a-f]{3}-[0-9a-f]{12}$")


class EvidenceError(ValueError):
    """Evidence does not prove the Windows identity contract."""


def load_json(path: Path) -> Any:
    with path.open(encoding="utf-8") as source:
        return json.load(source)


def validate_contract(contract: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    if contract.get("schema_version") != 1:
        errors.append("schema_version must be 1")
    if contract.get("network_policy") != {
        "mode": "local-only", "external_access": "forbidden"}:
        errors.append("network_policy must forbid external access")
    checks = contract.get("required_checks")
    if checks != list(FIELD_SETS):
        errors.append("required_checks must match the supported ordered checks")
    if contract.get("login_bound_seconds") != 30:
        errors.append("login_bound_seconds must be 30")
    if contract.get("deferred_checks") != ["disable-reenable"]:
        errors.append("disable-reenable must remain deferred")
    if contract.get("out_of_scope") != [
            "firmware-activation", "live-microsoft-update"]:
        errors.append("activation and live Microsoft Update must remain out of scope")
    return errors


def load_events(lines: Iterable[str]) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    for number, line in enumerate(lines, 1):
        if not line.strip():
            continue
        try:
            event = json.loads(line)
        except json.JSONDecodeError as error:
            raise EvidenceError(
                f"line {number}: invalid JSON: {error.msg}") from error
        if not isinstance(event, dict):
            raise EvidenceError(f"line {number}: event must be an object")
        events.append(event)
    return events


def _expect(event: dict[str, Any], **values: Any) -> None:
    check = event["check"]
    for field, expected in values.items():
        if event.get(field) != expected:
            raise EvidenceError(
                f"{check}.{field} must be {expected!r}")


def _validate_envelope(
    event: dict[str, Any], check: str, sequence: int, run_id: str,
) -> None:
    if set(event) != BASE_FIELDS | FIELD_SETS[check]:
        unexpected = sorted(set(event) - BASE_FIELDS - FIELD_SETS[check])
        missing = sorted(BASE_FIELDS | FIELD_SETS[check] - set(event))
        detail = []
        if unexpected:
            detail.append("unexpected " + ", ".join(unexpected))
        if missing:
            detail.append("missing " + ", ".join(missing))
        raise EvidenceError(f"{check} has invalid fields: {'; '.join(detail)}")
    _expect(
        event, schema_version=1, sequence=sequence, check=check,
        result="pass", external_access=False, run_id=run_id)
    if not isinstance(event["observed_at"], str) or not UTC.fullmatch(
            event["observed_at"]):
        raise EvidenceError(f"{check}.observed_at must be UTC RFC3339 seconds")


def _validate_login_time(event: dict[str, Any]) -> None:
    seconds = event["login_seconds"]
    if (isinstance(seconds, bool) or not isinstance(seconds, (int, float))
            or not math.isfinite(seconds) or seconds < 0):
        raise EvidenceError(f"{event['check']}.login_seconds is invalid")
    if event["login_bound_seconds"] != 30 or seconds > 30:
        raise EvidenceError(f"{event['check']} exceeded the 30-second login bound")


def judge(contract: dict[str, Any], events: list[dict[str, Any]]) -> dict[str, Any]:
    errors = validate_contract(contract)
    if errors:
        raise EvidenceError("invalid contract: " + "; ".join(errors))
    required = contract["required_checks"]
    if len(events) != len(required):
        raise EvidenceError(
            f"expected {len(required)} events; found {len(events)}")
    if not events or not isinstance(events[0].get("run_id"), str) \
            or not RUN_ID.fullmatch(events[0]["run_id"]):
        raise EvidenceError("run_id must be a lowercase UUID")
    run_id = events[0]["run_id"]
    for sequence, (check, event) in enumerate(zip(required, events), 1):
        _validate_envelope(event, check, sequence, run_id)

    by = {event["check"]: event for event in events}
    _expect(by["controller-ready"], samba_ad=True, dns=True, kerberos=True,
            time=True, synthetic_directory=True)
    _expect(by["windows-joined"], domain_joined=True, secure_channel=True,
            machine_account=True, join_material="one-use")
    _expect(by["windows-standard-online"], principal_role="standard",
            elevated=False, identity_resolved=True, cache_primed=True)
    _expect(by["windows-daily-admin"],
            principal_role="daily-administrator", local_admin=True,
            domain_admin=False, cache_primed=True)
    _expect(by["domain-admin-separate"], same_principal=False)
    _expect(by["windows-rebooted-joined"], native_boot=True,
            domain_joined=True, secure_channel=True)
    policy = by["windows-cached-policy"]
    _expect(policy, cached_logons_configured=True, capacity_sufficient=True)
    for field in (
            "cached_logon_count", "managed_user_roster",
            "administrative_margin"):
        if isinstance(policy[field], bool) or not isinstance(policy[field], int) \
                or policy[field] < 0:
            raise EvidenceError(f"windows-cached-policy.{field} is invalid")
    if policy["cached_logon_count"] < (
            policy["managed_user_roster"] + policy["administrative_margin"]):
        raise EvidenceError("cached logon capacity is insufficient")
    _expect(by["controller-offline"], authority_reachable=False,
            dns_reachable=False, kerberos_reachable=False,
            ldap_reachable=False, smb_reachable=False)
    _expect(by["windows-cached-login"], controller_online=False, cached=True,
            principal_role="standard", login="allowed")
    _expect(by["windows-cached-admin-login"], controller_online=False,
            cached=True, principal_role="daily-administrator",
            login="allowed", local_admin=True)
    _expect(by["windows-uncached-denied"], controller_online=False,
            principal_role="uncached-domain-user", login="denied")
    _expect(by["windows-local-rescue"], controller_online=False, scope="local",
            local_admin=True, login="allowed")
    _expect(by["controller-restored"], authority_reachable=True,
            dns_reachable=True, kerberos_reachable=True,
            ldap_reachable=True, smb_reachable=True)
    _expect(by["windows-secure-channel-restored"], secure_channel=True,
            rejoin_required=False)
    _expect(by["windows-update-policy"], automatic_updates_configured=True,
            policy_source="local-policy-or-domain",
            live_microsoft_update_tested=False)
    _expect(by["gateway-offline"], gateway_reachable=False,
            controller_reachable=True, domain_login=True)
    _expect(by["update-source-offline"], update_source_reachable=False,
            login_unaffected=True, diagnostics_secret_free=True)
    _expect(by["optional-storage-offline"], storage_reachable=False,
            login_succeeded=True, local_profile=True)
    _validate_login_time(by["optional-storage-offline"])
    _expect(by["optional-storage-access-denied"], storage_reachable=True,
            storage_access="denied", login_succeeded=True, local_profile=True)
    _validate_login_time(by["optional-storage-access-denied"])
    _expect(by["ad-dns-offline"], dns_reachable=False,
            kerberos_reachable=False, ldap_reachable=False,
            smb_reachable=False, cached_login=True)
    _expect(by["combined-dependencies-offline"],
            controller_reachable=False, gateway_reachable=False,
            update_source_reachable=False, optional_storage_reachable=False,
            cached_login=True, local_rescue=True)
    _expect(by["windows-services-restored"], dns_reachable=True,
            secure_channel=True, optional_storage_reachable=True,
            rejoin_required=False, rebuild_required=False)
    _expect(by["windows-diagnostics-sanitized"], secrets_found=0,
            reusable_credentials_retained=False,
            qemu_arguments_secret_free=True, tracked_artifacts_secret_free=True,
            logs_secret_free=True)
    _expect(by["windows-identity-acceptance"], checks=len(required),
            firmware_activation_tested=False,
            live_microsoft_update_tested=False,
            deferred=["disable-reenable"])
    return {
        "schema_version": 1,
        "result": "pass",
        "checks": len(required),
        "external_access": False,
        "deferred": ["disable-reenable"],
        "out_of_scope": [
            "firmware-activation", "live-microsoft-update"],
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--contract", type=Path, default=CONTRACT)
    parser.add_argument("evidence", type=Path)
    args = parser.parse_args(argv)
    try:
        contract = load_json(args.contract)
        with args.evidence.open(encoding="utf-8") as source:
            result = judge(contract, load_events(source))
    except (OSError, json.JSONDecodeError, EvidenceError) as error:
        print(f"windows identity acceptance: {error}", file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
