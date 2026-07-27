#!/usr/bin/env python3
"""Judge ordered, local-only cross-OS identity lifecycle evidence."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Iterable

CONTRACT = Path(__file__).with_name("identity_lifecycle.json")
OSES = ("windows", "arch")


class EvidenceError(ValueError):
    """Evidence does not prove the lifecycle contract."""


def load_json(path: Path) -> Any:
    with path.open(encoding="utf-8") as source:
        return json.load(source)


def validate_contract(contract: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    if contract.get("schema_version") != 1:
        errors.append("schema_version must be 1")
    policy = contract.get("network_policy", {})
    if policy != {"mode": "local-only", "external_access": "forbidden"}:
        errors.append("network_policy must forbid external access")
    principals = contract.get("principals", {})
    expected = {
        "standard_user": ("user", "standard"),
        "daily_administrator": ("user", "administrator"),
        "domain_administrator": ("administrator", "administrator"),
        "local_rescue": ("none", "administrator"),
    }
    names: set[str] = set()
    for role, (domain_role, workstation_role) in expected.items():
        principal = principals.get(role, {})
        name = principal.get("name")
        if not isinstance(name, str) or not name:
            errors.append(f"principals.{role}.name must be non-empty")
        elif name in names:
            errors.append(f"principal name {name!r} is reused")
        else:
            names.add(name)
        if principal.get("domain_role") != domain_role:
            errors.append(f"principals.{role}.domain_role must be {domain_role}")
        if principal.get("workstation_role") != workstation_role:
            errors.append(
                f"principals.{role}.workstation_role must be {workstation_role}"
            )
    checks = contract.get("required_checks")
    if not isinstance(checks, list) or not checks or len(checks) != len(set(checks)):
        errors.append("required_checks must be a non-empty unique list")
    deferred = contract.get("deferred_checks", [])
    revocation = [item for item in deferred if item.get("id") == "disable-reenable"]
    if len(revocation) != 1 or revocation[0].get("phase", 0) < 2:
        errors.append("disable-reenable must be explicitly deferred to phase 2 or later")
    return errors


def load_events(lines: Iterable[str]) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    for number, line in enumerate(lines, 1):
        if not line.strip():
            continue
        try:
            event = json.loads(line)
        except json.JSONDecodeError as error:
            raise EvidenceError(f"line {number}: invalid JSON: {error.msg}") from error
        if not isinstance(event, dict):
            raise EvidenceError(f"line {number}: event must be an object")
        events.append(event)
    return events


def judge(contract: dict[str, Any], events: list[dict[str, Any]]) -> dict[str, Any]:
    errors = validate_contract(contract)
    if errors:
        raise EvidenceError("invalid contract: " + "; ".join(errors))
    required = contract["required_checks"]
    positions: dict[str, int] = {}
    for index, event in enumerate(events):
        check = event.get("check")
        if check in positions:
            raise EvidenceError(f"duplicate evidence for {check}")
        if check in required:
            positions[check] = index
        if event.get("external_access") is not False:
            raise EvidenceError(f"event {check or index} does not prove external_access=false")
        if event.get("result") != "pass":
            raise EvidenceError(f"event {check or index} did not pass")
    missing = [check for check in required if check not in positions]
    if missing:
        raise EvidenceError("missing evidence: " + ", ".join(missing))
    if [positions[item] for item in required] != sorted(positions.values()):
        raise EvidenceError("lifecycle evidence is out of order")

    by_check = {event["check"]: event for event in events if event.get("check") in required}
    ready = by_check["controller-ready"]
    for service in ("samba_ad", "dns", "kerberos", "time"):
        if ready.get(service) is not True:
            raise EvidenceError(f"controller did not prove {service} ready")
    if ready.get("synthetic_directory") is not True:
        raise EvidenceError("controller evidence may contain private identities")
    for os_name in OSES:
        joined = by_check[f"{os_name}-joined"]
        if (
            joined.get("domain_joined") is not True
            or joined.get("secure_channel") is not True
            or joined.get("machine_account") is not True
        ):
            raise EvidenceError(f"{os_name} join lacks a secure channel")
        standard = by_check[f"{os_name}-standard-online"]
        if standard.get("principal_role") != "standard" or standard.get("elevated") is not False:
            raise EvidenceError(f"{os_name} standard user authorization is unsafe")
        daily = by_check[f"{os_name}-daily-admin"]
        if daily.get("principal_role") != "daily-administrator":
            raise EvidenceError(f"{os_name} daily administrator identity is wrong")
        if daily.get("local_admin") is not True or daily.get("domain_admin") is not False:
            raise EvidenceError(f"{os_name} daily administrator is not least-privileged")
        cached = by_check[f"{os_name}-cached-login"]
        if cached.get("controller_online") is not False or cached.get("cached") is not True:
            raise EvidenceError(f"{os_name} cached login was not proven during outage")
        uncached = by_check[f"{os_name}-uncached-denied"]
        if uncached.get("controller_online") is not False or uncached.get("login") != "denied":
            raise EvidenceError(f"{os_name} uncached outage login was not denied")
        rescue = by_check[f"{os_name}-local-rescue"]
        if rescue.get("scope") != "local" or rescue.get("local_admin") is not True:
            raise EvidenceError(f"{os_name} local rescue is not independent")

    separate = by_check["domain-admin-separate"]
    if separate.get("same_principal") is not False:
        raise EvidenceError("daily and domain administrator identities are not separate")
    outage = by_check["controller-offline"]
    if outage.get("authority_reachable") is not False:
        raise EvidenceError("controller outage was not proven")
    restored = by_check["controller-restored"]
    if restored.get("authority_reachable") is not True:
        raise EvidenceError("controller restoration was not proven")
    if by_check["windows-secure-channel-restored"].get("secure_channel") is not True:
        raise EvidenceError("Windows secure channel did not recover")
    if by_check["arch-identity-restored"].get("identity_lookup") is not True:
        raise EvidenceError("Arch identity lookup did not recover")
    return {
        "schema_version": 1,
        "result": "pass",
        "checks": len(required),
        "external_access": False,
        "deferred": ["disable-reenable"],
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--contract", type=Path, default=CONTRACT)
    parser.add_argument("evidence", type=Path)
    args = parser.parse_args(argv)
    try:
        contract = load_json(args.contract)
        with args.evidence.open(encoding="utf-8") as source:
            result = judge(contract, load_events(source))
    except (OSError, json.JSONDecodeError, EvidenceError) as error:
        print(f"identity lifecycle: {error}", file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
