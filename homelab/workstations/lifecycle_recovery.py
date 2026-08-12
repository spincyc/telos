#!/usr/bin/env python3
"""Judge gate-11 lifecycle-recovery evidence, fail-closed and honest.

Gate 11 (``homelab/WORKSTATION-FACTORY-STATE.md``) exercises eight recovery
scenarios: controller restart, PXE release rollback, failed-install recovery,
broken-boot repair, directory/DNS loss, update-failure handling, workstation
remint, and controller reconstruction.  This module reads one evidence stream
(one JSON record per scenario, as produced by ``homelab/vm/lifecycle_recovery``)
and validates every judged field fail-closed.

Honesty rules, mirroring the gate-12 verifier's NOT-RUN discipline:

* A scenario record is either ``"pass"`` (every judged field it owns is present
  and correct) or ``"not-run"`` (a proof that the local loopback lab could not
  fully render, carrying a non-empty ``deferred_reason``).  A ``"not-run"``
  scenario still has any recorded field validated fail-closed; it is never
  promoted to a pass.
* Any other ``result`` value, a missing scenario, a duplicated scenario, an
  ``external_access`` that is not ``false``, or a judged field that is absent or
  wrong when the scenario claims ``"pass"`` raises :class:`EvidenceError`.
* The overall verdict is ``"pass"`` only when every required scenario passed;
  when nothing failed but some scenarios were honestly deferred the verdict is
  ``"partial"`` and every deferred scenario is named.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Iterable

CONTRACT = Path(__file__).with_name("lifecycle_recovery.json")

SCENARIOS = (
    "controller-restart",
    "pxe-release-rollback",
    "failed-install-recovery",
    "broken-boot-repair",
    "directory-dns-loss",
    "update-failure-rollback",
    "workstation-remint",
    "controller-reconstruction",
)
# The scenarios whose *complete* proof needs a live guest boot; their provable
# loopback part is judged whenever recorded, and the live part may be deferred.
LIVE_BOOT_CHECKS = frozenset({
    "controller-restart",
    "failed-install-recovery",
    "broken-boot-repair",
    "directory-dns-loss",
    "controller-reconstruction",
})
# ADR 0068 dual-boot NVRAM entries authored by arch_second.
NVRAM_LINUX_LABEL = "Linux Boot Manager"
NVRAM_WINDOWS_LABEL = "Windows Boot Manager"
# ADR 0075 gated-update policy.
UPDATE_OPERATION = "pacman -Syu"
UPDATE_FALLBACK = "linux-lts"
UPDATE_MINIMUM_FREE_GIB = 8
UPDATE_REQUIRES = ["ac_power", "free_space", "official_mirror", "pacman_idle"]
VERSION_LENGTH = len("YYYYMMDD.NNN")


class EvidenceError(ValueError):
    """Evidence does not prove the lifecycle-recovery contract."""


def load_json(path: Path) -> Any:
    with path.open(encoding="utf-8") as source:
        return json.load(source)


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


def validate_contract(contract: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    if contract.get("schema_version") != 1:
        errors.append("schema_version must be 1")
    if contract.get("gate") != 11:
        errors.append("gate must be 11")
    policy = contract.get("network_policy", {})
    if policy != {"mode": "local-only", "external_access": "forbidden"}:
        errors.append("network_policy must forbid external access")
    checks = contract.get("required_checks")
    if (not isinstance(checks, list) or checks != list(SCENARIOS)):
        errors.append(
            "required_checks must list exactly the eight recovery scenarios "
            "in order")
    live = contract.get("live_boot_checks")
    if not isinstance(live, list) or set(live) != LIVE_BOOT_CHECKS:
        errors.append(
            "live_boot_checks must name exactly the guest-boot scenarios")
    elif isinstance(checks, list):
        if not set(live) <= set(checks):
            errors.append("live_boot_checks must be a subset of required_checks")
    update = contract.get("update_policy", {})
    if not isinstance(update, dict):
        errors.append("update_policy must be an object")
    else:
        # ADR 0075 is explicit: the updater does NOT claim or attempt an
        # automatic rollback; recovery is the independently bootable linux-lts.
        if update.get("operation") != UPDATE_OPERATION:
            errors.append(f"update_policy.operation must be {UPDATE_OPERATION!r}")
        if update.get("automatic_rollback") is not False:
            errors.append(
                "update_policy.automatic_rollback must be false (ADR 0075)")
        if update.get("recovery_fallback") != UPDATE_FALLBACK:
            errors.append(
                f"update_policy.recovery_fallback must be {UPDATE_FALLBACK!r}")
        if update.get("minimum_free_gib") != UPDATE_MINIMUM_FREE_GIB:
            errors.append(
                f"update_policy.minimum_free_gib must be {UPDATE_MINIMUM_FREE_GIB}")
        if update.get("requires") != UPDATE_REQUIRES:
            errors.append(
                "update_policy.requires must name the four ADR 0075 gates")
    entries = contract.get("dual_boot_entries", {})
    if entries != {
        "linux": NVRAM_LINUX_LABEL,
        "windows": NVRAM_WINDOWS_LABEL,
        "independent_uefi_entries": True,
    }:
        errors.append(
            "dual_boot_entries must bind the independent Linux/Windows UEFI "
            "entries")
    return errors


# --------------------------------------------------------------------------
# Per-scenario fail-closed field validation
#
# Each scenario declares its judged fields as ``(field, check)`` specs, split
# into a provable part (rendered in the local loopback lab) and a live part
# (needs a guest boot).  A "pass" scenario must present and satisfy every spec;
# a deferred "not-run" scenario must satisfy every field it *did* record but
# may legitimately omit fields it could not prove.  Values are never fabricated
# into a pass: an absent field simply cannot make a "pass" verdict.
# --------------------------------------------------------------------------


def _check_true(scenario: str, field: str, value: Any) -> None:
    if value is not True:
        raise EvidenceError(f"{scenario}: {field} must be proven true")


def _check_false(scenario: str, field: str, value: Any) -> None:
    if value is not False:
        raise EvidenceError(f"{scenario}: {field} must be false")


def _check_zero(scenario: str, field: str, value: Any) -> None:
    # A plain-int zero, never a bool.
    if isinstance(value, bool) or value != 0:
        raise EvidenceError(f"{scenario}: {field} must be 0")


def _equals(expected: Any):
    def checker(scenario: str, field: str, value: Any) -> None:
        if value != expected:
            raise EvidenceError(f"{scenario}: {field} must be {expected!r}")
    return checker


def _check_version(scenario: str, field: str, value: Any) -> None:
    if (not isinstance(value, str) or len(value) != VERSION_LENGTH
            or value[8] != "." or not value[:8].isdigit()
            or not value[9:].isdigit()):
        raise EvidenceError(f"{scenario}: {field} must be a YYYYMMDD.NNN version")


def _check_nonempty_reasons(scenario: str, field: str, value: Any) -> None:
    if (not isinstance(value, list) or not value
            or not all(isinstance(item, str) and item for item in value)):
        raise EvidenceError(
            f"{scenario}: {field} must be a non-empty list of reasons")


# Provable-in-loopback specs and the extra live-boot specs, per scenario.
PROVABLE_SPECS: dict[str, tuple[tuple[str, Any], ...]] = {
    # ADR 0068: PXE through the private boot FQDN and digest-manifested
    # releases, identity discovered only via AD DNS SRV, never a stale-snapshot
    # rollback.
    "controller-restart": (
        ("stable_service_discovery", _check_true),
        ("identity_survives_migration", _check_true),
        ("no_stale_snapshot_rollback", _check_true),
    ),
    "pxe-release-rollback": (
        ("prior_version", _check_version),
        ("current_version", _check_version),
        ("rolled_back", _check_true),
        ("prior_manifest_verified", _check_true),
        ("prior_manifest_served", _check_true),
        ("transactional", _check_true),
    ),
    "failed-install-recovery": (
        ("overlay_isolated", _check_true),
        ("canonical_unchanged", _check_true),
        ("writes_confined_to_overlay", _check_true),
        ("re_mintable", _check_true),
    ),
    "broken-boot-repair": (
        ("linux_entry", _equals(NVRAM_LINUX_LABEL)),
        ("windows_entry", _equals(NVRAM_WINDOWS_LABEL)),
        ("independent_uefi_entries", _check_true),
    ),
    "directory-dns-loss": (
        ("fault_injection", _equals("SIGSTOP")),
        ("cached_login_policy", _check_true),
        ("offline_credentials_expiration", _check_zero),
    ),
    # ADR 0075: no automatic image rollback; a failed gate is a safe deferral
    # with no partial change, and recovery is the independently bootable
    # linux-lts fallback.
    "update-failure-rollback": (
        ("operation", _equals(UPDATE_OPERATION)),
        ("automatic_rollback", _check_false),
        ("failed_gate_defers", _check_true),
        ("deferral_reasons", _check_nonempty_reasons),
        ("no_partial_change", _check_true),
        ("lts_fallback_present", _check_true),
    ),
    "workstation-remint": (
        ("disposable_destroyed", _check_true),
        ("clean_inputs_verified", _check_true),
        ("reminted", _check_true),
        ("canonical_unchanged", _check_true),
        ("no_destructive_change", _check_true),
    ),
    "controller-reconstruction": (
        ("public_inputs_verified", _check_true),
        ("synthetic_private_overlay", _check_true),
        ("seed_verified", _check_true),
        ("reconstruction_plan_complete", _check_true),
    ),
}

LIVE_SPECS: dict[str, tuple[tuple[str, Any], ...]] = {
    "controller-restart": (
        ("controller_restarted", _check_true),
        ("dependent_proof_resolved", _check_true),
    ),
    "failed-install-recovery": (
        ("install_failed_as_designed", _check_true),
        ("disk_recoverable", _check_true),
    ),
    "broken-boot-repair": (
        ("bootloader_repaired", _check_true),
    ),
    "directory-dns-loss": (
        ("controller_frozen", _check_true),
        ("cached_operation_continued", _check_true),
        ("directory_restored", _check_true),
    ),
    "controller-reconstruction": (
        ("converged_from_public_inputs", _check_true),
    ),
}


def _validate_scenario(
        scenario: str, event: dict[str, Any], *, passed: bool) -> None:
    specs = PROVABLE_SPECS[scenario] + LIVE_SPECS.get(scenario, ())
    for field, checker in specs:
        if field in event:
            checker(scenario, field, event[field])
        elif passed:
            raise EvidenceError(
                f"{scenario}: a passing scenario must record {field}")
    if (scenario == "pxe-release-rollback"
            and "prior_version" in event and "current_version" in event
            and not event["prior_version"] < event["current_version"]):
        raise EvidenceError(
            f"{scenario}: prior_version must precede current_version")


def judge(
        contract: dict[str, Any],
        events: list[dict[str, Any]]) -> dict[str, Any]:
    errors = validate_contract(contract)
    if errors:
        raise EvidenceError("invalid contract: " + "; ".join(errors))
    required = contract["required_checks"]

    seen: dict[str, dict[str, Any]] = {}
    for index, event in enumerate(events):
        check = event.get("check")
        if check in seen:
            raise EvidenceError(f"duplicate evidence for {check}")
        if event.get("external_access") is not False:
            raise EvidenceError(
                f"event {check or index} does not prove external_access=false")
        if check in required:
            seen[check] = event

    missing = [check for check in required if check not in seen]
    if missing:
        raise EvidenceError("missing evidence: " + ", ".join(missing))

    deferred: list[str] = []
    for scenario in required:
        event = seen[scenario]
        result = event.get("result")
        if result not in ("pass", "not-run"):
            # A "fail" or any unrecognized result is never promoted to a pass.
            raise EvidenceError(
                f"{scenario}: result must be 'pass' or a deferred 'not-run', "
                f"not {result!r}")
        if result == "not-run":
            reason = event.get("deferred_reason")
            if not isinstance(reason, str) or not reason:
                raise EvidenceError(
                    f"{scenario}: a not-run scenario must record a "
                    "deferred_reason")
            deferred.append(scenario)
        # Every recorded field is validated fail-closed; a passing scenario
        # must additionally record every provable and live field it owns.
        _validate_scenario(scenario, event, passed=(result == "pass"))

    return {
        "schema_version": 1,
        "result": "pass" if not deferred else "partial",
        "checks": len(required),
        "external_access": False,
        "deferred": deferred,
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
        print(f"lifecycle recovery: {error}", file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True))
    # A partial verdict is honest deferral, not a failure: like the gate-12
    # verifier's NOT-RUN, it exits zero but never claims a completed pass.
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
