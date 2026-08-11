#!/usr/bin/env python3
"""Judge ordered, local-only gate-10 dual-boot acceptance evidence.

Mirrors ``identity_lifecycle.py``: a contract JSON names the required checks
and boot policy, the producer emits one JSONL event per check, and this judge
refuses the gate unless every required check passed with the exact fields
that make its claim honest.  A producer that could not prove a check emits
``fail`` or ``not-run`` and this judge rejects the stream rather than ever
upgrading an observation.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Iterable

CONTRACT = Path(__file__).with_name("dualboot_acceptance.json")

REQUIRED_CHECKS = (
    "windows-default-boot",
    "five-second-policy",
    "arch-menu-selectable",
    "arch-console-login-surface",
    "efi-entries-intact",
    "partitions-unchanged",
    "evidence-complete",
)
DEFERRED_IDS = ("windows-login-driven", "arch-authenticated-login")
_HEX64 = frozenset("0123456789abcdef")


class EvidenceError(ValueError):
    """Evidence does not prove the dual-boot acceptance contract."""


def load_json(path: Path) -> Any:
    with path.open(encoding="utf-8") as source:
        return json.load(source)


def _is_number(value: Any) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def validate_contract(contract: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    if contract.get("schema_version") != 1:
        errors.append("schema_version must be 1")
    policy = contract.get("network_policy", {})
    if policy != {"mode": "local-only", "external_access": "forbidden"}:
        errors.append("network_policy must forbid external access")
    boot = contract.get("boot_policy", {})
    if boot.get("firmware") != "uefi" or boot.get("partition_table") != "gpt":
        errors.append("boot_policy must pin UEFI firmware over GPT")
    if boot.get("default_os") != "windows":
        errors.append("boot_policy.default_os must be windows")
    if boot.get("menu_timeout_seconds") != 5:
        errors.append("boot_policy.menu_timeout_seconds must be 5")
    bounds = boot.get("measured_handoff_bounds_seconds")
    if (
        not isinstance(bounds, list) or len(bounds) != 2
        or not all(_is_number(item) for item in bounds)
        or not 0 < bounds[0] <= 5 <= bounds[1]
    ):
        errors.append(
            "measured_handoff_bounds_seconds must bracket the 5-second policy")
    checks = contract.get("required_checks")
    if checks != list(REQUIRED_CHECKS):
        errors.append(
            "required_checks must be exactly the ordered gate-10 checks")
    deferred = contract.get("deferred_checks", [])
    for identifier in DEFERRED_IDS:
        matches = [
            item for item in deferred if item.get("id") == identifier]
        if len(matches) != 1 or matches[0].get("phase", 0) < 2:
            errors.append(
                f"{identifier} must be explicitly deferred to phase 2 or later")
        elif not matches[0].get("reason"):
            errors.append(f"{identifier} deferral must state its reason")
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


def _sha256_text(value: Any) -> bool:
    return (
        isinstance(value, str) and len(value) == 64
        and set(value) <= _HEX64
    )


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
            raise EvidenceError(
                f"event {check or index} does not prove external_access=false")
        if event.get("result") != "pass":
            raise EvidenceError(
                f"event {check or index} did not pass: "
                f"result={event.get('result')!r}")
    missing = [check for check in required if check not in positions]
    if missing:
        raise EvidenceError("missing evidence: " + ", ".join(missing))
    if [positions[item] for item in required] != sorted(positions.values()):
        raise EvidenceError("dual-boot evidence is out of order")

    by_check = {
        event["check"]: event for event in events
        if event.get("check") in required
    }
    boot_policy = contract["boot_policy"]

    default = by_check["windows-default-boot"]
    if default.get("default_os") != boot_policy["default_os"]:
        raise EvidenceError("default boot did not target the policy OS")
    if default.get("input_sent") is not False:
        raise EvidenceError("default boot must receive no input")
    if default.get("linux_handoff_observed") is not False:
        raise EvidenceError("default boot handed off to Linux, not Windows")
    if default.get("windows_menu_listed") is not True:
        raise EvidenceError("boot menu did not list the Windows entry")
    if default.get("guest_running") is not True:
        raise EvidenceError("Windows guest was not proven running")
    observation = default.get("observation")
    if observation not in ("boot-observed", "login-proven"):
        raise EvidenceError("default boot observation level is unknown")
    login_proven = default.get("login_proven")
    if login_proven is not (observation == "login-proven"):
        raise EvidenceError(
            "login_proven contradicts the recorded observation level")
    frames = default.get("frames_retained")
    if not isinstance(frames, int) or isinstance(frames, bool) or frames < 1:
        raise EvidenceError("default boot retained no framebuffer evidence")

    five = by_check["five-second-policy"]
    if five.get("policy_seconds") != boot_policy["menu_timeout_seconds"]:
        raise EvidenceError("five-second policy value differs from contract")
    if five.get("input_sent") is not False:
        raise EvidenceError("five-second measurement was contaminated by input")
    measured = five.get("measured_seconds")
    low, high = boot_policy["measured_handoff_bounds_seconds"]
    if not _is_number(measured) or not low <= measured <= high:
        raise EvidenceError(
            "measured menu-to-handoff time is outside the policy bounds")

    selectable = by_check["arch-menu-selectable"]
    if selectable.get("selection_method") != "menu-digit":
        raise EvidenceError("Arch selection method is not the proven one")
    entry = selectable.get("entry")
    if not isinstance(entry, str) or not entry.startswith("Arch"):
        raise EvidenceError("selected entry is not the Arch entry")
    if selectable.get("kernel_handoff") is not True:
        raise EvidenceError("Arch selection did not reach a kernel handoff")

    surface = by_check["arch-console-login-surface"]
    if surface.get("login_prompt_observed") is not True:
        raise EvidenceError("Arch ttyS0 login surface was not observed")
    if surface.get("login_driven") is not False:
        raise EvidenceError(
            "authenticated Arch login is deferred; evidence must not claim it")

    entries = by_check["efi-entries-intact"]
    if entries.get("method") not in ("systemd-boot-menu", "efibootmgr"):
        raise EvidenceError("EFI entry enumeration method is unknown")
    for name in ("windows_entry", "arch_entry", "recovery_choice"):
        if entries.get(name) is not True:
            raise EvidenceError(f"EFI boot choice missing: {name}")

    partitions = by_check["partitions-unchanged"]
    baseline = partitions.get("baseline_sha256")
    post = partitions.get("post_sha256")
    if not _sha256_text(baseline) or not _sha256_text(post):
        raise EvidenceError("partition-table digests are malformed")
    if baseline != post or partitions.get("byte_identical") is not True:
        raise EvidenceError("partition table changed across the boots")
    if partitions.get("roles_verified") is not True:
        raise EvidenceError("partition roles were not re-verified post-boot")

    complete = by_check["evidence-complete"]
    boots = complete.get("serial_boots")
    if not isinstance(boots, int) or isinstance(boots, bool) or boots < 2:
        raise EvidenceError("both cold boots must retain serial transcripts")
    total_frames = complete.get("frames")
    if (not isinstance(total_frames, int) or isinstance(total_frames, bool)
            or total_frames < 1):
        raise EvidenceError("framebuffer evidence was not retained")
    if complete.get("gpt_verified") is not True:
        raise EvidenceError("post-boot GPT verification was not recorded")

    return {
        "schema_version": 1,
        "result": "pass",
        "checks": len(required),
        "external_access": False,
        "windows_login_proven": bool(login_proven),
        "deferred": list(DEFERRED_IDS),
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
        print(f"dual-boot acceptance: {error}", file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
