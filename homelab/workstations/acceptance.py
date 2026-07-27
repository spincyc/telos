#!/usr/bin/env python3
"""Validate and render the cross-OS workstation acceptance contract."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

CONTRACT = Path(__file__).with_name("acceptance.json")
EXAMPLE_INSTANCE = Path(__file__).with_name("acceptance-instance.example.json")
CHECK_FIELDS = (
    "id",
    "os",
    "category",
    "actor",
    "precondition",
    "action",
    "expected",
    "pass",
    "failure",
    "evidence",
    "commands",
)
OPERATING_SYSTEMS = {"windows", "arch"}
STORAGE_STATES = {"available", "unreachable", "denied"}


def load_contract(path: Path = CONTRACT) -> dict[str, Any]:
    with path.open(encoding="utf-8") as source:
        value = json.load(source)
    if not isinstance(value, dict):
        raise ValueError("contract root must be an object")
    return value


def load_instance(path: Path) -> dict[str, str]:
    with path.open(encoding="utf-8") as source:
        value = json.load(source)
    if not isinstance(value, dict) or not all(
        isinstance(key, str) and isinstance(item, str) and item
        for key, item in value.items()
    ):
        raise ValueError("instance inputs must be a string-to-string object")
    return value


def instantiate(node: Any, inputs: dict[str, str]) -> Any:
    """Replace public role variables with private instance values."""
    if isinstance(node, dict):
        return {
            instantiate(key, inputs): instantiate(value, inputs)
            for key, value in node.items()
        }
    if isinstance(node, list):
        return [instantiate(value, inputs) for value in node]
    if not isinstance(node, str):
        return node
    rendered = node
    for key, value in inputs.items():
        rendered = rendered.replace("{{" + key + "}}", value)
    if "{{" in rendered or "}}" in rendered:
        raise ValueError(f"unresolved instance variable in {node!r}")
    return rendered


def contract_errors(contract: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    identity = contract.get("identity", {})
    for key in ("dns_domain", "kerberos_realm", "netbios_domain", "storage_host"):
        if not isinstance(identity.get(key), str) or not identity[key]:
            errors.append(f"identity.{key} must be a non-empty string")

    expected_principals = {
        "daily_administrator": ("domain", "administrator", "user"),
        "domain_administrator": ("domain", "administrator", "administrator"),
        "standard_user": ("domain", "standard", "user"),
        "local_rescue": ("local", "administrator", "none"),
    }
    principals = contract.get("principals", {})
    for name, (scope, workstation_role, domain_role) in expected_principals.items():
        principal = principals.get(name, {})
        if not isinstance(principal.get("name"), str) or not principal["name"]:
            errors.append(f"principals.{name}.name must be a non-empty string")
        expected = {
            "scope": scope,
            "workstation_role": workstation_role,
            "domain_role": domain_role,
        }
        for key, value in expected.items():
            if principal.get(key) != value:
                errors.append(f"principals.{name}.{key} must be {value!r}")

    limitations = contract.get("accepted_limitations", [])
    offline = [item for item in limitations if item.get("id") == "offline-revocation"]
    if len(offline) != 1 or "indefinitely" not in offline[0].get("statement", ""):
        errors.append("accepted_limitations must state indefinite offline cached login")

    checks = contract.get("checks")
    if not isinstance(checks, list):
        return errors + ["checks must be an array"]
    seen: set[str] = set()
    for index, check in enumerate(checks):
        if not isinstance(check, dict):
            errors.append(f"checks[{index}] must be an object")
            continue
        for field in CHECK_FIELDS:
            value = check.get(field)
            if not value:
                errors.append(f"checks[{index}].{field} is required")
        check_id = check.get("id")
        if check_id in seen:
            errors.append(f"duplicate check id: {check_id}")
        elif isinstance(check_id, str):
            seen.add(check_id)
        if check.get("os") not in OPERATING_SYSTEMS:
            errors.append(f"{check_id or index}: os must be arch or windows")
        commands = check.get("commands")
        if commands is not None and (
            not isinstance(commands, list)
            or not all(isinstance(command, str) and command for command in commands)
        ):
            errors.append(f"{check_id or index}: commands must be non-empty strings")

    for os_name in OPERATING_SYSTEMS:
        os_checks = [check for check in checks if check.get("os") == os_name]
        categories = {check.get("category") for check in os_checks}
        required = {"identity", "authorization", "recovery", "offline", "optional-storage"}
        for category in sorted(required - categories):
            errors.append(f"{os_name}: missing {category} check")
        storage_ids = {
            check.get("id", "").removeprefix(f"{os_name}-smb-")
            for check in os_checks
            if check.get("category") == "optional-storage"
        }
        for state in sorted(STORAGE_STATES - storage_ids):
            errors.append(f"{os_name}: missing SMB {state} check")
    return errors


def selected_checks(
    contract: dict[str, Any], os_name: str, include_storage: bool
) -> list[dict[str, Any]]:
    return [
        check
        for check in contract["checks"]
        if (os_name == "all" or check["os"] == os_name)
        and (include_storage or check["category"] != "optional-storage")
    ]


def render_text(checks: list[dict[str, Any]]) -> str:
    sections: list[str] = []
    for number, check in enumerate(checks, 1):
        commands = "\n".join(f"      $ {command}" for command in check["commands"])
        sections.append(
            f"{number}. [{check['os'].upper()}] {check['id']}\n"
            f"   Before: {check['precondition']}\n"
            f"   Do: {check['action']}\n"
            f"   Expect: {check['expected']}\n"
            f"   Pass: {check['pass']}\n"
            f"   If not: {check['failure']}\n"
            f"   Record: {check['evidence']}\n"
            f"   Suggested commands:\n{commands}"
        )
    return "\n\n".join(sections)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--contract", type=Path, default=CONTRACT)
    parser.add_argument("--instance", type=Path, default=EXAMPLE_INSTANCE)
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("validate")
    checklist = subparsers.add_parser("checklist")
    checklist.add_argument("--os", choices=["all", "windows", "arch"], default="all")
    checklist.add_argument("--include-storage", action="store_true")
    checklist.add_argument("--format", choices=["text", "json"], default="text")
    args = parser.parse_args(argv)

    try:
        contract = instantiate(
            load_contract(args.contract), load_instance(args.instance)
        )
    except (OSError, json.JSONDecodeError, ValueError) as error:
        print(f"acceptance contract: {error}", file=sys.stderr)
        return 2
    errors = contract_errors(contract)
    if errors:
        for error in errors:
            print(f"acceptance contract: {error}", file=sys.stderr)
        return 1
    if args.command == "validate":
        print(f"acceptance contract: {len(contract['checks'])} checks valid")
        return 0

    checks = selected_checks(contract, args.os, args.include_storage)
    if args.format == "json":
        print(json.dumps(checks, indent=2))
    else:
        print(render_text(checks))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
