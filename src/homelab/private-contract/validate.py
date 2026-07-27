#!/usr/bin/env python3
"""Dependency-free checks for the Telos private homelab instance contract."""

from __future__ import annotations

import argparse
import ipaddress
import json
import re
import sys
from pathlib import Path

CONTRACT_VERSION = 1
SECRET_WORDS = {
    "password", "passwd", "passphrase", "private_key", "keytab", "token",
    "recovery_key", "wifi_password", "psk",
}
SECRET_REF = re.compile(r"^(sops|pass|vault|systemd-creds)://\S+$")
MAC = re.compile(r"^[0-9a-f]{2}(?::[0-9a-f]{2}){5}$", re.I)


def require(condition: bool, message: str, errors: list[str]) -> None:
    if not condition:
        errors.append(message)


def validate(data: object) -> list[str]:
    errors: list[str] = []
    require(isinstance(data, dict), "root must be an object", errors)
    if not isinstance(data, dict):
        return errors

    def scan_keys(value: object, path: str = "$") -> None:
        if isinstance(value, dict):
            for key, child in value.items():
                if key.lower() in SECRET_WORDS:
                    errors.append(f"{path}.{key}: plaintext-secret field is forbidden")
                scan_keys(child, f"{path}.{key}")
        elif isinstance(value, list):
            for index, child in enumerate(value):
                scan_keys(child, f"{path}[{index}]")

    scan_keys(data)
    required = {"contract_version", "site", "identity", "services", "networks",
                "people", "machines", "secret_refs"}
    require(required <= data.keys(), f"missing keys: {sorted(required - data.keys())}", errors)
    require(data.get("contract_version") == CONTRACT_VERSION,
            f"contract_version must be {CONTRACT_VERSION}", errors)

    domain = data.get("identity", {}).get("dns_domain")
    services = data.get("services", {})
    require(isinstance(services, dict), "services must be an object", errors)
    service_names: list[str] = []
    if isinstance(services, dict):
        for key in ("bootstrap_dc_fqdn", "permanent_dc_fqdn", "boot_fqdn"):
            value = services.get(key)
            require(isinstance(value, str) and isinstance(domain, str) and
                    value.endswith("." + domain),
                    f"services.{key}: must be beneath the identity domain", errors)
            if isinstance(value, str):
                service_names.append(value)
        require(len(service_names) == len(set(service_names)),
                "service FQDNs must be distinct", errors)

    networks = data.get("networks", [])
    require(isinstance(networks, list) and bool(networks),
            "networks must be a nonempty array", errors)
    network_by_id: dict[str, ipaddress.IPv4Network] = {}
    vlans: set[int] = set()
    if isinstance(networks, list):
        for index, item in enumerate(networks):
            path = f"networks[{index}]"
            if not isinstance(item, dict):
                errors.append(f"{path}: must be an object")
                continue
            network_id = item.get("id")
            require(isinstance(network_id, str) and network_id not in network_by_id,
                    f"{path}.id: must be a unique string", errors)
            vlan = item.get("vlan")
            require(isinstance(vlan, int) and 1 <= vlan <= 4094 and vlan not in vlans,
                    f"{path}.vlan: must be a unique integer from 1 through 4094", errors)
            if isinstance(vlan, int):
                vlans.add(vlan)
            try:
                subnet = ipaddress.ip_network(item.get("cidr"), strict=True)
                require(isinstance(subnet, ipaddress.IPv4Network),
                        f"{path}.cidr: IPv4 is required", errors)
                for field, address in (
                    ("gateway", item.get("gateway")),
                    ("dhcp.first", item.get("dhcp", {}).get("first")),
                    ("dhcp.last", item.get("dhcp", {}).get("last")),
                ):
                    require(ipaddress.ip_address(address) in subnet,
                            f"{path}.{field}: must be inside {subnet}", errors)
                first = ipaddress.ip_address(item["dhcp"]["first"])
                last = ipaddress.ip_address(item["dhcp"]["last"])
                require(first <= last, f"{path}.dhcp: first must not exceed last", errors)
                if isinstance(network_id, str):
                    network_by_id[network_id] = subnet
            except (KeyError, TypeError, ValueError) as exc:
                errors.append(f"{path}: invalid network: {exc}")
            if "wifi_secret_ref" in item:
                require(bool(SECRET_REF.fullmatch(str(item["wifi_secret_ref"]))),
                        f"{path}.wifi_secret_ref: must be an encrypted-store reference", errors)

    people = data.get("people", [])
    accounts = [item.get("account") for item in people if isinstance(item, dict)] \
        if isinstance(people, list) else []
    require(len(accounts) == len(set(accounts)), "people accounts must be unique", errors)

    machines = data.get("machines", [])
    hostnames = [item.get("hostname") for item in machines if isinstance(item, dict)] \
        if isinstance(machines, list) else []
    require(len(hostnames) == len(set(hostnames)), "machine hostnames must be unique", errors)
    if isinstance(machines, list):
        for index, machine in enumerate(machines):
            if not isinstance(machine, dict):
                errors.append(f"machines[{index}]: must be an object")
                continue
            path = f"machines[{index}]"
            network_id = machine.get("network")
            require(network_id in network_by_id,
                    f"{path}.network: must reference a declared network", errors)
            if "ipv4" in machine and network_id in network_by_id:
                try:
                    require(ipaddress.ip_address(machine["ipv4"]) in network_by_id[network_id],
                            f"{path}.ipv4: must be inside its network", errors)
                except ValueError as exc:
                    errors.append(f"{path}.ipv4: {exc}")
            macs = machine.get("mac_addresses")
            require(isinstance(macs, list) and bool(macs) and
                    all(isinstance(mac, str) and MAC.fullmatch(mac) for mac in macs),
                    f"{path}.mac_addresses: one or more colon-separated MACs required", errors)

    refs = data.get("secret_refs", {})
    require(isinstance(refs, dict) and
            all(isinstance(value, str) and SECRET_REF.fullmatch(value)
                for value in refs.values()),
            "secret_refs values must be encrypted-store references", errors)
    return errors


def redacted_review(data: dict) -> dict:
    return {
        "contract_version": data.get("contract_version"),
        "site": {
            "label": "<configured>" if data.get("site", {}).get("label") else None,
            "timezone": data.get("site", {}).get("timezone"),
        },
        "identity": {
            "dns_domain": "<configured>"
            if data.get("identity", {}).get("dns_domain") else None,
            "kerberos_realm": "<configured>"
            if data.get("identity", {}).get("kerberos_realm") else None,
            "netbios_name": "<configured>"
            if data.get("identity", {}).get("netbios_name") else None,
        },
        "services": {
            key: "<configured>" if value else None
            for key, value in data.get("services", {}).items()
        },
        "networks": [
            {
                "id": item.get("id"),
                "purpose": item.get("purpose"),
                "vlan": item.get("vlan"),
                "cidr": "<configured>" if item.get("cidr") else None,
                "ssid": "<redacted>" if item.get("ssid") else None,
                "wifi_secret_ref": "<configured>" if item.get("wifi_secret_ref") else None,
            }
            for item in data.get("networks", [])
        ],
        "people": {"count": len(data.get("people", []))},
        "machines": {
            "count": len(data.get("machines", [])),
            "roles": sorted(item.get("role") for item in data.get("machines", [])),
        },
        "secret_refs": sorted(data.get("secret_refs", {}).keys()),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--review", action="store_true")
    parser.add_argument("instance", type=Path)
    args = parser.parse_args()
    try:
        data = json.loads(args.instance.read_text())
    except (OSError, json.JSONDecodeError) as exc:
        print(f"{args.instance}: {exc}", file=sys.stderr)
        return 2
    errors = validate(data)
    if errors:
        for error in errors:
            print(f"error: {error}", file=sys.stderr)
        return 1
    print(json.dumps(redacted_review(data), indent=2) if args.review else
          f"{args.instance}: valid contract version {CONTRACT_VERSION}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
