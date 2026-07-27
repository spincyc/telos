#!/usr/bin/env python3
"""Fail-closed checks for the controller's first UniFi attachment."""

from __future__ import annotations

import argparse
import ipaddress
import json
import re
import subprocess
import sys
from dataclasses import dataclass

PROHIBITED_PORTS = {53, 67, 69, 80, 4011}
PROHIBITED_UNITS = (
    "dnsmasq.service",
    "dnsmasq-homelab.service",
    "samba.service",
    "smb.service",
    "nmb.service",
    "nginx.service",
    "nginx-homelab.service",
)


@dataclass(frozen=True)
class Listener:
    protocol: str
    address: str
    port: int


def run(*argv: str) -> str:
    return subprocess.run(
        argv, check=True, text=True, stdout=subprocess.PIPE
    ).stdout


def interface_addresses(ip_data: list[dict], interface: str) -> set[str]:
    for link in ip_data:
        if link.get("ifname") == interface:
            return {
                f"{item['local']}/{item['prefixlen']}"
                for item in link.get("addr_info", [])
                if item.get("family") == "inet"
            }
    return set()


def default_gateways(route_data: list[dict], interface: str) -> set[str]:
    return {
        route["gateway"]
        for route in route_data
        if route.get("dst") == "default"
        and route.get("dev") == interface
        and "gateway" in route
    }


def parse_resolvers(text: str, interface: str) -> set[str]:
    for line in text.splitlines():
        if re.match(rf"^Link \d+ \({re.escape(interface)}\):", line):
            _, _, values = line.partition(":")
            return set(values.split())
    return set()


def parse_listeners(text: str) -> list[Listener]:
    listeners = []
    for line in text.splitlines():
        fields = line.split()
        if len(fields) < 5:
            continue
        endpoint, separator, port_text = fields[4].rpartition(":")
        if not separator or not port_text.isdigit():
            continue
        listeners.append(
            Listener(
                fields[0],
                endpoint.removeprefix("[").removesuffix("]"),
                int(port_text),
            )
        )
    return listeners


def prohibited_listeners(listeners: list[Listener]) -> list[Listener]:
    return [item for item in listeners if item.port in PROHIBITED_PORTS]


def check_units(states: dict[str, tuple[str, str]]) -> list[str]:
    failures = []
    for unit, (enabled, active) in states.items():
        if enabled not in {"disabled", "masked", "not-found"}:
            failures.append(f"{unit} is {enabled}, expected disabled or masked")
        if active != "inactive":
            failures.append(f"{unit} is {active}, expected inactive")
    return failures


def unit_state(unit: str) -> tuple[str, str]:
    def systemctl(verb: str) -> str:
        result = subprocess.run(
            ("systemctl", verb, unit),
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
        )
        return result.stdout.strip() or ("not-found" if verb == "is-enabled" else "inactive")

    return systemctl("is-enabled"), systemctl("is-active")


def ping(host: str) -> bool:
    return subprocess.run(
        ("ping", "-n", "-c", "1", "-W", "2", host),
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    ).returncode == 0


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--interface", required=True)
    parser.add_argument("--address", required=True, help="reserved IPv4 address/prefix")
    parser.add_argument("--gateway", required=True)
    parser.add_argument("--dns", action="append", required=True)
    parser.add_argument("--allow", action="append", default=[])
    parser.add_argument("--deny", action="append", default=[])
    args = parser.parse_args()

    expected_address = str(ipaddress.ip_interface(args.address))
    expected_gateway = str(ipaddress.ip_address(args.gateway))
    expected_dns = {str(ipaddress.ip_address(value)) for value in args.dns}
    failures = []

    addresses = interface_addresses(
        json.loads(run("ip", "-j", "-4", "address", "show")), args.interface
    )
    if addresses != {expected_address}:
        failures.append(f"address is {sorted(addresses)}, expected {expected_address}")

    gateways = default_gateways(
        json.loads(run("ip", "-j", "-4", "route", "show")), args.interface
    )
    if gateways != {expected_gateway}:
        failures.append(f"gateway is {sorted(gateways)}, expected {expected_gateway}")

    resolvers = parse_resolvers(run("resolvectl", "dns"), args.interface)
    if resolvers != expected_dns:
        failures.append(
            f"DNS is {sorted(resolvers)}, expected {sorted(expected_dns)}"
        )

    states = {unit: unit_state(unit) for unit in PROHIBITED_UNITS}
    failures.extend(check_units(states))

    listeners = parse_listeners(run("ss", "-H", "-n", "-lntu"))
    for item in prohibited_listeners(listeners):
        failures.append(
            f"prohibited listener: {item.protocol} {item.address}:{item.port}"
        )

    for host in args.allow:
        if not ping(host):
            failures.append(f"required destination is unreachable: {host}")
    for host in args.deny:
        if ping(host):
            failures.append(f"forbidden destination is reachable: {host}")

    if failures:
        for failure in failures:
            print(f"FAIL {failure}")
        return 1

    print("PASS reserved address, route, DNS, service state, listeners and reachability")
    print("REQUIRED EXTERNAL CHECK: capture DHCP discovery from a second client")
    print("REQUIRED EXTERNAL CHECK: verify its lease, gateway and DNS all name UniFi")
    print("REQUIRED EXTERNAL CHECK: power off this VM and renew that client's lease")
    return 0


if __name__ == "__main__":
    sys.exit(main())
