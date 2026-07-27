"""Deterministic policy and counters for the guest-only network simulation."""

from __future__ import annotations

import ipaddress
from collections import Counter
from dataclasses import dataclass

PRIVATE_NETWORKS = tuple(
    ipaddress.ip_network(value)
    for value in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")
)


@dataclass(frozen=True)
class Flow:
    protocol: str
    destination: str
    port: int | None = None


@dataclass(frozen=True)
class Decision:
    allowed: bool
    rule: str


class SimulatedFirewall:
    """Minimal egress policy with one counter for every terminal rule."""

    def __init__(
        self,
        *,
        gateway: str,
        dns: str,
        ntp: str = "198.51.100.10",
        update_addresses: frozenset[str],
        household_networks: tuple[str, ...],
    ) -> None:
        self.gateway = ipaddress.ip_address(gateway)
        self.dns = ipaddress.ip_address(dns)
        self.ntp = ipaddress.ip_address(ntp)
        self.update_addresses = frozenset(
            ipaddress.ip_address(value) for value in update_addresses
        )
        self.household_networks = tuple(
            ipaddress.ip_network(value) for value in household_networks
        )
        self.counters: Counter[str] = Counter()

    def decide(self, flow: Flow) -> Decision:
        protocol = flow.protocol.lower()
        destination = ipaddress.ip_address(flow.destination)

        if destination == self.gateway and protocol == "icmp":
            return self._count(True, "allow-gateway")
        if (
            destination == self.dns
            and protocol in {"udp", "tcp"}
            and flow.port == 53
        ):
            return self._count(True, "allow-dns")
        if (
            destination in self.update_addresses
            and protocol == "tcp"
            and flow.port == 443
        ):
            return self._count(True, "allow-update")
        if destination == self.ntp and protocol == "udp" and flow.port == 123:
            return self._count(True, "allow-ntp")
        if any(destination in network for network in self.household_networks):
            return self._count(False, "deny-household")
        if any(destination in network for network in PRIVATE_NETWORKS):
            return self._count(False, "deny-private")
        return self._count(False, "deny-default")

    def _count(self, allowed: bool, rule: str) -> Decision:
        self.counters[rule] += 1
        return Decision(allowed, rule)

    def report(self) -> tuple[str, ...]:
        rules = (
            "allow-gateway",
            "allow-dns",
            "allow-update",
            "allow-ntp",
            "deny-household",
            "deny-private",
            "deny-default",
        )
        return tuple(f"{rule} packets={self.counters[rule]}" for rule in rules)


def acceptance_probe_matrix(
    *,
    gateway: str = "10.1.31.1",
    dns: str = "10.1.31.1",
    update_address: str = "198.51.100.11",
    ntp: str = "198.51.100.10",
) -> tuple[tuple[Flow, Decision], ...]:
    """Exact positive and negative probes required by the simulation."""
    return (
        (Flow("icmp", gateway), Decision(True, "allow-gateway")),
        (Flow("udp", dns, 53), Decision(True, "allow-dns")),
        (Flow("tcp", dns, 53), Decision(True, "allow-dns")),
        (Flow("tcp", update_address, 443), Decision(True, "allow-update")),
        (Flow("udp", ntp, 123), Decision(True, "allow-ntp")),
        (Flow("tcp", ntp, 123), Decision(False, "deny-default")),
        (Flow("udp", ntp, 124), Decision(False, "deny-default")),
        (Flow("tcp", update_address, 80), Decision(False, "deny-default")),
        (Flow("icmp", "10.0.0.1"), Decision(False, "deny-household")),
        (Flow("tcp", "10.0.7.254", 443), Decision(False, "deny-household")),
        (Flow("icmp", "10.2.1.1"), Decision(False, "deny-private")),
        (Flow("tcp", "172.16.1.1", 443), Decision(False, "deny-private")),
        (Flow("tcp", "192.168.1.1", 443), Decision(False, "deny-private")),
        (Flow("tcp", "203.0.113.10", 443), Decision(False, "deny-default")),
    )


def verify_acceptance(firewall: SimulatedFirewall) -> tuple[str, ...]:
    failures = []
    for flow, expected in acceptance_probe_matrix(
        gateway=str(firewall.gateway),
        dns=str(firewall.dns),
        update_address=str(sorted(firewall.update_addresses)[0]),
        ntp=str(firewall.ntp),
    ):
        actual = firewall.decide(flow)
        if actual != expected:
            failures.append(f"{flow}: got {actual}, expected {expected}")
    return tuple(failures)
