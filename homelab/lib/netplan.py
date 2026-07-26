"""Controller managed-network plan: parse, validate, derive.

This is ADR 0045 as executable code. That ADR specifies four operator inputs,
five derived values, and seven validation rules, and it requires the complete
entered-and-derived plan to appear in the preflight summary before any
destructive authorization. The previous design recorded all of that in prose and
never implemented it, which is exactly the gap where a bad netmask or an
in-pool Controller address reaches dnsmasq.

Nothing here touches a disk, a network interface, or a running service. It is
pure computation over strings so that it can be exhaustively tested, and so the
installer can call it long before it asks anyone to authorize a wipe.

Deliberate strictness, beyond what ipaddress gives for free:

  * An address must be exactly four dotted decimal octets with no leading zeros.
    "10.0.010.1" is octal in some parsers and decimal in others; a provisioning
    tool must not be one of the ambiguous ones.
  * A CIDR must name the network address itself. "10.0.7.5/24" is rejected
    rather than silently normalised to 10.0.7.0/24, because an operator who
    typed it may have meant something else.
  * "Usable" excludes the network and broadcast addresses. For /31 and /32
    there are no usable host addresses under that definition, and a plan that
    needs a Controller plus a DHCP pool cannot fit in one anyway.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field

# ADR 0005 fixes the internal suffix; it is derived, never prompted for.
DNS_SUFFIX = "home.arpa"

# Exactly four dotted decimal octets, each 0-255, no leading zeros.
_OCTET = r"(?:0|[1-9]\d{0,2})"
_IPV4_RE = re.compile(rf"^{_OCTET}\.{_OCTET}\.{_OCTET}\.{_OCTET}$")

INPUT_FIELDS = (
    "managed_ipv4_cidr",
    "controller_ipv4_address",
    "dhcp_pool_start",
    "dhcp_pool_end",
)


class NetworkPlanError(ValueError):
    """A managed-network plan that must not reach dnsmasq or a partitioner."""


@dataclass(frozen=True)
class NetworkPlan:
    """A validated plan plus every value ADR 0045 says to derive."""

    managed_ipv4_cidr: str
    controller_ipv4_address: str
    dhcp_pool_start: str
    dhcp_pool_end: str

    network_address: str = field(default="")
    broadcast_address: str = field(default="")
    netmask: str = field(default="")
    prefix_length: int = field(default=0)
    dns_server: str = field(default="")
    dns_suffix: str = field(default=DNS_SUFFIX)
    default_router: None = field(default=None)
    pool_size: int = field(default=0)
    usable_addresses: int = field(default=0)

    def summary_rows(self) -> list[tuple[str, str]]:
        """The preflight rows ADR 0045 requires, entered values first."""
        return [
            ("Managed subnet", f"{self.managed_ipv4_cidr}  ({self.netmask})"),
            ("Controller address", self.controller_ipv4_address),
            ("DHCP pool", f"{self.dhcp_pool_start} - {self.dhcp_pool_end}"
                          f"  ({self.pool_size} addresses)"),
            ("Network / broadcast", f"{self.network_address} / {self.broadcast_address}"),
            ("Usable addresses", str(self.usable_addresses)),
            ("Client DNS server", f"{self.dns_server}  (derived: the Controller)"),
            ("DNS suffix", f"{self.dns_suffix}  (derived: ADR 0005)"),
            ("Default router", "none advertised  (derived: ADR 0011, no routing)"),
        ]


def _parse_address(value: str, field_name: str) -> ipaddress.IPv4Address:
    text = (value or "").strip()
    if not text:
        raise NetworkPlanError(f"{field_name}: required when Controller network services are enabled")
    if not _IPV4_RE.match(text):
        raise NetworkPlanError(
            f"{field_name}: {text!r} is not an unambiguous dotted-quad IPv4 address "
            "(four decimal octets, no leading zeros)"
        )
    try:
        return ipaddress.IPv4Address(text)
    except ipaddress.AddressValueError as error:
        raise NetworkPlanError(f"{field_name}: {text!r} is not a valid IPv4 address ({error})") from error


def _parse_network(value: str, field_name: str) -> ipaddress.IPv4Network:
    text = (value or "").strip()
    if not text:
        raise NetworkPlanError(f"{field_name}: required when Controller network services are enabled")
    if text.count("/") != 1:
        raise NetworkPlanError(f"{field_name}: {text!r} must be written as address/prefix, for example 10.0.7.0/24")
    address_part, _, prefix_part = text.partition("/")
    if not _IPV4_RE.match(address_part):
        raise NetworkPlanError(
            f"{field_name}: {address_part!r} is not an unambiguous dotted-quad IPv4 address"
        )
    if not re.fullmatch(r"(?:0|[1-9]\d?)", prefix_part):
        raise NetworkPlanError(f"{field_name}: {prefix_part!r} is not a decimal prefix length")
    prefix = int(prefix_part)
    if prefix > 32:
        raise NetworkPlanError(f"{field_name}: prefix length /{prefix} is out of range")
    try:
        # strict=True is the point: reject a CIDR with host bits set rather
        # than silently normalising what the operator typed.
        return ipaddress.IPv4Network(text, strict=True)
    except ValueError:
        canonical = ipaddress.IPv4Network(text, strict=False)
        raise NetworkPlanError(
            f"{field_name}: {text!r} has host bits set. "
            f"Enter the network address itself, which is {canonical.with_prefixlen}"
        ) from None


def check_usable_address(address_text: str, cidr_text: str, field_name: str) -> None:
    """Raise unless the address is a usable unicast host address in the subnet.

    Exposed separately from build_plan so the installer can apply this rule at
    the prompt that broke it, while a plan is still half-collected. build_plan
    calls the same function, so there is one implementation of the rule.
    """
    network = _parse_network(cidr_text, "managed_ipv4_cidr")
    address = _parse_address(address_text, field_name)
    if address not in network:
        raise NetworkPlanError(
            f"{field_name}: {address} is not inside {network.with_prefixlen}")
    if address == network.network_address:
        raise NetworkPlanError(
            f"{field_name}: {address} is the network address, not a usable host address")
    if address == network.broadcast_address:
        raise NetworkPlanError(
            f"{field_name}: {address} is the broadcast address, not a usable host address")


def build_plan(inputs: dict) -> NetworkPlan:
    """Validate the four ADR 0045 inputs and return the full derived plan.

    Raises NetworkPlanError with a message an operator can act on. Every rule in
    ADR 0045's validation list is checked here, in the order the ADR states it,
    so the code and the decision record can be read side by side.
    """
    unknown = set(inputs) - set(INPUT_FIELDS)
    if unknown:
        raise NetworkPlanError(f"unknown network input(s): {', '.join(sorted(unknown))}")

    network = _parse_network(inputs.get("managed_ipv4_cidr", ""), "managed_ipv4_cidr")
    controller = _parse_address(inputs.get("controller_ipv4_address", ""), "controller_ipv4_address")
    pool_start = _parse_address(inputs.get("dhcp_pool_start", ""), "dhcp_pool_start")
    pool_end = _parse_address(inputs.get("dhcp_pool_end", ""), "dhcp_pool_end")

    # The subnet must be able to hold a Controller and at least one lease.
    # /31 and /32 are rejected up front: ipaddress follows RFC 3021 and reports
    # two "hosts" in a /31, but this plan also needs a network and a broadcast
    # address, so the later per-address checks would reject it with a message
    # about RFC 3021 that would not help anybody.
    if network.prefixlen >= 31:
        raise NetworkPlanError(
            f"managed_ipv4_cidr: /{network.prefixlen} leaves no usable addresses for a "
            "Controller and a DHCP pool; use /30 or larger"
        )
    usable = list(network.hosts())
    if len(usable) < 2:
        raise NetworkPlanError(
            f"managed_ipv4_cidr: {network.with_prefixlen} has {len(usable)} usable address(es); "
            "the plan needs at least a Controller address and one DHCP lease"
        )
    first_usable, last_usable = usable[0], usable[-1]

    for name, address in (
        ("controller_ipv4_address", controller),
        ("dhcp_pool_start", pool_start),
        ("dhcp_pool_end", pool_end),
    ):
        check_usable_address(str(address), network.with_prefixlen, name)
        if not (first_usable <= address <= last_usable):
            raise NetworkPlanError(f"{name}: {address} is not a usable unicast address in {network.with_prefixlen}")

    if pool_start > pool_end:
        raise NetworkPlanError(
            f"dhcp_pool_start: {pool_start} is greater than dhcp_pool_end {pool_end}"
        )

    if pool_start <= controller <= pool_end:
        raise NetworkPlanError(
            f"controller_ipv4_address: {controller} lies inside the DHCP pool "
            f"{pool_start}-{pool_end}. The Controller holds a static address and dnsmasq "
            "must never be able to lease it to a client"
        )

    pool_size = int(pool_end) - int(pool_start) + 1

    return NetworkPlan(
        managed_ipv4_cidr=network.with_prefixlen,
        controller_ipv4_address=str(controller),
        dhcp_pool_start=str(pool_start),
        dhcp_pool_end=str(pool_end),
        network_address=str(network.network_address),
        broadcast_address=str(network.broadcast_address),
        netmask=str(network.netmask),
        prefix_length=network.prefixlen,
        dns_server=str(controller),
        dns_suffix=DNS_SUFFIX,
        default_router=None,
        pool_size=pool_size,
        usable_addresses=len(usable),
    )


def advisories(plan: NetworkPlan) -> list[str]:
    """Non-fatal observations worth printing in the preflight summary.

    These are not ADR 0045 validation rules and must never block an install on
    their own. They exist because an operator staring at a confirmation prompt
    benefits from being told that their subnet is publicly routable or that
    their pool has four addresses in it.
    """
    notes: list[str] = []
    network = ipaddress.IPv4Network(plan.managed_ipv4_cidr)
    rfc1918 = (
        ipaddress.IPv4Network("10.0.0.0/8"),
        ipaddress.IPv4Network("172.16.0.0/12"),
        ipaddress.IPv4Network("192.168.0.0/16"),
    )
    if not any(network.subnet_of(block) for block in rfc1918):
        notes.append(
            f"{plan.managed_ipv4_cidr} is not an RFC 1918 private range. "
            "This is permitted but unusual for a managed lab network."
        )
    if plan.pool_size < 8:
        notes.append(f"the DHCP pool holds only {plan.pool_size} address(es)")
    if plan.prefix_length < 16:
        notes.append(
            f"/{plan.prefix_length} is a very large broadcast domain "
            f"({plan.usable_addresses} usable addresses)"
        )
    return notes
