# ADR 0013: Start Controller network services with IPv4

- Status: Accepted
- Date: 2026-07-24

## Context

The first isolated network has no router, and the Controller is explicitly not
a router. Managed IPv6 would require separate decisions about router
advertisements, address assignment, prefixes, DNS behavior, and interaction
with future external routing.

Disabling the operating system's IPv6 stack would create compatibility problems
for software that expects IPv6 APIs even when no managed IPv6 network exists.

## Decision

Limit the initial bundled Controller network-services option to managed IPv4:

- provide DHCPv4;
- serve DNS on the Controller's IPv4 service address;
- do not provide DHCPv6, router advertisements, or managed IPv6 addressing.

Keep the operating system's IPv6 stack and ordinary link-local behavior
enabled. Reserve managed dual-stack operation as a future extension.

## Consequences

- The isolated acceptance test validates IPv4 leases and IPv4 access to DNS and
  local services.
- DHCP must not advertise a default gateway on the routerless isolated network.
- The initial design does not allocate a ULA prefix or manage IPv6 DNS records.
- Software must not globally disable IPv6 merely because managed IPv6 is out of
  scope.
- A future dual-stack ADR must define prefix ownership, router advertisements,
  DHCPv6, DNS records, firewall behavior, and validation.
