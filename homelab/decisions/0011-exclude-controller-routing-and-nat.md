# ADR 0011: Exclude routing and NAT from the initial Controller

- Status: Accepted
- Date: 2026-07-24

## Context

The Controller can provide DHCP and DNS on an isolated switch network without
also routing packets between networks. Making it a router or NAT gateway would
add interface requirements, forwarding policy, firewall rules, Internet-edge
security responsibilities, and another destructive failure mode.

## Decision

Exclude routing, NAT, and perimeter-firewall duties from the initial Controller
profile.

On the isolated acceptance network, the Controller provides local DHCP and DNS
without advertising or acting as a default gateway. The initial isolated test
therefore has no Internet access.

ADR 0045 subsequently excludes a gateway from the network input schema and
derives the absence of the DHCP default-router option.

Reserve a clearly marked future-extension section in the Controller design for
possible routing and NAT support.

## Consequences

- The initial Controller requires only a service interface for its managed
  network; it does not require separate LAN and WAN interfaces.
- DHCP must not advertise a nonexistent default gateway on the isolated
  acceptance network.
- Local `home.arpa` DNS behavior can be tested offline, but upstream recursive
  DNS resolution cannot.
- Production deployments may use an external router while still using
  Controller-owned DHCP and DNS.
- Routing, NAT, forwarding firewall rules, and dual-homed topology are out of
  scope until a later ADR explicitly adds them.
