# ADR 0012: Bundle Controller DHCP and DNS

- Status: Accepted
- Date: 2026-07-24

## Context

Allowing DHCP and DNS to be enabled independently creates mixed operating modes
and additional first-boot transitions. The initial autonomous-network
requirement needs both: DHCP supplies client network configuration and
advertises the Controller as the DNS endpoint, while DNS resolves
`home.arpa`.

## Decision

Expose one combined Controller network-services option in the initial profile:

- When enabled, Controller DHCP and DNS are configured and activated together.
- When disabled, both remain stopped and external infrastructure provides those
  functions.

Reserve independent DHCP-only and DNS-only operation as a future extension.
ADR 0044 subsequently selects one host-native dnsmasq instance as the initial
implementation of this bundle.

## Consequences

- The installer asks one material network-services question instead of exposing
  unsupported combinations.
- Automatic first-boot activation and fail-closed recovery treat DHCP and DNS
  as one unit.
- Controller DHCP advertises the Controller as the client DNS endpoint.
- Failure of either service means the combined first-boot activation has not
  succeeded.
- A future ADR may add independently controlled modes without redefining the
  initial behavior.
