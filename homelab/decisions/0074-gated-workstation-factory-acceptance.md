# ADR 0074: Gate workstation-factory acceptance

- Status: Accepted
- Date: 2026-07-27

## Context

The live network attachment remains undecided. Local progress must continue
without silently modifying UniFi or erasing hardware.

## Decision

Acceptance proceeds through three gates:

1. isolated QEMU tests for AD DNS, time, PXE artifacts, installers and joins;
2. read-only UniFi preflight followed by separately authorized network changes;
3. physical PXE installation of the privately inventoried pilot workstation.

The physical gate verifies DNS SRV and forwarding, Kerberos, Samba database
health, Windows secure channel, Arch SSSD identity, cached login, local rescue,
NAS-unavailable login, both UEFI entries, Windows-default timeout and artifact
digests.

The chosen live attachment may be the existing LAN, a privately inventoried
dedicated interface, or a VLAN trunk. It is a deployment input, not baked into
images or public documentation.

This amends ADR 0056 only where its matrix assumes ProxyDHCP, Controller-owned
DHCP/DNS or an isolated network without a gateway. ADR 0056's QEMU/OVMF,
artifact, rejection-corpus and hardware-gate requirements remain accepted.

## Consequences

- Development continues before the cabling decision.
- No mutation crosses a gate without explicit evidence and authorization.
- The same artifacts are tested locally and on hardware.
