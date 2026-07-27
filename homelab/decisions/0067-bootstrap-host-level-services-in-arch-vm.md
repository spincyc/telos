# ADR 0067: Bootstrap host-level services in an Arch VM

- Status: Accepted
- Date: 2026-07-27
- Supersedes: ADR 0052

## Context

The physical Controller does not exist. The current Arch workstation can prove
the design without immediately changing the live network.

## Decision

Create the private `services.bootstrap_dc_fqdn` as an Arch QEMU VM with profile
defaults of 4 vCPUs, 8 GiB RAM and an 80 GiB disk. Initially attach it only to
an isolated development network.

Run Samba AD/DNS/time and PXE services as host-level processes directly in the
guest, not in containers or nested service VMs, using the same
Ansible roles intended for the future physical Controller. UniFi remains
unchanged until a separately approved integration gate.

The bootstrap VM creates the real domain; it is not a disposable clone once
workstations join it. Use domain-aware backups and never duplicate, rename or
restore its live DC disk as a migration technique.

This replaces ADR 0052's workstation-hosted ProxyDHCP path.

## Consequences

- QEMU can prove configuration and artifacts before hardware erasure.
- The VM is temporary infrastructure but holds durable directory state until
  another DC is verified.
- Bridging, a dedicated interface and a VLAN trunk remain explicit later
  attachment choices.
