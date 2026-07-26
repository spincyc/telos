# ADR 0008: Support Controller-owned DHCP and DNS

- Status: Accepted
- Date: 2026-07-24
- Supersedes: ADR 0006

## Context

The Controller profile must be generic. Some deployments have external network
infrastructure such as UniFi, while another required deployment consists of an
isolated network whose only permanent network infrastructure is a switch.

ADR 0006 made UniFi the mandatory client DNS endpoint and deferred
Controller-hosted DNS. That prevents the Controller from operating
autonomously on the isolated network.

## Decision

The Controller must optionally function as the primary DHCP and DNS server for
its managed network.

When external infrastructure owns DHCP or DNS, the corresponding Controller
services must remain disabled. Two DHCP authorities must never be active on the
same layer-2 network during installation, testing, or transition.

The first acceptance sequence must validate the installed Controller's DHCP and
DNS behavior on an isolated network containing no permanent router or DNS/DHCP
appliance. Provisioning occurs first on the existing full network, and ADR 0010
defines the powered-off transition to the isolated network.

## Consequences

- ADR 0006 is superseded; UniFi is a supported integration environment rather
  than a mandatory dependency.
- The `home.arpa` suffix remains unchanged.
- Controller DHCP and DNS configuration must be reproducible from the
  repository.
- The installer and runbook must clearly distinguish external-infrastructure
  operation from Controller-owned DHCP/DNS operation.
- DHCP activation requires conflict detection and an explicit transition
  procedure.
- A bare Controller target still cannot provide its own initial DHCP, boot
  loader, or installation artifacts; an off-target bootstrap source remains
  necessary.
- ADR 0012 bundles Controller DHCP and DNS as one initial option.
- ADR 0013 limits the initial managed network-service scope to IPv4.
- ADR 0044 subsequently selects dnsmasq as the initial bundled DHCP, DNS, PXE,
  and first-stage TFTP implementation.
- ADR 0045 subsequently makes the managed subnet, Controller address, and DHCP
  pool validated installation inputs rather than fixed profile values.
- Prefix policy and the DHCP redundancy model remain open.
