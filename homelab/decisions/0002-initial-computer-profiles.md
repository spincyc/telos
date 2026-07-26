# ADR 0002: Initial computer profiles

- Status: Accepted
- Date: 2026-07-24

## Context

The desired end state is a network-boot provisioning system that can
interactively authorize a disk wipe and install a selected computer profile.
The initial deployment model needs names for the central homelab
server/orchestration role and for user-facing computers.

## Decision

Begin with two computer profiles:

- **Controller**, identified as `controller`
- **Workstation**, identified as `workstation`

The Controller is the homelab server, orchestrator, and general infrastructure
utility. Each Workstation deployment pivots on the hostname of its Controller.

## Consequences

- Deployment records will select either `controller` or `workstation`.
- The Controller must be reconstructible without depending on a functioning
  instance of itself.
- The Controller's exact service boundaries remain open.
- A Workstation identifies its Controller by a fully qualified `home.arpa`
  hostname.
- The Workstation parameter name, discovery mechanism, bootstrap behavior, and
  offline behavior remain open.
- Disk wiping still requires target-disk validation and interactive
  authorization; selecting a profile alone is not sufficient authorization.
