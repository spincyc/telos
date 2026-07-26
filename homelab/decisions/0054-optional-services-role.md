# ADR 0054: Define an optional Services role for always-on applications

- Status: Accepted
- Date: 2026-07-25

## Context

Homebridge, openHAB and similar home-automation applications must run
continuously, need mDNS on the host network to pair and be discovered, and often
need a USB radio passed through. They are also the services whose downtime is
most visible in the house.

Putting them on the Controller couples them to ADR 0016's guarded updates, which
require a reboot whenever the kernel or networking stack changes. Patching DNS
would stop the lights answering.

## Decision

Define a third role, `services`, separate from Controller and Workstation.

- Implement each application as a Podman **quadlet** -- a systemd unit
  generated from a declarative container definition -- so lifecycle, ordering,
  restart policy and journal integration are ordinary systemd.
- Applications that need discovery run with host networking, which is required
  for HomeKit and UPnP to work at all.
- USB radios are bound by stable `by-id` path and declared per application.
- Application state lives on its own Btrfs subvolume, excluded from the
  operating-system checkpoint under ADR 0027 and backed up separately, because
  its restore point is not the same as the operating system's.
- The role is **disabled by default** and enabled per instance.
- The role may be assigned to the Controller host today. Moving it to its own
  machine later changes which host claims the role and nothing else.

The Controller profile does not depend on the services role, and the services
role does not depend on Controller-hosted DHCP or DNS beyond ordinary name
resolution.

## Consequences

- Home automation can start on one machine and move without redesign.
- Container images become an artifact class with their own provenance, pinning
  and update cadence, distinct from pacman.
- Running the role on the Controller is an accepted, recorded trade-off: a
  Controller maintenance window is a home-automation outage until the role
  moves.
- Host networking removes container network isolation for those applications.
  That is a deliberate cost of mDNS working.
