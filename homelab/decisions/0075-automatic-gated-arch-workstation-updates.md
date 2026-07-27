# ADR 0075: Automatically apply gated Arch workstation updates

- Status: Accepted
- Date: 2026-07-27

## Context

Workstations may leave the home network indefinitely. Waiting for a Controller
would leave mobile machines stale, while blindly running a rolling-release
upgrade can interrupt work or fill a small disk. Arch supports full upgrades,
not partial upgrades.

## Decision

Every Arch workstation runs one randomized, persistent daily timer. It performs
only `pacman -Syu`, using Arch's signed repository databases and signed packages.
The transaction starts only on AC power, with at least 8 GiB free, with an
official mirror reachable, and with no other pacman transaction active. A missed
run is retried after the machine next boots; a failed gate is a safe deferral.

Before and after package inventories, the gate report, pacman evidence and the
running kernel are retained locally. User sessions are never forcibly rebooted.
A kernel change records that a reboot is recommended. The `linux-lts` package is
installed as an independently bootable fallback, but the updater does not claim
or attempt an automatic rollback.

The policy works from any ordinary internet connection and has no Controller,
directory or home-LAN dependency. Metered-network avoidance may be added after
field measurements; phase one treats connectivity as permission to update.

A centrally approved, signed Arch Linux Archive snapshot is a possible later
control for staged fleet rollouts. It is not implemented here and must not be
represented as a recovery snapshot: package signatures establish provenance,
while the pre-update inventory is evidence rather than a restorable image.

## Consequences

- Arch workstations remain current while away from home.
- Updates wait for power, space and a complete official repository transaction.
- A rare bad update can still require selecting `linux-lts` or repairing the
  system; retained evidence makes that repair diagnosable.
- Reboot-sensitive security fixes take effect when the user next reboots.
