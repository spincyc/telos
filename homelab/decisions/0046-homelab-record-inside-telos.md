# ADR 0046: Keep the homelab record inside Telos and split public profile from private instance

- Status: Accepted
- Date: 2026-07-25

## Context

ADR 0001 recorded one operator-specific path as the canonical working copy.
The record later lived elsewhere, so the accepted decision and reality
disagreed and nobody noticed. Separately, the homelab needs printable standalone reconstruction
manuals, which is exactly what the Telos publication system already produces.

Telos publishes to a public site. The homelab record contains real hostnames,
RFC 1918 addresses, NAS share paths and service topology.

## Decision

Move the homelab design record, implementation and documentation into the Telos
repository, and split it in two:

- **Profile material is public.** Decision records, the generic Controller,
  Workstation and Services profiles, the PXE design, the installer, the Ansible
  roles, and both reconstruction manuals contain no instance data and publish to
  the Telos site.
- **Instance material is private.** Real hostnames, addresses, interface names,
  disk serials, DHCP reservations, share paths and per-machine inventory live
  in a separately versioned private sibling repository and are never rendered
  into the site.

Documents that need an instance value read it from the private contract at
deployment time and use a clearly marked placeholder in public builds.
A published document must be complete and useful without the overlay.

## Consequences

- The published manuals describe a reusable profile, not this house.
- A reader who clones the repository can build the same system with their own
  overlay.
- The private sibling repository needs a verified private remote and its own
  recovery policy, separate from the public repository.
- The site build must fail closed if instance data ever reaches a published
  source file. `scripts/site` gains that check.
- ADR 0001 is superseded.
