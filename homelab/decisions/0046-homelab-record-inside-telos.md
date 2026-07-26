# ADR 0046: Keep the homelab record inside Telos and split public profile from private instance

- Status: Accepted
- Date: 2026-07-25

## Context

ADR 0001 recorded `/home/ksh/git/codex/homelab-infrastructure` as the canonical
working copy. That path is empty; the record actually lived at
`/home/ksh/git/homelab`, so the accepted decision and reality disagreed and
nobody noticed. Separately, the homelab needs printable standalone reconstruction
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
  disk serials, DHCP reservations, share paths and per-machine inventory live in
  `homelab/instance/`, which is gitignored and never rendered into the site.

Documents that need an instance value read it from the private overlay at build
time and fall back to a clearly marked placeholder when the overlay is absent.
A published document must be complete and useful without the overlay.

## Consequences

- The published manuals describe a reusable profile, not this house.
- A reader who clones the repository can build the same system with their own
  overlay.
- `homelab/instance/` is gitignored; losing it loses instance data, so it needs
  its own off-host backup under the recovery policy, separate from Git.
- The site build must fail closed if instance data ever reaches a published
  source file. `scripts/site` gains that check.
- ADR 0001 is superseded.
