# ADR 0073: Keep household instance data in telos-private

- Status: Accepted
- Date: 2026-07-27

## Context

The reusable Telos manuals are public. Household identities, inventories and
personal policy belong in a backed-up private project rather than an
untracked directory inside the public repository.

## Decision

Keep generic roles, templates, tests and redacted examples in public `telos`.
Keep household users, hostnames, MAC addresses, serial numbers, network
assignments, NAS paths and private projects in sibling repository
`../telos-private`.

Verify that its GitHub remote is private before first push. Passwords, Wi-Fi
keys, recovery material and join credentials must be encrypted or remain
outside Git even there. Public builds use placeholders and fail if instance
data leaks into rendered sources.

## Consequences

- Private instance state receives versioned off-host backup.
- Public documentation stays complete without the overlay.
- Build interfaces between the repositories must be explicit and fail closed.
- This specializes ADR 0046's public/private split; it does not supersede that
  decision.
