# ADR 0071: Permit indefinite cached mobile logon

- Status: Accepted
- Date: 2026-07-27

## Context

Some laptops remain away at college indefinitely. They must continue accepting
a user who previously completed a successful online domain logon.

## Decision

Allow cached domain logon without a time expiry on Windows and Arch. Require
three privately named, distinct roles:

- a separate non-domain break-glass administrator;
- a privileged domain administrator that is not the daily identity; and
- a standard test identity that proves non-administrator behavior.

The private overlay maps household account names to those roles.

Disabling or expiring an AD account blocks connected authentication and network
access but cannot revoke an offline cached logon. Temporary revocation controls
and remote check-in are phase-two or phase-three work.

This amends only ADR 0055's finite offline credential lifetime. Its other
identity decisions remain accepted.

On Arch, set SSSD's `offline_credentials_expiration` to `0`, its documented
no-expiration value. Do not omit the setting or substitute a large finite
number.

## Consequences

- Long trips do not strand users.
- Phase-one revocation has no reliable offline deadline.
- Manuals and acceptance evidence must state connected and disconnected
  behavior separately.
