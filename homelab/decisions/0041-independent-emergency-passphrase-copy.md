# ADR 0041: Keep one independent emergency copy of the signing-media passphrase

- Status: Deferred for post-proof revalidation by ADR 0043
- Date: 2026-07-24

## Context

ADR 0040 makes the operator's existing off-Controller password manager the
authoritative store for the signing-media passphrase. Both signing media use
that one passphrase under ADR 0039.

The password manager is independent of the Controller, but account lockout,
vault corruption, device loss, provider failure, or loss of its own recovery
material could still make two healthy signing media inaccessible.

## Decision

Maintain exactly one authorized emergency copy of the shared signing-media
passphrase outside the password manager.

The emergency copy must:

- reproduce the exact passphrase without depending on memory;
- remain offline and require no Controller, home-network, DNS, identity, cloud,
  or password-manager service;
- be stored physically apart from the password manager's recovery material,
  the primary signing medium, and the backup signing medium;
- never appear in Git, ordinary documentation, an inventory database, a
  Controller or Workstation, PXE storage, an installer, or a signing host;
- be accessed only for password-manager recovery or a scheduled break-glass
  test; and
- be returned to protected storage or securely replaced immediately after use.

The password manager remains the normal authoritative source. The emergency
copy is a break-glass recovery path, not a second routine retrieval location.

A passphrase rotation is incomplete until the password manager, both LUKS2
volumes, and the emergency copy agree on the new credential and each has been
tested through its appropriate path. Destroy the obsolete emergency copy only
after the new one has been verified.

ADR 0042 subsequently selects a human-readable paper recovery sheet in a
tamper-evident sealed envelope kept in locked, fire-resistant storage. The
exact storage location, access control, test cadence, and destruction method
remain separate decisions.

## Consequences

- Password-manager loss does not automatically make both signing media
  unrecoverable.
- The design gains another physical secret whose loss, theft, or unnoticed
  duplication must be considered.
- Possession of the emergency copy plus either signing medium exposes both
  private signing keys.
- Keeping exactly one authorized copy limits exposure but provides no
  redundancy against simultaneous loss of that copy and the password manager.
- Recovery remains possible without external registration or a functioning
  home network.
