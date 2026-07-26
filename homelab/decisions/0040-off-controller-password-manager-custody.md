# ADR 0040: Store the signing-media passphrase in an off-Controller password manager

- Status: Deferred for post-proof revalidation by ADR 0043
- Date: 2026-07-24

## Context

ADR 0039 selects one high-entropy passphrase for both signing-media LUKS2
volumes but leaves authoritative custody open. The user already operates a
password manager that remains accessible when the Controller and home network
are unavailable.

Storing the passphrase in a service hosted by the Controller would create a
recovery cycle: the signing authority might be needed to repair or update the
Controller, while the Controller would be needed to retrieve its unlock
credential.

## Decision

Use the operator's existing off-Controller password manager as the
authoritative store for the shared signing-media passphrase.

The password manager used for this purpose must:

- remain accessible when the Controller is powered off, damaged, isolated, or
  being rebuilt;
- not depend exclusively on DNS, identity, networking, or storage supplied by
  the Controller;
- protect its local or remote vault independently of the signing media; and
- have an operator-tested recovery path independent of the Controller.

Retrieve the passphrase manually for a signing session and enter it
interactively into the designated signing environment. Do not add password
manager API credentials, automated vault retrieval, or a machine account to
the initial signing workflow. Do not cache or persist the retrieved passphrase
on the signing host.

The repository and non-secret machine records may contain only a stable,
non-secret reference describing which password-manager entry the operator must
retrieve. They must not contain the passphrase, a vault export, session token,
recovery code, or password-manager credential.

The specific password-manager product and account remain operator-owned
instance details rather than Controller profile dependencies. This design does
not require external registration; a qualifying local or externally hosted
manager is acceptable.

ADR 0041 subsequently requires one independent emergency copy, and ADR 0042
selects a sealed paper recovery sheet in locked, fire-resistant storage.
Password-manager entry naming, clipboard versus direct-entry handling,
authorized human access, audit cadence, and coordinated passphrase-rotation
procedure remain separate decisions.

## Consequences

- The operator has one established authoritative place to retrieve the
  passphrase.
- Controller failure or isolation does not prevent signing-media unlock.
- Signing remains an attended operation and gains no password-manager service
  or API dependency.
- Compromise of the password-manager entry plus possession of either signing
  medium exposes both private signing keys.
- ADR 0041's independent emergency copy provides a break-glass path when the
  password manager is unavailable.
- The generic repository can document the capability and secret reference
  without prescribing or exposing the user's password-manager account.
