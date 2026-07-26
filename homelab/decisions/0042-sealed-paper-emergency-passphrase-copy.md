# ADR 0042: Use a sealed paper emergency passphrase copy

- Status: Deferred for post-proof revalidation by ADR 0043
- Date: 2026-07-24

## Context

ADR 0041 requires one emergency copy of the signing-media passphrase that works
without any computer, network, cloud, Controller service, or password manager.
Encrypting that copy would introduce another credential whose loss could defeat
the break-glass path.

The copy therefore needs a durable human-readable form and a physical custody
boundary rather than another digital encryption layer.

## Decision

Print the exact signing-media passphrase as a human-readable recovery sheet.
Place it in a tamper-evident sealed envelope and keep the envelope in locked,
fire-resistant storage physically separate from:

- the primary signing medium;
- the backup signing medium; and
- the password manager's own recovery material.

The sheet may contain only:

- the exact passphrase in a transcription-resistant layout;
- a non-secret purpose and version label;
- enough non-secret instructions to identify the two signing-media LUKS2
  volumes it unlocks; and
- a verification value that detects transcription error without containing
  another secret.

Do not print either signing private key, a password-manager credential, a vault
recovery code, or unrelated recovery material on the sheet.

Before sealing a new or rotated sheet, use it to unlock and close each medium
separately, verify both key fingerprints through a trial signature, and confirm
that no digital copy remains in the print path, spool, temporary directory, or
device storage under operator control.

Record only a non-secret envelope identifier, creation date, and seal-inspection
status outside the envelope. Do not record the passphrase or an image of the
sheet.

Opening the envelope is a break-glass event. Record the event without the
secret, replace the sheet and envelope after use, and rotate the passphrase if
custody or observation during the event is uncertain.

This plaintext physical sheet is an explicit exception to digital at-rest
encryption. Its locked location, separation, tamper evidence, and access
control form its protection boundary.

The exact storage location, authorized people, paper and printing method,
envelope type, verification-value format, inspection and test cadence, and
secure destruction method remain separate decisions.

## Consequences

- Recovery requires no additional credential or functioning technology.
- Fire-resistant locked storage and tamper evidence reduce, but do not
  eliminate, physical theft, photography, copying, fire, or water risk.
- Anyone who reads the sheet and obtains either signing medium can recover both
  private signing keys.
- Printing creates a temporary digital and device-spool exposure that the
  creation procedure must explicitly eliminate or avoid.
- Every authorized opening consumes the sealed state and requires replacement.
