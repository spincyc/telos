# ADR 0031: Use one lab-wide Secure Boot signing identity

- Status: Deferred for post-proof revalidation by ADR 0043
- Date: 2026-07-24

## Context

ADR 0030 adds a lab-controlled Secure Boot certificate to each managed
machine's firmware `db` while retaining factory platform ownership and
Microsoft and OEM trust. The remaining scope choice is whether each machine
gets its own signing identity or all managed machines trust one lab identity.

Per-machine identities limit the impact of one compromised key, but require
per-machine artifact signing, certificate enrollment, inventory, and rotation.
A single identity makes compatible signed artifacts reusable and keeps a small
lab's provisioning and update path understandable.

## Decision

Use one dedicated, lab-wide Secure Boot code-signing identity for managed
Controller and Workstation systems.

- Enroll the same public certificate in firmware `db` on every managed machine
  that must execute lab-signed EFI artifacts.
- Use its private counterpart to sign the lab-controlled installed-system EFI
  artifacts defined by each profile, including the Controller's systemd-boot
  executable and normal and recovery UKIs.
- Record and verify the shared certificate fingerprint in the profile's
  non-secret artifact manifest and each machine's provisioning record.
- Do not create or manage a separate Secure Boot signing identity for every
  machine.

Sharing the identity does not mean copying its private key to every machine.
ADR 0020 keeps private signing material off-host, and ADR 0032 subsequently
selects encrypted removable primary and backup media used only in a designated
signing environment. Signing automation, detailed rotation, and operator
authorization remain separate decisions.

This identity is scoped to Secure Boot code signing. This decision does not
authorize its use for TLS, SSH, package repositories, backup encryption, disk
recovery, or other unrelated purposes. ADR 0033 subsequently selects a
different identity for signing TPM PCR policies. The network-provisioning trust
chain remains open.

## Consequences

- A compatible signed boot artifact can be reused across managed machines
  without per-machine signing.
- Provisioning maintains one public certificate and fingerprint rather than a
  per-machine Secure Boot certificate inventory.
- Compromise of the private key permits malicious EFI artifacts to satisfy
  Secure Boot on every machine that trusts the lab certificate. ADR 0029's TPM
  policy still controls automatic Controller-root unlock, and ADR 0033 assigns
  that policy a different signing key.
- Rotation or revocation affects the entire managed lab and must use a planned
  overlap that enrolls and verifies the replacement certificate before
  retiring the old one.
- Signer unavailability can block production of new boot artifacts for every
  managed machine, so custody and recovery must avoid a single unrecoverable
  copy.
- Public certificates and fingerprints are not secrets; the private key is.

## References

- Microsoft Secure Boot key creation and management guidance:
  https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/windows-secure-boot-key-creation-and-management-guidance?view=windows-11
