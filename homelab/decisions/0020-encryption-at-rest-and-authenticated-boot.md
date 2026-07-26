# ADR 0020: Require encryption at rest and authenticated boot

- Status: Accepted
- Date: 2026-07-24

## Context

The Controller and Workstation profiles manage private lab systems and may
store credentials, cached identity data, service state, and personal data.
Encryption must therefore be a baseline property rather than an optional
hardening step.

UEFI firmware must be able to read an EFI System Partition. Windows BitLocker
similarly requires a separate unencrypted system partition. A conventional
UEFI system therefore cannot encrypt every byte needed before an operating
system starts. Those mandatory public artifacts need integrity protection and
must not contain secrets.

The Controller also requires a Windows-capable physical boot path for firmware
maintenance. ADR 0021 subsequently selects a permanent bare-metal Windows
installation for that environment.

## Decision

For systems installed and managed by the Controller and Workstation profiles:

- encrypt every persistent data-bearing operating-system and service volume;
- encrypt disk-backed swap and persistent crash or hibernation state;
- encrypt backups of managed-system data, secrets, and recovery state;
- use LUKS2 for Linux data-bearing volumes;
- use BitLocker for Windows data-bearing volumes;
- require Secure Boot for provisioning, installed-system boot, and recovery
  paths;
- limit unencrypted storage to mandatory firmware-readable boot and recovery
  partitions;
- keep those unencrypted partitions minimal and free of credentials,
  decryption keys, tokens, private data, and other reusable secrets; and
- authenticate executable boot artifacts through the accepted Secure Boot
  chain.

This is an at-rest encryption boundary. It does not yet define transport
encryption.

The policy applies to new or rebuilt systems managed by these profiles. It does
not assert that existing lab devices have already been migrated or authorize
inventorying them.

ADR 0043 creates one narrow sequencing exception. Its labeled, disposable
`development-proof` installation must still use encryption at rest, but may
defer the custom authenticated-boot chain and run with Secure Boot disabled
when an already trusted upstream chain is unavailable. Such an installation
does not satisfy this ADR for final profile acceptance and must be reprovisioned
after the signing design is revisited.

## Consequences

- The EFI System Partition and any mandatory unencrypted recovery partition are
  explicit exceptions; their contents are public but their executable path
  must be authenticated.
- Linux kernel and initramfs artifacts must not embed raw unlock keys or other
  reusable secrets.
- Network-boot and recovery designs must work with Secure Boot enabled rather
  than instructing the operator to disable it.
- Recovery keys and private signing material must be stored off-host and
  separately from the encrypted data they recover or authenticate.
- Encryption-key loss can make otherwise healthy backups unusable, so restore
  tests must include key recovery.
- ADRs 0029 through 0042 record the current TPM and signing design but are
  deferred for post-proof revalidation by ADR 0043. ADR 0021 defines the
  Windows maintenance form, and ADR 0023 selects Unified Kernel Images as the
  final authenticated Arch artifact.
- Firmware and Secure Boot database changes become planned maintenance events
  because they can affect TPM-sealed LUKS2 or BitLocker unlock.
- Existing lab systems require a separately authorized audit and migration
  plan if they are to conform to this policy.

## References

- UAPI Boot Loader Specification:
  https://uapi-group.org/specifications/specs/boot_loader_specification/
- Arch dm-crypt documentation:
  https://wiki.archlinux.org/title/Dm-crypt
- Arch Secure Boot documentation:
  https://wiki.archlinux.org/title/Unified_Extensible_Firmware_Interface/Secure_Boot
- Microsoft BitLocker overview:
  https://learn.microsoft.com/en-us/windows/security/operating-system-security/data-protection/bitlocker/
