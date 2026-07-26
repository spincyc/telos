# ADR 0023: Use signed Unified Kernel Images

- Status: Accepted
- Date: 2026-07-24

## Context

ADR 0020 requires Secure Boot and prohibits secrets in firmware-readable boot
storage. ADR 0022 selects systemd-boot for Arch, with `linux-lts` as the default
kernel and standard `linux` as the secondary kernel.

systemd-boot can load separate kernel, initramfs, and command-line resources or
a Unified Kernel Image. A UKI packages those components into one EFI executable
that can be signed and verified as a unit.

## Decision

Build and install a signed UKI for each accepted Arch kernel:

- one UKI for `linux-lts`, selected by default; and
- one UKI for standard `linux`, exposed as the secondary Arch entry.

Each UKI contains its matching kernel, initramfs, and kernel command line.
systemd-boot discovers and launches the UKIs as Boot Loader Specification Type
#2 entries.

Do not make an unsigned or partially authenticated Linux boot entry part of the
normal installed-system path. The Secure Boot trust chain must verify each UKI
before execution.

UKIs reside on firmware-readable, unencrypted boot storage and are therefore
public artifacts. They must not contain raw volume keys, credentials, reusable
tokens, private data, or other secrets.

This decision does not select the UKI generator, initramfs generator, signing
tool, or signing automation. ADR 0024 subsequently selects a third
self-contained recovery UKI, ADR 0025 selects one shared ESP for all boot
artifacts, ADR 0029 defines TPM2 unlock authorization for the two normal UKIs,
ADR 0030 defines additive enrollment of the lab signer without replacing
factory PK or KEK ownership, and ADR 0032 defines removable off-host custody of
the signing private key.

ADR 0043 keeps the UKI topology but allows checksum-verified, unsigned
development UKIs only in the explicitly non-production functional proof. That
exception is removed before final acceptance; it is not an installed profile
option.

## Consequences

- The kernel, initramfs, and embedded command line are authenticated together.
- A change to any bundled component requires regenerating and signing its UKI.
- Kernel package updates must produce and validate both UKIs before the update
  is considered successful.
- Boot storage must be sized for both current UKIs and the recovery UKI selected
  by ADR 0024.
- Root-filesystem checkpoints do not automatically include UKIs, so rollback
  must restore a matching boot-artifact set. Final acceptance additionally
  requires the signing workflow selected after ADR 0043's revalidation.
- Signed UKIs provide a suitable measured-boot unit for a future TPM-bound
  LUKS2 policy without deciding that policy here.
- The Windows maintenance installation continues to use its independent native
  Windows Boot Manager path.

## References

- UAPI Boot Loader Specification:
  https://uapi-group.org/specifications/specs/boot_loader_specification/
- `systemd-stub`:
  https://man.archlinux.org/man/systemd-stub.7
- `ukify`:
  https://man.archlinux.org/man/ukify.1
- Arch Unified Kernel Image documentation:
  https://wiki.archlinux.org/title/Unified_kernel_image
