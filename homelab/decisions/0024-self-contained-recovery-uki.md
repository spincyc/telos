# ADR 0024: Include a self-contained recovery UKI

- Status: Accepted
- Date: 2026-07-24

## Context

ADR 0023 defines signed UKIs for the current `linux-lts` and standard `linux`
kernels. Both normal UKIs depend on the installed Arch root, and both may be
regenerated during one guarded package transaction. The secondary standard
kernel protects against some branch-specific kernel failures but is not a
whole-system recovery environment.

The Controller may be the normal PXE and recovery host for the rest of the lab.
It therefore needs a local recovery path that does not depend on its installed
root or its own network services. Local recovery cannot cover physical disk or
boot-storage failure, so off-host recovery remains necessary.

## Decision

Install a third, signed, self-contained recovery UKI on the Controller.

The recovery UKI:

- boots independently of the installed Arch root filesystem;
- is operator-selectable and never the automatic normal boot;
- contains the storage, encryption, filesystem, and boot-artifact tools needed
  to diagnose and recover the installed system;
- requires separately held LUKS2 recovery material under ADR 0029 and contains
  no raw unlock key, credential, token, or other reusable secret;
- starts in a non-destructive state and requires explicit operator action
  before mounting writable storage or changing disk state; and
- is authenticated by the same accepted Secure Boot trust policy as the normal
  Arch UKIs.

The exact rescue userspace, image generator, included hardware support,
network behavior, update cadence, validation procedure, and whether firmware
also registers the recovery UKI directly remain undecided.

ADR 0043 permits a checksum-verified, unsigned recovery-UKI candidate during
the functional proof so its userspace and recovery behavior can be exercised.
Its authenticated execution, rotation, and interaction with TPM policy remain
final-hardening acceptance tests.

## Consequences

- The Controller can diagnose or restore an encrypted root even when neither
  normal Arch entry reaches that root.
- Recovery boot storage must accommodate three UKIs.
- Recovery testing must verify boot, console access, storage discovery, LUKS2
  unlock with off-host material, checkpoint access, restoration of known
  boot artifacts, and generation of matching UKI candidates. Final hardening
  additionally validates signatures and the accepted signing workflow.
- A damaged disk, EFI System Partition, firmware trust database, or systemd-boot
  installation can still require off-host media or network bootstrap. ADR 0025
  does not add XBOOTLDR.
- The recovery image is a privileged artifact and must be reproducibly built,
  signed, versioned, and deliberately rotated.
- Secure Boot authenticates the recovery UKI, but its measured state is not
  authorized for automatic TPM2 root unlock.
- Windows remains a firmware-maintenance environment rather than the primary
  Arch recovery mechanism.

## References

- UAPI Boot Loader Specification:
  https://uapi-group.org/specifications/specs/boot_loader_specification/
- `systemd-stub`:
  https://man.archlinux.org/man/systemd-stub.7
- systemd-boot:
  https://man.archlinux.org/man/systemd-boot.7
