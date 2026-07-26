# ADR 0022: Use systemd-boot for Arch

- Status: Accepted
- Date: 2026-07-24

## Context

The Controller is UEFI-only, runs Arch as its normal operating system, boots
`linux-lts` by default, and retains standard `linux` as a secondary kernel.
ADR 0020 requires Secure Boot, and ADR 0021 adds a permanent
BitLocker-encrypted Windows maintenance installation with its own native UEFI
entry.

GRUB can read more storage layouts and provides a larger boot-time environment.
Those capabilities add configuration and Secure Boot complexity that the
accepted UEFI-only Arch boot path does not inherently need. Encrypting Linux
data does not require GRUB when mandatory public boot artifacts contain no
secrets and are authenticated.

systemd-boot is part of the systemd package, reads Boot Loader Specification
entries and unified kernel images, supports multiple Linux kernels, and can
coexist with Windows Boot Manager.

## Decision

Use systemd-boot as the installed Arch boot manager for the initial Controller
profile.

- Make the systemd-boot UEFI entry the normal firmware default.
- Make `linux-lts` the automatic Arch kernel selection.
- Expose standard `linux` as an operator-selectable secondary Arch entry.
- Keep Windows Boot Manager independently registered as a native UEFI entry.
- Do not make Windows depend on systemd-boot remaining functional.
- Sign and trust systemd-boot as part of the Secure Boot chain required by ADR
  0020.

The operator experience for requesting a Windows boot remains undecided.
systemd-boot may discover Windows, but the final design must retain a direct
firmware path that does not require chainloading through the Linux boot manager.

ADR 0023 subsequently selects signed Unified Kernel Images as the kernel
artifact format. ADR 0030 retains factory PK and KEK ownership while adding the
lab signer to `db`, and ADR 0031 makes that signer lab-wide. Private-key
custody is subsequently resolved by ADR 0032. Signing automation, boot
counting, checkpoint integration, and boot-menu timeout remain undecided. ADR
0024 subsequently adds a self-contained recovery UKI, and ADR 0025 places all
boot artifacts on one shared ESP without XBOOTLDR.

Under ADR 0043, Milestone A may exercise the same systemd-boot and UKI topology
without the custom trust and signing workflow. Signing remains mandatory for
final acceptance after the deferred design is revalidated.

## Consequences

- Arch uses a small UEFI-only boot manager aligned with its systemd userspace.
- GRUB is not installed merely to support Windows or LUKS2 data volumes.
- Linux kernel and initramfs artifacts must reside on firmware-readable boot
  storage in a format systemd-boot can launch.
- Public boot storage must remain secret-free and its executable artifacts must
  be authenticated.
- Checkpoint and recovery procedures must explicitly preserve, restore, or
  regenerate matching boot artifacts outside an encrypted root filesystem.
  Milestone A may use checksum-verified development artifacts under ADR 0043;
  the hardened workflow must use the signing design accepted after
  revalidation.
- Windows remains bootable through its own UEFI entry if the Arch boot manager
  is damaged.

## References

- systemd-boot:
  https://man.archlinux.org/man/systemd-boot.7
- UAPI Boot Loader Specification:
  https://uapi-group.org/specifications/specs/boot_loader_specification/
- Arch systemd-boot documentation:
  https://wiki.archlinux.org/title/Systemd-boot
