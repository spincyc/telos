# ADR 0025: Use one shared EFI System Partition

- Status: Accepted
- Date: 2026-07-24

## Context

The Controller boots Windows Boot Manager, systemd-boot, two normal signed Arch
UKIs, and one self-contained signed recovery UKI. systemd-boot can obtain Linux
artifacts from the EFI System Partition or from a separate XBOOTLDR partition.

XBOOTLDR would separate Linux artifacts from Windows-owned boot files and
provide an independent capacity boundary. It would also add another
firmware-readable, unencrypted partition that must be provisioned, backed up,
validated, and recovered.

A deliberately sized shared ESP can hold all accepted boot artifacts while
keeping one authoritative public boot filesystem.

## Decision

Use one FAT32 EFI System Partition shared by Windows and Arch on the initial
Controller.

- Store Windows Boot Manager in its standard vendor directory.
- Store systemd-boot in its standard vendor directory.
- Store the two normal Arch UKIs and the recovery UKI in the Boot Loader
  Specification location on the ESP.
- Do not create an XBOOTLDR partition.
- Keep the ESP unencrypted, minimal, secret-free, and covered by Secure Boot
  integrity verification under ADR 0020.
- Back up and validate the complete ESP as one unit.

ADR 0043 preserves this physical layout during the functional proof but defers
Secure Boot integrity acceptance. Proof-stage ESP backups and artifacts use
checksums and explicit `development-proof` labeling until hardening.

The exact ESP size must be selected only after measuring the generated UKIs and
allowing documented update and recovery headroom. Fallback-path ownership,
redundant boot-media copies, backup format, and restore procedure remain
undecided.

## Consequences

- Windows and Arch share one boot-filesystem failure and administrative domain.
- Provisioning, backup, integrity checks, and recovery have one boot partition
  to manage instead of an ESP plus XBOOTLDR.
- Windows installation and maintenance must preserve the Arch vendor
  directories and signed UKIs.
- Arch maintenance must preserve Windows Boot Manager and its native firmware
  entry.
- Installer preflight must verify that the ESP has sufficient capacity for the
  current three UKIs and update headroom before modifying the installed system.
- Root-filesystem checkpoints still do not include the ESP; checkpoint recovery
  must coordinate with its matching UKIs.
- Physical disk or ESP failure still requires an off-host recovery path unless
  a future decision adds redundant boot media.

## References

- UAPI Boot Loader Specification:
  https://uapi-group.org/specifications/specs/boot_loader_specification/
- systemd-boot:
  https://man.archlinux.org/man/systemd-boot.7
- EFI System Partition:
  https://wiki.archlinux.org/title/EFI_system_partition
