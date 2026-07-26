# ADR 0019: Require UEFI boot for the Controller

- Status: Accepted
- Date: 2026-07-24

## Context

The initial Controller must be installed reproducibly through the network-boot
workflow and expose both accepted kernel choices after installation. Supporting
both UEFI and legacy BIOS would require separate boot artifacts, installation
paths, partition assumptions, and recovery tests.

Modern UEFI provides one consistent baseline for automated provisioning and
installed-system boot. Legacy BIOS compatibility is not required for the first
Controller acceptance target.

## Decision

Require the initial Controller profile to provision and boot in UEFI mode.
Legacy BIOS and Compatibility Support Module boot are unsupported.

The installer preflight must verify that it is running in UEFI mode before
offering destructive authorization. The eventual installed-system acceptance
test must verify UEFI boot with `linux-lts` as the default and standard `linux`
available as the secondary kernel.

This decision applies to the Controller profile. It does not independently
decide the firmware requirements for every future Workstation target.

ADR 0020 subsequently requires Secure Boot and encryption at rest. ADR 0030
retains factory PK and KEK ownership while adding the lab signer to `db`.
Disk partitioning and the precise UEFI network-boot chain remain separate
decisions. ADR 0022 subsequently selects systemd-boot for Arch, and ADR 0023
selects signed Unified Kernel Images.

## Consequences

- The Controller has one firmware boot path to implement, document, and test.
- Installer media and scripts do not need a legacy BIOS branch.
- A Controller target booted in legacy or CSM mode must fail preflight before
  any disk modification.
- Older hardware without usable UEFI cannot run the initial Controller profile.
- Legacy support, if later required, needs a separate ADR and acceptance path.

## References

- Arch UEFI documentation:
  https://wiki.archlinux.org/title/Unified_Extensible_Firmware_Interface
- Arch installation guide boot-mode verification:
  https://wiki.archlinux.org/title/Installation_guide#Verify_the_boot_mode
