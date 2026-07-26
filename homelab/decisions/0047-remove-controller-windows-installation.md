# ADR 0047: Remove the permanent Windows maintenance installation from the Controller

- Status: Accepted
- Date: 2026-07-25

## Context

ADR 0021 put a permanent, licensed, BitLocker-protected Windows installation on
the Controller solely to run vendor firmware tools. That cost a large disk
allocation, a Windows licence, BitLocker recovery-key custody, a second Secure
Boot trust path, and a materially more complex shared-ESP and partition design,
for a task performed perhaps twice a year.

Most current hardware accepts UEFI capsule updates through fwupd on Linux, and
vendors that do not ship a bootable DOS or EFI updater image on USB.

## Decision

Remove the permanent Windows installation from the Controller profile.

- Perform firmware maintenance with `fwupd` where the vendor publishes to LVFS.
- Otherwise use vendor-supplied bootable media, created on demand.
- The Controller disk carries one ESP, one LUKS2 container and nothing else.
- Preflight records firmware vendor, version and LVFS availability in the
  installation manifest so the maintenance path is known before it is needed.

This decision governs the Controller profile only. The Workstation profile may
still install Windows; that is decided separately.

## Consequences

- ADR 0021 is superseded. ADR 0022's requirement to keep Windows Boot Manager
  independently bootable no longer applies to the Controller.
- ADR 0025's shared ESP is no longer shared. It carries systemd-boot and the
  three UKIs only, which makes ADR 0051's sizing tractable.
- The Microsoft reserved and Windows recovery partitions leave the Controller
  layout entirely.
- No Windows licence, BitLocker key custody or Windows recovery testing is
  required for a Controller.
- If a Controller ever meets hardware that genuinely requires Windows-hosted
  flashing, the operator uses removable media rather than permanent disk.
