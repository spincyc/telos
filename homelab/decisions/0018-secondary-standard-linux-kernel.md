# ADR 0018: Install the standard Linux kernel as a secondary kernel

- Status: Accepted
- Date: 2026-07-24

## Context

ADR 0017 makes Arch's `linux-lts` package the default Controller kernel. An LTS
branch may lack support for very recent hardware or encounter a branch-specific
regression. A second official Arch kernel can provide an alternate local boot
path without changing the default.

A secondary kernel does not protect against failures shared by both kernels,
including broken boot configuration, initramfs generation, storage, firmware,
or user-space packages.

## Decision

Install Arch's official standard `linux` package as the secondary Controller
kernel. Keep `linux-lts` as the default boot selection.

Both kernels are managed by pacman and updated in the same guarded full-system
transaction defined by ADR 0016.

ADR 0022 subsequently selects systemd-boot. The eventual configuration must
expose an operator-selectable standard-kernel entry without making it the
automatic default; exact menu behavior remains open.

## Consequences

- The Controller has a local alternate kernel when the LTS branch lacks needed
  hardware support or has a branch-specific failure.
- Kernel packages consume additional boot and root-filesystem space.
- Initramfs generation and post-update validation must cover both kernels.
- Health validation must confirm that `linux-lts` remains the default.
- The standard kernel is not a known-good previous version and is not a
  substitute for a system checkpoint, off-host recovery media, or rebuild.
- Out-of-tree kernel modules, if introduced later, must work with both kernels
  or explicitly document the reduced recovery path.

## References

- Arch `linux` package:
  https://archlinux.org/packages/core/x86_64/linux/
- Arch `linux-lts` package:
  https://archlinux.org/packages/core/x86_64/linux-lts/
- Arch supported kernels:
  https://wiki.archlinux.org/title/Kernel
