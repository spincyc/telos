# ADR 0017: Use linux-lts as the default Controller kernel

- Status: Accepted
- Date: 2026-07-24

## Context

ADR 0015 selects Arch Linux for the Controller, and ADR 0016 defines guarded
full-system updates. Arch offers multiple supported kernel packages, including
the standard `linux` package and the upstream long-term-support branch packaged
as `linux-lts`.

The Controller prioritizes predictable infrastructure operation over early
access to kernel features. Selecting an LTS kernel reduces kernel feature churn,
but it does not stabilize Arch user space or replace whole-system recovery.

## Decision

Use Arch's official `linux-lts` package as the default kernel for the initial
Controller profile.

This decision did not determine whether the profile also installs a secondary
kernel; ADR 0018 subsequently selected the standard `linux` package for that
role. This decision does not alter the guarded full-system update policy in ADR
0016.

## Consequences

- The normal Controller boot path uses an upstream long-term-support kernel
  maintained as an official Arch package.
- Pacman continues to update the kernel as part of full-system upgrades.
- User-space packages and foundational services remain rolling-release
  software.
- Hardware validation must confirm that the selected LTS branch supports the
  target Controller.
- A recovery checkpoint remains necessary because an LTS kernel is not a
  whole-system rollback mechanism.
- ADR 0018 defines secondary-kernel installation; boot-menu behavior remains
  open.

## References

- Arch `linux-lts` package:
  https://archlinux.org/packages/core/x86_64/linux-lts/
- Arch supported kernels:
  https://wiki.archlinux.org/title/Kernel
