# ADR 0015: Use Arch Linux for the Controller host

- Status: Accepted
- Date: 2026-07-24

## Context

ADR 0014 places foundational services directly on the Controller host. The
preferred host candidates were Arch Linux and FreeBSD.

The Controller is not only a DHCP/DNS appliance. It must also provide network
boot and installation assets, support orchestration, and remain suitable for
future Linux-hosted services. Requiring Linux VMs for otherwise ordinary
workloads would work against the host-first design.

Arch Linux shares its installation and image-building ecosystem with the
Arch-based portions of the Workstation provisioning flow. FreeBSD offers a
cohesive base system, ZFS, jails, and strong network-service capabilities, but
software that assumes Linux kernel interfaces may require a Linux VM.

## Decision

Use Arch Linux as the host operating system for the initial Controller profile.

This decision selected the operating-system family only. Subsequent ADRs select
the kernels and Btrfs-inside-LUKS2 root filesystem. The installation package
state and complete rollback mechanism remain open.

FreeBSD is not part of the initial Controller baseline. It remains available
for a future profile or for a workload that specifically benefits from it.

## Consequences

- Controller and Arch Workstation provisioning can reuse Archiso concepts,
  artifacts, and operational knowledge.
- The Controller can run ordinary Linux applications and containers without a
  Linux compatibility layer or mandatory Linux VM.
- Arch's rolling release model requires an explicit update, validation, and
  rollback policy before the Controller is considered production-ready.
- Reproducible builds must record the exact package state and installation
  inputs rather than treating "current Arch" as a sufficient specification.
- Hardware prerequisites and pre-install validation remain part of the generic
  Controller profile.

## References

- Archiso:
  https://wiki.archlinux.org/title/Archiso
- `archinstall`:
  https://man.archlinux.org/man/archinstall.1
- FreeBSD Linux binary compatibility:
  https://docs.freebsd.org/en/books/handbook/linuxemu/
- Containers on FreeBSD:
  https://docs.freebsd.org/en/books/handbook/containers/
