# ADR 0064: Narrow phase one to a workstation factory

- Status: Accepted
- Date: 2026-07-27

## Context

The broader Controller design delays the immediate need: mint repeatable
Windows 11 Pro and Arch laptops whose users share one identity.

## Decision

Phase one delivers only:

- an isolated, reproducible bootstrap domain-controller development VM;
- host-level Samba AD DNS and identity;
- iPXE, TFTP and HTTP installation services;
- configurable Windows 11 Pro and Arch dual boot;
- Windows-default startup and cross-platform domain logon; and
- non-blocking optional SMB storage.

Every phase has a Make target for Arch dependencies, build, test, publish,
rollback and convergence. Hardware and UniFi changes follow isolated QEMU
tests and an explicit integration gate.

Home automation, generalized Controller services, encryption, Secure Boot,
temporary revocation enforcement and high availability remain later work.
This sequencing supersedes ADR 0007 where it requires Controller-first
acceptance.

## Consequences

- A usable pilot arrives before the complete platform.
- Pilot workstations are development systems, not security-hardened systems.
- Deferred capabilities stay visible in a migration register.
