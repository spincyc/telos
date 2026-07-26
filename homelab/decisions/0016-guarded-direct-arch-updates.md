# ADR 0016: Use guarded direct Arch updates

- Status: Accepted
- Date: 2026-07-24

## Context

Arch Linux is a rolling-release distribution. ADR 0015 therefore left the
Controller's update, validation, and rollback policy unresolved.

A true staged-promotion workflow would need to preserve the exact tested
package set through a private repository, package cache, or dated repository
snapshot. That would add a package-distribution layer on top of pacman for a
single Controller.

The `linux-lts` package changes only the kernel branch. It does not turn Arch
into a fixed-release distribution or stabilize independently updated
user-space packages and services.

## Decision

Use pacman directly for guarded Controller updates:

- do not apply unattended operating-system package upgrades;
- review Arch news and the complete pending update set before maintenance;
- create a recoverable system checkpoint before changing packages;
- perform a supported full-system pacman upgrade, not a partial upgrade;
- reboot when the transaction affects the kernel, initramfs, system manager,
  networking stack, or foundational services;
- automatically validate Controller health, including DHCP, DNS, and PXE,
  after the update; and
- restore the checkpoint or rebuild from recorded inputs if validation fails.

Do not create a private Arch repository, a package-promotion service, or a
wrapper package manager for the initial Controller.

This ADR defines the workflow boundary, not its implementation. Subsequent ADRs
select the kernels and Btrfs-inside-LUKS2 root filesystem, and ADR 0028 selects
native Btrfs checkpoint operations. ADR 0032 requires the off-host Secure Boot
signing path to pass preflight before a hardened full-system upgrade mutates
packages. ADR 0043 defers that signing requirement during the functional proof:
the proof workflow must instead regenerate, checksum, install, and validate the
matching development UKIs as part of the guarded transaction. Exact health
checks, maintenance cadence, retention, and package-state recording format
remain undecided.

## Consequences

- Pacman remains the sole operating-system package manager.
- Maintenance is simpler than a repository-promotion pipeline.
- Updates require an operator-controlled maintenance window.
- After security hardening, a boot-affecting upgrade includes whatever signing
  workflow is accepted when ADRs 0029 through 0042 are revalidated.
- The update transaction uses one internally consistent repository state and
  avoids unsupported partial upgrades.
- Reproducibility and recovery depend on recorded inputs, working checkpoints,
  and periodically tested rebuild procedures.
- A future fleet or availability requirement may justify a package mirror or
  staged-promotion system through a new ADR.

## References

- Arch system maintenance:
  https://wiki.archlinux.org/title/System_maintenance
- `checkupdates`:
  https://man.archlinux.org/man/extra/pacman-contrib/checkupdates.8.en
- Arch Linux news:
  https://archlinux.org/news/
- Arch `linux-lts` package:
  https://archlinux.org/packages/core/x86_64/linux-lts/
