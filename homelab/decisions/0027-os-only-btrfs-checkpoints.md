# ADR 0027: Limit root checkpoints to operating-system state

- Status: Accepted
- Date: 2026-07-24

## Context

ADR 0016 requires recoverable pre-update checkpoints, and ADR 0026 selects
Btrfs inside LUKS2 for the Arch root.

Rolling the entire machine backward after a failed operating-system update
could discard newer logs, operator files, DHCP leases, DNS state, databases, or
other service data. Excluding all of `/var/lib`, however, would separate
pacman's database and other version-coupled operating-system state from the
packages a root checkpoint is intended to restore.

The checkpoint boundary therefore needs to follow state ownership rather than
one coarse directory rule.

## Decision

Make the root Btrfs checkpoint an operating-system checkpoint.

The checkpointed root includes:

- installed operating-system files and libraries;
- `/etc` and other declarative host configuration;
- pacman's database and other package-manager state; and
- system state that must remain version-aligned with the installed packages.

Use separate Btrfs subvolumes, excluded from a root checkpoint, for:

- ordinary user home directories and the root operator's home;
- logs;
- caches and disposable temporary state;
- the snapshot store itself; and
- mutable application and Controller service data.

Do not exclude all of `/var/lib` as one unit. Keep pacman and other
version-coupled operating-system state with the root, and assign mutable service
paths to separate subvolumes when each service is defined.

The exact subvolume names, mount options, retention rules, and service paths
remain undecided. ADR 0028 subsequently selects native Btrfs operations as the
checkpoint primitive.

## Consequences

- A root rollback restores packages, pacman state, and declarative host
  configuration together.
- Logs and operator data survive an operating-system rollback.
- Rolling back the OS does not silently replace mutable service data with an
  older same-disk snapshot.
- The service inventory must classify every persistent path as
  version-coupled OS state, mutable service state, cache, log, or operator data.
- A service update that migrates its data schema may make the newer data
  incompatible with a rolled-back binary. Such updates need
  application-consistent backup and rollback procedures; an OS-only checkpoint
  is not sufficient.
- Separate subvolumes are not included in a root snapshot even when mounted
  beneath the root path, so backup and restore procedures must cover them
  explicitly.
- The shared ESP remains outside the Btrfs checkpoint and requires coordinated
  UKI recovery under ADRs 0023 through 0025.

## References

- Btrfs subvolumes:
  https://btrfs.readthedocs.io/en/latest/Subvolumes.html
- Arch Btrfs documentation:
  https://wiki.archlinux.org/title/Btrfs
