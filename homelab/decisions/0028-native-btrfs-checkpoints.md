# ADR 0028: Manage checkpoints with native Btrfs operations

- Status: Accepted
- Date: 2026-07-24

## Context

ADR 0016 requires guarded update checkpoints. ADRs 0026 and 0027 select Btrfs
inside LUKS2 and define an operating-system-only root checkpoint boundary.

Snapper can add snapshot metadata, retention, timelines, and rollback helpers.
The Controller update workflow must already coordinate a root checkpoint with
signed UKIs on the separate ESP, package state, service-aware preparation, a
reboot, and post-update health validation. A snapshot manager would not remove
that orchestration.

## Decision

Use native Btrfs subvolume operations as the checkpoint primitive in the
repository-controlled guarded-update workflow.

- Create a read-only snapshot of the operating-system root before a guarded
  update.
- Associate that root snapshot with a backup and manifest of the matching
  shared-ESP artifacts.
- Record enough update and package-state metadata to identify the checkpoint
  and the transaction it protects.
- Use the self-contained recovery UKI to restore a root checkpoint and its
  matching boot artifacts when the installed root is not safely recoverable.
- Do not install Snapper, `snap-pac`, or an automatic timeline-snapshot service
  for the initial Controller.

This decision selects the checkpoint primitive rather than the complete
workflow. Snapshot naming, metadata format, retention limits, deletion policy,
ESP backup format, exact rollback commands, and post-validation checkpoint
lifecycle remain undecided.

## Consequences

- Btrfs remains the only root-snapshot implementation layer.
- The repository owns a small amount of explicit orchestration for root and ESP
  consistency instead of delegating root-only state to a snapshot manager.
- There are no automatic periodic snapshots unless a later ADR adds them.
- Read-only snapshots still consume space as the live filesystem diverges, so
  capacity monitoring and a bounded retention policy are required.
- A same-disk Btrfs snapshot and ESP copy are recovery checkpoints, not off-host
  backups.
- Rollback tooling must refuse an incomplete checkpoint whose root snapshot,
  ESP artifacts, metadata, or integrity validation is missing.
- During ADR 0043's functional proof, a complete checkpoint uses matching
  checksum-verified development ESP artifacts. After hardening, the checkpoint
  must instead satisfy the revalidated signing policy.

## References

- Btrfs subvolume operations:
  https://btrfs.readthedocs.io/en/latest/btrfs-subvolume.html
- Arch Btrfs documentation:
  https://wiki.archlinux.org/title/Btrfs
