# ADR 0026: Use Btrfs inside LUKS2 for the Arch root

- Status: Accepted
- Date: 2026-07-24

## Context

ADR 0016 requires a recoverable checkpoint before guarded Arch package
updates, and ADR 0020 requires Linux data-bearing volumes to use LUKS2.

The root filesystem needs reliable ordinary operation and a practical way to
capture a coherent pre-update filesystem state. Ext4 would require a separate
volume-management snapshot layer. ZFS would add out-of-tree kernel modules to a
rolling Arch host that maintains two kernel branches. Btrfs supplies native
copy-on-write subvolumes, snapshots, checksums, and send/receive support through
the in-kernel Linux storage stack.

## Decision

Use Btrfs for the initial Controller's Arch root filesystem, contained inside a
LUKS2-encrypted volume.

This decision selects the root filesystem and encryption layering only. ADR
0027 subsequently defines the operating-system checkpoint boundary. The
following remain open:

- compression and mount options;
- swap implementation;
- service-data placement and application-consistent backup behavior;
- multi-device layout or redundancy;
- storage-capacity allocations.

ADR 0028 subsequently selects native Btrfs operations for checkpoints.
ADR 0029 subsequently defines automatic TPM2 root unlock plus an off-host
recovery key.

Additional persistent data-bearing volumes must still satisfy ADR 0020 but do
not automatically inherit this exact filesystem choice.

## Consequences

- Pre-update checkpoints can use native read-only Btrfs snapshots without an
  additional LVM layer.
- Btrfs checksums detect data and metadata corruption, but correction depends on
  another valid copy and separately selected redundancy.
- A snapshot shares the physical failure domain with its source and is not a
  backup.
- Snapshot behavior follows subvolume boundaries; nested or separately mounted
  subvolumes are not automatically part of a root snapshot. ADR 0027 defines
  the OS-versus-mutable-state boundary.
- A live filesystem snapshot may be crash-consistent rather than
  application-consistent; stateful services need quiescing or native backup
  procedures.
- The shared ESP and its UKIs sit outside Btrfs and require coordinated backup,
  validation, and recovery.
- The self-contained recovery UKI must include cryptsetup and Btrfs support.

## References

- Arch Btrfs documentation:
  https://wiki.archlinux.org/title/Btrfs
- Arch dm-crypt whole-system documentation:
  https://wiki.archlinux.org/title/Dm-crypt/Encrypting_an_entire_system
- Btrfs subvolume documentation:
  https://btrfs.readthedocs.io/en/latest/Subvolumes.html
