# ADR 0037: Use ext4 inside the signing-media LUKS2 volumes

- Status: Deferred for post-proof revalidation by ADR 0043
- Date: 2026-07-24

## Context

ADR 0036 selects one LUKS2-encrypted data volume on each removable signing
medium. The inner filesystem stores a small, fixed set of private keys and
related metadata. It does not need snapshots, compression, pooling,
cross-platform access, or a volume-management layer.

The filesystem must retain ordinary Unix ownership and permission semantics and
recover predictably after an interrupted signing session.

## Decision

Create one ext4 filesystem inside each signing-media LUKS2 volume:

- one independently created ext4 filesystem on the primary medium; and
- one independently created ext4 filesystem on the backup medium.

Store private keys, public certificates, fingerprints, and non-secret
role-specific metadata as ordinary files with Unix ownership and permissions.
Do not use FAT, exFAT, Btrfs, ZFS, or another inner filesystem for the initial
signing-media design.

Give the two filesystems distinct, non-secret UUIDs and labels so tooling can
verify that the operator attached the intended primary or backup medium before
opening or synchronizing it. Do not use a device path such as `/dev/sdX` as
identity.

The exact labels, filesystem creation options, directory layout, ownership,
permissions, mount options, free-space threshold, check cadence, and
backup-synchronization procedure remain separate decisions.

ADR 0038 subsequently selects read-only routine mounts with
`ro,noload,nodev,nosuid,noexec` and reserves writable mounts for explicit
signing-media maintenance.

## Consequences

- The signing environment uses mature Linux filesystem tooling and normal Unix
  access controls.
- Journaling improves recovery from an interrupted write but does not replace
  clean unmounting, the second medium, or tested recovery.
- The media do not gain snapshots or checksumming of file data; those features
  are unnecessary for the small key store and its explicit verified backup.
- Windows and FreeBSD access remains unsupported, consistent with ADR 0036.
- Primary and backup media have independent filesystem identities, reducing
  accidental device confusion during synchronization.

## References

- Linux ext4 documentation:
  https://docs.kernel.org/filesystems/ext4/index.html
- `mke2fs`:
  https://man.archlinux.org/man/mke2fs.8.en
