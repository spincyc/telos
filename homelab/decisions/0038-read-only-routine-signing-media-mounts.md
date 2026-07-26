# ADR 0038: Mount signing media read-only during routine signing

- Status: Deferred for post-proof revalidation by ADR 0043
- Date: 2026-07-24

## Context

ADR 0037 selects ext4 inside each signing-media LUKS2 volume. Routine signing
only needs to read the two private keys and their metadata; signed artifacts
are returned to a separate staging area. Allowing ordinary writes to the key
medium during every signing session would add avoidable corruption and
accidental-change risk.

An ext4 filesystem mounted only with `ro` may still replay a dirty journal and
write to the device. A routine signing session therefore needs both a
non-writing mount configuration and a fail-closed response to an unclean
filesystem.

## Decision

During routine signing:

- open the LUKS2 mapping read-only;
- verify the expected LUKS2 and ext4 identities;
- require the ext4 filesystem to be clean before mounting it;
- mount it with `ro,noload,nodev,nosuid,noexec`;
- read private keys only through their role-specific configured paths; and
- write signing requests, signatures, completed artifacts, logs, and temporary
  files somewhere other than the signing medium.

If the filesystem is dirty, damaged, unexpectedly writable, or has the wrong
identity, stop signing. Do not replay its journal or repair it implicitly in
the routine path.

Permit writes to the decrypted volume, including a read-write mount, only
during an explicit signing-media maintenance operation, such as:

- initial key creation;
- an authorized key or certificate rotation;
- a verified metadata change;
- primary-to-backup synchronization; or
- filesystem repair.

A writable operation must identify whether it targets the primary or backup,
validate the pre-change key fingerprints and manifest, produce and validate a
post-change manifest, flush writes, cleanly unmount ext4, close LUKS2, and
detach the medium before it is complete.

Keep the backup detached except during planned synchronization, read-only
recovery testing, or repair. Routine trial-signature tests use the same
read-only policy as the primary.

The exact mount point, filesystem-cleanliness command, writable-maintenance
authorization, staging location, manifest format, synchronization procedure,
and temporary-data cleanup remain separate decisions.

## Consequences

- Normal signing cannot accidentally alter, rotate, or delete the stored keys.
- `noload` prevents ext4 journal replay from silently turning a nominally
  read-only session into a write.
- An interrupted prior write forces a visible maintenance event before further
  signing.
- Key creation, rotation, and backup synchronization require a deliberate
  writable workflow with more checks.
- Read-only mounting does not protect an unlocked private key from a
  compromised signing environment; it protects the stored media from writes.

## References

- Linux ext4 mount options:
  https://docs.kernel.org/admin-guide/ext4.html
- `mount` read-only behavior:
  https://man7.org/linux/man-pages/man8/mount.8.html
- `cryptsetup-open`:
  https://man.archlinux.org/man/cryptsetup-open.8.en
