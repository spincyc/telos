# ADR 0036: Encrypt signing media with LUKS2

- Status: Deferred for post-proof revalidation by ADR 0043
- Date: 2026-07-24

## Context

ADR 0035 places both private signing keys on one primary removable medium and
both backup copies on a second medium. Those media require an encryption format
that is directly supported by the Linux signing environment without a custom
key-storage service or application-specific encryption layer.

Cross-platform access is not a goal. Restricting private-key access to the
designated Linux signing environment is part of the custody boundary.

## Decision

Use one LUKS2-encrypted data volume on each signing medium:

- one independently encrypted LUKS2 volume on the primary medium; and
- one independently encrypted LUKS2 volume on the backup medium.

Place all private signing material on the filesystem inside that encrypted
volume. Do not create an unencrypted data filesystem or private-key copy
elsewhere on either medium. The partition table and LUKS2 header are mandatory
unencrypted metadata and must contain no secrets beyond the encrypted keyslot
material intrinsic to LUKS2.

Require an operator-supplied unlock credential in the designated signing
environment. Do not configure TPM auto-unlock, host-stored keyfiles, or another
automatic unlock path for either removable volume.

After signing, unmount the filesystem, close the LUKS mapping, and physically
detach the medium. The signing workflow must fail closed if either operation
does not complete cleanly.

Record the non-secret volume identifiers and the exact cryptographic and key
derivation parameters used to create each volume. Do not expose an unlock
credential in that record.

ADR 0037 subsequently selects ext4 as the inner filesystem. The partition
layout, LUKS2 cipher and PBKDF parameters, LUKS header backup procedure,
file-level key encryption, and rekey procedure remain separate decisions. ADR
0038 subsequently selects the routine mount policy, and ADR 0039 selects one
shared manually entered passphrase. ADR 0040 subsequently places its
authoritative custody in the operator's existing off-Controller password
manager.

## Consequences

- Arch and other Linux signing environments can use standard `cryptsetup`
  tooling without a new encryption application.
- Windows and FreeBSD are not supported signing-media access environments.
- No private signing key is readable while the volume is closed, assuming the
  unlock credential and encryption remain uncompromised.
- Once unlocked, LUKS2 does not protect the keys from the signing environment;
  ADR 0032's trusted-environment requirement remains essential.
- LUKS2 encryption alone does not make the stored files an authenticated
  signing manifest. Public-key fingerprints and trial-signature verification
  remain required.
- Damage to a LUKS2 header can make an otherwise intact volume inaccessible;
  the second medium and a future header-backup procedure provide recovery.

## References

- `cryptsetup-luksFormat`:
  https://man.archlinux.org/man/cryptsetup-luksFormat.8.en
- `cryptsetup-open`:
  https://man.archlinux.org/man/cryptsetup-open.8.en
- Arch dm-crypt documentation:
  https://wiki.archlinux.org/title/Dm-crypt
