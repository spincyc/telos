# ADR 0039: Unlock both signing media with one shared passphrase

- Status: Deferred for post-proof revalidation by ADR 0043
- Date: 2026-07-24

## Context

ADR 0036 creates independent LUKS2 volumes on the primary and backup signing
media and requires manual unlock. Separate passphrases would add another
credential-selection and recovery failure mode without separating the private
keys: either medium already contains both signing authorities under ADR 0035.

The passphrase must remain available when the Controller and ordinary network
services are unavailable.

## Decision

Generate one high-entropy random passphrase and enroll it in a LUKS2 keyslot on
both signing-media volumes.

- Generate at least 128 bits of entropy with a cryptographically secure random
  source and encode it in a form suitable for reliable manual entry or transfer.
- Use the same passphrase for the primary and backup, while retaining the
  independently generated LUKS2 volume master key on each medium.
- Enter the passphrase interactively in the designated signing environment.
- Do not store it on either signing medium, any Controller or Workstation, the
  bootstrap or signing host, an installer, PXE storage, Git, a command line,
  environment variable, shell history, log, or generated artifact.
- Keep its authoritative custody off-host and physically separate from both
  signing media.

Changing the shared passphrase is incomplete until the new credential has been
enrolled and tested on both media and the old credential has been removed from
both. Test each medium separately.

ADR 0040 subsequently selects the operator's existing off-Controller password
manager as the authoritative store. The passphrase generator and encoding,
human access policy, input method, keyslot layout, LUKS2 PBKDF parameters, and
rotation cadence remain separate decisions. ADR 0041 subsequently requires one
independent emergency copy, and ADR 0042 selects its sealed paper form.

## Consequences

- Routine signing and recovery use one operator credential instead of selecting
  a passphrase by medium.
- Losing or forgetting the passphrase can make both otherwise healthy media
  inaccessible unless a future independent recovery keyslot is added.
- Disclosure of the passphrase plus possession of either medium exposes both
  private signing keys.
- Disclosure of the passphrase alone or theft of a locked medium alone is
  insufficient to read the keys.
- The backup protects against primary-media loss, but not against loss or
  compromise of their shared passphrase.
- Credential custody cannot depend solely on the Controller being operational.

## References

- `cryptsetup-luksAddKey`:
  https://man.archlinux.org/man/cryptsetup-luksAddKey.8.en
- `cryptsetup-open`:
  https://man.archlinux.org/man/cryptsetup-open.8.en
