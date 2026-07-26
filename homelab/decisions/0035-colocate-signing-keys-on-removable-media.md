# ADR 0035: Co-locate both signing keys on each removable medium

- Status: Deferred for post-proof revalidation by ADR 0043
- Date: 2026-07-24

## Context

ADRs 0031 and 0034 select a lab-wide Secure Boot signing identity and a
Controller-wide TPM-policy signing identity. ADR 0033 requires them to remain
cryptographically distinct, and ADR 0032 places their private material under
encrypted removable off-host custody.

Every normal Controller UKI requires both policy authorization and Secure Boot
authentication. Separate physical media would add handling, synchronization,
and failure points to every provisioning and boot-artifact update while both
keys would still be exposed to the same designated signing environment during
that work.

## Decision

Store both distinct private keys on the same encrypted primary removable
medium:

- the lab-wide Secure Boot code-signing private key; and
- the Controller-wide TPM-policy signing private key.

Store the backup copy of both keys together on the same separately encrypted
backup medium defined by ADR 0032.

Keep the identities logically and cryptographically separate. Give each key a
role-specific name, expected public-key fingerprint, and explicit signing
configuration. Signing tooling must select the intended key by role rather than
expose one ambiguous generic signer.

Rotating either identity must update and verify both the primary and backup
media before the rotation is complete. The other identity does not rotate
merely because the two share storage.

ADR 0036 subsequently selects LUKS2 for both removable media. The filesystem,
subsequently selected by ADR 0037, is ext4. The directory layout, file
encryption and permissions, and detailed backup-synchronization procedure
remain separate decisions. ADR 0039 subsequently selects one shared passphrase
for both media, and ADR 0040 places its authoritative custody in the operator's
existing off-Controller password manager.

## Consequences

- One primary medium is sufficient for a normal Controller signing session,
  and one backup medium recovers the complete signing capability.
- Provisioning and updates avoid coordinating two pairs of removable devices.
- Theft or compromise of an unlocked medium can expose both signing
  authorities. An attacker with both can create an EFI artifact that satisfies
  Secure Boot and the Controller TPM policy.
- Separate cryptographic identities still prevent accidental cross-use, permit
  independent rotation, and limit compromise that reaches only one key through
  its signing interface rather than the underlying storage.
- This design does not provide physical separation, two-person control, or an
  HSM boundary between the authorities.
- A later requirement for stronger separation requires a new ADR and separate
  custody.

## References

- `ukify` Secure Boot and PCR signing options:
  https://man.archlinux.org/man/ukify.1
- Microsoft Secure Boot key creation and management guidance:
  https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/windows-secure-boot-key-creation-and-management-guidance?view=windows-11
