# ADR 0033: Separate TPM policy signing from Secure Boot signing

- Status: Deferred for post-proof revalidation by ADR 0043
- Date: 2026-07-24

## Context

ADR 0029 authorizes automatic Controller-root unlock through a signed TPM2
policy over the two normal UKIs' PCR 11 measurements. ADRs 0030 and 0031 define
a lab-wide Secure Boot signing identity whose certificate firmware trusts for
EFI image execution.

Reusing one private key for both purposes would make compromise or misuse of
that key sufficient to satisfy both the executable-authentication and
disk-unlock authorization layers. Separate keys preserve independent
cryptographic roles even when one signing workflow produces both signatures.

## Decision

Create a dedicated TPM signed-PCR policy key pair that is cryptographically
distinct from the lab-wide Secure Boot code-signing key pair.

Use the TPM policy private key only to sign approved PCR 11 policies for the two
normal Controller UKIs:

- the default `linux-lts` UKI; and
- the secondary standard `linux` UKI.

Do not give the recovery UKI a policy signature that authorizes automatic root
unlock. Continue to sign it only for Secure Boot execution under ADR 0024.

Enroll or otherwise bind only the TPM policy public key to the Controller's
LUKS2 TPM2 unlock policy. The public key and its fingerprint are non-secret and
belong in the artifact manifest and machine provisioning record. Never enroll,
embed, or copy the TPM policy private key to a managed machine.

Apply ADR 0032's custody pattern to the TPM policy private key: keep encrypted
primary and backup copies on removable off-host media and use the key only in
the designated signing environment during planned work. ADR 0035 subsequently
co-locates both distinct private keys on the same primary medium and both
backup copies on the same backup medium.

For each normal UKI, the returned artifact must contain a valid TPM policy
signature and a valid Secure Boot signature. The final Secure Boot signature
must authenticate the UKI containing its policy metadata. Verify both
authorities before installing the artifact in the active ESP.

ADR 0034 subsequently makes the TPM policy identity shared across Controllers.
ADR 0035 subsequently resolves its physical-media placement. Its algorithm,
lifetime, exact systemd enrollment and signing commands, rotation procedure,
and additional PCR bindings remain separate decisions.

## Consequences

- Compromise of the Secure Boot signing key alone does not authorize a new UKI
  for automatic LUKS2 unlock.
- Compromise of the TPM policy signing key alone does not make a modified UKI
  executable under Secure Boot.
- An attacker who compromises both authorities can create a boot artifact that
  satisfies both layers. Co-locating their media or exposing them in one
  compromised signing session reduces the practical benefit of separation.
- A live compromise after a legitimate automatic unlock is outside this
  pre-boot separation boundary.
- Losing the TPM policy private key does not invalidate existing signed UKIs,
  but prevents authorizing new normal UKIs until a replacement policy key is
  enrolled from a trusted boot or with recovery material.
- TPM-policy key rotation does not inherently require changing firmware `db`;
  Secure Boot key rotation does not inherently require changing the TPM policy
  authority.
- Normal UKI production now requires two independently verified signatures.

## References

- `systemd-cryptenroll`:
  https://man.archlinux.org/man/systemd-cryptenroll.1
- systemd TPM2 PCR measurements:
  https://systemd.io/TPM2_PCR_MEASUREMENTS/
- `ukify`:
  https://man.archlinux.org/man/ukify.1
