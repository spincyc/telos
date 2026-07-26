# ADR 0034: Share one TPM policy signing identity across Controllers

- Status: Deferred for post-proof revalidation by ADR 0043
- Date: 2026-07-24

## Context

ADR 0033 separates TPM signed-PCR policy authorization from Secure Boot code
signing but leaves the TPM policy key's scope open. A unique policy key per
Controller would limit one key's authorization scope, but would also require
per-machine private-key generation, backup synchronization, selection, and
rotation during provisioning and every UKI update.

Each Controller's LUKS2 unlock secret is already sealed to that machine's TPM.
Sharing the policy-signing authority does not share the sealed secret or make a
disk portable between TPMs.

## Decision

Use one dedicated TPM policy signing identity across all machines provisioned
with the Controller profile.

- Bind the same TPM policy public key to each Controller's LUKS2 signed-PCR
  policy.
- Use the corresponding shared private key to sign approved PCR 11 policies
  for each Controller's two normal UKIs, including instance-specific UKIs.
- Record and verify the common policy-public-key fingerprint in the Controller
  profile artifact manifest and each instance's non-secret provisioning
  record.
- Do not generate or maintain a separate TPM policy private key for every
  Controller.

This does not create a shared LUKS2 recovery key, volume key, TPM-sealed secret,
or TPM enrollment. Those remain unique to each Controller. Moving an encrypted
disk to another Controller does not move its automatic-unlock capability.

The identity remains cryptographically separate from the lab-wide Secure Boot
signer under ADR 0033 and follows ADR 0032's removable off-host custody model.
ADR 0035 subsequently places both private keys on the same primary removable
medium and both backup copies on the same backup medium.

This decision applies only to the accepted Controller automatic-unlock design.
It does not enroll Workstations or future profiles into the policy without a
separate decision.

## Consequences

- Controller provisioning and updates manage one policy-signing identity and
  fingerprint rather than a private-key inventory per machine.
- A compatible policy signature can be generated through one consistent
  signing workflow even when a UKI contains instance-specific data.
- Compromise of the shared policy private key affects policy authorization for
  every Controller. An attacker still needs to satisfy Secure Boot separately,
  and each LUKS2 secret remains sealed to its own TPM.
- Policy-key rotation requires updating every Controller's TPM enrollment and
  normal UKIs, but does not inherently require changing firmware `db`.
- Losing the private key leaves existing signed UKIs usable but blocks new
  policy signatures for all Controllers until a replacement is enrolled.

## References

- `systemd-cryptenroll`:
  https://man.archlinux.org/man/systemd-cryptenroll.1
- systemd TPM2 PCR measurements:
  https://systemd.io/TPM2_PCR_MEASUREMENTS/
