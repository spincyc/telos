# ADR 0029: Automatically unlock the Controller root with TPM2

- Status: Deferred for post-proof revalidation by ADR 0043
- Date: 2026-07-24

## Context

The Controller provides foundational DHCP and DNS when configured for isolated
operation. Requiring a person to enter a disk passphrase after every power loss
would prevent those services from recovering unattended.

ADR 0020 requires LUKS2 and Secure Boot. ADR 0023 defines two normal signed UKIs
and ADR 0024 adds a signed self-contained recovery UKI.

A TPM2 device can seal a LUKS2 unlock secret to the physical TPM and to an
approved measured-boot policy. systemd supports a signed PCR policy that
authorizes updated kernel and initramfs states signed by the policy owner rather
than binding permanently to one brittle set of raw PCR values.

TPM-only automatic unlock trades some protection against theft of the complete
working machine for unattended infrastructure recovery. Disk removal, cloning,
or an unauthorized boot environment must still fail to unlock.

## Decision

ADR 0043 defers this decision during the functional proof. Do not enroll a TPM
unlock token or policy in Milestone A; unlock LUKS2 manually. Revisit this ADR
with ADRs 0030 through 0042 after the functional environment works.

Require TPM 2.0 for the initial Controller and automatically unlock its Arch
LUKS2 root only from either normal signed UKI:

- the default `linux-lts` UKI; or
- the secondary standard `linux` UKI.

Bind the TPM enrollment to a signed policy over the normal UKIs' measured boot
state, using the systemd UKI measurement in PCR 11. Do not rely on an
unconstrained TPM enrollment or only on the current raw PCR values. The exact
additional PCR bindings remain undecided. ADR 0033 subsequently selects a
dedicated TPM-policy signing identity distinct from the Secure Boot signer and
applies ADR 0032's removable off-host custody pattern to its private key. ADR
0034 subsequently shares that policy identity across Controllers without
sharing their TPM-sealed LUKS2 secrets.

Enroll a separate, high-entropy LUKS2 recovery key. Store it off-host and never
in Git, the ESP, a UKI, ordinary logs, or the Controller's only recovery copy.
If TPM policy validation fails, early boot must fall back to recovery-key entry
without weakening or replacing the policy automatically.

Authenticate the recovery UKI with Secure Boot, but do not give it the signed
PCR authorization needed for automatic LUKS2 unlock. Recovery boot always
requires separately held recovery material.

Do not require a TPM PIN for normal Controller boot.

ADR 0030 subsequently retains OEM and Microsoft firmware trust while adding a
lab signer to Secure Boot `db`. That broader permission to execute an EFI image
does not broaden this TPM policy: only the two approved normal lab UKI measured
states receive automatic root unlock. ADR 0031's lab-wide Secure Boot signing
identity is not thereby selected as the TPM-policy signing identity; ADR 0033
subsequently requires a separate key pair.

## Consequences

- A trusted normal boot can restore Controller services without a person at the
  console.
- Moving or cloning the encrypted storage to another machine does not carry the
  TPM unlock capability with it.
- An altered or unauthorized UKI does not receive the LUKS2 unlock secret.
- Theft of the complete machine may allow it to unlock while booting its
  approved OS; operating-system authentication and runtime security remain
  necessary.
- TPM clearing, motherboard replacement, trust-policy damage, and some firmware
  or Secure Boot changes can require the recovery key.
- Installation preflight must verify a usable TPM 2.0 device before destructive
  authorization for the Controller profile.
- Provisioning and recovery acceptance must separately test normal TPM unlock,
  refusal from the recovery UKI, and successful off-host recovery-key unlock.
- Windows BitLocker TPM behavior remains an independent Windows decision.

## References

- `systemd-cryptenroll`:
  https://man.archlinux.org/man/systemd-cryptenroll.1
- systemd TPM2 PCR measurements:
  https://systemd.io/TPM2_PCR_MEASUREMENTS/
- UAPI Linux TPM PCR Registry:
  https://uapi-group.org/specifications/specs/linux_tpm_pcr_registry/
