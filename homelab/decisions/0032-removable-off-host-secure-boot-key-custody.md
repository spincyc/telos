# ADR 0032: Keep the Secure Boot private key on removable off-host media

- Status: Deferred for post-proof revalidation by ADR 0043
- Date: 2026-07-24

## Context

ADR 0031 selects one Secure Boot signing identity for all managed lab machines.
Keeping its private key online on the Controller or another managed system
would let compromise of that system become compromise of the lab-wide signing
authority.

An online signing service or hardware security module could reduce update
ceremony or make the key non-exportable, but either would add infrastructure,
integration, and recovery work. Controller operating-system updates are already
operator-controlled maintenance under ADR 0016.

## Decision

Keep the lab-wide Secure Boot private key on a primary encrypted removable
medium that is normally detached and powered off.

Use that medium only in a designated trusted signing environment during planned
provisioning and update work. The existing bootstrap machine may provide the
initial signing environment, but the key must not be mounted in its ordinary
PXE-serving context. The exact isolated or ephemeral signing environment
remains an implementation decision. If that bootstrap machine is later
provisioned as a managed Controller or Workstation, signing responsibility must
move elsewhere first.

Do not copy or persist the private key on:

- a Controller or Workstation;
- an EFI System Partition or UKI;
- a PXE root, installer, or target machine;
- the ordinary filesystem of the bootstrap host;
- an always-online signing service; or
- Git, logs, build output, or provisioning records.

Build or prepare artifacts outside the key medium, validate the artifact and
its non-secret manifest in the signing environment, sign it there, verify the
result against the expected public-certificate fingerprint, and return only
the signed artifact and non-secret metadata. Unsigned candidates must remain
outside the active ESP. Package or boot-manager hooks must not install an
unsigned or locally self-signed replacement into the active boot path.

Create one separately encrypted backup copy on a second removable medium. Keep
it offline and physically separate from the primary medium and from the
credential that unlocks either copy. Do not connect the primary and backup
media during the same routine signing session. Periodically verify that the
backup can be decrypted and can produce a signature accepted by the recorded
public certificate; the exact test cadence remains open.

Every guarded Controller full-system upgrade must preflight the signing path
before package mutation, because the transaction may require new systemd-boot,
kernel, initramfs, or UKI signatures. Absence or failure of the signer stops the
update before intentional changes begin. A boot-affecting update is not
successful until all returned artifacts pass signature and manifest validation
and are installed together. Normal boot and ordinary runtime do not require
access to the private key.

ADR 0036 subsequently selects manually unlocked LUKS2 volumes for both
removable media. The signing environment, transfer format, tooling,
temporary-data handling, and detailed rotation and revocation procedure remain
separate decisions. ADR 0040 subsequently selects the operator's existing
off-Controller password manager for unlock-credential custody.

ADR 0033 subsequently applies this custody pattern to a distinct TPM-policy
signing private key. ADR 0035 subsequently places both distinct private keys on
the same physical primary medium and both backup copies on the same physical
backup medium.

## Consequences

- Compromise of a managed machine outside a signing window does not expose the
  detached private key.
- The private key is an exportable software key while its encrypted medium is
  unlocked. Compromise of the designated signing environment during that
  window can expose the lab-wide authority.
- Provisioning and boot-artifact updates require physical access to the primary
  medium; fully remote or unattended signing is unavailable.
- A managed machine may restore a previously checkpointed set of signed ESP
  artifacts without the signer. Fresh or regenerated artifacts require the
  designated signing round trip.
- Losing the primary medium is recoverable from the separately stored,
  periodically tested backup.
- Losing both copies does not stop already signed artifacts from booting, but
  blocks new signed artifacts until a new identity is enrolled on every
  affected machine.
- Suspected key disclosure is a lab-wide replacement and firmware-enrollment
  event.
- A later move to a hardware-backed or network signer requires a new ADR.

## References

- `systemd-sbsign` offline-signing support:
  https://man.archlinux.org/man/systemd-sbsign.1.en
- `ukify` signing-key and OpenSSL provider support:
  https://man.archlinux.org/man/ukify.1
- Microsoft Secure Boot key creation and management guidance:
  https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/windows-secure-boot-key-creation-and-management-guidance?view=windows-11
