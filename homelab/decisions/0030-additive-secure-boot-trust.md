# ADR 0030: Add lab Secure Boot trust without replacing platform ownership

- Status: Deferred for post-proof revalidation by ADR 0043
- Date: 2026-07-24

## Context

The Controller must boot lab-signed systemd-boot and Unified Kernel Images while
also retaining an independent native Windows maintenance installation. Its
firmware may additionally need OEM-signed drivers and option ROMs.

Replacing the factory Platform Key (PK), Key Exchange Keys (KEKs), and
authorized-signature database would make the lab responsible for the complete
firmware trust lifecycle. That would add key custody, compatibility, revocation,
and certificate-transition work without improving the Controller's automatic
LUKS2 unlock boundary: ADR 0029 separately limits that unlock to approved
normal UKI measurements through a signed TPM2 policy.

## Decision

Use an additive Secure Boot trust model for the initial Controller profile.

- Retain the platform's factory or OEM ownership represented by its PK and
  KEKs. Do not replace them with lab-owned PK or KEK material.
- Preserve the compatible OEM and Microsoft trust required for Windows,
  firmware servicing, third-party UEFI applications, and option ROMs.
- Preserve the platform's supported `dbx` revocation-update path.
- Add a lab-controlled public signing certificate to the firmware's authorized
  signature database (`db`) through a firmware-supported, physical-presence
  enrollment procedure that preserves the existing trust entries.
- Sign systemd-boot and all three Controller UKIs with the corresponding lab
  signing identity.
- Continue to authorize automatic LUKS2 unlock only for the two normal
  lab-approved UKIs under ADR 0029. Firmware permission to execute another
  OEM- or Microsoft-trusted EFI image does not grant that image the TPM unlock
  capability.

Before destructive installation, preflight must establish that the target can
retain the required factory trust and enroll the lab certificate without
replacing it. If that cannot be demonstrated, the initial Controller profile
does not support the target and installation must stop before wipe
authorization.

Record the enrolled certificate fingerprints and the retained trust state in
the machine's non-secret provisioning record. Do not put private signing
material in firmware, the ESP, a UKI, or Git.

ADR 0031 subsequently selects one lab-wide Secure Boot signing identity. The
private-key custody model is subsequently resolved by ADR 0032. Signing
automation, rotation and revocation procedure, exact enrollment tooling, and
current certificate manifest remain separate decisions. The manifest must
account for vendor and Microsoft certificate transitions rather than
permanently assuming the factory's original certificate set is sufficient.

## Consequences

- Normal Windows boot, firmware updates, and compatible option ROMs retain
  their conventional trust paths.
- The lab does not take on day-to-day PK, KEK, or complete platform-database
  ownership.
- A lab-signed boot component can execute, but only the measured states
  authorized by ADR 0029 can automatically unlock the Arch root.
- Initial enrollment requires physical presence and varies by firmware.
- Resetting firmware trust to factory defaults may remove the lab certificate.
  Arch then remains encrypted but may not boot until the certificate is
  re-enrolled; off-host recovery material remains required.
- Firmware, `db`, or `dbx` changes are planned maintenance and must be followed
  by Secure Boot, TPM-unlock, recovery-UKI, Windows, and BitLocker validation.
- ADR 0031 accepts that compromise of the shared lab signing private key affects
  every machine that trusts its certificate. Key custody must therefore be
  resolved before implementation.
- The precise Secure Boot-compatible network-provisioning chain remains open.

## References

- Microsoft Secure Boot key creation and management guidance:
  https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/windows-secure-boot-key-creation-and-management-guidance?view=windows-11
- Microsoft Secure Boot certificate update guidance:
  https://learn.microsoft.com/en-us/troubleshoot/windows-client/windows-security/update-secure-boot-certificates
- `sbctl`:
  https://man.archlinux.org/man/sbctl.8.en
