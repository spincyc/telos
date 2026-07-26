# ADR 0021: Install a permanent Windows maintenance environment

## Supersession

ADR 0047 supersedes this decision. The permanent Windows maintenance installation is removed from
the Controller profile in favour of fwupd and vendor-supplied boot media.
This ADR remains as the record of the earlier decision.

- Status: Superseded by ADR 0047
- Date: 2026-07-24

## Context

Some Controller hardware and peripheral firmware can require vendor tools that
run only under a full Windows installation. These tools need access to the
physical hardware and therefore cannot be assumed to work correctly from a
Windows VM.

Windows PE is a deployment and recovery environment rather than a general
Windows runtime. Arbitrary vendor utilities may depend on APIs, installers,
drivers, persistent state, or reboot sequences that WinPE does not provide.
Windows To Go is no longer a supported current-Windows deployment model.

ADR 0020 requires encryption for Windows data-bearing volumes and permits only
minimal, secret-free boot and recovery partitions to remain unencrypted.

## Decision

Include a permanent, licensed, bare-metal Windows maintenance installation in
the initial Controller profile.

- Use Windows only for physical firmware and hardware maintenance.
- Keep Arch Linux as the default boot and the sole normal Controller runtime.
- Do not host Controller services or authoritative configuration in Windows.
- Protect the Windows operating-system volume with BitLocker.
- Keep Windows Boot Manager independently registered as a native UEFI boot
  option.
- Store the BitLocker recovery material off-host under the recovery policy
  required by ADR 0020.
- Treat WinPE and vendor-supplied boot media as supplemental recovery or
  one-off tools, not as the supported primary Windows maintenance path.

The Windows edition, license source, storage allocation, account model, update
cadence, direct-boot user experience, and exact relationship between Windows
Boot Manager and the Linux boot manager remained undecided here. ADR 0022
subsequently selects systemd-boot for Arch while preserving an independent
native Windows UEFI entry; the direct-boot user experience remains open.

ADR 0043 permits the Windows installation and direct UEFI entry to be exercised
during the functional proof. That test is not final Windows acceptance;
BitLocker, Secure Boot, TPM, and recovery behavior must be completed and
retested after boot hardening.

## Consequences

- Controller storage and provisioning must accommodate two operating systems.
- Windows requires periodic maintenance even though it is not the Controller
  runtime.
- Firmware procedures must account for BitLocker suspension and recovery when
  a vendor or Microsoft procedure requires it.
- The native Windows UEFI entry provides a recovery path independent of the
  Linux boot manager.
- A Windows failure cannot prevent Arch from providing Controller services,
  provided the firmware boot order still selects Arch by default.
- The machine needs a valid Windows license with an edition entitled to
  operator-managed BitLocker.
- The destructive-install summary must show both operating systems and their
  encryption state before authorization.

## References

- WinPE overview:
  https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/winpe-intro?view=windows-11
- WinPE application limitations:
  https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/winpe-create-apps?view=windows-11
- Windows To Go support status:
  https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/deployment/windows-to-go/windows-to-go-overview
- BitLocker overview:
  https://learn.microsoft.com/en-us/windows/security/operating-system-security/data-protection/bitlocker/
