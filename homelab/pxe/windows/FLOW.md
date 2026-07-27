# Windows 11 UEFI network-install flow

This is the phase-one Windows path. It uses the unmodified Microsoft Setup UI
and stores no answer file, product key, domain credential, or disk-selection
answer.

## Published inputs

Publish one immutable release through two read-only paths:

- HTTP `/windows/<release>/` contains `wimboot`, `bootmgr`, `BCD`,
  `boot.sdi`, `boot.wim`, and `boot.ipxe`.
- SMB `\\bootstrap-dc\windows-<release>` contains the complete extracted
  Microsoft ISO tree, including root `setup.exe` and exactly one
  `sources\install.wim` or `sources\install.esd`.

The controller must verify both trees against one release receipt before
changing a `current` pointer. The SMB share permits reads only. Its install-only
account has no interactive login, write, administration, or access to another
share. Supply that account's temporary password at the console; never put it in
iPXE, BCD, WinPE, Git, an answer file, or a process argument.

## Firmware and PXE

Use QEMU/OVMF or physical UEFI firmware with:

- UEFI network boot, never legacy BIOS;
- TPM 2.0 (`swtpm` in QEMU);
- Secure-Boot-capable firmware, with Secure Boot disabled for phase one;
- an emulated NVMe or SATA/AHCI target disk, not an undriven virtio disk; and
- an `e1000e` network adapter for the stock Microsoft WinPE driver set.

The gateway supplies DHCP and the controller's iPXE URL. The controller does
not answer DHCP. iPXE loads, in order:

```text
wimboot
bootmgr                 as bootmgr
boot/BCD                as BCD
boot/boot.sdi           as boot.sdi
sources/boot.wim        as boot.wim
```

`install.wim` is deliberately not a wimboot initrd. WinPE obtains it from SMB,
which avoids copying a multi-gigabyte image into the firmware boot transaction.

## WinPE and Setup

At the first Microsoft Setup screen:

1. Press **Shift+F10** to open Command Prompt.
2. Run `wpeinit` and wait for it to finish.
3. Run `ipconfig /all`. Verify the provisioning-subnet address, gateway, DNS
   server, and absence of an unexpected DHCP authority.
4. Run:

   ```bat
   net use W: \\bootstrap-dc\windows-<release> * /user:TELOS\pxe-install
   ```

   Type the temporary install-only password when prompted. The trailing `*`
   is essential: it keeps the password out of command history and the process
   arguments.
5. Run `dir W:\setup.exe` and `dir W:\sources\install.wim`. For ESD media, use
   `install.esd`. Compare the install image's exact byte count to the immutable
   release receipt. Stock WinPE does not include `certutil` or PowerShell, so
   it must not be asked to hash the image. Before publication, the controller
   hashes every source artifact and verifies its read-only tree; its SMB read
   log ties this client session to that verified release.
6. Run:

   ```bat
   W:\setup.exe /InstallFrom W:\sources\install.wim
   ```

   Substitute `install.esd` only when the verified release uses ESD.
7. In the genuine Setup UI, select exactly **Windows 11 Pro**. The verified
   25H2 V2 English x64 media records it as image index 6, but the visible
   edition name is the authorization gate; do not select by an assumed index.
8. Choose **Custom: Install Windows only**. Inspect the disk identity and size.
   Create the approved Windows-first partition layout and stop if another disk
   is present or the measurements differ from the recorded plan.
9. Complete Setup without a product-key answer file. Physical ThinkPads use
   their firmware-backed entitlement; the QEMU proof may remain unactivated.

The harness may drive these same visible controls, but it must not introduce
`Autounattend.xml`, `Unattend.xml`, `ei.cfg`, a product-key file, or a hidden
edition-selection path.

## Required evidence

A passing local lifecycle retains:

- OVMF, TPM, CPU, disk-controller, NIC, and PXE command lines;
- DHCP provenance showing only the simulated gateway answered;
- HTTP request logs for every wimboot input;
- SMB authentication and read logs for the immutable release;
- the ISO, boot payload, and install-image digests;
- screenshots or OCR checkpoints naming **Windows 11 Pro**, the target disk,
  partition measurements, first boot, and activation state;
- `Get-ComputerInfo`, `Get-Tpm`, and partition inventory after first boot; and
- proof that no answer file or secret-bearing process argument existed.

Direct ISO attachment may be a diagnostic comparison, but it does not satisfy
PXE acceptance.
