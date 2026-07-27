# Offline Controller seed

`build.py` creates an ignored data ISO containing a fresh Arch package closure,
a `repo-add` database, the committed public Telos source, an installer, and a
hash receipt. It archives `HEAD`, never the working tree, so a private sibling
repository and untracked instance data cannot enter the image.

Build on Arch Linux:

```sh
python homelab/seed/build.py
```

The default output is
`homelab/var/seed/telos-controller-seed.iso`. The builder synchronizes isolated
pacman databases on every run and downloads the full closure even when a
package is installed on the build host. Pacman runs under `fakeroot`; staging
and final publication remain owned by the caller. The ISO is
written under a temporary name and atomically replaces the prior output only
after `xorriso` succeeds.

On an Arch live system, mount the data ISO and run:

```sh
sudo /path/to/seed/install-controller-deps /path/to/seed
```

The seed deliberately contains no inventory, credentials, domain name, host
name, address plan, or other instance value. Apply the separately held private
overlay only after the public bootstrap completes.

## Temporary VM operator sequence

Build or refresh every local artifact from a clean checkout:

```sh
make homelab-bootstrap-deps
make homelab-media-arch
make homelab-bootstrap-seed
make homelab-bootstrap-vm-create APPLY=1
```

Start the isolated VM with both read-only discs:

```sh
make homelab-bootstrap-vm-run \
  SEED_ISO=homelab/var/seed/telos-controller-seed.iso APPLY=1
```

At the Arch boot entry, press `e`, append
`console=ttyS0,115200n8` to the Linux kernel line, and boot the edited entry.
This edit affects only the current boot. Wait for the `root@archiso` prompt.

Identify the two optical discs by label; do not guess device names:

```sh
lsblk -o NAME,TYPE,SIZE,LABEL,MODEL,SERIAL
blkid
mkdir -p /run/telos-seed
mount -L TELOS_SEED /run/telos-seed
sed -n '1,80p' /run/telos-seed/receipt.json
```

Run the interactive installer:

```sh
/run/telos-seed/install-controller /run/telos-seed
```

It accepts only the VM disk with serial `TELOS-BOOTSTRAP-DC-001` and requires
the exact phrase `ERASE TELOS-BOOTSTRAP-DC-001` before erasing it. It then
prompts at the console for the temporary `local-rescue` password twice. The
operator must type it directly; it must not appear in a command, answer file,
Make variable, transcript, or Git repository.

The installer creates a 1 GiB FAT32 EFI System Partition and uses the rest of
the disk for an ext4 root filesystem. It installs only signed packages carried
on the read-only seed, installs systemd-boot, enables the serial console, locks
root, and disables SSH password authentication. The seed contains no private
inventory, address plan, household identity, credential or secret; the
installation adds only the password hash entered directly at its console.
When installation completes, follow its instruction to remove both ISOs and
reboot.

Detach the installation and seed media by exiting QEMU, then boot only the
virtual disk:

```sh
make homelab-bootstrap-vm-boot APPLY=1
```

The acceptance gate is a successful local `local-rescue` login followed by:

```sh
id
sudo -v
findmnt /
bootctl status
systemctl --failed
```

Record only pass/fail results. Do not record the password. Keep the VM
loopback-isolated until permanent key-based administration replaces the
temporary password and the separate network-attachment gate is approved.
