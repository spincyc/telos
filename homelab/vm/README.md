# Bootstrap VM network boundary

The initial `bootstrap-dc` environment uses only QEMU socket networking bound
to host loopback. It can exchange Ethernet frames with test guests, but it
cannot reach the household LAN or internet.

This phase does not create a bridge, tap, route, VLAN, DHCP listener, firewall
rule, or UniFi setting. Physical attachment is deliberately deferred.

Code must obtain NIC arguments from `vm.network.socket_network_args()`. A later
network design may add an existing-LAN, dedicated-interface, or VLAN-trunk
profile, but none is accepted by the bootstrap implementation.

## Lifecycle boundary

`make homelab-bootstrap-vm-create APPLY=1` creates private state
transactionally. The state directory is mode 0700, its files are mode 0600,
and `manifest.json` records the VM shape, firmware provenance, creation time,
and blocked physical-network gate. Existing state, symlinked state paths, and
partial state are refused.

Boot installation media with
`make homelab-bootstrap-vm-run ISO=/path/to/arch.iso APPLY=1`. Omitting
`APPLY=1` prints the complete QEMU command without starting the guest.
When `ISO` is present, firmware always tries that read-only medium before the
virtual disk. Without `ISO`, only the installed disk is bootable. The disk has
the stable serial `TELOS-BOOTSTRAP-DC-001`, so installer authorization does not
depend on a changing `/dev` name.

An optional offline seed may be attached as a second read-only CD:
`make homelab-bootstrap-vm-run SEED_ISO=homelab/var/seed/telos-controller-seed.iso
APPLY=1`. The explicit boot order remains installer ISO, virtual disk, then
seed. The seed therefore supplies packages and source without silently
replacing the official Arch installer as the boot authority.

## Interactive offline installation

At the Arch live-system root prompt, locate and mount the seed by its filesystem
label, then run its installer:

```sh
mkdir -p /run/telos-seed
mount -L TELOS_SEED /run/telos-seed
sudo /run/telos-seed/install-controller /run/telos-seed
```

The installer accepts exactly one writable disk whose reported serial is
`TELOS-BOOTSTRAP-DC-001`. Before erasing it, the console requires the complete
phrase:

```text
ERASE TELOS-BOOTSTRAP-DC-001
```

This is not a general-purpose hardware installer: a missing, duplicate or
differently serialized disk is refused. The resulting phase-one GPT layout is
a 1 GiB FAT32 EFI System Partition followed by an ext4 root partition using the
rest of the disk. It installs signed packages only from the read-only seed,
creates the fixed host name `bootstrap-dc`, installs systemd-boot, and enables
the serial console.

Near the end, `passwd` prompts twice for a temporary console password for
`local-rescue`. Type it directly at the guest console. Do not place it in a
command, Make variable, answer file, transcript or repository. Root is locked,
SSH root login is disabled, and SSH password and keyboard-interactive
authentication are disabled; the temporary password is for local console
testing and `sudo` only.

No private inventory, address plan, household identity, credential or secret is
read from or written to the public seed. The install does not contact a mirror
or enable physical networking. Keep the VM on its loopback-only boundary, and
remove both read-only discs before booting the installed disk.

The terminal is both the guest serial console and QEMU monitor. Use `Ctrl-a c`
to switch between them and `Ctrl-a h` for help. The Telos controller installer
opens on that serial console. A stock Arch ISO may keep its firmware and boot
menu on a graphical console; it is suitable as source media, but the Telos
controller image is the unattended, terminal-friendly installation path.

The VM is temporary infrastructure, but its directory data becomes durable
once it provisions the real domain. Destruction therefore requires
`APPLY=1 CONFIRM=bootstrap-dc` and refuses unexpected or symlinked files.
Ansible convergence from the host cannot begin while the socket-only boundary
is in force; it waits for the separately approved physical-network gate.
