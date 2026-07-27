# Workstation Factory

This is the human-readable path from an Arch build workstation to a verified
dual-boot client. It is intentionally terse. Every state-changing action has a
check and a stop condition.

[Printable manual](../../../doc/homelab/manual/workstation-factory.pdf) ·
[Network design](../../../doc/homelab/design/network.pdf)

> **Pilot boundary**
>
> Pilot workstations have no BitLocker, LUKS, custom Secure Boot trust, TPM
> enrollment, roaming profile, or offline revocation. Do not place sensitive
> data on them. None of those omissions may be silently carried into a
> production profile.

## 1. Keep public, private, and secret data separate

Clone public Telos, then create a sibling private project:

```sh
make homelab-private-onboard
```

**What this does:** creates a separate Git repository for site, identity,
and initial network inventory. It explains and asks one question at a time,
refuses to overwrite an existing path, and never creates a remote. Add machine,
person, and share inventory only after reviewing the generated contract.
The network cycle distinguishes the site allocation root from the bounded
managed-client subnet, then asks for explicit DHCP endpoints. It verifies that
the child subnet and pool are contained, compact, usable, and do not include
the gateway.

**Verify:** read its redacted review. Confirm the public Telos worktree contains
no real usernames, hostnames, addresses, MAC addresses, serials, or share
names.

**Stop if:** a password, Wi-Fi key, recovery key, private key, token, or
domain-join credential appears in either repository. Secrets belong in an
encrypted store referenced by name.

To adopt later public improvements, pull them into the public clone and rerun
its checks. Never merge the private repository into Telos:

```sh
git pull --ff-only
make check
../telos/scripts/telos-private preflight --root ../telos-private
```

## 2. Install the Arch build dependencies

```sh
make homelab-bootstrap-deps
```

**What this does:** performs one supported Arch full-system transaction and
installs the declared document, QEMU, Archiso, Samba, Ansible, and PXE build
tools.

**Verify:** run it a second time. Pacman should report no undeclared provider
choice and no partial-upgrade path.

**Stop if:** pacman proposes removing an unrelated package or a dependency is
being installed manually to work around the target. Correct the manifest.

## 3. Prove the temporary Controller in isolation

```sh
make homelab-bootstrap-vm-plan
make homelab-bootstrap-vm-create APPLY=1
make homelab-bootstrap-vm-status
make homelab-bootstrap-vm-run APPLY=1
```

**What this does:** creates the temporary Controller with four virtual CPUs,
8 GiB RAM, and an 80 GiB disk.

**Verify:** the printed QEMU network uses loopback-only socket transport.
There must be no bridge, TAP device, NAT, VLAN, host-interface change, or UniFi
change.

**Stop if:** the VM can reach the household LAN. Isolation is an acceptance
condition, not a convenience.

## 4. Establish the permanent identity namespace

The private inventory supplies:

- directory DNS domain and Kerberos realm;
- NetBIOS name;
- bootstrap host name;
- daily, privileged, standard-test, and local break-glass account names; and
- a reference to the one-time encrypted bootstrap credential.

Preview convergence:

```sh
make homelab-bootstrap-controller INVENTORY=/absolute/private/inventory
```

Apply only after reviewing the diff:

```sh
make homelab-bootstrap-controller \
  INVENTORY=/absolute/private/inventory APPLY=1
```

**What this does:** provisions one host-level Samba AD controller with its
integrated DNS. It does not make the Controller a DHCP server.

**Verify:** the directory database exists; `samba-tool dbcheck` passes; LDAP
and Kerberos SRV records resolve; a real test identity can obtain and destroy a
Kerberos ticket; a second convergence reports no changes.

**Stop if:** the host name, realm, NetBIOS name, time, address, or existing
Samba configuration differs from the frozen private inventory.

## 5. Build immutable PXE targets

Every release uses `YYYYMMDD.NNN` and refuses overwrite.

```sh
make homelab-pxe-controller \
  SOURCE=/path/to/controller-tree \
  VERSION=YYYYMMDD.NNN BASE_URL=http://boot.example/controller

make homelab-pxe-arch \
  SOURCE=/path/to/mounted-arch-iso \
  VERSION=YYYYMMDD.NNN BASE_URL=http://boot.example/arch

make homelab-pxe-windows \
  ISO=/path/to/windows-11.iso WIMBOOT=/path/to/wimboot \
  VERSION=YYYYMMDD.NNN BASE_URL=http://boot.example/windows

make homelab-pxe-test
```

**What this does:** stages controller, Arch, and Windows WinPE payloads into
versioned directories and writes SHA-256 manifests last.

**Verify:** change one staged byte in a disposable copy; verification must
fail. Confirm the Windows release contains no answer file or credential.

**Stop if:** an artifact is unlisted, a symlink escapes its source, the
Windows image does not advertise Windows 11 Pro, or a release directory already
exists.

> **Current Windows limit**
>
> The Windows target reaches WinPE. It does not yet erase a disk or perform an
> unattended installation. That remains blocked until the disk-serial
> authorization and reviewed setup script are complete.

## 6. Design UniFi before touching UniFi

The physical-network decision is deferred while the isolated proof runs.
Before a real PXE boot, choose and record either the existing LAN, a dedicated
interface, or a provisioning VLAN.

Use the [Network design runbook](../../../doc/homelab/design/network.pdf) for
the executable console sequence. UniFi labels vary by Network release: current
zone-based versions commonly place networks under **Settings → Networks** and
rules under **Settings → Security → Policy Engine**; older releases may call
them **Firewall & Security** and **LAN In**. Match the source zone, destination
zone, service and observed rule counter—not merely the menu name.

Before attaching a port or SSID, create endpoint and service groups, add the
narrow required allows, and add a logged final inter-zone deny. Then attach one
sacrificial access port. Record the client VLAN, lease server, address/prefix,
gateway, DNS, time offset, AD SRV answers, Kerberos ticket, required service
transactions, forbidden probes and matching deny counters. Only then attach a
production port or managed SSID.

Required invariants:

1. UniFi is the only address-assigning DHCP server.
2. DHCP option 66 names the active boot service.
3. DHCP option 67 names the UEFI x86-64 first-stage loader.
4. Domain clients receive the Samba AD DNS address.
5. DHCP Guarding trusts only the UniFi gateway.
6. The boot alias can move from the temporary VM to the permanent Controller.

**Verify:** capture one complete DHCP exchange. There must be exactly one
offer. Resolve the directory SRV records from the candidate client network
before joining any machine.

The minimum flow contract is DHCP UDP 67–68 to the UDM; DNS TCP/UDP 53 to AD
DNS; NTP UDP 123; Kerberos TCP/UDP 88 and 464; LDAP TCP/UDP 389; SMB TCP 445;
RPC endpoint TCP 135 plus the measured/configured dynamic RPC range; boot TFTP
UDP 69 only when used; and boot/update HTTP(S) TCP 80/443. Scope every rule to
named endpoint groups. A domain join is the proof for AD RPC—not a successful
ping.

> **PXE architecture caveat**
>
> UniFi remains the DHCP authority. Option 66 identifies the boot service and
> option 67 the approved x86-64 UEFI loader. DHCP Guarding trusts the UDM, so a
> separate ProxyDHCP service is intentionally excluded. Keep boot options on a
> dedicated provisioning network; an iPXE first stage must chain to HTTP(S)
> without looping back into itself.

Phase one validates IPv4 only. For each new network, explicitly disable IPv6
prefix delegation/router advertisements where supported and deny routed IPv6
between trust zones until an equivalent IPv6 contract has positive and negative
proofs. Link-local IPv6 may still appear. Never assume an IPv4 deny also
enforces IPv6.

For managed Wi-Fi, confirm the exact AP and Network release support PPSK in the
chosen mode. PPSK may require WPA2 and exclude WPA3/6 GHz. If unavailable, use
a dedicated restricted WPA2 SSID as a temporary shared-credential fallback,
rotate it after loss, and retain AD as user identity; 802.1X/RADIUS is the later
upgrade path.

**Stop if:** ordinary DNS works but the AD SRV records do not, or any second
DHCP offer appears.

## 7. Freeze the target machine

Record in the private inventory:

- bespoke host name;
- make and exact model;
- permanent wired-adapter MAC;
- whole-disk serial and exact byte size;
- UEFI mode;
- firmware Windows 11 Pro entitlement; and
- approved workstation profile.

Compute the layout without touching the disk:

```sh
make homelab-workstation-plan \
  DISK_BYTES=EXACT_INTEGER_FROM_THE_TARGET
```

The default profile provides a 1 GiB EFI partition, 16 MiB Microsoft reserved
partition, Windows recovery allowance, and a 75/25 Windows/Arch split. Windows
must receive at least 160 GiB and Arch at least 64 GiB.

**Verify:** compare the printed serial, byte count, and partition table with the
machine in front of you.

**Stop if:** any identity changes between planning and authorization. Re-run
discovery; never translate “the first disk” into permission to erase it.

## 8. Install and verify both operating systems

Install Windows first into only its declared allocation. Install Arch second
into only its declared allocation. Preserve independent native UEFI entries.
The menu waits five seconds and starts Windows by default.

Phase-one settings:

- Windows 11 Pro only;
- US language, keyboard, and regional defaults;
- site time zone from private inventory;
- Secure Boot disabled;
- no disk encryption; and
- local profiles.

**Verify after two cold boots:** Windows starts automatically; the firmware can
start Windows directly; the menu can start Arch; Windows partition boundaries
are unchanged after Arch installation.

**Stop if:** either operating system depends exclusively on the other
operating system’s root filesystem or boot files.

## 9. Join identity without losing recovery

Create and test the non-domain local break-glass administrator before joining
the domain. Then join Windows and Arch.

Verify all four roles:

| Role | Windows | Arch |
|---|---|---|
| Daily administrator | Local workstation administration | Approved `sudo` |
| Domain administrator | Reserved for directory work | Reserved for directory work |
| Standard test user | Login succeeds; not administrator | Login succeeds; no `sudo` |
| Local rescue | Works with AD unavailable | Works with AD unavailable |

Disconnect the laptop and repeat cached login on both operating systems.
Cached login is intentionally indefinite for mobile users.

[Follow the command-by-command Windows and Arch identity procedure →](workstation-identity-procedures/index.md)

> **Revocation limit**
>
> Disabling an account stops connected authentication and network access. It
> cannot revoke an indefinitely cached login while the laptop remains
> disconnected.

## 10. Add restricted Wi-Fi and optional storage

Store only a credential for the restricted managed-workstation network. Prefer
a distinct PPSK per workstation. Permit only directory, DNS, time, boot,
authenticated storage, and required update traffic. Deny management, peer, IoT,
and unrelated household zones.

Use SMB for optional user storage. Keep the real home/profile local; mount the
share beneath it on Arch and as a mapped drive on Windows.

Verify three storage states:

1. storage available and authorized;
2. storage unreachable; and
3. storage reachable but access denied.

Login must succeed in every state. Storage failure produces a bounded warning,
not a failed session.

## 11. Accept, publish, or roll back

```sh
make homelab-workstation-verify \
  INSTANCE=/absolute/private/acceptance-instance.json
make check
```

Retain the release version, manifests, disk plan, firmware state, domain tests,
network capture, and storage failure tests.

Publishing uploads into a new version directory, compares the remote bytes by
checksum, and only then changes the `current` pointer. A partial upload never
becomes bootable. Keep the previous verified version for rollback.

```sh
make homelab-pxe-publish \
  RELEASE=/path/to/versioned/release \
  DESTINATION=deployer@controller:/srv/http/boot

make homelab-pxe-rollback \
  TARGET=arch-workstation VERSION=YYYYMMDD.NNN \
  DESTINATION=deployer@controller:/srv/http/boot
```

Both commands are dry runs unless `APPLY=1` is supplied.

## 12. Move to permanent hardware later

Join the permanent Controller as an additional domain controller. Prove
directory and DNS replication, move the stable boot alias, update UniFi boot
settings, and repeat Windows and Arch authentication tests. Demote the
temporary Controller only after all tests pass.

Workstations remain joined to the permanent identity namespace and do not need
rebuilding.
