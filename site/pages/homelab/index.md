# Homelab

A Git-controlled workstation factory: prove the services in an isolated VM,
publish immutable network-boot releases, explicitly authorize one disk, and
build a dual-boot Windows and Arch machine with shared identity.

This is a **generic profile**, not a description of one house. Real hostnames,
addresses, interface MACs and per-machine inventory live in a private overlay
that never reaches this site — and the site build fails closed if any of it
leaks into a published source.

## Documents

Start with the **Factory human guide** for the two local modes, then the
**Factory operator runbook** for commands and their evidence. Use the owner,
maintenance and recovery guides for an existing workstation. The network gate
is a later, separately authorized transition. The PDFs below retain older
designs; current phase-one instructions and accepted limits are in the HTML
guides and the repository's factory state ledger.

| Document | What it is | |
|---|---|---|
| **Factory human guide** | What the local factory makes, disposable and kept instances, limits and safe next actions | [HTML](factory-guide/index.md) |
| **Factory operator runbook** | Current local commands, prerequisites, evidence, supported states, maintenance and retirement | [HTML](operator-runbook/index.md) |
| **Controller Design** | What the Controller owns, what it deliberately does not, storage and network boundaries, the install-once/converge-continuously split | [PDF](../../doc/homelab/design/controller.pdf) |
| **Network Design** | Right-sized private networks, UniFi configuration order, traffic policy, PXE and restricted managed Wi-Fi | [PDF](../../doc/homelab/design/network.pdf) |
| **Controller Network Simulation** | Rehearse DHCP/DNS authority, traffic isolation, Controller loss, and rollback in a disposable loopback-only lab without changing UniFi | [HTML](controller-network-simulation/index.md) |
| **Controller Network Gate** | Safely attach the proven bootstrap VM as an ordinary client on a restricted UniFi network, verify isolation, and roll back | [HTML](controller-network-gate/index.md) |
| **Controller Rebuild** | Earlier bare-metal recovery design; current phase one keeps DHCP on the gateway and uses the operator runbook's local rebuild path | [PDF](../../doc/homelab/manual/controller-rebuild.pdf) |
| **Workstation Factory** | Isolated bootstrap through a verified Windows/Arch workstation, with every gate and failure branch | [HTML](workstation-factory/index.md) · [PDF](../../doc/homelab/manual/workstation-factory.pdf) |
| **Workstation Owner Guide** | Normal use, automatic updates, travel checks, recovery, and a secret-free help bundle for the person carrying the laptop | [HTML](workstation-owner-guide/index.md) · [PDF](../../doc/homelab/manual/workstation-owner-guide.pdf) |
| **Recovery Library** | Symptom-led recovery, evidence to collect and the exact limits of each implemented path | [HTML](recovery-library/index.md) |
| **Maintenance Library** | Routine upkeep, gated Arch and Windows updates, and the travel and cached-login limits that keep a laptop usable away from home | [HTML](maintenance-library/index.md) |
| **Provisioning Design** | Network boot, the authorization boundary, what cannot be offered, and how the whole thing is tested | [PDF](../../doc/homelab/design/provisioning.pdf) |
| **Convergence Design** | Where install ends and day two begins, why the manifest is the authority, and getting back in when the directory is down | [PDF](../../doc/homelab/design/convergence.pdf) |
| **Decision Record** | Printable architecture history; the repository's numbered Markdown decisions remain the current source | [PDF](../../doc/homelab/decisions.pdf) |

## Active phase

The active phase is deliberately narrower than the older Controller design:

- UniFi remains the only DHCP authority.
- The temporary Arch VM hosts Samba AD/DNS and PXE services at host level.
- A permanent Controller can later replace it without rebuilding clients.
- Workstations use Windows 11 Pro and Arch on UEFI/GPT.
- Pilot disks are unencrypted and Secure Boot is disabled; this is an explicit
  temporary risk acceptance, not the production security target.
- User files remain local. Optional SMB storage must never block login.

[Open the step-by-step workstation factory →](workstation-factory/index.md)

[Rehearse Controller networking without changing UniFi →](controller-network-simulation/index.md)

[Attach and verify the bootstrap Controller →](controller-network-gate/index.md)

## Stable shape

- **Controller** — one Arch host owning PXE artifacts and the directory. UniFi
  owns DHCP; Samba owns the directory DNS zone.
- **Workstation** — pivots on its Controller's fully qualified name.
- **Services** — optional and off by default. Homebridge, openHAB and similar as Podman quadlets with host networking, because HomeKit and UPnP discovery need mDNS. Can run on the Controller today and move to its own machine later by changing which host claims the role.
- **Identity** — Samba AD lets Windows and Linux share accounts. Laptops retain
  cached logons away from home; disconnected revocation is therefore deferred.

## Two things that make it different from the usual

**Install is small; converge is continuous.** Installation establishes the disk
layout, boot artifacts, one interface and recovery access.
Everything else is Ansible from the repository. A change is a commit and a
converge run, not a reinstall.

**Nothing reaches metal untested.** A QEMU/OVMF matrix builds a virtual isolated
network, installs a virtual Controller from the real installer, and asserts that
leases land in the pool, `home.arpa` resolves, no default route is advertised,
checksums verify and a second converge run reports no changes. A stage that
cannot run yet reports what it is waiting for; it is never skipped quietly,
because a harness that silently shrinks reports green while testing nothing.

## What runs today

The isolated factory has live proofs for Windows-first installation,
Arch-second installation, identity, optional-storage failure and dual boot.
Its Windows automation is generated privately for an explicitly identified
disposable QEMU disk; it is never a public release input or permission to erase
physical hardware. The physical path remains interactive and unproven.

    make check            site, publication, privacy, and implementation checks
    make homelab-test     the suite, verbosely
    make homelab-matrix   the acceptance matrix
    make homelab-image    stage the provisioning image for building
    make homelab-instance seed the private overlay from the tracked template

Built and tested: network-plan validation, dnsmasq and nginx generation, the
prompt registry, hardware collection behind a substitutable seam, preflight
judgement, the step runner with its authorization token, the manifest, the
iPXE script and artifact checksums, the Archiso profile, and the Ansible
convergence layer including the generator bridge that keeps a machine's
installed configuration byte-identical to what the generators produce.

Installer tests cover NVMe, SATA and eMMC partition naming, several eligible
disks, absent serials, removable media and wireless-only machines. Those tests
are distinct from the live factory gates in the
[operator runbook](operator-runbook/index.md). Its gate table records the
recovery deferrals and whether the twice-through comparison is accepted; a
passing unit test or one successful install cannot close those gates.

The provisioning image is staged by a tool that assembles the tracked profile,
the installer, and the administrator public key from the private overlay, then
audits the result and prints the one privileged command that builds it. The
audit refuses a private key, an empty key file, and any declared path the tree
does not contain — and sshd is enabled only when there is a key for it to
accept, because a listening sshd with no authorized key is attack surface
nothing can log in through.

The persistent-directory and kept-workstation sequence has also run in the
isolated lab. Owner custody, disaster recovery with existing clients and any
physical pilot have their own evidence and authorization boundaries; consult
the runbook before treating a disposable rehearsal as a kept system.

## Status

The isolated bootstrap milestone is implemented without changing the host
network or UniFi. Physical attachment, destructive installation, encryption,
Secure Boot, and offline revocation remain explicit later gates.
