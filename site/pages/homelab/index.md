# Homelab

A Git-controlled, reproducible network-provisioning system: network boot a
machine, supply and validate its parameters, explicitly authorize the wipe, and
install a reusable profile. Then converge it continuously instead of
reinstalling it.

This is a **generic profile**, not a description of one house. Real hostnames,
addresses, interface MACs and per-machine inventory live in a private overlay
that never reaches this site — and the site build fails closed if any of it
leaks into a published source.

## Documents

| Document | What it is | |
|---|---|---|
| **Controller Design** | What the Controller owns, what it deliberately does not, storage and network boundaries, the install-once/converge-continuously split | [PDF](../../doc/homelab/design/controller.pdf) |
| **Controller Rebuild** | Bare metal to serving DHCP, written on the assumption that the Controller is dead and nothing it hosted is available | [PDF](../../doc/homelab/manual/controller-rebuild.pdf) |
| **Provisioning Design** | Network boot, the authorization boundary, what cannot be offered, and how the whole thing is tested | [PDF](../../doc/homelab/design/provisioning.pdf) |
| **Convergence Design** | Where install ends and day two begins, why the manifest is the authority, and getting back in when the directory is down | [PDF](../../doc/homelab/design/convergence.pdf) |
| **Decision Record** | All 63 architecture decisions — accepted, superseded and deferred — generated from the Markdown sources so the printed copy cannot drift | [PDF](../../doc/homelab/decisions.pdf) |

## Shape of it

- **Controller** — one Arch host owning boot, storage, the managed interface, bundled DHCPv4 and `home.arpa` DNS, PXE and the artifact service. No routing, no NAT, no default route advertised.
- **Workstation** — pivots on its Controller's fully qualified name.
- **Services** — optional and off by default. Homebridge, openHAB and similar as Podman quadlets with host networking, because HomeKit and UPnP discovery need mDNS. Can run on the Controller today and move to its own machine later by changing which host claims the role.
- **Identity** — Samba AD DC in a VM, so Windows and Linux share accounts and laptops keep cached logons away from home.

## Two things that make it different from the usual

**Install is small; converge is continuous.** Installation does only what cannot
be done later — partition, encrypt, boot artifacts, one interface, one account.
Everything else is Ansible from the repository. A change is a commit and a
converge run, not a reinstall.

**Nothing reaches metal untested.** A QEMU/OVMF matrix builds a virtual isolated
network, installs a virtual Controller from the real installer, and asserts that
leases land in the pool, `home.arpa` resolves, no default route is advertised,
checksums verify and a second converge run reports no changes. A stage that
cannot run yet reports what it is waiting for; it is never skipped quietly,
because a harness that silently shrinks reports green while testing nothing.

## What runs today

The installer exists and is driven end to end by an acceptance harness that
answers its genuine prompts through a pseudo-terminal — there is no unattended
code path for the harness to use, so there is nothing to abuse on real hardware.

    make check            site checks plus 297 tests
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

The installer is driven end to end against six hardware shapes — NVMe, SATA and
eMMC partition naming, several eligible disks, absent serials, removable media,
wireless-only — because the machines this runs on will not be the machine it was
written on. Matrix stage 1 passes: a lab guest boots UEFI on its serial console,
finds no boot disk, and attempts PXE over IPv4 on a segment with no route off
it. The remaining stages wait on a built Archiso image.

The provisioning image is staged by a tool that assembles the tracked profile,
the installer, and the administrator public key from the private overlay, then
audits the result and prints the one privileged command that builds it. The
audit refuses a private key, an empty key file, and any declared path the tree
does not contain — and sshd is enabled only when there is a key for it to
accept, because a listening sshd with no authorized key is attack surface
nothing can log in through.

Not yet run: the build itself, which needs root; and a real installation, which
needs a spare machine.

## Status

Milestone A — the functional proof — is the active target. Encryption at rest is
real throughout; Secure Boot and TPM unlock are deliberately deferred until the
provisioning path is proven, and the known defects in that deferred design are
written down rather than left to be rediscovered.
