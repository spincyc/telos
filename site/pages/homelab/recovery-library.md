# Recovery library

Version `20261001.002`

This is the symptom-led first stop when something in the homelab has failed and
you need to know what it is, what you can safely do about it, and whether the
fix exists yet. It is a **human guide**: it names the recovery path and links to
the exact commands; it is not itself the command-by-command runbook.

Every command shown here is a real `make` target in this repository. Nothing on
this page invents a command, and nothing here touches your private inventory —
site-specific names, addresses, and disk serials live only in the private
overlay.

> **Stop boundary**
>
> An owner carrying a laptop may restart, choose either operating system,
> reconnect Wi-Fi, and collect the evidence described in the
> [Workstation Owner Guide](../workstation-owner-guide/index.md). Everything below
> that reconstructs a Controller, rolls back a network-boot release, or
> re-installs a machine is **administrator work** performed at home on the
> isolated fabric. Stop before erasing a disk, changing firmware, or attaching
> anything to the house network unless that action is separately authorized.

## How to read the support status

Each scenario carries one of three status marks. Read the mark before you act:

- **Implemented today** — the recovery path exists, has an automated check or
  test, and can be run now against the isolated lab or a running laptop.
- **Deferred live proof** — prerequisites may already work, but this specific
  failure-and-recovery scenario has not been exercised successfully.
- **Partial** — part of the path is proven and part still depends on a gate
  that is not finished.

The authoritative, moving picture of which gate is accepted lives in the
factory state ledger and the [operator runbook](../operator-runbook/index.md).
Gate 11 closes phase one at `partial`, never PASS: controller restart,
failed-install recovery and broken-boot repair remain deferred by ADR 0080.

## 1. Controller restart or loss

**What it is.** The home Controller — the one Arch host that serves the
directory, DNS, and network-boot artifacts — is powered off, isolated for
maintenance, or gone.

**How you'd recover.** A laptop away from home does not need the Controller for
ordinary use: cached login, local files, public Internet, and operating-system
updates all keep working. So the first recovery is *no action* — confirm the
laptop is fine and wait. At home, a Controller that was only restarted converges
back to its known state because convergence is idempotent; nothing it hosts has
to be rebuilt. Directory changes, optional home storage, and new PXE work simply
wait until it is back.

**Current support status.** Partial. Cached login is proven in the identity
gates and the owner-facing ladder is in the
[Workstation Owner Guide](../workstation-owner-guide/index.md). That does not
prove the separate gate-11 controller-restart fault scenario, which remains
deferred. A dead directory needs its native backup, not just a fresh OS.

## 2. PXE release rollback

**What it is.** A newly published network-boot release (controller, Arch, or
Windows target) is bad, and machines that boot from it must return to a known
good version. Releases are immutable and versioned `YYYYMMDD.NNN`, so rollback
is a selection, never an edit.

**How you'd recover.** Select the previous release set on the Controller, or
republish a single prior target to its serving root:

```sh
make homelab-pxe-release-set-rollback VERSION=<prior YYYYMMDD.NNN>
make homelab-pxe-rollback TARGET=<controller|arch-workstation|windows> \
  VERSION=<prior YYYYMMDD.NNN> DESTINATION=<host:/absolute/root>
```

Prove the result before trusting it:

```sh
make homelab-pxe-release-set-verify RELEASE_SET=<versioned release-set directory>
make homelab-pxe-verify RELEASE=<versioned release directory>
```

**Current support status.** Implemented today. The transactional release-set
selection, rollback, and verification are built and tested; rejected-input and
rollback tests pass.

## 3. Failed install

**What it is.** A workstation install (Windows first, then Arch) did not
complete — it stopped, produced no bootable system, or failed an acceptance
check.

**How you'd recover.** Preserve the failed run's result and confirm teardown
before preparing another disposable install. The local factory's generated
Windows automation is restricted to the identified disposable QEMU disk and
does not authorize a physical erase. Physical installation remains interactive
and separately authorized against the measured disk serial. The local runners
can be prepared with:

```sh
make homelab-windows-install-prepare
make homelab-arch-install-prepare
```

**Current support status.** Deferred live proof. Both installation gates have
passed in the isolated lab; deliberate install fault injection and recovery
remain a separate deferred scenario. Do not erase a kept disk to repair a
failed disposable attempt.

## 4. Broken boot

**What it is.** The machine powers on but neither operating system starts, or the
five-second Windows-default boot menu is gone.

**How you'd recover.** The design keeps **independent UEFI boot entries** for
Windows and Arch precisely so a broken menu does not strip you of a way in: you
select the other system's firmware entry directly and repair from there. The
Arch installation is required to preserve the Windows Boot Manager and reapply
the boot policy, so a boot repair restores the menu rather than reinstalling an
OS. Recovery of the boot artifacts otherwise falls back to a PXE re-stage of the
affected system (scenario 3).

**Current support status.** Deferred live proof. Dual-boot acceptance has
passed; deliberately breaking and repairing the bootloader has not. Trying an
independent firmware entry is a way to recover access, not evidence of a
completed repair. Escalate before changing boot files or partitions.

## 5. Directory or DNS loss

**What it is.** Samba Active Directory or its DNS zone is unavailable, so new
domain logins, joins, and name resolution for domain services fail.

**How you'd recover.** Already-joined laptops keep working offline on cached
credentials, so this is rarely an emergency for the person carrying one. At
home, first restore the existing Controller's DNS, time and Samba service.
If its directory data is lost, use the operator runbook's native Samba backup
and restore procedure. A new OS and a newly provisioned domain do not recreate
the old account SIDs. Do not blindly rejoin clients or reset cached credentials.

**Current support status.** Partial. Native directory backup, restoration under
a new DC name, reconvergence and a directory probe have passed in an isolated
drill (2026-10-01). Existing-client authentication after replacing its original
DC needs its own keep-verify evidence; consult the runbook's current verdict.
That proof must preserve the domain identity and use a client prepared for
SRV-first discovery. Directory backups do not restore workstation files.

## 6. Update failure

**What it is.** An automatic operating-system update failed, was skipped, or
left the machine in a questionable state.

**How you'd recover.** Windows updates are automatic; the owner restarts when
Windows asks and reports repeated failures. Arch uses a gated, health-checked
policy rather than a blind unattended upgrade — it runs one complete
`pacman -Syu` transaction only when its preconditions hold (AC power, sufficient
free space, no competing transaction, the official mirror reachable), records
before/after package lists, and does not interrupt a session to reboot. Check
whether an update is actually required and whether the gate would allow one:

```sh
make homelab-arch-update-check
```

A failing gate is the safe outcome: it declines to upgrade rather than leaving a
half-applied system. Never run a partial `pacman -Sy`, delete the pacman lock,
or force package replacement.

**Current support status.** Partial. The Arch update policy, gate and package
evidence are built and tested (`make homelab-arch-update-test`); those tests do
not prove recovery from an unbootable update. Retain the update journal and
package lists, try the other OS, and escalate before package or boot repair.

## 7. Workstation remint

**What it is.** A laptop is being reset to a clean, known state — because it was
returned, repurposed, or has drifted too far to trust — and must be rebuilt from
the same reproducible inputs.

**How you'd recover.** Reminting is running the factory again from clean inputs:
destroy the disposable state, re-install Windows and Arch, and rejoin identity.
Because installation does only what cannot be done later and everything else is
convergence from the repository, the verifier can compare stable invariants
from the same sealed inputs. Disks are not promised byte-for-byte identical.
The aggregate driver runs two lifecycles; the verifier grades retained evidence:

```sh
make homelab-factory-verify
make homelab-factory-repeat
```

Both commands above are read-only plans unless their documented live options
are supplied. **Current support status:** the driver and comparator exist;
read gate 12 in the operator runbook for the latest twice-through verdict and
its explicit egress waiver. One completed workstation is not repeatability
evidence. Preserve needed user files before reminting a kept machine.

## 8. Controller reconstruction

**What it is.** The Controller is assumed dead and nothing it hosted is
available. It must be rebuilt from public inputs plus a synthetic private
overlay, with no dependence on the lost machine.

**How you'd recover.** Rebuild the seed, install and converge a fresh
Controller, and re-stage its network-boot artifacts — the same reproducible
path used to create the first one:

```sh
make homelab-bootstrap-seed
make homelab-factory-controller-bundle
make homelab-bootstrap-controller
make homelab-factory-pxe
```

These are building blocks, not a complete copy-paste recovery sequence. Follow
the current operator runbook for its required inputs and console installation.
For a persistent directory, also restore its native backup as in scenario 5.
The older printable Controller Rebuild manual describes a broader design.

**Current support status.** Implemented today (in the isolated lab). A fresh
no-network Controller has been built, installed, and converged with the
directory, DNS, signed time, TFTP, and HTTP all passing on loopback-only links;
serving a real physical workstation boot is a separate, still-pending gate.

## 9. Forgotten password, lost laptop or damaged disk

If a previously used account still signs in offline, preserve that access and
record whether connected login fails. An administrator can use the runbook's
one-account password-reset target after verifying the directory is healthy;
resetting the directory password does not immediately change a disconnected
laptop's cached credential. A lost local-rescue password has a different
recovery path from a lost domain password.

For a missing or suspect disk, stop install attempts and preserve the data that
is still readable. For a lost laptop or suspected compromise, report it through
the private help channel and have the administrator revoke connected access
and rotate exposed credentials. Neither action erases an unencrypted disk or
revokes disconnected cached login. The runbook documents local VM retirement;
physical disk sanitization, remote wipe and fleet incident automation are not
implemented.

## When to ask for help

Ask soon if a rollback or update gate keeps failing, if the isolated
Controller will not converge after a rebuild, or if a repaired boot menu does
not reappear. Ask immediately if both operating systems fail, a disk disappears,
a recovery key is unexpectedly requested, or a laptop is lost. Firmware, disk
layout, directory membership, network policy, and any physical-network or UniFi
change are administrator work and must never be improvised on the house network.

Collect evidence the same secret-free way described in the
[Workstation Owner Guide](../workstation-owner-guide/index.md): remove passwords,
keys, tokens, serial numbers, full addresses, and unrelated names before sending
anything, and use the family's agreed private channel.
