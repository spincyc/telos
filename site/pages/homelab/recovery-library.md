# Recovery library

Version `20260810.001`

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
- **Modeled, pending live guests** — the logic, planning, and tests exist, but
  the end-to-end live install/identity lifecycle (factory gates 6–10) has not
  yet been accepted, so the procedure is not yet a proven click-by-click path.
- **Partial** — part of the path is proven and part still depends on a gate
  that is not finished.

The authoritative, moving picture of which gate is accepted lives in the
factory state ledger, not on this page; when the mark here and the ledger
disagree, the ledger wins.

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

**Current support status.** Implemented today. The offline-first behavior is
covered by the cached-identity contracts, and the owner-facing check ladder is
in the [Workstation Owner Guide](../workstation-owner-guide/index.md).

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

**How you'd recover.** Re-run the install for the affected system. There is no
unattended path and no flag that skips a prompt: the destructive disk erase is
re-authorized by typing the target disk's serial at the console, so a repeat
install is a deliberate, re-confirmed action, not an automatic retry. The
install runners exist and can be prepared and driven:

```sh
make homelab-windows-install-prepare
make homelab-arch-install-prepare
```

**Current support status.** Modeled, pending live guests. Windows-first install
has a recorded pass in the isolated lab, and the Arch-second runner preserves
Windows partitions and recovery data, but the full live install-and-recover
loop is still being accepted.

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

**Current support status.** Modeled, pending live guests. Dual-boot disk
acceptance and Windows-preserving planning are implemented and tested; the live
boot-repair walkthrough waits on the dual-boot acceptance gate.

## 5. Directory or DNS loss

**What it is.** Samba Active Directory or its DNS zone is unavailable, so new
domain logins, joins, and name resolution for domain services fail.

**How you'd recover.** Already-joined laptops keep working offline on cached
credentials, so this is rarely an emergency for the person carrying one. At
home, the directory is restored by bringing the Controller back and letting it
converge (scenario 1); a Controller that must be rebuilt from scratch is
scenario 8. Rejoining a workstation after directory identity is restored uses
the join procedure in the identity runbook, not a blind rejoin.

**Current support status.** Partial. Samba AD, its DNS zone, signed time, and
Kerberos are proven on the disposable Controller, and cached-offline login is
contracted and tested. A dedicated directory backup-and-restore drill remains a
factory gate that is not yet accepted, so full directory disaster recovery is
still reconstruction-plus-rejoin rather than a point-in-time restore.

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

**Current support status.** Implemented today. The Arch update policy, its gate,
and its rollback record are built and tested (`make homelab-arch-update-test`).

## 7. Workstation remint

**What it is.** A laptop is being reset to a clean, known state — because it was
returned, repurposed, or has drifted too far to trust — and must be rebuilt from
the same reproducible inputs.

**How you'd recover.** Reminting is running the factory again from clean inputs:
destroy the disposable state, re-install Windows and Arch, and rejoin identity.
Because installation does only what cannot be done later and everything else is
convergence from the repository, a reminted machine ends up byte-for-byte
comparable to any other built from the same release. The repeatability
comparator that proves two runs agree is:

```sh
make homelab-factory-verify
```

**Current support status.** Modeled, pending live guests. The verifier and
manifest comparator are implemented, but the live twice-through remint depends
on the install and identity gates being accepted first.

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

This assumes the Controller is dead and rebuilds it bare; the printable
Controller Rebuild manual carries the command-and-evidence detail.

**Current support status.** Implemented today (in the isolated lab). A fresh
no-network Controller has been built, installed, and converged with the
directory, DNS, signed time, TFTP, and HTTP all passing on loopback-only links;
serving a real physical workstation boot is a separate, still-pending gate.

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
