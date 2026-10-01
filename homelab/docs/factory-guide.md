# Workstation factory — human guide

Version `20261001.002`

A terse orientation for an owner or family member. It says what the factory is,
what it makes, how it is used, where the hard safety line sits, and when to stop
and ask. It contains no secrets and no real machine values. The exact commands
live in the [operator runbook](operator-runbook.md); the authoritative,
minute-by-minute state lives in the
[factory state ledger](../WORKSTATION-FACTORY-STATE.md).

## What the factory is

The factory is a fully local, reproducible pipeline that turns a fresh public
Telos checkout plus verified installation media into a dual-boot laptop with one
shared login. Everything runs on one build host in throwaway virtual machines on
loopback-only links. Nothing it does touches your real network, your Wi-Fi
controller, or any physical laptop.

In order, one run:

1. starts from a clean public checkout and locally verified Arch and Windows
   media;
2. builds a disposable **controller** (Samba Active Directory, DNS, PXE network
   boot, and an HTTP package service) — that is the acceptance mode; a second,
   opt-in **persistent** controller mode exists for a directory you can log back
   into, described under "The persistent directory instance" in the
   [operator runbook](operator-runbook.md). Its directory setup, account
   creation and a kept workstation joined to it have all run live on
   throwaway instances (2026-09-25, 2026-09-30);
3. network-boots a throwaway **workstation** through that controller;
4. installs **Windows 11 Pro first, then Arch Linux second** on one UEFI/GPT
   disk, preserving Windows and its recovery data;
5. joins both operating systems to the same synthetic test domain;
6. proves login, reboot, offline login, update policy, and recovery; and
7. keeps machine-readable evidence for every gate.

Choose the disposable mode to test the factory: its directory and test accounts
end with the run. Choose the durable workflow when a virtual workstation must
keep its identity and remain usable after a relaunch. That workflow binds each
kept workstation to a named persistent directory, with separate backups and
explicit retirement. Rehearsals can use generated credentials on throwaway
instances; the owner's keeper uses passwords held by the owner. Neither mode
attaches a physical laptop or changes the household network.

## What a minted workstation is

A minted workstation is a single physical disk carrying Windows 11 Pro and Arch
Linux side by side. Windows is the default and shows a five-second boot menu;
either system can be chosen at power-on. Both log in with the **same** domain
account, and both keep working away from home because the login is cached
locally. Your files live locally; optional network storage may attach when it is
reachable but never blocks a login.

Today the factory proves this in virtual machines only. No real laptop has been
built. The pilot hardware (a ThinkPad X13 Gen 6 Intel) is a later, separately
authorized step.

## Ordinary use

- **To build or rebuild a workstation image:** follow the
  [operator runbook](operator-runbook.md) top to bottom. It is a plain ordered
  list of `make` commands, each paired with the evidence that proves it worked.
- **To check what currently works:** read the gate table in the
  [factory state ledger](../WORKSTATION-FACTORY-STATE.md). A gate marked PASS is
  proven; anything else is not, and the ledger says exactly why.
- **To recover from a broken run:** the runbook's recovery section drives the
  `homelab-factory-recover` target. Individual symptoms also have a published
  [recovery library](../../site/pages/homelab/recovery-library.md).
- **Day-to-day upkeep of a real laptop later:** see the published
  [maintenance library](../../site/pages/homelab/maintenance-library.md) and
  [owner guide](../../site/pages/homelab/workstation-owner-guide.md).

## The safety boundary — do not cross it without explicit authorization

Until the whole isolated lifecycle is proven and a human explicitly authorizes
the next phase, the boundary is absolute:

- **Do not** change UniFi or any real network device.
- **Do not** attach the controller to the physical network.
- **Do not** create a host bridge, TAP, route, VLAN, forwarding rule, or a
  physical DHCP or DNS listener.
- **Do not** erase or boot a physical laptop.
- Everything binds to host loopback only, and the **simulated gateway is the
  only thing allowed to hand out DHCP**. The controller must never become a
  second DHCP authority.

Physical attachment and hardware installation are separate gates that stay
closed by design. A green local run does **not** unlock them. If a task seems to
require any of the above, that is the signal to stop and ask.

## When to ask for help

Stop and escalate to the coordinator or owner when:

- a step needs `sudo`, a real disk, real network access, or UniFi;
- a run wants to erase or boot physical hardware;
- evidence disagrees with the ledger, or a gate you expected to pass does not;
- a run asks for a real hostname, address, credential, or the private overlay;
  those live only in the separate private repository and never in this public
  tree; or
- you are about to represent a pending step as working. Do not. The ledger and
  runbook are careful to separate *proven* from *pending*, and so must you.

## Security limits you must not misrepresent

Phase one is a working pilot, not a hardened product. Two limits are explicit
and owner-accepted:

- **No encryption yet.** Phase-one images use unencrypted Windows NTFS and
  unencrypted Arch storage. BitLocker, LUKS, Secure Boot, and TPM enrollment are
  deliberately deferred. The owner accepted that limit for the phase-one
  mobile pilot; it does not supply protection if someone obtains the disk.
  Full-disk encryption remains a later iteration.
- **Cached-login revocation is limited.** So a laptop keeps working away from
  home indefinitely, domain logons are cached locally and do not expire (Arch
  SSSD `offline_credentials_expiration = 0`; Windows non-expiring cached domain
  logons). The consequence is that disabling an account at the directory does
  **not** immediately lock out a laptop that is already away and offline.
  Immediate remote revocation is a later phase; today the limitation is
  documented, not solved. See ADR
  [0071](../decisions/0071-mobile-logon-and-revocation-limits.md).

## Maintenance and recovery, in one breath

Rebuild rather than repair: because installation does only what cannot be done
later and everything else is converged from the repository, the normal fix for a
damaged disposable image is to re-run the factory from the sealed media. A kept
directory is different: rebuilding its operating system alone does not restore
its accounts and domain identity. Use the native directory backup/restore
procedure in the runbook and prove clients still authenticate before returning
it to use. A directory restore is not a backup of anyone's files or workstation
disk.

The recovery runner distinguishes host-side checks, live guest checks and
deferred scenarios. The runbook records those limits; a successful check is
never evidence that an unrun repair works. Before retiring a kept VM, preserve
needed files and read the runbook's retirement sequence. For a lost laptop,
report the loss immediately: disabling connected access cannot erase a disk or
revoke a cached login on a disconnected machine.
