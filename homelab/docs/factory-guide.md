# Workstation factory — human guide

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
   boot, and an HTTP package service);
3. network-boots a throwaway **workstation** through that controller;
4. installs **Windows 11 Pro first, then Arch Linux second** on one UEFI/GPT
   disk, preserving Windows and its recovery data;
5. joins both operating systems to the same synthetic test domain;
6. proves login, reboot, offline login, update policy, and recovery; and
7. keeps machine-readable evidence for every gate.

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
  deliberately deferred. Full-disk encryption is a later iteration. Do not
  describe these images as safe for sensitive or mobile use until that decision
  is revisited.
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
damaged image is to re-run the factory from the sealed media. Recovery scenarios
(release rollback, remint, controller reconstruction, update-failure rollback)
have a dedicated target and are graded fail-closed; the runbook shows which are
proven live today and which still defer their proof to a future live guest.
