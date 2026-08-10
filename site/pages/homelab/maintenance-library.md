# Maintenance library

Version `20260810.001`

This is the "is action required?" guide for keeping the homelab healthy between
failures. It answers what to check, how often, and when a routine check turns
into a reason to ask for help. It is a **human guide**: it names each task and
links to the exact command; the click-by-click operator detail lives in the
runbooks it points to.

Every command shown here is a real `make` target in this repository. Nothing on
this page invents a command, and everything stays generic — site-specific
names, addresses, and disk serials live only in the private overlay and never
appear here.

> **Stop boundary**
>
> Routine maintenance means restarting, applying automatic updates, running the
> read-only checks below, and recording what you saw. Stop before changing
> firmware, partitions, boot entries, directory membership, network policy, or
> anything on the house network. Those are administrator actions covered by the
> recovery and network-gate runbooks, not routine maintenance.

## The routine at a glance

You do not have to do everything at once. The point of the automatic-update
policy is that a laptop left alone stays close to current; these checks confirm
that it did.

| Rhythm | What to confirm | Where |
|---|---|---|
| Each use | Machine boots, either OS starts, login works | daily habit |
| Weekly | Windows updated and restarted; Arch update timer healthy | Windows / Arch below |
| Before travel | Both systems updated, offline login proven, files reachable | Travel and offline use |
| Occasionally | Network-boot media still verifies; no private data leaked | Controller and media |

## Windows automatic updates

Windows Update stays enabled. The owner's whole job is to give it the chance to
run: plug in overnight at least weekly and restart when Windows asks. A restart
that Windows requested is part of the update, not an interruption to postpone
indefinitely. If updates repeatedly fail to install, that is a reason to ask for
help rather than to disable the service.

## Arch automatic updates and their gates

Arch does **not** run a blind unattended upgrade. A daily timer attempts exactly
one complete `pacman -Syu` transaction, and it runs only when every gate holds:

- the machine is on AC power;
- there is enough free space;
- no other package transaction is in progress; and
- the official Arch mirror is reachable.

It saves before/after package lists and verifies installed files, and it never
interrupts a session to reboot. A missed run simply retries later. This is the
deliberate trade recorded in the project's decisions: a gated, health-checked,
rollback-aware policy instead of blind automation.

To confirm the timer is healthy and see the next scheduled run:

```sh
systemctl status homelab-arch-update.timer --no-pager
```

To ask directly whether an update is warranted and whether the gate would allow
one right now:

```sh
make homelab-arch-update-check
```

A **failing gate is the safe answer**, not a fault: it declines the upgrade
rather than leaving a half-applied system. Never work around it by hand — do not
run a partial `pacman -Sy`, delete the pacman lock, or force a package
replacement. Arch requires full-system upgrades; a partial one is how a machine
breaks.

## Travel and offline use

A Telos laptop is built to work indefinitely away from home, including at
college, with the Controller unreachable. Cached login, local files, public
Internet, and both operating systems' automatic updates do not depend on
reaching home. Before a long trip, prove that once:

1. Update Windows, restart, and confirm login with Wi-Fi disconnected.
2. Let Arch's timer run, restart if it recommends one, and confirm login with
   Wi-Fi disconnected.
3. Open an important local file while optional network storage is unreachable.
4. Connect once to a non-home network and reach an ordinary HTTPS site.

The step-by-step travel checklist and its stop conditions are in the
[Workstation Owner Guide](../workstation-owner-guide/index.md).

### The cached-login limit you must understand

Cached, offline login is what makes travel work — and it is also its own
security limit. An account that has logged in on a laptop keeps working offline
even after an administrator disables its network access, because the disabling
happens at home and the laptop is not there to hear it. That protects travel
use; it is **not** remote erasure and it is **not** immediate revocation.
Immediate disconnected revocation is a deliberately deferred capability. The
practical consequence is simple: report a lost or stolen laptop promptly, and do
not assume that disabling an account instantly locks a machine that is already
away.

## Controller, directory, and media upkeep

These are administrator tasks done at home on the isolated fabric, not owner
tasks, but they belong on the maintenance calendar:

- **Media stays verified.** The network-boot inputs are content-addressed and
  sealed; confirm the seal and every bound input still match without
  re-downloading anything:

  ```sh
  make homelab-factory-offline-check
  ```

- **Releases stay provable.** A published network-boot release should still
  verify against its manifest:

  ```sh
  make homelab-pxe-release-set-verify RELEASE_SET=<versioned release-set directory>
  ```

- **Convergence stays clean.** The Controller's configuration is Ansible
  convergence from this repository; a syntax check catches drift the unit tests
  cannot:

  ```sh
  make homelab-converge-check
  ```

- **No private data leaks.** Before publishing anything, confirm no private
  inventory reached a public source:

  ```sh
  make homelab-private-check IDENTIFIERS=<private denylist file>
  ```

Capacity, logs, key and certificate expiry, backup-and-restore drills, and
network exports are also part of a full maintenance calendar; those depend on
gates that are still being accepted and are tracked in the factory state ledger
rather than promised here.

## When to ask for help

Ask soon if Arch or Windows updates repeatedly fail, if free space stays low, if
the update timer is not `active (waiting)`, or if a verification command that
used to pass starts failing. Ask immediately if either operating system stops
booting, a disk disappears, a recovery key is unexpectedly requested, an unknown
administrator prompt appears, or a laptop is lost. Directory rejoin, firmware,
disk layout, boot entries, network policy, package repair, and storage
authorization are administrator work.

When a check has actually failed, move to the
[Recovery library](../recovery-library/index.md), which is organized by symptom and
names the safe next action for each one.
