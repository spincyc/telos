# Workstation Owner Guide

This is the first-stop guide for someone using a Telos Windows 11 and Arch
laptop away from home. It covers normal use, automatic updates, optional
storage, safe recovery, and the evidence that makes remote help effective.

[Download the printable offline guide](../../../doc/homelab/manual/workstation-owner-guide.pdf)

> **Stop boundary**
>
> You may restart, choose either operating system, reconnect Wi-Fi, check
> update status, free your own ordinary files, test optional storage, and
> collect the evidence below. Stop before changing firmware, partitions, boot
> entries, directory membership, system time by hand, package databases,
> security policy, or another person's files.

## Normal use

Windows starts by default after the five-second boot menu. Choose Arch before
the countdown ends. Your local profile must open even when home Wi-Fi, the
Controller, and optional network storage are unavailable.

Before a long trip:

1. Boot Windows, update it, restart, and test login with Wi-Fi disconnected.
2. Boot Arch, let its automatic update run, restart if recommended, and test
   login with Wi-Fi disconnected.
3. Open important local files while optional storage is unreachable.
4. Connect once to a non-home network.
5. Open the printable guide with every network disabled.

A previously used account may keep working offline after an administrator
disables network access. That protects travel use, but is not remote erasure.
Report a lost laptop promptly.

## Wi-Fi

Use the managed-workstation network supplied with the laptop. Its credential
may be unique to that machine. Do not copy it to another device.

If Wi-Fi fails, turn it off, wait five seconds, and turn it on. Test another
known network or phone hotspot. If other networks work, report “managed
network absent.” If none work, restart once and collect evidence. Do not forget
and recreate the saved network unless an administrator asks.

## Automatic updates

Leave Windows Update enabled. Plug in overnight at least weekly, and restart
when Windows requests it.

Arch uses a daily timer for one complete `pacman -Syu` transaction. It runs
only on AC power, with at least 8 GiB free, no other package transaction, and
the official mirror reachable. A missed run retries after the next boot. It
saves before/after package lists and verifies installed files, but does not
interrupt a user session to reboot.

```sh
systemctl status homelab-arch-update.timer --no-pager
```

The timer should say `active (waiting)` and show a next run.

Never run `pacman -Sy`, delete the pacman lock, force package replacement, or
power off during package installation. Arch requires full-system upgrades.

## Optional storage

Optional storage appears after login as a Windows mapped drive or Arch folder.
It is not your home directory.

| Result | Meaning | Response |
|---|---|---|
| Opens | Network and authorization work | Use normally |
| Unavailable | Away, server down, or route blocked | Work locally; retry later |
| Access denied | Server reachable, permission differs | Record exact message; do not alter permissions |
| Login fails too | Not acceptable | Disconnect Wi-Fi, test cached login, escalate |

When copying important work to a backup, open the copied file from the
destination. A visible filename does not prove its bytes arrived.

## Recovery ladder

Use this order and stop as soon as normal operation returns:

1. Save work locally. Photograph the exact message if saving is impossible.
2. Connect power. Check airplane mode, Wi-Fi, free space, date, time zone, and
   Caps Lock.
3. Repeat the failed action once.
4. Restart normally.
5. Try the other operating system from the boot menu.
6. Disconnect Wi-Fi and test an account previously used on this machine.
7. Use the local rescue account only when an administrator directs you.
8. Escalate with evidence.

Power down and unplug for swelling, liquid, smoke, burning odor, crackling,
repeated thermal shutdown, exposed conductors, or a charger or port too hot to
touch.

## Evidence without secrets

Record the operating system, local date/time, power state, what you attempted,
exact result, last successful boot/login/update, and whether restart, the other
OS, offline login, and another network worked. Add exact error text or a
tightly cropped photo. For Arch, include:

```sh
systemctl status homelab-arch-update.timer --no-pager
systemctl status homelab-arch-update.service --no-pager
journalctl -u homelab-arch-update.service -b --no-pager
df -h /
```

Remove passwords, Wi-Fi keys, recovery keys, tokens, private keys, browser
contents, personal documents, full addresses, public IP addresses, serial
numbers, and unrelated names. Send evidence only through the family's agreed
private channel, never a public issue or chat.

## Ask for help

Ask soon if updates repeatedly fail, free space stays below 8 GiB, time drifts,
storage says access denied, either OS stops booting, or login works only
offline.

Ask immediately if both operating systems fail, the disk disappears, a
recovery key is unexpectedly requested, an unknown administrator prompt
appears, the laptop is lost, or you suspect account compromise.

Directory accounts, domain rejoin, firmware, Secure Boot, disk layout,
encryption, boot entries, PXE, network policy, package repair, and storage
authorization are administrator work.

## Offline copy

The workstation image should install the versioned PDF locally in both
operating systems and add a desktop or Start-menu shortcut. A documentation
update copies a new version, verifies its SHA-256 digest, then changes the
shortcut. The previous copy remains until the new one opens successfully.

Disconnect every network and open the shortcut. Verify the footer says
`20260727.001` and the recovery ladder is readable without following a link.
