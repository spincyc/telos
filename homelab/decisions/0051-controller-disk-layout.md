# ADR 0051: Fix the Controller disk layout and ESP size

- Status: Accepted
- Date: 2026-07-25

## Context

ADR 0025 deferred ESP sizing until the UKIs could be measured, and ADR 0047 has
now removed Windows from the Controller entirely. The layout can be settled.

Three UKIs must fit: `linux-lts`, `linux`, and a self-contained recovery UKI
whose embedded rescue userspace is by far the largest. A UKI with a full
initramfs and rescue tooling runs to a few hundred megabytes, and the ESP must
hold two copies of everything during an update transaction so a failed update
cannot leave the machine unbootable.

## Decision

Use this GPT layout on a single Controller disk:

| # | Size | Type | Contents |
|---|---|---|---|
| 1 | 2 GiB | EFI System (FAT32) | systemd-boot, three UKIs, update headroom |
| 2 | rest | Linux LUKS2 | Btrfs, subvolumes per ADR 0027 |

- 2 GiB is deliberate headroom, not a measurement. It costs nothing on any
  plausible Controller disk and removes an entire class of failed-update
  outage. The ESP is the one partition that cannot be grown after the fact
  without moving everything after it.
- No XBOOTLDR, no Microsoft reserved partition, no Windows recovery partition.
- Swap is a file inside the encrypted Btrfs root, not a separate partition, so
  ADR 0020's encrypted-swap requirement is satisfied without a second LUKS
  container.
- Hibernation is disabled on the Controller. A machine whose purpose is to
  answer DHCP does not suspend.
- The installer refuses any disk smaller than 64 GiB and requires the operator
  to confirm the disk by model, serial and size, never by `/dev/sdX`.

## Consequences

- The install-time disk decisions are now fully specified.
- Update transactions can stage a complete new artifact set before switching.
- A Controller disk is portable to different hardware because nothing in the
  layout is machine-specific.
- Multi-disk redundancy remains out of scope; the Controller is one failure
  domain under ADR 0014 regardless.
