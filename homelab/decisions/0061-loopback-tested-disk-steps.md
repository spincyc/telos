# ADR 0061: Test the disk-writing steps against loopback devices

## Supersession

ADR 0062 supersedes this decision. A second privileged test tier was premature:
it adds root requirements and a privileged CI runner to prove partition
layout, before a single end-to-end install had ever been observed. The QEMU
matrix under ADR 0056 covers the same ground with a feedback loop that also
proves the machine boots.
This ADR remains as the record of the earlier decision.

- Status: Superseded by ADR 0062
- Date: 2026-07-26

## Context

Everything decided so far is pure computation and is unit-tested: the network
plan, the prompt registry, preflight judgement, the step runner, the manifest.
The remaining installer work is different in kind. Partitioning, LUKS2, Btrfs
subvolume creation, `pacstrap` and boot-artifact generation all require a real
block device and root privilege, so none of it can be exercised by the fast
suite.

Asserting on generated argv lists would only prove the installer produces the
commands its author intended. It would not prove those commands do what he
thinks to an actual device, which is where the interesting mistakes live: a
wrong partition type GUID, an alignment that silently costs performance, a
subvolume layout that does not match what ADR 0027 says gets checkpointed.

## Decision

Write the disk steps so they take a **device path** and nothing else about how
that device came to exist. A test can then supply a loopback device backed by a
sparse file, and the genuine `sgdisk`, `cryptsetup` and `mkfs.btrfs` run against
it for real.

- Loopback tests live in `homelab/tests/integration/` and are **not** part of
  the default suite. They need root and they are slow.
- Run them with an explicit target: `make homelab-integration`.
- Each test creates its own sparse backing file in a temporary directory,
  attaches it, runs the step, asserts on the result by re-reading the device
  with `sgdisk --print`, `cryptsetup luksDump` and `btrfs subvolume list`, and
  detaches and deletes it unconditionally.
- A test must never touch a device it did not create. The helper refuses any
  path that is not a loop device it attached itself, and the refusal is tested.
- `pacstrap` and UKI generation are **not** covered here. They need network
  access and a full Arch environment, so they belong to the QEMU matrix under
  ADR 0056.

This does not replace the acceptance matrix. Loopback tests answer "does this
step produce the layout it claims"; the matrix answers "does a machine built
this way boot and serve DHCP".

## Consequences

- Partitioning and filesystem bugs are caught in seconds against a real kernel
  block layer, rather than in minutes as a failed virtual install.
- The default test suite stays fast and needs no privileges, so it keeps being
  run.
- Two test tiers must both be kept green, and CI needs a privileged runner for
  the second.
- Steps are forced into a shape that takes a device path rather than discovering
  one, which is better design independently of testing.
- A loopback device is not a real disk: it has no firmware, no 4K-native
  geometry, no TRIM and no SMART. Layout is provable this way; behaviour on real
  hardware is not.
