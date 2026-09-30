# ADR 0079: Drop the replacement-Controller PXE mint

- Status: Accepted
- Date: 2026-09-30

## Context

`homelab/LOCAL-FACTORY-LIFECYCLE.md` Gate 3, "replacement Controller mint",
requires PXE-booting a blank candidate Controller from the bootstrap
Controller and installing it to a serial-authorized disposable disk. ADR
0056's acceptance matrix carries the same idea: a bootstrap host serves the
boot chain and a virtual Controller target network-boots its installer.

Neither was ever built. In `homelab/qemu/matrix.py` the `boot-chain`,
`install`, `activation` and `converge` stages all report that they are not
implemented; `homelab/vm/factory_publication.py` publishes only the
`arch-workstation` and `windows` boot targets; and no mint evidence exists.

The Controller already has a proven rebuild path. Per ADRs 0065 and 0067 the
first Controller is a QEMU VM. `make homelab-bootstrap-vm-install` installs
its canonical image from the Arch ISO and the seed ISO by driving the genuine
interactive installer over the serial console, as ADR 0058 prescribes. Its
first live run, on 2026-09-24, succeeded first time. Its guards are recorded
in `homelab/FACTORY-MAKE-TARGETS.md`, "Installing the canonical Controller
image": among them, it erases only a disk byte-identical to a freshly created
empty image, never a working Controller.

The machine is not the asset that cannot be rebuilt; the domain is. ADR 0067
makes the bootstrap VM the real domain once workstations join it and forbids
duplicating, renaming or restoring its live DC disk. Lifecycle Gate 7 already
requires same-realm reconstruction from a tested Samba AD backup. A second
way to install the machine adds nothing to either.

## Decision

Drop lifecycle Gate 3, "replacement Controller mint". Local factory acceptance
does not PXE-boot, network-install or cold-boot-accept a candidate
Controller. The first Controller is installed from ISO with
`make homelab-bootstrap-vm-install` and converged by Gate 2. Recovery of the
domain itself remains Gate 7's tested Samba AD backup.

This supersedes:

- the Gate 3 section of `homelab/LOCAL-FACTORY-LIFECYCLE.md`, item 5 of its
  2026-07-27 implementation gaps, and Gate 3's place in its all-gates
  promotion rule and in its `homelab-factory-controller` command row; and
- the part of ADR 0056's matrix, as amended by ADR 0074, that network-boots a
  virtual Controller target from a bootstrap host, which is the Controller
  `boot-chain` stage of `homelab/qemu/matrix.py`.

ADR 0056's requirement that the Controller target be installed by the genuine
installer, driven as ADR 0058 prescribes, stays in force;
`homelab-bootstrap-vm-install` meets it. ADRs 0074 and 0077 contain no
Controller network-install requirement and are unchanged. Lifecycle gate
numbers are neither reused nor renumbered.

Not decided here: a physical Controller, the permanent DC of ADR 0068, or the
second DC on separate hardware that ADR 0055 requires may later adopt network
installation. That needs a new ADR; nothing in the dropped gate carries over
to it.

## Consequences

- Local factory promotion requires lifecycle Gates 1, 2 and 4 through 7. A
  run with no Gate 3 evidence is not incomplete on that account.
- No code changes with this decision. The unimplemented matrix stages remain
  pending stubs, and the PXE release set still builds a `controller` target
  (`homelab/lib/pxe_release_set.py`). Whether either keeps a purpose is a
  separate change.
- No factory step brings up a candidate Controller beside the running one, so
  the identity collision Gate 3 guarded against, two machines claiming the
  bootstrap DC identity, is not exercised. ADR 0067's prohibition on cloning
  a live DC disk continues to govern every rebuild.
- Gate 3 would have proved a destroy-and-remint of the Controller. The ISO path
  has one live run, not a repeated one; Controller reconstruction stays graded
  by lifecycle Gate 7 and the ledger's lifecycle-recovery gate.
