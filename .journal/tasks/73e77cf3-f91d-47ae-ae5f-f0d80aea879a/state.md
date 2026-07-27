---
schema_version: 1
task_uuid: "73e77cf3-f91d-47ae-ae5f-f0d80aea879a"
title: "Complete sealed media and immutable PXE releases"
status: "active"
priority: "high"
priority_reason: "First incomplete executable factory gates"
parent: null
discovered_by: null
hard_dependencies: ["ebd2daed-fc26-4851-b1e7-cbd86dba96c0", "97541f7d-8649-4520-af30-9bd8deba2b00"]
soft_dependencies: []
related_to: ["c9c5d25a-3d94-4eaa-95b8-2cadbd44633c"]
superseded_by: null
created_at: "2026-07-27T21:51:51Z"
updated_at: "2026-07-27T23:03:14Z"
---

# Goal

Finish factory gates 1 and 2: aggregate sealed-cache receipt plus immutable,
versioned controller, Arch, and Windows PXE releases, including Windows
installation-image delivery.

## Acceptance criteria

- One release version covers all required families with verified manifests.
- Altered, missing, symlinked, wrong-edition, mutable, and unlisted inputs are rejected.
- Publication and rollback are atomic and no media enters Git/site output.
- Tests, receipts, ledger, Make contracts, and journal are current.

## Scope and concurrency

Owns sealed-cache aggregation and immutable release production. Generated
media/PXE state is a shared mutable resource; only one executor may mutate it.

## Activation plan

First implement and checkpoint a deterministic aggregate media seal that
reuses existing Arch, Windows, wimboot, and extracted-install-source
verification. Then implement the transactional multi-target release set.

## Progress

The aggregate seal is implemented and verified against both fixtures and the
live ignored cache. It records a stable content/provenance inventory, separate
tool versions, and rejects unstable or unsafe inputs. The task remains active
for the first real controller/Arch/Windows release set.

The transactional builder now stages all three leaves privately, binds them
and the sealed Windows SMB source into one aggregate receipt, and selects only
after complete verification. Negative, interruption, and rollback tests pass.
The sealed Arch ISO now derives a mount-free, digest-addressed 96-file source
cache. The next slice must build the missing purpose-built Controller
mkarchiso netboot output and then build the first set. The `TELOS_SEED` data
disc is not a valid substitute.

Controller source intake now rejects links, special files, and empty required
payloads; target metadata binds the complete copied source inventory. The
unsupported `cms_verify=y` claim was removed pending a defined signing-key
contract.

A real rootless build additionally corrected the intake for current EROFS
output and SHA-512 sidecars. The Archiso profile now contains and audits the
minimal UEFI HTTP-PXE hook chain and wired DHCP activation while excluding
unused MEMDISK, NBD, and NFS transports. A clean reproducible rebuild remains
before import and release selection.

## Cleared blocker

The audited profile is staged at `/tmp/homelab-image/profile`. The environment
now supports `unshare --map-auto --map-root-user`, so modern `mkarchiso` can
use its rootless build path without an operator credential.

## Resume

Build the disposable netboot output, import it into the ignored Controller
cache, then build and verify the first transactional release set. Physical
launch remains explicitly reserved for the user's own session.
