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
updated_at: "2026-07-27T21:58:25Z"
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
