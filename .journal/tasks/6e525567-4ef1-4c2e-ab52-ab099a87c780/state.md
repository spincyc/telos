---
schema_version: 1
task_uuid: "6e525567-4ef1-4c2e-ab52-ab099a87c780"
title: "Finish dual-boot recovery and repeatability gates"
status: "queued"
priority: "normal"
priority_reason: "Final local acceptance depends on both installed operating systems"
parent: null
discovered_by: null
hard_dependencies: ["0ab775e2-490d-4901-869d-d83e788a8e42"]
soft_dependencies: []
related_to: ["c0fc1fa3-1f4f-46e6-8167-9f6eca031d6e"]
superseded_by: null
created_at: "2026-07-27T21:51:56Z"
updated_at: "2026-07-27T21:51:56Z"
---

# Goal

Complete factory gates 9–12: optional storage bounds, cold-boot dual-OS
acceptance, failure/recovery drills, controller reconstruction, two complete
repeatability cycles, and a final machine-readable receipt.

## Acceptance criteria

- Optional SMB never exceeds its declared login failure bound.
- Dual boot, EFI/partition integrity, failure injection, rollback, remint, and encrypted-backup reconstruction are proven.
- Two post-destruction lifecycle repeats have compared manifests and explained nondeterminism.
- Unsupported NFS, encryption, Secure Boot, TPM, and external update claims remain absent.

## Scope and concurrency

Owns final shared factory environment, controller, guest disk, recovery state,
and repeat runs. It is not parallel-safe with other factory mutations.
