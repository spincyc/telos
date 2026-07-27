---
schema_version: 1
task_uuid: "0ab775e2-490d-4901-869d-d83e788a8e42"
title: "Implement Arch-second installation and identity"
status: "queued"
priority: "normal"
priority_reason: "Arch installation depends on accepted Windows disk state"
parent: null
discovered_by: null
hard_dependencies: ["e1135b56-26e9-4d97-946a-0284f5eb8c99"]
soft_dependencies: []
related_to: ["6e525567-4ef1-4c2e-ab52-ab099a87c780"]
superseded_by: null
created_at: "2026-07-27T21:51:55Z"
updated_at: "2026-07-27T21:51:55Z"
---

# Goal

Install Arch second without altering Windows/recovery extents, establish
independent native systemd-boot, and prove domain identities, offline access,
signed updates, rollback, and recovery.

## Acceptance criteria

- Dirty/hibernated NTFS and any unplanned destructive change are rejected.
- Only reserved space is consumed and Windows remains the five-second default.
- SID mapping, SSSD/Kerberos, privilege boundaries, rescue, offline policy, updates, rollback, and recovery are verified.
- Retained evidence is machine-readable and secret-free.

## Scope and concurrency

Owns Arch installation and identity on the shared disposable disk. Serialize
all guest-disk, bootloader, directory, and factory-environment mutation.
