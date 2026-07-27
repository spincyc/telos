---
schema_version: 1
task_uuid: "97541f7d-8649-4520-af30-9bd8deba2b00"
title: "Reconcile factory durable state and local inputs"
status: "active"
priority: "high"
priority_reason: "Factory execution depends on an accurate restart ledger and input inventory"
parent: null
discovered_by: null
hard_dependencies: []
soft_dependencies: ["ebd2daed-fc26-4851-b1e7-cbd86dba96c0"]
related_to: ["73e77cf3-f91d-47ae-ae5f-f0d80aea879a"]
superseded_by: null
created_at: "2026-07-27T21:51:50Z"
updated_at: "2026-07-27T21:55:17Z"
---

# Goal

Reconcile the authoritative factory ledger with HEAD and ignored local inputs,
verify canonical receipts without disclosing secrets, and supersede stale
claims in `HANDOFF.md`.

## Acceptance criteria

- Canonical media/controller receipts and ignored-state facts are verified.
- Redundant root ISO is compared but not deleted without authority.
- Completed gates, blockers, baselines, and literal restart sequence are current.
- Documentation-only validation passes.

## Scope and concurrency

Owns factory state-ledger and stale handoff documentation. Read-only media
inspection may run concurrently; coordinate any overlapping ledger edits.
