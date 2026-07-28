---
schema_version: 1
generated_at: "2026-07-28T01:49:56Z"
task_count: 10
---

# Work queue

This file is a rebuildable view. Task `state.md` files are authoritative.

## Active

- `cfcab9ef-1f05-46d5-967e-a5a4bb43d923` — Implement Windows-first installation [active, normal] (depends on c9c5d25a-3d94-4eaa-95b8-2cadbd44633c)

## Queued

- `e1135b56-26e9-4d97-946a-0284f5eb8c99` — Complete Windows identity and recovery acceptance [queued, normal] (depends on cfcab9ef-1f05-46d5-967e-a5a4bb43d923)
- `0ab775e2-490d-4901-869d-d83e788a8e42` — Implement Arch-second installation and identity [queued, normal] (depends on e1135b56-26e9-4d97-946a-0284f5eb8c99)
- `6e525567-4ef1-4c2e-ab52-ab099a87c780` — Finish dual-boot recovery and repeatability gates [queued, normal] (depends on 0ab775e2-490d-4901-869d-d83e788a8e42)
- `c0fc1fa3-1f4f-46e6-8167-9f6eca031d6e` — Complete homelab documentation pass [queued, normal] (depends on 6e525567-4ef1-4c2e-ab52-ab099a87c780)
- `a8c935bc-acd4-4a2d-bc7d-cc0c81e422a8` — Prepare external integration readiness plan [queued, low] (depends on c0fc1fa3-1f4f-46e6-8167-9f6eca031d6e)

## Blocked

None.

## Terminal

- `ebd2daed-fc26-4851-b1e7-cbd86dba96c0` — Restore repository verification gate [done, high]
- `97541f7d-8649-4520-af30-9bd8deba2b00` — Reconcile factory durable state and local inputs [done, high]
- `73e77cf3-f91d-47ae-ae5f-f0d80aea879a` — Complete sealed media and immutable PXE releases [done, high] (depends on ebd2daed-fc26-4851-b1e7-cbd86dba96c0, 97541f7d-8649-4520-af30-9bd8deba2b00)
- `c9c5d25a-3d94-4eaa-95b8-2cadbd44633c` — Prove integrated isolated PXE handoff [done, high] (depends on 73e77cf3-f91d-47ae-ae5f-f0d80aea879a)
