---
schema_version: 1
task_uuid: "c9c5d25a-3d94-4eaa-95b8-2cadbd44633c"
title: "Prove integrated isolated PXE handoff"
status: "queued"
priority: "high"
priority_reason: "Required integration proof before destructive guest installation"
parent: null
discovered_by: null
hard_dependencies: ["73e77cf3-f91d-47ae-ae5f-f0d80aea879a"]
soft_dependencies: []
related_to: ["cfcab9ef-1f05-46d5-967e-a5a4bb43d923"]
superseded_by: null
created_at: "2026-07-27T21:51:52Z"
updated_at: "2026-07-27T21:51:52Z"
---

# Goal

Prove real x86-64 UEFI iPXE handoff for Arch and WinPE on the loopback-only
userspace factory fabric with gateway-only DHCP authority and manifest-exact
served bytes.

## Acceptance criteria

- Arch installer and WinPE handoffs are observed from real UEFI iPXE requests.
- DHCP authority, architecture choice, release integrity, and network isolation are measured.
- Rogue offers, wrong architecture, altered releases, and forbidden networking fail safely.
- No TAP, bridge, route, UniFi, physical-interface, or external-network mutation occurs.

## Scope and concurrency

Owns the disposable isolated PXE integration environment. Serialize with other
tasks that mutate the same controller or generated release state.
