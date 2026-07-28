---
schema_version: 1
task_uuid: "e1135b56-26e9-4d97-946a-0284f5eb8c99"
title: "Complete Windows identity and recovery acceptance"
status: "active"
priority: "normal"
priority_reason: "Windows acceptance follows successful installation"
parent: null
discovered_by: null
hard_dependencies: ["cfcab9ef-1f05-46d5-967e-a5a4bb43d923"]
soft_dependencies: []
related_to: ["0ab775e2-490d-4901-869d-d83e788a8e42"]
superseded_by: null
created_at: "2026-07-27T21:51:54Z"
updated_at: "2026-07-28T12:57:50Z"
---

# Goal

Join installed Windows to synthetic Samba AD using one-use/offline material and
prove connected/offline identities, privilege boundaries, update policy,
recovery, and secret-free diagnostics under injected failures.

## Acceptance criteria

- DNS, time, secure channel, user/admin/rescue identities, reboot, and cached login are verified.
- AD/DNS, gateway, update-source, and optional-storage failures are exercised.
- Reusable administrator credentials are not embedded or retained.
- Firmware activation and live Microsoft Update remain explicitly outside local proof.

## Scope and concurrency

Owns Windows domain identity and acceptance on the existing disposable guest;
serialize access to that guest and controller directory state.

## Activation plan

Reconcile the retained installed guest with the disposable Controller and
existing identity-lifecycle contracts. Implement private one-use join and
acceptance inputs without adding reusable credentials to QEMU arguments,
logs, or tracked artifacts. Prove the connected identity boundary before
fault injection, then exercise cached login, recovery identities, and the
specified service failures with machine-readable receipts.
