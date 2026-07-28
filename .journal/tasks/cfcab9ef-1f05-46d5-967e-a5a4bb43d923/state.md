---
schema_version: 1
task_uuid: "cfcab9ef-1f05-46d5-967e-a5a4bb43d923"
title: "Implement Windows-first installation"
status: "active"
priority: "normal"
priority_reason: "Next factory gate after isolated PXE proof"
parent: null
discovered_by: null
hard_dependencies: ["c9c5d25a-3d94-4eaa-95b8-2cadbd44633c"]
soft_dependencies: []
related_to: ["e1135b56-26e9-4d97-946a-0284f5eb8c99"]
superseded_by: null
created_at: "2026-07-27T21:51:53Z"
updated_at: "2026-07-28T00:34:34Z"
---

# Goal

PXE-install Windows 11 Pro on a serial-authorized disposable UEFI/GPT disk,
with ephemeral answer/startup inputs, verified layout, native boot, and safe
secret teardown.

## Acceptance criteria

- Exact stable disk serial is structurally required and authorization is narrowly scoped.
- Planned ESP/MSR/Windows/recovery layout preserves reserved Arch space.
- Edition, locale, encryption exception, native UEFI boot, hibernation/Fast Startup, and NTFS shutdown are verified.
- Failures produce machine-readable, secret-free evidence.

## Scope and concurrency

Owns Windows installation workflow and disposable workstation disk. Serialize
all destructive guest-disk and shared factory-environment operations.

## Activation plan

Audit the existing answer-file, disk-authorization, and QEMU lifecycle
surfaces against the acceptance criteria. Implement the smallest missing
fail-closed controls, then perform an unattended install only on a freshly
created disposable disk with an exact pinned serial.

## Decisions

Private per-run Windows startup and answer files are authorized for disposable
QEMU acceptance only. They must use synthetic values, bind mutation to the
exact disk serial, remain outside Git and immutable releases, retain no
secrets, and be removed during teardown. Physical launch remains interactive
and uses user-supplied private values.

For disposable QEMU, the synthetic serial is enforced and recorded at the host
launcher because stock WinPE has no proven direct serial query. QEMU must
expose exactly one writable disk, and WinPE must independently recheck exactly
one eligible disk of the authorized capacity before setup and immediately
before partition mutation. Physical installation still uses the hardware
serial directly.
