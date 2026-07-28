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
updated_at: "2026-07-28T01:07:25Z"
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

## Progress

The host authorization contract is implemented and tested. It binds the
selected release, standalone 256 GiB-or-larger qcow2, safe serial, exact sole
writable OS-disk QEMU exposure, layout record, and command digest. Private
runtime inputs have restrictive permissions, digest-only receipts,
known-secret evidence rejection, and success/failure teardown.

The user authorized pushing checkpoints and directed continuous progress.
`origin/main` now includes `dafb18a`; continue with private WinPE input
rendering and Windows-first partition application.

Private DiskPart, startup, and answer-file renderers are implemented. Recovery
uses an explicit absolute offset after an untouched Arch gap. Setup is pinned
to Pro, en-US, and the precreated Windows partition. The disk-count and
capacity boundary is checked twice before the sole destructive call. Next,
construct and verify the private WinPE overlay and complete install-source
publication.

The private wimboot injection set and complete install-source publication are
implemented. The disposable Controller verifies and checksums the private
overlay and sealed Windows tree, serves the overlay only on the isolated HTTP
endpoint, and exports the source through authenticated read-only SMB.
Readiness now includes SMB. Next, integrate this material with a persistent
NVMe Windows install lifecycle and native-boot evidence.

The persistent workstation QEMU boundary is implemented with fixed-serial
NVMe, 8 GiB RAM, PXE-first e1000e, copied OVMF state, private publication
media, and QMP. Existing topology callers remain virtio-only. Next, execute a
real private publication build, then integrate the bounded install and
native-disk reboot phases.

The guarded preparation command is implemented and dry-run verified. Apply
creates only new ignored private state and removes incomplete bundles on any
failure. The next boundary is a real preparation from the sealed source,
followed by the bounded Controller/workstation install lifecycle.

One complete private bundle has been prepared from the sealed source. The
bounded lifecycle launcher now validates the bundle and exact disk boundary,
boots the disposable Controller with the private publication attached, boots
the persistent workstation without installation media, re-audits both live
QEMU processes, captures secret-free evidence, and guarantees child teardown.
Focused tests and the real-bundle dry run pass. The next operation is the first
bounded loopback-only WinPE overlay observation.

The first bounded execution failed safely during Controller publication,
before the workstation launched. Samba's password-database command requires
its configuration file to exist, but the publisher created the file
afterward. All children and the disposable overlay were cleaned up; the fresh
workstation disk was never booted. Publication now creates the fail-closed
read-only configuration before adding the synthetic account. A newly prepared
bundle is required because completed private publication images are immutable.
