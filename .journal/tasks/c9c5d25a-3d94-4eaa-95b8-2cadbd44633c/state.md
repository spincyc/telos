---
schema_version: 1
task_uuid: "c9c5d25a-3d94-4eaa-95b8-2cadbd44633c"
title: "Prove integrated isolated PXE handoff"
status: "active"
priority: "high"
priority_reason: "Required integration proof before destructive guest installation"
parent: null
discovered_by: null
hard_dependencies: ["73e77cf3-f91d-47ae-ae5f-f0d80aea879a"]
soft_dependencies: []
related_to: ["cfcab9ef-1f05-46d5-967e-a5a4bb43d923"]
superseded_by: null
created_at: "2026-07-27T21:51:52Z"
updated_at: "2026-07-28T00:19:18Z"
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

## Activation plan

First reconcile the known boot-path mismatch and publish/capture boundary in
the loopback lifecycle. Then prove real OVMF iPXE requests and Arch/WinPE
handoffs from selected release `20260727.001`, retaining packet and manifest
evidence without attaching any physical interface.

## Progress

Real OVMF now completes gateway-only DHCP, verified iPXE TFTP, selected
bootstrap HTTP, and immutable Arch kernel/initramfs downloads. The fail-closed
lifecycle retains bounded private evidence and verifies the exact publication
before starting the workstation. Release `20260727.001` lacks serial-console
arguments because it predates this implementation; mint `.002` and repeat for
the post-kernel handoff marker.

Release `.002` proved full selected image download and non-returning iPXE
control transfer. Direct Q35 boot proved the exact kernel/initramfs valid.
The next `.003` release adds early UART and serial-primary diagnostics to
observe the remaining EFI-to-kernel boundary without weakening acceptance.

Release `.003` proved kernel entry, `/init`, and Archiso PXE hooks. Its
network-root failure was a deterministic `eth0` rename race; `.004` will bind
the PXE MAC and disable initramfs interface renaming. Acceptance records the
partial phases but still requires root-image retrieval and live userspace.

Release `.005` completed real Arch UEFI PXE acceptance through root-image
retrieval, mount, and `archiso login:` on the loopback-only fabric. Retained
success evidence records gateway-only DHCP and every handoff phase. Continue
with the separate real WinPE handoff before completing this task.
