# Homelab documentation pass

Status: queued

The current implementation work continues without waiting for this pass.
Homelab documentation is HTML/Markdown-first. No Homelab PDF is required at
this time, and a missing PDF must not block implementation, testing, or
publication.

## Required document layers

Every supported Homelab workflow must have two linked views:

1. **Human guide.** A terse, readable path for an owner or family member. It
   explains what the workflow accomplishes, when to use it, what must already
   be true, visible stop conditions, and the next safe action.
2. **Operator guide.** Exact commands and UI fields, expected intermediate
   output, measurements, verification after every material change, failure
   branches, rollback, recovery, and an evidence record.

The human guide must not become a command dump. The operator guide must not
assume that a smart reader can infer omitted steps. Both must use callouts that
say what a step changes and why it is necessary.

## Definition of done

A workflow is documented only when:

- prerequisites, scope, risks, and explicit non-goals are stated;
- private values are represented by named placeholders and remain in the
  private overlay;
- every mutation has a preceding observation and a following verification;
- expected output or measurable pass criteria are shown;
- stop conditions prevent unsafe continuation;
- retry, rollback, and recovery paths are executable;
- ordinary maintenance, updates, backups, restore tests, and replacement are
  covered;
- a secret-free diagnostic bundle and escalation path are described;
- first-time, routine, failure, and decommissioning paths are linked;
- commands and Make targets agree with the current implementation;
- the public guide works from a fresh clone without untracked artifacts;
- HTML navigation exposes the current guide and labels incomplete work;
- automated checks reject stale commands, leaked private data, broken links,
  and unsupported claims.

Screenshots and diagrams should be added where they remove ambiguity. Schematics
are appropriate for topology, trust boundaries, boot flow, storage layout, and
state transitions. Other illustrations should use the project-wide drawing
standard. Empty page-space is not a goal; insufficient explanation should be
fixed with useful content rather than decoration.

## Pass sequence

| Order | Topic | Human guide | Detailed operator guide and identified gaps | Status |
|---:|---|---|---|---|
| 1 | Documentation map | One page answering “what do I read now?” | Replace PDF-only links; define document ownership, version display, freshness checks, and public/private boundaries | queued |
| 2 | Controller network gate | Explain the deliberately restricted first attachment and safe rollback | Complete UniFi field-by-field setup, VLAN/subnet/firewall measurements, lease/DNS tests, packet-path proof, rollback, and evidence record | active draft |
| 3 | Bootstrap Controller | Explain what the VM buys, what it currently owns, and why it can be replaced | Fresh-clone dependencies, media verification, seed build, VM creation, installation, password handling, disk identity, boot checks, snapshots/backups, restore rehearsal, update, and rebuild | partial |
| 4 | Network design | Explain the address aesthetic, small scan-friendly ranges, and device classes | Exact UniFi objects and order, restricted provisioning Wi-Fi, DHCP/DNS authority boundaries, firewall matrix, discovery exceptions, capacity measurements, conflict tests, and recovery from a broken isolated network | gap |
| 5 | Directory and DNS | Explain one identity across Windows and Arch, cached logons, and travel limits | Samba AD/DNS deployment, validation, time synchronization, administrator tiers, user lifecycle, temporary revocation phases, backup/restore, disaster recovery, and authority handoff | gap |
| 6 | PXE and install media | Explain wired boot, Wi-Fi limitations, provenance, and what remains manual | Arch and Windows acquisition, hashes/signatures, immutable release layout, wimboot, firmware boot order, restricted network credentials, update publication, rollback, and offline recovery | partial |
| 7 | Workstation factory | Provide a short minting checklist with clear go/no-go gates | Target-laptop firmware, configurable disk baseline, Windows-primary dual boot, no-encryption pilot, installation, identity joins, local recovery, acceptance measurements, rebuild avoidance, and release recording | partial |
| 8 | Windows owner and operator paths | Normal use, automatic updates, travel, and first-response recovery | Windows 11 Pro update policy, firmware licensing, AD join/cache tests, local rescue, boot repair, storage fallback, diagnostic capture, reimage decision, and decommission | partial |
| 9 | Arch owner and operator paths | Normal use, automatic updates, travel, and first-response recovery | Gated automatic update design, Arch News handling, health checks, rollback, AD/SSSD cache behavior, UID/time verification, boot repair, package-state evidence, and reimage decision | gap |
| 10 | User storage | Explain local-first homes and optional NAS behavior | Primary and backup NAS SMB/NFS tradeoffs, per-user share automation, UID/GID and timestamp tests, offline/nonblocking mounts, permissions, backup semantics, restore proof, and failure injection | gap |
| 11 | Recovery library | One symptom-led page for family members away from home | Controller loss, directory/DNS loss, network loss, expired credentials, failed update, broken boot, damaged disk, lost laptop, forgotten password, restore verification, and escalation bundles | gap |
| 12 | Maintenance library | A calendar and “is action required?” checklist | Daily/weekly/monthly/quarterly tasks, Windows and Arch updates, controller updates, media refresh, certificate/key expiry, capacity, logs, backup/restore drills, UniFi exports, dependency refresh, and release/version records | gap |
| 13 | Migration and VM-later register | Explain which changes do and do not require rebuilding workstations | Stable names/contracts, controller replacement, host-to-VM candidates, service-by-service cutover, parallel validation, rollback, and retirement of bootstrap-dc | partial |
| 14 | Private-overlay bootstrap | Walk another household through answering questions safely | Generate their equivalent private repository, validate answers, protect secrets, connect it to public Telos, update/rebase safely, back up privately, and prove no private material is published | partial |
| 15 | Decommission and incident response | Explain lost, retired, transferred, or compromised devices | Disable access, cached-logon limitations, credential rotation, share removal, inventory evidence, data disposition, firmware reset, and post-incident verification | gap |
| 16 | Cross-document acceptance | A release note stating what is usable now | Fresh-clone rehearsal, link check, command transcript, screenshots/diagrams review, privacy scan, accessibility pass, failure-path drill, and publication check | queued |

## Page pattern

Detailed operator pages should use this order:

1. Outcome and boundary.
2. Preconditions and recorded starting measurements.
3. Diagram of the affected components.
4. One change at a time.
5. “What this does” callout.
6. Immediate observation and expected result.
7. Intermediate question: proceed, correct, or roll back?
8. Failure branch and safe stop.
9. End-to-end verification from each affected client.
10. Recovery rehearsal.
11. Maintenance and update policy.
12. Evidence to retain, with secrets excluded.

Write-on records and learning/reflection material belong after the
instructional and reference content, not between required steps.

## Immediate gaps exposed by the first installation

The Bootstrap Controller guide must incorporate the actual acceptance findings:

- QEMU virtio serials have a 20-character limit.
- The Arch boot entry needs an explicit serial-console parameter in this test
  path.
- `pacstrap -U` option ordering must be tested against the current Arch ISO.
- The live keyring must be initialized and populated before offline package
  installation.
- Shutdown and QEMU-console escape behavior must be documented for both plain
  terminals and tmux.
- Successful acceptance includes locked root, working `local-rescue` sudo,
  UEFI/systemd-boot with the LTS entry, the expected root filesystem, enabled
  recovery services, and zero failed units.

These findings require implementation tests as well as prose; documentation
must not present a manual workaround as the finished path.
