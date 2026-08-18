# Homelab documentation pass

Document version: `20260817.001`

Status: in progress — the first two guides shipped 2026-08-12 (`2680c23`):
[`docs/factory-guide.md`](docs/factory-guide.md) (human) and
[`docs/operator-runbook.md`](docs/operator-runbook.md) (operator). Both are
committed and present on public `origin/main`, but neither is wired into the
generated site yet (`site/site.json` and `scripts/site` reference neither), so
"unpublished" for these two means "not in the site navigation", not "private".
They are credited against pass-sequence row 7 below.

The current implementation work continues without waiting for this pass.
Homelab documentation is HTML/Markdown-first. No Homelab PDF is required at
this time, and a missing PDF must not block implementation, testing, or
publication.

The live implementation state, accepted decisions, local evidence, remaining
factory gates, and literal restart point are maintained in
[WORKSTATION-FACTORY-STATE.md](WORKSTATION-FACTORY-STATE.md). Update that
ledger before ending a work session so continuation does not depend on chat
history.

Current cross-platform design contracts include
[guest progress reporting](GUEST-PROGRESS-REPORTING.md), which records the
prior art, transport decision, trust boundary, deadlines, and failure
semantics for affirmative guest-to-harness progress signals.

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

Two of those four checks now exist and run in `make check` and
`make homelab-check`: `tools/doc-make-target-drift` rejects a documented Make
target the Makefile does not define, and `scripts/site check` rejects leaked
instance data (real addresses, MACs, disk serials, and RFC 1918 CIDRs judged by
prefix length as well as network address). A document may declare names it does
not claim to implement — a `reserved`/`not implemented` paragraph, or a
`<!-- doc-make-target-drift: proposed -->` marker covering a section — so an
honest interface proposal stays green while a copy-paste command that would
fail does not. Broken links are covered by `scripts/site check` for published
sources only; unsupported claims are still checked by hand.

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
| 7 | Workstation factory | **shipped 2026-08-12: [`docs/factory-guide.md`](docs/factory-guide.md)** | **shipped 2026-08-12: [`docs/operator-runbook.md`](docs/operator-runbook.md)** — real Make targets in lifecycle order paired with the proven evidence, pass/fail gate table, troubleshooting, rollback/rebuild/verify; reserved aggregate names flagged. Remaining: site navigation wiring (the leak scanner rejects the lab address) and the corrections listed below | drafted; site wiring outstanding |
| 8 | Windows owner and operator paths | Normal use, automatic updates, travel, and first-response recovery | Windows 11 Pro update policy, firmware licensing, AD join/cache tests, local rescue, boot repair, storage fallback, diagnostic capture, reimage decision, and decommission | partial |
| 9 | Arch owner and operator paths | Normal use, automatic updates, travel, and first-response recovery | Gated automatic update design, Arch News handling, health checks, rollback, AD/SSSD cache behavior, UID/time verification, boot repair, package-state evidence, and reimage decision | gap |
| 10 | User storage | Explain local-first homes and optional NAS behavior | Primary and backup NAS SMB/NFS tradeoffs, per-user share automation, UID/GID and timestamp tests, offline/nonblocking mounts, permissions, backup semantics, restore proof, and failure injection | gap |
| 11 | Recovery library | One symptom-led page for family members away from home | Controller loss, directory/DNS loss, network loss, expired credentials, failed update, broken boot, damaged disk, lost laptop, forgotten password, restore verification, and escalation bundles | drafted |
| 12 | Maintenance library | A calendar and “is action required?” checklist | Daily/weekly/monthly/quarterly tasks, Windows and Arch updates, controller updates, media refresh, certificate/key expiry, capacity, logs, backup/restore drills, UniFi exports, dependency refresh, and release/version records | drafted |
| 13 | Migration and VM-later register | Explain which changes do and do not require rebuilding workstations | Stable names/contracts, controller replacement, host-to-VM candidates, service-by-service cutover, parallel validation, rollback, and retirement of bootstrap-dc | partial |
| 14 | Private-overlay bootstrap | Walk another household through answering questions safely | Generate their equivalent private repository, validate answers, protect secrets, connect it to public Telos, update/rebase safely, back up privately, and prove no private material is published | partial |
| 15 | Decommission and incident response | Explain lost, retired, transferred, or compromised devices | Disable access, cached-logon limitations, credential rotation, share removal, inventory evidence, data disposition, firmware reset, and post-incident verification | gap |
| 16 | Cross-document acceptance | A release note stating what is usable now | Fresh-clone rehearsal, link check, command transcript, screenshots/diagrams review, privacy scan, accessibility pass, failure-path drill, and publication check | queued |

## Known corrections outstanding in the shipped guides

Closed 2026-08-17, kept only as history: the two corrections previously listed
here — the gate-9 "no storage check" misdescription and the gate table pinned to
ledger `20260812.001` — were both applied to `docs/operator-runbook.md`. Do not
re-open them.

Outstanding as of 2026-08-17, in the documents this pass owns:

- **Site navigation wiring is still deferred.** Neither `docs/factory-guide.md`
  nor `docs/operator-runbook.md` is referenced by `site/site.json` or
  `scripts/site`, because both carry the lab address the leak scanner rejects.
  This is the one item keeping gate 13 in progress; the recipe is documented and
  the decision is open.
- **The canonical-Controller-image blocker must be retired when the reinstall is
  driven.** It is currently recorded in three places — the runbook's "Blocker:
  the canonical Controller image is absent", the banner at the top of
  `HANDOFF.md`, and the first bullet of the state ledger's blockers — plus the
  short "Blocked today" pointers at each live-target instruction site. All of
  them come out together, and only after a real reinstall.
- **The persistent-instance documentation carries a NOT RUN marker.** The
  runbook's "The persistent directory instance" section and the
  "Persistent controller instance (not a gate)" section of
  `FACTORY-MAKE-TARGETS.md` describe an implemented, unit-tested, never-executed
  surface. Re-verify both against a real run before removing the marker; nothing
  in them may be promoted to the present indicative until then.
- **Gate 12's verdict needs re-checking when the repeat driver lands.** The
  runbook and the ledger now say gate 12 is blocked on the absent image and on
  the missing aggregate `homelab-factory-repeat` driver — a reserved name, not
  implemented — and not on any gate. Both statements move together.
- **`docs/factory-guide.md` covers the persistent instance only by pointer.**
  The human guide still describes one mode (disposable controller) with a clause
  pointing at the runbook. If the persistent path becomes a normal operator
  workflow, the guide needs its own short human-level explanation.

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
