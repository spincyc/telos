# Homelab documentation pass

Document version: `20261002.001`

Status: local documentation pass complete on 2026-10-02, including the accepted
gate-12 repeat; live evidence remains governed by the state ledger. The first two guides shipped
2026-08-12 (`2680c23`):
[`docs/factory-guide.md`](docs/factory-guide.md) (human) and
[`docs/operator-runbook.md`](docs/operator-runbook.md) (operator). Both are
committed and present on public `origin/main`. Both are now wired into
`site/site.json` and the Homelab navigation. Wiring is local implementation;
deployment still requires the exact-commit publication checks. They are
credited against pass-sequence row 7 below. The topic map distinguishes
usable local instructions from physical-network, hardware, and service work
that has not been accepted; a topic's documentation status is not a live PASS.

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

Command, privacy and published-link checks exist: `tools/doc-make-target-drift`
runs in `make check` and `make homelab-check` and rejects a documented Make
target the Makefile does not define, and `scripts/site check` rejects leaked
instance data (real addresses, MACs, disk serials, and RFC 1918 CIDRs judged by
prefix length as well as network address). Since 2026-09-30 that includes the
two guides under `docs/`; site wiring on 2026-10-01 also places them under the
strict published-prose scan. A document may declare names it does
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
| 1 | Documentation map | [Site index](../site/pages/homelab/index.md): task-led reading order, current HTML guides and historical PDFs | This map owns coverage; the state ledger owns verdicts; the Make contract owns interfaces. Checks and source versions are described below. | current local map and navigation |
| 2 | Controller network gate | [Network simulation](../site/pages/homelab/controller-network-simulation.md), human view | [Network gate](../site/pages/homelab/controller-network-gate.md): fields, observations, packet capture and rollback; [readiness plan](EXTERNAL-INTEGRATION-READINESS.md) owns the read-only review before any attachment | documented; physical execution separately authorized |
| 3 | Bootstrap Controller | [Factory guide](docs/factory-guide.md), two controller modes | [Runbook](docs/operator-runbook.md), Stages 0–1 and persistent instance; [media intake](media/FRESH-CLONE.md), [offline seed](seed/README.md), [console fallback](vm/README.md). Fresh-clone seed/create/install, password custody, rebuild and native directory backup are explicit. | local workflow documented; another-household proof and kept-disk backup remain absent |
| 4 | Network design | [Factory page](../site/pages/homelab/workstation-factory.md), Stage 6 | Field-by-field restricted attachment and rollback exist in the network gate; the [network design source](../src/homelab/design/network/main.tex) contains zone/port/Wi-Fi/cutover worksheets | existing coverage, not an empty gap; whole-house deployment and a full HTML design remain later |
| 5 | Directory and DNS | [Owner guide](../site/pages/homelab/workstation-owner-guide.md), Controller absence and cached login | [Runbook](docs/operator-runbook.md), persistent identity, accounts and directory recovery; [role reference](ansible/roles/domain_controller/README.md), [backup contract](FACTORY-MAKE-TARGETS.md). Restored-client proof is distinct from a directory-only restore. | local procedures documented; live DR verdict belongs to ledger |
| 6 | PXE and install media | [Factory guide](docs/factory-guide.md) and factory page, Stages 5–6 | [Media intake](media/FRESH-CLONE.md), runbook Stages 0–3, [staged netboot recipe](archiso/README.md), release rollback, [Windows flow](pxe/windows/FLOW.md). Samba repair acquisition, Windows source staging and online/offline order are explicit. | local workflow documented; fresh netboot rebuild and hardware boot not proven by this doc pass |
| 7 | Workstation factory | [Factory guide](docs/factory-guide.md), shipped 2026-08-12 | [Operator runbook](docs/operator-runbook.md): commands, evidence, gate table, failures and cleanup; [durable flow](DURABLE-WORKSTATION-FLOW.md) owns the kept-workstation sequence | documented; gate 12 accepted with only the UniFi waiver; keeper credentials and publication remain separate |
| 8 | Windows owner and operator paths | Owner guide: normal use, updates, travel, rescue and evidence | Runbook Stages 2/4/5 and [identity procedure](../site/pages/homelab/workstation-identity-procedures.md); firmware activation/live Microsoft Update remain outside local acceptance | local identity/install covered; physical repair and disposal remain later |
| 9 | Arch owner and operator paths | Owner guide and [maintenance library](../site/pages/homelab/maintenance-library.md) | Runbook Stages 3/4/5, generated SSSD contract, UID/time/cache verification; maintenance covers news review, package evidence and stop conditions | existing coverage; live boot break/repair deferred by ADR 0080 |
| 10 | User storage | Owner guide: local homes and three optional-storage outcomes | Runbook gate 9 and maintenance/recovery checks; [operator source](../src/homelab/manual/workstation-factory/optional-services.tex) has SMB mapping and three-state drill | local failure checks proven; NAS deployment, per-user automation, backup/restore and NFS remain unimplemented |
| 11 | Recovery library | [Recovery library](../site/pages/homelab/recovery-library.md), including credentials/loss/disk symptoms | Runbook recovery, native directory backup/restore reference, 40/40 restored-client proof without rejoin, secret-free evidence and explicit owner/physical limits | local DR proven; three gate-11 scenarios deferred |
| 12 | Maintenance library | [Maintenance library](../site/pages/homelab/maintenance-library.md), calendar and escalation | Runbook maintenance: status, versions, capacity, backups, update evidence and restore drills. Real network exports/certificate deployment wait for those services. | local calendar documented; future service tasks labelled |
| 13 | Migration and VM-later register | Factory page, Stage 12 | [ADR 0068](decisions/0068-stable-service-names-and-dc-migration.md), network design placement register, ADR 0081 restore-name contract | design exists; multi-DC replication/cutover/demotion not implemented or proven |
| 14 | Private-overlay bootstrap | Factory page, Stage 1 | Interactive onboard and preflight, [overlay reference](instance-example/README.md), runbook private-backup/restore checks | local setup documented; another-household fresh-clone rehearsal remains an acceptance task |
| 15 | Decommission and incident response | Owner guide and recovery library: stop, protect data, report loss | Runbook retirement: named VM destroy, custody cleanup, directory-account follow-up, private inventory and physical sanitization boundary | local retirement documented; physical wipe/firmware reset/remote revocation unimplemented |
| 16 | Cross-document acceptance | Site index and the runbook's supported-state table | Command, privacy, source-link and rendered-site checks passed; Chromium reviewed both guides and recovery at 390px and 1440px, including fragments, keyboard links and code/table scrolling. | local pass complete 2026-10-02; fresh-household live execution and deployment remain unproven |

## Corrections and remaining acceptance

Closed 2026-08-17, kept only as history: the two corrections previously listed
here — the gate-9 "no storage check" misdescription and the gate table pinned to
ledger `20260812.001` — were both applied to `docs/operator-runbook.md`. Do not
re-open them.

Reconciled 2026-10-01/02, in the documents this pass owns:

- **Site navigation wiring is implemented.** Both guides are registered in
  `site/site.json`; source-relative repository links resolve to published pages
  or their public source. The runbook uses the Makefile's synthetic defaults
  without address literals, and both guides pass the strict prose privacy scan.
  Local link/privacy checks are not a claim of deployment.
- **~~The canonical-Controller-image blocker must be retired when the
  reinstall is driven.~~ Done 2026-09-24** (`1e56a43`): the owner installed the
  image through `make homelab-bootstrap-vm-install`, and the runbook section,
  the `HANDOFF.md` banner, the state ledger's first blocker and the per-site
  "Blocked today" pointers were retired together.
- **~~The persistent-instance documentation carries a NOT RUN marker.~~
  Replaced 2026-09-25** (`b2e8fed`): the serial-console converge and durable
  accounts ran live on a throwaway instance. The durable flow passed
  2026-09-30. Native backup and same-instance restore under a new DC name
  passed on 2026-10-01. After Samba SRV repair, existing SRV-first client
  keep-verify passed 40/40 without rejoin or changes to its kept disk,
  firmware variables or marker (`run-20261001T235410Z-588718-de077620`).
  Owner keeper and physical recovery remain unperformed; directory recovery
  does not back up workstation files.
- **Gate 12 accepted 2026-10-02, PASS-WITH-WAIVER.** Final receipt
  `homelab/var/factory/repeat/recovered-repeat-3-receipt.json` records one
  reverified accepted cycle plus one fresh six-phase cycle at identical pins,
  equivalent with zero retries. Each cycle has 15 PASS checks, only ADR 0080's
  UniFi waiver and a gate-4 PASS. The new local network counters are all zero;
  independent comparison agrees with no divergence. No route-policy extension
  was needed or applied. Historical checker/IKE, listener and route failures
  remain retained, and intermittent firmware stalls are not claimed fixed.
  Gate 11 remains separately closed for phase one at `partial`, with its
  three agreed deferrals; the repeat's narrower lifecycle run does not replace
  that evidence.
- **Online prerequisites and fresh-clone order are explicit.** The runbook
  describes the dependency target's host package transaction, Samba repair
  acquisition/sealing, Windows source staging, and seed/netboot builds before
  the offline boundary. The netboot recipe stages the profile first and uses
  its completed `out/` as `CONTROLLER_SOURCE`; no public authorized key means
  console-only access. Fresh canonical VM creation is distinct from a
  lost-password rebuild. These source-checked recipes do not claim a newly
  executed netboot build or a fresh-household installation.
- **The human guide explains both controller modes.** The runbook now covers
  kept-instance maintenance, native directory backups, private-overlay backup,
  incident triage and named VM retirement, with explicit boundaries for missing
  physical sanitization, NAS backups and disconnected revocation.
- **Public support descriptions match implemented local paths.** The recovery
  library no longer says gates 6–10 are unaccepted or that restoring a directory
  means provisioning a fresh domain and rejoining. The identity page points to
  generated SSSD configuration instead of an obsolete copy with local ID
  mapping. The site index separates current local guides from historical PDFs.
- **Closed 2026-09-30, from that day's cold review:** the runbook's selected
  release-set digest (it quoted `.001`'s), its "proven live" gate-11 date and
  release rollback, the open-listed SSSD `offline_timeout` (fixed by
  `2f86a21`), the `artifact_scan` wording (`b84bc86`), a missing
  `FACTORY_DURATION` warning, WinPE's disk selection (ADR 0078), the stale
  controller-seed and Arch inputs, the handoff banner, the NOT RUN durable
  accounts in the ledger and handoff, and the human guide's persistent mode.

## Local acceptance record, 2026-10-02

All sixteen topics above have a human path and an operator reference or an
explicit unsupported boundary. Final command drift passed with 113 defined
and 83 documented targets, no stale targets. Source link/privacy checks and
`make verify-site` passed for 26 pages and 148 publications; `make site`
produced 181 files. The registry and diff hygiene checks passed.

Chromium reviewed the factory guide, operator runbook and recovery library
at 390px and 1440px. Document width matched the content viewport in all six
cases; code and tables retained local scrolling. All local links and fragments
resolved after correcting the repeatability anchor. Keyboard Tab reached all
16, 43 and 11 links respectively, with visible focus outlines. Private review
records are retained with the strict-repeat recovery checkpoint. This is a
local render review, not a deployment claim or a full accessibility audit.

The earlier isolated source-copy check/build/verify required no private
overlay or lab media. The corrected seed/netboot recipe was checked against
source contracts, not executed as a new image build. Another-household live
installation, owner keeper passwords, physical integration and deployment
remain separate acceptance boundaries; completing this documentation pass
does not claim those outcomes.

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

## Findings retained from the first installation

These are maintained implementation constraints, not fresh installation
blockers. Runbook Stage 0.5, the seed/VM guides and the installer tests cover:

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

The canonical Controller installer passed live 2026-09-24. Keep its regression
tests and the manual console fallback aligned; documentation must not present
a manual workaround as the finished path.
