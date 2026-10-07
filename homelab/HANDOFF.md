# Workstation-factory handoff (for a fresh agent)

**Last updated:** 2026-10-02 16:58 UTC (gate 12 accepted at
PASS-WITH-WAIVER from `011e678`, equivalent with zero retries; TASK-6 DONE;
earlier failures retained; TASK-7 local documentation checks passed;
Windows VBS, merged gate-4 and restored-client DR PASS retained;
previous passes
2026-09-30, 2026-09-25, 2026-09-24 and 2026-08-17).
**Read this first, then `homelab/WORKSTATION-FACTORY-STATE.md`** (the canonical
per-gate state) and `homelab/FACTORY-MAKE-TARGETS.md` (the Make contract).

## Start here (2026-10-02 16:58 UTC)

**Goal on the critical path:** a *keepable* dual-boot workstation whose
accounts live in a persistent directory (aiq TASK-21), then the physical path
(gate 14, owner go-ahead only).

| Piece | State |
|---|---|
| Canonical Controller image | **Installed** 2026-09-24 (first live run of `homelab-bootstrap-vm-install`) |
| Gates 5–8 with the owner's real names | **PASS** 2026-09-24 (gate 6 judge 24 checks, gate 8 21) — §7 item 5 |
| Private roster (`homelab/instance/identity/principals.json`, gitignored) | All three directory roles named and UID-pinned, plus one `additional_standard_users` entry. **Names are instance data: never write them into a tracked file or a commit message** (ADR 0046) |
| Persistent directory, throwaway instance `rehearsal` | **Converged** under the permanent realm and holding the **four durable accounts** (temporary passwords, change at first logon) — 2026-09-25, owner-run; probe PASS and password policy recorded 2026-09-30. Its workstation `rehearsal-ws1` stays at stage `arch-install`: the owner-run arch-join stopped on a mistyped temporary password (reset: `homelab-factory-persistent-account-password`) |
| Durable workstation flow (TASK-28) | **DONE; PASS live end to end 2026-09-30**, unattended under agent custody (TASK-40, `fa8ec58`/`14b925e`) on throwaway instance `rehearsal-auto` and kept workstation `rehearsal-auto-ws1`: create, converge, accounts, probe, adopt, durable Arch install and join, durable Windows join, keep-verify across a Controller cold relaunch. Run ids: `homelab/DURABLE-WORKSTATION-FLOW.md`, "Live record" — §7 item 6 |
| One-command mint (TASK-45, TASK-46) | **DONE 2026-10-07.** `make homelab-factory-mint` with one sitting of password entry; UAT PASS on `uat2`/`uat2-ws` (made-up users, keep-verify 41/41, every standard account logged in on Arch). Gate 5 now takes about 10 minutes (switch `TCP_NODELAY`, `b9024cc`). Details: `FACTORY-MAKE-TARGETS.md`, "One-command mint". |
| Keeper directory instance (TASK-21) | **Awaiting the owner's one sitting** (2026-10-07): `make homelab-factory-mint PERSISTENT_DC=keeper WORKSTATION=keeper-ws1 ARCH_HOSTNAME=keeper-ws1 APPLY=1` at the owner's terminal; the instance `keeper` exists (seeded 2026-10-02, never converged) and is reused. Earlier text kept: **Blocked on owner-terminal passwords**, still absent. The DR prerequisite is satisfied; its convergence dry run is checked and creation awaits owner-terminal credentials and a free lab lane. The owner availability question remains unanswered. Owner custody, short password policy (minimum 4, complexity off, minimum age 0), temporary Domain Admin `tj-` joins and SRV-first discovery remain the accepted choices. Exact owner sequence: `FACTORY-MAKE-TARGETS.md`, "Owner-terminal keeper sequence (TASK-21)"; §7 item 9. |
| Backup/restore and DR naming (TASK-41, TASK-42) | **DONE; restored-client proof PASS, 40/40, 2026-10-01.** After native backup and same-instance restore as DC `dr-2610012255`, repair `bdebb4f` and reconvergence passed four strict DNS probes. Existing SRV-first `rehearsal-auto-ws2` keep-verify `run-20261001T235410Z-588718-de077620` passed both OSes without a rejoin. Kept disk, variables and marker unchanged; no fold/ledger entry; clean teardown. The earlier failed attempt and the passing run's bounded Windows cold-boot retry remain recorded; firmware is not claimed fixed. Restored instance and native backup retained. Exact evidence: `FACTORY-MAKE-TARGETS.md`, backing up and restoring a directory; §7 item 8. |
| Windows VBS and merged gate 4 (TASK-43) | **DONE.** Windows run `windows-installs/run-20261001T235652Z-a782e2f67fac` (`8eb69a9`) finished 2026-10-02 01:17 UTC (~70 min), exit 0, `observed` / `native-windows-clean-shutdown`, one firmware PXE boot, canonical disk/firmware unchanged, zero external connections. Prepared before resealing, it used release `20260727.005`; publication retained unconsumed for the keeper. Combined with Arch `run-20261001T193550Z-e5108779aad1`, the complete capture passed all four gate-4 checks: 34 DHCP server frames all gateway, 268 approved flows; receipt `homelab/var/factory/authority-audits/20261002-winpe-vbs-merged.json`. |
| Completed original repeat | `homelab/var/factory/repeat/20261002T011915Z-907070-repeat` finished about 2026-10-02 05:26 UTC from `93eb6b6`. Final `homelab/var/factory/repeat/recovery-repeat-receipt.json`: **FAIL**, `equivalent: false`, zero retries. Iteration 1 failed 15 pass / one listener-change failure; discarded snapshots prevent attribution. Iteration 2 is **PASS-WITH-WAIVER**, 15 pass / one ADR 0080 UniFi waiver, zero fail/not-run, all six local network counters zero. Both gate-4 audits passed. Originals preserved; SHA-256 inventory `/tmp/telos-recovery-root/original-repeat-before-recovery.sha256`. |
| Stopped recovery repeat | Reuse support `7e4c72c` preserves acceptance, source/pin verification and private snapshots. Recovery `homelab/var/factory/repeat/20261002T053117Z-1175062-repeat` **STOPPED about 06:39 UTC, exit 2; no final comparison receipt.** Windows `run-20261002T053119Z-97daa1c63993` failed `pxe-loop` after about 67 minutes (OVMF Windows Boot Manager `Not Found`, second `wimboot`); retry `run-20261002T063837Z-3c2cd155d481` failed immediately when the process audit saw `python3` immediately after launch. Former supervisor `1174594` / driver `1175062` are stopped evidence only. Originals' SHA inventory still matches. Read-only inspection found the loader and matching ESP/firmware GUID; firmware fault unresolved. Only those failed bundles' `publication.iso` files were retired, preserving disks/variables/results/logs; private retirement receipt records 23,144,542,208 bytes reclaimed, 58 GiB free. Exact evidence: [the repeat driver](FACTORY-MAKE-TARGETS.md#the-repeat-driver). |
| Completed second recovery | Process-audit fix committed `c45c0dc`; 4,149 tests, five skips, zero failures/errors/lab touches/QEMU attempts; independent 35 tests, no blockers. Recovery `homelab/var/factory/repeat/20261002T114212Z-1294100-repeat` ran 11:42:12–13:47:15 UTC, reusing the accepted original iteration 2 and pins. Both cycles completed all six functional phases. Final receipt **FAIL**, `equivalent: false`, zero retries: fresh cycle 15 pass / one fail solely on `route=4`; the other five local counters are zero (forwarding by privilege), UniFi unproven, both gate-4 audits PASS. Raw diagnostics retain one automatic IPv6 router-advertisement ECMP next-hop replacement, counted in both all-table views as four old/new entries. Former supervisor `1293625` / driver `1294100` stopped, exit 2. Exact final receipt and diagnostics: [the repeat driver](FACTORY-MAKE-TARGETS.md#the-repeat-driver). |
| Accepted third strict recovery | `homelab/var/factory/repeat/20261002T143757Z-1346697-repeat` from `011e678` finished 16:41:30 UTC, supervisor exit 0; former supervisor `1346230` / driver `1346697` stopped and no QEMU remains. Final `recovered-repeat-3-receipt.json`: **PASS-WITH-WAIVER**, equivalent, zero retries. One unchanged accepted original iteration 2 plus one fresh full cycle at identical pins; both 15 PASS / only ADR 0080 UniFi waiver, both gate-4 audits 4/4 PASS, fresh six local counters zero. Independent comparison agrees with zero divergences. Gate 12 is closed for phase one; TASK-6 DONE. No route-policy exception was needed or approved. Exact final receipt, fingerprints and durable diagnostics: [the repeat driver](FACTORY-MAKE-TARGETS.md#the-repeat-driver). |
| Committed 2026-09-30 | ADR 0079 (`0b9f102`, replacement-Controller PXE mint dropped); media seal tolerates tool-version drift and the cache is resealed to Arch 2026.08.01 (`110dfb5`; release sets `20260727.00N` stay bound to the old seal); hermetic seed tests (`9c3ca80`, TASK-30); PXE services enabled across reboot (`dfbcce7`, unit-tested only); ADR 0080 (`19c2c64`, gate 11 closes at `partial`, gate 12 waives `host_network_changes`); gate-14 readiness plan (`b719e7a`); drift-tool wildcard (`4d9f0ac`); the durable-flow design (`5f9a790`, `881c45a`); the gate-12 driver hands arch-install the Windows disk and scans retained evidence (`b84bc86`); TASK-28 steps 1-9 (`715147f`..`5f5b322`, `a54e7c9`), recorded password policy (`d3f8567`), one-account password reset (`bcf8d16`), agent credential custody (`fa8ec58`, `14b925e`) |
| Committed 2026-09-30/10-01 (`4d35cbe..668b524`) | Durable flow's live record (`2b403ab`); backup and restore (`10dd1af`..`d6d1d91`, ADR 0081); SRV-first DC naming (`0a9cd99`, `a2775db`, `3d214e5`); dual-boot login wait derived from the Arch boot gates (`f8f0443`); gate 11's controller-state default (`3fb969e`) and SSSD priming before the outage (`668b524`) |
| Next owner actions | (a) the keeper's terminal credential steps (TASK-21), unblocked by DR and still awaiting the owner; verify the lab is idle before each live step; (b) re-converge `rehearsal` with `RECONVERGE=1` so the enabled PXE units can be checked across a reboot; (c) the read-only UniFi review items (TASK-37) — access or screenshots for the eleven stage-1 items in `homelab/EXTERNAL-INTEGRATION-READINESS.md` |
| Gates 11/12 live runs (TASK-6) | Gate 11 **closed for phase one at `partial`** (independent live proof: five pass, exactly three ADR 0080 deferrals). The accepted original repeat's second iteration completed Windows identity 24 checks, Arch identity 21, dual-boot eight observed checks (Windows login not driven there), and lifecycle recovery three pass / five deferred; the latter does not replace gate 11's independent proof. The whole original repeat remains FAIL. Historical repeat `20261001T153726Z-2517176-repeat` also remains FAILED on two checker defects and gate-4 IKE traffic. Checker fixes: `c07f701`, `41b6bc8`; live-proven VBS IKE suppression: `8eb69a9`; OVMF cache fix: `c8e37d0`, without a firmware-fixed claim; mandatory per-iteration gate 4: `8eb5b6d`. `93eb6b6` closes the A→B→A false pass by pinning actual publication manifest/seal and verifying copied leaf bytes (`tools/factory-repeat-input-binding`). Its pre-run audit passed 4,115 tests, five skips, zero failures/errors or lab touches, two advisory argv mentions; `tmt check` PASS. |

**Owner-only steps** (they read passwords at the owner's terminal; hand over
the exact command, never run them yourself): `homelab-bootstrap-vm-install`,
`homelab-factory-persistent-converge APPLY=1`,
`homelab-factory-persistent-accounts APPLY=1`, and the durable flow's live
steps, the last three under owner custody only (the keeper): an agent-custody
throwaway instance (`CUSTODY=agent THROWAWAY=1`) runs them unattended.
Everything else in the loopback factory is agent-runnable under the standing
directive in §1. Gate 14 is **not authorized**; only its read-only
UniFi review is.

**Rules learned the hard way this pass** (details in §5):

- After any lab-state change, run the unit suite with `qemu-system-x86_64`
  shimmed to refuse and log; zero calls proves nothing booted. A test once
  launched a real Windows install (`272d693`).
- No test may read `build/`, `homelab/var/`, or `homelab/instance/`: the owner's
  overlay now pins UIDs and names, and three tests silently depended on its
  absence (`4e19ffb`, `cdc316c`); the four that read the seed ISO were fixed
  2026-09-30 (`9c3ca80`, TASK-30).
- A serial-console capture of a variable-length value must end in a line-end
  lookahead `(?=[\r\n])`. End-of-buffer matches a split read: three live
  failures (`06f01af`, `f7bbf13`, `05eec6e`). Symptom: "X vs Y" where X is a
  prefix of Y.
- The in-guest principal program closes stderr on purpose; failures now print a
  credential-free `__TELOS_PRINCIPAL_FAILURE=<category>` line (`efedf50`).

> ## RESOLVED 2026-09-24 — the canonical Controller image is installed
>
> **The blocker this banner carried since 2026-08-14 is closed.** The owner ran
>
> ```sh
> make homelab-bootstrap-vm-install APPLY=1 CONFIRM='<the erasure phrase>' \
>     ISO=homelab/var/media/arch/archlinux-x86_64.iso \
>     SEED_ISO=homelab/var/seed/telos-controller-seed.iso
> ```
>
> on 2026-09-24 (receipt `installed_utc` `2026-09-25T01:30:06Z`). It was the
> **first live run** of that target (`7b29624`) and it succeeded first time: all
> 19 console events from the archiso login through `console-password-updated`,
> `installation-complete` and `poweroff-observed`; QEMU exit 0;
> `build/homelab/vm/bootstrap-dc/bootstrap-dc.qcow2` now holds a GPT with two
> partitions (one ESP), 2,539,716,608 bytes allocated, SHA-256
> `ae7b6787c3741c388d7c44bddf859fefebc669d44aaf9a07f2edfb50ba114a3b`; receipt
> `build/homelab/vm/bootstrap-dc/install-receipt.json`. Since then
> `make homelab-bootstrap-vm-status` reports `ready`, the
> `make homelab-factory-repeat` dry run no longer refuses, and
> `make homelab-factory-persistent-converge-plan PERSISTENT_DC=<name>` no longer
> reports NOT READY. The gate runners, the persistent targets,
> `homelab-factory-repeat APPLY=1` and `homelab-sim-auto-run` no longer run
> against an empty disk. **Corrected 2026-09-30:** this said "None has been
> deliberately run since"; gates 5–8 ran with real names 2026-09-24/25 (§7 item
> 5) and the persistent converge and durable accounts ran 2026-09-25 on
> `rehearsal`. The accidental unit-suite launch is recorded in §5.
>
> **Keep the new `local-rescue` password safe — losing it costs the whole image
> again.** It is the only credential that can ever open the image: root is
> locked, there is no authorized key, no init shell, and SSH password auth is
> off. A future reinstall goes through the same target, now proven once; the
> manual console recipe is the fallback and already exists verbatim — do not
> re-derive it: `homelab/docs/operator-runbook.md`, section "Keep the
> `local-rescue` password", and `homelab/vm/README.md`, section "Interactive
> offline installation". Rebuilding the image invalidates no retained gate
> receipt.
>
> History, kept so it is not re-derived: the image was destroyed 2026-08-14 with
> explicit owner authorization after its `local-rescue` console password was
> lost, and until 2026-09-24 `bootstrap-dc.qcow2` was a 197,888-byte empty disk
> on which no live factory target could run.

---

## 1. Where the factory is right now

Goal: mint an isolated dual-boot Windows + Arch workstation and prove all
local acceptance gates, loopback-only, with no plaintext secrets in retained
evidence. Unattended installation is confined to disposable QEMU disks under
ADR 0078; physical gate 14 needs separate owner authorization. Gates 1–14 tracked in `WORKSTATION-FACTORY-STATE.md`.

| Gate | What | Status |
|---|---|---|
| 1 Media intake | — | **pass** |
| 2 Immutable PXE releases | — | **pass** |
| 3 Controller convergence | — | **pass** |
| 4 PXE authority boundary | — | **PASS, four checks, 2026-10-02 (TASK-43 DONE).** Complete Windows VBS (`8eb69a9`) plus Arch capture; receipt `homelab/var/factory/authority-audits/20261002-winpe-vbs-merged.json`. Historical repeat IKE failure retained; each new iteration still needs its own audit. |
| 5 Windows-first install | — | **PASS** (bundle `homelab/var/factory/windows-installs/run-20260810T145421Z-5b457e50e20b`) |
| 6 Windows join and login | domain identity + recovery | **PASS — 24/24 contracted checks, proven 2026-08-13** (one deferral: `disable-reenable`; see §2) |
| 7 Arch-second install | — | **pass** (bundle `arch-installs/run-20260811T141601Z-6941005247e8`) |
| 8 Arch join and login | SSSD identity lifecycle | **PASS — 21/21, proven 2026-08-14** (see §3) |
| 9 Optional storage failure | rides gates 6 and 8, no target of its own by design | **PASS** — the Windows half in the 2026-08-13 gate-6 evidence, the Arch half in the passing 2026-08-14 gate-8 run, whose `arch-storage-{attached,denied,absent-login}` checks are gate 9's three (see state doc) |
| 10 Dual-boot acceptance | 8 checks; Windows BOOT observed, login NOT driven | **PASS with two deferrals** (`homelab/var/factory/dualboot-acceptance/run-20260811T170510Z-a619bcb1f028`) — judge reports `deferred: ["windows-login-driven", "arch-authenticated-login"]` and `windows_login_proven: false` |
| 11 Lifecycle recovery | 3 loopback-provable, 5 need a live guest boot | **CLOSED for phase one at `partial`, 2026-10-01** (ADR 0080; never relabelled pass) — `homelab/var/factory/recovery/run-20261001T015135Z-gate11live/` (pass 5 / not_run 3 / fail 0): the 3 loopback scenarios plus `directory-dns-loss` and `controller-reconstruction` LIVE (`2c3cd56`); judge `partial`, deferred exactly `controller-restart`, `failed-install-recovery`, `broken-boot-repair`, whose primitives do not exist. Two defects fixed first: `3fb969e` (the `--controller-state` default never existed, so both hooks always deferred) and `668b524` (prime SSSD with an online login before the outage). The hooks need a PREPARED, unexecuted gate-8 bundle. Superseded: the 2026-08-14 run `run-20260814T120300Z-3b3169f9f15f` (3 pass / 5 not_run) was the only evidence |
| 12 Repeatability (twice-through) | — | **CLOSED FOR PHASE ONE, PASS-WITH-WAIVER.** Strict `20261002T143757Z-1346697-repeat` finished 16:41:30 UTC from `011e678`, equivalent with zero retries: accepted original cycle reused plus one fresh cycle at identical pins. Each cycle has 15 PASS / only ADR 0080 UniFi waiver and gate-4 4/4 PASS; independent comparison agrees. The fresh six local counters are zero. No route-policy exception was needed or approved. Original listener failure `011915`, stopped `053117` without a receipt, route failure `114212` and earlier `20261001T153726Z-2517176-repeat` retain their verdicts. No live repeat remains. |
| 13 Documentation | — | **Local pass complete, 2026-10-02 (TASK-7).** Accepted gate-12 evidence and all sixteen topics are reconciled. Command drift passes (113 defined / 83 documented); source privacy/links, site build and `make verify-site` pass (26 pages / 148 publications / 181 files). Final Chromium review of both guides and recovery at 390px/1440px passes width, fragments, keyboard focus and code/table scrolling checks. Keeper passwords, a fresh-household live installation and external integration remain separate. No push or deployment is claimed. |
| 14 External integration | physical / UniFi / ThinkPad | **HARD-BLOCKED on explicit owner authorization** — do not attempt. Plan: `homelab/EXTERNAL-INTEGRATION-READINESS.md`. Only its read-only UniFi review is authorized (TASK-37, awaiting owner-supplied access) |

Owner directive in force: *proceed through gates 6–13 without stopping for
per-gate approval; stop only at genuine blocks or gate 14.* Gate 14 needs a
separate explicit go-ahead.

### What landed after the gate-8 pass — implemented, unit-tested, NEVER RUN LIVE

Fourteen commits (`7ef4f23`, `7be4e46`, `e357736`, `6d98eed`, `8c759e0`,
`76cc439`, `11cff9a`, `b00a7cb`, `d3aed78`, `8ffa25c`, `087c888`, `eea7808`,
`d3d1d50`, `c84798a`) landed after the gate-8 evidence and **none of them has
executed live.** Treat every claim below as the designed contract, not observed
behaviour. (Superseded in part 2026-09-30: persistent convergence and the
serial-console accounts ran live 2026-09-25 on `rehearsal`; §7 item 5.)

- **A persistent Controller instance beside the disposable one** (`7ef4f23`
  through `8ffa25c`): six new targets,
  `homelab-factory-persistent-{plan,status,up,converge-plan,converge,destroy}`,
  each requiring `PERSISTENT_DC=<name>` and living under `PERSISTENT_DC_ROOT`
  (`build/homelab/vm/persistent-dc`), never under the canonical acceptance
  state. Bring-up seeds the instance *from* the canonical image and then boots
  it in place; convergence provisions AD in place over the `local-rescue`
  serial console, leaves the built-in Administrator enabled, and needs
  `RECONVERGE=1` to run a second time. Durable accounts are declared once in the
  gitignored overlay (`identity/principals.json`) and, for this simulated
  instance, staged over its serial console by
  `homelab-factory-persistent-accounts` (`73dbd2b`; eight persistent targets in
  all). Documented in `homelab/docs/operator-runbook.md`, "The persistent
  directory instance".
  **Correction 2026-08-17: the durable-account sub-path was NOT implemented in
  any usable sense** — see the durable-accounts entry in the next section.
  **Corrected 2026-09-24:** this said the accounts were provisioned by
  `make homelab-bootstrap-controller INVENTORY=<private inventory>`. That
  host-side Ansible path cannot reach a simulated persistent instance at all —
  its only NIC is a QEMU socket netdev to the userspace gateway, with no route
  to the host LAN — and remains the path for a Controller reachable over SSH,
  i.e. after network attachment. Neither path had run live then; the
  serial-console path ran 2026-09-25 (`b2e8fed`), the Ansible path has not.
- **`087c888` — the removed `community.general.yaml` callback** was still named
  in `ansible.cfg` and aborted **every** host-side Ansible run. Fixed; without
  this nothing host-side converges.
- **`eea7808`** gives the Controller a network identity that survives a reboot,
  so a persistent instance keeps its address across power cycles.
- **`d3d1d50`** lets a Controller image that has been simulated against be
  destroyed again (the destroy lock refused it).
- **`c84798a`** documents that a lost `local-rescue` console password costs the
  whole image — which is exactly what then happened; see the banner at the top
  of this file.

### Second batch, `1ec5506..f8d0348` (2026-08-17) — NEVER RUN LIVE, except three

Fourteen more commits landed the same day. **Nothing in this batch has run
against a live guest except `7b29624`'s install target (2026-09-24), the
repeat driver (gate 12, first live runs 2026-09-30/10-01) and `2c3cd56`'s two
gate-11 hooks (passed live 2026-10-01).** Read every other item as the
designed contract.

- **`7b29624` — `make homelab-bootstrap-vm-install`.** The canonical Controller
  reinstall is no longer only a long hand-driven console session. See the
  banner at the top of this file for the exact invocation and the evidence, and
  the runbook's section 0.5 for the guards and what stays the operator's to
  type. **RAN 2026-09-24 — its first live run, and it succeeded first time.**
  Same commit:
  `homelab-bootstrap-vm-status` now separates "created but not installed" from
  "ready" and reads the install receipt; `homelab-factory-persistent-up` and
  `-converge` refuse an uninstalled source, and converge checks *before* it
  prompts for the unrecoverable console password; `--state-dir` now precedes the
  subcommand in all six persistent recipes (previously **every** persistent
  target died for anyone who set `FACTORY_CONTROLLER_STATE`); and
  `make homelab-instance` seeds missing subdirectories instead of doing nothing
  when the overlay directory already exists.
- **`27d8af9` + `2aaa7fe` — `make homelab-factory-repeat` is real.** Gate 12's
  aggregate driver: six lifecycle phases in order, one union receipt, because no
  single phase bundle can carry the gate. `FACTORY_DURATION` is forwarded as the
  **per-phase** budget and its 120 s default is far too small for a real
  lifecycle. The dry run is read-only and safe; while the canonical image was
  empty it refused to apply and named `make homelab-bootstrap-vm-install` as the
  remedy, reading the real partition table rather than a size floor, and since
  the 2026-09-24 install it no longer refuses. The first twice-through stopped
  in iteration 1 at dual-boot acceptance (fixed `f8f0443`); later failures are
  retained above. Gate 12 finally closed for phase one on 2026-10-02 with the
  strict accepted repeat in the gate table. The earlier accidental,
  interrupted unit-suite launch remains recorded in §5.
- **`0c2df66` — `make homelab-image-service-gate`.** A host-side judge that
  grades a booted candidate image's declared systemd services from a retained
  guest console transcript (`IMAGE_PROFILE` and `IMAGE_TRANSCRIPT` required,
  `IMAGE_SERVICE_TOKEN`/`IMAGE_SERVICE_EVIDENCE` optional). **The live capture
  half does not exist** — producing a transcript needs a booted candidate image,
  which needs root — so the judge is available and the capture is the blocked
  half, the same split both identity gates use.
- **`2c3cd56` — two of gate 11's five live-boot hooks are implemented**
  (`directory-dns-loss`, `controller-reconstruction`), backed by token-scoped
  markers the guest itself printed. Three remain stubs because their primitives
  do not exist: a Controller *restart* (as distinct from the SIGSTOP/SIGCONT
  outage), a bootloader break-and-repair, and install fault injection. **Both
  hooks passed live 2026-10-01**, after `3fb969e` and `668b524`; the verdict
  stays `partial` by ADR 0080, which closes phase one there.
- **`aec5747`, `390e5cf`, `280c99d` — gate 12's last four producers.** All
  sixteen checks now have a wired producer. Two honest limits:
  `host_network_changes` **cannot legitimately render PASS today** — its `unifi`
  counter is unprovable without a run-window host egress ledger that nothing
  produces (waived for the loopback factory by ADR 0080, 2026-09-30) — and
  `artifact_scan` required a scanned tree (since `b84bc86` it scans each
  phase's retained evidence).
- **`ee8b5e6` — the Windows identity lane derives its principals from the
  private overlay roster** instead of hardcoding `student`/`operator`/
  `directory-admin` in ~15 places. With no overlay every value is byte-identical,
  so the **gate-6 and gate-8 verdicts are untouched**. **Corrected 2026-09-24:**
  this bullet said using an overlay was "no longer fatal" to gate 6. It still
  was: the guest-side PowerShell kept the synthetic names until `efcaf6d`
  (TASK-26) — the probe now renders the host roster into the staged control
  disc and the post-submit diagnostic checks only the name's shape. That is
  unit-tested and **unrun live**; see §7 item 4.
- **`f8d0348` — durable directory accounts were unreachable, and are now
  repaired but UNPROVEN.** An adversarial review found they could not be
  provisioned by any wired path; six independent breaks, the worst being that
  Ansible resolves `group_vars` relative to the **inventory source**, so an
  overlay holding `group_vars` one level above its inventory was read by nothing
  and every AD variable silently fell back to its role default. Provisioning is
  now host-side and only host-side; the in-guest path is declared dead rather
  than half-wired. `RECONVERGE=1` also no longer poisons the durable disk (the
  old guard was a bash `!`-prefixed pipeline, which `errexit` exempts).
  **Corrected 2026-09-30:** this said "Do not describe durable accounts as
  working"; the serial-console path below ran live 2026-09-25. **Corrected 2026-09-24:**
  "host-side and only host-side" was overtaken by `73dbd2b`, which stages the
  roster into a simulated persistent instance over its serial console
  (`homelab-factory-persistent-accounts-plan`, then
  `homelab-factory-persistent-accounts APPLY=1`) because host-side Ansible
  cannot reach it; `homelab-bootstrap-controller` stays the path for an
  SSH-reachable Controller. Since `0e588db` both paths refuse unless
  `identity/principals.json` exists and itself names all three directory roles
  (`standard_user`, `daily_administrator`, `domain_administrator`). The
  serial-console path ran live 2026-09-25 on `rehearsal` (`b2e8fed`); the
  Ansible path has not.
- **`90e8b52`** derives each role's required Python imports by AST extraction and
  proves them at the promotion gate; it found `ldb` surviving only as a
  transitive pacman dependency of samba. **`f677d06`** gives Windows guests a
  deliberately *diagnostic* COM1 progress reporter, because no virtio driver
  exists anywhere in this tree. **`a879b15`** records why gate 10's two deferrals
  cannot be closed and that the Controller image is not what blocks them.
  **`4d91958`** forbids discarding the working tree while lanes share the
  checkout — undo by path, never a bare pathspec.

---

## 2. Gate 6 (DONE) — what was proven and how

**Result:** attempt `20260813T191519Z-28a9f6ee07f5` on bundle
`homelab/var/factory/windows-installs/run-20260813T171405Z-6729c809fcab` ran
24/24 and published `.../acceptance-evidence.jsonl`;
`make homelab-windows-identity-judge WINDOWS_IDENTITY_EVIDENCE=<that jsonl>`
prints verbatim:
```json
{"checks": 24, "deferred": ["disable-reenable"], "external_access": false,
 "out_of_scope": ["firmware-activation", "live-microsoft-update"],
 "result": "pass", "schema_version": 1}
```
So the honest framing is "24 of 24 CONTRACTED checks pass", not "all checks":
account **disable/re-enable is deferred** and unproven, and firmware activation
plus live Microsoft Update are out of scope by decision (unreproducible in
QEMU). This is the first-ever successful gate-6 publish. `AIQ TASK-2` is marked
**done**.

### The hard problem (secure channel) and the fix — READ if touching gate 6
During the fault phases the harness SIGSTOP/SIGCONTs the controller (the
disposable Samba AD DC). Netlogon drops the **machine secure channel**, and the
acceptance operator runs **UAC-filtered non-elevated** (deliberate — the
credential proofs test the deny-only Administrators SID), so it CANNOT actively
reset the channel. A read-only `Test-ComputerSecureChannel` never re-establishes
it, and a scheduled-task/EncodedCommand UAC-bypass was **rejected as
inappropriate** (defense-evasion; my own tool classifier flagged it — do not
reintroduce it).

Owner-approved fix = **reboot-and-reverify**, implemented across
`windows_identity_faults.py`, `windows_identity_orchestrator.py`,
`windows_identity_adapter.py`, `windows_identity_run.py`:
- `NativeProcessBoundary.reboot_and_await_readiness(trigger)` — captures a switch
  cursor, fires a **clean** guest reboot, waits for boot.
- Reboot trigger = `adapter.reboot_guest()` → `launch_guest("powershell
  -NoProfile -Command \"Start-Sleep -Seconds 8; Restart-Computer -Force\"")`.
  Gotchas learned the hard way: (a) a QMP `system_reset` is an UNCLEAN reset →
  Windows post-crash recovery screen → never rejoins the network; use a clean
  guest restart. (b) the public-command launcher **only accepts a PowerShell
  invocation** (`shutdown /r` is rejected). (c) the operator holds
  `SeShutdownPrivilege` even non-elevated, so Restart-Computer works.
- **Boot detection = the reboot's fresh DHCP DISCOVER**, NOT a new switch port: a
  guest reboot does NOT drop the host↔switch socket (the port persists across
  reboots), so waiting for a new `port-connected` hangs. Wait for
  `wait_for_plain_dhcp_transaction` on the retained `windows_switch_generation`.
- Re-login = `adapter.reestablish_operator_session()` →
  `_reauthenticate(..., establish_session_only=True)`: sign-in nav + password
  submit + desktop prove, **skipping the DC-side controller-auth arm** (it can't
  drive the just-frozen DC console → `reboot-reauth-controller-auth-arm`) **and
  the guest post-submit diagnostic**. The subsequent fault checks re-prove
  connected domain logins themselves, so those proofs are redundant here.
- **TWO reboots** are wired — one before `windows-secure-channel-restored` and
  one before `windows-services-restored` — because the fault sequence takes the
  controller offline a SECOND time (`ad-dns-offline`,
  `combined-dependencies-offline`) after the first reboot.

Also fixed this session: update-policy check needed the install to set
`HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU NoAutoUpdate=0` (added
to the unattend FirstLogonCommands in `windows_install_contract.py`); GUI
references made version-portable (`windows_identity_reference.py`); the
`synthetic_directory` proof relocated to windows-standard-online; and the whole
credential-proof mechanism was rebuilt earlier (token LogonUser, Kerberos via
LSA, raw-token-groups, live-tolerant secret scanner).

### Cheap-iteration technique (CRITICAL — how to debug gate 6 without 68-min re-installs)
A gate-5 install (~68 min) yields ONE gate-6 attempt because gate-6 destroys the
one-use `<bundle>/publication.iso` (the recovery credential ISO) at run start.
**Trick:** right after an install, `cp -p <bundle>/publication.iso <stash>/`;
before each `identity-prepare`, copy it back (`chmod 0600`). Each
`identity-prepare` builds a fresh overlay from the pristine base disk, so the
credential still matches. This turns 68-min-per-attempt into ~40-min
identity-only cycles. **Delete the stash when done — it holds a one-use
credential** (I deleted `pub-stash`/`pub-stash2` at session end).

The gate-6 flow (each step APPLY=1, controller state = `build/homelab/vm/bootstrap-dc`
— reinstalled 2026-09-24, see the banner at the top; a real-name run needs the
§7 item 4 caveat):
```
make homelab-windows-install-prepare APPLY=1                      # → bundle path
make homelab-windows-install-run APPLY=1 WINDOWS_RUN=<bundle> FACTORY_DURATION=7200
make homelab-windows-identity-prepare APPLY=1 WINDOWS_RUN=<bundle> FACTORY_CONTROLLER_STATE=build/homelab/vm/bootstrap-dc
make homelab-windows-identity-run APPLY=1 WINDOWS_IDENTITY_ATTEMPT=<attempt> FACTORY_CONTROLLER_STATE=build/homelab/vm/bootstrap-dc
make homelab-windows-identity-judge WINDOWS_IDENTITY_EVIDENCE=<attempt>/acceptance-evidence.jsonl
```
An identity run takes ~45–50 min (two reboots).

**Three names, one stream — all three are real; do not "correct" one into
another:**

| Name | What it is |
|---|---|
| `<attempt>/acceptance-evidence.jsonl` | The file gate 6 WRITES: 24 records, one per contracted check. Verified `wc -l` = 24. |
| `--windows-evidence` / `WINDOWS_IDENTITY_EVIDENCE=` | The CLI flag and Make variable that POINT AT that file, both for the judge and for `homelab-arch-identity-prepare`. |
| `<gate-8 bundle>/windows-evidence.jsonl` | A **7-record subset** that `homelab-arch-identity-prepare` copies into the gate-8 bundle — only the `windows-*` checks the gate-8 contract requires: `windows-joined`, `windows-standard-online`, `windows-daily-admin`, `windows-cached-login`, `windows-uncached-denied`, `windows-local-rescue`, `windows-secure-channel-restored`. |

Progress lands in the
attempt's `acceptance-progress.json` (`passed_count`, `next_check`,
`failure_detail`). The progressive sanitizer collapses errors to
`scoped-acceptance.acceptance/FaultPhaseError`; the real coordinate is in
`failure_detail` (stashed via `collector.note_failure_detail`).

---

## 3. Gate 8 (DONE) — what was proven and how

**Result: GATE 8 PASSES, 21 of 21 checks, proven live 2026-08-14.** Run 16,
bundle `homelab/var/factory/arch-identity/run-20260814T172142Z-495164bc7159`,
evidence `evidence/identity-lifecycle.jsonl`:

```
make homelab-arch-identity-judge \
  ARCH_IDENTITY_EVIDENCE=homelab/var/factory/arch-identity/run-20260814T172142Z-495164bc7159/evidence/identity-lifecycle.jsonl
# -> PASS: 21 checks, external_access=False
```

Because the two `arch-storage-*` checks are gate 9's Arch half, **gate 9's
outstanding proof closed with it.** Note `boot_stalls: 1` in the passing run:
the firmware stall recurred and the bounded power-cycle retry absorbed it.

**No gate-8 blocker remains.** What is still open around it:
- **The firmware boot stall is not root-caused.** It hit 3 of 16 runs and the
  bounded power-cycle retry recovers it. Retained evidence narrowed the
  mechanism: QMP reported `status: running` with `reason: timed-out`, so the
  vCPU was running -- which eliminates stalled device emulation and host I/O and
  leaves a firmware spin in the first ESP read. A framebuffer frame, the QMP
  event stream and the switch log are retained on each occurrence.
- ~~The fleet template drift~~ — **closed by `2f86a21` (2026-08-14; recorded
  2026-09-30)**: `ansible/roles/identity_client/templates/sssd.conf.j2` carries
  the same `offline_timeout` bounds the installer sets.

Re-running the gate boots the canonical Controller image, reinstalled
2026-09-24 — see the banner at the top of this file:

```
make homelab-arch-identity-prepare APPLY=1 \
  ARCH_RUN=homelab/var/factory/arch-installs/run-20260811T170109Z-7ceb936e2710 \
  WINDOWS_IDENTITY_EVIDENCE=<the gate-6 acceptance-evidence.jsonl>
make homelab-arch-identity-run APPLY=1 ARCH_IDENTITY_BUNDLE=<bundle> FACTORY_DURATION=3600
```
A gate-8 run fails fast (~6 min on a boot failure, ~7 to the login), so
iterating the boundary against an existing gate-7 disk is cheap. Each attempt is
a fresh `identity-prepare`, which builds a new overlay — never a re-install.

### How it got there — the run-by-run history

Everything below this line is the historical record of the sixteen live runs and
the eight distinct root causes they exposed. It is kept so the faults and the
refuted hypotheses are not re-derived; it is not a statement of current state.

### What was fixed, and why the previously recorded diagnosis was wrong
Do not re-derive these. Both are committed with their evidence.

1. **Pristine firmware variables, not serial routing.** The old note said the
   boundary "does not route the UEFI console to ttyS0". It does: the failing
   73-byte serial log is byte-identical to the first 73 bytes of the *passing*
   gate-10 boot-1 log — that is OVMF's own serial terminal init. What pristine
   variables lack is any boot option pointing at
   `\EFI\systemd\systemd-bootx64.efi`, so ESP auto-discovery never started
   systemd-boot and there was nothing to render. `arch_identity_prepare` now
   defaults to the gate-7 bundle's own `OVMF_VARS.fd`, which carries the
   `Linux Boot Manager` entry `bootctl` authored at install — the same pairing
   gate 10 requires as `VARS_SOURCE_GATE7`. `--ovmf-vars` still overrides it.
2. **A digit key selects; only Enter boots.** With the menu rendering, the digit
   moved the highlight onto Arch and stopped the five-second countdown, then the
   guest sat there until the harness gave up. `drive_boot_menu` now commits with
   `\r`, reading the highlight back from the raw inverse-video render rather
   than assuming the digit landed. Gate 10 had already recorded this lesson at
   `dualboot_acceptance.py:141`; the gate-8 lane claimed to mirror that lane
   while sending the digit alone.
3. **The boot was also nondeterministic** — one run rendered the menu and the
   next, with byte-identical vars and the same backing disk, rendered nothing.
   Fixed by aligning the argv with the gate-10 boundary: no `bootindex=1` (its
   fw_cfg boot order competes with the authored NVRAM entries), a `VGA` device
   (without one `-nodefaults` leaves no display and every QMP screendump fails,
   which is why the early failures left no frame evidence), and 8192 MiB. The
   run now also retains its exact `qemu-command.json` beside the bundle, so the
   next flake is diagnosed from what it booted rather than reconstructed.

Use `tools/factory-bundle-firmware-provenance <bundle> ...` to compare what any
two bundles actually booted — that pairing is what settled (1).

### Live progress, 2026-08-14 (four runs, each cheap)
Every fix below is committed with its evidence. The boot chain and the in-run
join are PROVEN; the operator login is the one remaining blocker.

| Run | Bundle | Outcome |
|---|---|---|
| 1 | `arch-identity/run-20260814T113757Z-11326c51f576` | menu rendered for the first time (gate-7 installed NVRAM), Arch highlighted, never booted |
| 2 | `arch-identity/run-20260814T115234Z-f792faf46d6e` | no menu again with byte-identical vars: the boot was nondeterministic |
| 3 | `arch-identity/run-20260814T120114Z-5fafdb4897ff` | argv aligned with gate 10 -> menu, Enter-commit, EFI handoff, ttyS0 getty, `menu_retries: 0`; login refused |
| 4 | `arch-identity/run-20260814T124858Z-0ac6c279561b` | in-run join proven: `join_media_{built,attached,consumed,destroyed}`, `join_verified`, `join_principal_destroyed` all true; login still refused |

Run 4 used a fresh gate-7 install,
`arch-installs/run-20260814T124513Z-e0c32ed98202` (`observed`,
Windows preserved, `TELOS ARCH NVRAM ENTRIES AUTHORED`, join media consumed and
destroyed), because the one-shot join unit only reaches a disk through a gate-7
install.

| 5 | `arch-identity/run-20260814T131951Z-83e2612decf0` | first run with the readiness gate: it fired correctly, reporting a readiness failure and NOT a refused login |
| 6 | (aborted) | controller principal staging failed; launched from a tree a lane was mid-edit on |
| 7 | `arch-identity/run-20260814T135756Z-c72cff0ac44f` | boot nondeterminism: no menu, 146-byte transcript, no `BdsDxe:` line at all |
| 8 | `arch-identity/run-20260814T140142Z-587985cdf83f` | boot + join proven again; readiness gate fired with full diagnostics |

**Run 8's diagnostics settled the identity question.** The gate prints thirteen
secret-free fields on failure; grep the transcript for
`TELOS ARCH DOMAIN DIAGNOSTIC`. They show the directory is **completely
correct**: `net ads search`, using the host keytab the in-run join wrote,
returns `operator` with `uidNumber 10001`, `gidNumber 10513`, `loginShell` and
`unixHomeDirectory`, and `Domain Users` with the matching `gidNumber 10513`. The
machine principal is in the keytab, LDAP on 389 answers, and the DC name
resolves. So Kerberos, LDAP, DNS-for-Samba, POSIX attributes and the staged
principal are all proven good.

What fails is inside SSSD alone: `domain-status` reports `Offline` and every
lookup logs `SSSD is offline`. The target is therefore SSSD's ability to reach a
DC, not identity, not the POSIX attributes, not the keytab, and not the Global
Catalog.

**Correction, recorded so it is not re-derived.** A first reading of that field
concluded SSSD had *discovered no DC at all*. That was wrong -- an artifact of
the diagnostic's own 200-column cap, which truncated the line at exactly
`Discovered AD Domain Controller servers: `. The cap is now 512 and the field
prints in full. What IS established: DNS works from the workstation (the join
unit's bounded `getent hosts <realm>` loop broke on its first iteration, and
nothing writes `/etc/hosts`), and DHCP hands the workstation the controller as
its only nameserver.

The asymmetry -- `net ads` reached the DC while SSSD did not -- is now partly
explained. Samba's DC location falls back to a NetBIOS broadcast, which this
flat hub floods and the DC answers, followed by a CLDAP netlogon ping; SSSD's AD
provider can locate a DC *only* by SRV. And the two query different records:
`net lookup ldap` asks `_ldap._tcp.dc._msdcs.<domain>` while SSSD asks
`_ldap._tcp.<domain>`. So `net ads` can succeed with no SRV record at all.
**What is still not settled** is whether `_ldap._tcp.<domain>` answers -- the
only SRV check in the repository queried loopback on the DC itself. The fix is
therefore deterministic rather than causal, and says so in the code.

**Also open: the boot is nondeterministic.** Two of eight runs (2 and 7) started
no UEFI boot option at all -- console init and then nothing, no `BdsDxe:` line
-- with byte-identical firmware variables and the same disk as runs that
succeeded. All three of today's gate-7 bundles do carry the authored
`Linux Boot Manager` entry, so this is not a missing entry. Aligning the argv
with gate 10 made it much rarer but did not root-cause it. A re-prepare against
the same gate-7 disk is cheap (~7 min, no reinstall), so retry on this
signature -- but it needs a real fix, and the VGA device added for frame
evidence is still not screenshotted by this lane.

| 9 | `arch-identity/run-20260814T144603Z-2ccf8c3ce931` | `ad_server` worked -- SSSD discovered and selected the DC, SRV answered -- but still Offline: the fault was the authenticated bind |
| 10 | `arch-identity/run-20260814T152400Z-ce7b701254a3` | **DOMAIN LOGIN WORKS.** `domain_online_observed`, `getty_seen`, `login_completed` all true; a home directory was created and an operator shell appeared. Only `sudo -S` elevation fails |

**The keytab was the bind failure.** `net ads join` at install time wrote
`/etc/krb5.keytab` against the domain of *that* run. The boot-time re-join
against this run's freshly provisioned domain left the old keys in place with
the same KVNO, so SSSD's `ldap_child` could select a dead key and the backend
went offline with the server correctly identified. Removing the keytab
immediately before the boot-time join fixed it -- the same reasoning the join
unit already applied to the SSSD cache. Note `net ads` kept working throughout
because it authenticates from `secrets.tdb`, which the join *does* rewrite.

A hypothesis worth recording as refuted, because it is easy to re-derive: the
keytab holds `HOST/TELOS-WS1.ad.factory.test` with the host part uppercased while
`ad_hostname` is the lowercase DNS name, which looks like a case mismatch. It is
not. Reading the shipped sssd binary, `ldap_child` selects the bind principal
from the keytab itself over a fixed pattern list whose matching pattern
truncates the hostname at the first dot, uppercases it and appends a dollar --
so the bind uses the machine account and `ad_hostname`'s case cannot affect it.
Pinning `ldap_sasl_authid` would have pinned the wrong thing while looking like
a fix.

| 11 | `arch-identity/run-20260814T155301Z-4b21f9334459` | **ROOT SHELL.** `sudo_elevated`, `sudo_uid: 0`; a boot stall recurred and the new retry recovered it. Only the local-rescue password remains |

**The sudo failure was a race on sudo's stdin.** The elevation gated on a marker
the shell printed *before* sudo ran, so the harness wrote the credential and then
typed the next command milliseconds later -- and that line became sudo's
password. The getty login and the rescue-password paths both wait for the prompt
of the program that will read them; the elevation now does too, via a
token-scoped `-p` prompt. It stays a genuine passworded proof: `-k` still
invalidates the timestamp and the sudoers rule is unchanged.

**The stall retry earned its keep on its first outing, and narrowed the
mechanism.** Run 11 hit the no-boot signature (`transcript_bytes: 146`, same as
run 7), the power-cycle recovered it, and the retained evidence answered the open
question: QMP reported `status: running` with `reason: timed-out`. The vCPU was
*running*, which kills the stalled-device-emulation and host-I/O candidates and
leaves a firmware spin in the first ESP read as the surviving hypothesis. A 3 MB
framebuffer capture and the QMP event stream are retained beside it.

| 12 | `arch-identity/run-20260814T161054Z-7ed00ab7472a` | **THE PROBES RAN FOR THE FIRST TIME: 18 of 21 checks pass.** All boot-phase facts true. Three fail: `arch-identity-restored`, `arch-storage-attached`, `arch-storage-denied` |

**Both remaining boot-phase failures were the same class of bug**, worth stating
once because it bit twice in a row. The elevation and the rescue password each
gated their write on a marker the *shell* printed before the program that would
read it existed, so the next thing the harness typed became the input. The getty
login always did it correctly -- wait for the prompt of the program that reads.
Both now do. The elevation had a second defect: its verdict pattern matched
sudo's own lecture (a read chunk ending on the `#` of `#1)`), so the harness
believed it already had root; every verdict is now a token-scoped marker or the
reader's own re-prompt.

**What 18 passing checks means.** The hard ones are proven live on both operating
systems: domain join, standard and administrative logins, administrator
separation, controller-offline cached login, uncached denial, local rescue,
controller restore, and the Windows secure channel. `arch-storage-absent-login`
passes too, so the absent-storage path works.

| 13 | `arch-identity/run-20260814T164555Z-2519fe2d8fec` | **19 of 21.** `arch-identity-restored` now passes. Only the two `arch-storage-*` checks remain |

`arch-identity-restored` failed on timing, not identity: its Windows twin
recovers because Netlogon is told to re-establish, while SSSD goes offline on a
failed request and returns on its own retry schedule, which can outlast a bounded
probe. Giving that recovery room fixed it without weakening the proof.

| 14 | `arch-identity/run-20260814T165752Z-bcb0e1d3fcb3` | 19 of 21. **Kerberos for the storage mount is now solved**; the fault moved to the server's share resolution |

**The storage mount's Kerberos is done.** Run 14's own diagnostics show the user
holding a TGT, the KDC issuing `cifs/unas.ad.factory.test` at `kvno = 1`, the
upcall helper and its `request-key` config in place, the name resolving and SSSD
Online. The earlier `ENOKEY` is gone. What remains is `mount error(2)` --
`ENOENT`, which for an authenticated CIFS session is the server answering *bad
network name*: `smbd` does not see a share called `operator`. Samba resolves
`//server/<name>` through its `[homes]` section only when it can look `<name>` up
as a user *on the server*, and on an AD DC the domain users are not local
accounts, so that depends on the controller's own name-service reaching the
directory. That is the layer to fix, and it is controller-side -- which is cheap,
because the controller role runs fresh on every gate-8 run.

| 15 | (superseded) | share mounted; the identity guard refused a pass reporting owner_uid=1 -- the harness had truncated 10001 on a partial read |
| 16 | `arch-identity/run-20260814T172142Z-495164bc7159` | **GATE 8 PASSES. 21 of 21.** Judge: `PASS: 21 checks, external_access=False` |

The last two faults, for the record. The per-user share never resolved because
the Controller's own name service had no directory source at all -- `smbd`
clones its `[homes]` section only when it can look the requested name up as a
user on the server, and on an AD DC the domain users are not local accounts. The
run before that got the mount working and was refused by the measurement guard,
which was right to refuse: the harness had read `owner_uid=1` from a guest that
printed `10001`, because the measurement pattern had no line anchor and a serial
chunk boundary inside the number matched its leading digits.

Note `boot_stalls: 1` in the passing run: the firmware stall recurred and the
power-cycle retry absorbed it. That fault is still not root-caused and is the
one thing still open around a passing gate 8; the `sssd.conf.j2` drift listed
beside it at the top of this section was closed by `2f86a21`.

### How the design premise was wrong (fixed in 73d7f32)
Gate 8 asserts its gate-7 disk *arrives joined* and only verifies with
`net ads testjoin`. But **every gate-8 run provisions a brand-new domain.** The
canonical `bootstrap-dc` image carries no provisioned AD, and the controller
role runs `samba-tool domain provision` whenever `sam.ldb` is absent
(`arch_install_run.py:1240-1243` already records this lesson). New domain SID
and krbtgt, empty SAM — so the `TELOS-WS1$` machine account the gate-7 install
created never exists in this run's directory, and `controller_principals.py`
stages only the three user roles, never a machine account.

With `id_provider = ad` and GSSAPI host-keytab binding, SSSD cannot bind to that
directory, marks the domain offline, and offline auth needs a cached credential
that cannot exist (fresh disk, per-run generated password). So `operator` is
refused deterministically — `LOGIN_REFUSED_FAILURE` — and no delay, backoff or
retry count can change it. `net ads testjoin` would fail for the same reason, so
`arch-joined` was never reachable in this design either.

**The Windows lane does not have this bug because it joins in-run.**
`windows_identity_orchestrator._run_acceptance_checks` records
`controller-ready`, calls `_execute_join(...)`, and only then records
`windows-joined`; `_execute_join` stages a one-use `tj-<hex>` join principal on
the freshly provisioned DC, builds a `TELOS_JOIN` ISO, hot-attaches it, and
drives the join in-guest. Gate 5 does not join at all.

**How it was fixed** (`73d7f32`, proven live in run 4): the Arch lane joins
in-run, reusing the one-use join media gates 5-7 already build
(`controller_join_material.py`, `arch_install_run.run_join_install`,
`ArchJoinMedia`). It is driven by a one-shot boot unit ordered
`Before=sssd.service systemd-user-sessions.service`, because **there is no
pre-login shell on the disk**: `local-rescue` ships a
disabled password and gate-7's `loader.conf` sets `editor no`, so neither a
console login nor a boot-cmdline edit can obtain root before the getty. Since
`serial-getty@ttyS0` is `After=systemd-user-sessions.service`, that ordering
makes the login prompt appear only after the join completed — no readiness
polling needed.

Each installer change requires **one fresh gate-7 install**, because the unit
only reaches a disk through an install (a gate-7 install boots the canonical
Controller image, reinstalled 2026-09-24 — see the banner at the top):
```
# Omit WINDOWS_RUN: the default --windows-disk is the standalone base the last
# passing gate-7 run overlaid. Note WINDOWS_RUN is forwarded as --windows-disk,
# i.e. a path to a windows.qcow2, not a bundle directory.
make homelab-arch-install-prepare APPLY=1
make homelab-arch-install-run APPLY=1 ARCH_RUN=<prepared bundle> FACTORY_DURATION=1800
# ~4.5 min. The Makefile default duration of 120 is too tight.
```
Rejected alternatives, recorded so they are not retried: pre-seeding the machine
account on the DC (the machine password lives only in the guest's `secrets.tdb`,
unknowable host-side), and joining from a post-login shell (circular — the login
is what the join enables).

**Also latent, fix alongside:** `arch-local-rescue` must fail regardless of the
join, because `check_arch_local_rescue` requires `passwd -S local-rescue` to
report `P` and nothing in the run ever sets that password. And
`LOGIN_ATTEMPTS = 3` exactly equals `pam_faillock`'s default `deny=3`, leaving
no headroom for a single spurious refusal.

---

## 4. Operating rules / security constraints (MUST follow)

- Loopback-only QEMU until explicit authorization; no host networking, UniFi, or
  physical disks (gate 14). ADR 0078 permits unattended installation only on
  disposable QEMU disks.
- **No plaintext secrets** in Git, logs, docs, PXE roots, answer files, or
  command output. Real hostnames/IPs/MACs/serials live ONLY in the gitignored
  `homelab/instance/` overlay.
- Never run `sudo` unasked — hand the operator the exact argv.
- One-use recovery `publication.iso` must be destroyed by end of acceptance; do
  not leave copies around (see the cheap-iteration note).
- Do NOT reintroduce UAC-bypass techniques (scheduled-task/EncodedCommand
  elevation) — rejected this session.
- Put temp files in the session scratchpad, not the attempt dir.
- Real account names, the owner's realm and its domain SID are instance data:
  keep them out of tracked files **and commit messages**; tests use
  placeholder names (`roster-a`) and synthetic SIDs.
- End commits with a `Co-Authored-By:` trailer naming **the model actually
  acting**, e.g. `Co-Authored-By: <acting model name> <noreply@anthropic.com>`.
  Do not copy a version from an old commit: the history already carries
  `Claude Opus 4.8`, `Claude Fable 5`, and `Claude Opus 5 (1M context)`, and
  three recent commits carry none. Use your own identity.

## 5. Gotchas

- **Install flakiness:** the gate-5 Windows install occasionally hits a
  PXE→WinPE→reboot→PXE loop (NVMe never becomes bootable; a 2nd `wimboot v2.9.0`
  in `<bundle>/evidence/workstation-serial.log` is the signature). It killed one
  120-min attempt. A healthy install has exactly one `wimboot` and prints
  `TELOS WINDOWS NATIVE READY` in ~69 min. Handled since 2026-10-01 (it struck
  gate 12's iteration 2 after ~3.5 h): `windows_install_run` fails on the 2nd
  banner live with `result.json` `failure_category: "pxe-loop"`, and
  `factory_repeat` retries that phase once with a fresh bundle, disclosed in the
  receipt's `retries`; a manual run still needs a manual re-prepare.
- **~~Pre-existing test failure~~ — FIXED 2026-08-14 (`e9ec869`).**
  `test_windows_run_dialog_calibration.test_guest_mismatch_fails_before_start`
  ("private publication must be a regular file") used to fail on HEAD; the stale
  guest-mismatch fixture was repaired and
  `PYTHONPATH=. python3 -m unittest homelab.tests.test_windows_run_dialog_calibration`
  now reports OK. Do not re-report it as a known failure.
- **Long-run monitoring:** identity/install runs are long; launch them
  backgrounded and attach a harness-tracked waiter (a bounded loop that greps a
  driver log for a DONE marker) so you get a completion notification. `Date.now`
  etc. work in bash but not in workflow scripts.
- **Disk space (measured 2026-09-24):** this is much bigger than it looks. A
  single full Windows install bundle is ~17–29 GB, but the tree AGGREGATES:
  `homelab/var` is **585 GB**, `homelab/var/factory` **548 GB**, of which
  `windows-installs` is **399 GB**, `arch-installs` **141 GB** and
  `dualboot-acceptance` **7.5 GB**. One bundle dominates: the historic identity
  input `windows-installs/run-20260728T114233Z-afecdf7cc9d0` is **241 GB** on
  its own (it holds every early identity attempt). Host: 881 GB used of 1.5 TB,
  546 GB free. (On 2026-08-14 it was 532 / 496 / 399 / 90 GB with 627 GB free;
  the growth is `arch-installs`.) Clean spent bundles (publication consumed →
  orphaned disk) if space is tight, and check `du -sh homelab/var/factory/*`
  before starting a long run.
- **One-use credential media: all destroyed.** The old `run-20260728T*` bundles
  used to carry orphaned `publication.iso` files holding a plaintext
  `install-password.txt`. All **29** were DESTROYED 2026-08-14: they were
  orphaned (no `identity/`, no `result.json` — so no acceptance had ever
  consumed them), and the standing rule is that a one-use credential is
  destroyed rather than parked. Current state verified:
  `find . -name 'publication*.iso' | wc -l` → **0**, and
  `find … -name 'install-password*'` → nothing. **No stray one-use credential
  remains in the tree.** Re-verified 2026-09-24, after the unit-suite accident
  below: both counts are still 0. If you create a publication stash for cheap
  iteration (see §2), you own deleting it.
- **No unit test may read the operator's `build/` or `homelab/var/` state.** On
  2026-09-24, once the canonical image was installed, a unit test that called
  `factory_repeat.main(["--apply", ...])` against the real canonical disk —
  expecting a refusal because that disk had been empty — was no longer refused,
  and launched a real Windows install (a simulated Controller and a Windows
  guest under QEMU) from inside the unit suite. It was stopped; both interrupted
  bundles and the one-use publication media each held were destroyed, and
  `272d693` made the tests create their own fresh qcow2. A test that asserts a
  fact about the lab rather than the code breaks the day the lab changes. Four
  tests in `test_windows_identity_process_boundary` and
  `test_windows_identity_secret_safety` statted the operator's
  `homelab/var/seed/telos-controller-seed.iso` and failed in a fresh worktree
  (2026-09-24); since `9c3ca80` (2026-09-30) they write their own synthetic
  seed. aiq TASK-36 carries the remaining hermeticity work.

## 6. Key files touched this session (all committed)
- `homelab/vm/windows_control/Invoke-TelosIdentityProbe.ps1` — read-only
  secure-channel probe (bounded re-verify only).
- `homelab/vm/windows_identity_faults.py` — two `driver.reboot()` calls;
  `FaultPhaseOperations.reboot_and_reauthenticate`.
- `homelab/vm/windows_identity_orchestrator.py` — `AcceptanceCallbacks
  .{reboot_guest,reestablish_operator_session}`; the reboot op with diagnostics.
- `homelab/vm/windows_identity_adapter.py` — `reboot_guest`,
  `reestablish_operator_session`, `_reauthenticate(establish_session_only=)`.
- `homelab/vm/windows_identity_run.py` — `reboot_and_await_readiness` (QMP-less
  clean reboot + DHCP boot-wait).
- `homelab/vm/windows_install_contract.py` — WindowsUpdate AU policy in unattend.
- `homelab/vm/windows_identity_reference.py` — version-portable references.
- Memory: the project's Claude memory directory — see
  `gate6-publication-single-use.md`.

## 7. First moves for the fresh agent
1. `git log --oneline -20`, read `WORKSTATION-FACTORY-STATE.md` gate table.
2. Re-lease the AIQ work if continuing (a new task, since TASK-2 is done): `aiq
   status` / `aiq dequeue`. TASK-26 and TASK-28 below are items in that local
   queue.
3. **The canonical Controller image is installed (2026-09-24) — keep its
   `local-rescue` password safe.** Nothing needs reinstalling; see the banner at
   the top. Losing that password costs the whole image again. If it ever is
   lost, `make homelab-bootstrap-vm-install APPLY=1 CONFIRM=… ISO=… SEED_ISO=…`
   is now proven by one live run, and the hand-driven console recipe in
   `homelab/docs/operator-runbook.md` ("Keep the `local-rescue` password") and
   `homelab/vm/README.md` ("Interactive offline installation") is the fallback.
4. **The Windows guest scripts no longer pin synthetic names (TASK-26,
   `efcaf6d`, 2026-09-24) — PROVEN LIVE the same day by the real-name
   rehearsal in item 5.**
   `Invoke-TelosIdentityProbe.ps1` names each principal by a `{{role}}`
   placeholder that `build_control_iso` renders from the host roster into the
   staged copy only (with no overlay the staged probe is byte-identical to the
   one gate 6 proved), `TelosPostSubmitDiagnostic.ps1` validates the operator
   name by shape, and `homelab/vm/windows_guest_principals.py` refuses any
   tracked guest script that pins a UPN literal or a synthetic account name.
   The risk recorded here — that the post-join operator sign-in reference,
   captured with the synthetic operator typed in, would miss its distance
   threshold for a renamed one — did **not** materialise: the typed UPN moves
   that crop by under one unit. What did break was the reference's recorded
   *state* string, which names the captured principal; fixed in `6d8f104`.
5. **Then prove the roster derivation on the cheap path, before anything durable.**
   The owner asked on 2026-08-18 whether to mint a real workstation against an
   ephemeral Controller first, to avoid iterating on workstation faults by
   rebuilding a Controller. The instinct is right, the risk is mislocated, and
   the answer is recorded here so it is not re-derived:

   - Workstation-against-disposable-Controller is the **most proven** path in
     this repository — gate 6 at 24/24, gate 8 at 21/21, gate 10 passing. It
     does not need verifying.
   - What was unproven (2026-08-18) was almost entirely **Controller-side**:
     persistent convergence, durable account staging over the serial console,
     and a durable workstation flow that did not exist yet. All three have
     since run live (item 6).
   - A workstation minted against an ephemeral Controller is **never
     keepable**: each run provisions a brand-new domain, so its machine
     account and every user SID die with the run. It validates the process and
     never yields the artifact.
   - The Controller is **not physical yet** (ADR 0065/0067 put the first one in
     a QEMU VM), so rebuilding it is one destroy target away. The genuinely
     unrebuildable thing was never the machine — it is the domain. The realm,
     DNS domain, NetBIOS name and address are declared in
     `instance/identity/directory.json`, which a rebuild reuses rather than
     re-decides; the **domain SID is not**. It is generated at first
     provisioning, read back from the disk after convergence and recorded only
     in the instance marker (`homelab/vm/bootstrap_dc.py`; no `--domain-sid` is
     passed). Rebuilding a persistent instance therefore creates a **new
     domain** under the same realm — new SIDs, every join lost — and no backup
     target exists for a persistent instance. **Corrected 2026-09-24:** this
     bullet said the realm and domain SID were both frozen in `directory.json`.
   - The real cheap test hiding in that question is the **roster derivation**:
     the owner's names flowing through both OS lanes. That code (`ee8b5e6`,
     `dcf4f3a`, `96f2d16`) has never run live and is exactly what would bite
     when minting a real workstation. Exercise it with **real names under the
     synthetic realm** — names live in `identity/principals.json` and the realm
     in `identity/directory.json`, separate documents with separate loaders, so
     nothing forces them together and no new flow is needed.

   **DONE 2026-09-24 — the real-name rehearsal passes gates 5–8** with
   `principals.json` naming the standard user and the daily administrator
   (domain administrator left synthetic) under the synthetic realm: gate 5
   `windows-installs/run-20260925T022641Z-b918669ae1f1` (observed, ~68 min);
   gate 6 attempt `attempt-20260925T035509Z-3a7559cc42a5`, judge `pass`, 24
   checks, the same single `disable-reenable` deferral as 2026-08-13; gate 7
   `arch-installs/run-20260925T044037Z-dd94354503e9`
   (`arch-installed-windows-preserved`); gate 8
   `arch-identity/run-20260925T044915Z-f44567dac8c6`, judge `PASS: 21
   checks`. It found two real defects, both fixed and re-proven in the same
   runs: the operator sign-in reference's recorded state pinned the captured
   name (`6d8f104`; gate 6 refused within a minute of the join), and the
   disk-roster fingerprint was read from a split serial chunk (`f7bbf13`;
   gate 8 read `1f942b04b` of `1f942b04b72754e6` and refused its own disk).
   Two earlier gate-6 attempts in the same bundle are the failing evidence.

   **Also DONE 2026-09-25:** a **throwaway-named** persistent instance
   (`rehearsal`) was converged under the permanent realm and given the four
   durable accounts (pinned UIDs, one of them an `additional_standard_users`
   entry, all with temporary passwords changed at first logon). Fixes found on
   the way: `05eec6e` (domain SID read from a split serial chunk — this
   instance's marker still holds the truncated SID), `efedf50` (explain a
   failed stage; refuse a policy-violating password before booting),
   `1b04fd3` (`CHANGE_AT_FIRST_LOGON=1`). Keep `rehearsal` as the directory
   TASK-28 is developed against, so workstation faults never touch the keeper;
   create the instance you intend to keep only once a workstation can be
   minted against a persistent directory.
6. **The durable workstation flow (TASK-28) is DONE.** It closes finding 7 of
   the 2026-08-17 review (every workstation runner wrapped the Controller in
   `DisposableBootDisk`; `96f2d16` had only turned that gap into a refusal).
   Follow `homelab/DURABLE-WORKSTATION-FLOW.md`: steps 1-9 (`715147f`..`5f5b322`,
   `a54e7c9`, `d3f8567`, `bcf8d16`) passed live end to end 2026-09-30,
   unattended under agent custody (TASK-40, `fa8ec58`/`14b925e`) on
   `rehearsal-auto` / `rehearsal-auto-ws1`; the run ids are in its "Live
   record". Installs stay on the disposable Controller; the persistent one
   serves only joins and logins. Under owner custody `rehearsal-ws1` stays at
   stage `arch-install`: its owner-run arch-join stopped at first login
   (`Login incorrect` with no expired-password notice, so the typed temporary
   password was not the staged one; directory unchanged). `RESTAGE=1` cannot
   fix that (staging is create-only and refused with `account-exists`,
   harmlessly); the reset is `homelab-factory-persistent-account-password`.
   Gate-5 installs for the flow (#0, #0b) were each observed with one PXE boot
   in 68-69 min.
7. **Gates 11 and 12 (aiq TASK-6) are DONE for phase one.** Gate 11 is closed at
   `partial` per ADR 0080: `recovery/run-20261001T015135Z-gate11live` passed
   five scenarios and deferred exactly the three agreed stubs. Gate 12's
   original `repeat/20261002T011915Z-907070-repeat` remains final FAIL,
   `equivalent: false`, zero retries. Iteration 1's listener-change failure
   remains unattributable; iteration 2 passed with only the ADR 0080 UniFi
   waiver and all six local network counters zero. Both gate-4 audits passed.
   Recovery support `7e4c72c` is committed and available, but recovery
   `repeat/20261002T053117Z-1175062-repeat` stopped about 06:39 UTC, exit 2,
   after Windows PXE-loop and retry process-audit failures. No comparison
   receipt was written. Recovery `repeat/20261002T114212Z-1294100-repeat`
   from process-audit fix `c45c0dc` finished at 13:47:15 UTC, exit 2. Its final
   receipt is FAIL, nonequivalent, zero retries: all functional phases
   completed, but the fresh aggregate failed solely on `route=4` (15 pass /
   one fail). Raw snapshots retain an automatic IPv6 router-advertisement
   ECMP next-hop replacement counted in both all-table views. The other five
   local counters are zero, forwarding by privilege proof, and UniFi remains
   unproven. That failed verdict stands. Third strict recovery
   `repeat/20261002T143757Z-1346697-repeat` from `011e678` finished at
   16:41:30 UTC with PASS-WITH-WAIVER, equivalent receipts and zero retries.
   One unchanged accepted original cycle plus one fresh full cycle at identical
   pins each have 15 PASS / only UniFi waiver and gate-4 4/4 PASS. The fresh
   six local counters are zero. Independent comparison agrees with zero
   divergences; supervisor exit 0 and teardown are verified, with no QEMU or
   driver remaining. TASK-6 is DONE; no route-policy exception was needed or
   approved. Preserve the final receipt, source fingerprints and diagnostics at
   [the exact retained paths](FACTORY-MAKE-TARGETS.md#the-repeat-driver).
   Preserve failed disks/variables/results/logs; guarded retirement also
   removed only publications from three early failed WinPE runs, leaving all
   21 other file hashes and the keeper publication unchanged. The firmware
   fault remains unresolved despite
   the loader existing on an ESP whose GUID matches the firmware entry.
8. **The DR proof (aiq TASK-41, TASK-42) is DONE.** `rehearsal-auto-ws2`
   Windows join
   `attempt-20261001T223623Z-5e1cc129efaf` passed, folded and retired its
   publication; pre-DR keep-verify `run-20261001T224742Z-294135-5bf47dc6`
   passed 40/40. Backup `20261001T225428Z-323971-342a3f27` was verified;
   same-instance destroy/restore `20261001T225520Z-327126-e82e02db` passed
   as DC `dr-2610012255`; reconvergence and probe
   `20261001T225659Z-328973-facea8fe` passed. Post-DR keep-verify
   `run-20261001T225740Z-329731-9a00cfd1` failed with Arch SSSD offline
   despite machine TGT and LDAP working. An unexplained SIGTERM during the
   Controller relaunch prevented Windows verification. Those failed results
   remain retained. Samba repair `bdebb4f` removed compressed SRV Targets;
   restored-DC reconvergence then passed four strict LDAP/Kerberos UDP/TCP
   probes. Keep-verify `run-20261001T235410Z-588718-de077620` PASSED 40/40
   without rejoining either OS, changing kept disk/variables/marker, folding
   overlays or adding a ledger entry; teardown was clean. Windows needed the
   existing bounded cold-boot retry after a pristine-overlay first-boot stall
   (72,192 read bytes, 33 operations, zero writes;
   `fabric/windows-boot-attempt-1.json`). Do not claim firmware is fixed or
   repeat the destructive drill. Restored `rehearsal-auto` and its backup remain.
   Full evidence paths and guards are in `FACTORY-MAKE-TARGETS.md`. The older
   `rehearsal-auto-ws1` cannot prove SRV-first recovery. Owner-custody
   `rehearsal` separately needs owner-run reconvergence before testing its
   newly enabled PXE units across a reboot.
9. **The keeper (aiq TASK-21) is blocked solely on owner-terminal passwords:** owner
   custody with the owner's real passwords; the keeper is still absent and
   its convergence dry run is checked. The owner's decisions
   were taken 2026-09-30 (Start-here table): the short policy, the temporary
   Domain Admin `tj-` join principal, backups to `homelab/var/backups/` proven
   before minting, SRV-first DR naming. Follow the exact
   [owner-terminal sequence](FACTORY-MAKE-TARGETS.md#owner-terminal-keeper-sequence-task-21):
   converge creates the absent keeper, apply the agreed password policy,
   stage temporary account passwords, probe, complete the durable workstation
   flow, pass keep-verify, then take the first keeper native backup. Credentials
   are typed only at the owner's terminal. Successful Windows bundle
   `run-20261001T235652Z-a782e2f67fac` is reserved with its publication
   unconsumed for keeper adoption. Confirm the lab is idle before each live
   step; only one live lane may run at a time. The domain SID is born at
   convergence. The throwaway
   instances and their kept workstations leave by `homelab-factory-persistent-destroy` and
   `homelab-durable-workstation-destroy` (directory destruction passed in the
   restore drill; kept-workstation destruction is not yet live-proven).
   Gate 14 only with explicit owner go-ahead; the plan is
   `homelab/EXTERNAL-INTEGRATION-READINESS.md`, and its read-only UniFi review
   (TASK-37) is authorized and waits on owner-supplied access. Decided
   2026-09-30 and no longer open: gate 11 `partial` closure and the gate-12
   egress waiver (ADR 0080, which keeps ADR 0077's ordering). Still open: the
   gate-14 go-ahead with its attachment values.

Superseded 2026-08-17, recorded so it is not re-derived: this list used to open
with gate-8 serial/OVMF work and to say gate 12 needed gates 8/9 live first.
Gate 8 passed 2026-08-14 (21/21) and gate 9 closed inside it, and the serial
diagnosis was itself wrong — the console *was* routed to ttyS0; the pristine
firmware variables carried no boot option pointing at systemd-boot. See §3.
Superseded later the same day: item 4 said gate 12 needed an aggregate
`homelab-factory-repeat` driver that was "a reserved name, not implemented". It
is implemented (`27d8af9`).
Superseded 2026-09-24: item 3 said to reinstall the canonical Controller image
and that the target had NOT RUN. The owner installed it 2026-09-24 through that
target, first time. The list now puts TASK-26 ahead of the real-name rehearsal
and names the durable workstation flow (TASK-28) as its own step. TASK-26 then
landed the same day (`efcaf6d`), so item 4 records it as done and unrun.
Superseded 2026-09-30: item 6 said TASK-28 awaited the owner's go-ahead (now
approved, in progress), and item 8 listed the gate-11 closure and the gate-12
egress decision as open (ADR 0080 decided both). Superseded later that day:
item 6 read "build the durable workstation flow … in progress", with the
2026-09-24 gap analysis (6-10 files, 1-3k lines); it is built and passed live
end to end, so item 6 records it as done and item 7 is the keeper. Item 8
waited on TASK-34, now done.
Superseded 2026-10-01: item 7 was the keeper, waiting on three owner
decisions (taken 2026-09-30; now item 9 after the DR proof, item 8), and item 8
read gates 11 and 12 as agent-runnable and unrun (now item 7).
