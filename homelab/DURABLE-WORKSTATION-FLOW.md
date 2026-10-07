# Durable workstation flow (TASK-28)

Status: approved design; all nine steps implemented and **PROVEN LIVE END TO
END** 2026-09-30, unattended under agent custody on the throwaway instance
`rehearsal-auto` (see "Live record"). TASK-28 is done; the keeper is aiq
TASK-21. Under owner custody steps 7-9 have not passed (`rehearsal-ws1` stays
at stage `arch-install`).

One-command mint, 2026-10-07: `make homelab-factory-mint` runs steps 1-9
plus the persistent directory and a backup, resuming from markers; owner
custody types every value once at the start (FACTORY-MAKE-TARGETS.md, "One-
command mint"). UAT PASS on throwaway `uat2` / `uat2-ws` with made-up users,
keep-verify 41/41 including every standard account's Arch login
(`VERIFY_USERS=1`). A Windows join whose firmware variables lose the
Linux-first boot order is no longer folded, and a desktop hidden by a Start
menu Windows opened itself is closed with Escape.

Current DR checkpoint, 2026-10-01: **PASS, 40/40**. After native backup,
destruction and restoration of `rehearsal-auto` under a new DC name, repaired
Samba DNS and reconvergence, the existing SRV-first `rehearsal-auto-ws2`
passed both operating systems without a rejoin. TASK-41 and TASK-42 are done.
The keeper (TASK-21) is still absent and requires owner-terminal credentials;
its DR prerequisite is now satisfied. See the live record below.

Every workstation runner today wraps the Controller in `DisposableBootDisk`,
and every run provisions a brand-new domain, so a minted workstation dies with
its run. This flow mints a workstation you keep: Windows and Arch on one disk,
joined to a **persistent** Controller instance (see
[FACTORY-MAKE-TARGETS.md](FACTORY-MAKE-TARGETS.md), "Persistent controller
instance"). It is developed against the throwaway instance `rehearsal`; the
keeper instance is created only after it works. Since the owner's decision of
2026-09-30 (TASK-40) rehearsals run under **agent credential custody**: a new
throwaway instance created with `CUSTODY=agent THROWAWAY=1` carries its own
generated credentials and every step below runs unattended. `rehearsal`
predates custody and stays owner custody (custody is fixed at creation), so
the next rehearsal is a new instance; the keeper stays owner custody.

## Shape

**Installs stay on the disposable Controller; the persistent Controller serves
only joins and logins.** The Windows install never touches the domain (gate 5
uses only WinPE, private HTTP inputs and an SMB source share), and the Windows
publication writes a standalone-server `smb.conf` and refuses an existing one
(`homelab/vm/factory_publication.py`), which on an AD DC would destroy the
directory. Publishing onto the durable disk would also leave install inputs,
including the one-use local-administrator credential, on it.

For one workstation `W` bound to one persistent instance:

| Step | What happens | Owner types |
|---|---|---|
| 1. Gate-5 install | Unchanged disposable Windows install. | nothing |
| 2. Adopt | The gate-5 disk becomes a standalone `W/workstation.qcow2`; the one-use `publication.iso` is **moved** into `W`, which takes custody of it. | nothing |
| 3. Durable Arch install | Disposable Controller for PXE only; the bundle carries the permanent realm; the install-time join is deferred. | nothing |
| 4. Durable Arch join | Persistent Controller on the per-run switch; one-use join media; first-logon password change for the daily administrator; Arch `local-rescue` password set; every role resolves at its pinned UID. | Controller console password; see open questions |
| 5. Durable Windows join | Local-administrator password rotated to one the owner types, then gate 6's join unchanged. The publication is destroyed only after the fold, so a failed attempt needs no reinstall. | Controller console password; see open questions |
| 6. Keep-verify | Relaunch the persistent Controller, boot both systems, re-prove both joins (the re-authentication path). | Controller console password |

Under agent custody the owner types nothing at any step: the "Owner types"
column describes owner custody only, and the custody store supplies each value
(see [FACTORY-MAKE-TARGETS.md](FACTORY-MAKE-TARGETS.md), "Credential custody").

Each step works on an overlay; on success it is folded into `W` (standalone
copy, fsync, rename) and appended to a ledger in `W`'s marker with the disk's
SHA-256. Kept workstations live in `build/homelab/vm/workstations/<name>/`,
outside `homelab/var/factory`, which is bulk-cleaned.

## The persistent Controller on the per-run fabric

A `PersistentControllerSession` boots the instance's own disk in place under
the instance lock and connects it to the loopback switch through a socket NIC.
It keeps the instance's own MAC, because the instance's network unit matches by
MAC. It has no QMP and no media, logs in as `local-rescue` with `sudo -k`, and
stops only by a clean console poweroff: killing its QEMU is a power cut on the
directory. It has no pause or SIGSTOP method at all, so gate 6's
controller-outage faults can never reach the durable directory. The owner's
console password is typed once per run, before any process starts, held in
memory for re-login after a relaunch, and dropped when the run ends; under
agent custody it is read from the instance's custody store instead.

The binding refuses an instance whose realm, SID or declared address disagree
with the fabric. The one tolerated SID difference is a recorded value that is a
strict prefix of the live one (the split-read defect fixed in `05eec6e` left
such a value in `rehearsal`'s marker); it is repaired only on request.

## Steps

<!-- doc-make-target-drift: proposed -->
| # | Change | First live run | Code |
|---|---|---|---|
| 1 | `homelab/vm/durable_workstation.py`: the binding and realm/SID checks | none | `715147f` |
| 2 | `homelab/vm/persistent_controller_session.py` plus additive helpers | none | `7cd9d7b` |
| 3 | `make homelab-factory-persistent-probe PERSISTENT_DC=<name>`: log in, prove AD, read realm and SID, resolve SRV records, stage and destroy a join principal, clean poweroff | #1, owner, about 10 min; retires the biggest risk | `a4739c8`; **PASS 2026-09-30** on `rehearsal` (run `20260930T174246Z-3085400-ef46502e`, 20 checks) and on `rehearsal-auto` (`20260930T203222Z-4179758-a6debb5b`, agent) |
| 4 | `homelab/vm/workstation_instance.py` and `homelab-durable-workstation-{plan,status,adopt,destroy,reconcile}` | none | `a46eaee`, `6103ec9`, `a54e7c9`; adopt **PASS 2026-09-30** (`rehearsal-ws1`, `rehearsal-auto-ws1`); reconcile and destroy NOT RUN |
| 5 | Durable Arch render: skip the install-time join; the one-use join unit seals itself after `testjoin`; synthetic output stays byte-identical | none | `195ad20` |
| 6 | Durable Arch install runner and target | #0 fresh gate-5 install (about 70 min, agent), then #2 | `752879e`; **PASS 2026-09-30** twice: gate-5 #0 `run-20260930T164848Z-d51d2c1e14cd` and #0b `run-20260930T192147Z-d12679ce1b5e` (both observed, one PXE boot, 68-69 min), adopted as `rehearsal-ws1` and `rehearsal-auto-ws1`; `durable-arch-installs/run-20260930T175938Z-ec176009c2f0` (2.5 min: Windows preserved, join deferred, one PXE boot, folded) and `run-20260930T203312Z-f7163443624a` |
| 7 | Durable Arch join: expired-password exchange, pinned-UID proof, join sealed | #3, agent (`rehearsal-auto`) | `9e69258`; **PASS 2026-09-30** (agent); owner custody NOT RUN to a pass |
| 8 | Durable Windows join: owner-typed local-administrator rotation, gate 6's join, fold before destroying the publication | #4, agent | `c149566`; **PASS 2026-09-30** (agent) |
| 9 | `homelab-durable-workstation-verify`: both systems across a Controller relaunch | #5, agent | `5f5b322`; **PASS 2026-09-30** (agent) |

The disposable gates 5-8 must not change: `windows_install_run.py`,
`windows_identity_run.py` and `arch_identity_run.py` are subclassed in new
modules rather than edited, and the synthetic installer output is pinned by a
golden digest.

Step 9 and the restored-client DR proof passed against `rehearsal-auto`.
Repeat steps 1-9 against the keeper (aiq TASK-21, owner custody, with passwords
typed at the owner's terminal). The keeper has not been created. Its exact
directory setup sequence is in [FACTORY-MAKE-TARGETS.md](FACTORY-MAKE-TARGETS.md#owner-terminal-keeper-sequence-task-21).
A throwaway instance and its workstations leave together by their destroy
targets (the domain dies with the instance).

## Risks

| Risk | Mitigation |
|---|---|
| The persistent Controller on the per-run fabric: MAC-matched network unit, the gateway's source-address validation, Kerberos time after a cold relaunch, the truncated recorded SID | **Retired 2026-09-30 by live run #1**: owner-run probe PASS in 20 s of guest time -- console login, Samba live, realm agrees, interface address and gateway reachable, A and both SRV records, clock skew -2 s, one join principal staged and its destruction proved, clean poweroff, and `rehearsal`'s truncated SID repaired (`REPAIR_SID=1`). The cold relaunch itself passed in keep-verify: AD live, clock within Kerberos skew. |
| Gate-6 machinery driving Windows behind the dual-boot menu | The publication is destroyed only after the fold. |
| First-logon prompt shapes and password change across the fabric | A change that lands before a failure leaves the new password live; the retry path asks for the current password. |
| Side effects on the durable directory: leaked join principals, orphaned machine accounts from retries, gate 6's controller-side diagnostic | Destruction proofs; `destroy` lists machine accounts left behind; the diagnostic is read-only or disabled on the durable path. |
| Each fold writes a full standalone disk copy of about 20-30 GB | Check free space before a run. |

## Open questions

Decided defaults unless the owner says otherwise: first-logon changes are
driven only for the daily administrator, on Arch, and other users change
theirs at first physical logon; Arch's `ad_server` asks DNS SRV first and
names the instance's recorded DC as its fallback (owner decision 2026-09-30,
TASK-42; disks installed earlier pin the bootstrap FQDN alone);
the Arch hostname is owner-chosen and Windows keeps gate 5's generated name;
the proven temporary Domain Admin join principal is kept for `rehearsal`.
Owner decision 2026-09-30, break-glass custody: during the durable join runs
the owner types a distinct Windows local-administrator password and a
distinct Arch `local-rescue` password; the factory never stores either. That
still governs owner-custody instances (the keeper); for throwaway rehearsal
instances it is superseded by the next decision.
Owner decision 2026-09-30, credential custody (TASK-40; the owner asked why
the rehearsal needed them at the terminal at all): rehearsals run under agent
custody end to end. The harness generates every credential of a throwaway
instance -- its `local-rescue` console password, set once on the staged copy
at creation, the domain Administrator, the staged accounts, the daily
administrator's first-logon change and both break-glass passwords -- keeps
them in 0600 custody stores for the instance's life and shreds them on
destroy, the same trade-off as the one-use `publication.iso`. The keeper stays
owner custody.
Owner decision 2026-09-30, password length: short passwords, changed later,
are allowed on `rehearsal` by an explicit recorded directory policy
(`make homelab-factory-persistent-password-policy`; the owner recorded minimum
length 4, complexity off, minimum age 0; the host checks, break-glass
included, judge by it). A relaxed policy applies to every account in that
domain, so the keeper's policy is a separate decision.
Owner decisions 2026-09-30 for the keeper (TASK-21), closing what was open
here: its directory password policy is short like `rehearsal`'s (minimum 4,
complexity off, minimum age 0, set with the policy target after converge),
and its joins keep the proven temporary Domain Admin `tj-` principal, with
delegated join rights revisited before physical laptops. Backups of kept
workstation disks still do not exist.
Owner decision 2026-09-30, backups (ADR 0081): the keeper is minted only
after backup and restore of a persistent directory are built and proven.
Both are built; backup, separate-name and same-instance restore under a new DC
name, reconverge and probe PASSED live on 2026-10-01 (see
FACTORY-MAKE-TARGETS.md for the runs). The first workstation keep-verify against
the restored DC FAILED; the later run passed both systems, 40/40, after the
Samba SRV serializer repair (`bdebb4f`) and reconvergence.
`homelab-factory-persistent-backup` takes a
`samba-tool domain backup offline` over an audited raw disk, and
`homelab-factory-persistent-restore` restores it with `samba-tool domain
backup restore` into a freshly created instance, never from a disk image (see
[FACTORY-MAKE-TARGETS.md](FACTORY-MAKE-TARGETS.md), "Backing up and restoring
an instance's directory").
Owner decision 2026-09-30, DC names (ADR 0081 item 5, TASK-42): Samba restores
a DC only under a name the domain does not hold, so a restored instance runs
DC `dr-<...>`; the instance marker records that name as `dc_hostname`, and
every step below uses the recorded name (absent means `bootstrap-dc`). Kept
Arch workstations installed from now on find the DC by SRV first, with the
recorded DC as the named fallback; a workstation installed before that names
`bootstrap-dc` alone and is refused, with that reason, after a rename.

### The live proof plan for backups

On `rehearsal-auto` (agent custody, so it runs unattended), with a NEW kept
workstation whose Arch side is SRV-first (`rehearsal-auto-ws1` predates it
and cannot survive the rename): a fresh gate-5 install -> adopt -> durable
Arch install -> arch-join -> windows-join, all against `rehearsal-auto`; then
backup -> destroy `rehearsal-auto` -> restore `rehearsal-auto` (new DC name)
-> reconverge (`RECONVERGE=1`: the restored instance is a fresh canonical copy
with no network unit, and convergence skips provisioning because a directory
exists) -> probe -> keep-verify. The exact commands are in
[FACTORY-MAKE-TARGETS.md](FACTORY-MAKE-TARGETS.md), "Backing up and restoring
an instance's directory". PASS means the restored directory, under its new DC
name, serves the kept workstation's Arch and Windows logins without a rejoin.

The sequence PASSED on `rehearsal-auto-ws2`, including the final check without
rejoining either OS. Retain the restored instance, verified backup and both
failed and passing evidence; no additional destructive drill is needed to
satisfy the keeper's prerequisite.

## Live record

2026-09-30, unattended under agent custody (TASK-40, `fa8ec58`/`14b925e`) on
throwaway instance `rehearsal-auto` and kept workstation `rehearsal-auto-ws1`,
all PASSED: create (generated console credential through the one-run init
shell, which was removed and proven absent), converge (44 s), accounts (4,
change at first logon), probe (`20260930T203222Z-4179758-a6debb5b`), adopt
(gate-5 `run-20260930T192147Z-d12679ce1b5e`), durable Arch install
(`run-20260930T203312Z-f7163443624a`), durable Arch join
(`run-20260930T203553Z-4184392-be2f79e8`: first-logon change landed, sealed,
SSSD online, pinned uids), durable Windows join
(`attempt-20260930T203917Z-c67065dfe5be`: folded, publication retired) and
keep-verify (`durable-workstation-verifies/rehearsal-auto-ws1/run-20260930T210156Z-8617-9bdffc4b`,
40 of 40 checks: Arch login, `testjoin`, SSSD and pinned uids; Controller
clean poweroff and cold relaunch in-session with AD live and the clock within
Kerberos skew; Windows booted by the menu default, the daily administrator
signed in, secure channel; `BootOrder` Linux-first with the menu defaulting to
Windows). Corrected 2026-09-30, kept so it is not re-derived: this read
"Keep-verify (step 9) was not yet run".

2026-10-01, SRV-first `rehearsal-auto-ws2` under agent custody:

- Windows join `attempt-20261001T223623Z-5e1cc129efaf` PASSED, folded and
  retired the custody publication. Pre-DR keep-verify
  `run-20261001T224742Z-294135-5bf47dc6` PASSED all 40 checks.
- Native backup `20261001T225428Z-323971-342a3f27` was verified. The original
  `rehearsal-auto` was destroyed and restored under the same instance name,
  with new DC name `dr-2610012255`, in
  `20261001T225520Z-327126-e82e02db` (PASS). Reconvergence PASSED, followed by
  probe `20261001T225659Z-328973-facea8fe` (PASS).
- Post-DR keep-verify `run-20261001T225740Z-329731-9a00cfd1` FAILED: Arch
  SSSD remained offline despite a working machine TGT and LDAP. An unexplained
  SIGTERM during the Controller relaunch then prevented Windows verification.
  At that checkpoint the cause was under diagnosis; the failed run remains
  evidence, and neither OS was rejoined.
- Samba emitted compressed SRV Targets that strict clients rejected. Repair
  `bdebb4f` preserves internal DNS and scopes the verified serializer library
  to `samba.service`. Restored-DC reconvergence then passed all four strict
  LDAP/Kerberos UDP/TCP probes.
- Post-repair keep-verify `run-20261001T235410Z-588718-de077620` PASSED all
  40 checks against the restored DC. Both systems passed without a rejoin;
  the kept disk, firmware variables and marker were unchanged, no overlay
  was folded and no ledger entry was added, and teardown was clean. The
  first Windows boot stalled after 72,192 read bytes in 33 operations, with
  zero writes and a pristine overlay. The existing bounded cold-boot retry
  passed; `fabric/windows-boot-attempt-1.json` records the first attempt.
  This is not a firmware-fix claim.

Full evidence paths are in [FACTORY-MAKE-TARGETS.md](FACTORY-MAKE-TARGETS.md),
"Backing up and restoring an instance's directory". The earlier ordinary
keep-verify passes and the failed recovery attempt retain their original
verdicts. The new passing run closes TASK-41/TASK-42. The separate WinPE VBS
run (`8eb69a9`), `windows-installs/run-20261001T235652Z-a782e2f67fac`,
finished at 2026-10-02 01:17 UTC with runner exit 0 and
`observed` / `native-windows-clean-shutdown`. Its release is `20260727.005`,
prepared before resealing, and its publication remains unconsumed for the
keeper. Its complete capture plus Arch run `run-20261001T193550Z-e5108779aad1`
passed all four gate-4 checks (TASK-43 DONE). Gate 12's fresh repeat
`20261002T011915Z-907070-repeat` started at 01:19:15 UTC from `93eb6b6` on
selected release `20261001.001`. At the 16:52 UTC checkpoint, it has finished
with final receipt FAIL, `equivalent: false`, zero retries. Iteration 1 failed
15 pass / one fail on `host_network_changes.listener=1`; discarded snapshots
prevent exact attribution. Iteration 2 passed 15 checks with only the ADR 0080
UniFi waiver, no fail/not-run and all six local network counters zero. Both
gate-4 audits passed. Recovery `20261002T053117Z-1175062-repeat` from
`7e4c72c` reused accepted iteration 2 but stopped about 06:39 UTC with exit 2
and no final comparison receipt. Windows `run-20261002T053119Z-97daa1c63993`
failed `pxe-loop` after OVMF reported Windows Boot Manager `Not Found`; its
permitted retry `run-20261002T063837Z-3c2cd155d481` failed an immediate
process audit that saw `python3` immediately after launch. No VMs remained after that run.
Original evidence hashes still match. Only the two failed bundles'
`publication.iso` files were retired; their disks, firmware variables, results
and logs remain. The process-audit fix is committed as `c45c0dc`. Recovery
`20261002T114212Z-1294100-repeat` ran from 11:42:12 to 13:47:15 UTC, reusing
the accepted original iteration at the same pins. Both cycles completed all
six functional phases, but the final comparison is **FAIL**,
`equivalent: false`, zero retries. The fresh cycle passed 15 aggregate checks
and failed only on `host_network_changes.route=4`; the other five local
counters are zero, forwarding by privilege proof, and UniFi remains unproven.
Raw before/after diagnostics retain one automatic IPv6 router-advertisement
ECMP next-hop replacement, counted in both all-table route views as four
old/new entries. That failure stands; its supervisor and driver stopped with
exit 2. Third strict recovery `20261002T143757Z-1346697-repeat` ran from
14:37:57 to 16:41:30 UTC from `011e678`, reusing unchanged accepted original
iteration 2 plus one fresh cycle. It finished **PASS-WITH-WAIVER**,
`equivalent: true`, zero retries: each cycle passed 15 checks with only the
ADR 0080 UniFi waiver and all four gate-4 checks. The fresh cycle's six local
network counters are zero; independent comparison agrees. Gate 12 is closed
for phase one and TASK-6 is done. Supervisor exit 0 and teardown are verified,
with no QEMU or repeat driver remaining. No route-policy exception was needed
or approved. Exact receipts, source fingerprints and diagnostic paths are in
[the repeat driver](FACTORY-MAKE-TARGETS.md#the-repeat-driver). The keeper
remains absent; TASK-21 is blocked solely on owner-terminal passwords. Its
reserved Windows publication is unconsumed, and the owner
availability question unanswered. Credentials must be typed at the owner's
terminal after verifying the lab is idle; only one live lane may run at a time.

Owner custody on `rehearsal`: probe PASS (above), password policy recorded,
adopt and durable Arch install PASS on `rehearsal-ws1`. The owner-run
arch-join stopped at first login: `Login incorrect` with no expired-password
notice means the typed temporary password was not the staged one, and the
directory was unchanged. `RESTAGE=1` cannot help (staging is create-only and
refused with `account-exists`, harmlessly); the reset is
`homelab-factory-persistent-account-password`. `rehearsal-ws1` remains at
stage `arch-install`.

Only one disposable Controller simulation runs at a time (the canonical
image's `.simulation.lock`: "another controller simulation is already
running"), so plan gate-5 installs, durable Arch installs and gate 11/12 runs
serially.
