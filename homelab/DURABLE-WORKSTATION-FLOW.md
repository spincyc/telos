# Durable workstation flow (TASK-28)

Status: approved design; all nine steps implemented and **PROVEN LIVE END TO
END** 2026-09-30, unattended under agent custody on the throwaway instance
`rehearsal-auto` (see "Live record"). TASK-28 is done; the keeper is aiq
TASK-21. Under owner custody steps 7-9 have not passed (`rehearsal-ws1` stays
at stage `arch-install`).

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

Step 9 passed against `rehearsal-auto`. Next, repeat steps 1-9 against the
keeper (aiq TASK-21, owner custody); a throwaway instance and its workstations
leave together by their destroy targets (the domain dies with the instance).

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
theirs at first physical logon; Arch's `ad_server` pins the bootstrap FQDN;
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
Still open with the owner, and blocking the keeper (TASK-21): its directory
password policy, backups (none exist for persistent instances or kept disks),
and join-principal privilege.

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
