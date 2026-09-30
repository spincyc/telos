# Durable workstation flow (TASK-28)

Status: approved design; steps 1-8 implemented and unit-tested 2026-09-30,
step 9 in progress. Nothing here has run live; each step says when it first
needs a live run.

Every workstation runner today wraps the Controller in `DisposableBootDisk`,
and every run provisions a brand-new domain, so a minted workstation dies with
its run. This flow mints a workstation you keep: Windows and Arch on one disk,
joined to a **persistent** Controller instance (see
[FACTORY-MAKE-TARGETS.md](FACTORY-MAKE-TARGETS.md), "Persistent controller
instance"). It is developed against the throwaway instance `rehearsal`; the
keeper instance is created only after it works.

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
memory for re-login after a relaunch, and dropped when the run ends.

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
| 3 | `make homelab-factory-persistent-probe PERSISTENT_DC=<name>`: log in, prove AD, read realm and SID, resolve SRV records, stage and destroy a join principal, clean poweroff | #1, owner, about 10 min; retires the biggest risk | `a4739c8`; **PASS 2026-09-30** (run `20260930T174246Z-3085400-ef46502e`, 20 checks) |
| 4 | `homelab/vm/workstation_instance.py` and `homelab-durable-workstation-{plan,status,adopt,destroy,reconcile}` | none | `a46eaee`, `6103ec9`, `a54e7c9` |
| 5 | Durable Arch render: skip the install-time join; the one-use join unit seals itself after `testjoin`; synthetic output stays byte-identical | none | `195ad20` |
| 6 | Durable Arch install runner and target | #0 fresh gate-5 install (about 70 min, agent), then #2 | `752879e`, NOT RUN |
| 7 | Durable Arch join: expired-password exchange, pinned-UID proof, join sealed | #3, owner | `9e69258`, NOT RUN |
| 8 | Durable Windows join: owner-typed local-administrator rotation, gate 6's join, fold before destroying the publication | #4, owner | `c149566`, NOT RUN |
| 9 | `homelab-durable-workstation-verify`: both systems across a Controller relaunch | #5, owner | in progress |

The disposable gates 5-8 must not change: `windows_install_run.py`,
`windows_identity_run.py` and `arch_identity_run.py` are subclassed in new
modules rather than edited, and the synthetic installer output is pinned by a
golden digest.

After step 9 passes against `rehearsal`, destroy `W` together with `rehearsal`
(its domain dies with it) and repeat steps 1-9 against the keeper.

## Risks

| Risk | Mitigation |
|---|---|
| The persistent Controller on the per-run fabric: MAC-matched network unit, the gateway's source-address validation, Kerberos time after a cold relaunch, the truncated recorded SID | **Retired 2026-09-30 by live run #1**: owner-run probe PASS in 20 s of guest time -- console login, Samba live, realm agrees, interface address and gateway reachable, A and both SRV records, clock skew -2 s, one join principal staged and its destruction proved, clean poweroff, and `rehearsal`'s truncated SID repaired (`REPAIR_SID=1`). |
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
distinct Arch `local-rescue` password; the factory never stores either.
Still open with the owner: backups for the keeper directory and kept disks,
and join-principal privilege for the keeper.
