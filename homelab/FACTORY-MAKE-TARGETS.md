# Workstation factory Make contract

Document version: `20261001.001`

Status: partly implemented. Targets marked **implemented** exist in the Makefile
today and were verified against `grep -n '^homelab-' Makefile` on 2026-08-17
(re-verified after `f8d0348`, and again on 2026-09-24 against `0e588db`).
Targets marked **reserved** do not exist; the local per-gate lifecycle that
actually runs is a separate, real set of targets — see
[Implemented per-gate lifecycle](#implemented-per-gate-lifecycle), which is the
contract to read before running anything. Do not attach placeholder recipes that
report success, and do not assume a reserved aggregate name works.

## Reproducibility boundary

The factory has two deliberately separate phases:

1. **Acquire** may use the Internet. It installs build-host dependencies and
   imports freshly resolved, verified Arch, Windows, and `wimboot` media into
   ignored local cache.
2. **Build and exercise** must work with the host network unavailable. It
   builds immutable releases, converges disposable guests, installs both
   operating systems, runs acceptance checks, recovers, destroys, and repeats.

`make` must never pull or update the checkout that is currently executing.
The public fresh-clone cycle belongs in a wrapper target which clones into a
new disposable directory, records the requested Git ref and resolved commit,
and invokes the ordinary targets there. Generated media, VM disks, credentials,
and evidence remain ignored and must never be required from Git.

Every mutating or destructive target is a dry run unless `APPLY=1` is supplied.
Disk-erasing targets additionally require a stable target identifier and an
exact confirmation value. Verification targets must distinguish `PASS`,
`FAIL`, and `NOT RUN`; a planned assertion is never a pass.

This vocabulary binds the DOCUMENTATION too, not only the targets. A gate's
recorded verdict in any homelab document is `PASS`, `FAIL`, `NOT RUN`, or —
where a judge itself renders it — `PARTIAL`, always with a scope note naming
what is and is not covered. Hedged prose verdicts ("advanced", "complete-ish",
"proven/advanced", "complete-ish (see state doc)") are not permitted: they hide
which half of a gate is unproven. When a gate is half-proven, write both halves
explicitly, e.g. "PASS (Windows) / NOT RUN (Arch)".

## Target graph

| Stage | Target | Status | Contract |
|---|---|---|---|
| Host | `homelab-factory-deps` | **implemented** | Install/check the complete Arch build-host dependency set. Online; explicit operator action. |
| Acquire | `homelab-factory-media` | **implemented** | Fresh-resolve Arch and `wimboot`; import the operator-supplied Windows ISO; emit one aggregate receipt. Online or local import. Delegates to `homelab-media`. |
| Seal | `homelab-factory-cache-seal` | **implemented** | Verify every cached input, record hashes and tool versions, and produce a portable inventory. No downloads. |
| Offline gate | `homelab-factory-offline-check` | **implemented** | Refuse absent/unsealed inputs and prove subsequent recipes have no download dependency. |
| Controller | `homelab-factory-controller` | **reserved** | Create a disposable controller overlay and converge PXE/HTTP, Samba AD DNS, Kerberos/time, logging, backup, and restore. The bundle half exists as **`homelab-factory-controller-bundle`** (implemented); the live runners converge the controller themselves. |
| Releases | `homelab-factory-pxe` | **implemented** | Build and verify immutable controller, Windows, and Arch releases using one `YYYYMMDD.NNN` release identifier. |
| Authority | `homelab-factory-authority-check` | **reserved — but implemented under another name** | Prove the simulated gateway is the only DHCP authority and no guest can reach a host or external network. This exists today as **`homelab-pxe-authority-audit SWITCH=…`** (implemented, read-only, renders `VERDICT PASS`/`FAIL`) and is wired into `homelab-factory-verify` as a distinct gate. Prefer the real name; do not implement a second one. |
| Windows | `homelab-factory-windows` | **reserved** | PXE-boot and install Windows 11 Pro first; reboot without installation media; join the synthetic domain and test login/recovery. Really performed by the per-gate `homelab-windows-install-*` and `homelab-windows-identity-*` targets below. |
| Arch | `homelab-factory-arch` | **reserved** | PXE-boot and install Arch second while preserving Windows and recovery partitions; join the same domain. Really performed by the per-gate `homelab-arch-install-*` and `homelab-arch-identity-*` targets below. |
| Dual boot | `homelab-factory-dualboot-check` | **reserved** | Cold-boot both systems and measure partition, EFI, boot-default, login, update, storage-failure, and recovery contracts. Really performed by `homelab-dualboot-acceptance-*` below. |
| Acceptance | `homelab-factory-verify` | **implemented** | Validate all retained evidence and produce a machine-readable final receipt. Never performs installation. |
| Recovery | `homelab-factory-recover` | **implemented** | Exercise release rollback, controller reconstruction, failed-install recovery, boot repair, and workstation remint. Graded by **`homelab-factory-recover-judge RECOVERY_EVIDENCE=…`** (implemented). Ran live 2026-10-01: `partial`, five pass, the three ADR 0080 deferrals (see [Lifecycle recovery's live hooks](#lifecycle-recoverys-live-hooks)). |
| Cleanup | `homelab-factory-clean` | **reserved** | Remove only the named disposable run after exact confirmation; preserve sealed media unless separately requested. |
| Repeat | `homelab-factory-repeat` | **implemented** (`27d8af9`, `2aaa7fe`) | Run the complete sealed-input lifecycle at least twice from destroyed disposable state and compare receipts. Aggregates every phase bundle into one receipt, because no single phase can carry gate 12. Dry run is read-only; see [The repeat driver](#the-repeat-driver). **In progress** — no live iteration has completed all six phases yet. |
| Fresh clone | `homelab-factory-fresh-clone` | **reserved** | Clone the public repository into a disposable directory, resolve and record the commit, acquire/import inputs, then invoke the same lifecycle. |

Seven names in the table above do not exist in the Makefile:
`homelab-factory-{controller,authority-check,windows,arch,dualboot-check,clean,fresh-clone}`.
`make` will fail with "No rule to make target". Two of the seven have real
substitutes already implemented under different names
(`homelab-factory-controller-bundle`, `homelab-pxe-authority-audit`).

Corrected 2026-08-17: this list read *eight* and included
`homelab-factory-repeat`, which `27d8af9` implemented. The count is now seven.

## Implemented per-gate lifecycle

This is what actually runs today, gate by gate. Every name below was verified
present in the Makefile on 2026-08-17. Each mutating target needs `APPLY=1`.

| Gate | Targets | Required variables |
|---:|---|---|
| 4 | `homelab-pxe-authority-audit` | `SWITCH=<run>/evidence/switch.jsonl` |
| 5 | `homelab-windows-install-prepare`, `homelab-windows-install-run` | `WINDOWS_RUN=<bundle>`, `FACTORY_DURATION=` |
| 6 | `homelab-windows-identity-prepare`, `homelab-windows-identity-run`, `homelab-windows-identity-judge` | `WINDOWS_RUN=`, `WINDOWS_IDENTITY_ATTEMPT=`, `FACTORY_CONTROLLER_STATE=`, `WINDOWS_IDENTITY_EVIDENCE=` |
| 7 | `homelab-arch-install-prepare`, `homelab-arch-install-run` | `WINDOWS_RUN=<a Windows install bundle>/windows.qcow2` — the disk file; unlike gates 5–6, a bundle directory is refused at `APPLY=1` |
| 8, 9 (Arch half) | `homelab-arch-identity-prepare`, `homelab-arch-identity-run`, `homelab-arch-identity-judge` | `ARCH_RUN=`, `WINDOWS_IDENTITY_EVIDENCE=` (consumed via `--windows-evidence`), `ARCH_IDENTITY_BUNDLE=`, `ARCH_IDENTITY_EVIDENCE=` |
| 10 | `homelab-dualboot-acceptance-prepare`, `homelab-dualboot-acceptance-run`, `homelab-dualboot-acceptance-judge` | `DUALBOOT_EVIDENCE=` |
| 11 | `homelab-factory-recover`, `homelab-factory-recover-judge` | `RECOVERY_RUN=`, `RECOVERY_BOOT=`, `IDENTITY_BUNDLE=`, `FACTORY_CONTROLLER_STATE=`, `RECOVERY_EVIDENCE=` (see [Lifecycle recovery's live hooks](#lifecycle-recoverys-live-hooks)) |
| 3 (bundle) | `homelab-factory-controller-bundle` | — |
| 12 | `homelab-factory-repeat`, `homelab-factory-verify` | `REPEAT_EVIDENCE_ROOT=`, `REPEAT_WORK_ROOT=`, `REPEAT_ITERATIONS=`, `REPEAT_RECEIPT=`, `FACTORY_DURATION=` (see [The repeat driver](#the-repeat-driver)); `homelab-factory-verify` remains the per-bundle comparator |

Gate 9 deliberately has no target of its own: its `optional-storage` checks are
graded inside the gate-6 and gate-8 identity acceptances.

Every `*-judge` target is read-only and prints one JSON verdict object. Read the
whole object, not just `result`: a judge may render `result: pass` while also
naming `deferred` and `out_of_scope` checks, and `homelab-factory-recover-judge`
renders `result: partial` whenever any scenario deferred.

The intended aggregate graph, annotated with what really implements each step:

```text
deps -> media -> cache-seal -> offline-check           (all implemented)
                              |
                              v
controller-bundle -> pxe -> pxe-authority-audit        (implemented; the
                         |                              reserved names are
                         |                              controller / authority-check)
                         v
windows-install-{prepare,run} -> windows-identity-{prepare,run,judge}
                         |
                         v
arch-install-{prepare,run} -> arch-identity-{prepare,run,judge}
                         |
                         v
dualboot-acceptance-{prepare,run,judge}
                         |
                         v
verify -> recover -> recover-judge -> [clean] -> repeat
                                       ^-- clean is reserved and absent;
                                           repeat is implemented, live run
                                           in progress
```

### Lifecycle recovery's live hooks

Gate 11's two live hooks, `directory-dns-loss` and `controller-reconstruction`,
run only with `RECOVERY_BOOT=1` and `IDENTITY_BUNDLE=` naming a gate-8 bundle
that `homelab-arch-identity-prepare` made and nothing has executed; an executed
bundle does not serve. The Controller state defaults to the canonical image
`build/homelab/vm/bootstrap-dc`, as every other runner's does
(`FACTORY_CONTROLLER_STATE=` overrides); the directory/DNS-loss hook primes the
SSSD cache with one online standard-user login before freezing the Controller,
as gate 8 does. Both passed live 2026-10-01 (ledger gate 11). Corrected
2026-10-01 (`3fb969e`, `668b524`), kept so it is not re-derived: the default
named `homelab/var/controller`, which never existed, so both hooks always
deferred, and with no prior online login nothing was cached for the outage to
test.

## The repeat driver

`homelab-factory-repeat` (`27d8af9`, wired into the Make contract by `2aaa7fe`)
is gate 12's aggregate driver. No single phase bundle can reach gate 12 on its
own — install order needs both installs in one list and the login checks need
both operating systems in one receipt — so the driver runs the phases in order
and assembles one union receipt from their bundles.

```sh
make homelab-factory-repeat                       # read-only dry run
make homelab-factory-repeat APPLY=1               # runs the lifecycle
```

| Variable | Default | Meaning |
|---|---|---|
| `REPEAT_EVIDENCE_ROOT` | `homelab/var/factory/repeat` | Where the aggregate bundle of each iteration is written. |
| `REPEAT_WORK_ROOT` | `homelab/var/factory/repeat-work` | Disposable work root, destroyed before each iteration. |
| `REPEAT_ITERATIONS` | `2` | Gate 12 requires at least 2. |
| `REPEAT_RECEIPT` | unset | Optional path for the comparison receipt. |
| `FACTORY_DURATION` | `120` | Forwarded to each phase as its **per-phase** budget, not a whole-run budget. |
| `FACTORY_RELEASES` | unset | Optional release set; the dry run reports `homelab/var/pxe`. |

**`FACTORY_DURATION`'s 120-second default is far too small for a real
lifecycle.** A single Windows install alone has run 68 minutes. Whatever value
is supplied applies to *every* phase, so budget per phase and expect the
apply path to take hours, not minutes.

One bounded retry: a `windows-install` that fails with its live-detected PXE
loop (`failure_category: "pxe-loop"`) is re-run once from a fresh bundle — any
other failure, phase, or a second loop fails the iteration — and each retry is
listed under `retries` in the iteration's `result.json`, the repeat receipt,
and stderr.

The dry run starts nothing and is safe at any time. Verified 2026-08-17 it
prints the loopback boundary, the iteration count, both roots, the release set,
the six lifecycle phases in order — `windows-install`, `windows-identity`,
`arch-install`, `arch-identity`, `dualboot-acceptance`, `lifecycle-recovery`,
each naming the Make target that really runs it — the four producer
measurements now available (`host_network_changes`, `login`,
`optional_storage_absence_nonblocking`, `artifact_scan`), and any precondition
that would refuse. Against a never-installed canonical image it refuses, naming
the remedy; this is what it printed until 2026-09-24:

```text
! refuses to apply: canonical Controller image …/bootstrap-dc.qcow2 is not an
  installed Controller: the image is entirely unallocated; nothing has ever
  been written to it. No live lifecycle can run against it; run
  `make homelab-bootstrap-vm-install` first
```

That refusal reads the actual partition table through `controller_image.probe`
and is fail-closed, so a partially written disk over a size floor does not
satisfy it. Since the canonical image was installed on 2026-09-24 the dry run no
longer refuses.

Verdict: **in progress, no result yet.** The first live twice-through
(`FACTORY_DURATION=7200`, started 2026-09-30T23:28Z) passed iteration 1's
phases 1-4 and failed `dualboot-acceptance`: a gate-7 disk's join-once and
domain-online units hold the Arch getty about 240 s, past the dual-boot
runner's old fixed 120 s login wait, which `f8f0443` now derives from those
bounds (420 s). The second started 2026-10-01T01:53Z. Until an iteration
completes all six phases, what is proven is that the aggregation is
deterministic, not that two real lifecycles agree. Corrected 2026-10-01: this
read NOT RUN, its only live execution the accidental unit-suite launch of
2026-09-24 (fixed by `272d693`; see `HANDOFF.md` §5).

## Installing the canonical Controller image

`homelab-bootstrap-vm-install` (`7b29624`) drives the interactive offline
installer against the canonical Controller disk over the serial console, which
was previously a long hand-driven console session. ADR
[0058](decisions/0058-pty-driven-acceptance-testing.md) sanctions exactly this:
it forbids an unattended path *inside* the installer and prescribes driving the
interactive one externally, answering prompts as a person would.

```sh
make homelab-bootstrap-vm-install \
    ISO=homelab/var/media/arch/archlinux-x86_64.iso \
    SEED_ISO=homelab/var/seed/telos-controller-seed.iso          # dry run

make homelab-bootstrap-vm-install APPLY=1 \
    CONFIRM='<the erasure phrase the installer asks you to type>' \
    ISO=homelab/var/media/arch/archlinux-x86_64.iso \
    SEED_ISO=homelab/var/seed/telos-controller-seed.iso          # installs
```

The two answers that matter stay the operator's. `CONFIRM` carries the erasure
phrase and is relayed verbatim — the driver holds neither the phrase nor the
disk serial, asserted against its own source — and the new `local-rescue`
console password is read twice by `getpass` at the controlling terminal, never
from a file, argv, an environment variable, or a Make variable. `SEED_ISO` is
required and the target exits 2 without it; `APPLY=1` without `CONFIRM` exits 2.

The guards are the point. It refuses to run as root, a symlinked or
mis-permissioned state directory, a manifest whose serial or format is wrong, a
disk any process holds open, an argv naming the serial anything but exactly
once, an argv carrying a network device, a missing controlling terminal,
mismatched password entries, and a guest that claims success on a disk that
still does not probe as installed. Above all it refuses a disk that is not
byte-identical to a freshly created qcow2 of the declared size, with the
reference generated by the local `qemu-img` at run time — so it can erase the
empty image it is meant to erase and never a working Controller.

Verdict: **PASS — one live run, 2026-09-24.** The owner's run was the target's
first, and it succeeded first time: all 19 console events from the archiso login
through `console-password-updated`, `installation-complete` and
`poweroff-observed`; QEMU exit 0; a GPT with two partitions (one ESP) and
2,539,716,608 bytes allocated; receipt
`build/homelab/vm/bootstrap-dc/install-receipt.json` (`installed_utc`
`2026-09-25T01:30:06Z`). One run on this host is the whole scope of that pass.
Corrected 2026-09-24: this verdict read NOT RUN. The manual console recipe in
[`homelab/vm/README.md`](vm/README.md) ("Interactive offline installation")
remains documented as the fallback. **Losing the `local-rescue` password still
costs the whole image** — root is locked, there is no authorized key, no init
shell, and SSH password authentication is off, so nothing in this repository
can open an image whose console password is gone.

`homelab-bootstrap-vm-status` reads the install receipt and now distinguishes
"created but not installed" from "ready", and exits non-zero on the former.
Since 2026-09-24 it reports `ready`.

## Grading a candidate image's declared services

`homelab-image-service-gate` (`0c2df66`) grades a booted candidate image's
declared systemd services against the tracked contract, from a retained guest
console transcript. It is a pure host-side judge: no guest, no root, no QEMU,
and no registry override.

```sh
make homelab-image-service-gate \
  IMAGE_PROFILE=<installer-live|controller-seed|workstation-install> \
  IMAGE_TRANSCRIPT=<retained guest console capture> \
  [IMAGE_SERVICE_TOKEN=<run token>] [IMAGE_SERVICE_EVIDENCE=<output path>]
```

`IMAGE_PROFILE` and `IMAGE_TRANSCRIPT` are both required; the target exits 2
without either. The transcript is a token-scoped, line-anchored marker frame
rather than JSONL, because `ttyS0` interleaves kernel messages with program
output at arbitrary byte boundaries; a framed line either matches whole or is
refused, and the frame carries its own record count so a truncated capture is
distinguishable from a short one. An undeclared but enabled unit degrades the
verdict to `partial` and is named rather than failing outright; only `pass` may
be read as "services verified".

**The live capture half does not exist.** Producing the transcript needs a
booted candidate image, which needs root, so the judge is available today and
the capture is the blocked half. This is the same split both identity gates
already use. Verdict for the pair: judge **implemented**, capture **BLOCKED**,
and `services_verified` therefore **NOT RUN**.

## Persistent controller instance (not a gate)

Eight further targets exist in the Makefile and belong to no gate. They run a
**persistent** directory server — one whose `/var/lib/samba` survives a
bring-up — beside the disposable acceptance controller. No acceptance target
references them, and nothing here runs unless `PERSISTENT_DC` names an instance:
persistence must be asked for by name and is never inferred. Corrected
2026-09-24: this read *six*; `73dbd2b` added the two durable-account targets.

| Target | Mutates | Contract |
|---|---|---|
| `homelab-factory-persistent-plan` | no | Read-only. Prints what a bring-up would do for `PERSISTENT_DC`. |
| `homelab-factory-persistent-status` | no | Read-only. Reports whether the instance exists, whether its directory is provisioned, the directory password policy it records (Samba's default when none), the latest recorded password reset of each staged account, by contract role, and its latest Samba backup and any restore (ADR 0081); for an agent-custody or throwaway instance, also its credential custody (never a value). |
| `homelab-factory-persistent-up` | `APPLY=1` | Creates the instance from the canonical image when absent (read-only against the canonical, under the same strict fence the disposable path uses), then boots it **in place**. A second bring-up reuses the disk rather than re-seeding it, which is what makes the directory durable. Since `7b29624` it **refuses an uninstalled canonical image** instead of silently seeding an instance from a blank disk. With `CUSTODY=agent THROWAWAY=1` (TASK-40) it instead creates a throwaway instance under agent credential custody and leaves it powered off; see "Credential custody" below. |
| `homelab-factory-persistent-converge-plan` | no | Read-only plan for the provisioning step. |
| `homelab-factory-persistent-converge` | `APPLY=1` | Provisions Active Directory into the instance in place, over the `local-rescue` console password typed at the operator's terminal. Long-running; prompts for credentials interactively and writes none of them to a file, a Make variable, an environment variable, or argv. Since `7b29624` it **checks the canonical image before it prompts**, so an uninstalled source no longer costs you the unrecoverable console password first, and a retried convergence only asks for a new Administrator password when provisioning was actually attempted. |
| `homelab-factory-persistent-accounts-plan` | no | Read-only plan for staging the owner's durable account roster (`73dbd2b`): roster source and fingerprint, each contract role with its `uidNumber`/`gidNumber` (never the real names), and the privilege separation. It refuses before printing anything if the private roster — `homelab/instance/identity/principals.json`, or `IDENTITY_OVERLAY` — is missing, unreadable, or does not itself name all three directory roles, and it refuses an instance that does not exist or holds no converged directory. |
| `homelab-factory-persistent-accounts` | `APPLY=1` | Stages that roster into the converged instance **over the serial console**, the only channel that reaches a simulated persistent instance: its only NIC is a QEMU socket netdev to the userspace gateway, with no route to the host LAN, so host-side Ansible cannot reach it. Prompts at the terminal for the `local-rescue` password and one password per directory role; none reaches a file, argv, an environment or Make variable, the instance marker, or a transcript. The daily administrator never joins Domain Admins. After a completed or an unfinished staging run it refuses unless `RESTAGE` is set. |
| `homelab-factory-persistent-destroy` | `APPLY=1` + `CONFIRM='DESTROY <name>'` | Disk-erasing: deletes a real directory server, so it needs the stable instance name and the exact confirmation carrying that name. An agent-custody instance's credential store is shredded first. |

**Every one of the eight requires `PERSISTENT_DC=<instance name>`** and exits 2
without it. `PERSISTENT_DC` has no default.

Fixed 2026-08-17 (`7b29624`): the six recipes that then existed emitted
`--state-dir` *after* the subcommand, so every persistent target died for anyone
who set `FACTORY_CONTROLLER_STATE`. The option now precedes the subcommand in all
eight, and `homelab/tests/test_factory_make_targets.py` feeds every generated
recipe, on both sides of its `APPLY` gate, through the real parser.

| Variable | Default | Meaning |
|---|---|---|
| `PERSISTENT_DC` | *(none; required)* | Stable instance name. Instances resolve under `PERSISTENT_DC_ROOT` and the name is validated, so the canonical acceptance state is unreachable as a persistent target. |
| `PERSISTENT_DC_ROOT` | `build/homelab/vm/persistent-dc` | Parent directory of every persistent instance. |
| `RECONVERGE` | unset | Required to converge an instance a **second** time; without it a convergence never re-runs. |
| `PERSISTENT_CONVERGE_TIMEOUT` | unset | Overrides the convergence's own long in-guest bound, in seconds. |
| `DIRECTORY_IDENTITY` | unset | Optional permanent directory identity document for the converge targets; unset, it resolves `homelab/instance/identity/directory.json`. The durable path refuses to inherit the acceptance realm. |
| `IDENTITY_OVERLAY` | unset | Optional private roster for the account targets; unset, it resolves `homelab/instance/identity/principals.json`. It carries names, never a credential. |
| `RESTAGE` | unset | Required to stage accounts again after a completed or an unfinished staging run. Staging is create-only: it stops with `account-exists` on the first account the directory already holds, so it never resets a password. `homelab-factory-persistent-account-password` is the reset. |
| `PERSISTENT_ACCOUNTS_TIMEOUT` | unset | Overrides the in-guest bound on the account staging program, in seconds (600 by default). |
| `CHANGE_AT_FIRST_LOGON` | unset | `1` makes the typed passwords TEMPORARY: each account must change its password at its first logon, the host skips its policy pre-check, and the in-guest program lifts the domain password policy only while creating the accounts, then restores and proves it. Without it every typed password must already meet the instance's directory password policy -- the one `-password-policy` recorded, else Samba's default (7 characters, 3 classes) -- checked before anything boots. |
| `SEED_ISO` | unset | Optional seed ISO for bring-up and convergence. |
| `CONFIRM` | unset | `DESTROY <instance name>`, required by `-destroy`. |
| `REPAIR_SID` | unset | `1` lets `-probe` complete a recorded domain SID that is a strict prefix of the live one, after a passing probe. Any other difference is refused. |
| `CUSTODY` | unset (owner) | Read only by `-up` (and `-plan`) when it **creates** an instance: `owner` or `agent`. Recorded in the marker and never changed; asking an existing instance for another custody is refused. `agent` requires `THROWAWAY=1`. |
| `THROWAWAY` | unset | `1` (and only `1`; anything else exits 2) records the new instance as a throwaway rehearsal instance. |

`FACTORY_DURATION` is deliberately **not** reused on this path: its 120-second
default would abort a Samba provisioning run. Verdict: `-converge` and
`-accounts` are **PASS**, owner custody on `rehearsal` 2026-09-25 and agent
custody on `rehearsal-auto` 2026-09-30 (converge 44 s; four accounts, change
at first logon); `-up` **PASS 2026-09-30** with `CUSTODY=agent THROWAWAY=1`
only (under owner custody `-converge` seeds the instance itself). `RESTAGE=1`
over existing accounts ran once on `rehearsal` and stopped with
`account-exists` as documented, writing nothing. `-destroy`, `RECONVERGE=1` and
`-up` under owner custody are **NOT RUN**. See "The persistent directory
instance" in [docs/operator-runbook.md](docs/operator-runbook.md).

### Probing an instance on the per-run fabric (TASK-28)

A ninth target, added 2026-09-30 as step 3 of
[DURABLE-WORKSTATION-FLOW.md](DURABLE-WORKSTATION-FLOW.md). Like the eight
above it requires `PERSISTENT_DC`, and it is a dry run unless `APPLY=1`.

| Target | Mutates | Contract |
|---|---|---|
| `homelab-factory-persistent-probe` | `APPLY=1` | The dry run binds the instance and prints the plan; nothing starts. Binding refuses unless the recorded realm, DNS domain and NetBIOS name match `homelab/instance/identity/directory.json` (or `DIRECTORY_IDENTITY`), the declared Controller address, prefix and gateway are the per-run fabric's, and the staged roster fingerprint is current; values are compared, never printed. `APPLY=1` asks once for the `local-rescue` password, before any process starts, then boots the instance's own disk in place under its lock (its own MAC; no QMP, no medium, no pause) on a per-run loopback switch and gateway with no workstation. It proves samba live, reads the realm and domain SID, checks the interface address, the gateway, the A and SRV records and the clock skew, stages and destroys one `tj-` join principal, and powers off over the console. Evidence lands in `homelab/var/factory/persistent-probe/<instance>/<run id>/`: a redacted console transcript, `switch.jsonl`, `fabric.log` and a `result.json` of secret-free checks. |

With `REPAIR_SID=1`, a recorded domain SID that is a strict prefix of the
live one (the split-read truncation fixed in `05eec6e`) is completed in the
marker, and only after a passing probe. Any other difference is a different
directory and is refused before anything is written to it. Verdict:
**PASS 2026-09-30**, owner-run against `rehearsal` with `REPAIR_SID=1` (run
`20260930T174246Z-3085400-ef46502e`): all 20 checks, clock skew -2 s, the
join principal's destruction proved, clean poweroff, and the truncated
recorded SID completed in the marker; and unattended under agent custody
against `rehearsal-auto` (run `20260930T203222Z-4179758-a6debb5b`, clock skew
-1 s).

### Setting an instance's directory password policy (TASK-28)

A tenth target, added 2026-09-30 because the owner wants short passwords on
the throwaway `rehearsal` that can be changed later, and Samba's default
policy (7 characters, 3 character classes, a 1-day minimum age) refuses them.
It requires `PERSISTENT_DC`, `MIN_PASSWORD_LENGTH` (1-14; Samba's maximum is
14) and `PASSWORD_COMPLEXITY` (`on` or `off`), none of which has a default,
and it is a dry run unless `APPLY=1`. Implemented by
`homelab/vm/persistent_password_policy.py`; the policy value lives in
`homelab/vm/directory_password_policy.py`.

| Target | Mutates | Contract |
|---|---|---|
| `homelab-factory-persistent-password-policy` | `APPLY=1` | The dry run binds the instance as `-probe` does, prints the policy the marker records (Samba's default when none), the requested one and the change, and starts nothing. `APPLY=1` asks once for the `local-rescue` password, before any process starts, boots the instance in place on a per-run switch and gateway with no workstation, proves its realm and domain SID are the bound directory's (a SID that needs repair is refused: run `-probe REPAIR_SID=1` first), reads the live policy, runs `samba-tool domain passwordsettings set --min-pwd-length=<n> --complexity=<on/off> --min-pwd-age=<0 or 1>` as root, reads it back with `samba-tool domain passwordsettings show`, and powers off over the console. Only when the read-back matches and the run ended cleanly is the policy written (atomically) into the instance marker as `directory_password_policy`. Evidence lands in `homelab/var/factory/persistent-password-policy/<instance>/<run id>/`: a redacted console transcript, `switch.jsonl`, `fabric.log` and a `result.json` of secret-free facts. |

A policy weaker than Samba's default (length under 7, or complexity off) also
sets the minimum password age to **0 days**, so a password set under it can be
changed again at once; any other policy sets Samba's default of 1 day. The
policy is the whole domain's: it applies to every account in that directory.
Every host-side pre-check of a typed password for a durable instance -- the
daily administrator's new password and the Arch `local-rescue` break-glass
password in `arch-join`, the Windows local-administrator break-glass password
in `windows-join`, and permanent passwords in `-accounts` -- uses the recorded
policy, falls back to Samba's default when none is recorded, and names the
policy in its refusal. Verdict: **PASS 2026-09-30**, one owner run on
`rehearsal` (minimum length 4, complexity off, minimum age 0, read back and
recorded).

### Resetting one staged account's password (TASK-28)

An eleventh target, added 2026-09-30 because the owner no longer held the daily
administrator's temporary password on `rehearsal`, and `RESTAGE=1` cannot give
it a new one: staging is **create-only** and stops with `account-exists` on the
first account the directory already holds (it did, harmlessly: no write, the
policy restored). This is the reset. It requires `PERSISTENT_DC` and `ROLE`,
neither of which has a default; `CHANGE_AT_FIRST_LOGON=1` (and only `1`) makes
the new value temporary; it is a dry run unless `APPLY=1`. Implemented by
`homelab/vm/persistent_account_password.py`; the guest program is
`controller_principals.password_reset_program`.

| Target | Mutates | Contract |
|---|---|---|
| `homelab-factory-persistent-account-password` | `APPLY=1` | `ROLE` is a **contract role** (`daily_administrator`, `standard_user`, `domain_administrator`, `additional_standard_user_<uid>`) and must be one the instance's staged record lists; the account name comes from the private roster staging used and appears only in the password prompt at the terminal. The dry run binds the instance as `-probe` does and starts nothing. `APPLY=1` asks, before any process starts, for the `local-rescue` password and the new password twice, and refuses the new one there if the instance's recorded directory password policy (else Samba's default) would. It then boots the instance in place on a per-run switch and gateway with no workstation, proves its realm and domain SID, and runs the reset program over the staging channel (base64 JSON on the guest shell's stdin, echo off, stderr closed): it refuses an account that does not exist (`account-missing`; it never creates), requires the staged uidNumber, replaces `unicodePwd` as an administrator's reset and, with `CHANGE_AT_FIRST_LOGON=1`, sets `pwdLastSet=0`, in one transaction, then reads back `pwdLastSet` and proves the objectSid and uidNumber unchanged. The domain password policy is not touched; a value the directory refuses anyway fails as `password-policy`. After a clean console poweroff and only on that proof, `{role, utc, must_change, run_id}` is appended (atomically) to the marker's `directory_account_password_resets`; `-status` prints the latest reset per role. Evidence lands in `homelab/var/factory/persistent-account-password/<instance>/<run id>/`: a redacted console transcript, `switch.jsonl`, `fabric.log` and a `result.json` of secret-free facts. |

Verdict: **NOT RUN.** `rehearsal`'s owner-custody arch-join retry needs it
first (see "Stage `arch-join`" below).

### Backing up and restoring an instance's directory (ADR 0081)

A twelfth and a thirteenth target, added 2026-09-30 because the owner decided
backup and restore must be built and proven before the keeper is minted.
Both use Samba's own tools and never a disk image (ADRs 0067, 0068, 0081),
both require `PERSISTENT_DC`, and both are dry runs unless `APPLY=1`.
Implemented by `homelab/vm/persistent_backup.py`; the backup disk's header
and the guest commands are `homelab/vm/samba_backup_disk.py`.

| Target | Mutates | Contract |
|---|---|---|
| `homelab-factory-persistent-backup` | `APPLY=1` | The dry run binds the instance as `-probe` does, prints the plan and the last recorded backup, and starts nothing. `APPLY=1` refuses a running instance, asks once for the `local-rescue` password before any process starts (agent custody reads its store), and boots the instance in place on a per-run switch and gateway with **one** extra audited device: a blank sparse raw disk the run creates (512 MiB, virtio-blk serial `TELOS-BACKUP-OUT`, no boot index). As root it proves the realm and domain SID are exactly the bound directory's, reads the DC's NetBIOS name, requires `samba-tool dbcheck --cross-ncs` clean, digests the SIDs of every non-DC security principal, runs `samba-tool domain backup offline` (samba keeps running, as Samba documents), writes the tarball onto the disk behind a 4 KiB header of its length, SHA-256 and the run's token, reads it back and prints the SHA-256, shreds its own copy, and powers off over the console. The host then reads the tarball off the disk and refuses it unless the header, token, length and SHA-256 agree with the guest's proof; writes `BACKUP_ROOT/<instance>/<run id>/` (0700) with `samba-backup.tar.bz2`, `manifest.json` and a copy of the instance marker, plus `custody-credentials.json` for a throwaway agent-custody instance only (all 0600); shreds the disk; and records `last_backup` `{utc, path, sha256, run_id}` in the marker. A failed run keeps nothing. Evidence lands in `homelab/var/factory/persistent-backup/<instance>/<run id>/`: a redacted console transcript, `switch.jsonl`, `fabric.log` and a secret-free `result.json`. |
| `homelab-factory-persistent-restore` | `APPLY=1` + `CONFIRM='RESTORE <name>'` | Requires `BACKUP=<one backup set directory>`. Refuses, dry or applied, an instance that exists (destroy it first), a set that is missing, not 0700/0600, or whose tarball, marker copy or custody copy does not match the manifest, a manifest and marker copy that disagree on realm, DNS domain, NetBIOS name or domain SID, a realm the directory identity does not declare, an owner-custody set holding a custody store, and a `RESTORE_DC_NAME` the domain has held (the backed-up DC's, the one it replaced, or `bootstrap-dc`). The dry run starts nothing. `APPLY=1` asks (owner custody only) for the canonical image's `local-rescue` password, creates the instance from the canonical image under the backup's custody (agent: a new console credential; the domain Administrator's and every staged account's passwords come back from the backup's store), boots it in place with **no network device** and the set on a read-only raw disk (serial `TELOS-BACKUP-IN`), verifies the header and SHA-256 in the guest, moves the package's `/var/lib/samba` aside, runs `samba-tool domain backup restore --newservername=<RESTORE_DC_NAME> --targetdir=/var/lib/samba`, installs its `smb.conf` as `/etc/samba/smb.conf`, renames the guest to `RESTORE_DC_NAME` (`/etc/hostname` and the `127.0.1.1` line of `/etc/hosts`), enables and starts samba, proves the realm, domain SID and principal digest equal the backup's, and powers off over the console. Only then does it write the backup's convergence (with `dc_hostname` set to `RESTORE_DC_NAME`), account, password-policy and reset records and a `restored` record into the new marker. The guest has no network yet: reconverge it next. A failure leaves an instance with no directory records, which every durable stage refuses: destroy it. Evidence lands in `homelab/var/factory/persistent-restore/<instance>/<run id>/`. |

| Variable | Default | Meaning |
|---|---|---|
| `BACKUP_ROOT` | `homelab/var/backups` | Parent of every backup set, one directory per instance. Gitignored. Every set holds every secret of its domain; nothing prunes them, and none may leave the host unencrypted. |
| `BACKUP` | *(none; required by `-restore`)* | One backup set directory. |
| `RESTORE_DC_NAME` | `dr-<UTC minute>` | The restored DC's name: 1-15 lowercase letters, digits or hyphens. Never a name the domain has held. |

**The restored DC has a new name, and every stage follows the recorded
name** (owner decision 2026-09-30, aiq TASK-42; ADR 0081 item 5). Samba
restores a DC only under a name the domain does not hold: naming the backed-up
DC fails with `Entry CN=<name>,OU=Domain Controllers,... already exists`. So
the restore records its new name as the instance's `dc_hostname` (absent
means `bootstrap-dc`, which covers every instance converged earlier), and the
console prompt, the binding, `-probe`'s A and SRV checks, a reconvergence's
host name and SPN aliases, and the Windows control disc all use it;
`-status` prints it. A kept workstation follows by DNS: a durable Arch install
now writes `ad_server = _srv_, <recorded DC FQDN>`. One installed before that
(for example `rehearsal-auto-ws1`) names its controller alone and is refused,
with that reason, once the instance's DC has another name.

The live disaster-recovery proof, on `rehearsal-auto` (agent custody, so it
runs unattended) with a NEW kept workstation `<w>` whose Arch side is
SRV-first:

```sh
# a fresh gate-5 Windows install first: make homelab-windows-install-run ... -> <bundle>
make homelab-durable-workstation-adopt WORKSTATION=<w> PERSISTENT_DC=rehearsal-auto WINDOWS_RUN=<bundle> APPLY=1
make homelab-durable-arch-install WORKSTATION=<w> PERSISTENT_DC=rehearsal-auto ARCH_HOSTNAME=<host> FACTORY_DURATION=1800 APPLY=1
make homelab-durable-arch-join WORKSTATION=<w> PERSISTENT_DC=rehearsal-auto ARCH_HOSTNAME=<host> APPLY=1
make homelab-durable-windows-join WORKSTATION=<w> PERSISTENT_DC=rehearsal-auto APPLY=1
make homelab-factory-persistent-backup PERSISTENT_DC=rehearsal-auto APPLY=1
make homelab-factory-persistent-destroy PERSISTENT_DC=rehearsal-auto APPLY=1 CONFIRM='DESTROY rehearsal-auto'
make homelab-factory-persistent-restore PERSISTENT_DC=rehearsal-auto BACKUP=homelab/var/backups/rehearsal-auto/<run id> APPLY=1 CONFIRM='RESTORE rehearsal-auto'
make homelab-factory-persistent-converge PERSISTENT_DC=rehearsal-auto RECONVERGE=1 APPLY=1
make homelab-factory-persistent-probe PERSISTENT_DC=rehearsal-auto APPLY=1
make homelab-durable-workstation-verify WORKSTATION=<w> PERSISTENT_DC=rehearsal-auto ARCH_HOSTNAME=<host> APPLY=1
```

The reconvergence is not optional: the restored instance is a fresh copy of
the canonical image, which has no network unit, and convergence is what lays
one down (it skips provisioning because a directory exists, and needs no
Administrator password). A restore drill into a separate instance name proves
the backup alone and destroys nothing: restore with `PERSISTENT_DC=<drill>`,
then destroy the drill.

Verdict: **Live 2026-10-01 on `rehearsal-auto` (agent custody):** backup PASS (`persistent-backup/rehearsal-auto/20261001T052659Z-1662152-992606e0`; 1.7 MB tarball, dbcheck clean, SHA-256 agreed in guest and on host); the first restore drill into `rehearsal-auto-drill` restored the domain but failed to start samba, which the seed masks (fixed `2b555fa`); the second PASSED as DC `dr-2610010529` (`persistent-restore/rehearsal-auto-drill/20261001T052900Z-1665425-61d8abf8`: realm, domain SID and principal digest equal the backup's); `RECONVERGE=1` then PASSED, and the probe PASSED on the fabric under the new DC name (`persistent-probe/rehearsal-auto-drill/20261001T053036Z-1667189-63cd4172`). The drill instance was destroyed. Still unrun: restoring into the SAME instance name after destroying it and keep-verifying an SRV-first kept workstation against the restored DC. Unit tests: `homelab/tests/test_persistent_backup.py`,
`homelab/tests/test_samba_backup_disk.py`.

Superseded 2026-09-30, kept so it is not re-derived: this paragraph said no
workstation could be installed against a persistent instance because the
durable workstation flow (finding 7 of the 2026-08-17 review, TASK-28) was
unbuilt. It is built and passed live end to end; see "Kept workstations" below.

The **durable directory accounts** that this path exists to carry have two
routes, and only the first has run live: for a *simulated* persistent instance,
`homelab-factory-persistent-accounts-plan` then
`homelab-factory-persistent-accounts APPLY=1` (above); for a Controller
reachable over SSH — after network attachment — the host-side Ansible path
`make homelab-bootstrap-controller INVENTORY=<private inventory>`. Since
`0e588db` (2026-09-24) both refuse unless
`homelab/instance/identity/principals.json` exists **and** itself names all
three directory roles, `standard_user`, `daily_administrator` and
`domain_administrator`: the inert template, or a file naming only some roles, is
refused with the synthetic name each unnamed role would have taken, rather than
minting permanent synthetic accounts. `local_rescue` may stay unnamed.
Corrected 2026-09-24: this paragraph named `homelab-bootstrap-controller` as the
only route, which cannot reach a simulated instance.

An adversarial review on 2026-08-17 found the accounts could not be provisioned
by any wired path at all; six independent breaks were repaired in `f8d0348` —
including Ansible resolving `group_vars` relative to the inventory source, so an
overlay holding `group_vars` one level above its inventory was read by nothing.
That made the Ansible path host-side and only host-side, with the in-guest
alternative inside the convergence bundle declared dead rather than
half-wired. Corrected 2026-09-30: this paragraph said none of it had been
exercised against a live directory. The serial-console path
(`homelab-factory-persistent-accounts`) staged four durable accounts into the
throwaway instance `rehearsal` on 2026-09-25; the host-side Ansible path has
still never run.

### Credential custody (TASK-40)

Owner decision 2026-09-30: rehearsal instances are run by the harness end to
end, with its own credentials; the keeper stays owner custody. Custody is a
property of the instance, fixed when `-up` creates it, and recorded in its
marker as `credential_custody` (`owner`, the default and what every older
marker means, or `agent`) with `throwaway`. Agent custody requires
`throwaway: true`. A kept workstation inherits its bound instance's custody.
Implemented by `homelab/vm/credential_custody.py` (store, generation, the
owner and agent sources) and `homelab/vm/agent_console_init.py` (creation).

| Custody | Credentials | Store |
|---|---|---|
| owner | Typed at the controlling terminal by every runner, exactly as documented above and below (prompts unchanged, byte for byte); held in memory; never stored. | None; a `custody/` directory beside an owner-custody instance or its kept workstation is refused. |
| agent | Generated with `secrets` (24 letters and digits, three character classes: typeable by gate 6 and inside Samba's default policy) and judged by the same host-side checks a typed value meets; nothing is asked at a terminal and every stage runs unattended. | `<instance>/custody/credentials.json` (directory 0700, file 0600, atomic replacement with the replaced copy shredded): the console, the domain Administrator and each staged account by contract role (`temporary`, `current`, `pending`). Each kept workstation keeps its own `<workstation>/custody/` for its Arch `local-rescue` and Windows local-administrator break-glass passwords. |

Creation under agent custody (`make homelab-factory-persistent-up
PERSISTENT_DC=<name> APPLY=1 CUSTODY=agent THROWAWAY=1`) seeds the staged copy
from the canonical image as always, then, **before the instance exists under
its own name**, generates a console password and stores it, converts the
staged copy to a sparse raw image, selects the disposable path's one-run
`init=/bin/bash` entry on **that copy's** ESP (`DisposableBootDisk`'s own edit,
reused), boots it with no network device (`-nic none`), remounts root rw,
runs `passwd local-rescue`, `exec`s systemd, logs in as `local-rescue` with the
new value and powers off through `sudo -k -S` (proving the value opens the
console and sudo), then writes the original `loader.conf` back, deletes the
one-run entry and proves both before converting the copy back and renaming
the staging directory into place. Any failure shreds the staged store and
removes the staging directory: no instance and no stray credential remain.
Nothing of this touches the canonical image, an owner-custody instance or an
existing instance, and the instance is left powered off (it is not booted
interactively). Converge next.

Every later runner chooses its source from the marker; there is no other Make
variable. Under agent custody: convergence reads the console password and
stores a generated Administrator password **before** provisioning can take
it; `-accounts` generates each role's value (temporary with
`CHANGE_AT_FIRST_LOGON=1`) and stores it before staging; `-account-password`
stores the new value as `pending` before the reset and makes it the role's own
once the directory proves the reset; `arch-join` decides its first-logon mode
from the store (below); `windows-join` and keep-verify read the daily
administrator's proven `current` password and refuse without one. Every
retained transcript and evidence scan adds every stored value to its needles.
`-destroy` and `homelab-durable-workstation-destroy` shred the stores before
anything else.

The trade-off, plainly: a throwaway instance's credentials sit in a 0600 file
in an ignored directory for the instance's whole life, like the one-use
`publication.iso` a kept workstation holds, and are shredded on destroy. That
is acceptable for a rehearsal directory that is destroyed after use and is
never offered to the keeper. The init-shell step is the disposable path's own
mechanism applied once to a copy nobody has booted; its risk is a failed
creation (retried by creating again), never a changed canonical image.

A full unattended rehearsal on a new instance `<name>` and workstation `<w>`
(`<bundle>` is a finished gate-5 Windows install):

```sh
make homelab-factory-persistent-up PERSISTENT_DC=<name> APPLY=1 CUSTODY=agent THROWAWAY=1
make homelab-factory-persistent-converge PERSISTENT_DC=<name> APPLY=1
make homelab-factory-persistent-accounts PERSISTENT_DC=<name> APPLY=1 CHANGE_AT_FIRST_LOGON=1
make homelab-factory-persistent-probe PERSISTENT_DC=<name> APPLY=1
make homelab-durable-workstation-adopt WORKSTATION=<w> PERSISTENT_DC=<name> WINDOWS_RUN=<bundle> APPLY=1
make homelab-durable-arch-install WORKSTATION=<w> PERSISTENT_DC=<name> ARCH_HOSTNAME=<host> FACTORY_DURATION=1800 APPLY=1
make homelab-durable-arch-join WORKSTATION=<w> PERSISTENT_DC=<name> ARCH_HOSTNAME=<host> APPLY=1
make homelab-durable-windows-join WORKSTATION=<w> PERSISTENT_DC=<name> APPLY=1
make homelab-durable-workstation-verify WORKSTATION=<w> PERSISTENT_DC=<name> ARCH_HOSTNAME=<host> APPLY=1
```

Verdict: **PASS 2026-09-30**, the whole sequence above, unattended, on
`rehearsal-auto` and `rehearsal-auto-ws1` (the creation's one-run init entry
removed and proven absent); run ids are in
[DURABLE-WORKSTATION-FLOW.md](DURABLE-WORKSTATION-FLOW.md), "Live record".
Unit tests: `homelab/tests/test_credential_custody.py`,
`homelab/tests/test_agent_custody_runners.py`.

### Kept workstations (TASK-28)

A kept workstation is minted against a persistent instance by the flow in
[DURABLE-WORKSTATION-FLOW.md](DURABLE-WORKSTATION-FLOW.md). Its state lives
under `DURABLE_WORKSTATION_ROOT` (default `build/homelab/vm/workstations`), one
directory per `WORKSTATION=<name>`: a standalone disk, a private marker bound to
one `PERSISTENT_DC`, an exclusive lock and an append-only stage ledger. None of
these targets boots a guest. `-adopt` **PASS 2026-09-30** on two real gate-5
bundles (`rehearsal-ws1`, `rehearsal-auto-ws1`); `-reconcile` and `-destroy`
are **NOT RUN**.

| Target | Opt-in | Effect |
|---|---|---|
| `homelab-durable-workstation-plan` | none | Read-only: what adopting `WINDOWS_RUN` into `WORKSTATION` bound to `PERSISTENT_DC` would do. |
| `homelab-durable-workstation-status` | none | Read-only: stages done, disk present, publication custody, bound instance; never the realm or SID. |
| `homelab-durable-workstation-reconcile` | `APPLY=1` | Under the lock, finishes an interrupted fold when its disk is in place and its variables are in place or staged, rolls it back when the ledger head's files are intact, and otherwise refuses without changing anything. Every stage runner refuses the workstation while a fold is pending. |
| `homelab-durable-workstation-adopt` | `APPLY=1` | Converts the gate-5 `windows.qcow2` into a standalone disk and moves the bundle's one-use `publication.iso` into the workstation's custody. Refuses an instance that has not converged. |
| `homelab-durable-workstation-destroy` | `APPLY=1`, `CONFIRM='DESTROY <name>'` | Shreds its custody store (agent custody) and the publication first, then the rest, and lists the machine accounts the workstation left in the directory. |

`make clean` removes everything under `build/` except `build/homelab/vm`
(since 2026-09-30): the canonical Controller image, persistent instances and
kept workstations are durable state, and each leaves only through its own
confirmed destroy target.

#### Stage `arch-install` (step 6)

Both targets require `WORKSTATION`, `PERSISTENT_DC` (the instance the
workstation was adopted against) and `ARCH_HOSTNAME` (the Arch host name, at
most 15 characters; stage `arch-join` derives the machine account from it).
Implemented by `homelab/vm/arch_durable_install_run.py`, which composes gate 7
without editing it.

| Target | Opt-in | Effect |
|---|---|---|
| `homelab-durable-arch-install-plan` | none | Read-only: binds the instance, resolves the permanent realm from `homelab/instance/identity/directory.json` (or `DIRECTORY_IDENTITY`), checks the workstation's next stage is `arch-install`, and prints the plan and a free-space estimate. Names the bound instance only, never the realm or SID. |
| `homelab-durable-arch-install` | `APPLY=1`, `FACTORY_DURATION` of at least 600 (use 1800) | Under the workstation's lock: prepares gate 7's bundle with `--durable-identity` over an overlay of the kept disk (its `sssd.conf` asks DNS SRV first and names the instance's recorded DC as the fallback, `ad_server = _srv_, <DC FQDN>`, and the workstation marker records that as `arch_dc_discovery`; a bundle prepared before that is refused), boots the disposable canonical Controller for PXE and the signed workstation repository only (no directory, no join account, no join media, no persistent Controller), and drives gate 7's installer, which prints `TELOS ARCH JOIN DEFERRED` where the join stood; a transcript carrying either install-time join marker is refused. On success the overlay and the installer-authored firmware variables are folded into the workstation as `arch-install`; on failure the overlay is removed and the workstation is unchanged. Evidence stays under `homelab/var/factory/durable-arch-installs/`. |

The installed disk's sealed join unit waits about 120 seconds for join media
at every boot until stage `arch-join` joins it. Verdict: **PASS 2026-09-30** on `rehearsal-ws1`
(`durable-arch-installs/run-20260930T175938Z-ec176009c2f0`): Windows preserved,
join deferred, one PXE boot, folded; adopt had run first on the gate-5 bundle
`run-20260930T164848Z-d51d2c1e14cd`. Again under agent custody on
`rehearsal-auto-ws1` (`durable-arch-installs/run-20260930T203312Z-f7163443624a`).

#### Stage `arch-join` (step 7)

Both targets require `WORKSTATION`, `PERSISTENT_DC` and `ARCH_HOSTNAME` (the
host name stage `arch-install` baked; its machine account is recorded in the
workstation's marker before the join, so `destroy` lists it). Implemented by
`homelab/vm/arch_durable_join.py`, which subclasses gate 8's boundary without
editing it.

| Target | Opt-in | Effect |
|---|---|---|
| `homelab-durable-arch-join-plan` | none | Read-only: binds the instance, checks the workstation's next stage is `arch-join`, that the durable account record and the private roster agree on every directory role's uidNumber, and that the host roster is the one the instance staged, then prints the plan, the prompts in order and a free-space estimate. Names the bound instance and contract roles only, never the realm, SID or an account name. |
| `homelab-durable-arch-join` | `APPLY=1`; `FIRST_LOGON_DONE=1` for a retry | Under the workstation's lock, after proving the kept disk and firmware variables are still the ledger head, asks at the terminal, before any process starts: the Controller's `local-rescue` console password; the daily administrator's temporary password (its current one with `FIRST_LOGON_DONE=1`, or when the account record asks for no change); its new password, twice; a new Arch `local-rescue` break-glass password, twice. New values are held to the bound instance's directory password policy (the one `homelab-factory-persistent-password-policy` recorded, else Samba's default) and must all be distinct. It then boots `PERSISTENT_DC` in place on the per-run switch (no pause, clean console poweroff), proves its realm and SID, stages one `tj-` principal, boots an overlay of the kept disk, attaches the one-use join media after the kernel handoff and destroys them when the guest has consumed them, waits for `TELOS ARCH JOIN VERIFIED` (the seal is written first), destroys the principal with proof, answers pam_sss's expired-password exchange on ttyS0 (proving no typed value is echoed), elevates, sets the break-glass password, proves `sssctl` online, every directory role at its recorded uidNumber, the sealed join unit and the host name, and powers both guests off. On success the overlay and its firmware variables are folded as `arch-join`; on failure the workstation's disk, variables and ledger are unchanged. Evidence stays under `homelab/var/factory/durable-arch-joins/`. |

A failure after the first-logon change landed says so; the retry is
`FIRST_LOGON_DONE=1`, typing the new password as the current one. Under agent
custody nothing is typed and `FIRST_LOGON_DONE` is refused: the new password is
generated and stored as `pending` before anything boots; a proven change makes
it `current`; a run that never wrote it marks it not live, so the next run
changes the temporary password to it; and a run that died after the change may
have landed leaves it pending, so the next run logs in with it as the current
one (and marks it not live if the login refuses it). The Arch break-glass
password is stored as pending in the workstation's store and made current by
the fold. Verdict: **PASS 2026-09-30** under agent custody on
`rehearsal-auto-ws1` (`durable-arch-joins/run-20260930T203553Z-4184392-be2f79e8`:
first-logon change landed, join sealed, SSSD online, every role at its pinned
uid). Owner custody: **NOT RUN** to a pass; the one run on `rehearsal-ws1`
stopped at first login (`Login incorrect`, no expired-password notice: the
typed temporary password was not the staged one; directory unchanged). A
retry needs a known password first: `homelab-factory-persistent-account-password
ROLE=daily_administrator` (above).

#### Stage `windows-join` (step 8)

Both targets require `WORKSTATION` and `PERSISTENT_DC`. Windows keeps gate 5's
computer name `TELOS-WIN-01`, recorded in the workstation's marker before the
join so `destroy` lists it. Implemented by `homelab/vm/windows_durable_join.py`
and `homelab/vm/windows_durable_prepare.py`, which compose gate 6 without
editing it.

| Target | Opt-in | Effect |
|---|---|---|
| `homelab-durable-windows-join-plan` | none | Read-only: binds the instance, checks the workstation's next stage is `windows-join`, that gate 6's roster and the durable roster name the same accounts and that the realm is the DNS domain upper-cased, builds the audited persistent argv, and prints the plan, the prompts in order and a free-space estimate. Names the bound instance only, never the realm, SID or an account name. With `windows-join` already folded and the publication still held, it plans only retiring the publication. |
| `homelab-durable-windows-join` | `APPLY=1` | Under the workstation's lock, after proving the kept disk and firmware variables are still the ledger head, asks at the terminal, before any guest starts: the Controller's `local-rescue` console password; a new Windows local-administrator (`telosadmin`) password, twice (typeable US-ASCII, the bound instance's recorded directory password policy or else Samba's default, distinct from the other two); the daily administrator's CURRENT domain password (changed at first logon in `arch-join`). It prepares gate 6's attempt over an overlay of the kept disk (Windows boots by systemd-boot's five-second Windows default) with the control probe and the operator sign-in reference rendered for the bound realm in the private attempt only, records the machine account, boots `PERSISTENT_DC` in place on the per-run switch (no pause, no fault, gate 6's Controller-side authentication diagnostic disabled, clean console poweroff), runs gate 6's Ctrl+Alt+Del rotation to the typed password and gate 6's join unchanged with one `tj-` principal destroyed with proof (no other principal is staged), signs the daily administrator in after the join reboot, proves membership, the secure channel and its local Administrators right, and shuts Windows down from inside. On success the overlay and firmware variables are folded as `windows-join`, and only then is the custody `publication.iso` shredded; on failure the workstation and its publication are unchanged. Evidence stays under `homelab/var/factory/durable-windows-joins/`. |

A retry after a join that reached the directory reuses `TELOS-WIN-01`'s machine
account. A fold whose publication retirement failed is finished by repeating
the target with `APPLY=1`. Under agent custody the daily administrator's
proven `current` password is read from the store (none is a refusal) and the
new local-administrator password is generated, stored as pending in the
workstation's store before any guest starts, and made current by the fold.
Verdict: **PASS 2026-09-30** under agent custody on `rehearsal-auto-ws1`
(`durable-windows-joins/rehearsal-auto-ws1/attempt-20260930T203917Z-c67065dfe5be`:
folded, custody publication retired). Owner custody: **NOT RUN**.

#### Keep-verify (step 9)

Requires `WORKSTATION`, `PERSISTENT_DC` and `ARCH_HOSTNAME` (the host name stage
`arch-join` joined). Implemented by `homelab/vm/durable_workstation_verify.py`,
which composes steps 7 and 8 (and through them gates 8 and 6) without editing
them. It is read-only toward the workstation and folds nothing; the workstation
module offers no non-stage ledger annotation, so the evidence directory is the
only record of a verify.

| Target | Opt-in | Effect |
|---|---|---|
| `homelab-durable-workstation-verify` | `APPLY=1` | Read-only plan without `APPLY=1`: checks every stage (`adopt`, `arch-install`, `arch-join`, `windows-join`) is folded with no fold pending, both machine accounts are recorded, the binding and both rosters agree, and parses the workstation's firmware variables: `BootOrder` must still start with an active `Linux Boot Manager` (a regression is shown and refuses the run before any prompt). With `APPLY=1`, under the workstation's lock and after proving its disk and variables are the ledger head, asks at the terminal, before any process starts: the Controller's `local-rescue` console password; the daily administrator's CURRENT domain password. It boots `PERSISTENT_DC` in place on one per-run switch (no pause, no fault, clean console poweroff) and proves its realm and SID; boots an overlay of the kept disk to Arch through the systemd-boot menu (recording that the menu's default is Windows), logs the daily administrator in on ttyS0, proves the roster, elevates, runs `net ads testjoin` and proves `sssctl` online, every directory role at its recorded uidNumber, the sealed join unit and the host name, and powers Arch off; relaunches the Controller (clean console poweroff, then a cold boot in the same session, which logs in again with the password it holds) and proves AD, the realm, the SID and the clock again; boots a second overlay to Windows by the menu's default, signs the daily administrator in through gate 6's domain sign-in (Controller-side diagnostic disabled, no principal staged), runs gate 6's read-only identity probe (interactive operator, membership, secure channel, local Administrators right) and shuts Windows down from inside. Both overlays are removed; the workstation's disk, variables and marker are hashed again and must be unchanged. `result.json` holds secret-free booleans per check and a `pass`/`fail` verdict; an Arch failure is recorded and Windows is still verified. Evidence stays under `homelab/var/factory/durable-workstation-verifies/<name>/`. |

Verdict: **PASS 2026-09-30** under agent custody on `rehearsal-auto-ws1`
(`durable-workstation-verifies/rehearsal-auto-ws1/run-20260930T210156Z-8617-9bdffc4b`,
40 of 40 checks, about 5 min), including the Controller's clean poweroff and
cold relaunch with AD live and the clock within Kerberos skew, and
`BootOrder` still Linux-first. Owner custody: **NOT RUN**.

## Required common inputs

The runner should accept one run identifier and one release identifier rather
than allowing each subtarget to invent paths:

```text
RUN=<opaque local run ID>
VERSION=YYYYMMDD.NNN
WINDOWS_ISO=homelab/var/media/windows/windows-11-x64.iso
ARCH_ISO=homelab/var/media/arch/archlinux-x86_64.iso
WIMBOOT=homelab/var/media/wimboot
APPLY=1
```

Synthetic public identity values must be fixed in tracked configuration.
Private identity, host, domain, network, and credential values are never
arguments to the public simulation. Secrets must enter through mode-`0600`
files or an interactive terminal and must not appear in process arguments,
Make output, receipts, or transcripts.

## Existing targets that remain valid

These targets already provide useful leaf operations and should be reused
rather than reimplemented:

- `homelab-bootstrap-deps`
- `homelab-media-arch`, `homelab-media-windows`,
  `homelab-media-wimboot`
- `homelab-bootstrap-seed`
- `homelab-pxe-controller`, `homelab-pxe-arch`,
  `homelab-pxe-windows`, `homelab-pxe-verify`
- `homelab-workstation-plan`, `homelab-workstation-verify`
- `homelab-arch-update-check`
- `homelab-sim-deps`, `homelab-sim-auto-plan`
- `homelab-sim-auto-run`, `homelab-sim-auto-repeat`
- `homelab-image-promotion-gate`
- `homelab-image-service-gate` (see
  [Grading a candidate image's declared services](#grading-a-candidate-images-declared-services))
- `homelab-bootstrap-vm-status`, `homelab-bootstrap-vm-install` (see
  [Installing the canonical Controller image](#installing-the-canonical-controller-image))
- `homelab-instance` — seeds a private overlay skeleton. Since `7b29624` it
  seeds **missing subdirectories** instead of doing nothing when the overlay
  directory already exists.

The promotion gate is the common static precondition for promoting any
Arch-derived image. It is read-only: it audits a candidate root through a
confined descriptor chain that follows no symlinked ancestor, mounts and boots
nothing, and always gates against the tracked `package-contract.json` rather
than a caller-supplied registry.

```sh
make homelab-image-promotion-gate \
  IMAGE_PROFILE=controller-seed \
  IMAGE_ROOT=<candidate root> \
  IMAGE_RECEIPT=<signed seed receipt> \
  IMAGE_EVIDENCE=<optional evidence path>
```

Every failure names its stage — `contract`, `root-audit`, or `seed-closure` —
so an unaccounted binary, an unowned path, a missing package signature, and an
installed version that drifted from the seed closure are distinguishable
without inspecting the candidate by hand. Passing this gate is necessary and
not sufficient: booting the candidate and verifying declared services remain
separate gates, and promotion still needs explicit authority. The
declared-services half now has a host-side judge —
`homelab-image-service-gate`, above — whose live capture step is still blocked.

The aggregate factory targets may delegate to a leaf only after its inputs and
outputs match this contract. In particular, do not claim the current simulator
proves PXE installation, AD join, or dual boot.

The simulation automation is deliberately separate from the final human gate:

```sh
make homelab-sim-deps
make homelab-sim-auto-plan
make homelab-sim-auto-run APPLY=1
make homelab-sim-auto-repeat APPLY=1 SIM_CYCLES=10
```

The dependency target checks only; it does not install or update packages.
Planning starts no guest. Automatic live targets generate and wipe their own
one-run credential and accept no password input. `homelab-sim-run APPLY=1`
remains the foreground operator-login cycle and is not a dependency of any
automatic target.

## Acceptance measurements

Each stage records start/end timestamps, input hashes, resolved Git commit,
tool versions, guest firmware and stable disk identities, exact commands
without secrets, process exit status, network transcript, partition/EFI
measurements, assertions, and cleanup result. The final verifier also confirms:

- the canonical controller disk and firmware variables are unchanged;
- all guest disks are disposable and scoped to the named run;
- no TAP, bridge, route, VLAN, forwarding rule, physical listener, or UniFi
  change was created;
- no external connection occurred after the offline gate;
- Windows was installed before Arch and Windows remains the default boot;
- both operating systems pass online and cached-offline login;
- optional storage absence does not delay or prevent login; and
- no tracked or publishable artifact contains media, credentials, private
  values, or oversized generated objects.
