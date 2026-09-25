# Workstation factory Make contract

Document version: `20260924.001`

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
| Recovery | `homelab-factory-recover` | **implemented** | Exercise release rollback, controller reconstruction, failed-install recovery, boot repair, and workstation remint. Graded by **`homelab-factory-recover-judge RECOVERY_EVIDENCE=…`** (implemented). |
| Cleanup | `homelab-factory-clean` | **reserved** | Remove only the named disposable run after exact confirmation; preserve sealed media unless separately requested. |
| Repeat | `homelab-factory-repeat` | **implemented** (`27d8af9`, `2aaa7fe`) | Run the complete sealed-input lifecycle at least twice from destroyed disposable state and compare receipts. Aggregates every phase bundle into one receipt, because no single phase can carry gate 12. Dry run is read-only; see [The repeat driver](#the-repeat-driver). **NOT RUN** — it has never completed a live lifecycle. |
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
| 11 | `homelab-factory-recover`, `homelab-factory-recover-judge` | `RECOVERY_EVIDENCE=` |
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
                                           repeat is implemented and NOT RUN
```

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

Verdict: **NOT RUN.** The driver is implemented and unit-tested; it has never
completed a live lifecycle — its only live execution was an accidental,
interrupted launch from inside the unit suite on 2026-09-24, fixed by `272d693`
(see `HANDOFF.md` §5) — and every end-to-end test fabricates its bundles, so
what is proven is that the aggregation is deterministic — not that two real
lifecycles agree.

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
| `homelab-factory-persistent-status` | no | Read-only. Reports whether the instance exists and whether its directory is provisioned. |
| `homelab-factory-persistent-up` | `APPLY=1` | Creates the instance from the canonical image when absent (read-only against the canonical, under the same strict fence the disposable path uses), then boots it **in place**. A second bring-up reuses the disk rather than re-seeding it, which is what makes the directory durable. Since `7b29624` it **refuses an uninstalled canonical image** instead of silently seeding an instance from a blank disk. |
| `homelab-factory-persistent-converge-plan` | no | Read-only plan for the provisioning step. |
| `homelab-factory-persistent-converge` | `APPLY=1` | Provisions Active Directory into the instance in place, over the `local-rescue` console password typed at the operator's terminal. Long-running; prompts for credentials interactively and writes none of them to a file, a Make variable, an environment variable, or argv. Since `7b29624` it **checks the canonical image before it prompts**, so an uninstalled source no longer costs you the unrecoverable console password first, and a retried convergence only asks for a new Administrator password when provisioning was actually attempted. |
| `homelab-factory-persistent-accounts-plan` | no | Read-only plan for staging the owner's durable account roster (`73dbd2b`): roster source and fingerprint, each contract role with its `uidNumber`/`gidNumber` (never the real names), and the privilege separation. It refuses before printing anything if the private roster — `homelab/instance/identity/principals.json`, or `IDENTITY_OVERLAY` — is missing, unreadable, or does not itself name all three directory roles, and it refuses an instance that does not exist or holds no converged directory. |
| `homelab-factory-persistent-accounts` | `APPLY=1` | Stages that roster into the converged instance **over the serial console**, the only channel that reaches a simulated persistent instance: its only NIC is a QEMU socket netdev to the userspace gateway, with no route to the host LAN, so host-side Ansible cannot reach it. Prompts at the terminal for the `local-rescue` password and one password per directory role; none reaches a file, argv, an environment or Make variable, the instance marker, or a transcript. The daily administrator never joins Domain Admins. After a completed or an unfinished staging run it refuses unless `RESTAGE` is set. |
| `homelab-factory-persistent-destroy` | `APPLY=1` + `CONFIRM='DESTROY <name>'` | Disk-erasing: deletes a real directory server, so it needs the stable instance name and the exact confirmation carrying that name. |

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
| `RESTAGE` | unset | Required to stage accounts again after a completed or an unfinished staging run. It does not reset the password of an account the directory already holds. |
| `PERSISTENT_ACCOUNTS_TIMEOUT` | unset | Overrides the in-guest bound on the account staging program, in seconds (600 by default). |
| `SEED_ISO` | unset | Optional seed ISO for bring-up and convergence. |
| `CONFIRM` | unset | `DESTROY <instance name>`, required by `-destroy`. |

`FACTORY_DURATION` is deliberately **not** reused on this path: its 120-second
default would abort a Samba provisioning run. Verdict: this whole surface is
implemented and unit-tested but **NOT RUN** — none of its applying targets has
executed live as of 2026-09-24. It is no longer blocked by the canonical image,
which was installed that day. See "The persistent directory instance" in
[docs/operator-runbook.md](docs/operator-runbook.md).

**No workstation can be installed against a persistent instance yet.** Every
workstation runner wraps the Controller in `DisposableBootDisk`, and a bundle
prepared against the permanent realm is refused by
`homelab/vm/arch_install_run.py` before any process starts. That durable
workstation flow is unbuilt — finding 7 of the 2026-08-17 review, tracked as
local work item TASK-28 — so a persistent instance can hold a durable directory
and durable accounts, and nothing yet joins it.

The **durable directory accounts** that this path exists to carry have two
routes, and **neither has run live**: for a *simulated* persistent instance,
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
half-wired. None of it has been exercised against a live directory: treat
durable accounts as designed and repaired, never as working.

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
