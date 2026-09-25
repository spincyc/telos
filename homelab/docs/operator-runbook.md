# Workstation factory — operator runbook

An exact, ordered runbook for building and verifying the isolated workstation
factory on one Arch build host. Every command below is a real `make` target
verified against the [Makefile](../../Makefile) and the
[Make contract](../FACTORY-MAKE-TARGETS.md). Every evidence claim matches the
[factory state ledger](../WORKSTATION-FACTORY-STATE.md); where a step is not yet
proven live, it is marked **NOT RUN** (or **PENDING**) and never described as
working.

Pair this with the [human guide](factory-guide.md) for orientation.

## Conventions and safety

- **Dry run is the default.** Every mutating or destructive target does nothing
  until you add `APPLY=1`. Disk-touching work runs against disposable qcow2
  overlays; the canonical controller disk and Windows disk are never mutated in
  place.
- **Loopback only.** All links and services bind to host loopback. The simulated
  gateway is the sole DHCP authority. No target here touches UniFi, the physical
  network, a host bridge/TAP/route/VLAN, or a physical disk. Do not add one.
- **Secrets never appear on a command line.** Synthetic AD passwords are
  generated in memory or read from mode-`0600` files by the runners and wiped
  after use. Never pass a real password in `make`, the environment, or an answer
  file.
- **`sudo` / operator console.** The live identity and install runners drive
  KVM QEMU and may prompt for `sudo` on this host to launch a guest or the
  controller-auth watcher. Where a step needs elevation it is called out with
  the exact argv. This runbook never runs `sudo` for you.
- The synthetic lab is public test data: realm **`AD.FACTORY.TEST`**, controller
  **`10.1.31.2`** (the Makefile default `BASE_URL=http://10.1.31.2`). Real
  hostnames, addresses, and credentials live only in the private overlay
  (`telos-private`) and must never enter this tree.

### Resolved 2026-09-24: the canonical Controller image is installed

**No live target in this runbook is blocked on the image any more.** From
2026-08-14 until 2026-09-24 `build/homelab/vm/bootstrap-dc/bootstrap-dc.qcow2`
was a 197,888-byte empty disk — the image had been destroyed with owner
authorization after its `local-rescue` console password was lost — and
`make homelab-bootstrap-vm-status` reported `created but not installed`. Every
step below carried a **Blocked today** marker; those markers were removed when
the image was installed.

On 2026-09-24 the owner ran
[`homelab-bootstrap-vm-install`](#05-reinstall-the-canonical-controller-image)
for the first time, and it succeeded first time (receipt `installed_utc`
`2026-09-25T01:30:06Z`). `make homelab-bootstrap-vm-status` now reports `ready`.

Every gate runner, every `homelab-factory-persistent` target,
`make homelab-factory-repeat APPLY=1`, and `make homelab-sim-auto-run` boot or
copy that image, so confirm `make homelab-bootstrap-vm-status` says `ready`
before any live step. Keep the `local-rescue` password somewhere durable —
**losing it costs the whole image again**; see
[Keep the `local-rescue` password](#keep-the-local-rescue-password). Rebuilding
the image invalidates no retained gate receipt.

### Target names: real vs reserved

[FACTORY-MAKE-TARGETS.md](../FACTORY-MAKE-TARGETS.md) reserves several aggregate
names that are **not implemented as Make targets**. Do not invoke them; use the
granular targets in this runbook. Reserved-but-absent, seven names (verified
with `grep` of the Makefile on 2026-08-17, and again on 2026-09-24):
`homelab-factory-controller`, `homelab-factory-authority-check`,
`homelab-factory-windows`, `homelab-factory-arch`,
`homelab-factory-dualboot-check`, `homelab-factory-clean`,
`homelab-factory-fresh-clone`. Each maps to the real targets below.

Corrected 2026-08-17: this list read *eight* and included
`homelab-factory-repeat`, which is now implemented — see
[5.3 Repeatability](#53-repeatability--not-run-gate-12).

## Lifecycle map

```text
deps -> media -> cache-seal -> offline-check
                                    |
                                    v
      controller-bundle -> pxe -> authority-audit (gate 4)
                                    |
                                    v
   windows-install (gate 5) -> windows-identity (gate 6)
                                    |
                                    v
   arch-install (gate 7) -> arch-identity (gate 8)
                                    |
                                    v
             dualboot-acceptance (gate 10)
                                    |
                                    v
                verify -> recover -> (repeat, NOT RUN)
```

## Common variables and their defaults

| Variable | Default | Meaning |
|---|---|---|
| `APPLY` | unset (dry run) | Set to `1` to actually mutate |
| `ARCH_ISO` | `homelab/var/media/arch/archlinux-x86_64.iso` | Verified Arch ISO |
| `WINDOWS_ISO_CACHE` | `homelab/var/media/windows/windows-11-x64.iso` | Imported Windows ISO |
| `WORKSTATION_REPO` | `homelab/var/media/arch/workstation-repo` | Signed Arch package repo |
| `WIMBOOT` | `homelab/var/media/wimboot` | Pinned iPXE `wimboot` |
| `FACTORY_MEDIA_SEAL` | `homelab/var/media/factory-media-seal.json` | Aggregate media seal |
| `FACTORY_DURATION` | `120` | Bounded live-run seconds |
| `BASE_URL` | `http://10.1.31.2` | Controller HTTP base for releases |
| `VERSION` | *(required for `-pxe`)* | Release id `YYYYMMDD.NNN` |

Everything under `homelab/var/` is disposable, git-ignored cache and evidence.
Never commit media, credentials, private inventory, or evidence.

---

## Stage 0 — Prerequisites

### 0.1 Build-host dependencies (online; explicit operator action)

```sh
make homelab-factory-deps
```

`homelab-factory-deps` chains `homelab-bootstrap-deps`, which checks the full
Arch build-host closure (QEMU `qemu-base`, `edk2-ovmf`, `archiso`, `samba`,
`krb5`, `dnsmasq`, `nginx`, `ipxe`, `ansible`, `wimlib`, `gptfdisk`, `mtools`,
and the Python/TeX/site sets). It reports what is missing; it does not silently
install. **Evidence:** the command exits 0 with no "missing" lines. The
lightweight live-tool subset can be re-checked any time with
`make homelab-sim-deps` (checks `qemu-system-x86_64`, `qemu-img`, `sfdisk`,
`mcopy`).

### 0.2 Acquire and import media (online or local import)

```sh
make homelab-factory-media
```

This fans out to `homelab-media-arch` (fetches + digest/keyring-verifies the
Arch ISO), `homelab-media-workstation-repo` (resolves the signed Arch install
closure into `WORKSTATION_REPO`), `homelab-media-wimboot` (version/hash-pinned
`wimboot`), and `homelab-media-windows`.

Microsoft requires an interactive download, so Windows import stops at an
explicit gate. Supply the operator-downloaded ISO and the SHA-256 from
Microsoft's verification table one of these ways:

```sh
# Explicit source + digest:
make homelab-media-windows \
  WINDOWS_ISO=<path to the downloaded ISO> \
  WINDOWS_SHA256=<Microsoft-published SHA-256>

# Or drop Win11_25H2_English_x64_v2.iso in the checkout root and just run:
make homelab-media-windows
```

The pinned 25H2 en-US digest is
`768984706b909479417b2368438909440f2967ff05c6a9195ed2667254e465e3`. Import
copies the ISO to `WINDOWS_ISO_CACHE`, writes a `.provenance.json` receipt, and
inspects the image catalog. **Evidence:** the import refuses to proceed unless
the digest matches and **Windows 11 Pro (index 6)** is present; the cache gains
`windows-11-x64.iso`, its `.provenance.json`, and `.verification.json`.

### 0.3 Seal the cache (no downloads)

```sh
make homelab-factory-cache-seal
```

**Evidence:** prints `PASS: local factory media cache is sealed` and writes the
atomic aggregate receipt `homelab/var/media/factory-media-seal.json` binding
Arch, the Windows provenance/Pro verification, the Windows install source, and
`wimboot`, recording content hashes and tool versions separately.

### 0.4 Offline gate (proves no download dependency downstream)

```sh
make homelab-factory-offline-check
```

**Evidence:** prints
`PASS: required local inputs verify without acquisition` and re-verifies the
seal plus the workstation repo against `homelab/package-contract.json`. It never
downloads and never silently rewrites the receipt. Every target below this line
must run with the host network unavailable.

### 0.5 Reinstall the canonical Controller image

**Done 2026-09-24 — run this again only if the image is lost,** and then only
after destroying and recreating the disk as in
[Keep the `local-rescue` password](#keep-the-local-rescue-password), because it
refuses any disk that is not freshly created. Its first live run succeeded; see
[Resolved 2026-09-24: the canonical Controller image is installed](#resolved-2026-09-24-the-canonical-controller-image-is-installed).

```sh
make homelab-bootstrap-vm-status                       # read-only; says what is there

make homelab-bootstrap-vm-install \
    ISO=homelab/var/media/arch/archlinux-x86_64.iso \
    SEED_ISO=homelab/var/seed/telos-controller-seed.iso        # dry run

make homelab-bootstrap-vm-install APPLY=1 \
    CONFIRM='<the erasure phrase the installer asks you to type>' \
    ISO=homelab/var/media/arch/archlinux-x86_64.iso \
    SEED_ISO=homelab/var/seed/telos-controller-seed.iso        # installs
```

`homelab-bootstrap-vm-install` (`7b29624`) boots the Arch ISO's kernel directly
with `console=ttyS0`, so the manual `e` edit at the boot menu is gone, and
answers the offline installer's prompts over the serial line. ADR
[0058](../decisions/0058-pty-driven-acceptance-testing.md) sanctions exactly
this: it forbids an unattended path *inside* the installer and prescribes
driving the interactive one externally, answering prompts as a person would.

**You still type both things that matter.** The erasure phrase arrives through
`CONFIRM` and is relayed verbatim — the driver contains neither the phrase nor
the disk serial, asserted against its own source — and the new `local-rescue`
console password is read **twice** by `getpass` at your terminal and is never a
Make variable, an environment variable, a file, or an argv element. `SEED_ISO`
is required (exit 2 without it), and `APPLY=1` without `CONFIRM` exits 2.

Without `APPLY=1` this prints the launch boundary and starts nothing. Verified
2026-08-17, the dry run reports the disk and its serial, that the image is
byte-identical to a newly created 80G qcow2 (`this erases nothing that exists`),
both ISO digests, `network: none`, and the exact `qemu-system-x86_64` argv.

It refuses to run as root, against a symlinked or mis-permissioned state
directory, a manifest whose serial or format is wrong, a disk any process holds
open, an argv naming the serial anything but exactly once, an argv carrying a
network device, a missing controlling terminal, mismatched password entries, and
a guest that claims success on a disk that still does not probe as installed.
Above all it refuses a disk that is not byte-identical to a freshly created
qcow2 of the declared size, with the reference generated by the local
`qemu-img` at run time — so it can erase the empty image it is meant to erase
and never a working Controller.

**Evidence when it runs:** `build/homelab/vm/bootstrap-dc/install-receipt.json`
(mode 0600) and a secret-redacted `install-console.log`; afterwards
`make homelab-bootstrap-vm-status` reports `ready` and names what installed it.

> **PASS — one live run, 2026-09-24.** The owner's run, the target's first,
> drove all 19 console events from the archiso login through
> `console-password-updated`, `installation-complete` and `poweroff-observed`;
> QEMU exited 0, and the disk now holds a GPT with two partitions (one ESP) and
> 2,539,716,608 bytes allocated. One run on this host is the whole scope of that
> pass. Corrected 2026-09-24: this callout read NOT RUN. The hand-driven console
> session remains the documented fallback — see
> [`homelab/vm/README.md`](../vm/README.md), "Interactive offline installation",
> and [Keep the `local-rescue` password](#keep-the-local-rescue-password) below.
> **Record the new `local-rescue` password somewhere durable. Losing it costs
> the whole image** — root is locked, there is no authorized key, no init shell,
> and SSH password authentication is off, so nothing in this repository can open
> an image whose console password is gone.

---

## Stage 1 — Controller and immutable releases

### 1.1 Build the disposable controller bundle

```sh
make homelab-factory-controller-bundle APPLY=1
```

Dry run (`APPLY` unset) prints the guest command without building. With
`APPLY=1` it builds the ephemeral convergence bundle
`homelab/var/factory/controller-convergence.iso` (mode `0600`, carrying a
generated synthetic AD password that the lifecycle runner deletes after
convergence). **Evidence:** the bundle ISO exists mode `0600`. Full controller
convergence — Samba AD/DNS, Kerberos/time, TFTP, nginx, and the *no DHCP/ProxyDHCP
listener* proof — is exercised inside the live install runners (Stage 2+) and
was accepted at ledger gate 3 (`20260727T201057Z-controller.json`).

### 1.2 Build the immutable release set

```sh
make homelab-factory-pxe VERSION=YYYYMMDD.NNN
# optional: CONTROLLER_SOURCE=<netboot tree> ARCH_SOURCE=<...> BASE_URL=<...>
```

Requires a `VERSION` of the form `YYYYMMDD.NNN` (it errors without one). It
delegates to `homelab-pxe-release-set`, building the controller, Arch, and
Windows leaves transactionally under one release id. **Evidence:** a
`homelab/var/pxe` release set for `VERSION`; the ledger's accepted set is
`20260727.005` (aggregate manifest SHA-256 `abbc459e…baccdc`). A genuine
controller mkarchiso netboot tree at `CONTROLLER_SOURCE` is a required local
input; the seed ISO is a data disc and is never substituted for it.

### 1.3 Gate 4 — PXE authority boundary (read-only audit)

```sh
make homelab-pxe-authority-audit \
  SWITCH=<run>/evidence/switch.jsonl
# optional: TOPOLOGY=<fabric> AUDIT_JSON=<path to persist full JSON>
```

Renders the read-only gate-4 verdict from a run's `switch.jsonl`. Exit status:
`0` PASS, `1` FAIL, `3` NOT-PROVABLE. **Evidence — gate 4 PASS 2026-08-12**
against the real gate-7 run
`arch-installs/run-20260811T170109Z-7ceb936e2710/evidence/switch.jsonl`, four
checks green and `VERDICT PASS workstation-factory-gate-4`:

- `gate4.dhcp-sole-authority` — every DHCP server frame came from the gateway;
- `gate4.controller-no-dhcp` — the controller emitted no DHCP frame of any kind;
- `gate4.controller-approved-flows-only` — every controller flow was within the
  approved AD-identity/PXE service set (DNS/Kerberos/LDAP/SMB/NetBIOS/RPC/TFTP/
  HTTP/NTP);
- `gate4.no-external-endpoint` — every endpoint stayed inside
  `['controller', 'gateway', 'workstation']`.

A controller DHCP offer, a controller identity announcement, or any
backdoor listen/egress still **fails** the gate.

---

## Stage 2 — Windows first (gate 5) and Windows identity (gate 6)

### 2.1 Install Windows 11 Pro first

```sh
make homelab-windows-install-prepare APPLY=1
make homelab-windows-install-run WINDOWS_RUN=<prepared bundle> APPLY=1
# FACTORY_DURATION=<seconds> bounds the live run (default 120)
```

`-prepare` builds a disposable private bundle; `-run` PXE-boots WinPE and
installs Windows 11 Pro to the approved layout against a fresh overlay, then
reboots with no ISO/PXE attachment. **Evidence — gate 5 PASS 2026-08-10**,
bundle `windows-installs/run-20260810T145421Z-5b457e50e20b`: `result.json`
records `status` `observed` / phase `native-windows-clean-shutdown`, exactly one
PXE firmware boot (`pxe_firmware_boots: 1`), release `20260727.005`; the serial
log shows the WinPE handoff, two native Windows Boot Manager boots,
`TELOS WINDOWS NATIVE READY`, and `Edition Professional`. The retained daily-use
identity input bundle is `run-20260728T114233Z-afecdf7cc9d0`.

### 2.2 Join and prove Windows identity

```sh
make homelab-windows-identity-prepare WINDOWS_RUN=<retained bundle> APPLY=1
make homelab-windows-identity-run WINDOWS_IDENTITY_ATTEMPT=<prepared attempt> APPLY=1
make homelab-windows-identity-judge WINDOWS_IDENTITY_EVIDENCE=<private JSONL>
# optional on prepare/run: FACTORY_CONTROLLER_STATE=<state>
#   WINDOWS_SUBMIT_FOCUS_TABS=<n> WINDOWS_REVIEWED_SUBMIT_FOCUS=1
```

**Evidence — gate 6 PASS, 24 of 24 contracted checks, 2026-08-13**, attempt
`20260813T191519Z-28a9f6ee07f5` on bundle
`homelab/var/factory/windows-installs/run-20260813T171405Z-6729c809fcab`. That
is the accepted run and the first one to publish
`acceptance-evidence.jsonl`; the earlier 2026-08-12 attempt
`20260812T043214Z-28ff545de0ce` also scored 24/24 but ran before the
secure-channel and publication fixes landed. The judge additionally reports
`deferred: [disable-reenable]` and `out_of_scope: [firmware-activation,
live-microsoft-update]`, so "24/24" means every contracted check, not every
conceivable one. `acceptance-progress.json` records
`passed_count: 24`, `total_checks: 24`, `next_check: null`, kind
`windows-identity-acceptance-progress`, with the 24 named checks:
`controller-ready`, `windows-joined`, `windows-standard-online`,
`windows-daily-admin`, `domain-admin-separate`, `windows-rebooted-joined`,
`windows-cached-policy`, `controller-offline`, `windows-cached-login`,
`windows-cached-admin-login`, `windows-uncached-denied`, `windows-local-rescue`,
`controller-restored`, `windows-secure-channel-restored`,
`windows-update-policy`, `gateway-offline`, `update-source-offline`,
`optional-storage-offline`, `optional-storage-access-denied`, `ad-dns-offline`,
`combined-dependencies-offline`, `windows-services-restored`,
`windows-diagnostics-sanitized`, and the aggregate `windows-identity-acceptance`.

> **Credential-media note (important for re-runs):** the gate-6 recovery step by
> design **destroys** the one-use, credential-bearing recovery publication,
> which consumes the gate-5 bundle's `publication.iso`. A fresh gate-5 install
> (Stage 2.1) regenerates a matching bundle before the next gate-6 attempt. This
> is expected, not a fault.

---

## Stage 3 — Arch second (gate 7) and Arch identity (gate 8)

### 3.1 Install Arch second, preserving Windows

```sh
make homelab-arch-install-prepare APPLY=1
#   optional WINDOWS_RUN=<gate-5 bundle> to overlay the real Windows disk
make homelab-arch-install-run ARCH_RUN=<prepared arch bundle> APPLY=1
```

`-prepare` builds a fresh qcow2 overlay over the persistent Windows disk (NVMe
serial `TELOS-WIN-0001`, Windows partitions preserved) and prints the loopback
QEMU command. `-run` PXE-boots archiso, hot-attaches the disk, installs Arch into
the approved allocation, joins the same domain, and installs systemd-boot with a
Windows-default menu. **Evidence — gate 7 PASS 2026-08-11**, bundle
`arch-installs/run-20260811T141601Z-6941005247e8`: `result.json` records
`status` `observed`, phase `arch-installed-windows-preserved`,
`windows_preserved: true`, `pxe_firmware_boots: 1`, release `20260727.005`,
`join_media` built/attached/consumed/destroyed, `join_principal_destroyed`. The
serial proves archiso login, virtio hot-attach, GPT verify, pacstrap of all 209
packages from the controller-served signed repo, `TELOS ARCH JOIN VERIFIED`
(live `net ads join` + `testjoin`), SSSD/local-rescue provisioning, and
systemd-boot `default auto-windows`. (Cold-boot NVRAM proof belongs to gate 10.)

### 3.2 Arch join and login — **PASS 2026-08-14, 21 of 21 (gate 8)**

```sh
make homelab-arch-identity-prepare \
  ARCH_RUN=<passing arch install bundle> \
  WINDOWS_IDENTITY_EVIDENCE=<produced gate-6 acceptance JSONL> APPLY=1
make homelab-arch-identity-run ARCH_IDENTITY_BUNDLE=<joined arch bundle> APPLY=1
make homelab-arch-identity-judge ARCH_IDENTITY_EVIDENCE=<produced JSONL>
```

**Evidence — gate 8 PASS 2026-08-14, 21 of 21 checks**, bundle
`homelab/var/factory/arch-identity/run-20260814T172142Z-495164bc7159`, stream
`evidence/identity-lifecycle.jsonl`. Judge it read-only with:

```sh
make homelab-arch-identity-judge \
  ARCH_IDENTITY_EVIDENCE=homelab/var/factory/arch-identity/run-20260814T172142Z-495164bc7159/evidence/identity-lifecycle.jsonl
```

which prints `PASS: 21 checks, external_access=False`. That run proves the
SSSD identity, UID/GID stability, named user and administrator behaviour,
cached-offline login, uncached denial, local rescue, identity restore, and the
three `arch-storage-*` checks that are gate 9's Arch half. Sixteen live runs and
eight distinct root causes got there; the narrative is in
[`HANDOFF.md`](../HANDOFF.md) §3 and is not repeated here. Still open around the
gate, but not blocking it: the firmware boot stall (3 of 16 runs, absorbed by a
bounded power-cycle retry) is not root-caused, and the fleet
`sssd.conf.j2` template should carry the same `offline_timeout` bounds the
installer sets.

---

## Stage 4 — Dual-boot acceptance (gate 10)

```sh
make homelab-dualboot-acceptance-prepare GATE7_RUN=<completed gate-7 bundle> APPLY=1
make homelab-dualboot-acceptance-run DUALBOOT_RUN=<prepared bundle> APPLY=1
make homelab-dualboot-acceptance-judge DUALBOOT_EVIDENCE=<produced JSONL>
```

Disposable, disk-only (no PXE, no media): it cold-boots a fresh overlay of the
gate-7 disk and measures the boot menu, Arch selectability, EFI recovery
choices, and GPT integrity. **Evidence — gate 10 PASS 2026-08-11**, bundle
`dualboot-acceptance/run-20260811T170510Z-a619bcb1f028`: `result.json` records
`status` `observed`, phase `dualboot-accepted`, `checks: 8` (all green),
`partitions_byte_identical: true`, `arch_clean_shutdown: true`. The firmware
started Linux Boot Manager, the five-second Windows-default menu rendered
(~5 s), Windows booted, boot 2 arrow-navigated to Arch, the GPT was
byte-unchanged, and both EFI boot managers plus the recovery entry were
present. The same `result.json` records `windows_clean_shutdown: false` — the
gate does not require a clean Windows shutdown and did not observe one. Note
`windows_login_proven: false` here — **live Windows login is proven by gate 6's
identity stream, not this gate.**

**Do not re-point gate 10 at a 2026-08-14 gate-7 bundle.** The three bundles
from that date bake in `telos-arch-join-once.service` and
`telos-arch-domain-online.service`, both ordered before
`systemd-user-sessions.service`. Gate 10 attaches no media and no network, so
the first spends 120 s waiting for `/dev/disk/by-label/TELOS_JOIN` and the
second another 120 s waiting for a directory account, pushing the ttyS0 getty
roughly 240 s past kernel handoff — past `observe_boot`'s 120 s login wait, so
`arch-console-login-surface` records no login prompt and the gate FAILS. Use an
08-11 bundle (`run-20260811T141601Z-6941005247e8` or
`run-20260811T170109Z-7ceb936e2710`); neither installer contains those units.
Nothing is destroyed by the mistake, but the run is wasted.

---

## The persistent directory instance (not part of any gate)

> **NOT RUN as of 2026-09-24.** Everything in this section is implemented and
> unit-tested (`homelab/tests/test_bootstrap_vm.py`,
> `homelab/tests/test_simulation_overlay.py`,
> `homelab/tests/test_domain_controller_role.py`) but has **never been executed
> live**. Read it as the designed contract, not as observed behaviour, and do
> not report any of it as working. It is no longer blocked by the canonical
> image, which bring-up seeds the instance from and which was installed
> 2026-09-24 — see
> [Resolved 2026-09-24: the canonical Controller image is installed](#resolved-2026-09-24-the-canonical-controller-image-is-installed).

Everything above is the **acceptance** factory, and its controller is disposable
on purpose: the canonical image carries no directory, the role provisions one
whenever `sam.ldb` is absent, and teardown discards the overlay after
re-verifying the canonical digests. That is what gate 3 requires and what gates 8
and 12 depend on — and it also means no account can survive relaunching the
directory.

A **persistent instance** exists alongside it for the case where you want a
workstation you can log back into — although no workstation can be installed
against one yet (below). It is opt-in by name, lives in its own state
directory, boots its own qcow2 with no backing file, and is deliberately *not*
hash-fenced, because that disk is the durable directory and is expected to
change. The acceptance canonical keeps its strict fence, and is unreachable as a
persistent target: instances resolve under their own parent and the name is
validated, so `PERSISTENT_DC=bootstrap-dc` yields `persistent-dc/bootstrap-dc/`
rather than the canonical.

```sh
make homelab-factory-persistent-plan   PERSISTENT_DC=<name>   # read-only
make homelab-factory-persistent-status PERSISTENT_DC=<name>   # read-only
make homelab-factory-persistent-up     APPLY=1 PERSISTENT_DC=<name> [SEED_ISO=<iso>]
make homelab-factory-persistent-destroy APPLY=1 PERSISTENT_DC=<name> \
    CONFIRM='DESTROY <name>'
```

> **No workstation can be installed against a persistent instance yet.** Every
> workstation runner wraps the Controller in `DisposableBootDisk`
> (`factory_runner.py`, `windows_install_run.py`, `windows_identity_run.py`,
> `arch_install_run.py`, `arch_identity_run.py`), and a bundle prepared against
> the permanent realm is refused in `homelab/vm/arch_install_run.py` before any
> process starts. That durable workstation flow is unbuilt — finding 7 of the
> 2026-08-17 review of this path, the one that was never fixed, tracked as local
> work item TASK-28. Until it exists, an instance can hold a durable directory
> and durable accounts, and nothing joins it.

Bring-up creates the instance when it is absent and boots it in place; a second
bring-up **reuses** the disk rather than re-seeding it, which is what makes the
directory durable. Boot-in-place was chosen over committing an overlay back
because a killed run then leaves the disk crash-consistent, recoverable by the
guest filesystem journal and Samba's own recovery, whereas a kill during a commit
would tear the whole base image.

Bring-up alone does not provision a directory — it boots the disk. Provisioning
is a separate explicit step, because it is long-running, it prompts for
credentials at your terminal, and it builds a disc that briefly carries one:

```sh
make homelab-factory-persistent-converge-plan PERSISTENT_DC=<name>   # read-only
make homelab-factory-persistent-converge APPLY=1 PERSISTENT_DC=<name> \
    [SEED_ISO=homelab/var/seed/telos-controller-seed.iso] \
    [RECONVERGE=1] [PERSISTENT_CONVERGE_TIMEOUT=<seconds>]
```

Three variables belong to this path alone and have no default worth guessing at:

| Variable | Default | Meaning |
|---|---|---|
| `PERSISTENT_DC_ROOT` | `build/homelab/vm/persistent-dc` | Parent of every persistent instance. Instances resolve under it and the name is validated, which is what keeps the canonical acceptance state unreachable as a persistent target. |
| `RECONVERGE` | unset | Required to converge an instance a second time. Without it a convergence never re-runs, so an operator who needs to repeat one **must** pass `RECONVERGE=1`. |
| `PERSISTENT_CONVERGE_TIMEOUT` | unset | Overrides the convergence's own long in-guest bound, in seconds. |

`FACTORY_DURATION` is deliberately **not** reused here: its 120-second default
would abort a Samba provisioning run mid-flight.

It converges **in place**, over the `local-rescue` console password the offline
installer had you type — so it needs no harness credential, and the durable ESP is
never rewritten. It prompts once for that password and twice for a new domain
Administrator password; neither reaches a file, an argument, an environment
variable, or a transcript. Expect roughly 15-25 minutes.

Unlike the disposable path, this leaves the built-in Administrator **enabled**,
with the password you typed. That is deliberate: the disposable payload's last act
is to disable it and shred its generated password, which is right for a throwaway
directory and would make a durable one unadministrable and unrecoverable.

The realm and address are effectively **permanent for the life of the instance** —
renaming a Samba AD domain afterwards is unsupported in practice — so choose them
before converging, not after. Convergence is recorded in the instance marker only
after the guest proved it and powered off, so an interrupted run can understate
convergence but never overstate it; `-status` and `-up` say when a directory is
not provisioned, so neither implies a domain that is not there.

Real account names are instance data, so they are named in the gitignored
overlay, never in a tracked file — see `homelab/instance-example/identity/`.
Absent that file every account keeps the synthetic contract name, which is
exactly what the acceptance gates expect. The durable-account targets below are
the exception: they refuse rather than fall back.

Convergence brings up the directory; the **durable accounts** in that roster are
staged by a separate pair of targets, over the serial console (`73dbd2b`):

```sh
make homelab-factory-persistent-accounts-plan PERSISTENT_DC=<name>   # read-only
make homelab-factory-persistent-accounts APPLY=1 PERSISTENT_DC=<name> \
    [IDENTITY_OVERLAY=<principals.json>] [RESTAGE=1] \
    [PERSISTENT_ACCOUNTS_TIMEOUT=<seconds>]
```

The serial console is the only channel that reaches a *simulated* persistent
instance: its only NIC is a QEMU socket netdev to the userspace gateway, with no
NAT and no route to the host LAN, so host-side Ansible cannot reach it at all.
The applied run asks at your terminal for the `local-rescue` password and then
one password per directory role, each different; none reaches a file, an
argument, an environment or Make variable, the instance marker, or a transcript.
The plan names contract roles, `uidNumber`/`gidNumber` and the roster
fingerprint, never the real names. The daily administrator is staged as a
standard directory account and never joins Domain Admins (gate 8's
`domain-admin-separate`). After a completed or an unfinished staging run a
second one is refused unless you pass `RESTAGE=1`, which does not reset the
password of an account the directory already holds.

**Both durable paths refuse an incomplete roster** (`0e588db`, 2026-09-24). They
run only if `homelab/instance/identity/principals.json` exists **and** itself
names all three directory roles — `standard_user`, `daily_administrator` and
`domain_administrator`. The inert template, or a file naming only some roles, is
refused with the synthetic name each unnamed role would have taken, rather than
minting permanent synthetic accounts; `local_rescue` is a local account, not a
directory SID, and may stay unnamed. The plan refuses before printing anything,
so you learn this from the plan, not after typing credentials.

The host-side Ansible path remains for a Controller reachable over SSH — that
is, after network attachment — against the private inventory:

```sh
make homelab-bootstrap-controller INVENTORY=<private inventory>   # --check by default
make homelab-bootstrap-controller INVENTORY=<private inventory> APPLY=1
```

Corrected 2026-09-24: this section routed the persistent instance's durable
accounts through `homelab-bootstrap-controller` alone, which cannot reach a
simulated instance.

> **NOT RUN and unproven — do not describe durable accounts as working.**
> Neither path has run live. An adversarial review on 2026-08-17 found the
> Ansible path could not provision an account by any wired route at all. Six
> independent breaks were repaired in `f8d0348`, the sixth being that Ansible
> resolves `group_vars` relative to the **inventory source**, so an overlay
> holding `group_vars` one level above its inventory was read by nothing and
> every AD variable silently fell back to its role default. Ansible provisioning
> is now host-side and only host-side, stated rather than implied: the factory
> bundle declares an empty account list with the reason, so the in-guest
> Ansible path is testably dead rather than half-wired. None of this has been
> exercised against a live directory. Treat it as designed and repaired, never
> as proven.

On the Ansible path check mode is the default and `APPLY=1` is required to
mutate the guest. Its two preconditions are opt-in and off by default —
`homelab_ad_provision_enabled` and `homelab_ad_admin_password_file`
(root-owned, mode 0600, a path and never a value) — both documented under
"Durable directory accounts" in
[`homelab/ansible/roles/domain_controller/README.md`](../ansible/roles/domain_controller/README.md).

Two properties of the Ansible path worth knowing before you rely on it. Durable
account passwords enter as **file paths** — root-owned, mode 0600 — and never as
values, so nothing puts a secret in a template, a log or the process table. And
the accounts age under the domain's password policy: nothing here sets a
never-expiring password, because that would hide a real property.

Real account names come from the private overlay roster, and since `ee8b5e6`
the Windows identity lane derives its principals from that roster instead of
hardcoding `student` / `operator` / `directory-admin` in about fifteen places.
With no overlay every derived value is byte-identical to the literals it
replaced, so the gate-6 and gate-8 verdicts are untouched; with one, a refusal
reports the expected roster, the roster it was handed, and where it came from.
**Corrected 2026-09-24:** this paragraph said an overlay was no longer fatal to
gate 6. It was, until `efcaf6d`: the guest-side PowerShell still pinned the
synthetic names. The probe now renders the host roster into the staged control
disc, the post-submit diagnostic checks the name's shape, and a build-time guard
refuses a guest script that pins a name. A gate-6 run with an overlay has
**NOT RUN**; its post-join sign-in reference image was captured with the
synthetic operator and may need recapturing for a renamed one.

### Keep the `local-rescue` password

It is unrecoverable, and losing it costs the whole image. Convergence reaches the
guest **only** over the serial console: the disk carries no harness credential, no
authorized key and no init shell, root is locked, and SSH password authentication
is off. Nothing in this repository can open a canonical image whose console
password is gone.

The recovery is a reinstall, and it is not expensive as long as the directory is
not yet provisioned — which is the usual case, because provisioning is a separate
explicit step:

```sh
make homelab-factory-persistent-destroy APPLY=1 PERSISTENT_DC=<name> \
    CONFIRM='DESTROY <name>'                       # if one was seeded from it
make homelab-bootstrap-vm-destroy  APPLY=1 CONFIRM=bootstrap-dc
make homelab-bootstrap-seed                        # if the seed predates
                                                   # any homelab/seed/ commit
make homelab-bootstrap-vm-create   APPLY=1
make homelab-bootstrap-vm-install  APPLY=1 \
    CONFIRM='<the erasure phrase the installer asks you to type>' \
    ISO=homelab/var/media/arch/archlinux-x86_64.iso \
    SEED_ISO=homelab/var/seed/telos-controller-seed.iso
```

The last step is [0.5](#05-reinstall-the-canonical-controller-image); its first
live run, on 2026-09-24, succeeded. The fallback, if it refuses or misbehaves,
is the hand-driven console session: `make homelab-bootstrap-vm-run APPLY=1
SEED_ISO=homelab/var/seed/telos-controller-seed.iso`, then reinstall from the
console as in `homelab/seed/README.md` and
[`homelab/vm/README.md`](../vm/README.md) ("Interactive offline installation").

Rebuilding the canonical image invalidates no gate receipt: the disk digest is
captured per run at prepare time by `ControllerOverlay`, and no tracked artifact
pins it.

Once a directory **is** provisioned, the same loss is expensive rather than cheap:
the accounts, the domain SID and every machine's join live only on that disk.

## Stage 5 — Verify, recover, repeat

### 5.1 Final verification (read-only; never installs)

```sh
make homelab-factory-verify FACTORY_EVIDENCE=<retained run evidence dir> APPLY=1
#   optional FACTORY_RELEASES=<release set>
```

Dry run prints the check plan; `APPLY=1` validates retained evidence and emits a
machine-readable receipt with a `PASS`/`FAIL`/`NOT RUN` verdict. A measurement
that is absent stays `NOT RUN` and is never promoted to a pass. It confirms the
canonical controller disk/firmware are unchanged, all guest disks are disposable
and run-scoped, no TAP/bridge/route/VLAN/forwarding/UniFi change occurred, no
external connection happened after the offline gate, Windows was installed before
Arch and remains default, both OSes pass online and cached-offline login,
optional storage absence never blocks login, and no tracked artifact carries
media/credentials/private values. **Evidence:** the emitted verdict for the run.

### 5.2 Lifecycle recovery (gate 11)

```sh
make homelab-factory-recover RECOVERY_RUN=<fresh run bundle dir> APPLY=1
#   optional FACTORY_RELEASES=<set> SEED_ISO=<seed> FACTORY_DURATION=<seconds>
make homelab-factory-recover-judge RECOVERY_EVIDENCE=<produced recovery-evidence.jsonl>
```

Exercises controller restart/loss, PXE release rollback, failed-install
recovery, broken-boot repair, directory/DNS loss, update-failure handling,
workstation remint, and controller reconstruction. **Evidence — gate 11
PARTIAL:** three scenarios are **proven live** in the loopback lab (2026-08-12):
`pxe-release-rollback`, `update-failure-rollback` (per ADR
[0075](../decisions/0075-automatic-gated-arch-workstation-updates.md)), and
`workstation-remint`.

**Changed 2026-08-17 (`2c3cd56`):** two of the five live-boot hooks are now
*implemented* — `directory-dns-loss` and `controller-reconstruction` — driven
over the gate-8 loopback identity topology, with every judged field backed by a
token-scoped marker the guest itself printed (`controller_frozen` is proven by
the workstation refusing an unprimed domain principal, not by the host's own
SIGSTOP flag). `2aaa7fe` also made this target forward the identity bundle and
controller state those hooks need; without it they would have deferred even
under `RECOVERY_BOOT=1`.

**They have NOT RUN:** implementing a hook is not running it, and no live boot
has been driven. The remaining three (`controller-restart`,
`failed-install-recovery`, `broken-boot-repair`) stay stubs because the
primitives they need do not exist — there is no way to power-cycle a live
Controller and re-establish its console (the boundary exposes an outage, not a
restart), nothing can break a guest's bootloader and repair it, and no
fault-injection seam can make an install fail on purpose. The judge returns
verdict `partial`, which is honest deferral, not a pass, and will keep doing so
until all five exist **and** a live boot runs.

### 5.3 Repeatability — **NOT RUN (gate 12)**

```sh
make homelab-factory-repeat                        # read-only dry run; safe any time
make homelab-factory-repeat APPLY=1 FACTORY_DURATION=<per-phase seconds>
```

The aggregate repeat driver now exists (`27d8af9`, wired by `2aaa7fe`), so the
second blocker recorded here until 2026-08-17 — "`homelab-factory-repeat` is
reserved and not implemented" — is **gone**. No phase bundle can reach gate 12
alone: install order needs both installs in one list and the login checks need
both operating systems in one receipt, so the driver runs the phases in order
and assembles one union receipt from their bundles.

| Variable | Default | Meaning |
|---|---|---|
| `REPEAT_EVIDENCE_ROOT` | `homelab/var/factory/repeat` | Aggregate bundle per iteration. |
| `REPEAT_WORK_ROOT` | `homelab/var/factory/repeat-work` | Disposable work root, destroyed before each iteration. |
| `REPEAT_ITERATIONS` | `2` | Gate 12 requires at least 2. |
| `REPEAT_RECEIPT` | unset | Optional path for the comparison receipt. |
| `FACTORY_DURATION` | `120` | Forwarded to each phase as its **per-phase** budget. |

**The 120-second `FACTORY_DURATION` default is far too small for a real
lifecycle** — a single Windows install alone has run 68 minutes — and the value
applies to *every* phase, not to the run. Budget per phase and expect hours.

The dry run starts nothing. Verified 2026-08-17 it prints the loopback boundary,
the iteration count, both roots, the release set, the six phases in order
(`windows-install`, `windows-identity`, `arch-install`, `arch-identity`,
`dualboot-acceptance`, `lifecycle-recovery`, each naming the Make target that
really runs it), the four producer measurements now available, and any
precondition that would refuse. Against a never-installed canonical image it
refuses, naming the remedy; this is what it printed until 2026-09-24:

```text
! refuses to apply: canonical Controller image …/bootstrap-dc.qcow2 is not an
  installed Controller: the image is entirely unallocated; nothing has ever
  been written to it. No live lifecycle can run against it; run
  `make homelab-bootstrap-vm-install` first
```

That refusal reads the real partition table and is fail-closed, so a partially
written disk over a size floor does not satisfy it. Since the canonical image
was installed on 2026-09-24 the dry run no longer refuses.

**All sixteen gate-12 checks now have a wired producer.** The four that never
had one — `login`, `optional_storage_absence_nonblocking`,
`host_network_changes`, `artifact_scan` — landed in `aec5747`, `390e5cf` and
`280c99d`. Two honest limits go with that:

- `host_network_changes` **cannot legitimately render PASS today.** Its `unifi`
  counter is unprovable without a run-window host egress ledger, which nothing
  produces; a snapshot pair cannot prove a connection that opened and closed
  between snapshots. The sentinel is deliberately not an integer, so a producer
  that omits the field leaves the check NOT RUN and one that emits an unproven
  counter renders FAIL. Neither can render PASS.
- `artifact_scan` requires a scanned tree; without one the check stays NOT RUN.

Nothing blocks the live twice-through any more except running it: two live
lifecycles, with the two limits above. The canonical Controller image was
installed on 2026-09-24 — see
[Resolved 2026-09-24: the canonical Controller image is installed](#resolved-2026-09-24-the-canonical-controller-image-is-installed)
— and the old blocker "pending gates 6–10" was satisfied 2026-08-14: gates 6, 7,
8, 9 and 10 all pass. Corrected 2026-09-24: this paragraph named the absent
canonical image as the one remaining blocker.

**Verdict: NOT RUN.** The driver is implemented and unit-tested; it has never
completed a live lifecycle — `SubprocessLifecycle`'s only execution was an
accidental, interrupted launch from inside the unit suite on 2026-09-24, fixed
by `272d693` — the phase table was read off the Makefile rather than confirmed
against a live lifecycle, and every end-to-end test fabricates its bundles. What is proven is that the
aggregation is deterministic, not that two real lifecycles agree.

### 5.4 Declared-service gate for a candidate image — **judge only**

```sh
make homelab-image-service-gate \
  IMAGE_PROFILE=<installer-live|controller-seed|workstation-install> \
  IMAGE_TRANSCRIPT=<retained guest console capture> \
  [IMAGE_SERVICE_TOKEN=<run token>] [IMAGE_SERVICE_EVIDENCE=<output path>]
```

`homelab-image-service-gate` (`0c2df66`) grades a booted candidate image's
declared systemd services against the tracked contract, from a retained guest
console transcript. It is pure host-side: no guest, no root, no QEMU, and no
registry override. `IMAGE_PROFILE` and `IMAGE_TRANSCRIPT` are both required
(exit 2 without either). An undeclared but enabled unit degrades the verdict to
`partial` and is named rather than failing outright, since stock systemd presets
legitimately enable units the contract has no opinion about; only `pass` may be
read as "services verified".

**The live capture half does not exist.** Producing the transcript needs a
booted candidate image, which needs root, so the judge is **available** and the
capture is **BLOCKED**. `services_verified` is therefore **NOT RUN**. This is
the same split both identity gates already use.

---

## Pass/fail gate summary (as of ledger `20260924.001`)

| Gate | What it proves | Real target(s) | State |
|---:|---|---|---|
| 1 | Media intake | `homelab-factory-media`, `homelab-factory-cache-seal` | PASS |
| 2 | Immutable releases | `homelab-factory-pxe VERSION=…` | PASS (`20260727.001`) |
| 3 | Controller convergence | `homelab-factory-controller-bundle APPLY=1` (+ live runners) | PASS |
| 4 | PXE authority boundary | `homelab-pxe-authority-audit SWITCH=…` | **PASS** |
| 5 | Windows-first install | `homelab-windows-install-{prepare,run}` | **PASS** |
| 6 | Windows join/login | `homelab-windows-identity-{prepare,run,judge}` | **PASS**, 24/24 contracted checks; judge also reports `deferred: [disable-reenable]` and `out_of_scope: [firmware-activation, live-microsoft-update]` |
| 7 | Arch-second install | `homelab-arch-install-{prepare,run}` | **PASS** |
| 8 | Arch join/login | `homelab-arch-identity-{prepare,run,judge}` | **PASS**, 21/21, proven live 2026-08-14 (bundle `arch-identity/run-20260814T172142Z-495164bc7159`; judge prints `PASS: 21 checks, external_access=False`) |
| 9 | Optional storage failure | *(no target of its own, by design: it rides gate 6 and gate 8)* | **PASS** — the Windows half in the 2026-08-13 gate-6 evidence, the Arch half graded inside the passing 2026-08-14 gate-8 run |
| 10 | Dual-boot acceptance | `homelab-dualboot-acceptance-{prepare,run,judge}` | **PASS**, 8/8; judge reports `deferred: [windows-login-driven, arch-authenticated-login]`, and Windows was observed booting rather than driven to a login or a clean shutdown |
| 11 | Lifecycle recovery | `homelab-factory-recover`, `-recover-judge` | **PARTIAL** — 3 pass / 5 not-run, retained at `homelab/var/factory/recovery/run-20260814T120300Z-3b3169f9f15f/`. Two of the five live-boot hooks are now *implemented* (`directory-dns-loss`, `controller-reconstruction`, `2c3cd56`) but **NOT RUN**; three remain stubs for want of a Controller restart, a bootloader break-and-repair, and install fault injection. Verdict stays `partial` until all five exist and a live boot runs. |
| 12 | Repeatability | `homelab-factory-repeat` (aggregate driver, `27d8af9`/`2aaa7fe`), `homelab-factory-verify` (per-bundle comparator) | **NOT RUN** — no longer blocked by any gate, and no longer blocked by a missing driver. All sixteen checks now have a wired producer (`aec5747`, `390e5cf`, `280c99d`), but `host_network_changes` cannot legitimately render PASS without a run-window host egress ledger that does not exist, and `artifact_scan` needs a scanned tree. The canonical Controller image is installed (2026-09-24); what remains is two live lifecycles. |
| 13 | Documentation | this runbook + [human guide](factory-guide.md) | in progress |
| 14 | External integration (UniFi/physical) | *(blocked by design)* | **BLOCKED** |

Gate 9 has no acceptance target of its own by design: its checks ride the two
identity gates. `homelab/workstations/acceptance.json` carries six
`optional-storage` checks — `windows-smb-{available,unreachable,denied}` and
`arch-smb-{available,unreachable,denied}` — and
`homelab/workstations/windows_identity_acceptance.py` gates the Windows side
through `optional-storage-offline` and `optional-storage-access-denied`. Both of
those passed in the 2026-08-13 gate-6 run, so the Windows half is live-proven.
The three `arch-smb-*` checks are driven by `arch_identity_run.py` as
`arch-storage-{attached,denied,absent-login}`, and they **passed inside the
gate-8 run of 2026-08-14** (`arch-identity/run-20260814T172142Z-495164bc7159`),
which closes gate 9's Arch half.

An earlier revision of this section claimed the identity contract carries no
storage check. That was wrong — corrected 2026-08-14.

---

## Troubleshooting — failure modes actually hit this session

**Frozen / offline DC, cached logon.** The gate-6 sequence deliberately takes
the controller offline (`controller-offline`) and proves cached login still
works (`windows-cached-login`, `windows-cached-admin-login`) while a
never-cached account is refused (`windows-uncached-denied`). If a cached login
*fails* offline, check that the prior online login actually cached
(`windows-cached-policy`) before blaming the DC. Reaching `controller-restored`
and `windows-secure-channel-restored` proves the channel heals when the DC
returns.

**Credential-media cleanup.** Two one-use credential carriers are built,
attached, consumed, and destroyed within a run: the gate-7 `TELOS_JOIN` ISO and
the gate-6 recovery publication. If a gate-6 attempt reports the gate-5
publication already consumed, that is expected — re-run Stage 2.1 to regenerate
the bundle. Never re-use or retain a credential ISO across runs.

**Live-scan / audit surfaces.** The gate-6 `windows-diagnostics-sanitized` check
and a live-tolerant secret scanner guard against leaking real values into
evidence. A gate-4/authority audit that failed on a **QEMU zombie at teardown**
was a same-EUID transient process the overlay-ownership audit could not inspect;
the fix re-checks such a process over a small bounded budget and skips it only if
it exits (staying live and un-inspectable still fails closed). If an audit
fails on `simulation_overlay` "cannot inspect process … file descriptors", look
for a leftover QEMU process, not a boundary breach.

**Gate-7 "disk has no partitions".** This was the verify's `lsblk` parse, not
the guest, transport, or timing. The `confirm_disk` step now forces an
NVMe-namespace rescan (`nvme ns-rescan`, `rescan_controller`) before
`partprobe`. If partitions still do not surface after a PCIe hotplug, that is the
place to look — not the backing image (which genuinely holds the Windows GPT).

**PXE never boots (firmware boots the disk instead).** With a bootable Windows
ESP on the target disk, OVMF auto-discovers and boots it, ignoring `-boot
order=n`. The fix is to PXE-boot with the NVMe **detached** (archiso is a RAM
live environment and needs no disk) and QMP hot-attach the disk after archiso is
up — mirroring a real PXE install. A serial that shows
`BdsDxe: starting … Windows Boot Manager` instead of `UEFI PXEv4` is this
failure.

**archiso login handshake.** The arch-workstation PXE release presents an
`archiso login:` prompt; the installer driver logs in as `root` (no password) at
that prompt before hot-attach and install. A run that stalls with no install
markers after reaching `archiso login:` is the login handshake, not the
transport.

---

## Rollback, recovery, and rebuild

- **Rollback a bad release:** proven live via `homelab-factory-recover`
  (`pxe-release-rollback`); the immutable release set is addressed by
  `YYYYMMDD.NNN`, so rolling back is selecting the prior set.
- **Failed install / broken boot / directory loss / controller loss:** driven by
  `homelab-factory-recover`; these five defer their live-boot proof today (gate
  11 `partial`). Follow the observable contract the runner records and escalate
  before assuming a scenario passed.
- **Rebuild a workstation image:** re-run Stages 0.3 → 5 from the sealed cache
  (no re-acquisition needed once `homelab-factory-offline-check` passes). Because
  install does only what cannot be done later, the normal fix for a damaged image
  is a clean re-mint, not an in-place repair.
- **Clean up a run:** the reserved `homelab-factory-clean` target is **not
  implemented**; remove a named disposable run bundle under `homelab/var/factory/`
  directly, and never delete sealed media or another run's evidence.
- **Reinstall the canonical Controller image:** `homelab-bootstrap-vm-install`
  (see [0.5](#05-reinstall-the-canonical-controller-image)); **PASS**, one live
  run on 2026-09-24, with the hand-driven console session as the documented
  fallback.

## Final verification and evidence to retain

Before declaring a build done, run `homelab-factory-verify` (Stage 5.1) with
`APPLY=1` and read its verdict. Retain, per run: `result.json` and its
`status`/`phase` markers, `acceptance-progress.json` (gate 6), `switch.jsonl`
(gate 4), and the recovery-evidence stream — all under
`homelab/var/factory/**`, mode `0600` where credential-adjacent. These are
**host-private, git-ignored** and are **not** release artifacts: never commit,
publish, or copy them, and never treat a missing evidence file in a fresh clone
as a pass.

## Read-only re-checks (safe any time)

```sh
make check                       # site manifest, tests, tmt registry gate
make homelab-factory-offline-check
make homelab-pxe-authority-audit SWITCH=<run>/evidence/switch.jsonl
make homelab-factory-verify FACTORY_EVIDENCE=<run dir>   # dry run without APPLY
make homelab-factory-repeat      # dry run: phase plan, producers, refusals
make homelab-bootstrap-vm-status # is the canonical image installed?
```

None of these boot a guest, mutate evidence, or touch the network.
