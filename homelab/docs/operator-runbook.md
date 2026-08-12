# Workstation factory — operator runbook

An exact, ordered runbook for building and verifying the isolated workstation
factory on one Arch build host. Every command below is a real `make` target
verified against the [Makefile](../../Makefile) and the
[Make contract](../FACTORY-MAKE-TARGETS.md). Every evidence claim matches the
[factory state ledger](../WORKSTATION-FACTORY-STATE.md); where a step is not yet
proven live, it is marked **PENDING** and never described as working.

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

### Target names: real vs reserved

[FACTORY-MAKE-TARGETS.md](../FACTORY-MAKE-TARGETS.md) reserves several aggregate
names that are **not implemented as Make targets**. Do not invoke them; use the
granular targets in this runbook. Reserved-but-absent (verified with `grep` of
the Makefile): `homelab-factory-controller`, `homelab-factory-authority-check`,
`homelab-factory-windows`, `homelab-factory-arch`,
`homelab-factory-dualboot-check`, `homelab-factory-clean`,
`homelab-factory-repeat`, `homelab-factory-fresh-clone`. Each maps to the real
targets below.

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
   arch-install (gate 7) -> arch-identity (gate 8, PENDING)
                                    |
                                    v
             dualboot-acceptance (gate 10)
                                    |
                                    v
                verify -> recover -> (repeat, PENDING)
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

**Evidence — gate 6 ALL 24 CHECKS PASS 2026-08-12**, attempt
`20260812T043214Z-28ff545de0ce`. `acceptance-progress.json` records
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

### 3.2 Arch join and login — **PENDING (gate 8)**

```sh
make homelab-arch-identity-prepare \
  ARCH_RUN=<passing arch install bundle> \
  WINDOWS_IDENTITY_EVIDENCE=<produced gate-6 acceptance JSONL> APPLY=1
make homelab-arch-identity-run ARCH_IDENTITY_BUNDLE=<joined arch bundle> APPLY=1
make homelab-arch-identity-judge ARCH_IDENTITY_EVIDENCE=<produced JSONL>
```

The targets exist and the live boundary is wired (synthetic principals now carry
POSIX attributes, staged per run). **This gate has not passed live.** Its
SSSD-identity, UID/GID-stability, cached-offline-login, update-gate, rollback,
and local-rescue proofs are still to be produced. Do not report gate 8 as
working.

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
(~5 s), Windows booted and shut down cleanly, boot 2 arrow-navigated to Arch,
the GPT was byte-unchanged, and both EFI boot managers plus the recovery entry
were present. Note `windows_login_proven: false` here — **live Windows login is
proven by gate 6's identity stream, not this gate.**

---

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
`workstation-remint`. The five that need a live guest boot
(`controller-restart`, `failed-install-recovery`, `broken-boot-repair`,
`directory-dns-loss`, `controller-reconstruction`) record their observable
contract and **defer** the boot proof; the judge returns verdict `partial`,
which is honest deferral, not a pass.

### 5.3 Repeatability — **PENDING (gate 12)**

The verifier and receipt comparator are implemented
(`homelab/vm/factory_verify.py`), but a full twice-through of the whole
lifecycle from destroyed disposable state is **pending gates 6–10 running
together live**. The reserved `homelab-factory-repeat` and
`homelab-factory-fresh-clone` aggregate targets are **not implemented**; repeat
by re-running Stages 0–5 from the sealed cache and comparing receipts with
`homelab-factory-verify`.

---

## Pass/fail gate summary (as of ledger `20260812.001`)

| Gate | What it proves | Real target(s) | State |
|---:|---|---|---|
| 1 | Media intake | `homelab-factory-media`, `homelab-factory-cache-seal` | PASS |
| 2 | Immutable releases | `homelab-factory-pxe VERSION=…` | PASS (`20260727.001`) |
| 3 | Controller convergence | `homelab-factory-controller-bundle APPLY=1` (+ live runners) | PASS |
| 4 | PXE authority boundary | `homelab-pxe-authority-audit SWITCH=…` | **PASS** |
| 5 | Windows-first install | `homelab-windows-install-{prepare,run}` | **PASS** |
| 6 | Windows join/login | `homelab-windows-identity-{prepare,run,judge}` | **PASS 24/24** |
| 7 | Arch-second install | `homelab-arch-install-{prepare,run}` | **PASS** |
| 8 | Arch join/login | `homelab-arch-identity-{prepare,run,judge}` | **PENDING (wired)** |
| 9 | Optional storage failure | *(no target yet)* | **PENDING** |
| 10 | Dual-boot acceptance | `homelab-dualboot-acceptance-{prepare,run,judge}` | **PASS** |
| 11 | Lifecycle recovery | `homelab-factory-recover`, `-recover-judge` | **PARTIAL** |
| 12 | Repeatability | `homelab-factory-verify` (comparator) | **PENDING** |
| 13 | Documentation | this runbook + [human guide](factory-guide.md) | in progress |
| 14 | External integration (UniFi/physical) | *(blocked by design)* | **BLOCKED** |

Gate 9 has no acceptance target yet: the identity contract carries no storage
check. It needs a loopback SMB target, an optional-mount client policy, and a
three-state Arch judge before it can be claimed.

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
```

None of these boot a guest, mutate evidence, or touch the network.
