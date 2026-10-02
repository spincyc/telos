# Workstation factory — operator runbook

Version `20261002.001`

An exact, ordered runbook for building and verifying the isolated workstation
factory on one Arch build host. Every command below is a real `make` target
verified against the [Makefile](../../Makefile) and the
[Make contract](../FACTORY-MAKE-TARGETS.md). Every evidence claim matches the
[factory state ledger](../WORKSTATION-FACTORY-STATE.md); where a step is not yet
proven live, it is marked **NOT RUN** (or **PENDING**) and never described as
working.

Pair this with the [human guide](factory-guide.md) for orientation.

## Conventions and safety

- **Review the target's boundary.** Factory live targets require `APPLY=1`;
  media/dependency acquisition and cache construction have their own effects
  described below. Acceptance runs use disposable qcow2 overlays. Persistent
  directory operations change their named instance in place, and successful
  durable workstation stages replace that workstation's disk under its lock.
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
- The synthetic lab is public test data: realm **`AD.FACTORY.TEST`**; use the
  Makefile's default `BASE_URL` for the simulated controller. Real
  hostnames, addresses, and credentials live only in the private overlay
  (`telos-private`) and must never enter this tree.

### Resolved 2026-09-24: the canonical Controller image is installed

**The existing build host has an installed image; a fresh clone does not.**
For a new host, acquire the media and build the offline seed in Stage 0.2,
then create and install the absent canonical VM in Stage 0.5. Do not use the
lost-password destroy procedure to initialize a fresh clone. From
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
[5.3 Repeatability](#53-repeatability-gate-12).

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
      verify -> recover (gate 11, partial) -> repeat (gate 12, accepted with waiver)
```

## Common variables and their defaults

| Variable | Default | Meaning |
|---|---|---|
| `APPLY` | unset (dry run) | Set to `1` to actually mutate |
| `ARCH_ISO` | `homelab/var/media/arch/archlinux-x86_64.iso` | Verified Arch ISO |
| `WINDOWS_ISO_CACHE` | `homelab/var/media/windows/windows-11-x64.iso` | Imported Windows ISO |
| `WINDOWS_INSTALL_SOURCE` | `homelab/var/media/windows/install-source` | Staged Windows Setup source, required before sealing |
| `WORKSTATION_REPO` | `homelab/var/media/arch/workstation-repo` | Signed Arch package repo |
| `SAMBA_DNS_CACHE` | `homelab/var/media/samba-dns` | Pinned, verified Samba SRV repair library and receipt |
| `WIMBOOT` | `homelab/var/media/wimboot` | Pinned iPXE `wimboot` |
| `FACTORY_MEDIA_SEAL` | `homelab/var/media/factory-media-seal.json` | Aggregate media seal |
| `FACTORY_DURATION` | `120` | Bounded live-run seconds, per phase. The default suits only a dry run: a Windows install takes ~69 min, so pass 5400-7200 for a real one |
| `BASE_URL` | Synthetic Controller URL from the Makefile | Controller HTTP base for releases; omit to use the isolated lab default |
| `VERSION` | *(required for `-pxe`)* | Release id `YYYYMMDD.NNN` |

`homelab/var/` is gitignored, but it also holds native directory backups under
`backups/`; it is not all disposable. Preserve backups and retained evidence.
Never commit media, credentials, private inventory, or evidence.

---

## Stage 0 — Prerequisites

### 0.1 Build-host dependencies (online; explicit operator action)

```sh
make homelab-factory-deps
```

`homelab-factory-deps` chains `homelab-bootstrap-deps`, which installs or
upgrades the full Arch build-host closure (QEMU `qemu-base`, `edk2-ovmf`, `archiso`, `samba`,
`krb5`, `dnsmasq`, `nginx`, `ipxe`, `ansible`, `wimlib`, `gptfdisk`, `mtools`,
and the Python/TeX/site sets). Review the declared closure before invoking it:
the target runs one full `pacman -Syu --needed --noconfirm` transaction, using
`sudo` unless already root. This changes host packages. **Evidence:** require
exit 0. The lightweight read-only live-tool subset can be re-checked with
`make homelab-sim-deps` (checks `qemu-system-x86_64`, `qemu-img`, `sfdisk`,
`mcopy`).

### 0.2 Acquire and import media (online or local import)

```sh
make homelab-factory-media
```

This fans out to `homelab-media-arch` (fetches + digest/keyring-verifies the
Arch ISO), `homelab-media-workstation-repo` (resolves the signed Arch install
closure into `WORKSTATION_REPO`), `homelab-media-samba-dns` (builds and verifies
the pinned SRV serializer repair), `homelab-media-wimboot` (version/hash-pinned
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

After import succeeds, stage the Windows source before sealing:

```sh
make homelab-stage-windows-source
```

The aggregate media target does not perform this step. It writes the atomic,
receipt-backed `WINDOWS_INSTALL_SOURCE` cache without changing the imported
ISO. For individual acquisition targets, see [fresh-clone media intake](../media/FRESH-CLONE.md).
The [Samba DNS repair contract](../media/samba-dns/README.md) owns the pinned
source/package versions, two-build check, ABI admission and upgrade rules.
Do not replace its required verified library/receipt pair with an arbitrary
host library.

**Prepare Controller artifacts while online.** A fresh canonical image needs
the offline seed; building it downloads its package closure:

```sh
make homelab-bootstrap-seed
```

Require the completed `homelab/var/seed/telos-controller-seed.iso`; see the
[seed contract](../seed/README.md). Separately, the aggregate PXE release
requires a completed Controller netboot tree. From repository root, with
`archiso` installed and a dedicated unused `/tmp/homelab-image` work tree:

```sh
make homelab-image
sudo mkarchiso -v -w /tmp/homelab-image/work \
  -o /tmp/homelab-image/out /tmp/homelab-image/profile
```

The first command stages and audits the installer, module closure and profile;
continue only if its audit succeeds. Build the staged profile, not the raw
tracked `homelab/archiso` directory. A public `authorized_keys` is optional:
without one, the image has console access and SSH is disabled. For another
work directory use `python3 homelab/bin/homelab-image --work <absolute-path>`
and follow its printed build command. `--check` also stages; it is not read-only.
Require a successful build and retain its completed `out/` as
`CONTROLLER_SOURCE` for Stage 1.2. See [the netboot recipe](../archiso/README.md).
Neither the seed ISO nor a stock Arch ISO is that source. ADR 0079 still
excludes replacement-Controller PXE mint acceptance; the canonical Controller
is installed from Arch plus the seed below.

### 0.3 Seal the cache (no downloads)

```sh
make homelab-factory-cache-seal
```

**Evidence:** prints `PASS: local factory media cache is sealed` and writes the
atomic aggregate receipt `homelab/var/media/factory-media-seal.json` binding
Arch, the Windows provenance/Pro verification, the Windows install source, and
`wimboot`, plus the verified Samba DNS repair library and receipt (including
pinned provenance), recording content hashes and tool versions separately.
The seed and Controller netboot builds above are separate local prerequisites;
this media seal alone does not prove either build completed.

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

**Existing host: done 2026-09-24.** First check status; leave a ready image in
place. On a fresh clone with no canonical VM, plan and create it before the
owner-terminal install below:

```sh
make homelab-bootstrap-vm-status
make homelab-bootstrap-vm-plan
make homelab-bootstrap-vm-create APPLY=1
```

If an existing image is lost, follow the separately guarded destroy/recreate
procedure in [Keep the `local-rescue` password](#keep-the-local-rescue-password).
The install refuses any disk that is not freshly created. Its first live run
succeeded; see
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

The fallback uses the same installer, not a second disk recipe. Its fixed VM
serial fits QEMU's 20-character virtio limit; never shorten a different serial
to make an identity check pass. The installer initializes/populates the live
Arch keyring and invokes offline `pacstrap -C ... -U <target> ...`; retain those
steps and option order when diagnosing a failed seed install. The source checks
live in `homelab/tests/test_seed_installer.py` and `test_bootstrap_vm.py`.

For a hand-driven console, shut down with the guest's `sudo poweroff` and wait
for QEMU to exit. `Ctrl-a c` switches its multiplexed serial console/monitor;
`Ctrl-a h` shows QEMU's help. If tmux intercepts that prefix, identify the guest
pane and use `tmux send-keys -t <guest-pane> C-a c` from another terminal. Do not
use a monitor quit or kill as a clean directory shutdown. Before acceptance,
the seed guide's checks must show working `local-rescue` sudo, locked root,
the expected root filesystem, systemd-boot/LTS entry and zero failed units.

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
make homelab-factory-pxe VERSION=YYYYMMDD.NNN \
  CONTROLLER_SOURCE=/tmp/homelab-image/out
# optional: ARCH_SOURCE=<...> BASE_URL=<...>
```

Requires a `VERSION` of the form `YYYYMMDD.NNN` (it errors without one). It
delegates to `homelab-pxe-release-set`, building the controller, Arch, and
Windows leaves transactionally under one release id. **Evidence:** a
`homelab/var/pxe` release set for `VERSION`; the selected set is
`20261001.001` (aggregate manifest SHA-256 `5f319624…fdd6311`), bound to the
current seal including Arch 2026.08.01 and the Samba repair bytes. Historical
sets `20260727.001`–`.005` bind the retained July seal, so
`make homelab-pxe-release-set-verify RELEASE_SET=<set>` refuses them
unless `FACTORY_MEDIA_SEAL=homelab/var/media/factory-media-seal.20260727-releases.json`;
new builds use the current seal. The separately reserved keeper Windows
bundle `run-20261001T235652Z-a782e2f67fac` used `.005`, prepared before resealing.

`CONTROLLER_SOURCE` is the completed netboot `out/` from Stage 0.2, not
`profile/` or `out/arch/`. Omit it only when a verified tree already exists at
`FACTORY_CONTROLLER_SOURCE` (default `homelab/var/media/controller/netboot`);
a fresh clone must build or supply it. The seed ISO is a data disc and is
never substituted. Verify the new set before using it:

```sh
make homelab-pxe-release-set-verify \
  RELEASE_SET=homelab/var/pxe/release-sets/YYYYMMDD.NNN
```

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

Windows-install switch logs from before TASK-43 (2026-10-01) fail
`gate4.controller-approved-flows-only` on one unanswered workstation→controller
UDP `500->500` flow. It is stock WinPE's built-in IPsec negotiation-discovery
probe, which IKEEXT sends at the SMB source mount. The owner decision is to
suppress the sender and leave the approved controller surface unchanged. The
generated `install.bat` therefore disables and stops IKEEXT right after
`wpeinit`; see `WINPE_IKE_SUPPRESSION` in
`homelab/vm/windows_install_contract.py`.

**Fresh gate-4 proof PASS, 2026-10-02.** Typed VBS calls in `8eb69a9` are
proven by the complete Windows run `run-20261001T235652Z-a782e2f67fac` plus
Arch `run-20261001T193550Z-e5108779aad1`: all four checks passed in
`homelab/var/factory/authority-audits/20261002-winpe-vbs-merged.json`
(34 DHCP server frames, all gateway; 268 approved flows). Both gate-4 audits
in the original October 2 repeat also passed. Earlier `68800da` required
unavailable `sc.exe`; a later WMIC parser falsely rejected a successful
change. Those failed attempts remain historical evidence. Gate-4 proof alone
does not close gate 12, and no firmware-fix claim follows from it.

---

## Stage 2 — Windows first (gate 5) and Windows identity (gate 6)

### 2.1 Install Windows 11 Pro first

```sh
make homelab-windows-install-prepare APPLY=1
make homelab-windows-install-run WINDOWS_RUN=<prepared bundle> APPLY=1 \
  FACTORY_DURATION=7200
```

**Set `FACTORY_DURATION`.** Its 120-second default aborts a real install, which
takes about 69 minutes; budget 5400-7200 seconds. It bounds one phase, not a
whole run.

`-prepare` builds a disposable private bundle; `-run` PXE-boots WinPE and
installs Windows 11 Pro to the approved layout against a fresh overlay, then
reboots with no ISO/PXE attachment. WinPE has no disk-serial query: it proceeds
only when exactly one online disk, disk 0, of the authorized capacity is
present, and the host binds and audits that disk's serial (ADR
[0078](../decisions/0078-private-disposable-windows-automation.md)). A physical
install is interactive instead: `homelab/pxe/windows/FLOW.md`. **Evidence — gate 5 PASS 2026-08-10**,
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
#   optional WINDOWS_RUN=<gate-5 bundle>/windows.qcow2 to overlay that Windows
#   disk -- the disk FILE, not the bundle directory (gate 6 takes the directory)
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
bounded power-cycle retry) is not root-caused. Corrected 2026-09-30: this also
listed the fleet `sssd.conf.j2` `offline_timeout` bounds as open; `2f86a21`
(2026-08-14) added them.

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

**Repeated 2026-10-02:** `run-20261002T163609Z-9bc15e4653cd` passed all
eight checks with Windows default, byte-identical partitions and clean
shutdowns for both operating systems. Its `windows_login_proven` remains
false; the same repeat's Windows identity stream passed all 24 checks.

**A gate-7 disk made since 2026-08-14 reaches its getty slowly.** It bakes in
`telos-arch-join-once.service` and `telos-arch-domain-online.service`, both
ordered before `systemd-user-sessions.service`. Gate 10 attaches no media and
no network, so the first spends 120 s waiting for
`/dev/disk/by-label/TELOS_JOIN` and the second another 120 s waiting for a
directory account, pushing the ttyS0 getty roughly 240 s past kernel handoff.
Since `f8f0443` (2026-10-01) `observe_boot`'s login wait is derived from those
two bounds (420 s), so any gate-7 bundle serves. Corrected 2026-10-01, kept so
it is not re-derived: the old fixed 120 s wait failed
`arch-console-login-surface` on such a disk — the first gate-12 run's
failure — and this paragraph said to use only an 08-11 bundle.

---

## The persistent directory instance (not part of any gate)

> **Serial-console path PROVEN LIVE 2026-09-25, once each, on a throwaway
> instance.** `homelab-factory-persistent-converge` provisioned the owner's
> permanent realm in place, and `homelab-factory-persistent-accounts` (with
> `CHANGE_AT_FIRST_LOGON=1`) staged the four durable accounts at their pinned
> UIDs; both finished with a clean poweroff. Three defects surfaced on the way
> and are fixed: the recorded domain SID was read from a split serial chunk
> (`05eec6e`; the instance converged before it keeps a truncated SID in its
> marker), a refused password was an unexplained "stage returned 1"
> (`efedf50`), and there was no way to start with temporary passwords
> (`1b04fd3`). Native backup and same-instance restore under a new DC name
> passed on 2026-10-01. After Samba SRV repair, the existing SRV-first
> workstation passed keep-verify 40/40 without rejoining either OS or changing
> its kept disk, firmware variables or marker
> (`run-20261001T235410Z-588718-de077620`); see the backup contract's live record.
> Owner-custody keeper and physical recovery remain unperformed.
> Still **NOT RUN**: `-up` under owner custody
> and the Ansible accounts path. A kept workstation against a
> persistent instance (TASK-28,
> [`DURABLE-WORKSTATION-FLOW.md`](../DURABLE-WORKSTATION-FLOW.md)) **PASSED
> live end to end 2026-09-30**, unattended under agent custody. Since
> `dfbcce7` convergence enables the TFTP and HTTP PXE units and exits 2 unless
> both are active (unit-tested only); an instance converged earlier needs
> `RECONVERGE=1` before a reboot-survival check.

Everything above is the **acceptance** factory, and its controller is disposable
on purpose: the canonical image carries no directory, the role provisions one
whenever `sam.ldb` is absent, and teardown discards the overlay after
re-verifying the canonical digests. That is what gate 3 requires and what gates 8
and 12 depend on — and it also means no account can survive relaunching the
directory.

A **persistent instance** exists alongside it for the case where you want a
workstation you can log back into, minted by the durable workstation flow
(below). It is opt-in by name, lives in its own state
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
make homelab-factory-persistent-up     APPLY=1 PERSISTENT_DC=<name> CUSTODY=agent THROWAWAY=1  # throwaway rehearsal: harness-held credentials, every stage unattended (TASK-40)
make homelab-factory-persistent-destroy APPLY=1 PERSISTENT_DC=<name> \
    CONFIRM='DESTROY <name>'
```

> **Kept workstations: PROVEN LIVE 2026-09-30.** The durable workstation flow
> (TASK-28) mints Windows and Arch on one disk against a persistent instance;
> every stage through keep-verify passed, unattended under agent custody, on a
> throwaway instance. Targets and verdicts:
> [`FACTORY-MAKE-TARGETS.md`](../FACTORY-MAKE-TARGETS.md), "Kept
> workstations"; design and run record:
> [`DURABLE-WORKSTATION-FLOW.md`](../DURABLE-WORKSTATION-FLOW.md). Corrected
> 2026-09-30: this callout said no workstation could be installed against a
> persistent instance because that flow was unbuilt.

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
    [CHANGE_AT_FIRST_LOGON=1] [PERSISTENT_ACCOUNTS_TIMEOUT=<seconds>]
```

Each typed password must meet Samba AD's default policy — at least 7
characters from at least 3 of uppercase, lowercase, digits and symbols, and not
containing the account name — and the host checks that before anything boots
(`efedf50`). With `CHANGE_AT_FIRST_LOGON=1` the passwords are **temporary**
instead: they are not policy-checked, each account must change its password at
its first logon (when the new one must meet the policy), and the domain policy is
lifted only while the accounts are created, then restored and verified by the
same in-guest program. **Proven live 2026-09-25** on the throwaway instance: the
run exits 0 only after every account shows a pending password change and the
saved policy is restored and re-read.

The serial console is the only channel that reaches a *simulated* persistent
instance: its only NIC is a QEMU socket netdev to the userspace gateway, with no
NAT and no route to the host LAN, so host-side Ansible cannot reach it at all.
The applied run asks at your terminal for the `local-rescue` password and then
one password per account — each directory role, and each of the overlay's
`additional_standard_users` — each different; none reaches a file, an
argument, an environment or Make variable, the instance marker, or a transcript.
The plan names contract roles (an additional standard user by its
`additional_standard_user_<uidNumber>` label), `uidNumber`/`gidNumber` and the
roster fingerprint, never the real names. Each `uidNumber` is the overlay's
`uid_number` pin for that role, or its positional default; see
`homelab/instance-example/identity/README.md` for the rules, and choose pins
before the first staging. The daily administrator and every additional standard
user are staged as standard directory accounts and never join Domain Admins
(gate 8's `domain-admin-separate`). After a completed or an unfinished staging
run a second one is refused unless you pass `RESTAGE=1`, which does not reset
the password of an account the directory already holds — and staging stops on
the first account the directory already holds, so it cannot add one person to a
directory that has the others. To give one staged account a new password (for
example a lost temporary one), reset it instead:

```sh
make homelab-factory-persistent-account-password PERSISTENT_DC=<name> \
    ROLE=<contract role> [CHANGE_AT_FIRST_LOGON=1] [APPLY=1]
```

It resets only an account that exists (never creates one), judges the new value
against the instance's recorded password policy before anything boots, and
appends the reset, by role, to the instance marker.

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

> **The Ansible path is NOT RUN and unproven** (the serial-console path above
> ran live on 2026-09-25). An adversarial review on 2026-08-17 found the
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
refuses a guest script that pins a name. **A gate-6 run with an overlay
PASSED 2026-09-24** (24 checks), after two more fixes the live run exposed:
the operator sign-in reference's recorded state no longer has to name the
typed principal (`6d8f104`), and gate 8 reads the disk's roster fingerprint
only from a complete line (`f7bbf13`). The reference image itself did not
need recapturing. Evidence paths are in `HANDOFF.md` §7.

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
#   optional FACTORY_RELEASES=<PXE release root, e.g. homelab/var/pxe; its selected set is verified>
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
#   live hooks: RECOVERY_BOOT=1 IDENTITY_BUNDLE=<prepared, unexecuted gate-8 bundle>
make homelab-factory-recover-judge RECOVERY_EVIDENCE=<produced recovery-evidence.jsonl>
```

Exercises controller restart/loss, PXE release rollback, failed-install
recovery, broken-boot repair, directory/DNS loss, update-failure handling,
workstation remint, and controller reconstruction. **Evidence — gate 11
CLOSED FOR PHASE ONE at `partial`, 2026-10-01** (never relabelled pass), run
`homelab/var/factory/recovery/run-20261001T015135Z-gate11live/`: 5 pass, 3 not
run, 0 fail; the judge prints `{"checks": 8, "deferred": ["controller-restart",
"failed-install-recovery", "broken-boot-repair"], "result": "partial"}`. Three
scenarios pass in the loopback lab with no guest boot —
`pxe-release-rollback`, `update-failure-rollback` (per ADR
[0075](../decisions/0075-automatic-gated-arch-workstation-updates.md)), and
`workstation-remint` — and `directory-dns-loss` and `controller-reconstruction`
pass live. `pxe-release-rollback` flips the host-side selection pointer to the
prior verified set and back; nothing is served or booted. Superseded
2026-10-01: the evidence here was `run-20260814T120300Z-3b3169f9f15f/` (3
pass, 5 not run), and an earlier "proven live … (2026-08-12)" had no retained
artifact.

**Phase-one closure (ADR
[0080](../decisions/0080-phase-one-closure-of-recovery-and-egress-checks.md),
owner, 2026-09-30):** this gate closes at `partial` once the three loopback
scenarios and the two implemented live-boot hooks below run and pass;
`controller-restart`, `failed-install-recovery` and `broken-boot-repair` are
deferred past phase one. Reached 2026-10-01.

**Changed 2026-08-17 (`2c3cd56`):** two of the five live-boot hooks are now
*implemented* — `directory-dns-loss` and `controller-reconstruction` — driven
over the gate-8 loopback identity topology, with every judged field backed by a
token-scoped marker the guest itself printed (`controller_frozen` is proven by
the workstation refusing an unprimed domain principal, not by the host's own
SIGSTOP flag). `2aaa7fe` also made this target forward the identity bundle and
controller state those hooks need; without it they would have deferred even
under `RECOVERY_BOOT=1`.

**Both passed live 2026-10-01**, after two fixes: `3fb969e` (the runner's
`--controller-state` default named `homelab/var/controller`, which never
existed, so both hooks always deferred; it is now the canonical image
`build/homelab/vm/bootstrap-dc`, overridden by `FACTORY_CONTROLLER_STATE`) and
`668b524` (the directory/DNS-loss hook froze the Controller before any online
login, so nothing was cached; it now primes SSSD with one online standard-user
login, as gate 8 does). `IDENTITY_BUNDLE` must be a gate-8 bundle that
`homelab-arch-identity-prepare` made and nothing has executed. The remaining
three (`controller-restart`, `failed-install-recovery`, `broken-boot-repair`)
stay stubs because the primitives they need do not exist — there is no way to
power-cycle a live Controller and re-establish its console (the boundary
exposes an outage, not a restart), nothing can break a guest's bootloader and
repair it, and no fault-injection seam can make an install fail on purpose. The
judge's `partial` is honest deferral, not a pass.

### 5.3 Repeatability — gate 12

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
| `REPEAT_REUSE_ITERATION` | unset | Reverify and reuse one accepted prior full cycle; it counts toward `REPEAT_ITERATIONS`. |
| `REPEAT_RECEIPT` | unset | Optional path for the comparison receipt. |
| `FACTORY_DURATION` | `120` | Forwarded to each phase as its **per-phase** budget. |

With `REPEAT_REUSE_ITERATION` and total `REPEAT_ITERATIONS=2`, the driver
reuses one accepted prior full cycle and runs one fresh full cycle. It
re-verifies the prior aggregate, gate-4 proof, identical input pins and evidence
stability, and records explicit reused/new sources. A failed cycle is not
eligible. The retained evidence, new disposable work and new timestamped
aggregate directories must be disjoint, with a new receipt path; their common
evidence parent may hold both runs. Never place retained evidence under work
the driver destroys. Original failures remain unchanged. Use the
[Make contract's recovery procedure](../FACTORY-MAKE-TARGETS.md#the-repeat-driver)
for the current handles and example; do not replay a historical invocation
over its retained paths or overlap an active lab lane. Private before/after
network diagnostics are retained for each new aggregate.

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
  counter renders FAIL. Neither can render PASS. ADR
  [0080](../decisions/0080-phase-one-closure-of-recovery-and-egress-checks.md)
  (owner, 2026-09-30) permits the unproven UniFi counter for the loopback factory: it is
  recorded as waived, never as PASS, and the waiver lapses at gate 14. Check 9
  renders `WAIVED` naming ADR 0080 and a run or repeat `PASS-WITH-WAIVER`
  (`c383e3c`). An unprivileged run cannot read the nft ruleset, so the
  `forwarding` counter is proven by privilege instead: under `--apply` the
  repeat driver sets no_new_privs, and each capture records that the run holds
  no network-admin capability and that the forwarding sysctls did not change
  (`6f86808`). This is the accepted forwarding basis; the receipt names it
  separately. Route, listener, bridge, tap and VLAN counters must still be zero.
- `artifact_scan` (check 15) scans each finished phase's retained top-level
  evidence files — not the checkout, bundle roots or disks — and stays NOT RUN
  when any evidence directory is missing (`b84bc86`; this read "requires a
  scanned tree"). Every retained file must be within the 1 MiB evidence limit:
  stall frames are PNG and the firmware log a tail within it (`6f86808`), and
  serial and publication logs keep a line-aligned head and tail around an
  elision line (`dfd4264`).

**Accepted 2026-10-02 at 16:41:30 UTC: PASS-WITH-WAIVER, equivalent,
zero retries.** Receipt
`homelab/var/factory/repeat/recovered-repeat-3-receipt.json` combines the
reverified accepted cycle `20261002T011915Z-907070-repeat/iteration-2` with
the fresh six-phase cycle `20261002T143757Z-1346697-repeat/iteration-2`.
Each has 15 PASS checks and only the approved UniFi waiver; each gate-4 audit
passes all four prerequisites. All six local network counters are zero. The
media seal, selected release `20261001.001` and Samba repair identities match.
Independent verification reproduced equivalence with no divergent results;
the supervisor exited 0 and all guests stopped. The [state ledger](../WORKSTATION-FACTORY-STATE.md)
records the exact source fingerprints, receipt digest and private diagnostics.
The route-policy extension proposed during recovery was not needed or applied.

Historical run `20261001T153726Z-2517176-repeat` completed two six-phase
lifecycles on 2026-10-01 in 4 hours 10 minutes, with equivalent receipts and
no retries. Two checker defects are fixed: the private-data scan misread a
dotted netmask (`c07f701`), and release verification received the root rather
than the selected set (`41b6bc8`). Both runs also failed gate 4 on a WinPE
IKE flow. Typed VBS suppression (`8eb69a9`) now has fresh gate-4 proof above;
the earlier `68800da` attempt and subsequent OVMF cache correction (`c8e37d0`)
do not establish that intermittent firmware stalls are fixed.

The original October 2 repeat `20261002T011915Z-907070-repeat` remains FAIL
on its first cycle's listener change; its accepted second cycle is retained
at PASS-WITH-WAIVER. Recovery `20261002T114212Z-1294100-repeat` completed
the functional phases but remains FAIL on `route=4`, with raw snapshots
retained. Reusing the accepted cycle does not erase either failure. The
current strict criteria still fail observed local route/listener changes.
The interrupted first recovery also remains retained; no failed receipt was
rewritten into a pass.

Every iteration must now pass the embedded gate-4 PXE authority audit
(`8eb5b6d`). Identical failed audits still fail repeat acceptance; absent or
incomplete packet proof leaves it `NOT-RUN`. Inspect the receipt's
`prerequisites`, sixteen checks, comparison and `needs_live_gate` together.
Phase-one acceptance is `PASS-WITH-WAIVER` only when the sole waiver is ADR
0080 and every other check and prerequisite passes.

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

## Pass/fail gate summary (local evidence through 2026-10-02)

| Gate | What it proves | Real target(s) | State |
|---:|---|---|---|
| 1 | Media intake | `homelab-factory-media`, `homelab-factory-cache-seal` | PASS |
| 2 | Immutable releases | `homelab-factory-pxe VERSION=…` | PASS; `20261001.001` selected and bound to the current seal including Samba repair. July `.001`–`.005` remain historical and require their retained seal — see [1.2](#12-build-the-immutable-release-set). |
| 3 | Controller convergence | `homelab-factory-controller-bundle APPLY=1` (+ live runners) | PASS |
| 4 | PXE authority boundary | `homelab-pxe-authority-audit SWITCH=…` | **PASS**, all four checks: complete Windows VBS (`8eb69a9`) plus Arch capture, receipt `20261002-winpe-vbs-merged.json`. Historical IKE failures stand; every accepted repeat cycle still requires its own audit. |
| 5 | Windows-first install | `homelab-windows-install-{prepare,run}` | **PASS** |
| 6 | Windows join/login | `homelab-windows-identity-{prepare,run,judge}` | **PASS**, 24/24 contracted checks; judge also reports `deferred: [disable-reenable]` and `out_of_scope: [firmware-activation, live-microsoft-update]` |
| 7 | Arch-second install | `homelab-arch-install-{prepare,run}` | **PASS** |
| 8 | Arch join/login | `homelab-arch-identity-{prepare,run,judge}` | **PASS**, 21/21, repeated 2026-10-02 in `arch-identity/run-20261002T163435Z-cd13514cfd7c`; judge prints `PASS: 21 checks, external_access=False`. |
| 9 | Optional storage failure | *(no target of its own, by design: it rides gate 6 and gate 8)* | **PASS** — the Windows half in the 2026-08-13 gate-6 evidence, the Arch half graded inside the passing 2026-08-14 gate-8 run |
| 10 | Dual-boot acceptance | `homelab-dualboot-acceptance-{prepare,run,judge}` | **PASS**, 8/8 in `run-20261002T163609Z-9bc15e4653cd`: Windows default, partitions byte-identical, both OS clean shutdowns. Windows login is not proven by this boot check; authenticated login belongs to the identity gates. |
| 11 | Lifecycle recovery | `homelab-factory-recover`, `-recover-judge` | **CLOSED FOR PHASE ONE at `partial`** (ADR 0080, 2026-10-01; never pass) — 5 pass / 3 not-run, retained at `homelab/var/factory/recovery/run-20261001T015135Z-gate11live/`: the three loopback scenarios plus `directory-dns-loss` and `controller-reconstruction` live; deferred exactly `controller-restart`, `failed-install-recovery` and `broken-boot-repair`, for want of a Controller restart, a bootloader break-and-repair, and install fault injection. |
| 12 | Repeatability | `homelab-factory-repeat` (aggregate driver), `homelab-factory-verify` (per-bundle comparator) | **PASS-WITH-WAIVER**, 2026-10-02: `recovered-repeat-3-receipt.json`, one reverified accepted cycle plus one fresh cycle, equivalent and zero retries. Each 15 PASS + only ADR 0080's UniFi waiver; both gate-4 audits pass. Local network counters all zero. Independent comparison agrees; earlier failures remain retained. |
| 13 | Documentation | this runbook + [human guide](factory-guide.md) | both guides wired into site navigation 2026-10-01; current local usage, maintenance, recovery and retirement documented, command/link/privacy checks passing. Live verdict reconciliation and publication are separate checks; a local site build does not prove deployment. |
| 14 | External integration (UniFi/physical) | *(blocked by design)* | **BLOCKED** — not authorized; only the read-only UniFi review in [`EXTERNAL-INTEGRATION-READINESS.md`](../EXTERNAL-INTEGRATION-READINESS.md) is |

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

- **Rollback a bad release:** rolling back is selecting the prior set, since
  each immutable release set is addressed by `YYYYMMDD.NNN`
  (`homelab-pxe-release-set-rollback VERSION=<prior>`). The loopback
  `pxe-release-rollback` scenario of `homelab-factory-recover` proves only that
  host-side pointer flip; nothing is served or booted. Corrected 2026-09-30:
  this read "proven live".
- **Failed install / broken boot / directory loss / controller loss:** driven by
  `homelab-factory-recover`; directory/DNS loss and controller reconstruction
  pass live (2026-10-01), while controller restart, failed install and broken
  boot defer their live-boot proof past phase one (gate 11 `partial`). Follow
  the observable contract the runner records and escalate before assuming a
  scenario passed.
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

## Routine maintenance of a kept local instance

Record the public commit, selected release-set version, instance/workstation
names, last successful probe and backup identifiers in private operational
notes. Keep account names and credentials out of public reports. First observe:

```sh
make homelab-bootstrap-vm-status
make homelab-factory-persistent-status PERSISTENT_DC=<name>
make homelab-durable-workstation-status WORKSTATION=<name>
make homelab-factory-offline-check
df -h build/homelab/vm homelab/var
```

Stop on an unexplained missing disk, pending fold, identity disagreement or
insufficient space. A fold creates a standalone disk copy, so free space must
cover the plan's estimate as well as retained backups. `make clean` preserves
`build/homelab/vm`; do not replace a named destroy target with a bulk deletion.

After a planned directory change, run the persistent probe and then verify
each affected kept workstation. These boot guests and require the appropriate
credential custody, even though the verify leaves workstation disks unchanged:

```sh
make homelab-factory-persistent-probe PERSISTENT_DC=<name> APPLY=1
make homelab-durable-workstation-verify WORKSTATION=<name> \
  PERSISTENT_DC=<name> ARCH_HOSTNAME=<installed hostname> APPLY=1
```

Require `pass` in each result, matching realm/SID and both operating systems'
authentication checks. A status listing alone does not prove directory health.
An instance provisioned before a configuration change needs its reviewed
`homelab-factory-persistent-converge` plan and an explicit `RECONVERGE=1` run;
do not infer that the new checkout has changed the guest.

For operating-system updates, follow the
[maintenance library](../../site/pages/homelab/maintenance-library.md). Record
Windows update history, Arch update-unit outcome and package lists before
rebuilding a failed image. Read Arch News before a planned refresh; the current
timer does not interpret news or perform article-specific manual interventions.
Do not treat package health checks as a proven boot-repair or rollback drill.

## Native directory backup and recovery

Observe instance status, ensure no live operation owns it, and retain a backup
before a directory change:

```sh
make homelab-factory-persistent-backup PERSISTENT_DC=<name>
make homelab-factory-persistent-backup PERSISTENT_DC=<name> APPLY=1
```

The plan is read-only. The applied target boots the named instance, runs Samba's
native offline backup and retains a set under `homelab/var/backups/` (or
`BACKUP_ROOT`). Verify its result, archive digest and database check. Backups
carry directory secrets: keep them private, preserve their restrictive modes
and retain an encrypted copy outside the build host. The factory does not
automate that off-host copy or back up workstation files/disks.

Use the full [backup/restore contract](../FACTORY-MAKE-TARGETS.md) for restore
inputs, refusal conditions and the live proof record. Prefer a drill into a
separate throwaway instance: restore the set under a **new DC hostname**, run
`RECONVERGE=1`, then the persistent probe. A directory-only drill proves neither
an existing client's trust nor recovery after destroying its original instance.
That stronger proof also needs a kept workstation rendered with SRV-first DC
discovery and a passing keep-verify after restoration. Never provision a new
domain as a substitute for restoring the existing realm/SID.

**Proven in the throwaway lab, 2026-10-01:** native backup, same-instance
destroy/restore under a new DC hostname, reconvergence and probe passed.
After the Samba SRV serializer repair (`bdebb4f`), existing SRV-first client
`rehearsal-auto-ws2` passed keep-verify 40/40
(`run-20261001T235410Z-588718-de077620`), without rejoining either OS. Kept
disk, firmware variables and marker were unchanged; no overlay was folded,
no ledger entry added, and teardown was clean. Earlier failed evidence remains
retained. The Windows check needed its existing bounded cold-boot retry; this
does not prove the firmware fault fixed. Owner keeper and physical recovery
remain unperformed. This directory proof does not back up workstation files.

Back up the separate private inventory and its external secret store too.
Restore a copy to a private temporary location, run the private preflight and
review its redacted output before reconnecting it to Telos. A Git commit in the
public repository backs up none of those values. Do not rotate or reset an
account during an outage merely to make cached login appear healthy; first
restore DNS/time/directory health, then use the one-account reset procedure if
the current password is actually lost.

## Retirement and incident response

A lost or suspect laptop is an incident, not a factory cleanup. Record the last
known use, affected account/device and exact symptom through the private help
channel. An administrator can revoke connected account/share/Wi-Fi access and
rotate exposed credentials through the owning systems, but this repository has
no fleet revocation or remote wipe target. Cached offline login and unencrypted
disk access remain possible. Preserve evidence before repair or reimaging.

For an intentionally retired **local VM**, first verify needed user files are
copied and open from their destination, retain the required private evidence,
and run both status targets. Then retire the explicitly named workstation:

```sh
make homelab-durable-workstation-destroy WORKSTATION=<name> \
  APPLY=1 CONFIRM='DESTROY <name>'
```

Read the result and confirm status no longer lists a usable disk or custody
publication. The target lists the machine accounts it leaves in the directory;
it does not delete them. Record that follow-up privately and have the directory
administrator remove only confirmed retired accounts. Do not retire a directory
until every bound workstation is retired or its recovery plan is verified:

```sh
make homelab-factory-persistent-destroy PERSISTENT_DC=<name> \
  APPLY=1 CONFIRM='DESTROY <name>'
```

Verify the named instance is absent and record which backups are retained under
the owner's retention decision. Destruction is irreversible and its first live
proof is separate from documenting the command. These targets remove local VM
state; they do not sanitize a physical disk, reset firmware, revoke external
shares or erase backup copies. Physical transfer/disposal needs a separate
device-specific sanitization procedure and verification; that path is not yet
implemented here.

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
