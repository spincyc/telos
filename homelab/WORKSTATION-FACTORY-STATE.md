# Local workstation factory state

Document version: `20260727.012`

Status: active implementation

Last evidence/workstream review: 2026-07-30T07:30:00-05:00

Repository baseline reviewed: `7297b87`

This is the durable restart ledger for the phase-one workstation factory. A
fresh operator or agent should read this file before changing the controller,
PXE services, workstation images, UniFi, or a physical laptop. Update the
version and the tables below whenever a decision, gate, blocker, or verified
result changes.

## Outcome and hard boundary

The immediate outcome is a reproducible, fully local factory that:

1. starts from a fresh public Telos checkout and verified local media;
2. creates an isolated controller;
3. configures that controller as PXE, HTTP, Samba AD DNS, and identity
   authority;
4. network-boots a disposable workstation through the controller;
5. installs Windows 11 first and Arch second on one UEFI/GPT disk;
6. joins both operating systems to the same domain;
7. verifies user and administrator login, reboot, offline login, updates,
   recovery, reminting, and optional non-fatal user storage; and
8. retains machine-readable evidence for every acceptance gate.

Until the isolated lifecycle passes, the boundary is absolute:

- do not change UniFi;
- do not attach the controller to the physical network;
- do not create a host TAP, bridge, route, VLAN, forwarding rule, or physical
  DHCP/DNS listener;
- do not erase or boot a physical workstation;
- bind simulated links and services to host loopback only; and
- use disposable overlays so the accepted controller disk is never modified
  by a test.

Physical attachment and hardware installation remain separate, explicitly
authorized gates. The simulated gateway owns DHCP during local testing. The
controller must not become a second DHCP authority.

## Agreed decisions

| Area | Current decision |
|---|---|
| Delivery order | Exhaust the complete local lifecycle before requesting another routine human console action or any physical-network change. |
| Installation order | Windows 11 first, Arch second. Arch installation must preserve Windows Boot Manager and apply the final boot policy. |
| Firmware and disk | UEFI/GPT only. Phase-one laptops use unencrypted Windows NTFS and unencrypted Arch storage; BitLocker, LUKS, Secure Boot, and TPM enrollment are deferred. |
| Allocation | Default surplus split is 75% Windows and 25% Arch, after a 160 GiB Windows minimum, 64 GiB Arch minimum, required recovery space, 1 GiB ESP, 16 MiB MSR, and GPT margin. About 256 GiB is the practical minimum. |
| Default boot | Windows is primary, with a five-second menu. Independent UEFI entries must remain usable for recovery. |
| Target hardware | Lenovo ThinkPad X13 Gen 6 Intel; physical acceptance is later. |
| Windows | Windows 11 Pro only. Physical activation uses each laptop's firmware-backed entitlement. The local VM proof need not activate Windows. |
| Identity | Samba AD supplies one identity for Windows and Arch. Public tests use synthetic identities only. Private users, domain values, credentials, and host names remain in `telos-private`. |
| Administration | The private overlay defines a named owner-administrator, a separate privileged identity, and a distinct local `local-rescue` break-glass account. Do not put the private identity values or credentials into public artifacts. |
| Mobile operation | Laptops must support cached/offline login indefinitely away from home, including college use. Arch sets SSSD `offline_credentials_expiration = 0`; Windows uses non-expiring cached domain logons. Document the security and revocation limits. |
| Storage | Local profiles/homes are authoritative for login. Optional per-user UNAS SMB storage may attach when reachable but must never block or fail login. NFS remains disabled pending UID/GID, timestamp, and permissions tests. |
| Updates | Windows updates are automatic. Arch uses an automatic, gated policy with health checks and rollback rather than blind unattended upgrades. |
| Network boot | Initial workstation minting is wired. Restricted provisioning Wi-Fi is a later UniFi/private-network task and cannot be assumed by PXE. |
| Revocation | Temporary user revocation is phase 2 or 3. Phase one must document cached-logon limitations rather than claiming immediate remote revocation. |
| Reproducibility | Every phase needs a Make target, including Arch build-host dependencies, fresh media acquisition/import, controller bootstrap, each PXE target, installation, test, recovery, rollback, and repeat. No generated artifact is required in Git. |
| Documentation | Homelab is Markdown/HTML-first; no PDF is required now. Maintain a terse human guide and an exact operator guide with intermediate observations, questions, measurements, stop conditions, rollback, recovery, and retained evidence. |
| Controller evolution | Start with host-level services for simplicity. Preserve stable DNS/service contracts so services may later move to VMs without rebuilding workstations. |

The accepted architectural records for this phase are ADRs
[0063](decisions/0063-dedicated-break-glass-key-pair.md) through
[0077](decisions/0077-isolate-the-local-workstation-factory.md), subject to
their explicit supersession statements. ADR 0066 keeps UniFi as the eventual
sole DHCP authority; ADR 0067 forbids cloning a live DC disk; ADR 0068 defines
stable names and DC migration; ADR 0071 requires unlimited SSSD offline
credential age; ADR 0072 keeps NFS outside phase one; ADR 0075 requires
official-mirror `pacman -Syu` when deployed; and ADR 0077 defines the no-uplink
local proof. The reserved, non-placeholder Make interface and its
online-acquisition/offline-execution split are in
[FACTORY-MAKE-TARGETS.md](FACTORY-MAKE-TARGETS.md).

## Verified so far

| Gate | Evidence | Result |
|---|---|---|
| Offline controller media and installation | Commit `00a209f` reproducibly builds controller seed SHA-256 `a73a1d5140010fed401c4f9581f87af0989db2eb33106260c9caf8c05b8be212`; the installed `bootstrap-dc` booted from UEFI/systemd-boot on ext4 with locked root and working `local-rescue` sudo. | pass |
| Installed controller safety gate | `homelab-network-attach-preflight` verified forwarding off, SSH root/password login disabled, authority services masked and inactive, and no provisioning/authority ports listening. | pass |
| Manual isolated rehearsal | The operator ran the installed preflight successfully in the disposable controller and powered it off normally. | pass |
| Unattended isolated rehearsal | `homelab/var/simulation/evidence/20260727T184229Z-1971156-b2907fed/result.json` records controller preflight, single DHCP authority, client continuity, and unchanged host state. | pass |
| Repeatable simulator implementation | Public commits through `d5a3534` add the unattended loopback rehearsal and its documentation. `make homelab-sim-auto-run APPLY=1` owns a generated memory-only password and does not require the operator's console password. | pass |
| Windows media authenticity and content | Commit `451f086`; the imported ISO matches the Microsoft-published SHA-256 and local inspection finds `/sources/install.wim`, the UEFI boot chain, and Windows 11 Pro index 6. | pass |
| Simultaneous isolated fabric | Commits through `1afd894` add a loopback-only learning switch and architecture-aware simulated PXE gateway with focused tests. | implemented; lifecycle integration pending |
| Concurrent fabric smoke | `python homelab/vm/factory_runner.py --apply --duration 40 --workstation-iso homelab/var/media/arch/archlinux-x86_64.iso` ran the controller and workstation QEMUs concurrently on loopback-only links. The simulated gateway was the sole DHCP responder; bounded teardown removed both QEMUs, the switch, and listeners; the canonical controller remained unchanged. Host-private, non-publishable evidence: `/tmp/telos-concurrent-switch-evidence.jsonl`, SHA-256 `022b076590cd330a6cf79bf3186301308e8a817f1989c67e8ebcbc79596d96eb`. | smoke pass; not PXE/install acceptance |
| Disposable Controller convergence | Host-private result `homelab/var/factory/evidence/20260727T201057Z-controller.json` (mode 0600) records a fresh no-network Arch/seed installation followed by loopback-only convergence. Gates passed in order: static controller network identity, bounded synthetic NTP measurement, Samba AD/DNS/Kerberos convergence, domain identity, `testparm`, `dbcheck`, LDAP SRV discovery, signed domain time, dedicated TFTP, nginx HTTP, and no DHCP/ProxyDHCP listener. Install, convergence, and cleanup all report `pass`. | pass |
| Guarded Arch-second path | Commit `9dcd148` adds Windows-preserving Arch planning and dual-boot disk acceptance tests. | implemented; full guest install pending |
| Windows media intake | Commit `451f086` pins the Microsoft metadata, verifies the imported ISO, and records the Windows 11 Pro image. | pass; WinPE boot pending |
| Offline identity contracts | Commit `771da6b` adds cached identity and optional-storage policy checks. | implemented; live AD join/login pending |
| Factory contract | Commit `fe772ca` records the Make interface, lifecycle gates, and isolated-factory ADR. | accepted; aggregate runtime pending |

The evidence directory is local, ignored state and is not a substitute for a
portable release receipt. Preserve the referenced run until its salient
results are copied into the eventual factory acceptance record.

The Controller acceptance evidence and its adjacent bounded redacted serial
diagnostic are host-private and non-publishable. Both are mode 0600 under the
ignored `homelab/var/factory/evidence/` tree. They contain synthetic lab
identity and operational detail, are not release inputs, and must not be added
to Git or the public site. The accepted run retained no console password,
Administrator password, authorization nonce, secret ISO, guest disk, firmware
copy, kernel, or initramfs. Cleanup deleted every disposable runtime artifact;
post-run inspection found no QEMU or simulated-gateway process.

The prior rehearsal is only a controller network-safety proof. It does **not**
prove a configured PXE server, Samba AD, either workstation installer, a domain
join, dual boot, user login, or recovery.

The concurrent fabric smoke likewise proves only simultaneous isolated
transport, DHCP authority, bounded cleanup, and preservation of the canonical
controller. It does **not** complete the PXE, installer, domain, login,
dual-boot, update, storage, recovery, or repeatability lifecycle gates. Its
`/tmp` evidence is host-private, ephemeral, and non-publishable; the recorded
digest identifies the reviewed local bytes but does not make them a release
artifact.

## Verified installation media

The browser download supplied by the operator was selected from Microsoft's
official Windows 11 software-download page as the English (United States), x64,
multi-edition consumer ISO:

| Field | Value |
|---|---|
| Original operator-supplied path | `<checkout>/Win11_25H2_English_x64_v2.iso` |
| Canonical ignored cache | `homelab/var/media/windows/windows-11-x64.iso` |
| Actual byte count | `8,471,603,200` |
| Microsoft-published SHA-256 | `768984706b909479417b2368438909440f2967ff05c6a9195ed2667254e465e3` |
| Locally calculated SHA-256 | `768984706b909479417b2368438909440f2967ff05c6a9195ed2667254e465e3` |
| Provenance receipt | `homelab/var/media/windows/windows-11-x64.iso.provenance.json` |
| Edition verification receipt | `homelab/var/media/windows/windows-11-x64.iso.verification.json` |
| Verified image | Windows 11 Pro, index 6 |

The matching digest proves the imported bytes match the operator-supplied
Microsoft-published digest. PXE staging must independently inspect the image
catalog and refuse it unless Windows 11 Pro is present. Never commit, publish,
or copy the ISO into a release tree.

Other present local inputs:

| Input | Local result |
|---|---|
| Arch Linux 2026.07.01 x86-64 ISO | `homelab/var/media/arch/archlinux-2026.07.01-x86_64.iso`; SHA-256 `e86295dc0bdf9b85a5a9256810c553239689d2ae8e80eeec81b4e2e910d8a6c0`; receipt is adjacent. |
| iPXE `wimboot` | `homelab/var/media/wimboot`; SHA-256 `5f067ccdc4d084d5bf77b6c853bd0f8402dfc2b4cd1b103d358993ae97fae8e3`. |
| Controller seed | Commit `00a209f`; `homelab/var/seed/telos-controller-seed.iso`; SHA-256 `a73a1d5140010fed401c4f9581f87af0989db2eb33106260c9caf8c05b8be212`; 267 package archives and 545 receipted payloads. |

All paths under `homelab/var/` are disposable, ignored cache or evidence.
Fresh-clone reconstruction rules are in
[media/FRESH-CLONE.md](media/FRESH-CLONE.md). The original repository-root
Windows ISO is not a durable cache and must not appear in a commit.

`make homelab-factory-cache-seal` now writes the ignored, atomic aggregate
receipt `homelab/var/media/factory-media-seal.json`; the reviewed local receipt
is 2,080 bytes with SHA-256
`f1ea65dd03a790308d9f32fa3c6df02b9aca8172515a26e67bb1820bd39273f6`.
`make homelab-factory-offline-check` verifies that existing receipt and every
bound input without invoking acquisition or silently replacing the receipt.
The seal records tool versions separately from content/provenance equivalence.

## Local lifecycle queue and acceptance gates

Do not skip a gate or turn a planned assertion into a reported pass.

| Order | Gate | Required proof | State |
|---:|---|---|---|
| 1 | Media intake | Verify Windows digest and receipt; inspect the image catalog for Windows 11 Pro; verify Arch signature/digest and `wimboot` pin; prove no media is tracked. | pass: aggregate seal binds Arch, Windows provenance/Pro verification, `wimboot`, and the 976-file Windows install source |
| 2 | Immutable PXE releases | Build and verify versioned Windows, Arch, and controller targets; manifests bind every byte to `YYYYMMDD.NNN`; rejected input and rollback tests pass. | pass: rootless Controller HTTP-PXE image and sealed Arch/Windows inputs selected transactionally as `20260727.001`; aggregate manifest SHA-256 `abbc459e31e32438624f72ceae8180c53e91e1a5edbeacf180dd18350baaccdc` |
| 3 | Controller convergence | From a fresh offline-installed disposable controller, configure Samba AD/DNS, Kerberos/time, HTTP/TFTP/iPXE, and verify the authority boundary without external access. | pass: `20260727T201057Z-controller.json`; release selection, backup, and restore remain lifecycle gates |
| 4 | PXE authority boundary | Simulated gateway remains sole DHCP authority; controller supplies only the approved boot and identity services; packet evidence proves no rogue offer, forwarding, or external connection. | simultaneous fabric and PXE gateway implemented; integrated proof pending |
| 5 | Windows-first install | OVMF workstation PXE-boots WinPE, selects the disk by stable serial, installs Windows 11 Pro to the approved layout, and reboots without ISO attachment. Destructive authorization is scoped to the disposable disk. | pending |
| 6 | Windows join and login | Join the synthetic domain; prove secure channel, DNS SRV, time, named user login, named administrator elevation, `local-rescue`, reboot, cached offline login, update policy, and recovery path. | pending |
| 7 | Arch-second install | PXE-boot Arch, preserve Windows partitions and recovery data, install into the approved allocation, join the same domain, and create independent UEFI entries with Windows default. | guarded disk path implemented; live install pending |
| 8 | Arch join and login | Prove SSSD identity, UID/GID stability, Kerberos time, named user and administrator behavior, reboot, cached offline login, automatic-update gate, rollback, and local rescue. | policy/model tests implemented; live login pending |
| 9 | Optional storage failure | Prove per-user SMB authorization when present and successful login with no delay or hard failure when the NAS is absent. Record UID/GID and timestamp measurements before reconsidering NFS. | pending |
| 10 | Dual-boot acceptance | From cold boot, select and log into both systems; verify Windows-default five-second policy, disk measurements, EFI recovery choices, and no cross-OS partition damage. | pending |
| 11 | Lifecycle recovery | Exercise controller restart/loss, PXE release rollback, failed install, broken boot, directory/DNS loss, update failure, workstation remint, and controller reconstruction from public inputs plus a synthetic private overlay. | pending |
| 12 | Repeatability | Destroy disposable state and repeat the entire factory at least twice from a clean local input set; compare manifests and explain any nondeterministic bytes. | pending |
| 13 | Documentation/publication | Human and operator guides match tested commands, contain no private data, pass links/site checks, and expose exact supported and unsupported states. | pending |
| 14 | External integration | Only after a new explicit authorization: read-only UniFi review, separately approved changes, physical attachment, then ThinkPad X13 Gen 6 Intel pilot. | blocked by design |

## Current blockers and cautions

- Live Windows identity attempts are blocked pending operator authorization.
  `make homelab-windows-identity-prepare APPLY=1` and the corresponding run
  target need privileged local QEMU execution that the current agent sandbox
  refuses. Every prior attempt tore down completely, so the retained bundle
  `run-20260728T114233Z-afecdf7cc9d0` remains the only identity input.
- Image promotion now has a static, non-privileged gate:
  `homelab.lib.image_promotion_gate.gate_candidate_image` merges the profile
  contract, audits a candidate root through the confined read-only package
  gate, and reconciles every required and installed package against the signed
  seed receipt, attributing each failure to contract, root-audit, or
  seed-closure. Booting a candidate image and promotion authority itself
  remain open.
- The actual Windows ISO is available and Windows 11 Pro was found at index 6.
  An OVMF WinPE boot and real Windows install are still required.
- The disposable controller is accepted for Samba AD, DNS, signed time,
  TFTP, and HTTP service behavior. It has not yet served a real workstation
  PXE boot or exercised release rollback, backup, or restoration.
- Existing PXE staging proves payload construction, not unattended Windows
  installation. An answer file, WinPE startup workflow, disk-serial gate,
  installation-image delivery, secret injection, and post-install acceptance
  remain to be implemented.
- The transactional release-set path is implemented and tested, but the first
  local set still needs the Controller netboot source tree. The factory derives
  the Arch source from its sealed ISO by mount-free, digest-addressed
  extraction. No `homelab/var/pxe` release has yet been accepted.
- `homelab/var/seed/telos-controller-seed.iso` is a `TELOS_SEED` data disc for
  offline convergence. It has no kernel, initramfs, or `airootfs.sfs` and must
  never be substituted for the missing custom mkarchiso netboot output.
- A local-only Samba AD test domain must use synthetic public-safe values. Real
  household identities and credentials belong only in the private overlay.
- Offline automatic updates can validate policy, refusal behavior, and staged
  signed packages; they cannot prove Microsoft Update or an official Arch
  mirror is reachable. ADR 0075's deployed Arch policy remains direct,
  gated, signed `pacman -Syu` from an official mirror.
- Firmware-backed Windows activation cannot be reproduced in QEMU and is not a
  local acceptance requirement.
- The phase-one lack of encryption is an explicit development exception. Do
  not represent these images as safe for a mobile or college laptop until the
  encryption decision is revisited.
- No successful local lifecycle permits an implicit UniFi mutation, physical
  attachment, or hardware erase.

## Resume here

This is the literal no-context-loss restart sequence. Run it from the public
Telos checkout before editing code or starting a guest:

```sh
pwd
git status --short
git log -1 --oneline
aiq status
sed -n '1,240p' homelab/WORKSTATION-FACTORY-STATE.md
make homelab-sim-deps
make homelab-sim-auto-plan
```

`aiq status` is first among the reads that decide what to do next: the AIQ
queue is authoritative for runnable work, and this ledger records only durable
factory results. A blocked queue with no ready task means the next move needs
an operator decision, not another command.

Expected: the current directory is the intended public Telos clone and
contains this Makefile; the current commit is at least the baseline recorded
above; any dirty files are understood and preserved; dependency checking is
read-only; and the plan says loopback-only with no host or UniFi changes. Do
not discard an unfamiliar dirty file, regenerate media, or rerun the final
human console gate merely to regain context.

The accepted automatic evidence can be re-read without booting anything:

```sh
python -m json.tool \
  homelab/var/simulation/evidence/20260727T184229Z-1971156-b2907fed/result.json
sha256sum homelab/var/media/windows/windows-11-x64.iso
python -m json.tool \
  homelab/var/media/windows/windows-11-x64.iso.provenance.json
python -m json.tool \
  homelab/var/media/windows/windows-11-x64.iso.verification.json
```

Expected: simulation status `pass` with all four checks true, and the Windows
digest equals the recorded value above. The edition receipt must identify
Windows 11 Pro at index 6. If the ignored evidence directory is absent in a
fresh clone, that means local evidence was not transferred; it does not turn a
planned check into a pass. Recreate only the automatic, disposable rehearsal
when new evidence is actually needed:

```sh
make homelab-sim-auto-run APPLY=1
```

This command generates and wipes its own one-run password. Never supply the
operator's `local-rescue` password in Make, the environment, a command, or an
answer file. `make homelab-sim-run APPLY=1` is the separate final human gate;
it already passed and should be repeated only after a material change to the
manual console path or immediately before separately authorized physical
attachment.

The next implementation action is to build and verify the purpose-built
Controller mkarchiso netboot output, build the first transactional immutable
release set, then keep the accepted configured
Controller alive on the isolated fabric and boot a disposable workstation
through gateway-supplied options 66/67. First prove an actual x86-64 UEFI iPXE
request and Arch installer handoff. Then exercise WinPE, Windows 11 Pro
installation, synthetic-domain join and login; Windows remains first in the
eventual dual-boot sequence. Retain packet/service evidence and prove the
Controller emits no DHCP or ProxyDHCP frames. Do not add an aggregate target
that reports success until the real PXE and installer paths pass. Follow
[FACTORY-MAKE-TARGETS.md](FACTORY-MAKE-TARGETS.md); planning or verification
remains the default, while destructive disposable-disk actions require
`APPLY=1` and exact disk identity confirmation.

Read-only checks before changing the release or integration paths:

```sh
make check
PYTHONPATH=. python -m unittest \
  homelab.tests.test_windows_media \
  homelab.tests.test_simulated_switch \
  homelab.tests.test_simulated_pxe_gateway \
  homelab.tests.test_controller_factory \
  homelab.tests.test_arch_second \
  homelab.tests.test_dualboot_disk_acceptance
```

Both commands are read-only. Build and runtime commands must come from the
currently active journal task and the Make contract; do not infer them from an
old handoff or revive the already-completed agent assignments that produced
the evidence above.

## Work coordination

The local AIQ journal (`aiq` CLI; state under `.git/aiq/`, never committed) is
the authoritative task queue, lease, and decision record. Worktree Marshal
work remains intentionally excluded from that queue. Agent names and statuses
are intentionally absent here because they become stale independently of
acceptance evidence. Re-read the queue (`aiq status`) at scheduling and
recovery boundaries. This ledger records only durable factory results, gates,
blockers, and the safe restart path.

After every material result, update this ledger's version, the gate table, the
latest evidence pointer, blockers, and the literal next command. Commit code,
tests, documentation, and generated public metadata in coherent, terse
changes; never commit media, credentials, private inventory, or ignored
evidence.
