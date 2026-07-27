# Local workstation factory state

Document version: `20260727.004`

Status: active implementation

Last evidence/workstream review: 2026-07-27T14:25:02-05:00

Repository baseline reviewed: `fe772ca`

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
| Offline controller media and installation | Commit `386d97c` reproducibly builds controller seed SHA-256 `6af5008493b229c3a91901934d98b2121c9c7bfc3a041117d4fa8d0dcd8d7aee`; the installed `bootstrap-dc` booted from UEFI/systemd-boot on ext4 with locked root and working `local-rescue` sudo. | pass |
| Installed controller safety gate | `homelab-network-attach-preflight` verified forwarding off, SSH root/password login disabled, authority services masked and inactive, and no provisioning/authority ports listening. | pass |
| Manual isolated rehearsal | The operator ran the installed preflight successfully in the disposable controller and powered it off normally. | pass |
| Unattended isolated rehearsal | `homelab/var/simulation/evidence/20260727T184229Z-1971156-b2907fed/result.json` records controller preflight, single DHCP authority, client continuity, and unchanged host state. | pass |
| Repeatable simulator implementation | Public commits through `d5a3534` add the unattended loopback rehearsal and its documentation. `make homelab-sim-auto-run APPLY=1` owns a generated memory-only password and does not require the operator's console password. | pass |
| Windows media authenticity and content | Commit `451f086`; the imported ISO matches the Microsoft-published SHA-256 and local inspection finds `/sources/install.wim`, the UEFI boot chain, and Windows 11 Pro index 6. | pass |
| Simultaneous isolated fabric | Commits through `1afd894` add a loopback-only learning switch and architecture-aware simulated PXE gateway with focused tests. | implemented; lifecycle integration pending |
| Concurrent fabric smoke | `python homelab/vm/factory_runner.py --apply --duration 40 --workstation-iso homelab/var/media/arch/archlinux-x86_64.iso` ran the controller and workstation QEMUs concurrently on loopback-only links. The simulated gateway was the sole DHCP responder; bounded teardown removed both QEMUs, the switch, and listeners; the canonical controller remained unchanged. Host-private, non-publishable evidence: `/tmp/telos-concurrent-switch-evidence.jsonl`, SHA-256 `022b076590cd330a6cf79bf3186301308e8a817f1989c67e8ebcbc79596d96eb`. | smoke pass; not PXE/install acceptance |
| Disposable Controller convergence | Commit `0dcdd55` adds the local Controller factory bundle and contract tests. | implemented; live convergence pending |
| Guarded Arch-second path | Commit `9dcd148` adds Windows-preserving Arch planning and dual-boot disk acceptance tests. | implemented; full guest install pending |
| Windows media intake | Commit `451f086` pins the Microsoft metadata, verifies the imported ISO, and records the Windows 11 Pro image. | pass; WinPE boot pending |
| Offline identity contracts | Commit `771da6b` adds cached identity and optional-storage policy checks. | implemented; live AD join/login pending |
| Factory contract | Commit `fe772ca` records the Make interface, lifecycle gates, and isolated-factory ADR. | accepted; aggregate runtime pending |

The evidence directory is local, ignored state and is not a substitute for a
portable release receipt. Preserve the referenced run until its salient
results are copied into the eventual factory acceptance record.

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
| Controller seed | Commit `386d97c`; `homelab/var/seed/telos-controller-seed.iso`; SHA-256 `6af5008493b229c3a91901934d98b2121c9c7bfc3a041117d4fa8d0dcd8d7aee`. |

All paths under `homelab/var/` are disposable, ignored cache or evidence.
Fresh-clone reconstruction rules are in
[media/FRESH-CLONE.md](media/FRESH-CLONE.md). The original repository-root
Windows ISO is not a durable cache and must not appear in a commit.

## Local lifecycle queue and acceptance gates

Do not skip a gate or turn a planned assertion into a reported pass.

| Order | Gate | Required proof | State |
|---:|---|---|---|
| 1 | Media intake | Verify Windows digest and receipt; inspect the image catalog for Windows 11 Pro; verify Arch signature/digest and `wimboot` pin; prove no media is tracked. | Windows digest and Windows 11 Pro index 6 verified; aggregate sealed-cache receipt pending |
| 2 | Immutable PXE releases | Build and verify versioned Windows, Arch, and controller targets; manifests bind every byte to `YYYYMMDD.NNN`; rejected input and rollback tests pass. | partial: existing Windows stage reaches WinPE; install-image/custom-WinPE path is active work |
| 3 | Controller convergence | From an accepted base controller overlay, configure Samba AD/DNS, Kerberos/time, HTTP/TFTP/iPXE, release selection, logging, backup, and restore without external access. | bundle implemented; live convergence pending |
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

- The actual Windows ISO is available and Windows 11 Pro was found at index 6.
  An OVMF WinPE boot and real Windows install are still required.
- The controller bundle and Samba role exist, but a disposable controller has
  not yet been converged and accepted as a real PXE/Samba AD server.
- Existing PXE staging proves payload construction, not unattended Windows
  installation. An answer file, WinPE startup workflow, disk-serial gate,
  installation-image delivery, secret injection, and post-install acceptance
  remain to be implemented.
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
sed -n '1,240p' homelab/WORKSTATION-FACTORY-STATE.md
make homelab-sim-deps
make homelab-sim-auto-plan
```

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

The next implementation action is to integrate the loopback switch, PXE
gateway, controller factory bundle, and disposable controller overlay into one
real concurrent QEMU rehearsal. Retain packet and service evidence, then boot a
workstation to its first PXE payload. Do not add an aggregate target that
reports success until this real path passes. Follow the target names and split
in [FACTORY-MAKE-TARGETS.md](FACTORY-MAKE-TARGETS.md). Planning or verification
should be the default; destructive disposable-disk actions require `APPLY=1`
and an exact disk identity confirmation.

Literal next commands for the integration owner:

```sh
PYTHONPATH=. python -m unittest \
  homelab.tests.test_windows_media \
  homelab.tests.test_simulated_switch \
  homelab.tests.test_simulated_pxe_gateway \
  homelab.tests.test_controller_factory \
  homelab.tests.test_arch_second \
  homelab.tests.test_dualboot_disk_acceptance
python homelab/vm/controller_factory.py \
  --output homelab/var/factory/controller-factory.iso
```

The first command is read-only. The second writes only an ignored, disposable
factory bundle. After it succeeds, the missing next command is intentionally
the real concurrent runner being implemented; do not substitute the old
single-controller simulation and report a lifecycle pass.

## Active workstream snapshot

Snapshot time: 2026-07-27T14:17:22-05:00. This is a coordination record, not
acceptance evidence. Replace it after integrations or agent reassignments.

| Workstream | Status | Responsibility or latest result |
|---|---|---|
| `arch_fetch_impl` | running | Arch media acquisition and verification |
| `arch_pxe_lifecycle` | running | Arch PXE/install lifecycle |
| `automation_docs_draft` | running | Human and operator automation guides |
| `controller_converge_audit` | running | Audit real controller convergence |
| `controller_factory_impl` | running | Integrate/test controller factory bundle |
| `ethernet_switch_impl` | running | Integrate/test isolated multi-peer switch |
| `evidence_privacy_fix` | running | Evidence redaction and private-data boundary |
| `factory_architecture` | running | Coordinate lifecycle architecture |
| `factory_architecture/factory_contract_review` | complete | Delivered lifecycle-gate corrections |
| `factory_architecture/network_fabric_review` | complete | Specified framed loopback switch and strict MAC/DHCP policy |
| `factory_architecture/windows_flow_review` | complete | Found Windows 11 Pro index 6 and identified WinPE/install/join blockers |
| `factory_ledger` | running | Maintain this restart ledger |
| `factory_make_targets` | running | Maintain reserved Make contract without false-success placeholders |
| `factory_runtime_feasibility` | running | Exercise full local runtime feasibility |
| `identity_lifecycle_tests` | running | Identity, cached login, revocation, and storage-failure contracts |
| `offline_controller_install` | running | Offline controller installation |
| `sim_cli_make` | running | Simulation CLI/Make integration |
| `sim_firewall_tests` | running | Isolated firewall contracts |
| `sim_gateway_impl` | running | Simulated gateway behavior |
| `sim_runtime_feasibility` | running | Runtime feasibility checks |
| `sim_security` | running | Simulation boundary and abuse review |
| `sim_topology_impl` | running | Local topology integration |
| `vm_install_audit` | running | Audit executable VM/install paths |
| `vm_install_audit/safe_exec` | complete | Classified isolated VM create/boot as safe; retained physical/host-update gates |
| `wimboot_fetch` | running | `wimboot` acquisition and verification |
| `windows_iso_inspect` | running | Windows ISO catalog and contents |
| `windows_media_harden` | running | Windows import/provenance hardening |
| `windows_pxe_audit` | running | Windows PXE/WinPE gap audit |
| `ws_samba/role_impl` | complete | Implemented guarded Samba AD role |
| `ws_samba/role_tests` | complete | Added Samba role contract tests |
| `ws_vm/nettests` | complete | Added loopback-only QEMU network safeguards |
| `potato_notebook/build_main` | complete, unrelated | Separate Telos project; no factory dependency |

After every material result, update this ledger's version, the gate table, the
latest evidence pointer, blockers, and the literal next command. Commit code,
tests, documentation, and generated public metadata in coherent, terse
changes; never commit media, credentials, private inventory, or ignored
evidence.
