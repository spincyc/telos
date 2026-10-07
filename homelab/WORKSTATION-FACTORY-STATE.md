# Local workstation factory state

Document version: `20261007.001`

Status: active implementation

Last evidence/workstream review: 2026-10-07 19:10 UTC

Repository baseline reviewed: one-command mint and UAT fixes `fa4910f`..`d9c080a` (2026-10-07) on top of `011e678` (guarded publication retirement; bounded process-audit fix `c45c0dc`, repeat recovery `7e4c72c`, Samba repair `bdebb4f`, WinPE VBS `8eb69a9`, publication input binding `93eb6b6`)

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
| Firmware and disk | UEFI/GPT only. Phase-one laptops use unencrypted Windows NTFS and unencrypted Arch storage; BitLocker, LUKS, Secure Boot, and TPM enrollment are deferred. Owner decision 2026-08-10: unencrypted password-based authentication is the accepted phase-one target and is not a blocker to minting a real workstation, including the college laptop — a manual install would not enable BitLocker either. Full-disk encryption is a later iteration to add once the lifecycle works. This supersedes the ADR 0069 caution that phase-one images are "unsuitable for sensitive college or mobile use" for the purpose of proceeding; do not re-raise encryption as a gate on minting. |
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
| Phase-one closure | Owner decisions 2026-09-30. [ADR 0079](decisions/0079-drop-the-controller-pxe-mint.md): no replacement Controller is PXE-minted; it is rebuilt from ISO. [ADR 0080](decisions/0080-phase-one-closure-of-recovery-and-egress-checks.md): gate 11 closes phase one at `partial` once its three loopback and two implemented live-boot scenarios run and pass (three deferred; reached 2026-10-01); gate 12 waives `host_network_changes` in the loopback factory, recorded as waived and never as pass, lapsing at gate 14. |
| Durable workstations | Owner-approved 2026-09-30 (TASK-28), as designed in [DURABLE-WORKSTATION-FLOW.md](DURABLE-WORKSTATION-FLOW.md): installs stay on the disposable Controller and the persistent one serves only joins and logins; under owner custody the owner types a distinct Windows local-administrator and Arch `local-rescue` password at join, which the factory never stores. |
| Credential custody | Owner decision 2026-09-30 (TASK-40): throwaway rehearsal instances (`CUSTODY=agent THROWAWAY=1`) run unattended on harness-generated credentials held in 0600 stores for the instance's life and shredded on destroy. The keeper stays owner custody: the owner's real passwords, typed and never stored. |
| Keeper (TASK-21) | Owner decisions 2026-09-30: a short directory password policy like `rehearsal`'s (minimum length 4, complexity off, minimum age 0); the temporary Domain Admin `tj-` join principal, delegation revisited before physical laptops; backup and restore ([ADR 0081](decisions/0081-samba-native-backup-and-restore-of-persistent-directories.md)) proven live before minting, to the gitignored `homelab/var/backups/` (`BACKUP_ROOT` overridable); a restored DC takes a new name that kept clients find by SRV first (TASK-42). |
| One-command minting | Owner request 2026-10-07: "I should not have to keep entering passwords"; drive everything, including all UAT, with made-up users and passwords until only one final list of users and passwords is needed. `make homelab-factory-mint` (`FACTORY-MAKE-TARGETS.md`, "One-command mint") runs the whole durable sequence and resumes from markers; rehearsals run under agent custody with made-up rosters (`IDENTITY_OVERLAY`, gitignored `homelab/instance/uat/`); the keeper stays owner custody, but the owner types every value once, in one sitting, and the command answers each step's own prompt over a pty, storing nothing. Accounts are staged with permanent passwords. A kept agent-custody store of the owner's real passwords was blocked by the session's safety classifier and is not pursued; do not re-propose it without new owner direction. |
| External integration | Gate 14 is not authorized. Only a read-only UniFi DHCP/PXE review with owner-supplied access is (2026-09-30, aiq TASK-37); the staged plan is [EXTERNAL-INTEGRATION-READINESS.md](EXTERNAL-INTEGRATION-READINESS.md). |

The accepted architectural records for this phase are ADRs
[0063](decisions/0063-dedicated-break-glass-key-pair.md) through
[0081](decisions/0081-samba-native-backup-and-restore-of-persistent-directories.md),
subject to their explicit supersession statements. ADR 0066 keeps UniFi as the
eventual sole DHCP authority; ADR 0067 forbids cloning a live DC disk; ADR 0068
defines stable names and DC migration; ADR 0071 requires unlimited SSSD offline
credential age; ADR 0072 keeps NFS outside phase one; ADR 0075 requires
official-mirror `pacman -Syu` when deployed; ADR 0077 defines the no-uplink
local proof; ADR 0078 permits generated Windows Setup automation on disposable
QEMU disks only; and ADRs 0079-0081 are the 2026-09-30 decisions above. The
reserved, non-placeholder Make interface and its
online-acquisition/offline-execution split are in
[FACTORY-MAKE-TARGETS.md](FACTORY-MAKE-TARGETS.md).

## Verified so far

| Gate | Evidence | Result |
|---|---|---|
| Offline controller media and installation | Commit `00a209f` reproducibly builds controller seed SHA-256 `a73a1d5140010fed401c4f9581f87af0989db2eb33106260c9caf8c05b8be212`; the installed `bootstrap-dc` booted from UEFI/systemd-boot on ext4 with locked root and working `local-rescue` sudo. That is the July image; today's canonical image was installed 2026-09-24 from a later seed (see the inputs table). | pass |
| Installed controller safety gate | `/usr/local/sbin/homelab-network-attach-preflight` (an installed helper, not a Make target) verified forwarding off, SSH root/password login disabled, authority services masked and inactive, and no provisioning/authority ports listening. | pass |
| Manual isolated rehearsal | The operator ran the installed preflight successfully in the disposable controller and powered it off normally. | pass |
| Unattended isolated rehearsal | `homelab/var/simulation/evidence/20260727T184229Z-1971156-b2907fed/result.json` records controller preflight, single DHCP authority, client continuity, and unchanged host state. | pass |
| Repeatable simulator implementation | Public commits through `d5a3534` add the unattended loopback rehearsal and its documentation. `make homelab-sim-auto-run APPLY=1` owns a generated memory-only password and does not require the operator's console password. | pass |
| Windows media authenticity and content | Commit `451f086`; the imported ISO matches the Microsoft-published SHA-256 and local inspection finds `/sources/install.wim`, the UEFI boot chain, and Windows 11 Pro index 6. | pass |
| Simultaneous isolated fabric | Commits through `1afd894` add a loopback-only learning switch and architecture-aware simulated PXE gateway with focused tests. | pass; the fabric carried the live gate-4 through gate-7 runs |
| Concurrent fabric smoke | `python homelab/vm/factory_runner.py --apply --duration 40 --workstation-iso homelab/var/media/arch/archlinux-x86_64.iso` ran the controller and workstation QEMUs concurrently on loopback-only links. The simulated gateway was the sole DHCP responder; bounded teardown removed both QEMUs, the switch, and listeners; the canonical controller remained unchanged. Host-private, non-publishable evidence: `/tmp/telos-concurrent-switch-evidence.jsonl`, SHA-256 `022b076590cd330a6cf79bf3186301308e8a817f1989c67e8ebcbc79596d96eb`. | smoke pass; not PXE/install acceptance |
| Disposable Controller convergence | Host-private result `homelab/var/factory/evidence/20260727T201057Z-controller.json` (mode 0600) records a fresh no-network Arch/seed installation followed by loopback-only convergence. Gates passed in order: static controller network identity, bounded synthetic NTP measurement, Samba AD/DNS/Kerberos convergence, domain identity, `testparm`, `dbcheck`, LDAP SRV discovery, signed domain time, dedicated TFTP, nginx HTTP, and no DHCP/ProxyDHCP listener. Install, convergence, and cleanup all report `pass`. | pass |
| Guarded Arch-second path | Commit `9dcd148` adds Windows-preserving Arch planning and dual-boot disk acceptance tests. | pass; the full guest install landed at gate 7 (`arch-installs/run-20260811T141601Z-6941005247e8`, 2026-08-11) |
| Windows media intake | Commit `451f086` pins the Microsoft metadata, verifies the imported ISO, and records the Windows 11 Pro image. | pass; WinPE boot and the real Windows 11 Pro install landed at gate 5 (`windows-installs/run-20260810T145421Z-5b457e50e20b`, 2026-08-10) |
| Offline identity contracts | Commit `771da6b` adds cached identity and optional-storage policy checks. | pass for Windows: live AD join, online/cached/offline login, and both `optional-storage` checks are inside the passing gate-6 evidence (2026-08-13). The Arch/SSSD half is NOT RUN pending gate 8. Superseded 2026-09-24: the Arch/SSSD half passed inside gate 8 (2026-08-14, 21 of 21, cached offline login and the three `arch-storage-*` checks included). |
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
| Arch Linux 2026.08.01 x86-64 ISO | `homelab/var/media/arch/archlinux-2026.08.01-x86_64.iso` (the `archlinux-x86_64.iso` symlink's target); SHA-256 `4e82dced1c4fd3e498b22a853f8db2a4d262d32b97e7e07d97390d9e425ffe5e`; receipt is adjacent; sealed 2026-09-30. Superseded 2026-09-30: this row named the 2026.07.01 ISO (SHA-256 `e86295dc0bdf9b85a5a9256810c553239689d2ae8e80eeec81b4e2e910d8a6c0`), which stays in the cache because the July seal and release sets bind it. |
| iPXE `wimboot` | `homelab/var/media/wimboot`; SHA-256 `5f067ccdc4d084d5bf77b6c853bd0f8402dfc2b4cd1b103d358993ae97fae8e3`. |
| Controller seed | `homelab/var/seed/telos-controller-seed.iso`, rebuilt 2026-08-14; SHA-256 `66afce1801e1577d1662465e748a4d0eec1019d75c6ead4c0d2be048218a452a`, the seed the 2026-09-24 canonical install used (its install receipt). Superseded 2026-09-30: this row named the July seed, commit `00a209f`, SHA-256 `a73a1d51…b8be212`, 267 package archives and 545 receipted payloads. |

All paths under `homelab/var/` are ignored local state. Preserve directory
backup sets under `homelab/var/backups/` and referenced acceptance evidence;
they are not disposable caches.
Fresh-clone reconstruction rules are in
[media/FRESH-CLONE.md](media/FRESH-CLONE.md). The original repository-root
Windows ISO is not a durable cache and must not appear in a commit.

`make homelab-factory-cache-seal` now writes the ignored, atomic aggregate
receipt `homelab/var/media/factory-media-seal.json`. The 2026-09-30 reseal
against Arch 2026.08.01 was 2,080 bytes, SHA-256 `bb84397b…c429`, with
`make homelab-factory-offline-check` PASS. It has since been resealed to include
the required verified Samba DNS repair library and provenance; the current
seal and selected release `20261001.001` passed input verification before
the fresh repeat. The offline-check target verifies the existing
receipt and every bound input without invoking acquisition or silently
replacing the receipt. Since `110dfb5` a tool-version-only difference is
reported on stderr rather than failing; content and provenance still fail
closed. The July receipt (SHA-256
`f1ea65dd03a790308d9f32fa3c6df02b9aca8172515a26e67bb1820bd39273f6`) is kept,
mode 0600, at `homelab/var/media/factory-media-seal.20260727-releases.json`,
because release sets `20260727.001`–`.005` bind it:
`make homelab-pxe-release-set-verify` refuses them against the new seal unless
`FACTORY_MEDIA_SEAL=` names that copy (checked 2026-09-30). The new selected
set uses the August ISO; gate-12 comparisons must use runs made under one seal.

## Local lifecycle queue and acceptance gates

Do not skip a gate or turn a planned assertion into a reported pass.

| Order | Gate | Required proof | State |
|---:|---|---|---|
| 1 | Media intake | Verify Windows digest and receipt; inspect the image catalog for Windows 11 Pro; verify Arch signature/digest and `wimboot` pin; prove no media is tracked. | pass: aggregate seal binds Arch, Windows provenance/Pro verification, `wimboot`, and the 976-file Windows install source |
| 2 | Immutable PXE releases | Build and verify versioned Windows, Arch, and controller targets; manifests bind every byte to `YYYYMMDD.NNN`; rejected input and rollback tests pass. | pass: release `20261001.001` is now selected and verifies against the current seal, including the Samba repair bytes; the fresh repeat uses it. Historical sets `20260727.001`–`.005` remain bound to the kept July seal. The separately completed Windows VBS run used `20260727.005` because it was prepared before resealing — see [Verified installation media](#verified-installation-media). |
| 3 | Controller convergence | From a fresh offline-installed disposable controller, configure Samba AD/DNS, Kerberos/time, HTTP/TFTP/iPXE, and verify the authority boundary without external access. | pass: `20260727T201057Z-controller.json`; release selection, backup, and restore remain lifecycle gates |
| 4 | PXE authority boundary | Simulated gateway remains sole DHCP authority; controller supplies only approved boot and identity services; packet evidence proves no rogue offer, forwarding, or external connection. | **PASS, four checks, 2026-10-02 (TASK-43 DONE).** Complete Windows VBS run `windows-installs/run-20261001T235652Z-a782e2f67fac` (`8eb69a9`) plus Arch `arch-installs/run-20261001T193550Z-e5108779aad1`: receipt `homelab/var/factory/authority-audits/20261002-winpe-vbs-merged.json`, 34 DHCP server frames all from the gateway, 268 approved flows. The earlier full repeat FAILED on WinPE UDP 500; that verdict stands. Initial `68800da` depended on unavailable `sc.exe`; a later WMIC parser falsely rejected a successful change; typed VBS calls in `8eb69a9` are the proven fix. Since `8eb5b6d`, every repeat iteration must pass its own audit; this separate proof cannot close gate 12. |
| 5 | Windows-first install | OVMF workstation PXE-boots WinPE, which installs only when it sees exactly one online disk, disk 0, of the authorized capacity, while the host binds and audits that disk's serial ([ADR 0078](decisions/0078-private-disposable-windows-automation.md); `render_startup` in `homelab/vm/windows_install_contract.py`); installs Windows 11 Pro to the approved layout, and reboots without ISO attachment. Destructive authorization is scoped to the disposable disk. Corrected 2026-09-30: this read "selects the disk by stable serial"; stock WinPE has no serial query. The interactive path a physical machine uses is `homelab/pxe/windows/FLOW.md`. | pass 2026-08-10: bundle `run-20260810T145421Z-5b457e50e20b` records `observed`/`native-windows-clean-shutdown`, exactly one PXE firmware boot, release `20260727.005`, private publication destroyed; serial log shows WinPE handoff, two native Windows Boot Manager boots, `TELOS WINDOWS NATIVE READY`, Edition Professional. Re-observed twice 2026-09-30 as the durable flow's step 1 (`run-20260930T164848Z-d51d2c1e14cd`, `run-20260930T192147Z-d12679ce1b5e`: one PXE boot each, 68-69 min). |
| 6 | Windows join and login | Join the synthetic domain; prove secure channel, DNS SRV, time, named user login, named administrator elevation, `local-rescue`, reboot, cached offline login, update policy, and recovery path. | PASS 2026-08-12, 24 of 24 CONTRACTED checks (attempt `20260812T043214Z-28ff545de0ce`, acceptance-progress.json passed 24/24). "24/24" is the whole contracted set, not every conceivable check: the judge additionally reports `deferred: ["disable-reenable"]` and `out_of_scope: ["firmware-activation", "live-microsoft-update"]`, so account disable/re-enable is still unproven and the two out-of-scope items are unreproducible locally by decision. The 24 are: join, standard/daily-admin/domain-admin-separate logins, reboot-rejoin, cached policy, controller-offline, cached standard+admin offline login, uncached-denied, local-rescue, controller/secure-channel restored, update policy, gateway/update-source/ad-dns/combined-dependency outages, services-restored, diagnostics-sanitized, and the aggregate. That run also executed the recovery step, which by design DESTROYS the one-use credential-bearing recovery publication -- so the retained gate-5 bundle's publication.iso is now consumed. **FULL PUBLISH PASS 2026-08-13**: attempt `20260813T191519Z-28a9f6ee07f5` on bundle `run-20260813T171405Z-6729c809fcab` ran 24/24 AND published `acceptance-evidence.jsonl`; `homelab-windows-identity-judge` grades it verbatim `{"checks": 24, "deferred": ["disable-reenable"], "external_access": false, "out_of_scope": ["firmware-activation", "live-microsoft-update"], "result": "pass", "schema_version": 1}` (re-run 2026-08-14 against the retained evidence). This is the first-ever successful gate-6 publish. THREE FILENAMES, one stream — do not confuse them: gate 6 WRITES `<attempt>/acceptance-evidence.jsonl` (24 records); the Make/CLI flag that names it for the next gate is `--windows-evidence` (`WINDOWS_IDENTITY_EVIDENCE=`); and `homelab-arch-identity-prepare` copies only the 7 `windows-*` records the gate-8 contract requires into the gate-8 bundle as `windows-evidence.jsonl` (verified 7 records: `windows-joined`, `windows-standard-online`, `windows-daily-admin`, `windows-cached-login`, `windows-uncached-denied`, `windows-local-rescue`, `windows-secure-channel-restored`). Getting the publish through required unwinding several over-strict/latent aggregate `_expect` assertions (publish stops at the first, so each confirm revealed the next): (1) `controller-ready.synthetic_directory` unprovable pre-join → relocated to windows-standard-online (`f8b0c24`); (2) reference disk-hash pinned to the original install → references made version-portable (`4e28609`); (3) `windows-secure-channel-restored.secure_channel` and `windows-services-restored.secure_channel` both came back false — after a controller SIGSTOP/SIGCONT outage Netlogon drops the machine secure channel and the non-elevated operator probe cannot actively reset it (a read-only re-verify never re-establishes; a UAC-bypass elevation was rejected as inappropriate). Owner chose reboot-and-reverify: the fault-restore step now REBOOTS the guest (clean Run-dialog `powershell … Restart-Computer -Force`; the switch socket persists across a guest reboot so boot is detected by the fresh DHCP DISCOVER, not a new port) and re-establishes the operator session with a lightweight re-login (`establish_session_only` — skips the DC-side controller-auth arm, which cannot drive the just-frozen DC console, and the guest post-submit diagnostic). Two reboots are wired, one before each of the two secure-channel checks (the fault sequence takes the controller offline a second time). (4) `windows-update-policy.automatic_updates_configured` was never configured → the install FirstLogonCommands now set `HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU NoAutoUpdate=0`. The debugging used a publication-stash technique to iterate the ~30-40min identity acceptance on a single 68-min install instead of re-installing per attempt. The entire credential-proof mechanism was rebuilt earlier this session (token LogonUser, Kerberos package via LSA, raw-token-groups membership, live-tolerant secret scanner, root-cause instrumentation). **Roster change 2026-08-17 (`ee8b5e6`), verdict UNTOUCHED:** the Windows identity lane no longer hardcodes `student`/`operator`/`directory-admin` in about fifteen places and instead derives its principals from the same private overlay roster the Arch lane already used. WITH NO OVERLAY EVERY DERIVED VALUE IS BYTE-IDENTICAL to the literals it replaced, so the gate-6 and gate-8 verdicts above stand unchanged. What changed is that **using an overlay is no longer fatal**: before, an overlay naming real accounts killed the gate at principal staging with a message naming neither the roster source nor the overlay file, because `controller_principals` refuses any roster that is not exactly its own. The synthetic names are therefore no longer fixed -- do not read them as a contract. Refusals now report the expected roster, the roster they were handed, and where it came from; the roster loader also fails CLOSED on any `OSError` other than `FileNotFoundError` rather than silently substituting the synthetic acceptance roster. |
| 7 | Arch-second install | PXE-boot Arch, preserve Windows partitions and recovery data, install into the approved allocation, join the same domain, and create independent UEFI entries with Windows default. | **PASS 2026-08-11**: bundle `arch-installs/run-20260811T141601Z-6941005247e8` records `observed`/`arch-installed-windows-preserved`, `windows_preserved` true, exactly one PXE firmware boot, release `20260727.005`, join media consumed and destroyed, join principal destroyed. The serial proves the full chain: archiso login, virtio hot-attach, GPT verify (lsblk parse fix `941ba41`), partition and mkfs into the approved allocation, pacstrap of all 209 packages from the controller-served signed workstation repo (`2e2bdde`), `TELOS ARCH JOIN VERIFIED` (live `net ads join` + `testjoin` against the disposable converged DC, `ffca280` + heredoc program transfer `80e53e1`), SSSD/probe/local-rescue provisioning, systemd-boot with `default auto-windows`, and ESP-state proofs (`91e564b`). NVRAM-entry proof deliberately belongs to gate 10's cold boot. |
| 8 | Arch join and login | Prove SSSD identity, UID/GID stability, Kerberos time, named user and administrator behavior, reboot, cached offline login, automatic-update gate, rollback, and local rescue. | **PASS — 21 of 21 checks, proven live 2026-08-14.** Run 16, bundle `arch-identity/run-20260814T172142Z-495164bc7159`, evidence `evidence/identity-lifecycle.jsonl`; `make homelab-arch-identity-judge ARCH_IDENTITY_EVIDENCE=<that file>` grades `PASS: 21 checks, external_access=False`. Sixteen live runs got here from "no systemd-boot menu". Every fault was real; the full narrative — eight distinct root causes, four refuted hypotheses recorded so they are not re-derived, and two recording errors corrected — lives in `HANDOFF.md` §3 rather than being duplicated here. Headline causes in the order they were fixed: pristine firmware variables carried no bootloader entry; a systemd-boot digit key selects without booting; every run provisions a brand-new domain so the gate-7 machine account cannot exist, which the Windows lane avoids by joining in-run; `sssd.service` reaching active is not its AD backend being online; `sssctl` needs the `ifp` responder; Samba's schema never replicates POSIX ids to the Global Catalog and `gpo_child` cannot read the root-only keytab; SSSD locates a DC only by SRV while `net ads` falls back to a broadcast; the install-time keytab's stale keys shadowed the fresh ones at the same KVNO; two credential writes were gated on a marker printed before their reader existed; the storage alias had no `cifs/` SPN; and the Controller's own name service had no directory source, so `smbd` could not resolve a domain user for its `[homes]` share. Open but NOT a gate-8 blocker: the firmware boot stall (3 of 16 runs, absorbed by a bounded QMP power-cycle retry; retained evidence narrowed it to a firmware spin, because QMP reported the vCPU `running` with a timeout, eliminating stalled device emulation and host I/O). Closed 2026-08-14 by `2f86a21` (recorded 2026-09-30; until then this row listed it as open): the fleet `sssd.conf.j2` carries the same `offline_timeout` bounds the installer sets. |
| 9 | Optional storage failure | Prove per-user SMB authorization when present and successful login with no delay or hard failure when the NAS is absent. Record UID/GID and timestamp measurements before reconsidering NFS. | **PASS 2026-08-14.** This gate has no target of its own by design and is graded inside the gate-6 and gate-8 identity acceptances: `homelab/workstations/acceptance.json` carries six `optional-storage` checks, and the three `windows-smb-*` ones are exercised by `windows_identity_acceptance.py` while the three `arch-smb-*` ones are the gate-8 runner's `arch-storage-{attached,denied,absent-login}`. The Windows half is live-proven in the 2026-08-13 gate-6 evidence (`optional-storage-offline` and `optional-storage-access-denied` among its 24 passed checks); the Arch half is live-proven in the passing 2026-08-14 gate-8 run (`arch-identity/run-20260814T172142Z-495164bc7159`). Controller side was already complete and test-locked 2026-08-12 (`11c2c5f`): the per-user `[homes]` share over `/srv/unas/<user>`, rfc2307 identities so an owner reads their own directory and a foreigner is denied, and the storage name published to the controller's own address, which the gate-8 runner repoints for the absent-login proof. The attached check now also records the UID, GID and file mtime this gate's proof asks for, and refuses a pass whose identifiers disagree with what the directory staged -- which is what makes them a stability proof. Two faults had to be fixed to get the Arch half green, both in `HANDOFF.md` §3: the storage alias had no `servicePrincipalName` for the `cifs/` ticket `mount.cifs` asks the KDC for, and the Controller's own name service had no directory source at all. |
| 10 | Dual-boot acceptance | From cold boot, select and log into both systems; verify Windows-default five-second policy, disk measurements, EFI recovery choices, and no cross-OS partition damage. | **PASS 2026-08-11**: bundle `dualboot-acceptance/run-20260811T170510Z-a619bcb1f028` records `observed`/`dualboot-accepted`, all eight checks green. From cold boot the firmware started `Linux Boot Manager` (systemd-boot), the five-second menu rendered Windows-default (measured ~5s), Windows BOOTED — observation `boot-observed`, six retained frames — but this run drove no Windows login and no Windows shutdown: the bundle's `result.json` records `windows_clean_shutdown: false` and `windows_login_proven: false`, and the `windows-default-boot` event records `clean_shutdown: false`, `login_proven: false`, `input_sent: false`. Boot 2 rendered the menu again (Linux-first NVRAM held — Windows adopted the blob-bearing entry and did not self-promote, `c15dff7`/`83be6bf`), the drive paused the countdown and arrow-navigated to Arch then pressed Enter (`6d8823b`), Arch handed off on ttyS0 to its getty login surface, the GPT was byte-unchanged, and both EFI boot managers plus the recovery entry were present. The judge grades it verbatim `{"checks": 8, "deferred": ["windows-login-driven", "arch-authenticated-login"], "external_access": false, "result": "pass", "schema_version": 1, "windows_login_proven": false}` (re-run 2026-08-14 via `python3 homelab/bin/homelab-dualboot-acceptance judge <bundle>/evidence/dualboot-events.jsonl`; the Make entry point is `homelab-dualboot-acceptance-judge DUALBOOT_EVIDENCE=…`). BOTH deferrals must be read with the pass: Windows login is deferred to gate 6's identity stream (where it is proven), and Arch AUTHENTICATED login is deferred to gate 8 — gate 10 proved only that Arch reached its ttyS0 getty prompt. **Established 2026-08-17: neither deferral can be closed on the retained disks, and the Controller image is not what blocks them.** Arch has no credential of any kind on that disk -- the install-time join bound it to a domain that no longer exists with nothing cached, `local-rescue` was created by `useradd` with no `-p` so its password is disabled and nothing ever sets it, and `loader.conf` sets `editor no` so the cmdline cannot reach root before the getty; the routine that would set the rescue password itself runs from the root shell the login is what enables. Windows has exactly one login that needs no directory, the local one, and its credential is destroyed: gate 5 generates it randomly and retains it only in the unattend, gate 6 recovers it only from the one-use `publication.iso`, and no `publication.iso` remains anywhere in the tree. Both remaining routes -- grading a break-glass local login as directory authentication, or editing `/etc/shadow` host-side in the disk under test -- are refused. A re-run today would reproduce the same eight-check pass with the same two deferrals in ~5 min and ~500 MB, and the gate-7 input is provably read-only across a run (fresh overlay, and `_bundle` re-hashes both input disks against the authorization at every start; all three digests were re-verified byte-identical on 2026-08-17, six days and one full run later). Every gate-7 disk since the three 2026-08-14 bundles bakes in `telos-arch-join-once` and `telos-arch-domain-online`, ordered before `systemd-user-sessions`, which with no join media and no directory burn ~240 s before the getty. Since `f8f0443` (2026-10-01) `observe_boot`'s login wait is derived from those two bounds (420 s), so any gate-7 bundle serves. Superseded 2026-10-01, kept so it is not re-derived: the fixed 120 s wait failed `arch-console-login-surface` on such a disk (the first gate-12 run), and this row said to re-run only on an 08-11 bundle. |
| 11 | Lifecycle recovery | Exercise controller restart/loss, PXE release rollback, failed install, broken boot, directory/DNS loss, update failure, workstation remint, and controller reconstruction from public inputs plus a synthetic private overlay. | **CLOSED FOR PHASE ONE 2026-10-01 at `partial`, per [ADR 0080](decisions/0080-phase-one-closure-of-recovery-and-egress-checks.md) -- never relabelled `pass`.** Run `homelab/var/factory/recovery/run-20261001T015135Z-gate11live/{recovery-evidence.jsonl,result.json}` (`RECOVERY_BOOT=1`, identity bundle prepared from gate-12 iteration 1's outputs): 8 scenarios, `pass: 5`, `not_run: 3`, `fail: 0`; the judge grades it `{"checks": 8, "deferred": ["controller-restart", "failed-install-recovery", "broken-boot-repair"], "result": "partial"}`, exactly the three ADR 0080 deferrals. `pxe-release-rollback`, `update-failure-rollback` (ADR 0075) and `workstation-remint` pass in the loopback lab with no guest; `directory-dns-loss` (Controller frozen by SIGSTOP, cached operation continued under `offline_credentials_expiration = 0`, directory restored) and `controller-reconstruction` (converged from public inputs plus a synthetic private overlay) pass LIVE. Runner + judge `f39f3a1` (`make homelab-factory-recover`, `homelab-factory-recover-judge RECOVERY_EVIDENCE=…`); the two live hooks `2c3cd56`, forwarded their inputs by `2aaa7fe`. Every judged live field is backed by a token-scoped marker the guest itself printed: `controller_frozen` by the workstation refusing an unprimed domain principal (the host's SIGSTOP flag must agree but is not the proof), `converged_from_public_inputs` by the reconstructed Controller's own convergence and readiness markers and then `net ads testjoin` from the joined workstation. Two defects were fixed on the way, and the four earlier `-gate11live` runs that day deferred one or both hooks on them: `3fb969e`, the runner's `--controller-state` default named `homelab/var/controller`, which never existed, so both hooks ALWAYS deferred (its error now prints the message); `668b524`, the directory/DNS-loss hook froze the Controller before any online login, so nothing was cached and cached operation could never be observed -- it now primes SSSD with one online standard-user login first, as gate 8 does. The live hooks need a PREPARED, unexecuted gate-8 bundle (`homelab-arch-identity-prepare`), not an executed one. The three deferred scenarios stay stubs past phase one because their primitives do not exist: nothing power-cycles a live Controller and re-establishes its console (the boundary exposes an outage, not a restart), breaks and repairs a guest's bootloader, or makes an install fail on purpose. Read `pxe-release-rollback` narrowly: it flips the host-side selection pointer to the prior verified set and back (`homelab/vm/lifecycle_recovery.py`); nothing is served or booted. Superseded 2026-10-01, kept so it is not re-derived: this row read PARTIAL with both hooks implemented but NOT RUN, its only retained evidence `run-20260814T120300Z-3b3169f9f15f` (`pass: 3`, `not_run: 5`); the judge's verdict is `partial` by construction (`"pass" if not deferred else "partial"`), and any earlier claim of a date-stamped live pass had no retained artifact behind it. |
| 12 | Repeatability | Destroy disposable state, run the entire factory at least twice from the same sealed inputs, and compare receipts. | **CLOSED FOR PHASE ONE, PASS-WITH-WAIVER, 2026-10-02; TASK-6 DONE.** Strict recovery `repeat/20261002T143757Z-1346697-repeat` from `011e678` finished 16:41:30 UTC, supervisor exit 0, equivalent receipts and zero retries. It reused unchanged accepted `20261002T011915Z-907070-repeat/iteration-2` plus one fresh cycle at identical pins. Both cycles have 15 PASS and only the ADR 0080 UniFi waiver; each gate-4 audit is 4/4 PASS and the fresh six local network counters are zero. Independent comparison agrees with zero divergences; no QEMU or repeat driver remains. Final receipt `homelab/var/factory/repeat/recovered-repeat-3-receipt.json`; exact SHA-256, source fingerprints and diagnostics: [the repeat driver](FACTORY-MAKE-TARGETS.md#the-repeat-driver). No route-policy exception was needed or approved. Original listener failure `011915`, stopped recovery `053117` without a receipt, route failure `114212`, and earlier checker/IKE failure `20261001T153726Z-2517176-repeat` retain their verdicts and evidence. The current contract still fails observed local route/listener changes, and firmware stalls are not claimed fixed. |
| 13 | Documentation/publication | Human and operator guides match supported commands, distinguish pending proof, pass privacy/link checks, and are usable from the site. | **Local documentation pass complete, 2026-10-02 (TASK-7).** Accepted gate-12 evidence and all sixteen topics are reconciled in the guides, map and ledger, with physical/NAS limits explicit. Final command drift passes (113 defined / 83 documented); source privacy/links, build and `make verify-site` pass (26 pages / 148 publications / 181 files). Chromium reviewed both guides and recovery at 390px/1440px: no page overflow, all local fragments resolve, every link is keyboard reachable with visible focus, and code/tables retain local scrolling. Earlier isolated source-copy build/verify required no private overlay or lab media; no fresh-household live install is claimed. Browser proof is archived with the strict-repeat checkpoint. Publication still needs separate push authority and exact-commit deployment evidence. |
| 14 | External integration | Only after a new explicit authorization: read-only UniFi review, separately approved changes, physical attachment, then ThinkPad X13 Gen 6 Intel pilot. | blocked by design; **not authorized**. The staged plan is [EXTERNAL-INTEGRATION-READINESS.md](EXTERNAL-INTEGRATION-READINESS.md) (`b719e7a`). The only authorized step (owner, 2026-09-30) is its read-only UniFi DHCP/PXE review with owner-supplied access, aiq TASK-37, blocked on that access. ADR 0080's gate-12 egress waiver lapses here. |

Owner decision 2026-09-30 ([ADR 0079](decisions/0079-drop-the-controller-pxe-mint.md)):
the `LOCAL-FACTORY-LIFECYCLE.md` Gate 3 replacement-Controller PXE mint is
dropped -- it was never implemented and has no row here; the Controller is
rebuilt from ISO by `make homelab-bootstrap-vm-install`, and local promotion
needs lifecycle Gates 1, 2 and 4-7.

The durable workstation flow (TASK-28,
[DURABLE-WORKSTATION-FLOW.md](DURABLE-WORKSTATION-FLOW.md)) is not a numbered
gate. **PASS 2026-09-30** end to end, unattended under agent custody on the
throwaway instance `rehearsal-auto`: create, converge, accounts, probe, adopt,
durable Arch install and join, durable Windows join, and keep-verify across a
Controller cold relaunch. The keeper instance is aiq TASK-21.

**Directory disaster recovery (TASK-41/TASK-42) PASSED 2026-10-01.** Native
backup, same-instance restore under new DC `dr-2610012255`, reconvergence and
probe passed. After repair `bdebb4f`, restored-DC convergence passed all four
strict LDAP/Kerberos UDP/TCP probes; the existing SRV-first
`rehearsal-auto-ws2` passed keep-verify 40/40 without a rejoin:
`homelab/var/factory/durable-workstation-verifies/rehearsal-auto-ws2/run-20261001T235410Z-588718-de077620/evidence/result.json`.
Kept disk, firmware variables and marker were unchanged; no fold or ledger
entry was made; teardown was clean. The first Windows boot stalled with
72,192 read bytes, 33 operations and zero writes on a pristine overlay; the
existing bounded cold-boot retry passed and retained
`fabric/windows-boot-attempt-1.json`. Firmware stalls are not claimed fixed.
Earlier failed evidence, restored instance and verified native backup remain.

**2026-10-07: the keeper now needs one sitting.** `make homelab-factory-mint
PERSISTENT_DC=keeper WORKSTATION=keeper-ws1 ARCH_HOSTNAME=keeper-ws1 APPLY=1`
at the owner's terminal asks every value once and runs the rest unattended
(about 30-35 minutes); its rehearsal UAT passed on `uat2` (FACTORY-MAKE-TARGETS.md,
"One-command mint"). The instance `keeper`, seeded 2026-10-02 and never
converged, is reused. The reserved Windows bundle named below was deleted on
2026-10-06; the mint installs a fresh one. History kept: the keeper (TASK-21)
was blocked solely on owner-terminal passwords and absent;
status and convergence planning were rechecked about 16:49 UTC. Its DR
prerequisite is satisfied. Owner-terminal credentials are still
required and the owner availability question remains unanswered. Windows VBS
run `run-20261001T235652Z-a782e2f67fac` (`8eb69a9`) finished at 2026-10-02
01:17 UTC after about 70 minutes: runner exit 0,
`observed` / `native-windows-clean-shutdown`, one firmware PXE boot, unchanged
canonical disk and firmware, and zero external connections. It used release
`20260727.005`, prepared before resealing; its publication remains unconsumed
for keeper adoption. Original repeat `20261002T011915Z-907070-repeat`
finished about 05:26 UTC with final receipt FAIL, `equivalent: false`, zero
retries. Iteration 1's listener-change failure remains unattributable because
raw snapshots were discarded. Iteration 2 passed with only the ADR 0080 UniFi
waiver: 15 pass, one waived, zero fail/not-run and six local network counters
zero. Both gate-4 audits passed. Iteration 2 completed Windows identity 24
checks, Arch identity 21, dual-boot eight observed checks (Windows login not
driven there), and lifecycle recovery three pass / five deferred.
Input binding `93eb6b6` closes the reproduced A→B→A false pass by pinning the actual
publication manifest and seal and validating copied leaf bytes; the repeatable
check is `tools/factory-repeat-input-binding`. The pre-run audit passed 4,115
tests with five skips, no failures/errors, zero lab-state touches and two
advisory argv mentions; `tmt check` passed. Before recovery, the root agent
verified no VMs remained and 74 GiB was free, then saved the originals' SHA-256
inventory at `/tmp/telos-recovery-root/original-repeat-before-recovery.sha256`.
Recovery support is committed and available in `7e4c72c`: it re-verifies one
accepted full cycle, pins and evidence stability before one fresh cycle,
records explicit reused/new sources, preserves failures, retains private
network snapshots and guards destructive root overlap. New work and receipt
paths are required. Validation passed 4,140 tests with five skips, no
failures/errors, lab touches or VM launches; independent review passed 25
tests and `tmt check` passed. Recovery `20261002T053117Z-1175062-repeat`
started at 05:31:17 UTC but stopped about 06:39 UTC with exit 2 and no final
comparison receipt. Supervisor `1174594` and driver `1175062` are historical
identifiers, not active processes. Windows `run-20261002T053119Z-97daa1c63993`
failed `pxe-loop` after about 67 minutes: OVMF reported Windows Boot Manager
`Not Found`, then entered `wimboot` again. Permitted retry
`run-20261002T063837Z-3c2cd155d481` immediately failed the process audit,
which saw `python3` immediately after launch. The root agent resumed at 11:32 UTC and
verified no VMs live and all original evidence hashes matching. Read-only
GPT/ESP inspection found `bootmgfw.efi` (3,008,968 bytes) and an ESP partition
GUID matching the firmware entry; that does not resolve the firmware fault.
Only `publication.iso` in the two failed Windows bundles was retired; their
disks, firmware variables, results and logs remain. Private retirement receipt
`/tmp/telos-recovery-root/abandoned-publications-retirement.json` records
23,144,542,208 bytes reclaimed and 58 GiB free. The original accepted iteration
and reserved keeper bundle remain untouched. The bounded process-audit fix
is committed as `c45c0dc`: 4,149 tests, five skips, no failures/errors, lab
touches or QEMU attempts; independent review passed 35 tests with no blockers.
Recovery `20261002T114212Z-1294100-repeat` ran from 11:42:12 to 13:47:15 UTC
at HEAD `c45c0dc`, reusing the same accepted iteration and pins. Windows
`run-20261002T114214Z-22aa7767d7e4` passed on its first attempt at 12:52:31 UTC:
`observed` / `native-windows-clean-shutdown`, one firmware PXE boot, release
`20261001.001`, unchanged canonical disk/variables and zero external
connections. Both cycles completed all six functional phases. That final
receipt is **FAIL**, `equivalent: false`, zero retries: the fresh cycle has
15 pass / one fail solely on `host_network_changes.route=4`. Other local
counters are zero, forwarding by privilege proof, and UniFi remains unproven.
Both gate-4 audits pass. Private before/after snapshots retain one automatic
IPv6 router-advertisement ECMP next-hop replacement, counted in the IPv4 and
IPv6 all-table views as four old/new entries. No automatic-route privilege
exception was approved; this failed receipt stands. Supervisor `1293625` and driver `1294100`
stopped with exit 2; no VMs remained after that run. Final receipt and
raw diagnostic paths are in
[the repeat driver](FACTORY-MAKE-TARGETS.md#the-repeat-driver).
The independent comparison, retirement receipt, full launch-test audit and
original evidence hash inventory also have durable private copies in
`homelab/var/factory/recovery-checkpoints/20261002-route-review/`.
Gate 11's independent live proof stays phase-one `partial` (five pass, three
ADR 0080 deferrals); the repeat's three/five recovery result does not replace
it. Historical repeat FAIL and restored-client DR PASS40/40 are unchanged.
Third strict recovery `20261002T143757Z-1346697-repeat` ran from 14:37:57 to
16:41:30 UTC from `011e678`, reusing unchanged accepted original iteration 2
plus one fresh full cycle at identical pins. Final receipt
`homelab/var/factory/repeat/recovered-repeat-3-receipt.json` is
**PASS-WITH-WAIVER**, `equivalent: true`, zero retries. Both cycles have
15 PASS and only the ADR 0080 UniFi waiver, and both gate-4 audits pass 4/4.
The fresh six local network counters are zero. Independent comparison agrees
with zero divergences. Supervisor `1346230` exited 0; driver `1346697` and all
QEMUs are stopped. Gate 12 is closed for phase one and TASK-6 is done. No
route-policy exception was needed or approved; that optional proposal is
superseded for acceptance. Durable supervisor and independent comparison files
are under `homelab/var/factory/recovery-checkpoints/20261002-strict-repeat-3/`;
exact work/receipt paths are in [the repeat driver](FACTORY-MAKE-TARGETS.md#the-repeat-driver).
Guarded retirement `011e678` freed 34,673,319,936 bytes from only three early
failed publications; all 21 other file hashes, prior receipts and the keeper's
reserved publication stayed unchanged. Its 27 tests passed with zero lab
touches, and private audit/retirement/hash records are in the route-review
directory above. Free space was 64 GiB before launch and about 30 GiB during
Windows installation; these are historical capacity measurements. Preserve
all failed receipts and both accepted cycles. TASK-7's local documentation
pass is complete: final command, source, rendered-site and browser checks
passed, as recorded in gate 13 and `DOCUMENTATION-PASS.md`. No push or
deployment is authorized by the live acceptance.

## Stage timing and why it was slow (2026-10-07)

Measured from retained evidence and live runs (read-only analysis, TASK-44):

| Stage | Wall time |
|---|---|
| Gate 5 Windows install | 68.2-69.9 min on six cycles; **10.3 min after `b9024cc`** (UAT-2) |
| Gate 6 Windows identity | 44.3-44.5 min, dominated by fixed waits (60 s sign-in pause, four Windows boots, two Controller-offline windows of 180-285 s, about fifteen Run-dialog action discs) |
| Gate 7 / gate 8 Arch | 2.8 min / 1.5-3.5 min |
| Gate 10 dual-boot | 5.3 min, about 4 min of it the Arch join units' boot waits with no directory up |
| Gate 12 cycle | about 2 h 03 min per cycle; Windows is about 91 % of it |
| Persistent converge / policy / accounts / probe / backup | under 1 min each |
| Durable Arch install / join / Windows join / keep-verify | 2.4-2.7 / 1.0-1.1 / 7.5-14 / 4.7-9.6 min |

Root cause of the Windows install time: 64 of its 69 minutes were Setup
pulling the 8 GB `install.wim` from the Controller's SMB share at a mean
1.8 MB/s, while guest, switch, Controller and host disk were nearly idle. The
loopback switch (`simulated_switch.py`) never set `TCP_NODELAY`, so each
Ethernet frame (one small write) waited for the peer's delayed ACK whenever
one was outstanding; request/response SMB stalled while bulk HTTP (`boot.wim`,
the Arch packages) stayed fast. `b9024cc` sets it on every accepted switch
peer and the gateway; the next install wrote the same 17 GB in about seven
minutes and finished in 10.3. Gate 6 and gate 12 have not been re-timed
since. Further savings ranked by the analysis, none taken: parallel repeat
iterations (port 31415 and the fixed fabric addressing block it), bounding
gate 10's join waits when no join media is present, trimming gate 6's fixed
waits, a Pro-only `install.wim`, and a golden sysprepped image for repeat
cycles (a redesign that conflicts with gate 5 proving PXE in every cycle).

Why the assembly is hard is mostly the boundary, not the technology: ADR 0077
and the hard boundary above (no TAP, bridge, VDE, passt or user-net; loopback
only; never `sudo`) force a Python userspace switch and simulated gateway
instead of a kernel bridge or libvirt network; ADR 0058 and the ban on guest
agents force serial-console automation of the Controller and QMP
pixel-compared GUI driving of Windows instead of cloud-init, SSH, WinRM or an
unattended `djoin`; ADR 0078 and the secret rules force one-use credential
discs; and gate 5's "PXE, no ISO attached, every cycle" rules out attaching
the ISO with an autounattend (10-15 min) or a golden image (minutes). A
rootless `unshare -rn` namespace with its own bridge would remove the switch
and gateway without `sudo` or host changes, but needs an ADR 0077 amendment.

Intermittent Windows boot stalls remain (see the mint's retries in
[FACTORY-MAKE-TARGETS.md](FACTORY-MAKE-TARGETS.md), "One-command mint"): the
firmware sometimes spins at the TianoCore logo after 72,192 bytes, once
reported `failed to load Boot0007 "Linux Boot Manager" ... Not Found` and
fell through to Windows Boot Manager, and the first Windows kernel boot in
the join topology sometimes hangs at about 29.8 MB read. Eleven manual boots
of the same disk outside the harness, with and without the control disc, all
passed; the cause is not identified and firmware is not claimed fixed.

A likely contributor, not yet tested: this host is an Intel Core Ultra 9
285K with split-lock detection, and `kernel.split_lock_mitigate` is `1`, so
every split lock a guest performs puts that vCPU thread to sleep for about
10 ms and serializes it with other split-locking cores. The kernel logged
`x86/split lock detection: #AC: CPU n/KVM/<pid> took a split_lock trap` at
Windows kernel addresses (`0xfffff80...`) during the 2026-10-07 Windows
boots (it logs once per thread, so the true rate is unknown). That penalty
is a well-known cause of slow or hung Windows guests on recent Intel hosts.
Disabling it needs root, so it is the owner's to run, and it is reversible:
`sudo sysctl -w kernel.split_lock_mitigate=0` (persist with a file in
`/etc/sysctl.d/`; undo with `=1`). Re-time gate 5 and the Windows join
afterwards before claiming any effect. The same day, UAT-3 lost two gate-5
installs: one to the PXE loop (OVMF `Not Found` for the Windows entry and
the NVMe removable path after Setup's reboot) and one where Windows powered
off at OOBE's "Updates are underway" screen without its readiness marker.

## Current blockers and cautions

- **RESOLVED 2026-09-24 — the canonical Controller image is installed.** The
  owner ran `make homelab-bootstrap-vm-install APPLY=1 CONFIRM=… ISO=…
  SEED_ISO=…` on 2026-09-24 (receipt `installed_utc` `2026-09-25T01:30:06Z`).
  It was the target's FIRST live run (`7b29624`) and it succeeded first time:
  all 19 console events from the archiso login through
  `console-password-updated`, `installation-complete` and `poweroff-observed`;
  QEMU exit 0; the disk holds a GPT with two partitions (one ESP), 2,539,716,608
  bytes allocated, SHA-256
  `ae7b6787c3741c388d7c44bddf859fefebc669d44aaf9a07f2edfb50ba114a3b`; receipt
  `build/homelab/vm/bootstrap-dc/install-receipt.json`.
  `make homelab-bootstrap-vm-status` now reports `ready`, the
  `make homelab-factory-repeat` dry run no longer refuses, and
  `make homelab-factory-persistent-converge-plan PERSISTENT_DC=<name>` no longer
  reports NOT READY. The manual console recipe is now the FALLBACK rather than
  the supported-but-unproven path: the runbook's
  ["Keep the `local-rescue` password"](docs/operator-runbook.md) section and
  ["Interactive offline installation"](vm/README.md) in `homelab/vm/README.md`.
  **Keep the new `local-rescue` password safe:** it is the ONLY credential that
  can ever open the image — root is locked, there is no authorized key, no init
  shell, and SSH password authentication is off — so losing it costs the whole
  image again. Rebuilding the image invalidates no retained gate receipt — the
  disk digest is captured per run at prepare time and no tracked artifact pins
  it.

  History, kept so it is not re-derived: from 2026-08-14 until 2026-09-24 this
  bullet was the CURRENT BLOCKER. The image had been destroyed 2026-08-14 with
  explicit owner authorization because its `local-rescue` console password was
  lost; `bootstrap-dc.qcow2` was then a 197,888-byte EMPTY disk (its
  `manifest.json` recorded `created_utc` `2026-08-14T20:52:55Z`),
  `build/homelab/vm/persistent-dc/` was empty, `homelab-bootstrap-vm-status`
  said `created but not installed`, and no live factory target could run.
  Prerequisites staged and verified at the time: the seed ISO
  `homelab/var/seed/telos-controller-seed.iso`, SHA-256
  `66afce1801e1577d1662465e748a4d0eec1019d75c6ead4c0d2be048218a452a`, and the
  signature-verified `homelab/var/media/arch/archlinux-2026.08.01-x86_64.iso`
  (SHA-256 `4e82dced1c4fd3e498b22a853f8db2a4d262d32b97e7e07d97390d9e425ffe5e`,
  fingerprint `3E80CA1A8B89F69CBA57D98A76A5EF9054449A5C`). The install target's
  guards are recorded in [FACTORY-MAKE-TARGETS.md](FACTORY-MAKE-TARGETS.md),
  "Installing the canonical Controller image".

- RESOLVED 2026-08-12 (owner chose "Hand off at install"): the gate-5 install now RETAINS the recovery publication.iso mode-0600 for the identity phase (`_retain_private_publication`, commit `0ef9fe6`) instead of destroying it; the destruction proof lives at the identity recovery gate. Note the operational consequence recorded in memory [[gate6-publication-single-use]]: each install yields exactly one gate-6 attempt, and a gate-6 run that fails after the credential actions (incl. the final publish) burns the publication and forces a fresh 68-min install. The historical analysis below is kept for context. --- BLOCKER (needs an owner design decision) 2026-08-12: the gate-6 identity acceptance requires a recovery `publication.iso` in the retained Windows bundle (`windows_identity_factory.py:588`), but a SUCCESSFUL gate-5 install DESTROYS its `publication.iso` by design (`windows_install_run.py:291`, commit `7b4bf6e`). The original bundle `run-20260728T114233Z-afecdf7cc9d0` only carried a usable publication because its own `result.json` recorded `fail` (a since-fixed validator double-count bug counted the single PXE boot twice), so its teardown skipped the destroy -- an ACCIDENTAL artifact. Gate 6's 24-check acceptance is genuinely PROVEN (attempt `20260812T043214Z-28ff545de0ce`, 24/24, which then ran the recovery gate that consumed that accidental publication). A fresh gate-5 install (`run-20260812T140120Z-70433b9dba26`, 2026-08-12, `observed`/`native-windows-clean-shutdown`) produced a native-ready `windows.qcow2` but correctly destroyed its publication, and the ephemeral local-rescue credential is retained nowhere -- so no matching recovery publication can be rebuilt. To make gate-6 repeatably runnable THROUGH the final publish (which emits `acceptance-evidence.jsonl`, the stream gate-8 prepare subsets into its bundle as `windows-evidence.jsonl` — see the gate-6 row for the three-filename explanation), the factory needs the recovery-publication provisioning made deliberate. RECOMMENDED FIX: the gate-5 install should HAND OFF the recovery publication to the identity phase (retain it mode-0600 in the bundle) rather than destroy it -- the credential-media DESTRUCTION PROOF already belongs to the identity recovery gate, which destroys it at the end of a successful acceptance (exactly what attempt 66 did). This restores the original working model deliberately and unifies the destruction proof at the recovery gate. It changes a passed gate's (gate 5) security teardown, so it is surfaced for owner confirmation rather than changed unilaterally mid-run. Alternative: provision a distinct recovery publication (with the installed disk's credential) as a separate retained artifact. Everything else in the lifecycle is done or owner-blocked.

- CURRENT 2026-08-11 (supersedes the two long gate-6/gate-7 investigation
  bullets below, which are retained as history): the live blockers those
  bullets tracked are closed. Gate 6's operator logon is proven live
  (first-profile creation reached; `13f1bf6`); its three remaining seams are
  the desktop proof (near-reference against the local-account reference — the
  operator's first desktop needs retention/calibration), receipt collection
  discarding a delivered `uncorrelated` result when the cleanup line arrives
  truncated (host `ValueError`), and the `classify_auth_events` correlation
  criteria rejecting a logon that visibly succeeded. Gate 7's repeated
  "no partitions" was the verify's lsblk parse (`941ba41`), not the guest, the
  transport, or partition timing; the audit failure was the run's own QEMU
  zombie at teardown (`a179368`). CLOSED 2026-08-14: the host-side join-media
  wiring this bullet tracked as "in progress" (build/attach/destroy the one-use
  TELOS_JOIN credential ISO around the in-guest join step) landed and is
  live-proven — gate 7's passing bundle
  `arch-installs/run-20260811T141601Z-6941005247e8` records `join_media`
  `built`/`attached`/`consumed`/`destroyed` all true, plus
  `join_media_destroyed` and `join_principal_destroyed` true. Gates 8 and
  10 gained runners (`e58cef8`, `3d45584`); gate 10 passed its live shakedown
  2026-08-11 and gate 8 had its first live run 2026-08-13 (see the gate-8 row).
  No successful local lifecycle permits any implicit
  UniFi mutation, physical attachment, or hardware erase.
- Gate 7 first live shakedown (2026-08-10, bundle
  `arch-installs/run-20260810T215936Z-02fe36622647`) found a real boot bug:
  the workstation booted the existing `Windows Boot Manager` instead of
  PXE, so the installer never ran. `arch_install_prepare` copied the
  Windows-installed OVMF vars (carrying a `Boot0008 "Windows Boot Manager"`
  NVRAM entry at boot priority) and pinned `-boot order=c,once=n`; the
  one-shot network boot cannot override a firmware that already has a
  bootable Windows entry. The Windows installer works only because it
  starts from a blank disk. Fix in progress: use pristine OVMF vars for the
  install boot (no inherited Windows entry) and a network-first boot order,
  keeping the persistent Windows disk untouched; `arch_second`'s
  `bootctl install` + `default auto-windows` handles the post-install menu.
  The PXE transport, controller publication, and archiso boot themselves
  worked — the controller published the Arch release and the disposable
  controller converged.
  Retry 2026-08-10 (`arch-installs/run-20260810T224324Z-f60ca3d20ef4`,
  pristine vars + `order=n`) still did not PXE: the workstation serial
  shows `BdsDxe: starting Boot0002 "UEFI QEMU NVMe Ctrl TELOS-WIN-0001"` —
  even with pristine vars and network-only order, OVMF auto-discovers the
  disk's Windows ESP bootloader, creates an NVMe boot entry, and boots it,
  ignoring `-boot order=n`. Forcing PXE while the target disk carries a
  bootable Windows ESP needs a stronger approach than the boot order:
  either PXE-boot with the NVMe DETACHED (archiso is a RAM live
  environment and needs no disk to boot) and QMP hot-attach the disk after
  archiso is up for the install, or write an explicit OVMF `BootOrder`
  NVRAM variable putting the network entry first and the disk last. The
  disk-detached-then-hot-attach approach mirrors how a real PXE archiso
  install works and is the recommended fix.
  Rework landed (`ec79189`) and its live retry
  (`arch-installs/run-20260810T232404Z-77e33381ce5a`) PROVED the boot fix:
  `BdsDxe: starting Boot0002 "UEFI PXEv4 (MAC:...)"` — deterministic PXE,
  archiso fetched and booted fully to `archiso login:` on ttyS0. The
  install then stalled at one small seam: the arch-workstation PXE release
  presents an `archiso login:` prompt on the serial console (no serial
  autologin drop-in), but `arch_install_run.drive_installer` waits for a
  root shell prompt and never answers the login, so it timed out at 1800s
  with no install markers. NEXT: have drive_installer log in as `root`
  (archiso live root has no password) at the `archiso login:` prompt
  before hot-attach + install, or add a serial getty autologin drop-in to
  the arch-workstation PXE release. The PXE transport, archiso boot, and
  the disk-detached approach are all proven; only the login handshake
  remains.
  UPDATE 2026-08-11 (runs through `arch-installs/run-20260811T025952Z-47fafcfc988a`):
  the login (`986ebdc`), the readiness handshake (`8ca8640`, re-probed in
  `07a1058` after a single probe was eaten as login echo), and the NVMe
  hot-attach (`ce02565`, a `pcie-root-port` since q35 will not hotplug onto
  pcie.0) are ALL proven live — the serial shows
  `TELOS ARCH INSTALL BEGIN` and `TELOS ARCH DISK ATTACHED serial=TELOS-WIN-0001`.
  TWO seams remain, both consistent across runs:
  (1) INSTALLER: `arch-second-verify.py` fails `/dev/nvme0n1 has no
  partitions`. The backing `windows.qcow2` genuinely holds the Windows GPT
  (17.6 GiB mapped, 29045 extents) and the overlay is correctly backed, so
  the guest is not enumerating the GPT after the PCIe hotplug. A
  `partprobe`/`blockdev --rereadpt`/`udevadm settle` retry loop
  (`490c313`, `1e23b55`) did NOT surface the partitions, so partprobe
  timing is not the cause. FIX APPLIED (pending live validation): the
  `confirm_disk` step now forces an NVMe-namespace rescan BEFORE partprobe —
  it derives the controller name from the namespace device
  (`base=$(basename "$dev"); ctrl=${base%n*}`, nvme0n1 -> nvme0) and issues
  both `echo 1 > /sys/class/nvme/$ctrl/rescan_controller` and
  `nvme ns-rescan /dev/$ctrl` best-effort inside the existing reread loop
  (arch_install_run.py; test `test_drive_installer...` asserts
  `rescan_controller`/`nvme ns-rescan`/`ctrl=${base%n*}`). If a namespace
  rescan still does not surface the GPT on the next live run, the fallbacks
  are a hotplug-capable virtio-blk target or a cold-plug-behind-a-disabled-
  boot-entry approach. (2) AUDIT: every run's terminal error was
  `simulation_overlay` "cannot inspect process <pid> file descriptors"
  (phase arch-install-driving; the pid incremented each run) — the
  fail-closed overlay-ownership audit hitting a same-uid transient process
  whose `/proc/<pid>/fd` it could not read. FIX APPLIED (pending live
  validation): `canonical_disk_users` now re-checks a same-EUID
  un-inspectable process over a tiny bounded budget
  (`_PROCESS_INSPECT_ATTEMPTS`/`_PROCESS_INSPECT_BACKOFF_SECONDS`) and skips
  it ONLY if it exits within the window (a process that has exited holds no
  descriptors on the canonical disk); a process that stays live and
  un-inspectable still fails closed, so the security boundary is unchanged.
  Two new tests pin both halves:
  `test_same_user_unidentified_live_process_fails_closed` and
  `test_transient_unidentified_process_that_exits_is_skipped`. Both seams
  now have code fixes with unit coverage; the whole transport + boot +
  login + hot-attach chain was already proven live and unchanged.

- Gate 6 operator logon — narrowed with strong evidence 2026-08-10
  (attempt `20260810T221525Z-f22a898acb74`, first with the realm fix and
  post-submit frame retention). Coordinate unchanged
  (`no-logon-event` + `uncorrelated`), and the 10 retained post-submit
  frames (`post-join-reauthentication/identity-postsubmit-000N.ppm`) are
  decisive: after the operator UPN + password + Enter, the sign-in form
  resets to EMPTY ("Sign in to: FACTORY") and stays static for the full
  10s — no spinner (no processing), no error message (no DC rejection),
  no desktop, no interactive logon event. Network and DNS are correctly
  configured: the switch log shows the post-reboot workstation completing
  DHCP, and the identity gateway runs in `identity_mode`, so the
  workstation's DNS is the DC (`CONTROLLER_IP`) with suffix
  `ad.factory.test` (`simulated_gateway.py` DHCP option 6/15). So the
  logon is submitted but never serviced to a completed interactive logon,
  and the realm fix alone did not change the outcome. NEXT DIAGNOSTIC
  (the instrument-and-rerun that cracked the receipt mystery): broaden the
  guest post-submit diagnostic `windows_join_control/TelosPostSubmitDiagnostic.ps1`
  beyond LogonType=2 4624/4625 to also report Netlogon/Kerberos errors in
  the System log and any non-Type-2 logon so the next run says WHY
  (no-logon-servers vs bad-credential vs profile-failure) instead of a
  bare `no-logon-event`; and capture a few sub-second frames at the Enter
  itself to catch a flashed error. Also verify the operator's AD password
  staging actually took (compare staged vs typed). Do NOT keep spending
  attempts on the bare coordinate; make the guest diagnostic speak first.
  Done and DEFINITIVE 2026-08-10. The guest diagnostic was enriched to
  report the specific cause (commit `7369991`; a fail-safe fix `683da02`
  after attempt 21 regressed to `watcher-error` from a Get-WinEvent against
  an absent NETLOGON/Kerberos provider). Attempt 22
  (`20260810T230825Z-c227e9001106`) rendered `no-logon-event` with the
  enriched, fail-safe diagnostic — meaning it found NOTHING in the window:
  no operator 4625 of any LogonType, no NETLOGON 5719/3210/5783, no
  Kerberos error, no non-interactive operator logon. This rules out
  DC/network/Kerberos entirely (any of those would write a System-log
  event) and, with the post-submit frames (form resets empty, no spinner,
  no error, no desktop), proves the operator's Enter is NOT initiating an
  interactive logon at all. The problem is the GUI submit not reaching
  LSA, not the directory. Note the local replacement sign-in pre-reboot
  uses the same plain-Enter submit and DOES reach the desktop, so the
  difference is the post-reboot domain "Other user" surface specifically.
  NEXT: capture frames through the `type_secret` + `key("ret")` submit
  (secret-safe — the field shows masked dots, not plaintext) to see
  whether the password field holds dots and what Enter does, then decide
  between a re-focus-before-Enter fix and clicking the submit arrow.
  ROOT CAUSE FOUND 2026-08-10 (attempt 23,
  `20260810T235549Z-3230f9dcca17`, submit-transition frames `cd9499f`):
  the `identity-submit-pre-activation.ppm` and `-post-activation.ppm`
  frames — captured immediately before and after the operator's Enter —
  BOTH show the Windows LOCK SCREEN (the clock/date), not the sign-in
  form. The UPN was entered into the sign-in form earlier (frames
  0001-0004), but by the time the password is typed and submitted the form
  has reverted to the lock screen, so the credential and Enter hit a dead
  surface and no logon fires. The cause is ordering in
  `windows_identity_adapter._reauthenticate`: `prove_password_target`
  (types the UPN, line ~962) runs, then the slow `controller_auth.arm()`
  (line ~1147 — sudo prompt + watcher launch + prearm handshake over the
  Controller serial, tens of seconds), then `submit_secret` (types the
  password + Enter, line ~1205). The Windows "Other user" sign-in form
  times out back to the lock screen during that arm. FIX: the arm must not
  sit between UPN entry and password submit. Move the controller-auth arm
  to BEFORE the GUI credential entry (arm while at the lock screen, then
  wake → UPN → password → submit contiguously and quickly), or re-wake and
  re-enter the sign-in form after the arm and before typing the password.
  The observation window is anchored to the submit fence, not the arm
  time, so arming earlier is semantically safe (the armed window is 120s,
  ample for the quick GUI entry).
  Fix landed in two parts. `7c8929c` added a `reestablish_sign_in_form`
  step (wake → account select → UPN → password-target) at the top of
  `submit_secret` on the domain-operator path. Attempt 24
  (`20260811T004113Z-62bd7ec41301`) still showed the lock-screen clock in
  the pre-activation frame: a plain wake key does not dismiss a
  domain-joined machine's timed-out lock screen — it requires the Secure
  Attention Sequence. `dea0472` prepends `Ctrl+Alt+Del`
  (`interaction.chord("ctrl","alt","delete")`, as the change-password flow
  already uses) to the re-establish. Attempts 25-27 still showed the lock
  screen; instrumented frames (attempt 28, commit `86616a9`) captured the
  re-establish step by step and proved the fix path: `Ctrl+Alt+Del` ALONE
  instantly restores the "Other user" form with the operator UPN intact
  and the password field focused and empty. The prior full re-entry
  (wake/select/UPN + observe waits) was actively harmful — it typed stray
  keys into the focused password field and its observe waits re-timed-out
  the form. Commit `b627bda` reduced the re-establish to exactly the SAS.
  REMAINING (attempt 29, `20260811T015138Z-3b6eed30a3b1`): the
  `reestablish-after-cad` frame is now a perfect clean focused empty form,
  but the `submit-pre-activation` frame (after `type_secret` +
  `_prove_secret_entry_departure`) is the lock screen AGAIN. Diagnosis:
  after the SAS transition the secret keystrokes do not appear to land in
  the field, so `_prove_secret_entry_departure`
  (`windows_identity_adapter.py:371`) loops to its full `remaining()`
  timeout waiting for dots that never show, and the form times out during
  that ~30-60s wait. TWO CANDIDATE FIXES to try next: (a) a short settle
  after the SAS before `type_secret` so the freshly surfaced form is
  input-ready — use a FIXED bounded sleep that does NOT consume the submit
  budget via `remaining()` (a naive `remaining()`-consuming settle broke
  the tight budget in
  `test_reviewed_submit_focus_timeout_never_issues_return`); or (b) verify
  the departure-proof `sign_in` reference geometry/crop still matches the
  post-SAS field (a stale reference would also loop). Add an
  after-`type_secret` frame to confirm which before choosing.
  DIAGNOSTIC IN PLACE (pending the next live run): `submit_secret` now
  retains a secret-safe `identity-after-type-secret.ppm` frame BETWEEN
  `type_secret` and `_prove_secret_entry_departure`
  (windows_identity_adapter.py, gated on `post_join_retain_submit_frames`
  so the mock-plan tests skip it; suite green). That frame is decisive
  between the two candidates: masked dots present -> field receives input,
  the departure-proof reference crop is stale (candidate b); empty field or
  lock screen -> keystrokes are not landing, apply the fixed bounded
  settle-before-`type_secret` (candidate a). Candidate (a) was deliberately
  NOT pre-applied: adding a settle sleep perturbs the sleep-count structure
  that `test_reviewed_submit_focus_timeout_never_issues_return` depends on,
  and the choice between (a) and (b) is unfalsifiable without this frame --
  so the next live run reads the frame first, exactly as the receipt
  mystery was cracked by instrument-then-rerun. This is the only remaining
  step for gate 6; the root cause and the form recovery are solved.
- The `receipt-unavailable` producer is identified. Attempts six
  (`20260810T132254Z-3a2af77f9c4f`) and seven (`20260810T133851Z-f48a348ade9b`)
  both reproduced the established coordinate and both rendered
  `controller-auth-receipt-origin=unattributed`, excluding the host result
  wait and the Controller's own wire value. Only one producer emits an
  unavailable receipt with no cleanup coordinate, no arm subphase, and no
  host error: `begin_submission()` finding its armed window already expired,
  so the submit fence is never sent and the Controller is never asked. The
  arithmetic makes it deterministic: submission always completed inside the
  120-second GUI budget that starts at arm, and the armed window was capped
  at 60 seconds, so any arm-to-fence phase between 60 and 120 seconds
  expires the window on every attempt. Commit `0524cbf` labels that expiry
  `arm-window-expired`, widens the window to the GUI budget
  (`min(adapter timeout, 240)`), and stops the terminal-cleanup rebuilds
  from stripping `receipt_origin` and `host_error`. Attempt seven was
  launched before those edits and ran only the cleanup-preservation change,
  so it confirms the shape but not the fix; attempt eight
  (`20260810T135411Z-ece0215bca67`) is the first run carrying the fix. Its
  receipt must either collect a real Controller answer (`authenticated`,
  `rejected`, `no-event`, ...) that finally splits a rejected credential
  from one never presented, or label itself — a still-`unattributed` receipt
  from attempt eight would falsify this identification.
  Falsified 2026-08-10: attempt eight (`20260810T135411Z-ece0215bca67`) ran
  the widened window and still rendered a bare unattributed receipt, so the
  expiry never fired and the producer sits earlier. The remaining match is
  a proved-cleanup `arm()` failure: the adapter stores the arm-failure
  result, discards the error whose arm subphase explains it, and continues
  the GUI without a watcher — deterministic if, for example, sudo on the
  shared Controller console refuses the watcher launch every attempt.
  Commit `01ddf88` preserves the arm subphase through the continue path to
  whatever coordinate the attempt reaches, and a receipt line that arrives
  but fails processing now names its exception type. Attempts nine and ten
  still rendered bare because the terminal desktop raises sit after the
  instrumented handlers and dropped the subphase a fifth time; commit
  `a6b0a14` carries it through them with an integration test that drives
  the real flow. RESOLVED 2026-08-10: attempt eleven
  (`20260810T145920Z-a13b99b97a30`) rendered
  `controller-auth-arm-subphase=receive;
  controller-auth-receive-observation=command-exit-nonzero`, and a local
  standalone execution reproduced the failure exactly: commit `fc628e8`
  (2026-07-30) added a relative `signal_cleanup` import to
  `controller_auth_diagnostic.py`, which the Controller executes as a bare
  file from `/opt/telos-factory` — the watcher crashed with an ImportError
  and exit 1 before printing ARMED on every attempt since, cleanup
  recovery succeeded, and the GUI continued without a watcher. Commit
  `2bdf36d` restores standalone execution and adds a subprocess test that
  runs the file exactly as the Controller does, replacing the syntax-only
  check that let this land. Attempt twelve
  (`20260810T161556Z-a9cff6b68239`) ran with the import fix and moved the
  failure: still `arm-subphase=receive` with `command-exit-nonzero`, but
  now with `cleanup=sink-absence-unproved` at the arm coordinate itself —
  the watcher executes past the import and crashes somewhere the local
  standalone reproduction cannot reach (its configuration check passes
  only on a real converged Controller). Commit `d7c228e` therefore
  retains a bounded, credential-redacted Controller console excerpt in
  the attempt's reauthentication evidence whenever arming fails, so the
  next attempt names the actual Controller-side error. Attempt thirteen
  (`20260810T162521Z-29ba30389e7d`) was externally interrupted mid-join
  (`join-guest.result-receive`, broken output pipe, complete teardown)
  and carries no signal on the watcher; attempt fourteen
  (`20260810T163132Z-98e4fc71625a`) was likewise externally interrupted
  during controller startup with complete teardown (both were harness
  reaps of the tracked background channel, not the owner; later attempts
  ran detached via `setsid` and completed). RESOLVED to one concrete bug
  2026-08-10 across attempts fifteen through eighteen — the receipt is no
  longer a mystery. The retained console transcript
  (`.../attempt-20260810T202257Z-8aa6cc949d90/post-join-reauthentication/controller-auth-console.txt`)
  shows the directory-side watcher printing all four prearm phases
  (`PAYLOAD_VALID`, `CONFIGURATION_VALID`, `SINK_READY`, `SID_READY`) then
  `ARMED`, then nothing: it blocks on `input()` awaiting the
  `__TELOS_AUTH_SUBMIT__` fence, which never arrives, so the host's
  bounded result wait expires (`origin=host-wait-expired`). The watcher
  is launched with `sudo -k -S`, which reads the sudo password from the
  same stdin the watcher then reads the fence from, and the fence IS
  newline-terminated (`serial_automation._send`). CORRECTED and RESOLVED
  2026-08-10: the stdin-handoff theory was wrong. The real cause was a
  result-collection ordering bug: `begin_submission` starts the host's
  bounded result deadline, then the domain-operator path runs its own
  Windows post-submit diagnostic for up to `SUBMISSION_PHASE_TIMEOUT`
  (70s) before calling `result()`, so the fixed deadline had already
  expired and the wait failed against a Controller receipt sitting unread
  in the console buffer — hence `host-wait-expired` with the watcher fully
  armed. Commit `b3ec83d` makes `result()` extend the session deadline to
  a fresh receipt window from its own call, so a late collection reads the
  waiting receipt. **Attempt nineteen (`20260810T213350Z-afb69732ff6c`)
  read a real directory receipt for the first time: `controller-auth=uncorrelated`,
  not `receipt-unavailable`.** The three-week receipt-unavailable
  investigation is closed. Fixes that mattered and stand: the
  standalone-import regression (`2bdf36d`), the hanging-`smbcontrol` crash
  (`3e9febe`), the result-ordering deadline (`b3ec83d`), the
  console-excerpt retention that read the crash (`d7c228e`, `29e0b7d`,
  `d44253d`), and all five diagnostic-labelling layers.
- NEW real coordinate (gate 6, not plumbing): attempt nineteen renders
  `check=windows-joined; operation=join-guest.reboot-reauth-desktop;
  post-submit-diagnostic=no-logon-event; controller-auth=uncorrelated;
  controller-auth-cleanup=live-route-unproved`. Both sides agree the
  post-reboot reauthentication is not completing the domain operator's
  interactive logon: Windows records no Type-2 interactive 4624/4625 for
  the operator SID in the window (`no-logon-event`), and the directory
  observed auth activity that did not correlate to the expected
  (account, domain, workstation_ip, sid) tuple (`uncorrelated`). This is a
  genuine identity/GUI problem to debug from real signal — likely the
  reauth surface is not submitting the operator credential to an
  interactive domain logon (wrong sign-in surface, account tile, or a
  correlation-criteria mismatch on SID/realm form). `live-route-unproved`
  is a secondary cleanup coordinate, not the primary failure. Investigate
  the retained `rotation-evidence/` and `post-join-reauthentication/`
  frames against the correlation criteria in `classify_auth_events` and
  the Windows logon query in
  `windows_join_control/TelosPostSubmitDiagnostic.ps1`.
- Boot-failure attempts no longer burn the full readiness budget: commit
  `627a719` aborts the Windows OS readiness wait as soon as the guest
  process exits or the switch records `peer-abandoned-before-authentication`
  (attempt four's 600-second mode); retry policy is unchanged.
- Test-cycle latency findings recorded 2026-08-10 and deliberately deferred
  rather than risked mid-acceptance: the two unconditional 60-second sleeps
  (rotation initial sign-in and reauthentication wake) should become bounded
  polls, but that needs a lock-curtain reference frame so the wake key is
  never sent to a black screen; the per-attempt controller rebuild
  (qemu-img convert, 267-package seed install, xorriso, Ansible convergence,
  roughly 3–6 minutes) could be replaced by a converged-controller snapshot
  keyed on input digests, but that weakens the per-attempt fail-closed
  convergence proof and needs a decision record before implementation;
  controller convergence and the first Windows boot could overlap, a
  moderate-risk reordering of `run_lifecycle`. None of these gate attempt
  cadence as hard as the now-fixed expiry did.
- Guest progress reporting is implemented to the unit level (commits
  `e4457c9`, `a315449`): the protocol library gained its missing halves
  (envelope-building reporter, host port arming/classification), the
  factory runner arms an audited dedicated virtserialport and records a
  secret-free, never-load-bearing progress block in evidence, and the
  archiso image carries a device-bound stdlib reporter service. Remaining
  before a live guest can report: a per-run credential-delivery hook into
  the sealed PXE payload (owner-facing design decision — do not invent a
  secret channel), the next privileged image rebuild, reconnect-aware
  collection across guest service restarts, and consumption by the
  identity and install runners.
- Local evidence for the PXE handoffs already exists and should not be
  re-derived: `homelab/var/factory/evidence/20260728T001858Z-3005758-pxe-handoff`
  records a passing x86-64 UEFI iPXE Arch installer handoff and
  `20260728T002735Z-3032556-pxe-handoff` a passing WinPE wimboot chain, both
  through the simulated gateway's options 66/67. Both were re-proved on
  2026-08-10 against release set `20260727.005` with current code:
  `20260810T143221Z-873911-pxe-handoff` (Arch) and
  `20260810T143444Z-874290-pxe-handoff` (WinPE), both `pass`. Gates 4–5
  stay pending because those runs used a seed-ISO disposable controller
  with publication-ISO release injection, not the accepted converged
  Controller serving the selected transactional release set, and gate 5
  additionally needs the real Windows Setup path.
- Gate 5's Windows Setup path is stronger than its recorded evidence: the
  retained bundle `run-20260728T114233Z-afecdf7cc9d0` completed a genuine
  one-shot PXE WinPE Windows 11 Pro installation — its serial log shows one
  `BdsDxe: starting ... UEFI PXEv4` boot, two subsequent native
  `Windows Boot Manager` disk boots with no ISO or PXE, the
  `TELOS WINDOWS NATIVE READY` marker, `Current Edition : Professional`,
  and a guest-initiated shutdown — while its `result.json` records
  `fail/windows-setup` only because the pre-`1463b65` validator counted the
  single PXE boot twice (`serial.count("UEFI PXEv4") != 1` matches both the
  loading and starting lines). The bundle's daily use as the identity input
  corroborates the successful install. A fresh full install run under the
  fixed validator was started 2026-08-10 from bundle
  `run-20260810T141818Z-8e3bc8bdd2ce` to record a clean pass.
- CORRECTED 2026-08-14 (the previous "Nothing is published / force-push
  required" text was false and is superseded). Everything in this repository is
  ALREADY PUBLIC. `main` tracks `origin` = `https://github.com/spincyc/telos.git`
  and has been published by ordinary fast-forward push 59 times
  (`git log -g refs/remotes/origin/main` shows 59 `update by push` entries and no
  forced update); no force-push is needed or has occurred.
  `continue-windows-identity-acceptance` is NOT at the same commit as `main` — it
  sits at `9a5841e` and is an ancestor of `main` (`git merge-base` returns
  `9a5841e` itself), i.e. it is a fully merged historical branch, not a divergent
  one. Standing posture: `main` is normally at or a few local commits ahead of
  `origin/main`, and an ordinary `git push` publishes them. Verify with
  `git rev-parse HEAD origin/main` and
  `git rev-list --left-right --count origin/main...HEAD` before pushing.
  CONSEQUENCE that matters for gate 13: `homelab/docs/factory-guide.md` and
  `homelab/docs/operator-runbook.md` are on public `origin/main`
  (`git ls-tree -r origin/main -- homelab/docs`), so calling them "unpublished"
  historically meant only missing site navigation, never privacy. Site wiring
  was implemented and verified locally on 2026-10-01. Never place a real hostname, IP, MAC, or serial in any
  tracked file; real instance values belong only in the gitignored
  `homelab/instance/` overlay.
- A fourth attempt `20260730T190013Z-696c1fb718b5` failed differently and
  worse: after 11 minutes it raised a bare `WindowsIdentityRunError` with no
  check, operation, or diagnostic at all. It booted the Windows guest twice,
  logged two `peer-abandoned-before-authentication` switch events, produced no
  rotation evidence, and tore down completely. That is earlier than the first
  three attempts, which all reached the desktop, and it is before any
  controller-auth code runs, so the receipt-origin work is not implicated.
  Both questions it raised are now closed. The boot path lost its coordinates
  because both boot raises passed `diagnostic=None`; fixed. Controller-state
  drift was checked and disproven **as measured on 2026-07-30**:
  `build/homelab/vm/bootstrap-dc` still dated from 2026-07-27 and the paired
  `windows.qcow2` from 2026-07-28, while each attempt writes only its own
  overlay, so four runs mutated neither. That dating is history only: the
  canonical image was destroyed and recreated empty on 2026-08-14, and
  reinstalled on 2026-09-24 (see the resolved blocker above), which falsifies
  the timestamps but not the finding —
  those four runs still mutated nothing. Do not
  read a fourth failure as four of a kind, and do not re-derive the drift
  hypothesis.
- A fifth attempt reproduced the boundary and rendered none of the coordinates
  added this session, so `receipt-unavailable` has a producer outside the four
  instrumented paths. Enumerating every producer by reading, rather than by
  running, excludes almost all of them: the six `arm()` producers all carry an
  arm subphase, which the failure lacks; `cancel()` returns `cancelled` on its
  success path, so the cancel-after-GUI-failure route is not it; the single
  raise relying on the error constructor default carries
  `arm_subphase=preflight`; and all seven adapter producers set a cleanup,
  which the failure also lacks. No known producer matches the observed shape of
  `receipt-unavailable` with neither cleanup nor arm subphase. Either a
  normalization step between the adapter and the rendered diagnostic drops the
  cleanup coordinate, or a producer remains unfound. Superseded 2026-08-10:
  both branches were true — the terminal-cleanup rebuilds stripped
  coordinates, and the unfound producer is the expired armed window in
  `begin_submission()`, which this reading pass missed because its raise
  sits between the arm and result phases it enumerated. See the first
  bullet in this section.
- Three authorized attempts (`20260730T181419Z-39d2f820716d`,
  `20260730T182932Z-c93f871638bd`, `20260730T184757Z-0e9b24f41a38`) all reached
  the same coordinate with complete five-part teardown. Both host-side
  exception-swallow paths are now instrumented with `host_error`, and neither
  fired on the third attempt, so no discarded host exception explains
  `receipt-unavailable`. It is therefore produced deliberately, and the next
  split is the one that matters: distinguish the host's bounded wait for the
  result receipt expiring from the Controller itself reporting
  `receipt-unavailable`, which is a legitimate value in its wire vocabulary.
  That split exists as of commit `6d55dd0` and attempts may be spent again;
  the labels excluded both branches and identified the true producer (see
  the first bullet in this section). Note the empty
  `runtime/controller/guard` directory is not evidence of failure: those paths
  are teardown media accounting for a guard controller this path does not run.
- Attempt `20260730T181419Z-39d2f820716d` ran with operator authorization and
  failed honestly at the established boundary: `check=windows-joined`,
  `operation=join-guest.reboot-reauth-desktop`,
  `error=WindowsLocalReauthenticationError`,
  `post-submit-diagnostic=no-logon-event`. All five teardown parts are proved.
  Pre-reboot rotation reached the desktop and the security-options surface;
  post-reboot reauthentication retained only sign-in frames and never a
  desktop. `controller-auth-collection=receipt-unavailable` and the attempt's
  `runtime/controller/guard` directory is empty, so the Controller diagnostic
  produced nothing. Until that receipt is delivered, the evidence cannot
  distinguish a rejected credential from one never presented to the directory,
  and further Windows-side attempts will keep reproducing the same coordinate.
  Fix Controller receipt collection before spending another attempt.
  Superseded 2026-08-10: receipt collection is fixed in `0524cbf` (expired
  arm window); see the first bullet in this section.
- Live Windows identity attempts run under the granted operator
  authorization for privileged local QEMU. Superseded 2026-08-10: the
  sandbox-refusal note no longer holds — `/dev/kvm` is world-readable on
  this host and the 2026-08-10 attempts ran KVM QEMU directly from the
  agent session, so attempts need no operator hand-off. Every prior attempt
  tore down completely, and the retained bundle
  `run-20260728T114233Z-afecdf7cc9d0` remains the only identity input.
- Image promotion now has a static, non-privileged gate:
  `homelab.lib.image_promotion_gate.gate_candidate_image` merges the profile
  contract, audits a candidate root through the confined read-only package
  gate, and reconciles every required and installed package against the signed
  seed receipt, attributing each failure to contract, root-audit, or
  seed-closure. Booting a candidate image and promotion authority itself
  remain open.
- The actual Windows ISO is available and Windows 11 Pro was found at index 6.
  Superseded 2026-08-14: the OVMF WinPE boot and the real Windows install are
  no longer outstanding — gate 5 passed 2026-08-10
  (`windows-installs/run-20260810T145421Z-5b457e50e20b`, one PXE firmware boot,
  `native-windows-clean-shutdown`, Edition Professional).
- The disposable controller is accepted for Samba AD, DNS, signed time,
  TFTP, and HTTP service behavior. Superseded 2026-08-14 in part: it HAS since
  served real workstation PXE boots (the passing gate-5 and gate-7 installs).
  The loopback release-pointer rollback passes in gate 11; serving and booting
  the rolled-back release remains separate proof. Native directory backup,
  same-instance restore under a new DC name, reconvergence and probe passed
  2026-10-01. Existing-client verification initially failed on SSSD readiness;
  after the Samba SRV repair and reconvergence it PASSED 40/40 without a
  rejoin (current recovery evidence above).
- Existing PXE staging proves payload construction, not unattended Windows
  installation. Superseded 2026-08-14: the answer file, WinPE startup workflow,
  disk-serial gate, installation-image delivery, secret injection, and
  post-install acceptance are all implemented and live-proven through gates 5
  and 6. Note the standing rule that there is no unattended install PATH for a
  physical machine; the local proof is a disposable-disk gate.
- The transactional release-set path is implemented and tested. The factory
  derives the Arch source from its sealed ISO by mount-free, digest-addressed
  extraction. Superseded 2026-08-14: the Controller netboot source tree is built
  and five release sets have been accepted —
  `homelab/var/pxe/release-sets/20260727.001` through `.005`, with
  `homelab/var/pxe/selected-release-set.json` then selecting `20260727.005`
  (manifest SHA-256 `110ec7942a1c8dbddeef48d88b00930076e37c94654663590727683c147da17f`).
  All five bind the July media seal; since the 2026-09-30 reseal they verify
  only against its kept copy (see [Verified installation media](#verified-installation-media)).
  The current selection is `20261001.001`, bound to the current seal and
  used by the active fresh repeat.
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

This boots `build/homelab/vm/bootstrap-dc`, installed 2026-09-24 — see the
resolved canonical-image blocker in
[Current blockers and cautions](#current-blockers-and-cautions).
`make homelab-bootstrap-vm-status` must report `ready` first.

This command generates and wipes its own one-run password. Never supply the
operator's `local-rescue` password in Make, the environment, a command, or an
answer file. `make homelab-sim-run APPLY=1` is the separate final human gate;
it already passed and should be repeated only after a material change to the
manual console path or immediately before separately authorized physical
attachment.

Everything the previous version of this paragraph prescribed is DONE and must
not be re-derived: the Controller netboot output is built, release sets
`20260727.001`–`.005` remain accepted against the kept July media seal;
`20261001.001` is now selected against the current seal. The UEFI iPXE request
and both installer handoffs are proven. Gates 5–10 pass; the complete Windows
VBS plus Arch gate-4 audit passed all four checks on 2026-10-02. Gate 11 is
closed for phase one at `partial` (2026-10-01).

Current actions and completed prerequisites:

1. **Keep the canonical Controller image's `local-rescue` password safe.** The
   image was installed 2026-09-24 through `make homelab-bootstrap-vm-install`
   (its first live run succeeded); losing the password costs the whole image,
   and the hand-driven console install per the runbook's
   ["Keep the `local-rescue` password"](docs/operator-runbook.md) recipe and
   ["Interactive offline installation"](vm/README.md) is the fallback.
2. **Gate 12 (aiq TASK-6) is DONE.** Strict recovery
   `repeat/20261002T143757Z-1346697-repeat` from `011e678` finished at
   16:41:30 UTC, supervisor exit 0, with PASS-WITH-WAIVER, equivalent cycles
   and zero retries. One accepted original cycle was reused and one fresh
   full cycle ran at identical pins; each has 15 PASS / only the UniFi waiver
   and gate-4 4/4 PASS. Independent comparison agrees; no repeat driver or
   QEMU remains. Preserve both accepted sources and the exact receipt/hash
   in [the repeat driver](FACTORY-MAKE-TARGETS.md#the-repeat-driver).
   Original listener failure `011915`, stopped recovery `053117` without a
   receipt, route failure `114212` and older failures remain unchanged. No
   automatic-route exception was needed or approved, and no new cycle is
   required for acceptance. The firmware fault remains unresolved.
3. **Disaster recovery (aiq TASK-41, TASK-42) is DONE.** `rehearsal-auto-ws2`
   has all four stages folded; Windows join `attempt-20261001T223623Z-5e1cc129efaf`
   passed and retired its publication. Pre-DR keep-verify
   `run-20261001T224742Z-294135-5bf47dc6` passed all 40 checks. Native backup
   `20261001T225428Z-323971-342a3f27` verified before destroying the throwaway
   directory; same-instance restore `20261001T225520Z-327126-e82e02db` passed
   under new DC `dr-2610012255`, followed by reconvergence and probe
   `20261001T225659Z-328973-facea8fe`. **The first post-DR keep-verify failed**:
   `run-20261001T225740Z-329731-9a00cfd1` could not bring SSSD online, although
   the machine key authenticated to Kerberos and LDAP answered. SIGTERM
   during the subsequent Controller relaunch prevented Windows verification;
   fallback termination is recorded. Repair `bdebb4f` corrected compressed SRV
   Targets, reconvergence passed four strict DNS probes, and subsequent
   `run-20261001T235410Z-588718-de077620` PASSED both systems, 40/40, without a
   rejoin. Kept files remained unchanged; no fold or ledger entry was added;
   teardown was clean. Preserve both verdicts, the native backup and restored
   instance. Intermittent first-boot firmware stalls persist despite cleared
   HDDP state and are not claimed fixed; the passing run used its recorded
   bounded Windows cold-boot retry. `rehearsal-auto-ws1` predates
   SRV-first and cannot prove discovery after a DC rename.
4. **The keeper (aiq TASK-21) is blocked solely on owner-terminal passwords**
   — DR prerequisite satisfied, keeper absent and convergence dry run checked
   again about 16:49 UTC. The first owner action is
   `make homelab-factory-persistent-converge PERSISTENT_DC=keeper APPLY=1`.
   Its owner decisions are
   taken (the Keeper row under Agreed decisions). Follow the exact
   [owner-terminal sequence](FACTORY-MAKE-TARGETS.md#owner-terminal-keeper-sequence-task-21)
   once the live lab lane is free: converge, policy, accounts, probe, durable
   workstation flow and keep-verify, then the first keeper native backup. It
   repeats the durable flow, which passed live end to end 2026-09-30 under
   agent custody on `rehearsal-auto` / `rehearsal-auto-ws1` (run ids in
   [DURABLE-WORKSTATION-FLOW.md](DURABLE-WORKSTATION-FLOW.md), "Live record"),
   under owner custody with the owner's real passwords. On the owner-custody
   `rehearsal`, `rehearsal-ws1` stays at stage `arch-install` (its arch-join
   stopped on a mistyped temporary password; the reset is
   `homelab-factory-persistent-account-password`). Separately, the
   Controller's TFTP and HTTP PXE services are enabled units since `dfbcce7`
   (unit-tested only; convergence exits 2 unless both are enabled and
   active); `rehearsal` was converged before that, so it needs an owner-run
   `make homelab-factory-persistent-converge APPLY=1 PERSISTENT_DC=rehearsal RECONVERGE=1`
   before a reboot-survival check of those units.
5. **Durable directory accounts** — the serial-console path RAN LIVE
   2026-09-25 on the throwaway instance `rehearsal`: converge plus the four
   durable accounts (`b2e8fed`). `make homelab-factory-persistent-accounts-plan
   PERSISTENT_DC=<name>` and then `make homelab-factory-persistent-accounts
   APPLY=1 PERSISTENT_DC=<name>` (`73dbd2b`) stage them, because host-side
   Ansible cannot reach a simulated instance;
   `make homelab-bootstrap-controller INVENTORY=<private inventory> APPLY=1`
   remains the path for a Controller reachable over SSH and has NOT RUN. Since
   `0e588db` both refuse unless `homelab/instance/identity/principals.json`
   names all three directory roles. `-up` remains unrun under owner custody;
   agent-custody creation passed 2026-09-30. Reconvergence and destruction
   passed in the 2026-10-01 directory restore drill.
6. **Gate 13 (aiq TASK-7) local pass is complete.** The accepted repeat,
   current procedures and all sixteen documentation topics are reconciled.
   Final command, privacy/link, build/verify and Chromium mobile/desktop
   checks passed. Publishing still requires push authority and exact-commit
   deployment proof; neither is claimed here.

Superseded 2026-08-17, kept so it is not re-derived: this list previously opened
with gate 8's serial routing and gate 9's storage checks. Both are done — gate 8
passed live 2026-08-14 and gate 9 closed inside it — and the gate-8 diagnosis
recorded here was wrong. The boundary did route the console to ttyS0; what the
pristine firmware variables lacked was any boot option pointing at
systemd-boot, so nothing rendered. See [HANDOFF.md](HANDOFF.md) §3. Also
superseded the same day: item 3 read "write the aggregate repeat driver …; it is
reserved and not implemented". It is implemented. Superseded 2026-09-24: item 1
read "Reinstall the canonical Controller image … It has NOT RUN"; the image was
installed that day through that target. The durable-accounts item (then 4, now
6) routed them through `homelab-bootstrap-controller` alone, which cannot reach
a simulated persistent instance. Items 2 and 3 are new. Superseded
2026-09-30: item 6 read "NOT RUN and unproven" although the serial-console path
ran 2026-09-25; item 3 read "it does not exist" before the flow was approved;
items 4 and 5 predate ADR 0080 and `b84bc86`. Superseded later on 2026-09-30:
item 3 read "the durable workstation flow — being built … its first live run
is the owner-run probe"; it passed live end to end, so item 3 is now the
keeper.
Superseded 2026-10-01: item 2 was the real-name rehearsal of gates 5–8, done
2026-09-24/25 (`HANDOFF.md` §7 item 5); the keeper (then 3) waited on three
owner decisions, taken 2026-09-30; items 4 and 5 read gate 11's two hooks and
gate 12 as NOT RUN; durable accounts and gate 13 were items 6 and 7.

Do not add an aggregate target that reports success for a gate whose live proof
is absent. Follow
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
