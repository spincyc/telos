# Local workstation factory state

Document version: `20260810.013`

Status: active implementation

Last evidence/workstream review: 2026-08-10T16:45:00-05:00

Repository baseline reviewed: `b3ec83d`

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
| 5 | Windows-first install | OVMF workstation PXE-boots WinPE, selects the disk by stable serial, installs Windows 11 Pro to the approved layout, and reboots without ISO attachment. Destructive authorization is scoped to the disposable disk. | pass 2026-08-10: bundle `run-20260810T145421Z-5b457e50e20b` records `observed`/`native-windows-clean-shutdown`, exactly one PXE firmware boot, release `20260727.005`, private publication destroyed; serial log shows WinPE handoff, two native Windows Boot Manager boots, `TELOS WINDOWS NATIVE READY`, Edition Professional |
| 6 | Windows join and login | Join the synthetic domain; prove secure channel, DNS SRV, time, named user login, named administrator elevation, `local-rescue`, reboot, cached offline login, update policy, and recovery path. | in progress: receipt plumbing fixed, real directory verdict now read; post-reboot operator interactive logon not completing (`no-logon-event` + `uncorrelated`) — see blockers |
| 7 | Arch-second install | PXE-boot Arch, preserve Windows partitions and recovery data, install into the approved allocation, join the same domain, and create independent UEFI entries with Windows default. | runner implemented `98ef086` (`homelab/vm/arch_install_{prepare,run}.py`, Windows-preserving, pure tests green); live install pending the fabric |
| 8 | Arch join and login | Prove SSSD identity, UID/GID stability, Kerberos time, named user and administrator behavior, reboot, cached offline login, automatic-update gate, rollback, and local rescue. | live harness + evidence producer implemented `68781ef` (`homelab/vm/arch_identity_run.py`, producer↔judge proven); live login pending gate 7's joined disk |
| 9 | Optional storage failure | Prove per-user SMB authorization when present and successful login with no delay or hard failure when the NAS is absent. Record UID/GID and timestamp measurements before reconsidering NFS. | pending |
| 10 | Dual-boot acceptance | From cold boot, select and log into both systems; verify Windows-default five-second policy, disk measurements, EFI recovery choices, and no cross-OS partition damage. | pending |
| 11 | Lifecycle recovery | Exercise controller restart/loss, PXE release rollback, failed install, broken boot, directory/DNS loss, update failure, workstation remint, and controller reconstruction from public inputs plus a synthetic private overlay. | pending |
| 12 | Repeatability | Destroy disposable state and repeat the entire factory at least twice from a clean local input set; compare manifests and explain any nondeterministic bytes. | verifier + comparator implemented `b3244e8` (`make homelab-factory-verify`, `homelab/vm/factory_verify.py`); live twice-through pending gates 6-10 |
| 13 | Documentation/publication | Human and operator guides match tested commands, contain no private data, pass links/site checks, and expose exact supported and unsupported states. | pending |
| 14 | External integration | Only after a new explicit authorization: read-only UniFi review, separately approved changes, physical attachment, then ThinkPad X13 Gen 6 Intel pilot. | blocked by design |

## Current blockers and cautions

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
- Nothing is published. `main` and `continue-windows-identity-acceptance` are
  reconciled at the same commit and carry every local result, including the
  reading-list line that previously existed only on `origin`. The remote still
  holds the pre-rewrite history, so the branches have diverged and publishing
  requires an authorized force-push; an ordinary push will be refused. Verify
  before pushing that no remote-only work has appeared since this reconciliation.
- A fourth attempt `20260730T190013Z-696c1fb718b5` failed differently and
  worse: after 11 minutes it raised a bare `WindowsIdentityRunError` with no
  check, operation, or diagnostic at all. It booted the Windows guest twice,
  logged two `peer-abandoned-before-authentication` switch events, produced no
  rotation evidence, and tore down completely. That is earlier than the first
  three attempts, which all reached the desktop, and it is before any
  controller-auth code runs, so the receipt-origin work is not implicated.
  Both questions it raised are now closed. The boot path lost its coordinates
  because both boot raises passed `diagnostic=None`; fixed. Controller-state
  drift was checked and disproven: `build/homelab/vm/bootstrap-dc` still dates
  from 2026-07-27 and the paired `windows.qcow2` from 2026-07-28, while each
  attempt writes only its own overlay, so four runs mutated neither. Do not
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
