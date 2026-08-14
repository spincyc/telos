# Workstation-factory handoff (for a fresh agent)

**Last updated:** 2026-08-14 (documentation reconciliation against on-disk
evidence; gate 6 was proved 2026-08-13).
**Read this first, then `homelab/WORKSTATION-FACTORY-STATE.md`** (the canonical
per-gate state) and `homelab/FACTORY-MAKE-TARGETS.md` (the Make contract).

---

## 1. Where the factory is right now

Goal: mint an isolated dual-boot Windows + Arch workstation and prove all
acceptance gates (1–14), loopback-only, no plaintext secrets, no unattended
install path. Gates 1–14 tracked in `WORKSTATION-FACTORY-STATE.md`.

| Gate | What | Status |
|---|---|---|
| 1 Media intake | — | **pass** |
| 2 Immutable PXE releases | — | **pass** |
| 3 Controller convergence | — | **pass** |
| 4 PXE authority boundary | — | **pass** (2026-08-12, real arch run) |
| 5 Windows-first install | — | **PASS** (bundle `homelab/var/factory/windows-installs/run-20260810T145421Z-5b457e50e20b`) |
| 6 Windows join and login | domain identity + recovery | **PASS — 24/24 contracted checks, proven 2026-08-13** (one deferral: `disable-reenable`; see §2) |
| 7 Arch-second install | — | **pass** (bundle `arch-installs/run-20260811T141601Z-6941005247e8`) |
| 8 Arch join and login | SSSD identity lifecycle | **NOT RUN** — 19 of 21 checks pass live 2026-08-14; the 2 storage checks remain (see §3) |
| 9 Optional storage failure | Windows half live-proven; Arch half waits on gate 8 | **PASS (Windows) / NOT RUN (Arch)** — `optional-storage-offline` and `optional-storage-access-denied` are among the 24 passed checks in the 2026-08-13 gate-6 evidence; the three `arch-smb-*` checks ride inside a gate-8 run. No standalone target by design. (see state doc) |
| 10 Dual-boot acceptance | 8 checks; Windows BOOT observed, login NOT driven | **PASS with two deferrals** (`homelab/var/factory/dualboot-acceptance/run-20260811T170510Z-a619bcb1f028`) — judge reports `deferred: ["windows-login-driven", "arch-authenticated-login"]` and `windows_login_proven: false` |
| 11 Lifecycle recovery | 3 loopback-provable, 5 need a live guest boot | **PARTIAL** — judge verdict is `partial` by construction whenever any scenario defers; retained artifact `homelab/var/factory/recovery/run-20260814T120300Z-3b3169f9f15f/` (pass 3 / not_run 5 / fail 0) |
| 12 Repeatability (twice-through) | — | **NOT RUN** — needs gates 8 and 9 live |
| 13 Documentation | — | guides added (`homelab/docs/`), **already public on `origin/main`**; "unpublished" = not wired into the generated site (they carry the lab address the site leak scanner rejects) |
| 14 External integration | physical / UniFi / ThinkPad | **HARD-BLOCKED on explicit owner authorization** — do not attempt |

Owner directive in force: *proceed through gates 6–13 without stopping for
per-gate approval; stop only at genuine blocks or gate 14.* Gate 14 needs a
separate explicit go-ahead.

---

## 2. Gate 6 (DONE) — what was proven and how

**Result:** attempt `20260813T191519Z-28a9f6ee07f5` on bundle
`homelab/var/factory/windows-installs/run-20260813T171405Z-6729c809fcab` ran
24/24 and published `.../acceptance-evidence.jsonl`;
`make homelab-windows-identity-judge WINDOWS_IDENTITY_EVIDENCE=<that jsonl>`
prints verbatim:
```json
{"checks": 24, "deferred": ["disable-reenable"], "external_access": false,
 "out_of_scope": ["firmware-activation", "live-microsoft-update"],
 "result": "pass", "schema_version": 1}
```
So the honest framing is "24 of 24 CONTRACTED checks pass", not "all checks":
account **disable/re-enable is deferred** and unproven, and firmware activation
plus live Microsoft Update are out of scope by decision (unreproducible in
QEMU). This is the first-ever successful gate-6 publish. `AIQ TASK-2` is marked
**done**.

### The hard problem (secure channel) and the fix — READ if touching gate 6
During the fault phases the harness SIGSTOP/SIGCONTs the controller (the
disposable Samba AD DC). Netlogon drops the **machine secure channel**, and the
acceptance operator runs **UAC-filtered non-elevated** (deliberate — the
credential proofs test the deny-only Administrators SID), so it CANNOT actively
reset the channel. A read-only `Test-ComputerSecureChannel` never re-establishes
it, and a scheduled-task/EncodedCommand UAC-bypass was **rejected as
inappropriate** (defense-evasion; my own tool classifier flagged it — do not
reintroduce it).

Owner-approved fix = **reboot-and-reverify**, implemented across
`windows_identity_faults.py`, `windows_identity_orchestrator.py`,
`windows_identity_adapter.py`, `windows_identity_run.py`:
- `NativeProcessBoundary.reboot_and_await_readiness(trigger)` — captures a switch
  cursor, fires a **clean** guest reboot, waits for boot.
- Reboot trigger = `adapter.reboot_guest()` → `launch_guest("powershell
  -NoProfile -Command \"Start-Sleep -Seconds 8; Restart-Computer -Force\"")`.
  Gotchas learned the hard way: (a) a QMP `system_reset` is an UNCLEAN reset →
  Windows post-crash recovery screen → never rejoins the network; use a clean
  guest restart. (b) the public-command launcher **only accepts a PowerShell
  invocation** (`shutdown /r` is rejected). (c) the operator holds
  `SeShutdownPrivilege` even non-elevated, so Restart-Computer works.
- **Boot detection = the reboot's fresh DHCP DISCOVER**, NOT a new switch port: a
  guest reboot does NOT drop the host↔switch socket (the port persists across
  reboots), so waiting for a new `port-connected` hangs. Wait for
  `wait_for_plain_dhcp_transaction` on the retained `windows_switch_generation`.
- Re-login = `adapter.reestablish_operator_session()` →
  `_reauthenticate(..., establish_session_only=True)`: sign-in nav + password
  submit + desktop prove, **skipping the DC-side controller-auth arm** (it can't
  drive the just-frozen DC console → `reboot-reauth-controller-auth-arm`) **and
  the guest post-submit diagnostic**. The subsequent fault checks re-prove
  connected domain logins themselves, so those proofs are redundant here.
- **TWO reboots** are wired — one before `windows-secure-channel-restored` and
  one before `windows-services-restored` — because the fault sequence takes the
  controller offline a SECOND time (`ad-dns-offline`,
  `combined-dependencies-offline`) after the first reboot.

Also fixed this session: update-policy check needed the install to set
`HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU NoAutoUpdate=0` (added
to the unattend FirstLogonCommands in `windows_install_contract.py`); GUI
references made version-portable (`windows_identity_reference.py`); the
`synthetic_directory` proof relocated to windows-standard-online; and the whole
credential-proof mechanism was rebuilt earlier (token LogonUser, Kerberos via
LSA, raw-token-groups, live-tolerant secret scanner).

### Cheap-iteration technique (CRITICAL — how to debug gate 6 without 68-min re-installs)
A gate-5 install (~68 min) yields ONE gate-6 attempt because gate-6 destroys the
one-use `<bundle>/publication.iso` (the recovery credential ISO) at run start.
**Trick:** right after an install, `cp -p <bundle>/publication.iso <stash>/`;
before each `identity-prepare`, copy it back (`chmod 0600`). Each
`identity-prepare` builds a fresh overlay from the pristine base disk, so the
credential still matches. This turns 68-min-per-attempt into ~40-min
identity-only cycles. **Delete the stash when done — it holds a one-use
credential** (I deleted `pub-stash`/`pub-stash2` at session end).

The gate-6 flow (each step APPLY=1, controller state = `build/homelab/vm/bootstrap-dc`):
```
make homelab-windows-install-prepare APPLY=1                      # → bundle path
make homelab-windows-install-run APPLY=1 WINDOWS_RUN=<bundle> FACTORY_DURATION=7200
make homelab-windows-identity-prepare APPLY=1 WINDOWS_RUN=<bundle> FACTORY_CONTROLLER_STATE=build/homelab/vm/bootstrap-dc
make homelab-windows-identity-run APPLY=1 WINDOWS_IDENTITY_ATTEMPT=<attempt> FACTORY_CONTROLLER_STATE=build/homelab/vm/bootstrap-dc
make homelab-windows-identity-judge WINDOWS_IDENTITY_EVIDENCE=<attempt>/acceptance-evidence.jsonl
```
An identity run takes ~45–50 min (two reboots).

**Three names, one stream — all three are real; do not "correct" one into
another:**

| Name | What it is |
|---|---|
| `<attempt>/acceptance-evidence.jsonl` | The file gate 6 WRITES: 24 records, one per contracted check. Verified `wc -l` = 24. |
| `--windows-evidence` / `WINDOWS_IDENTITY_EVIDENCE=` | The CLI flag and Make variable that POINT AT that file, both for the judge and for `homelab-arch-identity-prepare`. |
| `<gate-8 bundle>/windows-evidence.jsonl` | A **7-record subset** that `homelab-arch-identity-prepare` copies into the gate-8 bundle — only the `windows-*` checks the gate-8 contract requires: `windows-joined`, `windows-standard-online`, `windows-daily-admin`, `windows-cached-login`, `windows-uncached-denied`, `windows-local-rescue`, `windows-secure-channel-restored`. |

Progress lands in the
attempt's `acceptance-progress.json` (`passed_count`, `next_check`,
`failure_detail`). The progressive sanitizer collapses errors to
`scoped-acceptance.acceptance/FaultPhaseError`; the real coordinate is in
`failure_detail` (stashed via `collector.note_failure_detail`).

---

## 3. Gate 8 (NEXT LANE) — precise state and next step

`make homelab-arch-identity-{prepare,run,judge}`. Prepare is wired and works.
Three live runs (one 2026-08-13, two 2026-08-14) took this from "no menu at all"
to a fully proven boot chain. The best run is
`homelab/var/factory/arch-identity/run-20260814T120114Z-5fafdb4897ff`:
`menu_seen`, `entry_selected`, `entry_committed`, `handoff_seen`, `getty_seen`
all true, `menu_retries: 0`.

```
make homelab-arch-identity-prepare APPLY=1 \
  ARCH_RUN=homelab/var/factory/arch-installs/run-20260811T170109Z-7ceb936e2710 \
  WINDOWS_IDENTITY_EVIDENCE=<the gate-6 acceptance-evidence.jsonl>
make homelab-arch-identity-run APPLY=1 ARCH_IDENTITY_BUNDLE=<bundle> FACTORY_DURATION=3600
```
A gate-8 run fails fast (~6 min on a boot failure, ~7 to the login), so
iterating the boundary against an existing gate-7 disk is cheap. Each attempt is
a fresh `identity-prepare`, which builds a new overlay — never a re-install.

### What was fixed, and why the previously recorded diagnosis was wrong
Do not re-derive these. Both are committed with their evidence.

1. **Pristine firmware variables, not serial routing.** The old note said the
   boundary "does not route the UEFI console to ttyS0". It does: the failing
   73-byte serial log is byte-identical to the first 73 bytes of the *passing*
   gate-10 boot-1 log — that is OVMF's own serial terminal init. What pristine
   variables lack is any boot option pointing at
   `\EFI\systemd\systemd-bootx64.efi`, so ESP auto-discovery never started
   systemd-boot and there was nothing to render. `arch_identity_prepare` now
   defaults to the gate-7 bundle's own `OVMF_VARS.fd`, which carries the
   `Linux Boot Manager` entry `bootctl` authored at install — the same pairing
   gate 10 requires as `VARS_SOURCE_GATE7`. `--ovmf-vars` still overrides it.
2. **A digit key selects; only Enter boots.** With the menu rendering, the digit
   moved the highlight onto Arch and stopped the five-second countdown, then the
   guest sat there until the harness gave up. `drive_boot_menu` now commits with
   `\r`, reading the highlight back from the raw inverse-video render rather
   than assuming the digit landed. Gate 10 had already recorded this lesson at
   `dualboot_acceptance.py:141`; the gate-8 lane claimed to mirror that lane
   while sending the digit alone.
3. **The boot was also nondeterministic** — one run rendered the menu and the
   next, with byte-identical vars and the same backing disk, rendered nothing.
   Fixed by aligning the argv with the gate-10 boundary: no `bootindex=1` (its
   fw_cfg boot order competes with the authored NVRAM entries), a `VGA` device
   (without one `-nodefaults` leaves no display and every QMP screendump fails,
   which is why the early failures left no frame evidence), and 8192 MiB. The
   run now also retains its exact `qemu-command.json` beside the bundle, so the
   next flake is diagnosed from what it booted rather than reconstructed.

Use `tools/factory-bundle-firmware-provenance <bundle> ...` to compare what any
two bundles actually booted — that pairing is what settled (1).

### Live progress, 2026-08-14 (four runs, each cheap)
Every fix below is committed with its evidence. The boot chain and the in-run
join are PROVEN; the operator login is the one remaining blocker.

| Run | Bundle | Outcome |
|---|---|---|
| 1 | `arch-identity/run-20260814T113757Z-11326c51f576` | menu rendered for the first time (gate-7 installed NVRAM), Arch highlighted, never booted |
| 2 | `arch-identity/run-20260814T115234Z-f792faf46d6e` | no menu again with byte-identical vars: the boot was nondeterministic |
| 3 | `arch-identity/run-20260814T120114Z-5fafdb4897ff` | argv aligned with gate 10 -> menu, Enter-commit, EFI handoff, ttyS0 getty, `menu_retries: 0`; login refused |
| 4 | `arch-identity/run-20260814T124858Z-0ac6c279561b` | in-run join proven: `join_media_{built,attached,consumed,destroyed}`, `join_verified`, `join_principal_destroyed` all true; login still refused |

Run 4 used a fresh gate-7 install,
`arch-installs/run-20260814T124513Z-e0c32ed98202` (`observed`,
Windows preserved, `TELOS ARCH NVRAM ENTRIES AUTHORED`, join media consumed and
destroyed), because the one-shot join unit only reaches a disk through a gate-7
install.

| 5 | `arch-identity/run-20260814T131951Z-83e2612decf0` | first run with the readiness gate: it fired correctly, reporting a readiness failure and NOT a refused login |
| 6 | (aborted) | controller principal staging failed; launched from a tree a lane was mid-edit on |
| 7 | `arch-identity/run-20260814T135756Z-c72cff0ac44f` | boot nondeterminism: no menu, 146-byte transcript, no `BdsDxe:` line at all |
| 8 | `arch-identity/run-20260814T140142Z-587985cdf83f` | boot + join proven again; readiness gate fired with full diagnostics |

**Run 8's diagnostics settled the identity question.** The gate prints thirteen
secret-free fields on failure; grep the transcript for
`TELOS ARCH DOMAIN DIAGNOSTIC`. They show the directory is **completely
correct**: `net ads search`, using the host keytab the in-run join wrote,
returns `operator` with `uidNumber 10001`, `gidNumber 10513`, `loginShell` and
`unixHomeDirectory`, and `Domain Users` with the matching `gidNumber 10513`. The
machine principal is in the keytab, LDAP on 389 answers, and the DC name
resolves. So Kerberos, LDAP, DNS-for-Samba, POSIX attributes and the staged
principal are all proven good.

What fails is inside SSSD alone: `domain-status` reports `Offline` and every
lookup logs `SSSD is offline`. The target is therefore SSSD's ability to reach a
DC, not identity, not the POSIX attributes, not the keytab, and not the Global
Catalog.

**Correction, recorded so it is not re-derived.** A first reading of that field
concluded SSSD had *discovered no DC at all*. That was wrong -- an artifact of
the diagnostic's own 200-column cap, which truncated the line at exactly
`Discovered AD Domain Controller servers: `. The cap is now 512 and the field
prints in full. What IS established: DNS works from the workstation (the join
unit's bounded `getent hosts <realm>` loop broke on its first iteration, and
nothing writes `/etc/hosts`), and DHCP hands the workstation the controller as
its only nameserver.

The asymmetry -- `net ads` reached the DC while SSSD did not -- is now partly
explained. Samba's DC location falls back to a NetBIOS broadcast, which this
flat hub floods and the DC answers, followed by a CLDAP netlogon ping; SSSD's AD
provider can locate a DC *only* by SRV. And the two query different records:
`net lookup ldap` asks `_ldap._tcp.dc._msdcs.<domain>` while SSSD asks
`_ldap._tcp.<domain>`. So `net ads` can succeed with no SRV record at all.
**What is still not settled** is whether `_ldap._tcp.<domain>` answers -- the
only SRV check in the repository queried loopback on the DC itself. The fix is
therefore deterministic rather than causal, and says so in the code.

**Also open: the boot is nondeterministic.** Two of eight runs (2 and 7) started
no UEFI boot option at all -- console init and then nothing, no `BdsDxe:` line
-- with byte-identical firmware variables and the same disk as runs that
succeeded. All three of today's gate-7 bundles do carry the authored
`Linux Boot Manager` entry, so this is not a missing entry. Aligning the argv
with gate 10 made it much rarer but did not root-cause it. A re-prepare against
the same gate-7 disk is cheap (~7 min, no reinstall), so retry on this
signature -- but it needs a real fix, and the VGA device added for frame
evidence is still not screenshotted by this lane.

| 9 | `arch-identity/run-20260814T144603Z-2ccf8c3ce931` | `ad_server` worked -- SSSD discovered and selected the DC, SRV answered -- but still Offline: the fault was the authenticated bind |
| 10 | `arch-identity/run-20260814T152400Z-ce7b701254a3` | **DOMAIN LOGIN WORKS.** `domain_online_observed`, `getty_seen`, `login_completed` all true; a home directory was created and an operator shell appeared. Only `sudo -S` elevation fails |

**The keytab was the bind failure.** `net ads join` at install time wrote
`/etc/krb5.keytab` against the domain of *that* run. The boot-time re-join
against this run's freshly provisioned domain left the old keys in place with
the same KVNO, so SSSD's `ldap_child` could select a dead key and the backend
went offline with the server correctly identified. Removing the keytab
immediately before the boot-time join fixed it -- the same reasoning the join
unit already applied to the SSSD cache. Note `net ads` kept working throughout
because it authenticates from `secrets.tdb`, which the join *does* rewrite.

A hypothesis worth recording as refuted, because it is easy to re-derive: the
keytab holds `HOST/TELOS-WS1.ad.factory.test` with the host part uppercased while
`ad_hostname` is the lowercase DNS name, which looks like a case mismatch. It is
not. Reading the shipped sssd binary, `ldap_child` selects the bind principal
from the keytab itself over a fixed pattern list whose matching pattern
truncates the hostname at the first dot, uppercases it and appends a dollar --
so the bind uses the machine account and `ad_hostname`'s case cannot affect it.
Pinning `ldap_sasl_authid` would have pinned the wrong thing while looking like
a fix.

| 11 | `arch-identity/run-20260814T155301Z-4b21f9334459` | **ROOT SHELL.** `sudo_elevated`, `sudo_uid: 0`; a boot stall recurred and the new retry recovered it. Only the local-rescue password remains |

**The sudo failure was a race on sudo's stdin.** The elevation gated on a marker
the shell printed *before* sudo ran, so the harness wrote the credential and then
typed the next command milliseconds later -- and that line became sudo's
password. The getty login and the rescue-password paths both wait for the prompt
of the program that will read them; the elevation now does too, via a
token-scoped `-p` prompt. It stays a genuine passworded proof: `-k` still
invalidates the timestamp and the sudoers rule is unchanged.

**The stall retry earned its keep on its first outing, and narrowed the
mechanism.** Run 11 hit the no-boot signature (`transcript_bytes: 146`, same as
run 7), the power-cycle recovered it, and the retained evidence answered the open
question: QMP reported `status: running` with `reason: timed-out`. The vCPU was
*running*, which kills the stalled-device-emulation and host-I/O candidates and
leaves a firmware spin in the first ESP read as the surviving hypothesis. A 3 MB
framebuffer capture and the QMP event stream are retained beside it.

| 12 | `arch-identity/run-20260814T161054Z-7ed00ab7472a` | **THE PROBES RAN FOR THE FIRST TIME: 18 of 21 checks pass.** All boot-phase facts true. Three fail: `arch-identity-restored`, `arch-storage-attached`, `arch-storage-denied` |

**Both remaining boot-phase failures were the same class of bug**, worth stating
once because it bit twice in a row. The elevation and the rescue password each
gated their write on a marker the *shell* printed before the program that would
read it existed, so the next thing the harness typed became the input. The getty
login always did it correctly -- wait for the prompt of the program that reads.
Both now do. The elevation had a second defect: its verdict pattern matched
sudo's own lecture (a read chunk ending on the `#` of `#1)`), so the harness
believed it already had root; every verdict is now a token-scoped marker or the
reader's own re-prompt.

**What 18 passing checks means.** The hard ones are proven live on both operating
systems: domain join, standard and administrative logins, administrator
separation, controller-offline cached login, uncached denial, local rescue,
controller restore, and the Windows secure channel. `arch-storage-absent-login`
passes too, so the absent-storage path works.

| 13 | `arch-identity/run-20260814T164555Z-2519fe2d8fec` | **19 of 21.** `arch-identity-restored` now passes. Only the two `arch-storage-*` checks remain |

`arch-identity-restored` failed on timing, not identity: its Windows twin
recovers because Netlogon is told to re-establish, while SSSD goes offline on a
failed request and returns on its own retry schedule, which can outlast a bounded
probe. Giving that recovery room fixed it without weakening the proof.

| 14 | `arch-identity/run-20260814T165752Z-bcb0e1d3fcb3` | 19 of 21. **Kerberos for the storage mount is now solved**; the fault moved to the server's share resolution |

**The storage mount's Kerberos is done.** Run 14's own diagnostics show the user
holding a TGT, the KDC issuing `cifs/unas.ad.factory.test` at `kvno = 1`, the
upcall helper and its `request-key` config in place, the name resolving and SSSD
Online. The earlier `ENOKEY` is gone. What remains is `mount error(2)` --
`ENOENT`, which for an authenticated CIFS session is the server answering *bad
network name*: `smbd` does not see a share called `operator`. Samba resolves
`//server/<name>` through its `[homes]` section only when it can look `<name>` up
as a user *on the server*, and on an AD DC the domain users are not local
accounts, so that depends on the controller's own name-service reaching the
directory. That is the layer to fix, and it is controller-side -- which is cheap,
because the controller role runs fresh on every gate-8 run.

**The open blocker, precisely.** The two `arch-storage-*` checks -- gate 9's Arch
half, and the last thing gate 9 is waiting on. Kerberos is solved (above); the
server does not resolve the per-user share name for a domain user.
`arch-storage-denied` mounts the owner's own share first as its fail-closed
guard, so both move together once the share resolves.

### How the design premise was wrong (fixed in 73d7f32)
Gate 8 asserts its gate-7 disk *arrives joined* and only verifies with
`net ads testjoin`. But **every gate-8 run provisions a brand-new domain.** The
canonical `bootstrap-dc` image carries no provisioned AD, and the controller
role runs `samba-tool domain provision` whenever `sam.ldb` is absent
(`arch_install_run.py:1240-1243` already records this lesson). New domain SID
and krbtgt, empty SAM — so the `TELOS-WS1$` machine account the gate-7 install
created never exists in this run's directory, and `controller_principals.py`
stages only the three user roles, never a machine account.

With `id_provider = ad` and GSSAPI host-keytab binding, SSSD cannot bind to that
directory, marks the domain offline, and offline auth needs a cached credential
that cannot exist (fresh disk, per-run generated password). So `operator` is
refused deterministically — `LOGIN_REFUSED_FAILURE` — and no delay, backoff or
retry count can change it. `net ads testjoin` would fail for the same reason, so
`arch-joined` was never reachable in this design either.

**The Windows lane does not have this bug because it joins in-run.**
`windows_identity_orchestrator._run_acceptance_checks` records
`controller-ready`, calls `_execute_join(...)`, and only then records
`windows-joined`; `_execute_join` stages a one-use `tj-<hex>` join principal on
the freshly provisioned DC, builds a `TELOS_JOIN` ISO, hot-attaches it, and
drives the join in-guest. Gate 5 does not join at all.

**How it was fixed** (`73d7f32`, proven live in run 4): the Arch lane joins
in-run, reusing the one-use join media gates 5-7 already build
(`controller_join_material.py`, `arch_install_run.run_join_install`,
`ArchJoinMedia`). It is driven by a one-shot boot unit ordered
`Before=sssd.service systemd-user-sessions.service`, because **there is no
pre-login shell on the disk**: `local-rescue` ships a
disabled password and gate-7's `loader.conf` sets `editor no`, so neither a
console login nor a boot-cmdline edit can obtain root before the getty. Since
`serial-getty@ttyS0` is `After=systemd-user-sessions.service`, that ordering
makes the login prompt appear only after the join completed — no readiness
polling needed.

Each installer change requires **one fresh gate-7 install**, because the unit
only reaches a disk through an install:
```
# Omit WINDOWS_RUN: the default --windows-disk is the standalone base the last
# passing gate-7 run overlaid. Note WINDOWS_RUN is forwarded as --windows-disk,
# i.e. a path to a windows.qcow2, not a bundle directory.
make homelab-arch-install-prepare APPLY=1
make homelab-arch-install-run APPLY=1 ARCH_RUN=<prepared bundle> FACTORY_DURATION=1800
# ~4.5 min. The Makefile default duration of 120 is too tight.
```
Rejected alternatives, recorded so they are not retried: pre-seeding the machine
account on the DC (the machine password lives only in the guest's `secrets.tdb`,
unknowable host-side), and joining from a post-login shell (circular — the login
is what the join enables).

**Also latent, fix alongside:** `arch-local-rescue` must fail regardless of the
join, because `check_arch_local_rescue` requires `passwd -S local-rescue` to
report `P` and nothing in the run ever sets that password. And
`LOGIN_ATTEMPTS = 3` exactly equals `pam_faillock`'s default `deny=3`, leaving
no headroom for a single spurious refusal.

---

## 4. Operating rules / security constraints (MUST follow)

- Loopback-only QEMU until explicit authorization; no host networking, UniFi, or
  physical disks (gate 14). No unattended install path.
- **No plaintext secrets** in Git, logs, docs, PXE roots, answer files, or
  command output. Real hostnames/IPs/MACs/serials live ONLY in the gitignored
  `homelab/instance/` overlay.
- Never run `sudo` unasked — hand the operator the exact argv.
- One-use recovery `publication.iso` must be destroyed by end of acceptance; do
  not leave copies around (see the cheap-iteration note).
- Do NOT reintroduce UAC-bypass techniques (scheduled-task/EncodedCommand
  elevation) — rejected this session.
- Put temp files in the session scratchpad, not the attempt dir.
- End commits with a `Co-Authored-By:` trailer naming **the model actually
  acting**, e.g. `Co-Authored-By: <acting model name> <noreply@anthropic.com>`.
  Do not copy a version from an old commit: the history already carries
  `Claude Opus 4.8`, `Claude Fable 5`, and `Claude Opus 5 (1M context)`, and
  three recent commits carry none. Use your own identity.

## 5. Gotchas

- **Install flakiness:** the gate-5 Windows install occasionally hits a
  PXE→WinPE→reboot→PXE loop (NVMe never becomes bootable; a 2nd `wimboot v2.9.0`
  in `<bundle>/evidence/workstation-serial.log` is the signature). It killed one
  120-min attempt. A healthy install has exactly one `wimboot` and prints
  `TELOS WINDOWS NATIVE READY` in ~69 min. Retry on loop; watch the serial log to
  abort early rather than burn the full duration.
- **~~Pre-existing test failure~~ — FIXED 2026-08-14 (`e9ec869`).**
  `test_windows_run_dialog_calibration.test_guest_mismatch_fails_before_start`
  ("private publication must be a regular file") used to fail on HEAD; the stale
  guest-mismatch fixture was repaired and
  `PYTHONPATH=. python3 -m unittest homelab.tests.test_windows_run_dialog_calibration`
  now reports OK. Do not re-report it as a known failure.
- **Long-run monitoring:** identity/install runs are long; launch them
  backgrounded and attach a harness-tracked waiter (a bounded loop that greps a
  driver log for a DONE marker) so you get a completion notification. `Date.now`
  etc. work in bash but not in workflow scripts.
- **Disk space (measured 2026-08-14):** this is much bigger than it looks. A
  single full Windows install bundle is ~17–29 GB, but the tree AGGREGATES:
  `homelab/var` is **532 GB**, `homelab/var/factory` **496 GB**, of which
  `windows-installs` is **399 GB** and `arch-installs` **90 GB**. One bundle
  dominates: the historic identity input
  `windows-installs/run-20260728T114233Z-afecdf7cc9d0` is **241 GB** on its own
  (it holds every early identity attempt). Host: 799 GB used of 1.5 TB, 627 GB
  free. Clean spent bundles (publication consumed → orphaned disk) if space is
  tight, and check `du -sh homelab/var/factory/*` before starting a long run.
- **One-use credential media: all destroyed.** The old `run-20260728T*` bundles
  used to carry orphaned `publication.iso` files holding a plaintext
  `install-password.txt`. All **29** were DESTROYED 2026-08-14: they were
  orphaned (no `identity/`, no `result.json` — so no acceptance had ever
  consumed them), and the standing rule is that a one-use credential is
  destroyed rather than parked. Current state verified:
  `find /home/ksh/git/claude/telos -name 'publication*.iso' | wc -l` → **0**, and
  `find … -name 'install-password*'` → nothing. **No stray one-use credential
  remains in the tree.** If you create a publication stash for cheap iteration
  (see §2), you own deleting it.

## 6. Key files touched this session (all committed)
- `homelab/vm/windows_control/Invoke-TelosIdentityProbe.ps1` — read-only
  secure-channel probe (bounded re-verify only).
- `homelab/vm/windows_identity_faults.py` — two `driver.reboot()` calls;
  `FaultPhaseOperations.reboot_and_reauthenticate`.
- `homelab/vm/windows_identity_orchestrator.py` — `AcceptanceCallbacks
  .{reboot_guest,reestablish_operator_session}`; the reboot op with diagnostics.
- `homelab/vm/windows_identity_adapter.py` — `reboot_guest`,
  `reestablish_operator_session`, `_reauthenticate(establish_session_only=)`.
- `homelab/vm/windows_identity_run.py` — `reboot_and_await_readiness` (QMP-less
  clean reboot + DHCP boot-wait).
- `homelab/vm/windows_install_contract.py` — WindowsUpdate AU policy in unattend.
- `homelab/vm/windows_identity_reference.py` — version-portable references.
- Memory: `.claude/projects/-home-ksh-git-claude-telos/memory/` — see
  `gate6-publication-single-use.md`.

## 7. First moves for the fresh agent
1. `git log --oneline -20`, read `WORKSTATION-FACTORY-STATE.md` gate table.
2. Re-lease the AIQ work if continuing (a new task, since TASK-2 is done): `aiq
   status` / `aiq dequeue`.
3. Gate 8: diff `arch_identity_run.py` vs `dualboot_acceptance.py` on
   OVMF/serial; get the systemd-boot menu onto ttyS0; iterate the arch-identity
   run (fails fast, cheap) against the 141601Z disk; do a fresh gate-7 install if
   the disk is stale.
4. Gate 9 needs no separate work — its three remaining Arch checks are graded
   inside a passing gate-8 run. Gate 11 needs the live guest-boot hook (not
   another loopback run). Gate 12 needs gates 8/9 live first. Gate 14 only with
   explicit owner go-ahead.
