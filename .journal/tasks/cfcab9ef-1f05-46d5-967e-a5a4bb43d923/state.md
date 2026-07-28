---
schema_version: 1
task_uuid: "cfcab9ef-1f05-46d5-967e-a5a4bb43d923"
title: "Implement Windows-first installation"
status: "active"
priority: "normal"
priority_reason: "Next factory gate after isolated PXE proof"
parent: null
discovered_by: null
hard_dependencies: ["c9c5d25a-3d94-4eaa-95b8-2cadbd44633c"]
soft_dependencies: []
related_to: ["e1135b56-26e9-4d97-946a-0284f5eb8c99"]
superseded_by: null
created_at: "2026-07-27T21:51:53Z"
updated_at: "2026-07-28T01:54:31Z"
---

# Goal

PXE-install Windows 11 Pro on a serial-authorized disposable UEFI/GPT disk,
with ephemeral answer/startup inputs, verified layout, native boot, and safe
secret teardown.

## Acceptance criteria

- Exact stable disk serial is structurally required and authorization is narrowly scoped.
- Planned ESP/MSR/Windows/recovery layout preserves reserved Arch space.
- Edition, locale, encryption exception, native UEFI boot, hibernation/Fast Startup, and NTFS shutdown are verified.
- Failures produce machine-readable, secret-free evidence.

## Scope and concurrency

Owns Windows installation workflow and disposable workstation disk. Serialize
all destructive guest-disk and shared factory-environment operations.

## Activation plan

Audit the existing answer-file, disk-authorization, and QEMU lifecycle
surfaces against the acceptance criteria. Implement the smallest missing
fail-closed controls, then perform an unattended install only on a freshly
created disposable disk with an exact pinned serial.

## Decisions

Private per-run Windows startup and answer files are authorized for disposable
QEMU acceptance only. They must use synthetic values, bind mutation to the
exact disk serial, remain outside Git and immutable releases, retain no
secrets, and be removed during teardown. Physical launch remains interactive
and uses user-supplied private values.

For disposable QEMU, the synthetic serial is enforced and recorded at the host
launcher because stock WinPE has no proven direct serial query. QEMU must
expose exactly one writable disk, and WinPE must independently recheck exactly
one eligible disk of the authorized capacity before setup and immediately
before partition mutation. Physical installation still uses the hardware
serial directly.

## Progress

The host authorization contract is implemented and tested. It binds the
selected release, standalone 256 GiB-or-larger qcow2, safe serial, exact sole
writable OS-disk QEMU exposure, layout record, and command digest. Private
runtime inputs have restrictive permissions, digest-only receipts,
known-secret evidence rejection, and success/failure teardown.

The user authorized pushing checkpoints and directed continuous progress.
`origin/main` now includes `dafb18a`; continue with private WinPE input
rendering and Windows-first partition application.

Private DiskPart, startup, and answer-file renderers are implemented. Recovery
uses an explicit absolute offset after an untouched Arch gap. Setup is pinned
to Pro, en-US, and the precreated Windows partition. The disk-count and
capacity boundary is checked twice before the sole destructive call. Next,
construct and verify the private WinPE overlay and complete install-source
publication.

The private wimboot injection set and complete install-source publication are
implemented. The disposable Controller verifies and checksums the private
overlay and sealed Windows tree, serves the overlay only on the isolated HTTP
endpoint, and exports the source through authenticated read-only SMB.
Readiness now includes SMB. Next, integrate this material with a persistent
NVMe Windows install lifecycle and native-boot evidence.

The persistent workstation QEMU boundary is implemented with fixed-serial
NVMe, 8 GiB RAM, PXE-first e1000e, copied OVMF state, private publication
media, and QMP. Existing topology callers remain virtio-only. Next, execute a
real private publication build, then integrate the bounded install and
native-disk reboot phases.

The guarded preparation command is implemented and dry-run verified. Apply
creates only new ignored private state and removes incomplete bundles on any
failure. The next boundary is a real preparation from the sealed source,
followed by the bounded Controller/workstation install lifecycle.

One complete private bundle has been prepared from the sealed source. The
bounded lifecycle launcher now validates the bundle and exact disk boundary,
boots the disposable Controller with the private publication attached, boots
the persistent workstation without installation media, re-audits both live
QEMU processes, captures secret-free evidence, and guarantees child teardown.
Focused tests and the real-bundle dry run pass. The next operation is the first
bounded loopback-only WinPE overlay observation.

The first bounded execution failed safely during Controller publication,
before the workstation launched. Samba's password-database command requires
its configuration file to exist, but the publisher created the file
afterward. All children and the disposable overlay were cleaned up; the fresh
workstation disk was never booted. Publication now creates the fail-closed
read-only configuration before adding the synthetic account. A newly prepared
bundle is required because completed private publication images are immutable.

The second bounded execution also failed before workstation launch: the
Controller base image intentionally masks `smb.service`. The private publisher
now explicitly unmasks only that service inside the disposable overlay before
enabling it. Controller publication also fails immediately when its bootstrap
returns to the shell without a readiness marker, instead of waiting for the
outer timeout. Cleanup again completed and the workstation disk was not
booted.

The third attempt was stopped by a runner-only false positive before the
bootstrap command executed: the new early-return detector mistook the initial
prompt that triggered command submission for a returned prompt. It now ignores
the triggering read and only evaluates later Controller output. A pipe-level
regression test proves the initial prompt followed by readiness succeeds.

The fourth attempt revealed that a generic trailing `#` also matches pacman's
hash-based progress bar. Prompt recognition now requires the Controller's
structured root-shell prompt. A regression test distinguishes package
progress from the actual prompt. The run again stopped during disposable
Controller publication before workstation launch.

The fifth attempt reached Controller readiness and started the workstation,
but the switch had already ended after its 20-second port-acceptance window
because publication necessarily precedes the workstation connection. The
workstation was terminated before firmware completed and its qcow2 remained
at the empty image allocation size. The Windows lifecycle now gives the switch
a 360-second connection window while retaining the existing default for other
callers.

The sixth attempt passed the private WinPE overlay gate: all three isolated
ports connected, DHCP/TFTP/HTTP handoff completed, the exact private files
were fetched, and wimboot reported injecting `install.bat` and
`winpeshl.ini`. It did not install Windows. The guest repeatedly returned to
PXE, with no Setup or DiskPart evidence and only negligible qcow2 allocation.
The next diagnostic boundary is bounded QMP screenshot capture during WinPE;
serial evidence cannot expose the Windows-side failure.

The workstation command now exposes only a local emulated VGA device in
addition to its existing QMP Unix socket. During the bounded observation the
runner captures a private mode-0600 PPM every ten seconds, enabling diagnosis
without host display or input integration. The next fresh bundle will use this
evidence to identify the WinPE reboot.

The first screenshot attempt stopped before guest boot because QEMU had not
created its Unix socket when the runner tried one immediate connection. QMP
attachment now retries only local readiness errors within a ten-second bound.
The evidence-once contract still requires a fresh bundle for the diagnostic
retry.

The diagnostic screenshots prove WinPE starts and invokes the injected command
shell, then the startup batch exits and WinPE reboots. The batch now displays
only non-secret phase names and its numeric fail-closed exit code, then pauses
on failure for bounded screenshot capture. Disk authorization, capacity
checks, and mutation ordering are unchanged.

The diagnostic run reported fail-closed code 20 at the first disk-count check.
The selected WinPE image lacks `findstr`; the optional parser utility failed,
so no disk was counted. DiskPart itself succeeded and no mutation occurred.
The parser now uses only `cmd.exe` built-ins to recognize en-US DiskPart rows,
while preserving the exact disk number, count, and capacity requirements.

The next run passed the first disk gate and failed with code 30 while mounting
the authenticated SMB source. No partition mutation occurred. The next
diagnostic explicitly distinguishes a missing injected password file with code
29 and prints only WinPE's isolated `ipconfig` state before the existing mount
attempt.

The next diagnostic reported code 29: wimboot's injected inputs are not at the
WinPE `X:\` root. The executing batch itself proves the injection directory is
available. All injected input references now resolve relative to `%~dp0`,
while generated scratch files remain on `X:\`. No disk mutation occurred.

The corrected input path exposed a valid WinPE address and gateway, followed
by SMB error 53. The next publication gate now requires an exact TCP listener
at `10.1.31.2:445`, not merely an active service. WinPE also pings the isolated
Controller before SMB and assigns reachability failure code 28. The disk
remained untouched.

The listener-qualified run proved ICMP reachability to `10.1.31.2` but SMB
still returned error 53. The prepared client had used hostname `controller`
and domain `TELOS` even though the publication is a standalone Samba server.
New bundles use the exact numeric isolated UNC and the local
`.\pxe-install` account, eliminating DNS and domain assumptions.

The corrected names reached Samba but authentication returned error 86. The
publisher had passed the WinPE password file's CRLF carriage return into
`smbpasswd`, while WinPE supplied the logical password line. Publication now
normalizes only that trailing carriage return before both password
confirmations. No disk mutation occurred. A fresh bundle and live retry are
next.

The normalized retry still returned error 86. The remaining client-side
qualification `.\pxe-install` denotes the WinPE client context rather than the
remote standalone server. New bundles send the exact unqualified Samba passdb
user `pxe-install`, matching the share's `valid users` rule. No disk mutation
occurred. A fresh live retry is next.

The unqualified-user retry still returned error 86, so qualification was not
the remaining cause. New bundles give both Samba and WinPE the exact same
LF-terminated password line, removing consumer-dependent CRLF handling. No
disk mutation occurred. A fresh live retry is next.

The byte-identical retry still returned error 86. The remaining failed
assumption is that `net use ... *` reliably consumes its interactive password
prompt from redirected WinPE input. New bundles inject a secret-free VBScript
helper that reads the password file in-process and calls
`WScript.Network.MapNetworkDrive`; no secret enters arguments or logs. No disk
mutation occurred. A fresh live retry is next.
