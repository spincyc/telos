# Local workstation factory state

Document version: `20260727.001`

Status: active implementation  
Last evidence review: 2026-07-27  
Repository baseline reviewed: `d5a3534`

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

The accepted architectural records are ADRs
[0064](decisions/0064-narrow-phase-one-to-workstation-factory.md),
[0069](decisions/0069-plain-disk-phase-one-workstations.md),
[0070](decisions/0070-configurable-dual-boot-workstation-layout.md), and
[0074](decisions/0074-gated-workstation-factory-acceptance.md).

## Verified so far

| Gate | Evidence | Result |
|---|---|---|
| Offline controller media and installation | Controller seed SHA-256 `f328efb53d782bb536275d15d128ee6aae722d64e23f8ea4bab0fe39cb075820`; installed `bootstrap-dc` booted from UEFI/systemd-boot on ext4 with locked root and working `local-rescue` sudo. | pass |
| Installed controller safety gate | `homelab-network-attach-preflight` verified forwarding off, SSH root/password login disabled, authority services masked and inactive, and no provisioning/authority ports listening. | pass |
| Manual isolated rehearsal | The operator ran the installed preflight successfully in the disposable controller and powered it off normally. | pass |
| Unattended isolated rehearsal | `homelab/var/simulation/evidence/20260727T184229Z-1971156-b2907fed/result.json` records controller preflight, single DHCP authority, client continuity, and unchanged host state. | pass |
| Repeatable simulator implementation | Public commits through `d5a3534` add the unattended loopback rehearsal and its documentation. | pass |

The evidence directory is local, ignored state and is not a substitute for a
portable release receipt. Preserve the referenced run until its salient
results are copied into the eventual factory acceptance record.

The prior rehearsal is only a controller network-safety proof. It does **not**
prove a configured PXE server, Samba AD, either workstation installer, a domain
join, dual boot, user login, or recovery.

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

The matching digest proves the imported bytes match the operator-supplied
Microsoft-published digest. PXE staging must independently inspect the image
catalog and refuse it unless Windows 11 Pro is present. Never commit, publish,
or copy the ISO into a release tree.

Other present local inputs:

| Input | Local result |
|---|---|
| Arch Linux 2026.07.01 x86-64 ISO | `homelab/var/media/arch/archlinux-2026.07.01-x86_64.iso`; SHA-256 `e86295dc0bdf9b85a5a9256810c553239689d2ae8e80eeec81b4e2e910d8a6c0`; receipt is adjacent. |
| iPXE `wimboot` | `homelab/var/media/wimboot`; SHA-256 `5f067ccdc4d084d5bf77b6c853bd0f8402dfc2b4cd1b103d358993ae97fae8e3`. |
| Controller seed | `homelab/var/seed/telos-controller-seed.iso`; SHA-256 shown in the verified table above. |

All paths under `homelab/var/` are disposable, ignored cache or evidence.
Fresh-clone reconstruction rules are in
[media/FRESH-CLONE.md](media/FRESH-CLONE.md). The original repository-root
Windows ISO is not a durable cache and must not appear in a commit.

## Local lifecycle queue and acceptance gates

Do not skip a gate or turn a planned assertion into a reported pass.

| Order | Gate | Required proof | State |
|---:|---|---|---|
| 1 | Media intake | Verify Windows digest and receipt; inspect the image catalog for Windows 11 Pro; verify Arch signature/digest and `wimboot` pin; prove no media is tracked. | Windows digest imported; edition inspection pending |
| 2 | Immutable PXE releases | Build and verify versioned Windows, Arch, and controller targets; manifests bind every byte to `YYYYMMDD.NNN`; rejected input and rollback tests pass. | partial implementation |
| 3 | Controller convergence | From an accepted base controller overlay, configure Samba AD/DNS, Kerberos/time, HTTP/TFTP/iPXE, release selection, logging, backup, and restore without external access. | pending |
| 4 | PXE authority boundary | Simulated gateway remains sole DHCP authority; controller supplies only the approved boot and identity services; packet evidence proves no rogue offer, forwarding, or external connection. | pending |
| 5 | Windows-first install | OVMF workstation PXE-boots WinPE, selects the disk by stable serial, installs Windows 11 Pro to the approved layout, and reboots without ISO attachment. Destructive authorization is scoped to the disposable disk. | pending |
| 6 | Windows join and login | Join the synthetic domain; prove secure channel, DNS SRV, time, named user login, named administrator elevation, `local-rescue`, reboot, cached offline login, update policy, and recovery path. | pending |
| 7 | Arch-second install | PXE-boot Arch, preserve Windows partitions and recovery data, install into the approved allocation, join the same domain, and create independent UEFI entries with Windows default. | pending |
| 8 | Arch join and login | Prove SSSD identity, UID/GID stability, Kerberos time, named user and administrator behavior, reboot, cached offline login, automatic-update gate, rollback, and local rescue. | pending |
| 9 | Optional storage failure | Prove per-user SMB authorization when present and successful login with no delay or hard failure when the NAS is absent. Record UID/GID and timestamp measurements before reconsidering NFS. | pending |
| 10 | Dual-boot acceptance | From cold boot, select and log into both systems; verify Windows-default five-second policy, disk measurements, EFI recovery choices, and no cross-OS partition damage. | pending |
| 11 | Lifecycle recovery | Exercise controller restart/loss, PXE release rollback, failed install, broken boot, directory/DNS loss, update failure, workstation remint, and controller reconstruction from public inputs plus a synthetic private overlay. | pending |
| 12 | Repeatability | Destroy disposable state and repeat the entire factory at least twice from a clean local input set; compare manifests and explain any nondeterministic bytes. | pending |
| 13 | Documentation/publication | Human and operator guides match tested commands, contain no private data, pass links/site checks, and expose exact supported and unsupported states. | pending |
| 14 | External integration | Only after a new explicit authorization: read-only UniFi review, separately approved changes, physical attachment, then ThinkPad X13 Gen 6 Intel pilot. | blocked by design |

## Current blockers and cautions

- The actual Windows ISO is now available; media acquisition is no longer the
  blocker. Windows 11 Pro catalog inspection and an OVMF WinPE boot are still
  required.
- The controller has not yet been converged into a real PXE/Samba AD server.
- Existing PXE staging proves payload construction, not unattended Windows
  installation. An answer file, WinPE startup workflow, disk-serial gate,
  installation-image delivery, secret injection, and post-install acceptance
  remain to be implemented.
- A local-only Samba AD test domain must use synthetic public-safe values. Real
  household identities and credentials belong only in the private overlay.
- Offline automatic updates can validate policy and staged local repositories;
  they cannot prove reachability of public update services.
- Firmware-backed Windows activation cannot be reproduced in QEMU and is not a
  local acceptance requirement.
- The phase-one lack of encryption is an explicit development exception. Do
  not represent these images as safe for a mobile or college laptop until the
  encryption decision is revisited.
- No successful local lifecycle permits an implicit UniFi mutation, physical
  attachment, or hardware erase.

## Resume here

First establish the current boundary and inputs without mutating them:

```sh
git status --short
sha256sum homelab/var/media/windows/windows-11-x64.iso
python -m json.tool \
  homelab/var/media/windows/windows-11-x64.iso.provenance.json
make homelab-sim-auto-run APPLY=1
```

Expected: the Windows digest is the value recorded above, the receipt names
Microsoft Software Download, the root ISO is not staged for commit, and the
isolated rehearsal passes without host-network changes.

The next implementation action is media gate 1: inspect the Windows image
catalog for Windows 11 Pro and exercise the existing Windows PXE stage and
verifier against release `20260727.001`. Continue into controller convergence
only after that gate emits retained evidence. Prefer one aggregate
`make homelab-factory-local` lifecycle target, with independently runnable
phase targets beneath it. Planning or verification should be the default;
destructive disposable-disk actions require `APPLY=1` and an exact disk
identity confirmation.

After every material result, update this ledger's version, the gate table, the
latest evidence pointer, blockers, and the literal next command. Commit code,
tests, documentation, and generated public metadata in coherent, terse
changes; never commit media, credentials, private inventory, or ignored
evidence.
