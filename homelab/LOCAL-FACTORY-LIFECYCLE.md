# Offline local factory lifecycle

Document version: `20260727.001`

Status: implementation contract  
Recorded: 2026-07-27

This contract is the durable definition of the work that must finish before
the Controller or a workstation is attached to the household network. It
extends the isolated network rehearsal; that rehearsal alone is not a
workstation-factory acceptance test.

## Frozen decisions

- The complete rehearsal has no route to the host LAN or internet and makes no
  UniFi, bridge, TAP, route, firewall, VLAN, or physical-interface change.
- The real workstation is installed Windows 11 Pro first and Arch Linux
  second, on one UEFI/GPT disk.
- Windows is the default boot choice. Both systems retain independently
  bootable native UEFI entries.
- After reserving fixed partitions and the 160 GiB Windows and 64 GiB Arch
  minima, surplus usable space is split 75 percent Windows and 25 percent Arch.
- Phase-one workstations use no BitLocker, LUKS, custom Secure Boot trust, or
  TPM enrollment. These omissions are explicit pilot limits.
- The public rehearsal uses generated names, accounts, addresses, and
  short-lived credentials. Real people, machines, network values, credentials,
  and secrets remain in `telos-private` or an encrypted secret store.
- Windows and Arch updates are automatic in deployed workstations. The
  no-uplink factory proves configuration, gating, failure behavior, and locally
  staged signed-package handling. It cannot prove Microsoft Update or an
  official Arch mirror is reachable; those transactions remain an explicitly
  measured external-integration gate. Arch's deployed policy remains a full
  signed `pacman -Syu` from an official mirror, not a Controller dependency.
- Local profiles and cached logons must remain usable indefinitely away from
  home. Optional SMB user storage must never block logon.
- Temporary offline-logon revocation remains a later phase.
- Windows installation media is operator-supplied Microsoft media. It is
  locally hashed and never committed or published.
- Every build, start, verify, teardown, recovery, and remint operation has a
  Make target. Mutating targets are dry runs unless `APPLY=1` is explicit.
- Each workstation has a distinct, non-domain `local-rescue` account protected
  by a dedicated break-glass public key. The synthetic factory creates a
  per-run key pair, exposes no private key to a guest artifact, and destroys it
  after retaining only redacted access evidence. Real private key custody is
  outside both public and private Telos repositories.

## Topology

The factory is one host userspace Ethernet fabric with no uplink:

```text
                   loopback-only userspace Ethernet fabric
                  /                 |                    \
     simulated gateway       disposable Controller       workstation
     DHCP and test time       AD DNS, Kerberos, PXE       one persistent disk
     no forwarding            HTTP and install shares     Windows, then Arch
```

The fabric must support simultaneous broadcast among all three participants.
The current point-to-point, sequential `simulated_gateway.py` cycle is useful
for attachment safety but is not this fabric. The factory fabric must:

1. bind every host socket to loopback or a private Unix socket;
2. learn source MAC addresses and flood broadcast/unknown-unicast frames;
3. expose no host networking backend (`user`, SLIRP, TAP, bridge, passt, VDE);
4. record packet provenance and exact DHCP offer count;
5. drop malformed, oversized, spoofed, and cross-port source frames;
6. provide deterministic packet loss and service-failure injection; and
7. be audited before QEMU starts and again from each live process command line.

The simulated gateway is the only DHCP authority. It supplies an address,
gateway, AD DNS address, NTP address, and architecture-correct PXE next-server
and boot filename. It does not forward packets. The Controller is statically
addressed and must never answer DHCP. DHCP broadcasts still reach the
Controller so its silence is measured rather than assumed.

Guests inherit no host resolver, proxy environment, shared folder, clipboard,
guest agent, metadata service, or credential channel. Denied external
connection attempts are retained as evidence.

## Immutable inputs

Before any guest starts, make one private run receipt containing:

- public Telos commit;
- Controller base-disk and copied OVMF-variable hashes;
- Arch ISO signature, signer, version, size, and SHA-256;
- Windows ISO filename, size, SHA-256, detected editions, language, build, and
  architecture;
- `wimboot` source and SHA-256;
- offline Arch package-repository manifest;
- generated topology, MAC addresses, disk serials, and addresses;
- generated test realm and account names, but no passwords; and
- all generated PXE release versions (`YYYYMMDD.NNN`).

The run refuses mutable, unlisted, symlinked, or wrong-edition input. Large
media and disposable disks stay under ignored `homelab/var/`; the root-level
Windows ISO is input only and must never enter Git history.

## Staged lifecycle and acceptance

Each stage writes a machine-readable receipt. A later stage consumes and
verifies the previous receipt rather than trusting a directory merely because
it exists.

### Gate 1 — media and offline closure

1. Verify the actual Windows ISO and prove that it contains Windows 11 Pro.
2. Verify Arch media and all signatures.
3. Build immutable Arch, Windows, and Controller releases.
4. Prove every package, installer file, driver, boot file, answer template, and
   update used later is present locally.
5. Block DNS and connect attempts outside the simulated fabric.

Pass: rebuilding from the same inputs requires no external read and produces
equivalent manifests. Removing any declared dependency fails before boot.
Installed Windows, disk, and OVMF images are not expected to be
bit-reproducible; their declared semantic state is compared while
nondeterministic identifiers are recorded.

### Gate 2 — bootstrap Controller convergence

Boot a disposable overlay of the already installed `bootstrap-dc`. Converge it
from local source and packages into the test realm with host-level Samba AD,
integrated AD DNS, Kerberos, time, nginx, PXE files, and Windows installation
share. Keep DHCP, routing, and NAT disabled.

Pass:

- two consecutive convergence runs succeed and the second reports no change;
- `samba-tool dbcheck` succeeds;
- LDAP/Kerberos DNS SRV records resolve through the Controller;
- generated standard and administrative users can obtain Kerberos tickets;
- clients use only AD DNS; no public or simulated external DNS is configured as
  a secondary resolver;
- the Controller is the isolated realm's authoritative time source, Kerberos
  fails at injected excessive skew, and recovers after time correction;
- PXE and HTTP manifests verify byte-for-byte;
- no forbidden listener, forwarding flag, route, or DHCP response exists; and
- stopping storage or the simulated gateway does not damage AD.

### Gate 3 — replacement Controller mint

PXE-boot a blank candidate Controller from the bootstrap Controller and install
it to a serial-authorized disposable disk using only local artifacts. Do not
activate it as a second authority on the workstation fabric yet.
The candidate has a unique host name, address, and inert role; it is never a
clone of a running DC and never reuses the bootstrap DC identity.

Pass:

- firmware visibly selects network boot;
- DHCP option 93 selects the approved x86-64 UEFI first-stage loader, iPXE
  chains exactly once to HTTP, and BIOS or unsupported architectures fail
  closed;
- DHCP provenance names only the simulated gateway;
- the first-stage loader and every HTTP artifact match the selected release;
- wrong disk serial, missing receipt, altered artifact, and repeated release
  all fail closed;
- the installed candidate cold-boots without media;
- its disk and OVMF state differ while all canonical inputs remain unchanged;
- its preflight reports inert services before separately authorized
  convergence; and
- destroying and reminting it produces the same declared state.

This gate proves the Controller target, but the disposable bootstrap Controller
continues to provide authority for workstation tests. It avoids two machines
claiming the same DC identity.

### Gate 4 — Windows-first workstation install

Create one sparse workstation disk large enough to exercise the production
minimums and give it a fixed serial. PXE-boot WinPE, verify the selected release
inside WinPE, require that exact disk serial, partition only the declared
Windows allocation, and install Windows 11 Pro with US defaults. Partition
numbers are not normative: physical extents, GPT types, identities, and
boundaries are. Windows may create its recovery partition after its OS
partition; Arch must not renumber or move it.

The unattended answer and setup scripts are rendered per run into private
temporary storage. They may contain a short-lived join secret only while
needed; logs must redact it and teardown must destroy it. Prefer offline domain
join data or a one-use account over a reusable domain-administrator password.

Pass:

- Windows Setup uses no ISO attached to the workstation and no external
  network;
- GPT contains the planned ESP, MSR, Windows, and recovery partitions plus
  unallocated Arch space;
- Windows boots directly from its native UEFI entry;
- edition is Pro, activation is not required in the VM, locale is US, and disk
  encryption is off;
- the workstation joins the generated domain and its secure channel verifies;
- the standard domain user is not local administrator;
- the administrative test user has only the declared workstation rights;
- signed, locally staged MSU/CAB updates install automatically from the isolated
  source; this proves the pilot offline update job, not Microsoft Update or
  WSUS;
- hibernation and Fast Startup are disabled and NTFS reports a clean shutdown
  and no dirty bit before Arch is installed;
- cold reboot and connected domain login succeed; and
- exact disk layout, boot state, event evidence, and release hashes are saved.

### Gate 5 — Arch-second installation

Network-boot the Arch installer against the same workstation disk. It must
recognize and preserve every Windows partition and UEFI file, consume only the
planned remaining space, and install its own native systemd-boot entry.

Pass:

- before/after partition evidence proves Windows boundaries did not move;
- Arch never mounts a hibernated or dirty Windows filesystem;
- Windows Boot Manager remains directly firmware-bootable;
- the five-second menu defaults to Windows and can boot Arch;
- Arch joins the same domain using SSSD/Kerberos;
- the same AD SIDs map to the same numeric UID/GID values after reboot and a
  client remint;
- the standard user has no `sudo`; the declared administrative user does;
- the local rescue account works with AD unavailable;
- automatic Arch updates use the staged gate-and-reboot policy; and
- two cold boots reproduce Windows-default and explicit-Arch behavior;
- Secure Boot and TPM state are explicitly recorded as off for phase one; and
- boot order survives Windows servicing, with firmware variables backed up and
  restore-tested.

### Gate 6 — identity, mobility, and storage failures

Test connected domain login once, then disconnect each dependency separately
and in combination:

- AD/DNS unavailable;
- simulated gateway unavailable after lease acquisition;
- optional SMB storage unreachable;
- SMB reachable but access denied;
- update source unavailable; and
- Controller powered off after credentials are cached.

Pass on both operating systems:

- a previously logged-on standard user can log on from the local profile;
- local rescue can log on;
- no optional storage failure delays logon beyond the declared bound;
- storage does not replace the local home/profile;
- connected disablement blocks new connected authentication;
- disablement is tested while AD/DNS are healthy and reachable, after any
  required replication or cache invalidation;
- Windows cached-logon policy and SSSD
  `offline_credentials_expiration = 0` are asserted, including stale-cache
  behavior after an online password change; finite testing cannot prove the
  literal passage of unlimited time;
- Windows' cached-logon count is explicitly configured above the complete
  managed-user roster plus an administrative margin; a non-expiring cache is
  useless if a later user silently evicts the intended traveler's entry;
- the evidence explicitly notes that disconnected cached credentials cannot be
  revoked in phase one; and
- service restoration recovers without rejoining or rebuilding.

### Gate 7 — recovery and remint

Exercise wrong boot target, corrupt current PXE pointer, interrupted artifact
publication, failed installation, lost Controller, and destroyed workstation
disk. Roll back to the previous immutable release and remint from blank state.

Pass:

- an interrupted publish never becomes `current`;
- the previous release remains bootable;
- Controller reconstruction of the same realm uses a tested encrypted Samba AD
  backup that preserves the domain SID, object identities, machine trust, DNS,
  and Kerberos secrets; absent that backup, recovery is explicitly a new realm
  requiring every workstation to rejoin;
- workstation destruction and a complete Windows-first/Arch-second remint
  require no manual disk surgery;
- no canonical disk, source artifact, or firmware template changed;
- no process, socket, temporary credential, or writable overlay remains; and
- host network evidence before and after is equivalent.

## Required negative proofs

Acceptance must fail when any of these are injected:

- a second DHCP offer or a PXE offer from the Controller;
- wrong PXE architecture or release;
- corrupt manifest entry or unlisted artifact;
- unexpected disk serial or size;
- Windows edition other than Pro;
- Arch attempts to alter a Windows partition;
- either OS lacks its native UEFI boot path;
- standard user gains administration;
- optional storage blocks logon;
- update policy permits an unapproved source;
- a guest receives host-LAN or internet reachability;
- a QEMU process uses a forbidden network backend;
- canonical media, Controller disk, or OVMF template changes; or
- teardown leaves a process, listener, overlay, secret, or private transcript
  with permissive mode.

The optional-storage login bound is 30 seconds in the VM acceptance harness
unless a stricter production measurement is recorded. Physical promotion also
requires a separately verified ThinkPad X13 Gen 6 Intel driver set for storage,
wired networking, Wi-Fi, and firmware; success with generic QEMU hardware does
not satisfy that gate.

## Required command surface

The implementation may split internal helpers, but preserves this operator
surface:

| Target | Result |
|---|---|
| `homelab-factory-deps` | Declares and obtains build dependencies on Arch |
| `homelab-factory-media-verify` | Writes the immutable-input receipt |
| `homelab-factory-releases` | Builds and verifies all local PXE releases |
| `homelab-factory-plan` | Prints topology, disks, releases, gates, and QEMU commands |
| `homelab-factory-controller` | Runs Gates 2 and 3 |
| `homelab-factory-windows` | Runs Windows-first Gate 4 |
| `homelab-factory-arch` | Runs Arch-second Gate 5 on the same disk |
| `homelab-factory-mobility` | Runs dependency-failure Gate 6 |
| `homelab-factory-recover` | Runs rollback and blank remint Gate 7 |
| `homelab-factory-accept` | Runs all gates from immutable inputs |
| `homelab-factory-status` | Summarizes receipts without starting a guest |
| `homelab-factory-clean` | Plans removal of only one identified disposable run |

Every target that creates, starts, changes, or deletes state requires
`APPLY=1`. `homelab-factory-accept` must start from either a new run identifier
or an explicitly selected resumable run, and must never treat a partial
receipt as a pass.

## Durable restart protocol

The current implementation state, verified evidence pointer, blockers, and
literal next action live in
[WORKSTATION-FACTORY-STATE.md](WORKSTATION-FACTORY-STATE.md). That ledger is
the first read after a session change; this lifecycle document is the stable
acceptance contract.

Resume without starting a guest:

```sh
git status --short
git log -1 --oneline
sed -n '1,240p' homelab/WORKSTATION-FACTORY-STATE.md
make homelab-sim-deps
make homelab-sim-auto-plan
```

Preserve unexplained local changes. A missing ignored artifact is `NOT RUN`,
not permission to infer a prior pass. Read an existing receipt before deciding
whether to recreate it.

When the controller network-safety rehearsal itself needs fresh evidence, use:

```sh
make homelab-sim-auto-run APPLY=1
```

That cycle creates its own disposable credential, records structured private
evidence, verifies canonical disk and firmware hashes, and tears down without
the operator's password. Use `make homelab-sim-auto-repeat APPLY=1
SIM_CYCLES=N` for a deliberate bounded repeatability check. Neither command
proves the complete factory.

The distinct `make homelab-sim-run APPLY=1` path is a foreground human console
gate. Do not ask the operator to repeat it during ordinary code/test
iteration. Repeat it only after a material change to the manual path or as the
last rehearsal before separately authorized physical attachment.

## Evidence and promotion

Private evidence lives in a mode-0700, ignored run directory. It includes a
top-level `result.json`, per-gate receipts, serial transcripts with secrets
redacted, QEMU command audits, packet/provenance logs, screenshots only where
text evidence is insufficient, partition and UEFI state, AD/identity results,
update-policy results, failure-injection results, and cleanup hashes.

One command must summarize every gate as `PASS`, `FAIL`, or `NOT RUN`. A run is
promotable only when all seven gates pass. Local acceptance authorizes only the
later read-only UniFi preflight; it does not authorize a physical attachment
or UniFi mutation.

## Implementation gaps recorded on 2026-07-27

The repository already has useful components for media validation, immutable
PXE releases, workstation layout planning, a disposable Controller overlay,
QEMU boundary auditing, simulated DHCP/DNS/NTP, provenance checking, host
evidence, Samba AD convergence, SSSD, and Arch update policy. The following
gaps remain before the contract can pass:

1. replace point-to-point sequential simulation with a simultaneous,
   loopback-only userspace Ethernet fabric;
2. add architecture-aware DHCP PXE options and a real first-stage UEFI PXE
   loader to the simulated gateway path;
3. make Controller convergence fully local and run it inside the disposable
   guest, including a local package repository;
4. deploy and exercise actual PXE/HTTP/install-share services in that guest;
5. automate blank candidate-Controller PXE install and cold-boot acceptance;
6. extend Windows staging beyond WinPE: include the locally served install
   image without loading it through `wimboot`; customize WinPE image index 2;
   add the UEFI iPXE first stage, serial-gated disk/setup scripts, private
   answer and one-machine offline-domain-join rendering, driver injection where
   needed, WinRE/BCD construction, and redacted setup evidence;
7. implement same-disk Windows-first then Arch-second installation;
8. implement Windows domain join, login, secure-channel, privilege, cached
   login, update-policy, and recovery probes;
9. implement Arch installation, domain join, boot-default, cached-login,
   optional-storage, and update-policy probes;
10. add controlled dependency-failure injection and bounded login timing;
11. add full recovery/remint orchestration with stage receipts and resumable
    diagnostics; and
12. expose the complete lifecycle through dry-run-default Make targets and one
    final aggregate acceptance target.

For the VM path, prefer Q35/OVMF with an emulated device set supported by stock
WinPE (for example AHCI/NVMe storage and an e1000e NIC), and separately verify
that its firmware really exposes UEFI network boot. Virtio storage or
networking requires signed drivers injected into WinPE and the installed image.
The actual supplied media currently advertises Windows 11 Pro at image index 6;
code must still discover and receipt the edition rather than hard-code that
index.

Until these gaps close, wording must distinguish “network-attachment
simulation passed” from “offline workstation factory passed.”
