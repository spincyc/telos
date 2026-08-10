# Workstation factory Make contract

Document version: `20260727.002`

Status: interface proposal; targets marked **implemented** are available now.
The remaining names are reserved for the local lifecycle runner. Do not attach
placeholder recipes that report success.

## Reproducibility boundary

The factory has two deliberately separate phases:

1. **Acquire** may use the Internet. It installs build-host dependencies and
   imports freshly resolved, verified Arch, Windows, and `wimboot` media into
   ignored local cache.
2. **Build and exercise** must work with the host network unavailable. It
   builds immutable releases, converges disposable guests, installs both
   operating systems, runs acceptance checks, recovers, destroys, and repeats.

`make` must never pull or update the checkout that is currently executing.
The public fresh-clone cycle belongs in a wrapper target which clones into a
new disposable directory, records the requested Git ref and resolved commit,
and invokes the ordinary targets there. Generated media, VM disks, credentials,
and evidence remain ignored and must never be required from Git.

Every mutating or destructive target is a dry run unless `APPLY=1` is supplied.
Disk-erasing targets additionally require a stable target identifier and an
exact confirmation value. Verification targets must distinguish `PASS`,
`FAIL`, and `NOT RUN`; a planned assertion is never a pass.

## Target graph

| Stage | Target | Contract |
|---|---|---|
| Host | `homelab-factory-deps` | Install/check the complete Arch build-host dependency set. Online; explicit operator action. |
| Acquire | `homelab-factory-media` | Fresh-resolve Arch and `wimboot`; import the operator-supplied Windows ISO; emit one aggregate receipt. Online or local import. |
| Seal | `homelab-factory-cache-seal` | Verify every cached input, record hashes and tool versions, and produce a portable inventory. No downloads. |
| Offline gate | `homelab-factory-offline-check` | Refuse absent/unsealed inputs and prove subsequent recipes have no download dependency. |
| Controller | `homelab-factory-controller` | Create a disposable controller overlay and converge PXE/HTTP, Samba AD DNS, Kerberos/time, logging, backup, and restore. |
| Releases | `homelab-factory-pxe` | Build and verify immutable controller, Windows, and Arch releases using one `YYYYMMDD.NNN` release identifier. |
| Authority | `homelab-factory-authority-check` | Prove the simulated gateway is the only DHCP authority and no guest can reach a host or external network. |
| Windows | `homelab-factory-windows` | PXE-boot and install Windows 11 Pro first; reboot without installation media; join the synthetic domain and test login/recovery. |
| Arch | `homelab-factory-arch` | PXE-boot and install Arch second while preserving Windows and recovery partitions; join the same domain. |
| Dual boot | `homelab-factory-dualboot-check` | Cold-boot both systems and measure partition, EFI, boot-default, login, update, storage-failure, and recovery contracts. |
| Acceptance | **`homelab-factory-verify`** (implemented) | Validate all retained evidence and produce a machine-readable final receipt. Never performs installation. |
| Recovery | `homelab-factory-recover` | Exercise release rollback, controller reconstruction, failed-install recovery, boot repair, and workstation remint. |
| Cleanup | `homelab-factory-clean` | Remove only the named disposable run after exact confirmation; preserve sealed media unless separately requested. |
| Repeat | `homelab-factory-repeat` | Run the complete sealed-input lifecycle at least twice from destroyed disposable state and compare receipts. |
| Fresh clone | `homelab-factory-fresh-clone` | Clone the public repository into a disposable directory, resolve and record the commit, acquire/import inputs, then invoke the same lifecycle. |

The intended aggregate graph is:

```text
deps -> media -> cache-seal -> offline-check
                              |
                              v
controller -> pxe -> authority-check
                         |
                         v
windows-first -> arch-second -> dualboot-check
                                  |
                                  v
                    verify -> recover -> clean -> repeat
```

## Required common inputs

The runner should accept one run identifier and one release identifier rather
than allowing each subtarget to invent paths:

```text
RUN=<opaque local run ID>
VERSION=YYYYMMDD.NNN
WINDOWS_ISO=homelab/var/media/windows/windows-11-x64.iso
ARCH_ISO=homelab/var/media/arch/archlinux-x86_64.iso
WIMBOOT=homelab/var/media/wimboot
APPLY=1
```

Synthetic public identity values must be fixed in tracked configuration.
Private identity, host, domain, network, and credential values are never
arguments to the public simulation. Secrets must enter through mode-`0600`
files or an interactive terminal and must not appear in process arguments,
Make output, receipts, or transcripts.

## Existing targets that remain valid

These targets already provide useful leaf operations and should be reused
rather than reimplemented:

- `homelab-bootstrap-deps`
- `homelab-media-arch`, `homelab-media-windows`,
  `homelab-media-wimboot`
- `homelab-bootstrap-seed`
- `homelab-pxe-controller`, `homelab-pxe-arch`,
  `homelab-pxe-windows`, `homelab-pxe-verify`
- `homelab-workstation-plan`, `homelab-workstation-verify`
- `homelab-arch-update-check`
- `homelab-sim-deps`, `homelab-sim-auto-plan`
- `homelab-sim-auto-run`, `homelab-sim-auto-repeat`
- `homelab-image-promotion-gate`

The promotion gate is the common static precondition for promoting any
Arch-derived image. It is read-only: it audits a candidate root through a
confined descriptor chain that follows no symlinked ancestor, mounts and boots
nothing, and always gates against the tracked `package-contract.json` rather
than a caller-supplied registry.

```sh
make homelab-image-promotion-gate \
  IMAGE_PROFILE=controller-seed \
  IMAGE_ROOT=<candidate root> \
  IMAGE_RECEIPT=<signed seed receipt> \
  IMAGE_EVIDENCE=<optional evidence path>
```

Every failure names its stage — `contract`, `root-audit`, or `seed-closure` —
so an unaccounted binary, an unowned path, a missing package signature, and an
installed version that drifted from the seed closure are distinguishable
without inspecting the candidate by hand. Passing this gate is necessary and
not sufficient: booting the candidate and verifying declared services remain
separate gates, and promotion still needs explicit authority.

The aggregate factory targets may delegate to a leaf only after its inputs and
outputs match this contract. In particular, do not claim the current simulator
proves PXE installation, AD join, or dual boot.

The simulation automation is deliberately separate from the final human gate:

```sh
make homelab-sim-deps
make homelab-sim-auto-plan
make homelab-sim-auto-run APPLY=1
make homelab-sim-auto-repeat APPLY=1 SIM_CYCLES=10
```

The dependency target checks only; it does not install or update packages.
Planning starts no guest. Automatic live targets generate and wipe their own
one-run credential and accept no password input. `homelab-sim-run APPLY=1`
remains the foreground operator-login cycle and is not a dependency of any
automatic target.

## Acceptance measurements

Each stage records start/end timestamps, input hashes, resolved Git commit,
tool versions, guest firmware and stable disk identities, exact commands
without secrets, process exit status, network transcript, partition/EFI
measurements, assertions, and cleanup result. The final verifier also confirms:

- the canonical controller disk and firmware variables are unchanged;
- all guest disks are disposable and scoped to the named run;
- no TAP, bridge, route, VLAN, forwarding rule, physical listener, or UniFi
  change was created;
- no external connection occurred after the offline gate;
- Windows was installed before Arch and Windows remains the default boot;
- both operating systems pass online and cached-offline login;
- optional storage absence does not delay or prevent login; and
- no tracked or publishable artifact contains media, credentials, private
  values, or oversized generated objects.
