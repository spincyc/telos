# External integration readiness (gate 14)

Status: plan only. Written 2026-09-30 for local work item TASK-9.

Gate 14 is **not authorized**. This plan authorizes nothing. Every mutation
below is marked "needs separate owner authorization" and stays blocked until
the owner grants that mutation explicitly. The only authorized action is the
read-only UniFi review in stage 1.

The plan orders the work that takes the loopback-proven factory
([WORKSTATION-FACTORY-STATE.md](WORKSTATION-FACTORY-STATE.md), gate 14 row)
to a Controller on the home LAN and one minted Lenovo ThinkPad X13 Gen 6
Intel. Instance values are named only symbolically. Real addresses, MACs,
serials, host and account names, the realm and the domain SID live only in
the gitignored `homelab/instance/` overlay (ADR 0046).

## Decisions in force

| Decision | Source |
|---|---|
| Gate 14 is not authorized. The owner has authorized only a read-only UniFi DHCP/PXE settings review, using access the owner supplies. The review changes nothing. | Owner, 2026-09-30 |
| UniFi stays the sole DHCP authority. The Controller never offers DHCP or ProxyDHCP and never binds UDP 67 or 4011. UniFi options 66/67 are infrastructure state, not workstation state. | ADR 0066, ADR 0076 |
| The Controller first attaches as an ordinary UniFi client with a reservation. After that, Controller roles are enabled one at a time, each with its own rollback. | ADR 0076 |
| Phase-one laptops are unencrypted by owner decision, and that is not a blocker. The ledger's caution still applies: do not call these images suitable for mobile or college use until the encryption decision is revisited. | Ledger decisions table and cautions |
| Physical installs are interactive. The destructive confirmation is the typed hardware disk serial. Unattended Windows automation is limited to disposable QEMU. | ADR 0058, ADR 0078 |
| Anything a workstation keeps discovers services by stable name and SRV record, never by address. | ADR 0068 |
| The complete local lifecycle, including the twice-through repeat, must pass before any UniFi change or physical attachment. ADR 0080 (owner, 2026-09-30) closes phase one with gate 11 at `partial` (five scenarios run and pass, three deferred) and gate 12 passing with only `host_network_changes` waived. Gate 11 reached that state 2026-10-01; gate 12 has no result yet, so stages 2-6 stay blocked until it does. | ADR 0077, ADR 0080, ledger gates 11-12 |

**Evidence convention.** Private evidence goes under
`homelab/instance/evidence/gate14/<stage>/`, with files at mode 0600 inside
0700 directories. That covers screenshots, exports, captures, addresses,
MACs and serials, and none of it goes into Git or the site. The public
record (this file and the ledger's gate-14 row) carries only symbolic
outcomes: yes/no answers, pass/fail verdicts, and SHA-256 digests of the
private files.

**Stage shape.** Each stage lists, in this order: purpose, preconditions,
read-only observations, mutations, evidence, pass/stop conditions and
rollback. Observations always come before mutations. A stop condition halts
the stage and leads straight to its rollback.

## Stage 0 — Loopback-lab prerequisites (agent work)

**Purpose.** Close the gaps the 2026-09-30 cold review found, inside the
loopback lab only.

**Preconditions.** None beyond ordinary agent work. There is no UniFi
contact, no host network change and no physical device. Some items include
writing an artifact that a later stage installs (a host unit, a driver
bundle). The writing and the loopback test are stage 0. Installing on real
hosts belongs to the later stage and needs its authorization there.

| ID | Gap and evidence | Done when |
|---|---|---|
| P0.1 | **Local lifecycle incomplete.** Gate 11 reached its phase-one state 2026-10-01; gate 12's second live twice-through is running, after the first failed at iteration 1's dual-boot phase (ledger). ADR 0077, as narrowed by ADR 0080, blocks UniFi changes and attachment until gate 12 reaches its phase-one state too. | Gate 11 `partial` with exactly the three ADR 0080 deferrals; gate 12 passes twice-through with only `host_network_changes` waived. |
| P0.2 | **PXE services do not survive a reboot.** Convergence starts Samba, ntpd and TFTP with `systemctl restart` and starts nginx with a bare `nginx -c`. None of them was enabled (`homelab/vm/controller_factory.py` ~318-323). Fixed 2026-09-30 in `dfbcce7`: TFTP and a `telos-factory-http.service` are enabled units; unit-tested, and the reboot-survival check on a persistent instance has not run. | A converged Controller, rebooted in the lab, serves DNS, time, TFTP and HTTP without reconverging. |
| P0.3 | **iPXE chain loop under one boot filename.** The simulated gateway hands out the second-stage script URL only when a request carries option 175 or user class `iPXE` (option 77) (`homelab/vm/simulated_gateway.py` ~256-258). UniFi Network Boot gives every request the same filename. The Controller serves the stock `ipxe.efi`, which has no embedded script (`controller_factory.py` ~318). Stock iPXE would therefore run DHCP, get `ipxe.efi` again, and loop. | Either (a) a pinned iPXE build with an embedded script that chains the release entry point, or (b) UniFi class matching, if stage 1 row 5 shows it exists. `factory_publication._ipxe_binary` already accepts an explicit binary (~67-82). Under (a), the script must either resolve `services.boot_fqdn` at PXE time (stage 1 row 6 decides how) or chain through `${next-server}`. The simulated gateway gains a single-filename mode that reproduces UniFi, and a loopback PXE run reaches the installer through that mode. |
| P0.4 | **Addresses where names belong.** The release `boot.ipxe` chains to an IPv4 literal (`homelab/vm/factory_publication.py` ~272-277). The WinPE startup pings a literal (`homelab/vm/windows_install_contract.py` ~281). The install-source share binds a literal (`factory_publication.py` ~311). ADR 0068 names `services.boot_fqdn`, but the overlay's `directory.json` schema does not carry that key yet (`homelab/tests/test_directory_identity.py` ~431). Separately, `make homelab-factory-offline-check` fails, which blocks building a new release (TASK-34 item 3). | Releases render names from the overlay, and a new release set builds and passes the offline check. |
| P0.5 | **No Controller hosting.** The persistent instance boots with only a loopback QEMU socket netdev (`homelab/vm/bootstrap_dc.py` ~742-747). The tap path and the `homelab-bootstrap-network-*` targets serve only the canonical `bootstrap-dc` (~295-313). Nothing starts a Controller at host boot. `homelab/bin/homelab-host-network` hard-codes its physical, bridge and tap names. [network/ROLLBACK.md](network/ROLLBACK.md) isolates the VM by its canonical QEMU name. | The persistent instance can boot on a precreated tap from a private 0600 network config. A host unit starts it and stops it cleanly, and is tested in the lab. The helper's physical interface is a validated input. The rollback document covers the persistent instance by name. |
| P0.6 | **The attach preflight is pre-AD only.** `homelab/bin/homelab-network-attach-preflight` fails unless Samba, nginx, TFTP and ntpd are masked and nothing listens on the AD or boot ports. A converged DC therefore fails it by design. | A role-aware preflight that permits exactly the listeners of the enabled roles, and still refuses DHCP (67, 4011), forwarding, root SSH and password SSH. |
| P0.7 | **No directory durability.** Corrected 2026-10-01: backup and restore targets now exist (ADR 0081, `homelab-factory-persistent-backup`/`-restore`, TASK-41) but have NOT RUN live. Originally: there was no backup target and no restore drill: the domain-controller role README only documents `samba-tool domain backup online`, and the ledger records backup and restore as unexercised. The domain SID is not recorded durably (ledger gate 13; runbook, persistent-instance section). | An off-DC backup location is chosen, a backup restores on an isolated loopback machine, and convergence records the SID in the overlay. |
| P0.8 | **Upstreams point at the simulator.** The ntpd upstream is the simulated gateway (`controller_factory.py` ~496). No Samba `dns forwarder` is configured anywhere, although ADR 0066 requires one. The Controller manifest says `development_proof: true` (`controller_factory.py` ~283). | The NTP upstream and DNS forwarder come from the overlay and are tested against a simulated upstream. The keeper's manifest label is decided. |
| P0.9 | **No durable workstation flow** (TASK-28). Closed 2026-09-30: TASK-28 is done and proven live end to end on `rehearsal-auto`, keep-verify across a Controller relaunch included. Originally: Every workstation runner wraps a disposable Controller, and a bundle prepared against the permanent realm is refused. No workstation can be kept without this flow. | TASK-28 is done. A QEMU workstation joins the persistent instance and survives a Controller restart. |
| P0.10 | **No physical install path.** Gate 5 uses ADR 0078's QEMU-only automation: `DiskID 0` chosen by capacity, plus `LabConfig` TPM and Secure Boot bypasses (`windows_install_contract.py` ~290-293, ~358). The Arch installer is delivered by serial heredoc with `/dev/vda` hard-coded (`homelab/vm/arch_install_prepare.py` ~71). The install-source SMB publication writes a standalone `smb.conf` and refuses if one already exists (`factory_publication.py` ~298-319), so it cannot run beside the DC's own `smb.conf`. | An interactive physical path that follows ADR 0058 and [pxe/windows/FLOW.md](pxe/windows/FLOW.md). The operator drives Windows Setup with no bypass. The Arch installer is fetched over HTTP, targets NVMe, and is confirmed by the typed hardware serial. The DC serves the install source read-only. The whole path is rehearsed in QEMU with an operator typing every confirmation. |
| P0.11 | **Hardware support gaps.** Nothing injects WinPE drivers. The X13 Gen 6 has no built-in RJ45 ([Lenovo PSREF][psref]), so both PXE and WinPE use a USB-C Ethernet adapter, and WinPE needs that adapter's driver ([Lenovo][ht101981]). The resolved Arch `workstation-install` set has 21 packages, including `linux-firmware` and `networkmanager`, but no `intel-ucode` or `sof-firmware`. Neither OS provisions a Wi-Fi profile. | The WinPE release carries the pinned adapter driver, plus a storage driver if VMD stays on (stage 4). The Arch set adds `intel-ucode` (wired into the boot entry) and `sof-firmware`. Both OSes have a Wi-Fi driver and a way to add a profile without a passphrase entering Git. |

**Evidence.** Each item's own commit and passing tests, plus a live loopback
run where the Done-when column requires one.

**Pass/stop.** Stage 0 passes when every row is done. P0.9 blocks only
stage 5 onward. A row that cannot be done in the lab is a stop, recorded
with its reason.

**Rollback.** These are ordinary commits, reverted by path.

## Stage 1 — Read-only UniFi review (authorized)

**Purpose.** Learn exactly what UniFi can and does do, and record the
baseline that every later rollback restores.

**Preconditions.** The owner supplies the material. Screenshots or a text
transcript from the owner are preferred. If the owner supplies live access,
it should be a UniFi admin limited to the View Only role, removed after the
review. The agent keeps no credential. Nobody sends the admin password, the
backup file, Wi-Fi passphrases or RADIUS secrets.

**Observations (the owner shows or exports):**

| # | Show or export | Question it answers |
|---:|---|---|
| 1 | UniFi Network application version, UniFi OS version, and the gateway/console model and firmware. | Which DHCP, DNS and export features exist at all, and which vendor documentation applies. |
| 2 | The networks list: for each network, its name, purpose, VLAN ID, subnet and DHCP mode (server, relay or none). | Which network the Controller and the pilot join. Whether a separate provisioning network exists or would have to be created (a stage-3 change). Whether any other DHCP server or relay is in play. |
| 3 | The target network's DHCP settings: range, lease time, gateway, DNS servers (auto or manual), domain name, NTP (option 42), and any DHCP guarding or rogue-DHCP detection. | Where a reserved Controller address can sit outside the pool. What DNS and NTP clients get today (the rollback baseline). Whether guarding would flag or block the Controller. |
| 4 | The target network's "Network Boot" toggle, with its server and filename (option 67 and next-server), and the TFTP server field (option 66), whether set or not. | The baseline for options 66/67, and whether anything already PXE-boots from this network. A conflicting consumer is a stop. |
| 5 | Whether custom DHCP options can be added, and whether any rule can match on user class (option 77), vendor class (option 60) or client architecture (option 93). | Whether UniFi can break the iPXE loop by itself (P0.3 option b), or the embedded-script iPXE is required. |
| 6 | DNS settings: local DNS records, any domain-specific (conditional) forwarding, content filtering, any encrypted-DNS or DNS-interception feature, and anything already under `home.arpa`. | How AD names reach managed clients: per-network Samba DNS via DHCP (ADR 0066) or forwarding the AD domain to the Controller. Whether filtering would intercept Samba's forwarder or clients' queries. |
| 7 | IPv6 on the target network: router advertisements, DHCPv6, and advertised DNS (RDNSS). | Whether Windows clients would receive a non-AD IPv6 resolver that bypasses Samba DNS. The factory is IPv4-only (ADR 0013). |
| 8 | Existing DHCP reservations (fixed IPs) on the target network: their count and addresses. Device names may be redacted. | A free, stable Controller address that becomes `network.address` in the overlay's `directory.json`. That address is permanent for the instance, so it is frozen before convergence. |
| 9 | Firewall and traffic rules that touch the target network, network or client isolation, and the port profiles of the switch ports the Controller host and laptop will use (native VLAN, tagged VLANs, port isolation). | Whether a laptop can reach the Controller's TFTP, HTTP, SMB, DNS, Kerberos, LDAP and NTP, and whether the Controller can reach its update mirrors and NTP. Which rules a validation window would need. |
| 10 | Whether a settings backup can be downloaded, and the date of the latest one. The owner keeps the file; the agent records only its date and SHA-256. | The rollback baseline for every stage-3 change. |
| 11 | Which SSIDs bridge into the target network (names only). | What the laptops' Wi-Fi profiles must reach at home, in both OSes (P0.11). |

**Mutations.** None. A change the review shows is needed goes into stage 3's
table.

**Evidence.** The private review record and a digest of each screenshot or
transcript. Publicly: yes/no answers to rows 1, 5, 6 and 7, and "recorded"
for the rest.

**Pass.** Every row is answered and recorded. **Stop:**

- the target network has another DHCP server or a relay;
- Network Boot or options 66/67 are already used by another consumer; or
- the gateway has no Network Boot at all, which forces a re-plan.

**Rollback.** Nothing changed. The owner removes any temporary View Only
admin.

## Stage 2 — Controller hosting and attachment

**Purpose.** Put the Controller on the LAN without transferring any
authority (ADR 0076), then enable its roles one at a time.

**Preconditions.**

- P0.1-P0.8 are done and stage 1 is recorded. P0.9 is also done before
  M2.4, because the ledger creates the keeper instance only after TASK-28.
- The host has a spare wired NIC that is not its management interface
  ([network/ROLLBACK.md](network/ROLLBACK.md)).
- The keeper instance has been converged in the lab, with its stage-1
  address frozen in the overlay before convergence.
- The final human console gate (`make homelab-sim-run APPLY=1`) has been
  re-run immediately beforehand, as the ledger's restart section requires.

**Observations first.** Take the host `ip`, route, `nmcli` and `nft`
baselines that ROLLBACK.md names, confirm UniFi shows no client for the
Controller MAC, and capture a baseline DHCP exchange from a second device.

| ID | Mutation | Authorization |
|---|---|---|
| M2.1 | Host bridge and tap on the dedicated NIC (`homelab/bin/homelab-host-network prepare`). | needs separate owner authorization |
| M2.2 | UniFi reservation for the Controller MAC (stage 3, U1). | needs separate owner authorization |
| M2.3 | Pre-AD attach of the canonical `bootstrap-dc` with no roles, through the `homelab-bootstrap-network-*` targets. Run ADR 0076's six checks. | needs separate owner authorization |
| M2.4 | Install the host unit and boot the keeper persistent instance on the same tap and reservation. | needs separate owner authorization |
| M2.5 | Enable one role per authorization, in this order: time, Samba AD (DNS, Kerberos, LDAP), TFTP/HTTP, then the install-source share. No client is pointed at a role until stage 3. | needs separate owner authorization (each role) |

**Evidence.** The ROLLBACK.md before/after files; ADR 0076's six checks;
after each step, a host-side DHCP capture on the bridge showing no
Controller offer; the role-aware preflight (P0.6) output after each role;
UniFi lease and reservation screenshots.

**Pass.** ADR 0076's checks pass. After each role, the preflight passes, the
Controller sends no DHCP frame, and a second device's lease and DNS are
unchanged. Powering off the Controller affects no ordinary client.
**Stop:** any DHCP or ProxyDHCP frame from the Controller, any client
resolving through the Controller before U3, loss of the host's management
path, or a preflight failure.

**Rollback.** Follow ROLLBACK.md's emergency isolation, then the helper
teardown; for the keeper, isolate it by its persistent-instance name
(P0.5). Mask any role that failed and remove U1. Keep the keeper disk, and
never restore or power on a stale DC copy (ADR 0068). No workstation
depends on the Controller yet.

## Stage 3 — UniFi changes

**Purpose.** Point only the provisioning scope at the Controller.

**Preconditions.** Stage 1 is recorded, including the backup's date and
digest. Each role a change depends on is live and has passed its preflight.
A recorded rollback value exists for every field the change touches.

**Observations first.** Just before each change, re-read the fields it
touches and compare them with the stage-1 record. Any drift is a stop.

| ID | Change | Authorization | Rollback |
|---|---|---|---|
| U1 | DHCP reservation for the Controller at the overlay's `network.address` (used in stage 2). | needs separate owner authorization | Remove the reservation. |
| U2 | Validation-window rules: admin SSH to the Controller; Controller egress limited to Arch mirrors and NTP; if the laptop is on another network, laptop-to-Controller boot and identity ports. | needs separate owner authorization | Delete the added rules. |
| U3 | AD DNS for managed clients. Either the DHCP DNS on a **dedicated provisioning/managed network only** is set to the Controller, or the AD domain is forwarded to the Controller (only if stage 1 row 6 shows forwarding is possible). Never change the household network's DNS: the Controller is a VM on a workstation and must not become a household dependency (ADR 0076). Requires the P0.8 forwarder. | needs separate owner authorization | Restore the recorded DNS settings. |
| U4 | Network Boot on the provisioning network: server = Controller, filename = the P0.3 first-stage loader. Enabled for a mint window, then turned off. | needs separate owner authorization | Turn Network Boot off and restore the recorded values. |
| U5 | Only if stage 1 row 5 showed class matching and P0.3(b) was chosen: a rule that gives iPXE the chain script. | needs separate owner authorization | Delete the rule. |

**Evidence.** Before/after screenshots for each change, and a DHCP capture
showing exactly one DHCP server. For U3: a managed test client resolving the
AD SRV records and a public name. For U4: the stage-5 test boot (W1).

**Pass.** After every change, a second device outside the provisioning
scope gets the same lease, gateway and DNS from UniFi as in the stage-1
record. **Stop:** any household-client impact, a DNS failure, a PXE loop, or
a second DHCP responder.

**Rollback.** Undo in reverse order (U5 back to U1), restoring only recorded
values. Never invent DHCP, DNS, gateway, VLAN or PXE values (ROLLBACK.md).
Then confirm three things: an ordinary client renews its lease, resolves
names and reaches the gateway; options 66/67 are back in their recorded
state; and no lease remains for a detached Controller.

## Stage 4 — Laptop firmware preparation

**Purpose.** Make the X13 Gen 6 Intel PXE-bootable into the factory, and
change nothing the plan does not need.

**Preconditions.**

- The owner designates the pilot unit and confirms that nothing on it must
  be kept (the mint erases it).
- Either recovery media for the shipped image can be obtained from Lenovo,
  or the owner accepts that no return to the shipped state is possible.

**Observations first.** These come from the shipped OS and the firmware
screens, and are recorded in the overlay.

- Machine type, BIOS and EC versions, the hardware serial, and the disk
  model and capacity. About 256 GiB is the practical minimum (ledger).
- The edition of the firmware-embedded Windows entitlement, read in the
  shipped OS with
  `(Get-CimInstance SoftwareLicensingService).OA3xOriginalProductKeyDescription`.
  A unit shipped with Windows Home activates Home, not Pro.
- The storage mode (Intel VMD on or off), the Secure Boot state and the TPM.
- The Wi-Fi module model.
- The USB-C Ethernet adapter model, whether the firmware lists it as a UEFI
  PXE boot option, and the MAC Address Pass Through setting, which decides
  the MAC that UniFi sees.

| ID | Mutation | Authorization |
|---|---|---|
| F1 | BIOS update to a recorded Lenovo release, only if the adapter's UEFI PXE requires it. Lenovo may block downgrades, so treat this as irreversible. | needs separate owner authorization |
| F2 | Disable Secure Boot. iPXE, wimboot and the Arch kernel are unsigned. Re-enabling it later needs the deferred signing work and would stop Arch from booting. | needs separate owner authorization |
| F3 | Set Intel VMD, decided before Windows is installed. Changing it after the install is out of scope. VMD off avoids the WinPE storage driver; VMD on requires it (P0.11). | needs separate owner authorization |
| F4 | Enable the UEFI IPv4 network stack and PXE for the adapter, and set MAC pass-through as decided. Keep the internal disk first in the permanent boot order and use the one-time boot menu for PXE. | needs separate owner authorization |

**Evidence.** Photos of each firmware page before and after (private), the
recorded settings table, and the entitlement edition string.

**Pass.** The adapter appears as a UEFI PXE option, Secure Boot is off, VMD
is set as decided, and the entitlement is Pro or the owner has decided on a
Pro upgrade licence. **Stop:** a Home entitlement without that licensing
decision, no UEFI PXE support on the adapter, a disk below the practical
minimum, or unpreserved data on the unit.

**Rollback.** Restore the recorded firmware settings. F1 has no rollback.

## Stage 5 — First physical mint

**Purpose.** Install Windows 11 Pro first and Arch second, both joined to
the keeper directory, through the interactive physical path.

**Preconditions.** Stages 0-4 have passed, including P0.9-P0.11; without
TASK-28 no workstation can be kept. U3 and U4 are live for the mint window.
The operator is at the laptop, and directory credentials are typed only at
the console, never into a file, argument or answer file.

**Observations first.** Re-read U3 and U4 against the stage-3 record, and
check that the digests the Controller serves match the selected release
manifest. W1 is the laptop's first contact and changes no disk.

| ID | Mutation | Authorization |
|---|---|---|
| W1 | Test PXE boot to the first WinPE and archiso prompts, then power off. This checks for a loop, a missing driver, and DHCP provenance. | needs separate owner authorization |
| W2 | Windows install that erases the one internal disk, confirmed by typing its hardware serial. The layout comes from `workstations/profiles/phase1-windows-primary.json`. Windows 11 Pro is chosen visibly as in FLOW.md. There is no answer file and no `LabConfig`. | needs separate owner authorization |
| W3 | Windows domain join with an operator-typed credential. | needs separate owner authorization |
| W4 | Arch-second install that preserves Windows, with the disk confirmed by typed serial. | needs separate owner authorization |
| W5 | Arch domain join. | needs separate owner authorization |

**Evidence.** DHCP provenance (the UniFi lease and a bridge capture showing
a single DHCP server); Controller TFTP, HTTP and SMB logs that tie each boot
to the release version and digests; the confirmation transcript, with no
secrets; partition measurements before and after Arch; edition, activation
and `manage-bde -status`; `bcdedit` and `efibootmgr` listings;
`Test-ComputerSecureChannel` and `net ads testjoin` results.

**Pass.** Each W step completes and its evidence is retained. **Stop:** a
second DHCP offer or a PXE loop; WinPE without network or an invisible
disk; a failed Setup hardware check (stop, never add a bypass); an edition
other than Pro; the Arch planner refusing the Windows layout; or a failed
join.

**Rollback.** Before W2, no disk has changed. After W2 the laptop is the
disposable object: re-mint from W2, or restore the Lenovo recovery media.
Delete the pilot's machine accounts (needs separate owner authorization)
and turn U4 off.

## Stage 6 — Post-mint acceptance and rollback

**Purpose.** Prove ADR 0074's physical gate on real hardware, and prove that
the household is unaffected.

**Preconditions.** Stage 5 completed.

The acceptance checks are read-only apart from the power-off and
network-change tests. Each of those tests needs separate owner
authorization.

| Check | Pass |
|---|---|
| AD DNS SRV and forwarding, from both OSes | SRV records and public names resolve. |
| Kerberos and Samba health | `klist` shows directory tickets; `samba-tool dbcheck` is clean on the DC. |
| Windows secure channel; Arch SSSD identity | `Test-ComputerSecureChannel` is true; `id` and `sssctl domain-status` show the directory. |
| Cached/offline login, both OSes | Works with the Controller powered off and again away from the home network. |
| `local-rescue`, both OSes | Logs in. |
| NAS absent | Login is not delayed and does not fail. |
| Boot policy | Both UEFI entries are present; Windows is the default with a five-second menu. |
| Artifacts | Served release digests match the manifest. |
| Activation | Windows 11 Pro is activated from the firmware entitlement. |
| Encryption state | `manage-bde -status` and the Arch layout match the unencrypted phase-one decision. Clean Windows 11 installs can turn on device encryption by themselves, with a recovery key escrowed nowhere; report that divergence if it occurs. It is not a blocker. |
| Wi-Fi, both OSes | Connects at home. |
| Updates | Windows updates automatically; Arch runs its gated official-mirror update (ADR 0075). |
| Household unaffected | A second device's lease and DNS match the stage-1 record, including while the Controller is off. |
| Mint window closed | U4 is off unless the owner keeps it. |

**Evidence.** The private acceptance record. The ledger's gate-14 row is
updated with symbolic verdicts only.

**Rollback of gate 14.** Undo in this order: laptop, then UniFi, then
Controller.

1. **Laptop.** Re-mint it, or restore the Lenovo recovery media, and delete
   its machine accounts.
2. **UniFi.** Undo U5 back to U1 using recorded values, and verify an
   ordinary client.
3. **Controller.** Detach it (ROLLBACK.md with P0.5), keep the keeper disk,
   and never power on a stale DC copy.

If the keeper directory is abandoned, joined machines fall back to cached
and `local-rescue` logins (ADR 0055) and must be re-minted against the
replacement.

## Owner decisions this plan needs

| Decision | Needed by | Options |
|---|---|---|
| ADR 0077 completeness | Stage 2 | Decided 2026-09-30 by ADR 0080; gate 11 reached that state 2026-10-01, and what remains is gate 12. |
| AD DNS scope | U3 | A dedicated provisioning network, or AD-domain forwarding. Never household-wide. |
| First-stage iPXE | P0.3 | An embedded script that chains by service name or by `${next-server}`, or UniFi class matching. |
| Controller host and NIC | Stage 2 | Which machine hosts the VM, and which wired NIC it uses. |
| Backup location | P0.7 | An off-DC target the owner controls. |
| Network Boot window | U4 | Enabled only for mint windows, or left on. |
| VMD, MAC pass-through, BIOS update | Stage 4 | Per unit, recorded before Windows is installed. |
| Licensing if the entitlement is Home | Stage 4 | A Pro upgrade licence, or a different unit. |
| Home Wi-Fi | P0.11 | Which SSID, and how profiles are provisioned without the passphrase entering Git. |

[psref]: https://psref.lenovo.com/syspool/Sys/PDF/ThinkPad/ThinkPad_X13_Gen_6_Intel/ThinkPad_X13_Gen_6_Intel_Spec.pdf
[ht101981]: https://support.lenovo.com/np/he/solutions/ht101981
