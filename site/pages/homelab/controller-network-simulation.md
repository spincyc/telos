# Controller network simulation

Version `20260727.002`

Use this rehearsal before changing UniFi. It runs a userspace gateway, boots
the installed `bootstrap-dc` from a disposable overlay in one foreground QEMU
guest, and then runs a synthetic wire-level client. Their Ethernet transport
is a QEMU socket bound only to host loopback.

Most development cycles are automated with a credential that exists only for
one disposable Controller boot. The ordinary `local-rescue` password is not
read or changed. A separate final human cycle uses the real console login as
an explicit attachment gate.

The rehearsal answers four questions:

1. Does the gateway remain the only DHCP and client-DNS authority?
2. Does the Controller refrain from sending a DHCP-server message?
3. Does the implemented simulated gateway ignore unsupported traffic?
4. Does the client still work after the Controller disappears?

> **Hard boundary**
>
> This workflow does not create a host bridge, TAP, VLAN, route, firewall rule
> or UniFi object. It cannot reach the household LAN or Internet. The
> Controller's real disk and firmware are protected by disposable copies.

## Human guide

### What this proves

The lab exercises the implemented simulated packet paths without trusting the
real network. A host userspace process supplies the narrow gateway behavior.
The Controller runs in the foreground and is powered off before a synthetic
client runs on the same loopback-only socket transport. General forwarding is
not implemented.

A passing run is useful evidence that the Controller tooling respects its
boundary. It is not authorization to attach the VM to a physical interface.

### What this cannot prove

Only a later, separately approved hardware gate can prove:

- the selected switch port and VLAN are correct;
- UniFi Network applies the intended zone-policy order;
- the real gateway is the sole DHCP authority on that segment;
- the physical host bridge and interface are correctly identified; or
- real update mirrors and external time are reachable.

The firewall checks are pure model tests, not packet-filter tests against
UniFi, nftables, or a same-L2 peer. The synthetic client is not a second guest
or a general operating system. The cycle does not prove broadcast behavior
between physical peers on one VLAN.

### Safe sequence

| Stage | Human question | Safe outcome |
|---|---|---|
| Plan | Does every virtual NIC use a `127.0.0.1` socket? | Continue only if yes |
| Iterate | Does the Controller boot from disposable state and pass the exact installed preflight? | Repeat automated cycles without disclosing the ordinary console password |
| Human gate | Does the same check pass through the ordinary console login? | Record one final operator-confirmed result |
| Verify | Does the sequential synthetic-client cycle pass? | Retain the generated evidence and terminal result |
| Roll back | Are all simulation processes and disposable files gone? | The real Controller remains unchanged |

If any stage fails, stop the simulation. Do not compensate by creating a host
bridge, enabling QEMU user networking, or changing UniFi.

## Operator guide

Run every command from a fresh public Telos checkout. No private overlay is
needed.

### 1. Record the starting state

The installed Controller must be powered off. Confirm that no simulation is
already running:

```sh
pgrep -af 'qemu-system-x86_64.*telos-sim-' || true
```

Expected result: no matching QEMU process.

Record the immutable inputs:

```sh
git rev-parse HEAD
sha256sum build/homelab/vm/bootstrap-dc/bootstrap-dc.qcow2
```

> **What this does**
>
> The hash makes an accidental change to the installed disk visible. It
> contains no password, private address plan, or household identity.

**Stop if:** the Controller VM is running, the disk is absent, or the state
path is a symlink.

### 2. Plan without starting the guest

```sh
make homelab-sim-plan
```

Expected first line:

```text
Boundary: QEMU loopback sockets only; no host or UniFi changes
```

The plan must describe a userspace gateway, one foreground Controller, a
synthetic client, and then judgement. Inspect the one printed QEMU command.
Its `-netdev` must use `socket` with `connect=127.0.0.1:…`. It must contain
`-nodefaults` and must not contain `tap`, `bridge`, `user`, `slirp`, `passt`,
`0.0.0.0`, a host interface name, or a private-overlay path.

**Intermediate question:** does the printed topology match that exact
boundary? If not, stop. Do not add `--apply`.

### 3. Run automated disposable cycles

Use automation for code and evidence iteration:

```sh
make homelab-sim-auto-run APPLY=1
```

The runner locks and hashes the canonical Controller state, creates a sparse
raw disposable disk and writable firmware copy, and injects a one-run
systemd-boot entry into that copy with rootless tooling. The entry reaches an
initial shell only on the guest serial console. The runner remounts the
disposable root read-write, generates a random password in memory, and enters
it through `passwd`'s no-echo serial prompts. It then starts the normal init
system, logs in as `local-rescue`, runs the exact installed
network-attachment preflight, requires its exact `RESULT PASS` line and return
code zero, and powers off the guest.

The temporary password changes only the disposable copy; it does not read or
change the ordinary `local-rescue` password or hash. It never appears in an
argument, file, raw serial transcript, or evidence record. The runner drops
its in-memory credential references, deletes the disposable disk and firmware copy, and
verifies both canonical hashes. A password must never be accepted as an input
through Make, an environment variable, a command argument, an answer file, or
the repository.

To look for intermittent lifecycle failures, run a bounded number of fresh
cycles:

```sh
make homelab-sim-auto-repeat APPLY=1 SIM_CYCLES=10
```

Each cycle must create new disposable state. A failure stops the sequence; it
does not authorize continuing to the physical-network gate.

> **What this buys**
>
> Developers can repeat boot, preflight, shutdown, client-continuity, evidence,
> and cleanup checks without asking a person to re-enter their real password.
> It does not make the final human observation unnecessary.

### 4. Run the final human gate

```sh
make homelab-sim-run APPLY=1
```

The runner prints a persistent evidence directory beneath:

```text
homelab/var/simulation/evidence/<run-id>/
```

It records host state before, during, and after the cycle. Those files can
contain host interface names, addresses, routes, sockets, and firewall rules.
They are mode `0600`, ignored build evidence: keep them local and never commit
or publish them. The runner audits the Controller QEMU command and then
re-reads that live process from `/proc`. The Controller disk and UEFI
variables are disposable copies; the canonical installed state is not the
simulation's writable target.

Log in at the Controller console as `local-rescue`. Enter its temporary
password only at the console. Never put the password in a command, transcript,
Make variable, or evidence file.

Run these read-only operator checks:

```sh
sudo /usr/local/sbin/homelab-network-attach-preflight
ip -brief address
ip route
sudo ss -lntup
```

Expected measurements:

- preflight ends with `RESULT PASS`;
- the Controller has exactly the simulated NIC expected by the plan;
- IPv4 and IPv6 forwarding remain disabled;
- no Controller process answers DHCP, DNS, TFTP, HTTP, or PXE ports; and
- no route reaches a host or household interface.

**Stop if:** preflight fails, an unexpected NIC appears, a service is
listening, or any route points outside the simulated topology.

> **Operator gate**
>
> This console inspection is manual. The runner does not parse these commands
> or their output. Record the gate as `PASS` only after comparing each
> observation with the criteria above. Otherwise record `FAIL`, power off the
> guest, and do not treat the later runner result as approval.

### 5. Run the automated boundary checks

The model and runner checks are available separately:

```sh
make homelab-sim-check
```

The suite must report `OK`. The relevant tests check:

- one DHCP offer and acknowledgement from the gateway;
- detection of a DHCP-server message observed from the Controller;
- deliberate DNS answers only, with the Controller absent;
- time supplied by the simulated external peer;
- pure-model allow/deny decisions and silence from the narrow gateway
  implementation for unsupported packets;
- client continuity after Controller loss;
- loopback-only QEMU arguments and live-process auditing;
- disposable firmware and disk writes; and
- unchanged canonical Controller state.

A unit-test pass does not prove real firewall enforcement and does not replace
the operator gate in section 4.

### 6. Exercise Controller loss

At the Controller console, shut down only the Controller:

```sh
sudo poweroff
```

After QEMU exits, the same runner invokes the synthetic client, judges its
DHCP/DNS/NTP/probe transcript, compares host evidence, and terminates the
userspace gateway. Wait for these final lines:

```text
PASS gateway is sole DHCP authority
PASS client DHCP, DNS, NTP and probe survived controller poweroff
PASS observable host network state was unchanged
```

These statements are limited to this simulator and its transcript. They do
not describe the real UniFi network.

If the current user cannot query nftables, the runner also prints:

```text
NOTE host firewall rules were unavailable to this user
```

That note is a measurement limit, not a firewall pass. The runner still
requires the other captured host observations to remain stable and the
loopback-only QEMU boundary to pass. It does not claim that unobserved host
firewall rules were unchanged. Use a separately authorized privileged
observation if firewall-rule evidence is required; never make the simulation
privileged merely to suppress the note.

**Verify:** the host has no remaining simulation process:

```sh
pgrep -af 'qemu-system-x86_64.*telos-sim-' || true
```

Expected result: no match.

### 7. Prove rollback

Recompute the Controller-disk hash:

```sh
sha256sum build/homelab/vm/bootstrap-dc/bootstrap-dc.qcow2
```

It must exactly equal the value recorded in section 1. Also confirm that the
host received no Telos-created bridge or TAP:

```sh
ip -brief link
```

Compare this output with the host's normal interface inventory. Also inspect
the generated `before.json`, `during.json`, and `after.json` in the printed
evidence directory. The runner itself compares the captured cycle and fails if
its host-network invariants change. The simulator does not require or create a
named host network interface.

If QEMU remains after an interrupted run, terminate only the simulation
processes shown by the narrow query:

```sh
pkill -TERM -f 'qemu-system-x86_64.*telos-sim-'
```

Re-run the process query and disk hash. Do not delete the canonical Controller
disk.

### 8. Retain evidence

Keep the generated detailed evidence locally. It can contain private host
network details and is not suitable for the public repository. Evidence
directories are mode `0700`; individual artifacts are atomically written as
mode `0600`. Existing symlinks, FIFOs, and other non-regular destinations are
rejected. These protections reduce accidental disclosure but do not make the
contents public-safe.

The evidence set includes host snapshots, the gateway log, the packet
transcript, the Controller DHCP-authority audit, and structured
verification/result receipts. The automation records event names and results,
not serial bytes. Console input and plaintext credentials must never be
recorded. Keep a separate secret-free summary containing:

- date, operator, and Telos commit;
- canonical Controller-disk SHA-256 value;
- the dry-run boundary line;
- the manual operator-gate status and preflight `RESULT` line;
- the unittest summary;
- the runner's three final `PASS` lines;
- any firewall-observability `NOTE`;
- the local evidence-directory run ID, but not the contents of
  `before.json`, `during.json`, or `after.json`;
- the post-run process query;
- the matching post-run Controller-disk hash; and
- each failure and correction.

Do not put console passwords, detailed evidence JSON, private-overlay files,
real addresses, MAC addresses, UniFi exports, or household names in the
public repository.

## Decision after the rehearsal

| Result | Next action |
|---|---|
| Every check passes | Keep UniFi unchanged until the separately authorized physical network gate |
| A simulation check fails | Correct code or documentation, rebuild as required, and repeat from section 1 |
| Automated checks pass but the operator gate fails | Treat the cycle as failed; automation does not override the console observation |
| The canonical disk hash changes | Treat as a hard failure; do not attach the Controller |
| A host interface or non-loopback socket appears | Stop the simulation and investigate the isolation breach |

Physical same-L2 behavior, actual UniFi policy enforcement, switch-port
configuration, VLAN membership, and real attachment remain deferred to the
Controller Network Gate. This page never authorizes that gate.

[Return to Homelab →](../index.md)

[Read the later physical network gate →](../controller-network-gate/index.md)
