# Guest progress reporting

Status: design decision; implementation pending

This document defines how a disposable Arch or Windows guest may report
installation and acceptance progress to the local factory harness. The channel
is an affirmative liveness and diagnostic signal. It does not replace the
harness's observations, receipts, deadlines, or acceptance gates.

## Outcome and boundary

Each factory guest gets the same small, versioned event protocol over a
dedicated QEMU named `virtserialport`. Linux connects the guest process to that
port through a systemd service. Windows uses a boot-triggered task during
installation and may replace it with a Service Control Manager service when
reporting must span the installed system's normal lifetime.

The host remains authoritative:

- a guest event can say that a phase started or that the guest believes it
  finished, but only host-side evidence can pass a gate;
- an event cannot extend a deadline, authorize a mutation, prove credential
  rotation, prove teardown, or cause the harness to skip an observation;
- missing, malformed, unauthenticated, replayed, or contradictory events are
  diagnostic failures, never inferred success;
- the guest never reports credentials, private identity values, tokens,
  tickets, key material, or unrestricted logs.

This is a host/guest backchannel, not a request for internet access. It works
inside the isolated factory with no routable network.

## Prior art

| Mechanism | Useful precedent | Limitation for this factory | Decision |
|---|---|---|---|
| QEMU Guest Agent (QGA) | QGA already defines a JSON host/guest protocol. Its [`guest-sync-delimited`](https://www.qemu.org/docs/master/interop/qemu-ga-ref.html#command-guest-sync-delimited) exchange uses a sentinel and nonce to discard stale stream data after connection or timeout. | QEMU documents that virtio-serial lacks normal connection semantics, so partial requests and unread replies can survive a client. QGA is a privileged, general-purpose agent whose RPC surface is broader than progress reporting. | Reuse its synchronization lesson. Keep QGA as a secondary diagnostic/probe path, with an explicit RPC allowlist; do not make it the progress transport. |
| Named virtio serial port | QEMU supports chardev-backed serial devices, and QGA's conventional virtio endpoint demonstrates stable named guest paths such as `/dev/virtio-ports/org.qemu.guest_agent.0` ([QGA manual](https://www.qemu.org/docs/master/interop/qemu-ga.html)). | A byte stream supplies neither message boundaries nor trustworthy reconnect state. Windows also requires the appropriate signed virtio driver before the named port can be used. | Use a separate, stable port name solely for the shared progress protocol. Add explicit framing, synchronization, sequence, authentication, and deadlines. |
| systemd readiness and watchdog | [`sd_notify(3)`](https://www.freedesktop.org/software/systemd/man/latest/sd_notify.html) separates `READY=1`, `STATUS=`, and `WATCHDOG=1`; [`systemd.service(5)`](https://www.freedesktop.org/software/systemd/man/latest/systemd.service.html) gives the supervisor bounded startup and runtime failure behavior. | Notifications are local to the Linux service manager and say nothing directly to the host harness. | Implement a small Linux bridge supervised by systemd. Map local readiness/status/watchdog state into the shared protocol without treating it as acceptance. |
| cloud-init `phone_home` | cloud-init can POST selected final-stage values to a templated URL and retry a configured number of times ([module example](https://docs.cloud-init.io/en/latest/reference/yaml_examples/phone_home.html)). | It assumes an HTTP endpoint, is primarily a final-stage callback, and does not provide the continuous, network-independent, authenticated phase stream needed here. | Copy its explicit field selection and bounded retry ideas, not its transport or payload. |
| Ignition | Ignition applies a versioned, declarative configuration during initramfs first boot and deliberately produces the requested machine or fails boot ([rationale](https://coreos.github.io/ignition/rationale/), [configuration specifications](https://coreos.github.io/ignition/specs/)). | It is a provisioning input mechanism, not a cross-platform progress protocol, and normally runs only on first boot. | Preserve its versioned schema and fail-closed validation principles. Do not embed another provisioner. |
| Afterburn | Afterburn is a one-shot metadata agent and, on supported providers, performs boot or first-boot check-in ([overview](https://coreos.github.io/afterburn/), [platform matrix](https://coreos.github.io/afterburn/platforms/)). | Its check-in is provider-specific and not a general Windows/Linux local-hypervisor protocol. | Follow its separation between metadata acquisition and check-in, while keeping the Telos receiver provider-neutral. |
| Windows Task Scheduler and SCM | A Task Scheduler [`BootTrigger`](https://learn.microsoft.com/en-us/windows/win32/taskschd/starting-an-executable-on-system-boot) starts an action after boot and supports a delay. SCM maintains service startup and security configuration ([About Services](https://learn.microsoft.com/en-us/windows/win32/services/about-services)). | A task is appropriate for bounded install/first-boot work but weak for a continuously supervised agent. A service adds installation and privilege surface. | Use a boot task for disposable installation phases. Use a narrowly privileged auto/trigger-start service only where reporting must survive into normal installed-system operation. |
| CloudEvents | [CloudEvents](https://github.com/cloudevents/spec/blob/ce%40stable/cloudevents/spec.md) standardizes a small event envelope and requires identity, source, type, and specification version attributes. | Its transport bindings and full extension model are unnecessary here, and conformance would add surface without changing the local protocol's guarantees. | Use a CloudEvents-shaped envelope and vocabulary, but define and validate a closed Telos schema rather than claim CloudEvents conformance. |
| JCS and HMAC | [RFC 8785](https://www.rfc-editor.org/rfc/rfc8785) gives JSON one deterministic UTF-8 representation. [RFC 2104](https://www.rfc-editor.org/rfc/rfc2104) defines HMAC message authentication. | A MAC does not hide data, and a shared key alone does not prevent replay. Cross-language number handling can also undermine canonicalization. | Authenticate the canonical envelope with HMAC-SHA-256, prohibit non-integer JSON numbers, and bind every message to an attempt nonce and increasing sequence. |

## Chosen topology

```text
Arch systemd unit ─┐
                   ├─ Telos event encoder ─ named virtserialport ─ host receiver
Windows task/SCM ──┘                              │
                                                ├─ receipt/evidence correlation
COM1 (reduced fallback) ─────────────────────────┤
QGA (secondary probes only) ─────────────────────┘
```

The QEMU device is a dedicated named port, not the console, QMP socket, QGA
port, or a network socket. The name is a public protocol constant and must fit
the shortest supported platform/device-name limit. Each boot gets a fresh
host-side socket and a fresh attempt nonce. The receiver must refuse a
pre-existing socket, unexpected peer, symlinked path, or data arriving before
the current attempt is armed.

COM1 is the reduced fallback because it is available earlier and on more
Windows images. It emits only a fixed prefix followed by a single canonical
event per line. It must coexist with human-readable console output and
therefore cannot carry secrets, commands, acknowledgements, or a claim of
authenticated success. COM1 events may improve failure classification, but
they never satisfy an acceptance gate.

QGA is secondary. The harness may use a strictly allowlisted QGA command to
check agent reachability or retrieve an already-created, secret-free diagnostic
receipt. On initial contact and after any timeout it must perform
`guest-sync-delimited` and discard input until the nonce is returned. QGA
failure cannot silently switch an authoritative gate to guest assertion.

## Event and stream contract

The implementation should publish a JSON Schema and test the same fixtures in
the Linux, Windows, and host implementations. Each message is one unsigned
32-bit big-endian length followed by that many UTF-8 bytes of RFC 8785
canonical JSON. The maximum frame is 16 KiB. Zero length, oversize, invalid
UTF-8, duplicate keys, unknown fields, non-integer numbers, and noncanonical
encoding fail the connection.

The closed envelope contains:

| Field | Meaning |
|---|---|
| `specversion` | Telos guest-progress schema version. |
| `id` | Attempt-scoped event UUID. |
| `source` | Fixed role/OS producer identifier, never a private hostname. |
| `type` | Allowlisted event type: `sync`, `phase-started`, `heartbeat`, `phase-finished`, `phase-failed`, or `diagnostic-ready`. |
| `time` | Guest UTC timestamp for correlation only; host receive time controls deadlines. |
| `attempt` | Opaque public attempt identifier assigned by the host. |
| `boot_id` | Opaque per-boot value; changes across reboot. |
| `sequence` | Nonnegative JSON-safe integer (`0..9007199254740991`), strictly increasing within `(attempt, boot_id, producer)`. |
| `phase` | Allowlisted factory phase or `null` where the type does not use one. |
| `status` | Exact type-dependent coordinate: `sync=starting`, `phase-started=active`, `heartbeat=active`, `phase-finished=complete`, `phase-failed=failed`, and `diagnostic-ready=ready`. |
| `progress` | Optional integer `0..100`; display only, never used to infer completion. |
| `diagnostic` | Optional identifier and digest of a secret-free bounded receipt, not its unrestricted contents. |
| `mac` | Canonical Base64 HMAC-SHA-256 using a per-attempt key of at least 32 bytes. The authenticated bytes are `telos-guest-progress-v1`, one NUL byte, then the JCS encoding of the envelope with `mac` omitted. |

Before ordinary events, the guest sends `sync` containing the host-provided
attempt nonce and a new `boot_id`. The host acknowledges the exact
`(attempt, boot_id, sequence, id)` tuple. Until that acknowledgment, the guest
may retransmit the identical frame but may not reuse its sequence for different
content. The receiver deduplicates identical tuples, rejects tuple/content
collisions, rejects sequence rollback, and resets parser state when a transport
reconnect begins. Keys and nonce material are per attempt, never reused, never
printed, and destroyed during the same teardown whose completion the harness
already proves.

The protocol is observation-only in its first version. The host sends
acknowledgments and synchronization challenges, not commands or authorization.
Adding host-to-guest actions requires a separate threat model and decision.

## Deadlines and failure semantics

All limits are host-monotonic and clamped to the enclosing phase deadline.
Guest wall-clock timestamps and reported percentages never alter them.
Defaults are deliberately explicit and may only be changed in reviewed
configuration:

| Limit | Default | Result when exceeded |
|---|---:|---|
| Named-port appearance/open after the reporting service starts | 30 seconds | Mark primary transport unavailable; enable COM1 observation and optional QGA probe. Do not fail an otherwise independently observable installation solely for missing progress. |
| First authenticated `sync` after the OS reaches the service/task start boundary | 60 seconds | Record `progress-sync-timeout`; continue only until the enclosing phase deadline. |
| Host acknowledgment after a valid frame | 5 seconds | Guest retries the identical frame with bounded exponential backoff; it does not advance sequence until acknowledged or the enclosing deadline expires. |
| Heartbeat interval while a reported phase is active | 10 seconds | One missed heartbeat is tolerated. |
| Silence after the last valid authenticated event | 30 seconds | Record `progress-stalled`, take bounded secondary observations, and keep the phase's original deadline. |
| Receiver drain during teardown | 5 seconds | Stop accepting new events, persist only already-validated events, close and destroy the socket/key state, and report cleanup failure if absence cannot be proved. |

The harness still owns a separately configured absolute deadline for every
installation or acceptance phase. Progress never resets or extends it.
Transport retry ends at the earlier of its local limit and that phase
deadline. When the phase deadline expires, the harness captures the last valid
coordinate and any bounded secondary diagnostics, then follows the existing
failure and teardown path.

The receiver distinguishes:

- **absent:** no valid event was received;
- **unavailable:** the expected device, driver, task, or service could not be
  observed;
- **malformed:** framing or schema validation failed;
- **unauthenticated:** the MAC, attempt, or synchronization challenge failed;
- **replayed:** a prior boot/sequence/event tuple was reused incorrectly;
- **stalled:** valid events stopped beyond the silence deadline;
- **contradictory:** a reported transition violates the phase state machine;
- **cleanup-unproved:** socket, key publication, listener, or process absence
  could not be proved.

None of these states becomes success. A missing progress channel may coexist
with acceptance only when every relevant gate has independent authoritative
evidence. An authenticated `phase-finished` event merely tells the harness
which observation to try next.

## OS integration

### Linux

Install a systemd-supervised bridge with explicit device ordering and a
restricted service sandbox. The bridge waits boundedly for the named port,
maps `READY=1`, bounded `STATUS=`, and watchdog activity into the shared event
types, and exits nonzero on protocol or transport failure. systemd restart
limits must fit inside the host phase deadline. The journal remains useful for
local diagnosis, but only allowlisted status coordinates cross the port.

### Windows

During setup and first boot, register a Task Scheduler boot task under a
narrow built-in principal, with a bounded start delay and execution time
limit. It waits boundedly for the signed virtio serial driver/device and then
starts the same schema encoder. If the named device is unavailable, it emits
the reduced COM1 coordinate and exits with a classified code.

Use an SCM service only for phases that must survive task completion or accept
service lifecycle supervision. Its account, service ACL, executable path,
binary signature/provenance, restart policy, and allowed device ACL must be
explicitly verified. Neither form runs arbitrary scripts received from the
host.

## Acceptance criteria

Implementation is complete only when tests prove:

1. identical fixtures are accepted and rejected on host, Linux, and Windows;
2. fragmented, coalesced, truncated, oversized, stale, replayed, reordered,
   forged, and noncanonical frames fail closed;
3. reconnect synchronization cannot consume stale bytes as a current event;
4. every timeout is bounded by the original host phase deadline;
5. loss of the primary channel exercises COM1 and QGA diagnostic branches
   without upgrading either to authoritative evidence;
6. a false guest success cannot pass an independent host gate;
7. keys, sockets, tasks/services, helper processes, QGA publication, and COM1
   capture are absent after successful and failed teardown; and
8. retained events and diagnostics are bounded and secret-free.
