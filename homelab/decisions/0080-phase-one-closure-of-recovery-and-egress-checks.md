# ADR 0080: Close phase one with partial recovery and a waived egress counter

- Status: Accepted
- Date: 2026-09-30

## Context

ADR 0077 requires the complete Controller and dual-boot lifecycle to pass
inside the local QEMU network, twice from the same verified inputs, before any
UniFi change or physical attachment. Two parts of that lifecycle cannot reach
`pass` as built.

Lifecycle recovery (ledger gate 11) has eight scenarios. Three are provable
in the loopback lab without a guest and pass. Two need a live guest boot and
are implemented (`directory-dns-loss`, `controller-reconstruction`) but have
not run. Three have no primitive to drive them: a Controller restart as
distinct from a SIGSTOP/SIGCONT outage, a bootloader break and repair, and an
install fault-injection seam. The judge renders `partial` whenever any
scenario defers, by construction.

Repeatability (ledger gate 12) grades sixteen checks. `host_network_changes`
carries a `unifi` contact counter that no snapshot pair can prove, because a
connection can open and close between two snapshots; only a run-window host
egress ledger could, and nothing produces one. The check therefore can never
render `pass`.

## Decision

The owner decided on 2026-09-30:

- **Gate 11 closes phase one at `partial`.** The three loopback scenarios and
  the two implemented live-boot scenarios must run and pass. The Controller
  restart, broken-boot repair and failed-install recovery scenarios are
  deferred past phase one. The judge's verdict stays `partial`, is recorded as
  such, and is never relabelled `pass`.
- **Gate 12 waives `host_network_changes` for the loopback factory.** The
  runner conditions of ADR 0077 already confine every guest NIC to an audited
  host-loopback hub with no route off the host, and audit planned and live
  process arguments; the counter adds no proof inside that boundary. The
  check is recorded as waived under this ADR, never as `pass`, and every other
  gate-12 check, including the twice-through comparison, still has to pass.
- No run-window egress recorder is built now. The waiver lapses at gate 14:
  a factory attached to a real network must prove its egress directly.

This supersedes ADR 0077's "complete lifecycle must pass" only for these two
items. Everything else in ADR 0077 stands, including its twice-through
requirement and its statement that it authorizes no UniFi query or change,
host bridge, physical attachment or physical erasure.

## Consequences

- Once gate 11 reaches `partial` with exactly those three deferrals and gate 12
  passes with only the waived check, ADR 0077 no longer blocks the separately
  authorized gate-14 stages.
- The aggregate verdict code must represent a waiver distinctly from `pass`
  and from `NOT RUN`, naming this ADR, so a receipt cannot be misread as full
  acceptance.
- The three deferred recovery scenarios and the egress recorder remain
  recorded work for a later phase, not closed work.
