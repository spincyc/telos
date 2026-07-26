# ADR 0057: Record corrections to the deferred signing design

- Status: Accepted
- Date: 2026-07-25

## Context

ADR 0043 deferred ADRs 0029 through 0042 until the functional environment is
proven. Reviewing them as a group before that revalidation found three problems
worth recording now, so Milestone B starts from a corrected design rather than
rediscovering them.

## Decision

Do not act on this ADR during Milestone A. When ADRs 0029 through 0042 are
revalidated, treat the following as required inputs.

**1. The key separation in ADRs 0033 to 0035 is largely notional.** ADR 0033
makes the TPM policy key cryptographically distinct from the Secure Boot key,
which is correct. ADR 0035 then stores both on the same removable medium and ADR
0039 gives the primary and backup media the same passphrase. One compromised
passphrase yields both identities on both media, so the separation survives on
paper only. Either separate the custody or stop paying for the separation.

**2. ADR 0039's shared passphrase defeats the backup's independence.** A backup
exists to survive a failure the primary did not. Sharing its passphrase means a
credential compromise takes both copies simultaneously.

**3. ADR 0030's additive trust model may be infeasible on the actual hardware.**
Many consumer and OEM firmwares permit `db` modification only after entering
Setup Mode, which clears PK and therefore replaces platform ownership -- the
exact thing ADR 0030 forbids. ADR 0030 handles this by failing preflight, which
means the profile may simply not support the machine. Before Milestone B,
test enrollment on the real target firmware and decide what happens when it
cannot be done additively.

Also revisit whether three signed UKIs and two signing identities are
proportionate to a single-operator homelab, given the operational cost the
custody chain in ADRs 0036 through 0042 imposes.

## Consequences

- Milestone B begins with the known defects written down.
- No Milestone A behaviour changes.
- ADRs 0029 to 0042 keep their Deferred status; this ADR does not supersede
  them, it annotates them.
- If firmware testing shows additive enrollment is impossible, ADR 0030 needs
  replacement rather than adjustment.
