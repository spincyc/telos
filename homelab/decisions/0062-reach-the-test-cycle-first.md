# ADR 0062: Reach a running install cycle before hardening the installer

- Status: Accepted
- Date: 2026-07-26

## Context

The installer's pure-logic core is written and tested: network-plan validation,
the prompt registry, hardware collection, preflight judgement, the step runner
and the manifest. The next work was heading toward a second privileged test tier
(ADR 0061) and a plan/verify pair for every disk operation, before any end-to-end
installation had ever been run.

That is refinement ahead of evidence. Nobody has yet watched this installer fail
on a real target, so we do not know which failures are common, which messages
are unclear, or which steps are fragile. Hardening against imagined failures
costs time and biases the design toward the author's guesses.

## Decision

Reach a running install cycle first. Specifically:

- ADR 0061 is superseded. There is no loopback test tier.
- `disks.py` provides the commands to run and nothing else. The `verify_*`
  functions that re-read and parse `sgdisk`, `cryptsetup` and `btrfs` output are
  removed; in the QEMU matrix a wrong layout presents as a machine that does not
  boot, within about ninety seconds.
- Priority order is now: installer entry point, Archiso profile, QEMU matrix,
  then a real install on the spare machine.
- Hardening resumes after the cycle exists, directed by what actually fails.

Retained deliberately, because retrofitting them is expensive and they are what
stands between an operator error and an erased disk:

- the validation layer --- `netplan`, `prompts`, `preflight`;
- the structural authorization token in `steps.py`; and
- the manifest's non-secret guarantee.

## Consequences

- Time to first observed installation drops from days to about a session.
- Layout defects are caught as boot failures rather than as assertions, which is
  slower per defect but arrives far sooner overall.
- The default test suite stays fast and unprivileged, and CI needs no
  privileged runner.
- Some of ADR 0061's content will likely return once the matrix starts finding
  layout bugs it cannot explain. Reinstating it then will be cheap and informed.
- This ADR is a statement about sequencing, not about standards. Nothing here
  lowers the bar for the code that gates destruction.
