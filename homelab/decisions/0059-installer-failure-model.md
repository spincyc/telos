# ADR 0059: Fail fast, leave the evidence, do not roll back or resume

- Status: Accepted
- Date: 2026-07-26

## Context

The installer runs one long destructive sequence: partition, encrypt, create
filesystems, install the base system, write boot artifacts, record the manifest.
Any step can fail. The design needs one answer for what happens next, chosen
before the code is written rather than improvised per step.

Three models were considered: stop and report; roll back to an empty disk; or
checkpoint each step so a re-run can resume.

The disk is unrecoverable from the moment partitioning begins. There is
therefore no user data left to protect, and the thing actually worth preserving
after a failure is the evidence of why it failed.

## Decision

**Stop at the failing step. Change nothing further. Report precisely.**

- No rollback. A cleanup path is a second destructive code path that only ever
  executes when something is already wrong, and running it destroys the state
  that explains the failure.
- No resume. Resume logic must reason correctly about state it did not observe,
  which is where installers grow their worst bugs. A re-run starts from the
  beginning.
- On failure the installer prints: the steps that completed, the step that
  failed, the exact command, its exit status, and its captured output; then
  states plainly that the disk is **not bootable** and that the fix is to run
  the installer again.
- The installer exits non-zero so the acceptance harness can detect it.

Steps are declared as either non-destructive or destructive. **A destructive
step cannot execute without an authorization token**, and that token can only be
produced by the confirmation described in ADR 0058. This is structural, not a
convention: there is no boolean to pass by mistake.

## Consequences

- A failed installation leaves a machine that will not boot. That is stated in
  the failure output rather than discovered at the next power-on.
- The failure report is the primary debugging artefact, so its quality matters
  as much as the happy path's.
- Re-running is always safe in the sense that it repeats the same authorization
  and the same destruction; it is never safe in the sense of preserving
  anything.
- The acceptance matrix under ADR 0056 can assert on failure output as well as
  on success, because failures are deterministic and fully reported.
- If installation ever becomes slow enough that restarting is painful, that is
  an argument for making steps faster, not for adding resume.
