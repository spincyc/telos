# ADR 0078: Permit private disposable Windows Setup automation

- Status: Accepted
- Date: 2026-07-27

## Context

ADR 0058 forbids an unattended installation path because a recorded answer set
could bypass the disk-serial confirmation that authorizes destructive work.
The workstation factory now needs repeatable Windows installation proof before
physical launch, while immutable PXE releases and the public repository must
remain free of credentials and machine-specific answers.

## Decision

Disposable QEMU acceptance may use generated Windows startup and answer files
only when all of these controls hold:

- the run uses a freshly created disposable disk with an exact, safely
  representable synthetic serial;
- a serial-bound authorization receipt names that disk, capacity, layout,
  selected immutable release, and generated-input digests before mutation;
- generated files live only in an ignored private run directory with modes
  `0700` for directories and `0600` for files;
- credentials and identities are synthetic, unique to the run, absent from
  process arguments, immutable releases, source caches, logs, and Git;
- edition, locale, disk selection, partition layout, and first-boot checks are
  explicit rather than inherited from Setup defaults;
- retained evidence contains digests and non-secret outcomes, never generated
  answer content or credentials; and
- teardown removes generated inputs and credentials on success, failure, and
  interruption.

The physical workstation path remains interactive at the authorization and
private-value boundaries. Its operator supplies real identity and credential
values at launch.

This narrowly supersedes ADR 0058's absolute prohibition on unattended code
for disposable QEMU Windows acceptance. ADR 0058 continues to govern physical
installation and any run that lacks the controls above.

## Consequences

- Local Windows installation can be repeated without weakening the physical
  erase boundary.
- Automation must fail closed before disk mutation if identity, serial,
  capacity, release, layout, permissions, or teardown guarantees differ.
- Generated Windows automation is runtime state, not a release artifact.
