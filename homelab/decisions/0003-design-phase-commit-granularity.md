# ADR 0003: Design-phase commit granularity

- Status: Accepted
- Date: 2026-07-24

## Context

The architecture is being developed one material decision at a time, but the
concepts affect one another and need to be integrated into coherent documents.
Creating a commit for every conversational decision would fragment the initial
design before its major parts fit together.

## Decision

During the initial architecture and design phase, accumulate and integrate
related decisions into larger coherent sections before committing them.

After the design foundation exists, use smaller, focused commits for
implementation work and later revisions.

## Consequences

- Accepted design decisions are recorded in working-tree ADRs immediately, but
  need not be committed immediately.
- The initial uncommitted working tree may contain several related accepted
  decisions.
- A design commit should represent a coherent, reviewable body of architecture
  rather than an arbitrary number of conversational steps.
- Later operational changes should retain a narrower commit scope.
