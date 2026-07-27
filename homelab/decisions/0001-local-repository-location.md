# ADR 0001: Local repository location

## Supersession

ADR 0046 supersedes this decision. The homelab design record now lives inside the Telos publication
repository, and the split between publishable profile documentation and private
instance data is defined there.
This ADR remains as the record of the earlier decision.

- Status: Superseded by ADR 0046
- Date: 2026-07-24

## Context

The infrastructure documentation needs a stable local Git working copy. The
handoff and active workspace used different operator-specific paths.

## Decision

Use one explicitly recorded operator-local path as the normal working copy and
initialize it as a Git repository with `main` as its initial branch.

## Consequences

- The active workspace is the canonical local checkout.
- This decision does not make the local checkout the only required copy.
- A Git remote and an off-host recovery copy remain separate open decisions.
- Repository structure beyond the minimal decision records remains open.
