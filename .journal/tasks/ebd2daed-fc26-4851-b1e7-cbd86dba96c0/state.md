---
schema_version: 1
task_uuid: "ebd2daed-fc26-4851-b1e7-cbd86dba96c0"
title: "Restore repository verification gate"
status: "done"
priority: "high"
priority_reason: "Broken repository-wide check blocks trustworthy feature verification"
parent: null
discovered_by: null
hard_dependencies: []
soft_dependencies: []
related_to: ["97541f7d-8649-4520-af30-9bd8deba2b00"]
superseded_by: null
created_at: "2026-07-27T21:51:49Z"
updated_at: "2026-07-27T21:54:51Z"
---

# Goal

Fix `make check` and `make homelab-test` so homelab tests use a consistent
repository-root import model, while separately classifying sandbox socket
permission failures without weakening tests.

## Acceptance criteria

- The import/discovery failure is corrected with the smallest coherent change.
- Small affected tests and complete relevant checks pass, or environmental skips are reported.
- Invocation documentation reflects tested behavior.

## Scope and concurrency

Owns root/homelab test invocation and directly related documentation only.
Safe to run alongside read-only factory audits, but shared Makefile edits must
be serialized.

## Result

All repository test entry points now use a consistent repository-root import
model. The full unsandboxed `make check` passed 31 root tests and 800 homelab
tests together with site, research, and package-closure validation.
