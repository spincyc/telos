---
schema_version: 1
task_uuid: "c0fc1fa3-1f4f-46e6-8167-9f6eca031d6e"
title: "Complete homelab documentation pass"
status: "queued"
priority: "normal"
priority_reason: "User-facing documentation must follow stabilized implementation"
parent: null
discovered_by: null
hard_dependencies: ["6e525567-4ef1-4c2e-ab52-ab099a87c780"]
soft_dependencies: []
related_to: ["a8c935bc-acd4-4a2d-bc7d-cc0c81e422a8"]
superseded_by: null
created_at: "2026-07-27T21:51:57Z"
updated_at: "2026-07-27T21:51:57Z"
---

# Goal

Execute all 16 topics in `homelab/DOCUMENTATION-PASS.md` as concise guides
plus exact runbooks whose commands and acceptance claims match tested behavior.

## Acceptance criteria

- Every mutation has observation, verification, stop, rollback, evidence, and secret-free diagnostics.
- Migration, maintenance, recovery, decommissioning, private overlay, and cross-document acceptance are covered.
- Rendered HTML, links, privacy, accessibility, responsive layout, unsupported-state labels, and fresh-clone usability are checked.
- Homelab remains Markdown/HTML-first; PDFs do not block completion.

## Scope and concurrency

Owns homelab documentation after factory behavior stabilizes. Read-only
documentation inventory can run earlier, but normative edits wait on upstream
acceptance.
