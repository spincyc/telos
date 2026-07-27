# Durable agent journal protocol

`.journal/` is every agent's committed operational memory. Chat and process
state are caches; recover from Git and this directory.

## Operating loop

### Recover

Before mutation:

1. Resolve the repository root and Git common directory.
2. Observe branch or detached state, HEAD, remotes, and working tree.
3. Generate an agent-instance UUID.
4. Read `state.md`, `queue.md`, active task state, relevant decisions and
   events, and all leases.
5. Reconcile records with Git and the filesystem; record discrepancies.
6. Keep paths, hostname, PID, and other host data only in ignored `runtime/`.

### Ingest

Before acting, record every user message as an immutable event classified
`new-task`, `amendment`, `decision`, `control`, `information`, or `question`.
Only `new-task` creates a task.

For a new task, record a faithful summary, title, goal, draft acceptance
criteria, constraints, priority, likely dependencies, overlap, and possible
supersession. Preserve the request verbatim except explicit redactions for
secrets or host data. Create its UUID and standard subtree, queue it, and
commit before acknowledgment.

New work does not interrupt active work unless the user clearly directs it or
continuation is unsafe, destructive, or invalid. Attach corrections and
controls to existing tasks.

### Schedule

Before concurrent activation, document overlap analysis across files,
behavior, interfaces, tests, dependencies, Git state, generated artifacts,
and external mutable resources. Uncertainty prevents concurrency; serialize
unsafe work on the current branch.

At each scheduling boundary, reassess nonterminal tasks for priority,
dependencies, supersession, duplication, parallel safety, conflicts, and
starvation. Prefer:

1. active or unblocked work;
2. prerequisites;
3. explicit priority;
4. the oldest runnable request.

Ambiguous replacement becomes `supersession-proposed`, not cancellation.
Choose documented, safe, reversible assumptions. Ask only when all reasonable
paths need unavailable authority or credentials, cause irreversible or
external effects, or materially change the product. Continue other runnable
work when one task blocks.

Follow `AI_GUIDANCE.md`'s collaboration rules. Be critical without flattery or
performative opposition; make concerns useful and preserve momentum.

### Checkpoint

Hold `.journal/.lock/` only during ingestion, queue rebuilds, state changes,
staging, and commits—not implementation, tests, research, or chat.

Commit locally:

- after new-task ingestion;
- after consequential decisions;
- at task transitions;
- after verified implementation units;
- before risky or long operations;
- before yield, handoff, or likely context loss;
- after recovery or queue reconciliation changes state.

Commit one task's journal and attributable implementation together. Never
capture, stash, discard, or rewrite pre-existing user changes.

Use:

```text
Imperative summary

Task-ID: <task-uuid>
Decision-ID: <decision-uuid>
```

Use `Journal-Scope: repository` when no task applies. Do not record a commit's
own SHA; trailers link it to journal records.

After completion, rebuild and reassess the queue, then start the next runnable
task. Yield only when none is runnable, authority is missing, or the
environment forces handoff.

## Data model

- `state.md`: repository recovery snapshot.
- `queue.md`: rebuildable view; never authoritative.
- `repository/{events,decisions}/`: immutable repository records.
- `tasks/<uuid>/state.md`: authoritative task record.
- `tasks/<uuid>/{events,decisions}/`: immutable task records.
- `leases/<uuid>/state.md`: durable execution ownership.
- `runtime/`, `.lock/`: ignored host-local coordination.

Statuses: `queued`, `active`, `verifying`, `blocked`,
`supersession-proposed`, `superseded`, `done`, `cancelled`. Readiness and
parallel safety are derived.

Dependencies form a directed graph. Hard dependencies block activation; soft
dependencies suggest order. `parent` is decomposition; `discovered_by` is
provenance. Derive reverse `blocks` links. Cycles are invalid.

Priorities: `critical`, `high`, `normal`, `low`. Reserve `critical` for safety,
data loss, or active breakage. Explicit user priority remains subject to hard
dependencies and parallel safety.

Use UTC RFC 3339 timestamps and UUID identity. Never move or delete terminal
task directories.

## History

Committed events and decisions are immutable. Correct them with a new linked
record. A consequential decision changes scope, architecture, interfaces,
dependencies, security, compatibility, data handling, scheduling,
concurrency, acceptance criteria, or agreed direction. Put routine details in
events.

A superseding decision records `supersedes`, rationale, and consequences.
Keep the prior record. Store cross-task decisions under `repository/`.

## Locks and leases

Create `.journal/.lock/` atomically. Its `owner.json` records lock UUID, agent
UUID, PID, hostname, boot ID if available, process-start identity, time,
operation, and task UUIDs. Release only a matching lock UUID.

PID alone does not prove liveness. Check environment, process-start identity,
runtime ownership, and Git/journal progress. Allow new incomplete locks a
short grace period. Never steal a foreign or indeterminate lock. Continue
read-only or unrelated implementation while waiting.

A committed lease is ownership, not a mutex. Time only prompts investigation.
Reclaim after reconciliation and an immutable recovery event.

## Reread and validate

Reread top-level and relevant task state at cold start, recovery, handoff,
message ingestion, scheduling, activation, every checkpoint, unexpected Git
changes, completion, and yield.

```sh
python3 .journal/bin/journal.py validate
python3 .journal/bin/journal.py rebuild-queue
```

Validation covers schemas, UUIDs, references, cycles, statuses, priorities,
immutable record structure, queue reproducibility, and leases. Failure blocks
the checkpoint, not unrelated read-only progress.
