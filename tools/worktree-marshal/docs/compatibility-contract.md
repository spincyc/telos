# Triptych Compatibility Contract

## Purpose and authority

This document freezes the observable compatibility baseline for extracting
`scripts/triptych-codex` into Worktree Marshal. It describes the legacy
launcher at schema version 1. The package now contains that compatibility
engine, while the repository-local command remains its stable entry point.

Until an extraction change deliberately replaces a behavior and supplies a
migration, the compatibility engine and its legacy black-box tests remain
authoritative.
Existing retained runs must continue to be managed by code that understands
their exact legacy identity. A generic command must not silently adopt,
rename, rewrite, or clean legacy state.

The installed command may address this domain only through the explicit
spelling `worktree-marshal --profile triptych COMMAND ...`. Its parser maps
the generic command words to the legacy options below and then enters this
adapter. It does not change the state base, manifest, branch, ref, environment,
lock, diagnostic, or Codex-policy identity. Omitting `--profile triptych`
never selects this domain by discovery or fallback.

## Legacy identity

The compatibility mode owns these exact identifiers:

- executable and diagnostic name: `scripts/triptych-codex` and
  `triptych-codex`;
- manifest schema: integer `1`;
- run ID grammar: eight UTC date digits, `t`, six time digits, `z-`, and
  twelve lowercase hexadecimal digits;
- worker branch prefix: `codex/isolated/`;
- private ref prefix: `refs/triptych-codex/runs/`;
- environment variables: `TRIPTYCH_CODEX_ROLE`, `TRIPTYCH_CODEX_REAL`,
  `TRIPTYCH_CODEX_STATE_DIR`, and `TRIPTYCH_CODEX_RUN_ID`; and
- linked-worktree lock reason prefix: `triptych-codex `.

The state-base override in `TRIPTYCH_CODEX_STATE_DIR` must be absolute. Without
it, the base is `$XDG_STATE_HOME/triptych-codex` when `XDG_STATE_HOME` is an
absolute path. When it is unset, the base is
`$HOME/.local/state/triptych-codex`; a set relative `XDG_STATE_HOME` is
rejected. Beneath that base, each repository owns a directory formed from a
normalized checkout name and the first twelve hexadecimal digits of the
SHA-256 digest of its common Git-directory path.

Each repository directory contains `repository.lock`, `runs/`, `worktrees/`,
and `tmp/`. One run owns matching `<run-id>` entries in the latter three
locations: a JSON manifest and lock under `runs/`, a linked worktree under
`worktrees/`, and its only run-scoped temporary directory under `tmp/`.

## Manifest and durable-state behavior

The allocation record begins with these fields:

- `schema_version`, `run_id`, `state`, `created_at`, and `updated_at`;
- `base_sha`, `target_ref`, and `branch`;
- `control_root`, `common_git_dir`, and `relative_cwd`; and
- `worktree` and `tmpdir`.

Lifecycle operations add audit, integration, conflict, rollback, cleanup, and
retirement checkpoints. Schema 1 accepts these lifecycle states:

```text
allocating
allocation-failed
ready
running
preserved
failed-preserved
interrupted
quarantined
retirement-pending
retirement-ref-cleanup-pending
cleaned
cleaned-branch-retained
integration-conflict
integration-continue-pending
integration-review-pending
integration-manual-landing-pending
integration-abort-pending
integration-abort-recovery-failed
integration-rebase-pending
integration-rebase-recovery-failed
integration-rebase-rollback-pending
integration-rebase-rollback-failed
integration-merge-pending
integration-merge-failed
integration-verification-pending
integration-verification-failed
integrated-pending-cleanup
integration-cleanup-pending
integration-cleanup-failed
cleaned-ref-retained
```

Manifests are private UTF-8 JSON files written with sorted keys, two-space
indentation, a trailing newline, atomic replacement, file synchronization, and
parent-directory synchronization. The state root and its `runs`, `worktrees`,
and `tmp` containers are mode `0700`; manifest and lock files are mode `0600`.
Loading validates the schema, run identity, repository identity, state, paths,
refs, branches, and recorded object IDs and fails closed on an inconsistency.

A future manifest schema must be versioned explicitly. Migration must be
tested against retained schema-1 runs and must never make an older executable
silently misinterpret newer state. Merely installing or invoking Worktree
Marshal is not authorization to migrate or delete state.

## Legacy command surface

With no Triptych lifecycle option, the launcher creates a unique locked
worktree from a stable, clean primary checkout and starts Codex there. The
direct lifecycle surface is:

```text
--triptych-status [RUN_ID]
--triptych-reopen RUN_ID [-- CODEX_ARGUMENTS...]
--triptych-resolve RUN_ID
--triptych-continue RUN_ID
--triptych-abort RUN_ID
--triptych-final-diff RUN_ID
--triptych-integrate RUN_ID
--triptych-clean RUN_ID
--triptych-retire RUN_ID --discard-head FULL_OID --target-contains FULL_OID
--triptych-help
```

All commands currently discover and validate a non-bare Git working tree,
including help. Operator errors return status 2. An invoked Codex process has
its exit status normalized and propagated. Reopen starts a new Codex process;
it does not resume a prior conversation.

The Triptych Make interface exposes `codex`, `status`, `reopen`, `clean-run`,
`integrate`, `resolve`, `continue`, `abort`, and `final-diff`. Except for the
status overview, its original interface accepted the opaque run ID as a second
Make goal, such as `make integrate <run-id>`. The extracted fragment documents
`make integrate RUN=<run-id>` as the preferred form. Triptych enables the
fragment's positional compatibility mode so both forms remain usable during
the migration; generic consumers do not enable that mode by default. The
direct launcher is the required interface for untrusted or external values.
Retirement deliberately has no Make target.

## Lifecycle invariants

- Allocation requires a stable, clean primary checkout and refuses nested
  allocation from a managed linked worktree.
- Each worker has a unique locked branch and linked worktree. Repository and
  run locks serialize their respective lifecycle transitions.
- Workers and resolvers receive the same exact run-owned path as `TMPDIR`,
  `TMP`, and `TEMP`; managed cleanup authenticates and removes that directory.
- An unchanged first successful run may be cleaned automatically. Changed,
  committed, failed, interrupted, inconsistent, or still-active work is
  retained or quarantined rather than discarded.
- Cleanup fails closed unless it proves the managed worktree, branch, head,
  index, temporary directory, and relevant private refs are in the expected
  state. A run is not marked cleaned while its temporary path remains.
- Integration requires separate authorization and a clean, audited worker.
  It confirms already-contained work, lands a linear result with an
  expected-old ref transaction, or performs the launcher-owned rebase of the
  audited linear worker commits. It never creates a merge commit.
- A genuine rebase conflict stays in the managed worker. The resolver may edit
  and stage only recorded conflict scope; only the launcher may continue or
  abort the rebase.
- Successful manual continuation stops at a clean review-pending candidate.
  `final-diff` compares exact objects without exposing the private worktree.
  Landing that candidate requires fresh authorization and an unchanged
  captured target.
- Hooks, signing, credential prompts, pagers, and editors are disabled for
  launcher-owned Git operations as applicable. The launcher does not push or
  deploy.
- Retirement is a separately authorized destructive exception. It uses exact
  object arguments, durable checkpoints, an anchored discard head, a
  containment check, and an atomic branch/anchor/receipt transaction. It does
  not move the target or establish semantic equivalence.

## Codex adapter boundary

The legacy implementation supports Codex only. Its extracted selector treats
a nonempty `TRIPTYCH_CODEX_REAL` value as the sole candidate and requires that
spelling to be absolute. When the variable is absent or empty, it scans the
inherited executable path in order for the literal name `codex`, treating an
empty path entry as the current directory. It skips metadata-read failures,
nonregular or nonexecutable files, and any candidate whose followed device and
inode match the authenticated launcher snapshot. The returned pathname is the
selected spelling made absolute by `candidate.absolute()`, not a canonical
resolution. In this contract, “real Codex” means only a usable non-launcher
candidate under those point-in-time checks.

The exact selection failures remain
`TRIPTYCH_CODEX_REAL must be an absolute path`,
`TRIPTYCH_CODEX_REAL does not name a usable non-launcher executable`, and
`cannot find the real Codex executable; set TRIPTYCH_CODEX_REAL` for,
respectively, a relative override, an unusable override, and unsuccessful
inherited-path search.

The extracted static argument policy accepts only the interactive, `exec`, and
`review` agent surfaces and their scoped allowlisted options. Unknown options
fail closed, known non-agent command surfaces are rejected, an explicit `--`
is preserved, and an implicit free-form prompt receives `--` so command-like
words remain data. A separated image option is normalized into one token so
its value is not classified as a command. These transforms preserve the
legacy input-copy, argument order, partial-failure, and diagnostic behavior.

The fixed argv prefix uses the executable and working directory supplied by
the engine, disables Codex multi-agent mode, clears additional writable roots
and sandbox permissions, and defaults to Codex `workspace-write` sandboxing.
A caller may narrow that to `read-only` but may not request a broader sandbox
through the launcher. The adapter module now owns executable candidate
selection, the static option and command sets, scoped option scanning, prompt
normalization, this argument-level configuration, and the sanitized Codex base
environment transform plus deterministic runtime-marker enrichment. The engine
retains profile binding and lifecycle hints, compatibility wrappers and
validation timing, working-directory authentication and choice, role
selection, manifest authority, the Git-sanitized mapping source,
linked-worktree refusal checks, process creation and replacement, inherited
descriptors, and lifecycle policy. No common base-adapter contract exists yet.

The base transform starts from the engine-supplied Git-sanitized mapping. It
removes all built-in Triptych and Worktree Marshal role, real-Codex, run,
profile, and agent marker names, then sets `TRIPTYCH_CODEX_REAL` to the
selected executable spelling. It prefixes that executable's lexical parent to
the executable path, removing every prior entry with exactly the same string
while preserving every other entry and its order. The engine supplies that
base mapping and selects which shared enrichment mode to invoke. For an
ordinary Triptych worker or resolver, the adapter operation adds the selected
role, the manifest's run marker, and its one exact run-owned path as `TMPDIR`,
`TMP`, and `TEMP`. For Triptych linked-worktree pass-through it adds only the
worker-role marker because this profile has no profile or agent marker names;
it receives no retained-run manifest and adds no run or temporary-path marker.

Selection does not verify executable provenance, signature, version, or actual
Codex behavior; exclude copies or wrappers; pin a descriptor or device/inode
identity; close the stat/access/use replacement window; or confer sandbox
assurance. Metadata lookup follows symbolic links, and the selected link or
file may be replaced later. The static allow and deny policy is
version-sensitive and assumes that the selected executable continues to honor
the recognized Codex argument grammar and precedence. Argument construction
does not constrain reads, credentials, providers, or network access or itself
create an operating-system sandbox. The base-environment transform removes
only Git-sensitive channels through the existing Git sanitizer and the
explicit launcher control markers above; it does not remove arbitrary host
variables or credentials. Its executable-path comparison does not
canonicalize or authenticate entries or remove aliases and equivalent
spellings. Marker enrichment adds coordination metadata but does not strengthen
that isolation boundary. A generic core must not claim the same containment
for another agent unless an agent-specific policy and enforcement layer
provide and test equivalent behavior.

## Threat boundary and platform assumptions

The launcher hardens its own Git operations: it pins a resolved Git executable
pathname, removes Git configuration and tracing environment channels,
disables replace objects, hooks, signing, editors, pagers, and terminal
credential prompts, validates relevant effective Git configuration, and uses
exact ref and object checks for destructive transitions.

That is not a complete operating-system sandbox. The child inherits much of
the host environment after Git-specific sanitization. The launcher does not
independently remove arbitrary credentials, block the network, constrain every
executable, or prevent an unconfined child from invoking Git or remote tools.
Its workspace containment relies on the Codex sandbox settings it enforces.
Consequently, an arbitrary-command or unconfined-agent adapter must not be
presented under the legacy assurance boundary.

The implementation also relies on POSIX facilities including `fcntl` locks,
inherited file descriptors, directory descriptors, no-follow opens, signals,
and POSIX rename and unlink semantics. Native Windows is outside the frozen
platform contract; WSL or a future separately tested backend is required.

The launcher protects managed lifecycle state against accidental changes,
races, path replacement, and many Git configuration attacks. It does not
protect against a hostile account that can rewrite the launcher's code, its
state files, the repository's Git object database, or the resolved Git
executable pathname or selected Codex executable pathname while it is in use.

## Extraction acceptance baseline

The compatibility suite contains 185 focused tests in
`scripts/tests/test_triptych_codex.py`. The repository-local wrapper delegates
to the packaged engine, so that complete suite remains the required parity
gate for observable lifecycle, failure, concurrency, recovery, Make
forwarding, and security behavior against disposable repositories.
Triptych-specific output and identities remain compatibility assertions rather
than generic defaults.
