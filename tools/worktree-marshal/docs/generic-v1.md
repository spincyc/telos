# Generic v1 Profile Contract

## Selection and command grammar

`generic-v1` is Worktree Marshal's first native lifecycle profile. Every
stateful invocation begins with the exact, case-sensitive tokens
`worktree-marshal --profile generic-v1`. Profiles are not selected from the
environment, repository configuration, filesystem contents, or a retained run
ID. Only top-level `--help` and `--version` operate without a profile, and they
do not discover Git or create state.

The commands are:

```text
run --agent codex [-- CODEX_ARGUMENTS...]
status [RUN_ID]
reopen RUN_ID [-- CODEX_ARGUMENTS...]
final-diff RUN_ID
integrate RUN_ID
resolve RUN_ID
continue RUN_ID
abort RUN_ID
clean RUN_ID
retire RUN_ID --discard-head FULL_OID --target-contains FULL_OID
```

Codex arguments after `run` or `reopen` require the literal `--` delimiter.
`retire` is a destructive, direct-only exception and deliberately has no Make
wrapper. Run IDs and object IDs remain opaque inputs to the lifecycle engine.

## Durable identity

The profile owns these exact identifiers:

- profile ID `generic-v1`, manifest format `worktree-marshal-run`, manifest
  schema integer `1`, and agent ID `codex`;
- diagnostic name `worktree-marshal`;
- worker branch prefix `worktree-marshal/generic-v1/isolated/`;
- private ref prefix `refs/worktree-marshal/generic-v1/runs/`;
- linked-worktree lock reason prefix `worktree-marshal generic-v1 `; and
- environment variables `WORKTREE_MARSHAL_ROLE`,
  `WORKTREE_MARSHAL_RUN_ID`, `WORKTREE_MARSHAL_PROFILE_ID`,
  `WORKTREE_MARSHAL_AGENT_ID`, `WORKTREE_MARSHAL_REAL_CODEX`, and
  `WORKTREE_MARSHAL_STATE_DIR`.

Without an override, state begins at
`$XDG_STATE_HOME/worktree-marshal/profiles/generic-v1` when
`XDG_STATE_HOME` is set to an absolute path. When it is unset, state begins at
`$HOME/.local/state/worktree-marshal/profiles/generic-v1`; a set relative
`XDG_STATE_HOME` is rejected. An absolute
`WORKTREE_MARSHAL_STATE_DIR` names the Worktree Marshal state base, below
which the profile still appends `profiles/generic-v1`. Each repository then
uses the same normalized-name and common-Git-directory digest scheme as the
compatibility engine.

Each repository state root contains a `profile.json` marker. The marker is
authenticated before its repository lock, run manifests, worktrees, or
temporary paths are used. A generic run manifest includes the exact
`format_id`, `profile_id`, and `agent` values above in addition to the shared
lifecycle fields.

## Codex executable selection

A nonempty `WORKTREE_MARSHAL_REAL_CODEX` value is the sole executable
candidate and must be an absolute path. When it is absent or empty, Marshal
scans the inherited executable path in order for the literal name `codex`,
treating an empty entry as the current directory. It skips candidates whose
metadata cannot be read, that are not regular executable files, that fail the
executable access check, or whose followed device and inode match the
authenticated launcher snapshot. It returns the selected spelling using
`candidate.absolute()`, not a canonical resolution.

The exact failures are
`WORKTREE_MARSHAL_REAL_CODEX must be an absolute path`,
`WORKTREE_MARSHAL_REAL_CODEX does not name a usable non-launcher executable`,
and `cannot find the real Codex executable; set WORKTREE_MARSHAL_REAL_CODEX`
for, respectively, a relative override, an unusable override, and unsuccessful
inherited-path search.

This is point-in-time selection of a usable non-launcher candidate. It does not
authenticate provenance, signature, version, or actual Codex behavior;
distinguish a copy or wrapper; pin a file descriptor or device/inode identity;
close the stat/access/use replacement window; or establish sandbox assurance.
Metadata lookup follows symbolic links, and the selected link or file may
later be replaced. Executable selection does not alter the profile's durable
identity, discover or migrate retained runs, or grant lifecycle authority.
The engine continues to bind the profile and own executable-selection timing,
working-directory authentication and choice, environment role and manifest
selection, process creation and replacement, and post-exit lifecycle policy.

## Codex argument policy

The Codex adapter owns static, separate allowlists for root, `exec`, and
`review` options and a set of known non-agent command surfaces. Unknown options
fail closed within each parsed scope. An explicit `--` forces the remaining
tokens to be prompt data; otherwise an implicit free-form interactive, `exec`,
or `review` prompt receives `--`. A separated `-i` or `--image` value is
combined with its option before command classification. Native resume and fork
surfaces are refused in favor of the retained-run lifecycle.

Only `read-only` and `workspace-write` are accepted sandbox values. The fixed
argv prefix uses the engine-supplied executable and working directory, disables
Codex multi-agent mode, clears additional writable roots and sandbox
permissions, and supplies `--sandbox workspace-write` when the accepted user
arguments did not specify a sandbox. These are argument-level controls; the
engine still authenticates and chooses the working directory, supplies the
profile-specific lifecycle hint, selects the role and manifest inputs for
child, resolver, and pass-through environments, creates or replaces the
process, and owns every lifecycle transition.

This static policy is sensitive to Codex CLI version, aliases, parsing, and
option-precedence changes. It assumes the selected executable honors the
recognized grammar. It is not a generic `AgentAdapter` or an operating-system
sandbox, and it does not authenticate executable provenance, close the
selection/use replacement window, or constrain filesystem reads, credentials,
providers, or network access. Policy changes require new parity and
enforcement review; this extraction changes no durable identity and adds no
migration or lifecycle authority.

## Codex base environment

The adapter transforms the Git-sanitized base mapping supplied by the engine.
It first removes every built-in Triptych and Worktree Marshal role,
real-Codex, run, profile, and agent marker name, then sets the current
profile's `WORKTREE_MARSHAL_REAL_CODEX` marker to the selected executable
spelling. It derives the executable-path entries from that result, prefixes
the selected executable's lexical parent, removes every prior entry exactly
equal to that parent string, and preserves the spelling and order of all other
entries.

The engine retains active-profile capture, supplies the Git-sanitized mapping
at the established point, selects the worker or resolver role, and decides
whether the exact launcher-owned manifest is authoritative. One shared adapter
operation then enriches that mapping deterministically and returns the same
object. For ordinary workers and resolvers it adds the selected role, run ID,
profile ID, agent ID, and the manifest's one exact run-owned path as `TMPDIR`,
`TMP`, and `TEMP`. For linked-worktree pass-through it adds only the worker,
profile, and agent markers; it receives no retained-run manifest and adds no
run or temporary-path marker.

This is targeted filtering, not complete environment isolation. Beyond the
existing Git-sensitive names and explicit launcher control markers, arbitrary
host variables and credentials remain inherited. Executable-path comparison
is lexical and exact: it does not canonicalize, authenticate, or remove
aliases, equivalent spellings, relative or empty entries, or unrelated
directories. The transform does not constrain reads, subprocesses, providers,
or network access, repair executable provenance or replacement risks, or
provide an operating-system sandbox. Marker enrichment adds coordination
metadata but does not strengthen that isolation boundary. These operations
introduce no generic `AgentAdapter`, durable identity change, migration, or
lifecycle authority.

## Isolation and compatibility

The generic profile and Triptych schema 1 are separate coordination domains.
They may contain identical-looking run IDs without referring to the same run.
Generic operations inspect only generic state and refs and never fall back to,
migrate, or mutate Triptych state. The explicit `triptych` profile is the only
installed-command route to the compatibility adapter. There is no migration
command in v1.

All built-in managed-worktree markers, lock prefixes, and branch prefixes are
recognized when refusing nested agent allocation, regardless of which profile
the nested command selected. Selection changes durable identity, not the
underlying safety model: `generic-v1` supports only the hardened Codex adapter
and does not accept an arbitrary executable.

## Make integration

The packaged fragment defaults to `--profile generic-v1` and the unprefixed
targets `codex`, `status`, `reopen`, `final-diff`, `integrate`, `resolve`,
`continue`, `abort`, and `clean-run`. Lifecycle targets take a validated
command-line `RUN=<run-id>`; the status overview needs no run ID. A repository
may pin trusted fixed global arguments while importing the fragment, but Make
invocations and the environment may not override them.
