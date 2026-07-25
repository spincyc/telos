# Worktree Marshal

Transactional Git worktrees for coding agents.

## Extraction status

This directory contains the shared lifecycle engine, its first extracted
cycle-free Git policy, durable-state vocabulary, and integration-transaction
restoration seams, its advisory-lock and descriptor-bookkeeping boundaries,
its first generic
profile, its command-execution and child-process supervision boundaries, its
run-identity and lexical
state-path boundary, its state-location, repository-name, and private-directory
authentication boundaries, the
immutable runtime-identity record and launcher-entry authentication
boundaries, its Git-executable discovery, pre-pin validation, and absolute-path
selection boundaries, its raw and authenticated Git-invocation boundary, the
exact Git-administration line-format validation and bounded descriptor-reader
boundaries, its exact pointer-path and real-directory validation boundary, its
read-only linked-worktree path-validation and cache-consistency boundaries,
its retained-worktree manifest-binding and authentication-dispatch boundary,
its Git-working-directory ancestor-authentication boundary,
its read-only repository-discovery boundary,
its exact path-entry inspection boundary,
its Codex-executable candidate-selection, static argument-policy, sanitized
base-environment, and deterministic marker-enrichment boundaries, the frozen
Triptych compatibility adapter, the Python distribution, and the Make
integration fragment. The repository-local
[`scripts/triptych-codex`](../../scripts/triptych-codex) command is a thin,
in-process bootstrap for the co-located package engine.

Built artifacts now install a `worktree-marshal` command. This remains a
pre-release extraction at version `0.0.0`; do not upload it to a package index
yet or treat installation as authorization to operate on a repository or
retained run. Stateful invocations select one immutable lifecycle domain
explicitly:

```text
worktree-marshal --profile generic-v1 run --agent codex
worktree-marshal --profile generic-v1 status [RUN_ID]
worktree-marshal --profile generic-v1 reopen RUN_ID [-- CODEX_ARGUMENTS...]
worktree-marshal --profile generic-v1 final-diff RUN_ID
worktree-marshal --profile generic-v1 integrate RUN_ID
worktree-marshal --profile generic-v1 resolve RUN_ID
worktree-marshal --profile generic-v1 continue RUN_ID
worktree-marshal --profile generic-v1 abort RUN_ID
worktree-marshal --profile generic-v1 clean RUN_ID
worktree-marshal --profile generic-v1 retire RUN_ID --discard-head FULL_OID --target-contains FULL_OID
```

Only `--help` and `--version` work without a profile. The explicit
`--profile triptych` spelling reaches the legacy state domain through the
compatibility adapter; the generic profile never discovers, adopts, migrates,
or falls back to Triptych runs. The exact generic identities are frozen in
[`docs/generic-v1.md`](docs/generic-v1.md).

The importable integration fragment is
[`worktree-marshal.mk`](src/worktree_marshal/resources/worktree-marshal.mk)
and its default Make targets are deliberately unprefixed:

```text
codex  status  reopen  final-diff  integrate
resolve  continue  abort  clean-run
```

Lifecycle targets take `RUN=<run-id>`; `status` also works without `RUN` for
an overview. Target names, the executable, and fixed command arguments are
configured in the including Makefile before importing the fragment; invocation
and environment overrides are rejected. Target names use the literal grammar
`[A-Za-z0-9][A-Za-z0-9_.-]*`. Triptych currently binds the fragment to its
compatibility launcher, clears the fragment's default
`--profile generic-v1` arguments, and temporarily accepts its former
`make <target> <run-id>` spelling as well. Generic consumers get only the
`RUN=` form unless they deliberately enable positional compatibility. A later
package command will install or update a pinned copy in a consumer repository;
consumers should not locate package resources dynamically during every Make
parse.

The package tests now install a wheel rebuilt from the source distribution in
an environment outside this checkout, with source-tree import paths removed.
That installed artifact passes a bounded lifecycle checkpoint covering generic
run preservation, integration, and cleanup through the packaged unprefixed
Make targets; bidirectional Triptych schema-1 run, status, and clean
interoperability through the packaged compatibility adapter; cross-profile
selected-run lookup isolation without manifest mutation; and rejection when
the generic profile's configured Codex executable aliases the installed
console, including symbolic- and hard-link aliases. It also passes a managed
conflict checkpoint: the generic packaged Make flow retains a conflict, stages
a resolver result, continues to a review-pending candidate, renders an opaque
read-only final diff, and lands that exact candidate only on a fresh integrate;
the installed Triptych adapter discards a staged resolution and restores the
exact audited source on abort. A further installed checkpoint starts two
deliberately overlapping generic run invocations from one unchanged control
base and verifies distinct run IDs, branches, locked worktrees, active run
locks, temporary roots, and isolated committed results without entering the
Triptych state domain. Serial integration through the packaged Make targets
then lands the first result by fast-forward and rebases the second result onto
that advanced target. The rebased landing records the exact source, target,
candidate, and integrated heads and produces linear no-merge history containing
both results; both integrations clean their worker namespaces. These bounded
overlap and non-racing integration checks do not establish scheduler
throughput, concurrent integration, target-race handling, or recovery
guarantees.

A fourth installed checkpoint creates one eligible clean rewritten generic
quarantine through the installed run and reopen commands. It verifies that no
Make retirement target exists, ordinary cleanup cannot acquire destructive
authority, and representative wrong full object IDs leave the quarantine
unchanged. The exact direct-only retirement command records the selected
discard and target-containment identities while leaving the target and control
checkout unchanged. Its manifest records the completed worktree-removal,
ref-transaction, and receipt-removal checkpoints; afterward the worker
worktree, run temporary directory, worker branch, and exact per-run retirement
refs are absent, while the cleaned manifest, adjacent state, and an unrelated
ref remain. An immediate repeat with the identical command and object IDs
leaves that manifest, the target and control snapshot, the ref set, worktree
registrations, and surviving sentinels unchanged; changed valid object IDs are
refused. The selected target checkpoint establishes reachability only, not
incorporation, semantic equivalence, or supersession of the discarded history.

This is one stable-target retirement happy path, representative pre-checkpoint
refusals, and completed-state exact-command idempotency. It does not cover the
full eligibility and refusal matrix, target races or lost containment,
active-worker, path, manifest, or ref tampering, interrupted checkpoints,
worktree-removal or ref-transaction failures, receipt recovery, garbage
collection, or concurrent retirement. Those retirement cases, broader crash
and race recovery, broader security coverage, the complete installed lifecycle
matrix, and the supported Python and Git CI matrix remain release gates; the
first forty step-5 seams are protected by direct source tests and artifact
provenance, and the installed abort checkpoint covers archived transaction
restoration. Each remaining helper boundary still requires its own direct
parity coverage.

Step 5 has begun narrowly: [`git.py`](src/worktree_marshal/git.py) owns only
the deterministic environment and argument transforms, their fixed policy
constants, validation of effective-configuration bytes captured by the
engine, and dependency-injected Git-executable discovery and pre-pin
validation. That operation selects the literal `git` command from the
inherited `PATH`, strictly resolves the selected pathname, captures its
metadata, and checks that it is a regular executable file. The engine still
owns the process-global resolved-path cache, startup ordering, `raw_git`
argument construction, repository authentication, the exact configuration
probe and its failure diagnosis, and all subprocess execution. The cache pins
only a resolved pathname, not a file descriptor or device/inode identity; it
does not make an inherited `PATH` entry trusted or close the existing
stat/access/exec replacement window. Direct tests freeze those seams, their
source-copy behavior, and their wheel and source-distribution presence.

[`model.py`](src/worktree_marshal/model.py) now owns the exact durable state
vocabulary, its two existing pending-state families, and the pure predicate
used by manifest validation. It also owns the ordered integration-transaction
field inventories and the deterministic in-place transform used to clear or
archive a transaction and restore its recorded prior state. The existing
engine wrappers still choose when to apply that transform, acquire the archive
timestamp afterward, and own validation, persistence, and recovery. Typed run
records and transition-graph enforcement remain deferred. Codex profile lookup
timing, role choice, manifest authority, the Git-sanitized mapping source,
subprocess creation and command execution, repository authentication,
effective-configuration probing, ref transactions, and lifecycle
orchestration also remain together in `engine.py`.

[`identity.py`](src/worktree_marshal/identity.py) owns the three frozen runtime
records for a discovered repository, an authenticated linked worktree, and the
authenticated launcher entry point. It also owns the dependency-injected,
read-only authentication operation for the in-process launcher path: lexical
absolute-path rejection, strict resolution and metadata capture, the regular
file and executable checks, and construction of the authenticated snapshot.
It now also owns the dependency-injected format validation used for exact
Git-administration path lines: exactly one terminal line feed, no carriage
return, strict UTF-8, and a nonempty, NUL-free value. The module now also owns
the dependency-injected `safe_regular_file_bytes` kernel for one bounded,
descriptor-based file read. Two further dependency-injected kernels implement
the existing exact pointer-path and real-directory checks. The read-only
`validate_linked_worktree_path` kernel composes those operations with the
exact-line reader to validate the linked-worktree administration paths and
topology. The read-only `validate_linked_worktree_identity_cache` kernel
validates the constructed identity against the engine-supplied prior-identity
and Git-administration-owner lookups. The dependency-injected
`authenticate_retained_worktree` operation binds a retained manifest to the
repository's current common-directory spelling and lazily dispatches its
worktree path to the engine-supplied linked-worktree authenticator. The
dependency-injected `authenticate_git_cwd` operation now owns the complete
ancestor traversal that authenticates the `.git` marker governing a Git
working directory. `engine.py` continues to re-export the same class objects.
The launcher wrapper supplies the error, filesystem-policy, access,
executable-mode, and identity factory dependencies lazily at their established
lookup points. Only strict resolution and metadata-read operating-system errors
are translated by that operation. The exact-line wrapper likewise supplies the
current regular-file byte-reader wrapper, Unicode decoding error type, and
launcher error type lazily.

The reader opens the final path component with `O_NOFOLLOW` when that flag is
available, requires the pre-read descriptor snapshot to describe a regular
file with exactly one link, accepts at most 16 MiB, and reads with a
16-MiB-plus-one detection budget in chunks of at most 1 MiB. It compares
device, inode, size, modification time, and change time before and after the
read and runs descriptor closure on every post-open path. Only an
operating-system error while opening the file is translated into the
intact-file diagnostic; later descriptor-operation failures remain outside
that translation.

`exact_pointer_path` treats an absolute raw value as its candidate and otherwise
joins it to the engine-supplied relative base. It computes that candidate's
lexical absolute spelling, strictly resolves the existing path, and rejects it
when the resolved path differs, thereby rejecting a symbolic component in the
observed traversal. `exact_real_directory` computes the supplied path's lexical
absolute spelling, applies `lstat` to that spelling, strictly resolves it, and
requires both a directory mode and equality between the resolved and lexical
paths. Resolution or metadata failures in their narrow protected blocks retain
the existing unavailable-path diagnostics; failed equality or directory checks
retain the existing symbolic-path and exact-directory diagnostics.

Linked-worktree validation first requires the worktree to be an exact real
directory and reads its `.git` file as one exact line. It requires a nonempty
`gitdir: ` pointer, resolves that pointer relative to the worktree, and
requires an exact real Git administration directory. It then reads and
resolves `commondir` relative to that directory, requires an exact common Git
directory, and, when the engine supplies an expected common directory,
requires their exact equality. Finally, it requires the common `worktrees`
administration directory, proves that the per-worktree Git directory is its
distinct direct child, and resolves the `gitdir` backlink back to the worktree's
`.git` file. The kernel returns exactly the validated
`(canonical_worktree, git_file, git_dir, common_git_dir)` components.

Cache consistency is checked only after the engine constructs the
`LinkedWorktreeIdentity`. The kernel first obtains the prior identity for the
canonical worktree. A non-`None` value that compares unequal to the new
identity raises `the retained worktree Git identity changed` and short-circuits
the administration-owner lookup. Otherwise the kernel obtains the prior owner
of the Git administration directory. A non-`None` owner that compares unequal
to the canonical worktree raises `the retained worktree Git admin directory
is not unique`. Both diagnostics retain their existing no-explicit-cause
scope. Lookup, comparison, truth-conversion, dependency-provider, and error
construction failures remain untranslated.

Retained-worktree authentication first obtains `common_git_dir` through the
manifest's `get` operation. It resolves the stringifier before reading and
stringifying the repository's common directory, then preserves the existing
inequality and truth conversion. A mismatch raises `the retained run's common
Git directory changed` without an explicit cause and performs no path
conversion or linked-worktree authentication. On success, the operation
resolves the linked-worktree authenticator before the path factory, reads the
manifest's exact `worktree` item, constructs that path, and reads the
repository common directory a second time for the
`expected_common_git_dir` keyword. It returns the authenticator's exact result.
Mapping, property, provider, stringification, comparison, path-construction,
callback, and error-construction failures remain untranslated.

Git-working-directory authentication first constructs and strictly resolves
the supplied directory. Only the selected operating-system and runtime errors
from that protected operation become `the Git working directory is
unavailable`, explicitly chained from the original error. It then eagerly
materializes `(directory, *directory.parents)` before inspecting any marker,
fixing the candidate order from the directory through its nearest-to-farthest
ancestors. Parent access and iteration, marker joining, and their failures are
outside that protected block and remain untranslated.

For each candidate, the operation applies `lstat` to its `.git` marker. The
selected file-not-found exception is handled before the broader
operating-system exception and silently advances to the next ancestor; another
selected operating-system error becomes `cannot inspect the Git administration
marker` with an explicit cause. A directory predicate is resolved first and
receives the first fresh `st_mode` read. A truthy result short-circuits the
regular-file, cache, and linked-authentication paths; the marker must then
strictly resolve equal to its exact pathname or
`the primary Git administration directory is symbolic` is raised without an
explicit cause. If the directory predicate is false, the regular-file
predicate is resolved and receives a second fresh `st_mode` read. A marker
that satisfies neither predicate immediately raises
`the Git administration marker is not a real file or directory`, without
examining another ancestor.

For a regular-file marker, the operation resolves the engine-supplied identity
lookup and queries it with the candidate. A prior value is distinguished by
identity with `None`, not truthiness: a present value supplies its
`common_git_dir`, while absence supplies `None`. Only after that selection does
the operation resolve and invoke the linked-worktree authenticator with the
candidate and exact `expected_common_git_dir` keyword. The callback may perform
the engine-owned linked-identity and Git-admin-owner cache mutations, but its
return is ignored. A successful directory or file branch returns `None`; when
every marker is absent, the operation falls through with the same implicit
`None` and performs no cache lookup or linked authentication. Except for the
two narrow translations above, dependency, metadata-property, predicate,
resolution, comparison, truth-conversion, cache, callback, and error
construction failures remain untranslated.

The exact-signature engine wrapper retains the current size limit and supplies
all primitive operations and policy values lazily. `MAX_ADMIN_FILE_BYTES`
remains in `engine.py` because the active-rebase administration audit also
uses it. The engine also retains every existing reader and path-check consumer,
the exact public retained-worktree wrapper and all of its existing callers,
the public linked-worktree authentication wrapper, and the exact public
`authenticate_git_cwd(cwd)` wrapper. That wrapper intentionally does not
return the injected kernel's result, preserving an implicit `None` on success
even under rebinding. The engine's `git()` path retains authentication followed
by effective-configuration validation followed by raw Git execution, as well
as Git argument construction, the configuration probe and its diagnosis, and
all subprocess execution. The engine also retains late `LinkedWorktreeIdentity`
construction, both process-global identity and Git-admin-owner registry
objects, their bound lookups, both assignments after a successful check, all
repository discovery and lifecycle workflows, lifecycle sequencing, top-level
error handling, and every mutation. Each registry is resolved again for its
assignment. An
identity-registry assignment failure prevents the owner assignment; an owner
assignment failure retains the identity entry, preserving the existing
partial-mutation and dynamic-rebinding behavior. The injected authenticator
may therefore perform engine-owned cache mutation, but the retained-worktree
operation receives no registry and performs no registry access or assignment
itself. The bounded reader does not authenticate parent path components,
establish canonicality or containment, lock the file, or prove that no content
mutation occurred when the observed metadata is unchanged. The path kernels
likewise establish neither containment, ownership, permissions, a stable
descriptor identity, nor protection from replacement after validation.
`exact_pointer_path` imposes no file-type requirement, and a normalized `..`
or an absolute value may name any available path that passes its equality
check. Linked-worktree validation is a sequence of read-only path snapshots,
not one atomic filesystem proof; paths may be replaced between or after its
checks. It does not authenticate repository ownership, permissions, Git object
content, branch or ref state, worktree registration, or lifecycle authority.
The cache kernel likewise performs sequential reads, not an atomic
check-and-reserve operation. Its entries are process-local and nondurable, and
it neither locks the registries nor reserves a worktree or Git administration
directory against a later or concurrent claim. It does not authenticate the
identity's paths or establish repository ownership; those path checks remain a
separate prerequisite, and successful cache validation alone creates no
registry entry.
The retained-worktree operation performs one literal common-directory spelling
comparison and a later dispatch, not manifest, repository, or filesystem
authentication. It neither validates the manifest schema or path ownership
nor freezes an atomic view across its two repository common-directory reads.
The supplied linked-worktree authenticator remains responsible for the actual
path, topology, identity-cache, and owner-cache checks.
Git-working-directory authentication is likewise a sequence of pathname and
metadata snapshots, not a locked or descriptor-pinned proof; the canonical
starting directory or any eagerly selected ancestor or marker may be replaced
between or after its checks. A primary-directory marker check establishes only
strict-resolution equality with the exact marker pathname, not ownership,
permissions, contents, repository identity, or lifecycle authority. A linked
marker delegates those path, topology, and process-local cache checks to the
linked-worktree authenticator. Absence of every marker deliberately succeeds,
so a later configuration probe or Git command may still reject the directory.
Git-executable discovery and pre-pin validation belong to `git.py`, while its
process-global cache and invocation remain in `engine.py`; neither is a future
responsibility of `identity.py`.

The dependency-injected `absolute_git_path` operation in `git.py` now owns the
existing authenticated `rev-parse --path-format=absolute` query, output
stripping, path construction, and non-strict resolution. Its exact engine
wrapper supplies the current authenticated Git operation and path factory
lazily. The engine retains authentication, configuration validation, argument
hardening, executable caching, subprocess execution, repository discovery,
and every lifecycle caller. The returned path remains a point-in-time
pathname observation rather than a pinned administration identity.

The module now also owns raw Git argument construction and authenticated Git
invocation sequencing. Raw invocation preserves the pinned executable, fixed
base arguments, caller arguments, and command forwarding. Authenticated
invocation preserves Git-CWD authentication, effective-configuration
validation, argument hardening, and execution order. The engine retains the
executable cache, configuration probe, subprocess execution, lifecycle
callers, ref operations, and every mutation.

The dependency-injected `discover_repository` operation now owns the complete
read-only discovery and state-identity derivation sequence. It resolves the
supplied directory or current directory, requires Git's exact non-bare
working-tree response, resolves the reported top level, obtains absolute worktree
and common administration paths in order, and authenticates the relative
current directory before selecting any state policy. It derives the unchanged
twelve-character common-directory digest, selects and resolves the
profile-bound state path, rejects state inside the worktree, and constructs
the immutable repository record last.

The engine wrapper supplies the current path, Git, hashing, filesystem,
state-policy, profile, constructor, and error dependencies lazily. The engine
retains all Git execution and configuration validation, state selection and
slug wrappers, profile binding, initialization, persistence, discovery callers,
lifecycle workflows, and mutation. Discovery remains a sequence of read-only
observations rather than an atomic repository or state authentication proof;
the observed checkout, administration paths, or state location may later
change.

The dependency-injected `path_entry_exists` operation now owns the exact
retirement path-entry probe. It applies `lstat` once, returns `False` only for
the selected file-not-found type, translates another selected
operating-system error with the unchanged explicit cause, and otherwise
returns `True`. The engine retains every retirement caller, temporary-path
authentication and removal, lifecycle transition, durable write, and
mutation. The probe establishes only point-in-time entry presence, not type,
ownership, containment, or stability.

[`adapters/codex.py`](src/worktree_marshal/adapters/codex.py) owns the
dependency-injected `select_codex_executable` operation for a usable,
non-launcher Codex executable candidate. The exact-signature engine wrapper
resolves and passes the active profile once, then supplies the current
environment, path, filesystem, access, mode, and error providers lazily. The
selector reads the captured profile's override field. A nonempty override must
be absolute and is the sole candidate. Otherwise the selector scans the
inherited executable path in order for the literal name `codex`, treating an
empty entry as the current directory. It skips candidates whose metadata
cannot be read, that are not regular executable files, or whose followed
metadata has the authenticated launcher's device and inode, and returns the
selected spelling made absolute. That return is `candidate.absolute()`, not
`candidate.resolve()`.

The module now also owns the existing static Codex root, `exec`, and `review`
option sets and known non-agent command set, plus the dependency-injected
`scan_allowed_options`, `normalize_codex_arguments`, and `codex_argv`
operations. This is a default-deny argument grammar, not a general command
parser. It rejects options outside the selected scope, rejects known
non-agent command surfaces, preserves an explicit `--`, inserts `--` before an
implicit free-form prompt, and normalizes a separated image option so its
value cannot become a command token. Only `read-only` and `workspace-write`
are accepted as sandbox values.

The argv builder places the engine-supplied executable and working directory
in a fixed prefix, disables Codex multi-agent mode, clears additional writable
roots and sandbox permissions, and defaults the sandbox to `workspace-write`
when no accepted sandbox option was supplied. Exact-signature engine wrappers
retain their established names and supply the current policy objects, profile
reopen hint, error type, and primitive operations lazily.

The dependency-injected `codex_environment` operation now transforms the
Git-sanitized base mapping supplied by the engine. It removes every built-in
launcher control marker, sets the captured profile's real-Codex marker to
the selected executable spelling, derives executable-path entries from that
mapping, and prefixes the executable's lexical parent. Every entry exactly
equal to that parent spelling is removed before the prefix is added; all other
entries retain their order and spelling.

A shared dependency-injected `enrich_codex_environment` operation now adds the
runtime markers to that supplied base mapping and returns the same mapping.
For an ordinary manifest-backed worker or resolver it adds the engine-selected
role, run ID, optional profile and agent IDs, and the manifest's one exact
temporary path as `TMPDIR`, `TMP`, and `TEMP`. For linked-worktree
pass-through it adds only the engine-selected worker role and optional profile
and agent IDs; it receives no retained-run manifest and adds no run or
temporary-path marker.

Here “real Codex” means only a candidate that passed those point-in-time
checks. Selection does not canonicalize the result, authenticate provenance or
version, distinguish a copy or wrapper, pin a file descriptor or device/inode
identity, close the stat/access/use replacement window, or establish sandbox
assurance. Symbolic links are followed while reading metadata, and either the
link or file may later be replaced. The engine retains profile binding, its
legacy wrappers and startup ordering, the working-directory authentication
wrapper and choice, profile lookup and enrichment call timing, role selection,
manifest authority, the Git-sanitized mapping source, linked-worktree refusal
checks, process creation and replacement, inherited descriptors, and every
post-exit and lifecycle decision.

The static grammar and fixed argv prefix rely on the selected executable
continuing to honor the recognized Codex CLI grammar and option precedence.
They do not repair the selector's executable-trust or replacement window,
constrain reads, credentials, providers, or network access, or themselves
provide an operating-system sandbox. The base-environment transform performs
targeted Git and launcher-control filtering only: it does not remove arbitrary
host variables or credentials. Its `PATH` comparison is lexical and exact; it
does not canonicalize, authenticate, or remove equivalent aliases and other
entries. Marker enrichment adds coordination metadata but does not strengthen
that isolation boundary. New Codex options, aliases, or subcommands require
policy and parity review. No shared base-adapter contract has been introduced.

[`state.py`](src/worktree_marshal/state.py) owns only the exact run-ID grammar,
dependency-injected timestamp and random-suffix composition, and lexical
repository-lock, run-lock, and manifest path construction. It now also owns
the dependency-injected precedence policy that selects a profile override,
`XDG_STATE_HOME`, or the home-directory fallback, plus ASCII repository-name
filtering for repository slugs. Engine wrappers retain their existing signatures,
profile-aware invalid-ID and relative-path diagnostics, and lazy environment,
path, home, error, clock, and entropy lookups. The module now also owns
descriptor-authenticated private-directory creation with mode 0700, mandatory
no-follow and directory flags, pre/open identity comparison, and unconditional
post-open closure, plus atomic manifest persistence and profile/repository-bound
manifest loading, plus exact lexical run temporary-path identity. The state
module now also owns core manifest lifecycle and path-containment validation
and integration and retirement checkpoint-field validation, plus local
target-branch syntax validation through an engine-supplied Git probe. It now
also owns exact run temporary-parent authentication and descriptor-relative
no-follow entry probing through engine-supplied descriptor operations, plus
authenticated temporary-directory opening and recursive open-descriptor
content removal through the same injected operations, and the composed run
temporary-root removal, absence, and exact-directory lifecycle checks, plus
the pure retirement parameter, argument-matching, conflicting-lifecycle, and
cleanup-target checkpoint policy over engine-supplied field inventories. The
engine retains Git execution and the selection and sequencing of every
directory, initialization, lock, persistence, temporary allocation, and
lifecycle mutation. State-base selection acquires
the current profile once, and repository normalization captures the current
substitution operation before reading the repository name. Those selection and
lexical helpers do not resolve, authenticate, create, or otherwise touch a
selected path. Repository digesting, final state-root construction and
containment rejection, the profile marker, manifest persistence and validation,
temporary-path authentication, lock acquisition, and all lifecycle decisions
remain in `engine.py`.

[`locks.py`](src/worktree_marshal/locks.py) owns the immutable registered
descriptor record; the algorithms that register, unregister, authenticate,
prune, and sort inherited descriptors; and the complete advisory file-lock
context manager. That manager preserves private parent setup, mode 0600,
exclusive and optional nonblocking acquisition, registration timing, and
unregister/unlock/close release order. The engine retains the process-global
registry, Repository-bound path wrappers, lifecycle lock ownership and
nesting, subprocess propagation, and every lifecycle locking decision.

[`process.py`](src/worktree_marshal/process.py) owns generic subprocess
execution with sanitized environment and inherited lock descriptors, plus the
existing child wait loop, temporary `SIGHUP` and `SIGTERM` forwarding,
interrupt escalation, handler restoration after successful setup, and
negative-return-code normalization. Engine wrappers supply lazy resolvers for
the environment, sanitizer, runner, descriptors, diagnostics, signal operations,
handled exception classes, timeout matching, and negative-status absolute-value
calculation, preserving its existing global rebinding behavior. The engine
still creates every process, supplies the adapter's executable, working
directory, and raw argument inputs, chooses its environment and inherited
descriptors, and owns all post-exit lifecycle decisions. The frozen legacy
contract and current security boundary are recorded in
[`docs/compatibility-contract.md`](docs/compatibility-contract.md); the target
architecture and release sequence are in [`docs/design.md`](docs/design.md).

## Development check

From this directory, run the package tests with:

```sh
python3 -m unittest discover -s tests -t . -v
```

This package suite includes artifact-content checks and the bounded
installed-artifact lifecycle checkpoints described above; it does not yet run
the complete legacy lifecycle matrix against the installed console.

The repository's `make check-agent-isolation` target additionally runs the
complete Triptych lifecycle suite through the thin compatibility bootstrap.

The initial package uses only the Python standard library at runtime and
requires Python 3.10 or newer. Its source is licensed under the MIT License.
