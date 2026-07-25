# Worktree Marshal Design

## Product boundary

Worktree Marshal is a transactional supervisor for coding-agent work in Git
repositories. It allocates independent worktrees, records durable run state,
audits results, and performs explicitly authorized cleanup or integration.
Several Marshal processes may run concurrently; Marshal is not a prompt
scheduler, agent-message bus, model router, or task-DAG engine.

The first supported agent is Codex because the Triptych launcher already has a
tested, default-deny Codex argument and sandbox policy. Supporting another
agent requires an explicit adapter and sandbox capability; accepting an
arbitrary executable is not equivalent support.

## Intended package boundaries

The current package deliberately keeps lifecycle transition selection,
validation, persistence, and orchestration in one shared `engine.py`. `cli.py`
owns the installed grammar, `profiles.py` owns immutable durable profile
identities, `git.py` now owns the cycle-free Git policy kernel,
Git-executable discovery and pre-pin validation, and absolute path selection,
plus raw and authenticated invocation sequencing,
`model.py` now owns the exact
state vocabulary, pure classifier, and I/O-free integration-transaction
restoration transform, `state.py` now owns run identity, state-location
selection, repository-name normalization, lexical lock and manifest paths,
private state-directory authentication, manifest persistence and loading, and
exact run temporary-path identity,
`identity.py` now owns immutable runtime identity records and launcher-entry
authentication plus exact Git-administration line-format validation and the
bounded descriptor-based regular-file reader plus exact pointer-path and
real-directory validation, read-only linked-worktree path validation, and
read-only linked-worktree cache-consistency policy plus retained-worktree
manifest binding and authentication dispatch plus Git-working-directory
ancestor authentication, read-only repository discovery, and exact path-entry
inspection,
`locks.py` now owns advisory lock acquisition and lock-descriptor bookkeeping
and validation algorithms,
`process.py` now owns command execution, child waiting, and exit-status
normalization,
`adapters/codex.py` now owns Codex executable candidate selection and static
argument policy plus the sanitized Codex base-environment transform and
deterministic marker enrichment, and `triptych_compat.py` binds the frozen
compatibility profile. The rest of the engine will be separated behind these
modules only after parity tests protect each seam:

```text
worktree_marshal/
  cli.py                 command parsing and stable exit behavior
  model.py               state vocabulary and transaction restoration now
  state.py               identity, location, lexical paths, and private directories
  locks.py               advisory acquisition and descriptor bookkeeping
  git.py                 policy, discovery, paths, and invocation sequencing
  process.py             command execution, signal forwarding, and exit status
  identity.py            records, auth, path/cache checks, and repository discovery
                         public wrappers and linked registry objects/writes remain in engine
  worktrees.py           allocation, audit, reopen, and cleanup
  integration.py         verification, rebase, landing, and rollback
  conflicts.py           resolver scope, continuation, and abort
  retirement.py          separately authorized destructive retirement
  adapters/base.py       future agent contract; explicitly not introduced
  adapters/codex.py      selection, arguments, base environment, and marker enrichment
  sandboxes/base.py      enforcement contract independent of an adapter
  resources/             generated integration assets such as the Make fragment
```

Integration, conflict, and retirement workflows remain together until their
durable invariants have direct state-machine tests. File boundaries are not a
reason to weaken an atomic lifecycle operation.

## Trust model

A linked worktree is an isolation mechanism for cooperative development, not
an operating-system security boundary. Linked worktrees share Git
administration and object storage, and a same-user unconfined process can
potentially reach launcher state, other checkouts, credentials, and the
network. Post-run auditing detects and contains many mistakes and races but
cannot prove that hostile code never touched unrelated state.

A future `AgentAdapter` abstraction would own a complete accepted-argument and
environment contract. No common base-adapter contract exists at this boundary.
A separate future `SandboxBackend` would own enforceable filesystem, process,
and network claims. Marshal must not infer sandbox assurance merely because an
adapter module exists. Any future trusted-command adapter must be an explicit
opt-in and must state that it is unconfined.

## Extraction sequence

1. Freeze the schema-1 Triptych compatibility contract and extract the Make
   API without moving lifecycle behavior.
2. Relocate the existing launcher behind a thin `scripts/triptych-codex`
   compatibility entry point, preserving state paths, refs, environment names,
   diagnostics, and every retained run.
3. Add wheel and source-distribution parity tests, including installation of a
   wheel rebuilt from the source distribution.
4. Introduce the explicit `generic-v1` profile and generic branding while
   keeping the Codex adapter as the only supported confined agent and the
   Triptych domain available only by explicit compatibility selection.
5. Split pure identity, state, locking, Git, and process helpers; encode valid
   state transitions before separating integration and recovery logic.
6. Publish a `0.x` release only after installation outside the Triptych
   checkout passes the complete lifecycle suite.
7. Add another agent or stronger workspace backend only with its own threat
   model, enforcement tests, and explicit capability declaration.

Each step remains behavior-preserving unless it includes a documented state or
command migration. A new installation never implies permission to migrate,
integrate, clean, retire, push, or deploy a run.

The repository currently implements steps 1 through 4 as pre-release seams and
has begun step 5 with forty behavior-preserving boundaries. The original
pure Git policy kernel transforms an explicit environment mapping and Git
argument sequence in `git.py`; `engine.py` retains its optional
environment-acquisition wrapper, subprocess creation and command execution,
lock acquisition, repository authentication, configuration probing, ref
transactions, and lifecycle orchestration.
The second cycle-free boundary places the exact durable state vocabulary, the
existing retirement-pending and managed-conflict families, and a pure
classifier in `model.py`. Manifest validation uses that predicate while
retaining its exact diagnostics and engine-global rebinding behavior. The
third boundary moves the ordered integration-transaction and manual-landing
field inventories plus their deterministic in-place clear/archive transform
into `model.py`. Engine wrappers retain their existing signatures, pass their
current field inventories explicitly, acquire the abort timestamp only after
the transform, and continue to own transition selection, validation, durable
writes, and recovery. The transform deliberately preserves the existing
direct-call behavior of restoring any string previous state; manifest loading
still validates durable states separately. A transition graph, typed run
records, checkpoint validation, and all recovery choices remain deferred.
The fourth boundary moves the immutable registered-lock descriptor and the
register, unregister, stale-entry pruning, identity-validation, and
sorted-selection algorithms into `locks.py`. Explicit resolvers let engine
wrappers obtain the current registry and record factory at the same operation
points as before, preserving even reentrant rebinding behavior. The
process-global registry, repository and per-run lock paths, `flock` acquisition
and release, subprocess `pass_fds`, and lifecycle lock ownership remain in
`engine.py`. The fifth boundary moves only the existing child wait loop,
temporary `SIGHUP` and `SIGTERM` forwarding, interrupt escalation, handler
restoration after successful setup, and negative-return-code normalization
into `process.py`. The engine wrapper supplies lazy resolvers at the original
signal-operation, handled-exception, timeout, and negative-status
absolute-value lookup points. Process creation, command execution, executable
invocation for Codex, working-directory authentication and choice,
environment enrichment, inherited descriptors, and post-exit lifecycle
decisions remain in `engine.py`. Direct tests also retain the legacy
partial-setup behavior: a failure while installing the second handler occurs
before the protected wait and does not roll back the first installation.
The sixth boundary extends `git.py` with deterministic parsing and rejection
of command-bearing values in the effective-configuration bytes captured by the
engine. At that boundary, the engine retained working-directory authentication,
the exact Git configuration probe, unsuccessful-probe diagnosis,
process-global executable pinning, and subprocess execution. Lazy resolvers
preserved the engine's existing configuration-policy and error lookups at
their original decision points.
The seventh boundary moves the exact run-ID grammar, dependency-injected
timestamp and random-suffix composition, and lexical repository-lock,
run-lock, and manifest path construction into `state.py`. Engine wrappers
retain their original signatures, profile-aware invalid-ID diagnostics, and
lazy clock and entropy lookup order. These constructors intentionally perform
no validation, resolution, authentication, directory creation, or filesystem
access. That boundary left state-base selection and every stateful operation
in `engine.py`.
The eighth boundary extends `state.py` with the existing profile-override,
`XDG_STATE_HOME`, and home-fallback selection policy plus ASCII
filtering for repository slugs. The state-base wrapper retains its signature,
resolves the active profile once, and supplies lazy environment, path, home,
and error dependencies. The repository-slug wrapper retains its signature and
captures the current substitution operation before reading the repository
name. Repository digest calculation, final state-root joining and resolution,
outside-worktree containment rejection, directory creation, authentication,
and all durable writes remain in `engine.py`.
The ninth boundary moves only the frozen `Repository`,
`LinkedWorktreeIdentity`, and `LauncherIdentity` records into `identity.py`.
The engine imports and re-exports those exact class objects, so existing
constructors and type comparisons keep their established surface. Their
canonical Python module and new pickle provenance are now `identity.py`; the
engine aliases keep old engine-qualified lookups resolvable, and Marshal does
not persist these records with pickle. That record-only checkpoint did not
perform validation or I/O.
The tenth boundary moves only the existing in-process launcher-entry
authentication operation into `identity.py`. Its exact-signature engine
wrapper supplies lazy resolvers for the current operating-system error and
launcher error types, regular-file predicate, executable access operation and
mode, and identity factory. This preserves lexical absolute-path rejection,
strict resolution followed by metadata capture, short-circuiting regular-file
and executable checks, late identity construction, the three exact
diagnostics, and the narrow rule that only resolution or metadata-read
operating-system errors are translated and chained. The operation
authenticates a read-only path snapshot; it deliberately does not strengthen
the existing stat/access race into descriptor-based authentication. Launcher
sequencing, the public error type, the remaining repository and
linked-worktree authentication, identity caches, all other path and file
authentication, lifecycle decisions, and every mutation remain in
`engine.py`. Git-executable selection is a Git invocation concern, not a
future `identity.py` responsibility; Codex-executable selection likewise
belongs to its adapter rather than identity.
The eleventh boundary extends `git.py` with the existing Git-executable
discovery and pre-pin validation operation. Its dependency-injected lookup
selects the literal `git` command from the inherited `PATH`, strictly resolves
the selected pathname, captures its metadata, and checks that it is a regular
executable file while preserving the existing diagnostics and exception
scope. The exact-signature engine wrapper retains the process-global
resolved-path cache and its cache-hit short circuit, startup ordering,
`raw_git` argument construction, repository and configuration probing, and all
subprocess execution. This is pathname selection and caching, not
device/inode or descriptor authentication: it neither makes the inherited
`PATH` trustworthy nor closes the existing stat/access/exec replacement
window. It adds no new sandbox, lifecycle, or release assurance.
The twelfth boundary moves the existing exact Git-administration line-format
operation into `identity.py`. Its exact-signature engine wrapper supplies lazy
resolvers for the current `safe_regular_file_bytes` operation, Unicode
decoding error type, and launcher error type. Byte acquisition still precedes
format inspection. The short-circuiting enforcement of exactly one terminal
line feed and no carriage return, strict UTF-8 decoding, the nonempty and
NUL-free path-value checks, the three exact diagnostics, and the narrow
decoding-error cause remain unchanged. That boundary left the safe reader and
all descriptor I/O, size and change checks, pointer-prefix and path
interpretation, exact-directory and topology validation, linked-worktree
identity caches, and lifecycle orchestration in the engine.
The extracted helper validates only the line format presented by its injected
reader. It does not independently authenticate a file or path, reject every
symbolic traversal, establish pointer canonicality or containment, eliminate
a replacement race, or add sandbox, lifecycle, or release assurance.
The thirteenth boundary starts `adapters/codex.py` with only the existing
`select_codex_executable` candidate-selection operation. Its exact-signature
engine wrapper resolves and passes the active profile once, then supplies lazy
dependencies for environment access, path construction, the inherited
executable path, current directory, metadata and regular-file checks,
executable access and mode, and launcher error type. The operation reads the
captured profile's override field. A nonempty override must be absolute and is
the sole candidate. With an absent or empty override, the operation scans the
inherited executable path in order for the literal name `codex`, treating an
empty entry as the current directory. Metadata-read operating-system errors,
nonregular or nonexecutable candidates, and candidates whose followed device
and inode equal the authenticated launcher snapshot are skipped. The returned
path is the candidate spelling made absolute by `candidate.absolute()`, not a
canonical resolution.

That boundary left active-profile binding, the legacy
`resolve_real_codex` wrapper and startup ordering, accepted-surface and option
policy, argv and child/resolver environment construction,
sandbox-enforcement arguments, process creation, and every post-exit and
lifecycle decision in the engine. The selector does not authenticate origin,
signature, version, or implementation; reject a copy or wrapper; pin a file
descriptor or device/inode identity; close the stat/access/use replacement
window; or establish sandbox assurance. Metadata lookup follows symbolic
links, and the selected link or file may later be replaced.

The fourteenth boundary extends `adapters/codex.py` with the existing static
root, `exec`, and `review` option sets, known non-agent command set,
`scan_allowed_options`, `normalize_codex_arguments`, and `codex_argv`. The
dependency-injected operations preserve the exact engine wrapper signatures,
policy-object and primitive-operation lookup points, profile-specific reopen
hint, diagnostics, input-copy and separated-image mutation behavior, scoped
sandbox tracking, and result order.

Beyond executable selection, this seam adds adapter ownership only of the
static Codex CLI grammar, prompt delimiting and normalization, and fixed
argument-level sandbox configuration. Unknown options fail closed in each
parsed scope. An explicit `--` remains authoritative; otherwise free-form
interactive, `exec`, and `review` prompts receive a `--` delimiter so
command-like words remain data. Known non-agent command surfaces are rejected.
Only `read-only` and `workspace-write` sandbox values are accepted. The argv
builder uses the engine-supplied executable and working directory, disables
multi-agent mode, clears additional writable roots and sandbox permissions,
and adds `--sandbox workspace-write` only when no accepted sandbox was
supplied.

That boundary left active-profile binding and lifecycle-hint selection,
wrapper call timing and early validation, executable-selection sequencing,
working-directory authentication and choice, resolver prompt selection, base
and enriched environment construction, process creation and in-place
replacement, inherited descriptors, and every state, audit, post-exit, and
lifecycle decision in the engine. Its static allow and deny policy remains
sensitive to Codex CLI version and parsing changes and relies on the selected
executable honoring the expected argument meanings and precedence.

The fifteenth boundary moves only the existing `codex_environment` base
transform into `adapters/codex.py`. Its exact-signature engine wrapper retains
active-profile capture at the established point and lazily supplies the
Git-sanitized environment, complete built-in control-marker inventory,
stringification, executable-path parsing, and path-separator operations. The
adapter removes every control-marker name from that supplied mapping, sets the
captured profile's real-Codex marker to the selected executable spelling, and
derives the current executable-path entries from the resulting environment.
It prefixes the selected executable's lexical parent and removes every
existing entry exactly equal to that parent spelling while preserving all
other entries and their order.

The engine retains child, resolver, and linked-worktree pass-through
enrichment, including role, run, profile, agent, and run-owned temporary-path
values as applicable. It also retains profile capture and call timing for
those consumers, working-directory authentication and choice, process
creation and `execve` replacement, inherited descriptors, and every state,
audit, post-exit, and lifecycle decision.

The base transform is targeted filtering, not complete environment isolation:
it does not remove arbitrary host variables or credentials or constrain reads,
providers, subprocesses, or network access. Its `PATH` comparison is lexical
and exact, not canonical or identity-based, so aliases, equivalent spellings,
relative or empty entries, and all unrelated entries remain. It neither
strengthens executable provenance or selection/use replacement guarantees nor
provides an operating-system sandbox. The adapter module is still not a
generic `AgentAdapter`; no common base adapter, capability contract, new agent,
state migration, durable identity change, sandbox backend, or release
assurance is introduced by this seam.

The sixteenth boundary moves the three existing runtime-marker sequences into
one shared `enrich_codex_environment` operation in `adapters/codex.py`. The
operation deterministically mutates and returns the engine-supplied base
mapping. It always adds the supplied role. With an ordinary worker or resolver
manifest it next adds the run ID, the optional profile and agent IDs, and that
manifest's one exact temporary path as `TMPDIR`, `TMP`, and `TEMP`. Without a
manifest, linked-worktree pass-through adds only its worker role and the
optional profile and agent IDs; it adds no run or temporary-path marker.

The engine retains each consumer's established profile lookup and enrichment
call timing, chooses the worker or resolver role, decides whether the exact
launcher-owned manifest is authoritative, and supplies the Git-sanitized base
mapping. It also retains working-directory selection and authentication, the
linked-worktree marker, lock, and branch refusal checks, process creation and
`execve` replacement, inherited descriptors, and every state, audit, post-exit,
and lifecycle decision. This deterministic marker helper is not a generic
`AgentAdapter` or complete environment isolation. It adds no new capability
contract, agent, sandbox backend, credential filtering, durable identity,
migration, or release assurance.

The seventeenth boundary moves only the existing
`safe_regular_file_bytes` kernel into `identity.py`. Its exact-signature engine
wrapper retains `MAX_ADMIN_FILE_BYTES` and lazily supplies the current open
flags, descriptor operations, operating-system and launcher error types,
regular-file predicate, size limit, and primitive minimum and length
operations. The constant remains in the engine because the separate
active-rebase administration audit also uses it. Existing callers—including
the exact-line wrapper, generic profile-marker authentication, and active
rebase metadata readers—continue through the engine wrapper at their
established call points.

The kernel opens the final path component with `O_NOFOLLOW` only when the
platform provides that flag, requires the pre-read descriptor snapshot to
describe a regular file with exactly one link, rejects a metadata size above
16 MiB, and reads through a 16-MiB-plus-one detection budget in chunks no
larger than 1 MiB. It then compares the descriptor's device, inode, size,
modification time, and change time with the pre-read snapshot and runs
descriptor closure on every post-open path. Only an operating-system error
during open is translated into the intact-file diagnostic; later
descriptor-operation failures retain their existing scope.

This is a bounded descriptor read, not complete pathname or mutation
authentication. It does not authenticate or canonicalize parent components,
establish path containment, lock the file, or prove the absence of a mutation
that leaves the compared metadata unchanged. That boundary left pointer-prefix
and path interpretation, exact-directory and linked-worktree topology
validation, identity registries, repository and retained-worktree
authentication, all workflows, and every mutation in the engine. It added no
durable identity, migration, sandbox, lifecycle, or release assurance.

The eighteenth boundary moves only the existing `exact_pointer_path` and
`exact_real_directory` kernels into `identity.py`. Their exact-signature engine
wrappers lazily supply the current path factory, lexical absolute-path and
filesystem-spelling operations, protected operating-system and runtime error
types, launcher error type, and directory predicate. Existing
linked-worktree-authentication calls retain their established raw values,
relative bases, labels, order, and wrapper lookup points.

`exact_pointer_path` converts the raw value to a path, uses it directly when
absolute or joins it to the supplied relative base, computes the candidate's
lexical absolute spelling, and strictly resolves the existing candidate.
Resolution failures retain the unavailable-path diagnostic; a resolved value
different from the lexical absolute path retains the symbolic-traversal
diagnostic. `exact_real_directory` computes a supplied path's lexical absolute
spelling, applies `lstat` to that spelling, strictly resolves it, and requires
both a directory mode and equality between the resolved and lexical paths.
Its protected metadata or resolution failures retain the unavailable
diagnostic, while failed mode or equality checks retain the
exact-real-directory diagnostic.

These are path snapshots, not full repository or linked-worktree
authentication. The pointer kernel does not require a file type or containment
under its relative base; normalized `..` components and absolute values may
name any available path that passes the equality check. Neither kernel
authenticates ownership or permissions, pins a descriptor identity, prevents
replacement after validation, or grants lifecycle authority. The engine
retained Git-pointer prefix parsing, selection of raw values and relative
bases, common-directory and backlink comparison, direct-child topology,
identity registries, repository and retained-worktree authentication, every
workflow, and every mutation at that boundary. It did not genericize
repository or worktree authentication or add a shared capability contract.
That seam added no durable identity, migration, sandbox, lifecycle, or release
assurance.

The nineteenth boundary moves only the read-only validation prefix of
`authenticate_linked_worktree_path` into
`identity.validate_linked_worktree_path`. The kernel lazily resolves the
engine-supplied exact-directory, exact-line, and exact-pointer operations,
primitive length operation, and launcher error type at their established call
points. It performs no identity construction or registry access and returns
exactly `(canonical_worktree, git_file, git_dir, common_git_dir)`.

The validation sequence remains fixed. It requires an exact real worktree,
reads its `.git` file as one exact line, requires a nonempty `gitdir: ` prefix,
resolves that pointer relative to the worktree, and requires an exact real
per-worktree Git administration directory. It reads and resolves `commondir`
relative to that directory, requires an exact real common Git directory, and
optionally validates the engine-supplied expected common directory by exact
equality. It then requires the common `worktrees` administration directory,
checks that the per-worktree directory is its distinct direct child, and reads
and resolves the `gitdir` backlink to require exact equality with the
worktree's `.git` file. The existing invalid-pointer, unexpected-common,
direct-child, and changed-backlink diagnostics and their no-explicit-cause
scope remain unchanged; failures from the injected lower-level operations
remain untranslated.

At that boundary, the exact public engine wrapper received the four components,
constructed `LinkedWorktreeIdentity` only after every validation succeeded,
and then performed the existing identity-cache and Git-admin-owner-cache
checks and assignments in their established order. It retained both
process-global registries, late constructor and registry rebinding,
partial-mutation behavior, `authenticate_retained_worktree`,
`authenticate_git_cwd`, `active_rebase_directories`, every other caller and
workflow, and every mutation.

This kernel validates a linked-worktree path topology through a sequence of
read-only snapshots; it is not an atomic filesystem or repository proof.
Paths may be replaced between or after checks. It does not establish ownership
or permissions, authenticate Git objects, refs, branches, or worktree
registration, enforce lifecycle state, or make the caches durable across
processes. No generic repository-authentication contract, durable identity,
migration, sandbox, lifecycle, or release assurance is introduced.

The twentieth boundary moves only those two read-only cache-consistency checks
into `identity.validate_linked_worktree_identity_cache`. After path validation
and the exact four-component unpack, the engine still constructs
`LinkedWorktreeIdentity` at its established late point. It then supplies the
constructed identity and canonical worktree separately, preserving the
rebound constructor's ability to return an opaque object without a readable
`worktree` attribute. Lazy callbacks obtain the prior identity and prior Git
administration-directory owner; the kernel receives neither registry object
and performs no assignment.

The check order remains exact. The kernel obtains the prior identity first.
`None` means no prior claim; a non-`None` value is compared with the constructed
identity, and a truthy inequality raises `the retained worktree Git identity
changed` without an explicit cause. That failure short-circuits the owner
lookup. Otherwise the kernel obtains the administration-directory owner.
`None` again means no prior claim; a non-`None` value is compared with the
canonical worktree, and a truthy inequality raises `the retained worktree Git
admin directory is not unique` without an explicit cause. Lookup, comparison,
truth-conversion, provider, and error-construction failures remain
untranslated, and the launcher error type is resolved only after the relevant
collision evaluates true.

At that boundary, the public engine wrapper retained both process-global
registry objects and both assignments. After the kernel succeeded, it reloaded
the identity registry and assigned the constructed identity, then reloaded the
owner registry and assigned the canonical worktree. Failure of the first
assignment prevented the second; failure of the second preserved the first
assignment. Registry rebinding during either lookup or the first assignment
therefore remained observable exactly as before. The engine also retained the
late constructor, boundary-19 path-validation orchestration, all
authentication entry points and callers, every lifecycle workflow, and every
mutation.

This kernel reads process-local cache claims sequentially; it is not an atomic
check-and-reserve operation. It neither locks nor writes either registry,
reserves a worktree or Git administration directory, prevents a claim from
changing between checking and assignment, nor makes an entry durable or
visible to another process. It does not authenticate paths, prove filesystem
or repository ownership, or validate Git registration or lifecycle state. It
introduces no generic authentication contract, durable identity or migration
change, sandbox or lifecycle authority, packaging or distribution change, or
release assurance.

The twenty-first boundary moves the full retained-worktree manifest binding and
authentication dispatch into `identity.authenticate_retained_worktree`. Its
exact-signature engine wrapper remains `(repository, manifest)` and lazily
supplies the current stringifier, launcher error type, linked-worktree
authenticator, and path factory. Every existing caller continues through that
wrapper without changed arguments, return handling, or workflow placement.

Evaluation order remains fixed. The operation first obtains
`common_git_dir` with the manifest's `get` method. It resolves the stringifier
before the first fresh read of `repository.common_git_dir`, stringifies that
value, and applies the existing inequality and truth conversion. A truthy
mismatch resolves the launcher error type only then and raises `the retained
run's common Git directory changed` without an explicit cause. That branch
does not resolve the authenticator or path factory, subscript the manifest's
`worktree`, construct a path, or perform the second repository read.

On success, the operation resolves and captures the linked-worktree
authenticator before evaluating its arguments. It next resolves the path
factory before subscripting the exact manifest `worktree` item, constructs
that positional path, and reads `repository.common_git_dir` a second time for
the exact `expected_common_git_dir` keyword. It invokes the captured
authenticator and returns its result unchanged. Mapping, property, provider,
stringification, comparison, truth-conversion, path-construction, callback,
and error-construction failures remain untranslated.

The engine continues to own the exact public retained-worktree wrapper and all
of its callers, `authenticate_linked_worktree_path`, the boundary-19 path
validator, the boundary-20 cache-consistency validator, late
`LinkedWorktreeIdentity` construction, both process-global registry objects,
both assignments, dynamic rebinding and partial-mutation behavior, every
lifecycle workflow, and every mutation. The injected authenticator may reach
those engine-owned cache mutations, but the retained-worktree operation
receives no registry object and contains no registry access or assignment.

This is a non-atomic manifest-to-repository spelling check followed by
delegated authentication. It does not validate the manifest schema,
authenticate the manifest file or its path ownership, canonicalize the
recorded spelling, freeze one value across the two common-directory reads, or
establish repository, Git-registration, or lifecycle authority. The injected
authenticator remains responsible for path topology and process-local cache
policy. This boundary introduces no generic contract, durable identity or
migration change, sandbox or lifecycle authority, packaging or distribution
change, or release assurance.

The twenty-second boundary moves the full eager ancestor and marker traversal
of `authenticate_git_cwd` into `identity.authenticate_git_cwd`. Its
exact-signature engine wrapper remains `(cwd)` and lazily supplies the current
path factory, protected operating-system and runtime error types,
file-not-found error type, directory and regular-file predicates, linked
identity lookup, linked-worktree authenticator, and launcher error type. The
public wrapper deliberately invokes the kernel without returning its result,
so a successful call still returns implicit `None` even if the injected kernel
alias is rebound to return an opaque value.

The operation first constructs and strictly resolves the supplied directory.
Only a selected operating-system or runtime failure in that block becomes
`the Git working directory is unavailable`, explicitly chained from the
original error. It then evaluates the literal
`(directory, *directory.parents)` before the loop: access to and complete
iteration of `parents` therefore precede the first marker join or `lstat`, and
the fixed candidates run from the directory through its
nearest-to-farthest ancestors. Parent access or iteration and candidate-marker
joining are outside the protected block, so their failures remain
untranslated.

For each candidate, the operation joins `.git` and applies `lstat`. The
file-not-found handler is selected first and advances silently; only then can a
selected broader operating-system failure become
`cannot inspect the Git administration marker`, explicitly chained from that
failure. All-marker absence falls through with implicit `None`, without a
cache lookup or linked-worktree authentication.

For an existing marker, the directory-predicate provider is resolved before a
first fresh `metadata.st_mode` read. A truthy directory result short-circuits
the regular-file predicate and every cache or linked-authentication operation.
The marker is then strictly resolved outside the `lstat` exception block and
compared with its exact pathname; a truthy inequality raises
`the primary Git administration directory is symbolic` without an explicit
cause, while equality returns `None`. If the directory predicate is false,
the regular-file-predicate provider is resolved before a second fresh
`metadata.st_mode` read. If that result is also false, the operation
immediately raises
`the Git administration marker is not a real file or directory` without an
explicit cause or further ancestor traversal.

A regular-file marker resolves the supplied identity lookup and calls it with
the candidate. The result is tested by identity with `None`, not by truthiness.
A present identity supplies a fresh `common_git_dir` read; absence supplies
`None`. Only after that choice does the operation resolve and call the
linked-worktree authenticator with the candidate positionally and the exact
`expected_common_git_dir` keyword. The authenticator's return is ignored and
the kernel returns `None`. Dependency-provider, metadata-property, predicate,
strict-resolution, comparison, truth-conversion, lookup, identity-property,
callback, and error-construction failures outside the two narrow protected
blocks remain untranslated. Lazy providers preserve the established dynamic
rebinding points.

The engine retains the exact non-returning public wrapper and every caller.
`git()` still authenticates the working directory, validates the effective Git
configuration, and only then performs the raw Git operation; Git argument
construction, command and subprocess execution, configuration probing and
failure diagnosis remain in the engine. It also retains the public
linked-worktree and retained-worktree authentication wrappers, boundary-19
path validation, boundary-20 cache validation, late
`LinkedWorktreeIdentity` construction, both process-global registry objects,
both registry writes, their dynamic rebinding and partial-mutation behavior,
all repository-discovery and lifecycle workflows, and every mutation. The
kernel receives only the identity registry's currently bound `get` operation,
not the registry object. Its linked authenticator may reach the engine-owned
registry writes, but the Git-CWD kernel performs no registry assignment
itself.

This traversal is a point-in-time pathname and metadata observation, not an
atomic authentication proof. It canonicalizes the starting directory and
eagerly snapshots the ancestor sequence but acquires no lock and pins no
descriptor; directories and markers may be replaced between or after checks.
An accepted primary `.git` directory proves only exact path equality after
strict resolution, not ownership, permissions, content, Git identity, or
lifecycle authority. A regular-file marker delegates its path, topology, and
process-local cache checks to linked-worktree authentication. No-marker
success is deliberate compatibility behavior, and a later configuration
probe or Git command may still fail. This boundary adds no generic
authentication contract, durable identity or migration change, sandbox or
lifecycle authority, packaging or distribution change, workflow change, or
release assurance.

The twenty-third boundary moves the complete read-only `discover_repository`
operation into `identity.discover_repository`. Its exact-signature engine
wrapper remains `(cwd=None)` and supplies the current path type, authenticated
Git call, absolute Git-path helper, digest and filesystem-encoding operations,
state-base and repository-slug helpers, selected profile's state-environment
name, late `Repository` constructor, selected value-error type, and launcher
error type lazily at their established lookup points.

The operation preserves the optional-current-directory selection and resolves
the start before its first authenticated Git call. It requires the exact
non-bare working-tree response, discovers and resolves the top level, then
obtains the worktree and common administration paths in selector order.
Relative-current-directory authentication precedes every state operation and
retains its exact explicitly chained diagnostic. The common-directory digest
is still the first twelve hexadecimal characters of the engine-supplied
SHA-256 operation over the engine-supplied filesystem encoding.

State-base selection remains before repository-name normalization. The joined
state path is resolved, compared with the worktree root, and only then has its
parents inspected. A state path inside the worktree resolves the selected
profile's state-environment name only while constructing the unchanged
diagnostic. On success the operation resolves the repository constructor last
and preserves every discovered component, the linked-worktree inequality,
and the resolved state root.

The engine retains the Git working-directory authentication wrapper and every
Git command, effective-configuration probe, executable cache, state-location
and repository-slug wrappers, active-profile binding, all repository
initialization and durable state operations, every repository-discovery
caller, every lifecycle workflow, and every mutation. Repository discovery is
a sequential set of Git, pathname, and state-policy observations, not an
atomic repository or state authentication proof; the checkout, Git
administration, or selected state path may change between or after them. This
boundary adds no state migration, generic adapter contract, sandbox or
lifecycle authority, packaging or distribution change, workflow change, or
release assurance.

The twenty-fourth boundary moves the existing `absolute_git_path` operation
into `git.absolute_git_path`. The exact engine wrapper remains
`(cwd, selector)` and supplies the current authenticated Git operation and path
factory lazily. The kernel preserves the exact `rev-parse`,
`--path-format=absolute`, selector argument order, strips the captured standard
output, constructs one path, resolves it with the existing non-strict default,
and returns that result without adding translation or validation.

The engine retains Git-CWD authentication, effective-configuration validation,
argument hardening, subprocess construction and execution, the pinned
executable cache, repository discovery and every lifecycle caller and
mutation. The returned path is one post-command pathname observation, not a
pinned administration identity; it may be absent or replaced after resolution.
This boundary adds no command, state, packaging, workflow, or release change.

The twenty-fifth boundary moves the existing `path_entry_exists` operation
into `identity.path_entry_exists`. Its exact engine wrapper remains
`(path, *, label)` and supplies the current file-not-found, operating-system,
and launcher error types lazily. The kernel applies `lstat` once, returns
`False` only for the selected file-not-found type, translates another selected
operating-system error into the unchanged label-specific diagnostic with an
explicit cause, and otherwise returns `True`. Matcher, label-formatting, and
error-construction failures retain their established untranslated behavior.

The engine retains all retirement callers and sequencing, path removal,
temporary-directory authentication, every state transition and durable write,
and every mutation. This probe observes only one final path entry at one
instant; it establishes no type, ownership, containment, stable descriptor
identity, or protection against later replacement. This boundary adds no
workflow, state, packaging, or release change.

The twenty-sixth boundary moves the complete `private_directory` operation
into `state.private_directory`. Its exact engine wrapper remains `(path)` and
supplies the operating-system and launcher error types, directory predicate,
portable flag lookup, read-only flag, descriptor open/stat/chmod/close
operations, and same-file predicate lazily.

The operation preserves recursive mode-0700 creation followed by final-entry
`lstat` in one translated block, the real-directory rejection, mandatory
`O_DIRECTORY` and `O_NOFOLLOW` support, and the separately translated safe
open. It then compares the opened descriptor with the pre-open metadata,
enforces mode 0700 through the descriptor, and closes that descriptor for
every post-open outcome. Closure failures may still mask the earlier result.

The engine retains directory-selection and call sequencing, profile-root and
manifest initialization, lock acquisition, manifest persistence, temporary
directory allocation, lifecycle workflows, and all higher-level mutation.
The helper narrows final-component link traversal and detects a changed
directory identity across its snapshots; it does not authenticate ancestors,
ownership, mount behavior, or later replacement. This boundary adds no state
schema, workflow, packaging, or release change.

The twenty-seventh boundary moves the complete `file_lock` context manager
into `locks.file_lock`. The exact engine wrapper remains
`(path, *, blocking=True)` and supplies private-directory setup, file open and
mode enforcement, advisory-lock flags and operation, blocking-error type,
descriptor registration and unregistration, and unlock behavior lazily.

The operation preserves parent setup, append/update UTF-8 opening, mode 0600,
exclusive and optional nonblocking acquisition, close-before-reraise on a
selected blocking error, registration only after acquisition, and the exact
unregister, unlock, close release order for every yielded outcome. The engine
retains the process-global descriptor registry and wrappers, repository/run
lock-path selection, lifecycle lock ownership and nesting, subprocess
inheritance, and every workflow decision. Advisory locks remain cooperative
and process-scoped; this boundary adds no state, workflow, packaging, or
release change.

The twenty-eighth boundary moves the complete generic `command` execution
operation into `process.command`. Its exact engine wrapper retains every
argument and default while supplying the inherited environment, Git sanitizer,
subprocess runner, inherited lock descriptors, filesystem stringifier, and
launcher error type lazily. The operation preserves copy/update/sanitize
ordering, fixed subprocess options, text and byte diagnostics, command
rendering, and exact failure fallback. The engine retains Git executable
selection, Git argument construction and policy, all callers, and every
lifecycle decision. This boundary adds no command surface, state, workflow,
packaging, or release change.

The twenty-ninth boundary moves raw Git argument construction and authenticated
Git invocation sequencing into `git.raw_git` and `git.authenticated_git`.
Exact engine wrappers and defaults remain unchanged. Raw invocation preserves
pinned-executable stringification, base-argument placement, caller arguments,
and command forwarding. Authenticated invocation preserves CWD authentication,
effective-configuration validation, hardening, and raw execution order. The
engine retains executable caching, the configuration probe, subprocess
execution, all ref and lifecycle callers, and every mutation. This boundary
adds no Git command, state, workflow, packaging, or release change.

The thirtieth boundary moves atomic manifest persistence into
`state.write_manifest`. The exact engine wrapper remains unchanged and supplies
every validation, clock, path, filesystem, JSON, descriptor, and error
dependency lazily. The operation preserves run-ID validation, in-place update
timestamp mutation, private parent setup, mode-0600 temporary creation,
sorted indented JSON plus terminal newline, file and parent-directory fsync,
atomic replacement, and best-effort temporary cleanup on every outcome. The
engine retains manifest loading and validation, transition selection, and all
write callers. This boundary changes no schema, workflow, or release surface.

The thirty-first boundary moves manifest loading and profile/repository
identity validation into `state.load_manifest`. It preserves run-ID and path
selection order, exact missing-versus-unreadable diagnostics and causes,
single profile capture after decoding, schema/run/profile identity checks,
literal common-directory comparison, and final dispatch to the existing path
validator. The engine retains path and lifecycle-state validation and every
caller. This boundary changes no schema, workflow, or release surface.

The thirty-second boundary moves exact manifest temporary-path identity into
`state.validate_exact_run_tmpdir`. It preserves run-ID type and grammar checks,
the lexical `<state-root>/tmp/<run-id>` construction, exact string comparison,
diagnostics, lazy dependency lookup, and the returned path. The engine retains
temporary-directory authentication, containment policy, removal, and every
lifecycle caller.

The thirty-third boundary moves profile-aware run-ID validation into
`state.validate_run_id`. The exact engine wrapper preserves the frozen grammar,
short-circuiting match, lazy profile display-name lookup only on rejection,
and unchanged diagnostic.

The thirty-fourth boundary moves core manifest lifecycle, worktree and
temporary containment, branch/run identity, relative-CWD containment, primary
checkout identity, and base-commit syntax into
`state.validate_manifest_core_paths`. The engine retains integration and
retirement checkpoint-field validation and target-ref authentication.

The thirty-fifth boundary moves integration and retirement object, path-list,
hash, marker, timestamp, and lifecycle-checkpoint validation into
`state.validate_manifest_checkpoint_fields`. The engine supplies the existing
field inventories and patterns at the established lookup point and retains
target-ref authentication and lifecycle sequencing.

The thirty-sixth boundary moves local target-branch type, namespace, and
Git-ref-format result validation into `state.validate_manifest_target_ref`.
The engine retains Git execution, supplies the exact non-raising ref-format
probe, and preserves its position after all other manifest validation.

The thirty-seventh boundary moves exact run temporary-parent authentication
and descriptor-relative no-follow entry probing into
`state.exact_run_tmp_parent` and `state.run_tmp_entry`. The engine supplies
its temporary-path identity validator, flag values, and descriptor operations
at the established lookup point and retains lock ownership, removal, and every
lifecycle caller.

The thirty-eighth boundary moves descriptor-relative temporary-directory
opening with pre/open identity authentication and recursive open-descriptor
content removal into `state.open_exact_temporary_directory` and
`state.remove_open_temporary_contents`. The engine supplies its flag values,
descriptor operations, entry probe, and recursion at the established lookup
point and retains every removal and lifecycle caller.

The thirty-ninth boundary moves the run temporary-root lifecycle checks —
authenticated removal with post-removal disposition, cleaned-run absence, and
exact-directory presence — into `state.remove_run_tmpdir`,
`state.require_run_tmp_absent`, and `state.require_run_tmp_directory` as
compositions of the injected parent-authentication, entry-probe, and
traversal kernels. The engine supplies its own wrappers at the established
lookup point and retains lock ownership and lifecycle sequencing.

The fortieth boundary moves the pure retirement parameter policy — exact
checkpoint object-parameter reading, operator-argument matching, conflicting
integration and cleanup lifecycle rejection, and the durable ref-cleanup
target checkpoint — into `state.retirement_parameters`,
`state.require_matching_retirement_arguments`,
`state.reject_conflicting_retirement_lifecycle`, and
`state.retirement_cleanup_target`. The engine supplies its existing field
inventory and object pattern at the established lookup point and retains
retirement authorization, Git probing, and lifecycle sequencing.

Direct tests freeze all forty extracted boundaries, their
compatibility surfaces, artifact inclusion, field and operation order,
partial-failure behavior, and the dynamic restoration of every vocabulary
value currently accepted in
`integration_previous_state` before any graph is introduced. The Make API and
legacy contract are frozen; the shared engine is
co-located behind the thin `scripts/triptych-codex` bootstrap; wheel and source
artifacts are built, a wheel is rebuilt from the extracted source artifact,
and that wheel is installed and checked outside the source checkout without
source-tree import paths; and the generic console requires the versioned,
separately named `generic-v1` state profile. The installed artifact now also
passes a bounded
stateful checkpoint covering generic preservation, integration, and cleanup
through the packaged unprefixed Make targets; bidirectional Triptych schema-1
run, status, and clean interoperability through the packaged compatibility
adapter; cross-profile selected-run lookup isolation without manifest
mutation; and generic installed-console alias rejection. A second installed
checkpoint now covers the generic packaged Make conflict flow through
resolution, continuation, opaque final-diff review, and fresh exact-candidate
landing, plus exact Triptych source restoration when aborting after a staged
resolution. A third installed checkpoint covers two deliberately overlapping
generic runs with distinct locked namespaces and isolated committed results,
followed by serial packaged Make integration: one direct fast-forward and one
conflict-free rebase onto the captured advanced target. The latter lands a
linear candidate containing both results, records its exact integration
identities, and cleans the generic worker namespace. This does not establish
scheduling throughput, concurrent integration, target-race handling, or crash
recovery. A fourth installed checkpoint covers direct generic retirement of one
eligible clean rewritten quarantine. It verifies representative non-mutating
refusals, the exact discard, containment, initial-target, and cleanup-target
identities, unchanged target and control state, bounded removal of the worker
and its exact namespace as observed at completion, retention of the cleaned
manifest, durable completion checkpoints, and completed-state exact-command
idempotency across the manifest, refs, worktree registrations, and surviving
sentinels. The containment checkpoint proves reachability only, not
incorporation or semantic supersession.

The retirement checkpoint does not establish the full eligibility and refusal
matrix, target-race, tamper, active-worker, interrupted-checkpoint,
worktree-removal, ref-transaction, receipt-recovery, garbage-collection, or
concurrent-retirement behavior. Those cases and the broader recovery, security,
complete installed-lifecycle, and supported Python and Git CI matrices remain
release gates. These bounded checkpoints advance but do not satisfy step 6.

## Distribution and repository integration

The extracted project is a standard Python package named `worktree-marshal`,
requires Python 3.10 or newer on POSIX, has no runtime dependency beyond the
standard library and Git, and is licensed under MIT. Release artifacts should
be reproducible wheels and source distributions published from a dedicated
repository after signed tags and CI across supported Python and Git versions.

End users should install a pinned release with an isolated application
installer such as `pipx` or `uv tool`. A package command will write a versioned
Make fragment into a repository so Make does not execute Python merely to find
an installed resource at parse time. The fragment defaults to the plain
targets `codex`, `status`, `reopen`, `final-diff`, `integrate`, `resolve`,
`continue`, `abort`, and `clean-run`; projects may configure those names before
generation when they conflict. Generated configuration is fixed Makefile code,
not invocation-controlled shell input, and target names use a restricted
literal grammar. The native CLI remains canonical for automation and for any
run ID not obtained from the local launcher.
