"""Profile-bound transactional worktree lifecycle engine.

The launcher is deliberately conservative.  It never copies a dirty checkout,
never grants Codex another writable checkout, and never commits, integrates, or
pushes a result merely because the child process exits.
"""

from __future__ import annotations

import fcntl
import hashlib
import json
import os
import re
import secrets
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator, Sequence, TextIO

from .adapters.codex import (
    EXEC_FLAG_OPTIONS,
    EXEC_VALUE_OPTIONS,
    NON_AGENT_CODEX_COMMANDS,
    REVIEW_FLAG_OPTIONS,
    REVIEW_VALUE_OPTIONS,
    ROOT_FLAG_OPTIONS,
    ROOT_VALUE_OPTIONS,
    codex_argv as _codex_argv,
    codex_environment as _codex_environment,
    enrich_codex_environment as _enrich_codex_environment,
    normalize_codex_arguments as _normalize_codex_arguments,
    scan_allowed_options as _scan_allowed_options,
    select_codex_executable as _select_codex_executable,
)
from .git import (
    GIT_BASE_ARGUMENTS,
    GIT_BOOLEAN_VALUES,
    GIT_COMMAND_CONFIG_RE,
    GIT_INDEXED_CONFIG_ENV_RE,
    GIT_UNSAFE_ENV,
    absolute_git_path as _absolute_git_path,
    authenticated_git as _authenticated_git,
    discover_git_executable as _discover_git_executable,
    hardened_git_arguments,
    raw_git as _raw_git,
    sanitized_git_environment as _sanitized_git_environment,
    validate_effective_git_configuration as _validate_effective_git_configuration,
)
from .identity import (
    LauncherIdentity,
    LinkedWorktreeIdentity,
    Repository,
    authenticate_git_cwd as _authenticate_git_cwd,
    authenticate_launcher as _authenticate_launcher,
    authenticate_retained_worktree as _authenticate_retained_worktree,
    discover_repository as _discover_repository,
    exact_pointer_path as _exact_pointer_path,
    exact_real_directory as _exact_real_directory,
    exact_single_line as _exact_single_line,
    path_entry_exists as _path_entry_exists,
    safe_regular_file_bytes as _safe_regular_file_bytes,
    validate_linked_worktree_identity_cache as _validate_linked_worktree_identity_cache,
    validate_linked_worktree_path as _validate_linked_worktree_path,
)
from .locks import (
    RegisteredLockDescriptor,
    file_lock as _file_lock,
    inherited_lock_descriptors as _inherited_lock_descriptors,
    register_lock_descriptor as _register_lock_descriptor,
    unregister_lock_descriptor as _unregister_lock_descriptor,
)
from .model import (
    ABORTED_INTEGRATION_ARCHIVE_FIELDS as _ABORTED_INTEGRATION_ARCHIVE_FIELDS,
    INTEGRATION_TRANSACTION_FIELDS,
    MANAGED_CONFLICT_STATES,
    MANUAL_LANDING_CHECKPOINT_FIELDS,
    RETIREMENT_PENDING_STATES,
    RUN_STATES,
    is_run_state,
    restore_integration_transaction as _restore_integration_transaction,
)
from .process import (
    command as _command,
    normalized_exit_status as _normalized_exit_status,
    wait_for_child as _wait_for_child,
)
from .profiles import (
    BUILTIN_PROFILES,
    CONTROL_ENVIRONMENTS,
    MANAGED_CONTEXT_ENVIRONMENTS,
    RuntimeProfile,
)
from .state import (
    RUN_ID_RE,
    exact_run_tmp_parent as _exact_run_tmp_parent,
    manifest_path as _manifest_path,
    load_manifest as _load_manifest,
    new_run_id as _new_run_id,
    open_exact_temporary_directory as _open_exact_temporary_directory,
    private_directory as _private_directory,
    reject_conflicting_retirement_lifecycle as _reject_conflicting_retirement_lifecycle,
    remove_open_temporary_contents as _remove_open_temporary_contents,
    remove_run_tmpdir as _remove_run_tmpdir,
    repo_lock_path as _repo_lock_path,
    repository_slug as _repository_slug,
    require_matching_retirement_arguments as _require_matching_retirement_arguments,
    require_run_tmp_absent as _require_run_tmp_absent,
    require_run_tmp_directory as _require_run_tmp_directory,
    retirement_cleanup_target as _retirement_cleanup_target,
    retirement_parameters as _retirement_parameters,
    run_lock_path as _run_lock_path,
    run_tmp_entry as _run_tmp_entry,
    state_base as _state_base,
    validate_exact_run_tmpdir as _validate_exact_run_tmpdir,
    validate_manifest_checkpoint_fields as _validate_manifest_checkpoint_fields,
    validate_manifest_core_paths as _validate_manifest_core_paths,
    validate_manifest_target_ref as _validate_manifest_target_ref,
    validate_run_id as _validate_run_id,
    write_manifest as _write_manifest,
)

OBJECT_ID_RE = re.compile(r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")
RETIREMENT_OBJECT_FIELDS = (
    "retirement_discard_head",
    "retirement_target_contains",
    "retirement_initial_target_head",
    "retirement_cleanup_target_head",
)
RETIREMENT_CORE_FIELDS = RETIREMENT_OBJECT_FIELDS[:3]
RETIREMENT_FIELDS = (
    *RETIREMENT_OBJECT_FIELDS,
    "retirement_started_at",
    "retirement_anchor_created",
    "retirement_worktree_removed_at",
    "retirement_ref_cleanup_started_at",
    "retirement_ref_transaction_committed_at",
    "retirement_receipt_removed_at",
    "retirement_completed_at",
    "retirement_cleanup_warning",
)
RETIREMENT_TIMESTAMP_FIELDS = (
    "retirement_started_at",
    "retirement_worktree_removed_at",
    "retirement_ref_cleanup_started_at",
    "retirement_ref_transaction_committed_at",
    "retirement_receipt_removed_at",
    "retirement_completed_at",
)
MAX_ADMIN_FILE_BYTES = 16 * 1024 * 1024
MAX_ADMIN_TREE_BYTES = 64 * 1024 * 1024


class LauncherError(RuntimeError):
    """A fail-closed launcher error suitable for display to the operator."""


class ManagedConflictScopeError(LauncherError):
    """A correctable resolver-scope violation with intact rebase administration."""


@dataclass(frozen=True)
class Audit:
    registered: bool
    locked: bool
    branch: str | None
    head: str | None
    status: str | None

    @property
    def clean(self) -> bool:
        return self.status == ""


_ACTIVE_PROFILE: ContextVar[RuntimeProfile] = ContextVar(
    "worktree_marshal_active_profile"
)
_PINNED_GIT: Path | None = None
_LOCK_FD_REGISTRY: dict[int, RegisteredLockDescriptor] = {}
_LINKED_WORKTREE_IDENTITIES: dict[Path, LinkedWorktreeIdentity] = {}
_LINKED_ADMIN_OWNERS: dict[Path, Path] = {}


def active_profile() -> RuntimeProfile:
    try:
        return _ACTIVE_PROFILE.get()
    except LookupError as exc:
        raise RuntimeError("the lifecycle profile is not bound") from exc


@contextmanager
def profile_context(profile: RuntimeProfile) -> Iterator[None]:
    token = _ACTIVE_PROFILE.set(profile)
    try:
        yield
    finally:
        _ACTIVE_PROFILE.reset(token)


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def new_run_id() -> str:
    return _new_run_id(
        current_time=lambda: datetime.now(timezone.utc),
        random_suffix=lambda: secrets.token_hex(6),
    )


def diagnostic(message: str) -> None:
    print(f"{active_profile().diagnostic_name}: {message}", file=sys.stderr)


def authenticate_launcher(path: Path) -> LauncherIdentity:
    return _authenticate_launcher(
        path,
        os_error_type=lambda: OSError,
        error_type=lambda: LauncherError,
        regular_file_test=lambda: stat.S_ISREG,
        access_check=lambda: os.access,
        executable_mode=lambda: os.X_OK,
        identity_factory=lambda: LauncherIdentity,
    )


def pin_git_executable() -> Path:
    global _PINNED_GIT
    if _PINNED_GIT is not None:
        return _PINNED_GIT
    resolved = _discover_git_executable(
        executable_locator=lambda: shutil.which,
        path_factory=lambda: Path,
        os_error_type=lambda: OSError,
        error_type=lambda: LauncherError,
        regular_file_test=lambda: stat.S_ISREG,
        access_check=lambda: os.access,
        executable_mode=lambda: os.X_OK,
    )
    _PINNED_GIT = resolved
    return resolved


def sanitized_git_environment(
    source: dict[str, str] | None = None,
) -> dict[str, str]:
    """Preserve the legacy optional-source API around the pure policy helper."""
    return _sanitized_git_environment(
        os.environ if source is None else source,
        unsafe_names=GIT_UNSAFE_ENV,
        indexed_config_pattern=GIT_INDEXED_CONFIG_ENV_RE,
    )


def register_lock_descriptor(stream: TextIO) -> None:
    _register_lock_descriptor(
        stream,
        registry=lambda: _LOCK_FD_REGISTRY,
        record_factory=lambda: RegisteredLockDescriptor,
    )


def unregister_lock_descriptor(stream: TextIO) -> None:
    _unregister_lock_descriptor(
        stream,
        registry=lambda: _LOCK_FD_REGISTRY,
    )


def inherited_lock_descriptors() -> tuple[int, ...]:
    return _inherited_lock_descriptors(registry=lambda: _LOCK_FD_REGISTRY)


def command(
    argv: Sequence[str],
    *,
    cwd: Path,
    check: bool = True,
    text: bool = True,
    environment: dict[str, str] | None = None,
    input_data: str | bytes | None = None,
) -> subprocess.CompletedProcess:
    return _command(
        argv,
        cwd=cwd,
        check=check,
        text=text,
        environment=environment,
        input_data=input_data,
        base_environment=lambda: os.environ,
        sanitize_environment=lambda: sanitized_git_environment,
        process_run=lambda: subprocess.run,
        inherited_descriptors=lambda: inherited_lock_descriptors(),
        filesystem_path=lambda: os.fspath,
        error_type=lambda: LauncherError,
    )


def raw_git(
    cwd: Path,
    *args: str,
    check: bool = True,
    text: bool = True,
    environment: dict[str, str] | None = None,
    input_data: str | bytes | None = None,
) -> subprocess.CompletedProcess:
    return _raw_git(
        cwd=cwd,
        args=args,
        check=check,
        text=text,
        environment=environment,
        input_data=input_data,
        executable=lambda: pin_git_executable(),
        base_arguments=lambda: GIT_BASE_ARGUMENTS,
        command_call=lambda: command,
    )


def validate_effective_git_configuration(cwd: Path) -> None:
    result = raw_git(cwd, "config", "--null", "--list", text=False, check=False)
    if result.returncode:
        raise LauncherError("cannot inspect the repository's effective Git configuration")
    _validate_effective_git_configuration(
        result.stdout,
        error_type=lambda: LauncherError,
        boolean_values=lambda: GIT_BOOLEAN_VALUES,
        command_config_pattern=lambda: GIT_COMMAND_CONFIG_RE,
    )


def git(
    cwd: Path,
    *args: str,
    check: bool = True,
    text: bool = True,
    environment: dict[str, str] | None = None,
    input_data: str | bytes | None = None,
) -> subprocess.CompletedProcess:
    return _authenticated_git(
        cwd,
        args,
        check=check,
        text=text,
        environment=environment,
        input_data=input_data,
        authenticate_cwd=lambda: authenticate_git_cwd,
        validate_configuration=lambda: validate_effective_git_configuration,
        harden_arguments=lambda: hardened_git_arguments,
        raw_git_call=lambda: raw_git,
    )


def absolute_git_path(cwd: Path, selector: str) -> Path:
    return _absolute_git_path(
        cwd,
        selector,
        git_call=lambda: git,
        path_factory=lambda: Path,
    )


def safe_regular_file_bytes(path: Path, *, label: str) -> bytes:
    return _safe_regular_file_bytes(
        path,
        label=label,
        open_flags=lambda: (
            os.O_RDONLY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
        ),
        file_open=lambda: os.open,
        os_error_type=lambda: OSError,
        error_type=lambda: LauncherError,
        file_stat=lambda: os.fstat,
        regular_file_test=lambda: stat.S_ISREG,
        maximum_file_bytes=lambda: MAX_ADMIN_FILE_BYTES,
        file_read=lambda: os.read,
        minimum=lambda: min,
        length=lambda: len,
        file_close=lambda: os.close,
    )


def exact_single_line(path: Path, *, label: str) -> str:
    return _exact_single_line(
        path,
        label=label,
        file_reader=lambda: safe_regular_file_bytes,
        decode_error_type=lambda: UnicodeDecodeError,
        error_type=lambda: LauncherError,
    )


def exact_pointer_path(raw_value: str, *, relative_to: Path, label: str) -> Path:
    return _exact_pointer_path(
        raw_value,
        relative_to=relative_to,
        label=label,
        path_factory=lambda: Path,
        absolute_path=lambda: os.path.abspath,
        filesystem_path=lambda: os.fspath,
        os_error_type=lambda: OSError,
        runtime_error_type=lambda: RuntimeError,
        error_type=lambda: LauncherError,
    )


def exact_real_directory(path: Path, *, label: str) -> Path:
    return _exact_real_directory(
        path,
        label=label,
        path_factory=lambda: Path,
        absolute_path=lambda: os.path.abspath,
        filesystem_path=lambda: os.fspath,
        os_error_type=lambda: OSError,
        runtime_error_type=lambda: RuntimeError,
        directory_test=lambda: stat.S_ISDIR,
        error_type=lambda: LauncherError,
    )


def path_entry_exists(path: Path, *, label: str) -> bool:
    return _path_entry_exists(
        path,
        label=label,
        file_not_found_error_type=lambda: FileNotFoundError,
        os_error_type=lambda: OSError,
        error_type=lambda: LauncherError,
    )


def authenticate_linked_worktree_path(
    worktree: Path,
    *,
    expected_common_git_dir: Path | None = None,
) -> LinkedWorktreeIdentity:
    (
        canonical_worktree,
        git_file,
        git_dir,
        common_git_dir,
    ) = _validate_linked_worktree_path(
        worktree,
        expected_common_git_dir=expected_common_git_dir,
        real_directory=lambda: exact_real_directory,
        single_line=lambda: exact_single_line,
        pointer_path=lambda: exact_pointer_path,
        length=lambda: len,
        error_type=lambda: LauncherError,
    )

    identity = LinkedWorktreeIdentity(
        worktree=canonical_worktree,
        git_file=git_file,
        git_dir=git_dir,
        common_git_dir=common_git_dir,
    )
    _validate_linked_worktree_identity_cache(
        identity,
        canonical_worktree=canonical_worktree,
        prior_identity=lambda: _LINKED_WORKTREE_IDENTITIES.get(
            canonical_worktree
        ),
        admin_owner=lambda: _LINKED_ADMIN_OWNERS.get(git_dir),
        error_type=lambda: LauncherError,
    )
    _LINKED_WORKTREE_IDENTITIES[canonical_worktree] = identity
    _LINKED_ADMIN_OWNERS[git_dir] = canonical_worktree
    return identity


def authenticate_retained_worktree(
    repository: Repository,
    manifest: dict,
) -> LinkedWorktreeIdentity:
    return _authenticate_retained_worktree(
        repository,
        manifest,
        stringifier=lambda: str,
        error_type=lambda: LauncherError,
        linked_worktree_authenticator=lambda: authenticate_linked_worktree_path,
        path_factory=lambda: Path,
    )


def authenticate_git_cwd(cwd: Path) -> None:
    _authenticate_git_cwd(
        cwd,
        path_factory=lambda: Path,
        os_error_type=lambda: OSError,
        runtime_error_type=lambda: RuntimeError,
        file_not_found_error_type=lambda: FileNotFoundError,
        directory_test=lambda: stat.S_ISDIR,
        regular_file_test=lambda: stat.S_ISREG,
        identity_lookup=lambda: _LINKED_WORKTREE_IDENTITIES.get,
        linked_worktree_authenticator=lambda: authenticate_linked_worktree_path,
        error_type=lambda: LauncherError,
    )


def state_base() -> Path:
    profile = active_profile()
    return _state_base(
        profile=profile,
        environment=lambda: os.environ,
        path_factory=lambda value: Path(value),
        home=lambda: Path.home(),
        error_type=lambda: LauncherError,
    )


def private_directory(path: Path) -> None:
    _private_directory(
        path,
        os_error_type=lambda: OSError,
        error_type=lambda: LauncherError,
        directory_test=lambda: stat.S_ISDIR,
        flag_lookup=lambda: lambda name, default: getattr(os, name, default),
        read_only_flag=lambda: os.O_RDONLY,
        file_open=lambda: os.open,
        file_stat=lambda: os.fstat,
        same_stat=lambda: os.path.samestat,
        file_chmod=lambda: os.fchmod,
        file_close=lambda: os.close,
    )


def repository_slug(root: Path) -> str:
    return _repository_slug(root, substitute=re.sub)


def discover_repository(cwd: Path | None = None) -> Repository:
    return _discover_repository(
        cwd,
        path_factory=lambda: Path,
        git_call=lambda: git,
        absolute_git_path=lambda: absolute_git_path,
        digest_factory=lambda: hashlib.sha256,
        filesystem_encode=lambda: os.fsencode,
        state_base=lambda: state_base,
        repository_slug=lambda: repository_slug,
        state_environment=lambda: active_profile().state_environment,
        repository_factory=lambda: Repository,
        value_error_type=lambda: ValueError,
        error_type=lambda: LauncherError,
    )


def _initialize_profile_root_locked(repository: Repository) -> None:
    profile = active_profile()
    if profile.manifest_profile_id is None:
        return
    marker = repository.state_root / "profile.json"
    expected = {
        "agent": profile.manifest_agent,
        "format_id": "worktree-marshal-profile-root",
        "profile_id": profile.profile_id,
        "schema_version": profile.schema_version,
    }
    if not marker.exists():
        unexpected = [
            path.name
            for path in repository.state_root.iterdir()
            if path.name != "profile.lock"
        ]
        if unexpected:
            raise LauncherError(
                "the generic profile state root is unmarked and nonempty"
            )
        flags = (
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
        )
        try:
            descriptor = os.open(marker, flags, 0o600)
        except FileExistsError:
            pass
        except OSError as exc:
            raise LauncherError("cannot create the generic profile marker") from exc
        else:
            with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
                json.dump(expected, stream, indent=2, sort_keys=True)
                stream.write("\n")
                stream.flush()
                os.fsync(stream.fileno())
            directory_descriptor = os.open(
                repository.state_root,
                os.O_RDONLY | getattr(os, "O_DIRECTORY", 0),
            )
            try:
                os.fsync(directory_descriptor)
            finally:
                os.close(directory_descriptor)
    try:
        recorded = json.loads(
            safe_regular_file_bytes(
                marker,
                label="the generic profile marker",
            ).decode("utf-8")
        )
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise LauncherError("cannot authenticate the generic profile marker") from exc
    if recorded != expected:
        raise LauncherError("the generic profile marker does not match this profile")


def initialize_profile_root(repository: Repository) -> None:
    if active_profile().manifest_profile_id is None:
        return
    with file_lock(repository.state_root / "profile.lock"):
        _initialize_profile_root_locked(repository)


def initialize_state(repository: Repository) -> None:
    private_directory(repository.state_root)
    initialize_profile_root(repository)
    private_directory(repository.state_root / "runs")
    private_directory(repository.state_root / "worktrees")
    private_directory(repository.state_root / "tmp")


@contextmanager
def file_lock(path: Path, *, blocking: bool = True) -> Iterator[TextIO]:
    with _file_lock(
        path,
        blocking=blocking,
        private_directory=lambda: private_directory,
        file_open=lambda: path.open,
        file_chmod=lambda: os.chmod,
        exclusive_flag=lambda: fcntl.LOCK_EX,
        nonblocking_flag=lambda: fcntl.LOCK_NB,
        lock_operation=lambda: fcntl.flock,
        blocking_error_type=lambda: BlockingIOError,
        register_descriptor=lambda: register_lock_descriptor,
        unregister_descriptor=lambda: unregister_lock_descriptor,
        unlock_flag=lambda: fcntl.LOCK_UN,
    ) as stream:
        yield stream


def repo_lock_path(repository: Repository) -> Path:
    state_root = repository.state_root
    return _repo_lock_path(state_root)


def run_lock_path(repository: Repository, run_id: str) -> Path:
    state_root = repository.state_root
    return _run_lock_path(state_root, run_id)


def manifest_path(repository: Repository, run_id: str) -> Path:
    state_root = repository.state_root
    return _manifest_path(state_root, run_id)


def validate_run_id(run_id: str) -> None:
    _validate_run_id(
        run_id,
        pattern=lambda: RUN_ID_RE,
        display_name=lambda: active_profile().display_name,
        error_type=lambda: LauncherError,
    )


def validate_exact_run_tmpdir(
    repository: Repository,
    manifest: dict,
) -> Path:
    return _validate_exact_run_tmpdir(
        repository,
        manifest,
        validate_run_id=lambda: validate_run_id,
        stringifier=lambda: str,
        error_type=lambda: LauncherError,
    )


def write_manifest(repository: Repository, manifest: dict) -> None:
    _write_manifest(
        repository,
        manifest,
        validate_run_id=lambda: validate_run_id,
        current_timestamp=lambda: utc_now,
        manifest_path=lambda: manifest_path,
        private_directory=lambda: private_directory,
        make_temporary=lambda: tempfile.mkstemp,
        path_factory=lambda: Path,
        descriptor_chmod=lambda: os.fchmod,
        descriptor_open=lambda: os.fdopen,
        json_dump=lambda: json.dump,
        replace_path=lambda: os.replace,
        directory_open=lambda: os.open,
        read_only_flag=lambda: os.O_RDONLY,
        directory_flag=lambda: getattr(os, "O_DIRECTORY", 0),
        descriptor_sync=lambda: os.fsync,
        descriptor_close=lambda: os.close,
        error_type=lambda: LauncherError,
    )


def load_manifest(repository: Repository, run_id: str) -> dict:
    return _load_manifest(
        repository,
        run_id,
        validate_run_id=lambda: validate_run_id,
        manifest_path=lambda: manifest_path,
        json_loads=lambda: json.loads,
        file_not_found_error_type=lambda: FileNotFoundError,
        os_error_type=lambda: OSError,
        decode_error_type=lambda: json.JSONDecodeError,
        active_profile=lambda: active_profile(),
        validate_manifest_paths=lambda: validate_manifest_paths,
        stringifier=lambda: str,
        error_type=lambda: LauncherError,
    )


def validate_manifest_paths(repository: Repository, manifest: dict) -> None:
    state = _validate_manifest_core_paths(
        repository,
        manifest,
        run_state_test=lambda value: is_run_state(
            value,
            run_states=RUN_STATES,
        ),
        retirement_states=RETIREMENT_PENDING_STATES,
        path_factory=Path,
        validate_temporary=validate_exact_run_tmpdir,
        authenticate_temporary_parent=exact_run_tmp_parent,
        worker_branch_prefix=lambda: active_profile().worker_branch_prefix,
        object_id_pattern=OBJECT_ID_RE,
        error_type=LauncherError,
    )
    _validate_manifest_checkpoint_fields(
        manifest,
        state,
        object_fields=(
            "final_head",
            "observed_head",
            "integrated_head",
            "integration_source_head",
            "integration_target_head",
            "integration_candidate_head",
            "integration_conflict_head",
            "integration_conflict_commit",
            "integration_precommit_commit",
            "integration_precommit_index_tree",
            "integration_target_mismatch_head",
            "integration_landing_expected_head",
            "integration_landing_candidate_head",
            "cleanup_expected_head",
            "last_integration_source_head",
            "last_integration_target_head",
            "last_integration_candidate_head",
        ),
        retirement_object_fields=RETIREMENT_OBJECT_FIELDS,
        path_fields=(
            "integration_conflict_paths",
            "integration_unmerged_paths",
            "integration_allowed_staged_paths",
            "integration_protected_index_paths",
            "last_integration_conflict_paths",
        ),
        hash_fields=(
            "integration_protected_index_hash",
            "integration_rebase_metadata_hash",
        ),
        retirement_timestamp_fields=RETIREMENT_TIMESTAMP_FIELDS,
        retirement_fields=RETIREMENT_FIELDS,
        retirement_core_fields=RETIREMENT_CORE_FIELDS,
        retirement_states=RETIREMENT_PENDING_STATES,
        object_id_pattern=OBJECT_ID_RE,
        hash_match=lambda value: re.fullmatch(r"[0-9a-f]{64}", value),
        error_type=LauncherError,
    )
    _validate_manifest_target_ref(
        repository,
        manifest,
        check_ref_format=lambda root, target_ref: git(
            root,
            "check-ref-format",
            target_ref,
            check=False,
        ),
        error_type=LauncherError,
    )


def resolve_real_codex(launcher: LauncherIdentity) -> Path:
    profile = active_profile()
    return _select_codex_executable(
        launcher,
        profile=profile,
        environment=lambda: os.environ,
        path_factory=lambda: Path,
        executable_path=lambda: os.get_exec_path,
        current_directory=lambda: os.curdir,
        os_error_type=lambda: OSError,
        regular_file_test=lambda: stat.S_ISREG,
        access_check=lambda: os.access,
        executable_mode=lambda: os.X_OK,
        error_type=lambda: LauncherError,
    )


def scan_allowed_options(
    arguments: list[str],
    start: int,
    flag_options: set[str],
    value_options: set[str],
) -> tuple[int, bool, bool]:
    return _scan_allowed_options(
        arguments,
        start,
        flag_options,
        value_options,
        length=lambda: len,
        error_type=lambda: LauncherError,
    )


def normalize_codex_arguments(arguments: Sequence[str]) -> tuple[list[str], bool]:
    return _normalize_codex_arguments(
        arguments,
        list_factory=lambda: list,
        length=lambda: len,
        option_scanner=lambda: scan_allowed_options,
        root_flag_options=lambda: ROOT_FLAG_OPTIONS,
        root_value_options=lambda: ROOT_VALUE_OPTIONS,
        exec_flag_options=lambda: EXEC_FLAG_OPTIONS,
        exec_value_options=lambda: EXEC_VALUE_OPTIONS,
        review_flag_options=lambda: REVIEW_FLAG_OPTIONS,
        review_value_options=lambda: REVIEW_VALUE_OPTIONS,
        non_agent_commands=lambda: NON_AGENT_CODEX_COMMANDS,
        reopen_hint=lambda: (
            active_profile().lifecycle_hint("reopen")
        ),
        error_type=lambda: LauncherError,
    )


def codex_argv(real_codex: Path, workdir: Path, arguments: Sequence[str]) -> list[str]:
    return _codex_argv(
        real_codex,
        workdir,
        arguments,
        argument_normalizer=lambda: normalize_codex_arguments,
        stringifier=lambda: str,
    )


def require_stable_clean_base(
    repository: Repository,
    *,
    purpose: str = "starting an isolated session",
) -> tuple[str, str]:
    if repository.linked_worktree:
        raise LauncherError("internal error: attempted to allocate from a linked worktree")
    status = git(
        repository.root,
        "status",
        "--porcelain=v1",
        "--untracked-files=all",
    ).stdout
    if status:
        raise LauncherError(
            f"the control checkout is not clean; review or preserve its changes before {purpose}"
        )

    for marker in (
        "MERGE_HEAD",
        "CHERRY_PICK_HEAD",
        "REVERT_HEAD",
        "BISECT_LOG",
        "rebase-apply",
        "rebase-merge",
    ):
        marker_path = Path(git(repository.root, "rev-parse", "--git-path", marker).stdout.strip())
        if not marker_path.is_absolute():
            marker_path = repository.root / marker_path
        if marker_path.exists():
            raise LauncherError(f"Git operation in progress ({marker}); finish it before {purpose}")

    base_sha = git(repository.root, "rev-parse", "--verify", "HEAD^{commit}").stdout.strip()
    branch_ref = git(repository.root, "symbolic-ref", "--quiet", "HEAD", check=False)
    if branch_ref.returncode:
        raise LauncherError("the control checkout must be on a named branch")
    return base_sha, branch_ref.stdout.strip()


def worktree_records(repository: Repository) -> list[dict[str, str | bool]]:
    result = git(
        repository.root,
        "worktree",
        "list",
        "--porcelain",
        "-z",
        text=False,
    )
    records: list[dict[str, str | bool]] = []
    current: dict[str, str | bool] = {}
    for raw_field in result.stdout.split(b"\0"):
        if not raw_field:
            if current:
                records.append(current)
                current = {}
            continue
        field = raw_field.decode("utf-8", errors="surrogateescape")
        key, separator, value = field.partition(" ")
        if key == "worktree" and current:
            records.append(current)
            current = {}
        current[key] = value if separator else True
    if current:
        records.append(current)
    return records


def registered_record(repository: Repository, worktree: Path) -> dict[str, str | bool] | None:
    expected = Path(os.path.abspath(os.fspath(worktree)))
    for record in worktree_records(repository):
        value = record.get("worktree")
        if isinstance(value, str) and Path(os.path.abspath(value)) == expected:
            return record
    return None


def audit_run(repository: Repository, manifest: dict) -> Audit:
    worktree = Path(manifest["worktree"])
    if worktree.is_symlink():
        return Audit(False, False, None, None, None)
    record = registered_record(repository, worktree)
    if record is None or not worktree.is_dir():
        return Audit(False, False, None, None, None)
    authenticate_retained_worktree(repository, manifest)

    branch_result = git(worktree, "symbolic-ref", "--quiet", "--short", "HEAD", check=False)
    branch = branch_result.stdout.strip() if branch_result.returncode == 0 else None
    head_result = git(worktree, "rev-parse", "--verify", "HEAD^{commit}", check=False)
    head = head_result.stdout.strip() if head_result.returncode == 0 else None
    status_result = git(
        worktree,
        "status",
        "--porcelain=v1",
        "--untracked-files=all",
        check=False,
    )
    status = status_result.stdout if status_result.returncode == 0 else None
    return Audit(
        registered=True,
        locked="locked" in record,
        branch=branch,
        head=head,
        status=status,
    )


def exact_unchanged_audit(manifest: dict, audit: Audit) -> bool:
    return (
        audit.registered
        and audit.locked
        and audit.branch == manifest["branch"]
        and audit.head == manifest["base_sha"]
        and audit.clean
    )


def allocate_run(repository: Repository) -> tuple[dict, TextIO]:
    initialize_state(repository)
    repository_lock = repo_lock_path(repository)
    with file_lock(repository_lock):
        base_sha, target_ref = require_stable_clean_base(repository)
        for _ in range(16):
            run_id = new_run_id()
            worktree = repository.state_root / "worktrees" / run_id
            if not worktree.exists() and not manifest_path(repository, run_id).exists():
                break
        else:
            raise LauncherError("could not allocate a unique run ID")

        profile = active_profile()
        branch = f"{profile.worker_branch_prefix}{run_id}"
        temporary = repository.state_root / "tmp" / run_id
        private_directory(temporary)
        manifest = {
            "schema_version": profile.schema_version,
            "run_id": run_id,
            "state": "allocating",
            "created_at": utc_now(),
            "base_sha": base_sha,
            "target_ref": target_ref,
            "branch": branch,
            "control_root": str(repository.root),
            "common_git_dir": str(repository.common_git_dir),
            "relative_cwd": repository.relative_cwd.as_posix(),
            "worktree": str(worktree),
            "tmpdir": str(temporary),
            **profile.manifest_identity(),
        }
        write_manifest(repository, manifest)
        try:
            git(
                repository.root,
                "worktree",
                "add",
                "--quiet",
                "--lock",
                "--reason",
                f"{profile.lock_reason_prefix}{run_id}",
                "-b",
                branch,
                str(worktree),
                base_sha,
            )
            audit = audit_run(repository, manifest)
            if not exact_unchanged_audit(manifest, audit):
                raise LauncherError("new worktree failed its post-allocation audit")
            child_cwd = worktree / repository.relative_cwd
            if not child_cwd.is_dir():
                raise LauncherError("the starting subdirectory is absent from the allocated worktree")
            manifest["state"] = "ready"
            write_manifest(repository, manifest)
        except Exception as exc:
            manifest["state"] = "allocation-failed"
            manifest["error"] = str(exc)
            write_manifest(repository, manifest)
            raise

        run_lock_stream = run_lock_path(repository, run_id).open("a+", encoding="utf-8")
        os.chmod(run_lock_path(repository, run_id), 0o600)
        fcntl.flock(run_lock_stream.fileno(), fcntl.LOCK_EX)
        register_lock_descriptor(run_lock_stream)
        return manifest, run_lock_stream


def child_environment(manifest: dict, real_codex: Path) -> dict[str, str]:
    profile = active_profile()
    environment = codex_environment(real_codex)
    return _enrich_codex_environment(
        environment,
        profile=profile,
        role="worker",
        manifest=manifest,
    )


def resolver_environment(manifest: dict, real_codex: Path) -> dict[str, str]:
    profile = active_profile()
    environment = codex_environment(real_codex)
    return _enrich_codex_environment(
        environment,
        profile=profile,
        role="resolver",
        manifest=manifest,
    )


def codex_environment(real_codex: Path) -> dict[str, str]:
    profile = active_profile()
    return _codex_environment(
        real_codex,
        profile=profile,
        sanitized_environment=lambda: sanitized_git_environment,
        control_environments=lambda: CONTROL_ENVIRONMENTS,
        stringifier=lambda: str,
        executable_path=lambda: os.get_exec_path,
        path_separator=lambda: os.pathsep,
    )


def wait_for_child(process: subprocess.Popen) -> int:
    return _wait_for_child(
        process,
        forwarded_signals=lambda: (signal.SIGHUP, signal.SIGTERM),
        get_signal_handler=lambda signum: signal.getsignal(signum),
        set_signal_handler=lambda signum, handler: signal.signal(
            signum,
            handler,
        ),
        interrupt_signal=lambda: signal.SIGINT,
        keyboard_interrupt=lambda: KeyboardInterrupt,
        process_lookup_error=lambda: ProcessLookupError,
        timeout_expired=lambda: subprocess.TimeoutExpired,
    )


def normalized_exit_status(returncode: int) -> int:
    return _normalized_exit_status(
        returncode,
        absolute=lambda value: abs(value),
    )


def branch_is_integrated(repository: Repository, manifest: dict, head: str) -> bool:
    target_ref = manifest.get("target_ref")
    if not isinstance(target_ref, str):
        return False
    target = git(repository.root, "rev-parse", "--verify", target_ref, check=False)
    if target.returncode:
        return False
    result = git(
        repository.root,
        "merge-base",
        "--is-ancestor",
        head,
        target.stdout.strip(),
        check=False,
    )
    return result.returncode == 0


def commit_is_ancestor(repository: Repository, ancestor: str, descendant: str) -> bool:
    result = git(
        repository.root,
        "merge-base",
        "--is-ancestor",
        ancestor,
        descendant,
        check=False,
    )
    if result.returncode not in {0, 1}:
        raise LauncherError(
            f"cannot compare retained-run history: {result.stderr.strip() or 'no diagnostic'}"
        )
    return result.returncode == 0


def recorded_commit(repository: Repository, manifest: dict, field: str) -> str:
    value = manifest.get(field)
    if not isinstance(value, str) or not OBJECT_ID_RE.fullmatch(value):
        raise LauncherError(f"the retained run has no valid recorded {field.replace('_', ' ')}")
    resolved = git(
        repository.root,
        "rev-parse",
        "--verify",
        f"{value}^{{commit}}",
        check=False,
    )
    if resolved.returncode or resolved.stdout.strip() != value:
        raise LauncherError(
            f"the retained run's recorded {field.replace('_', ' ')} is unavailable"
        )
    return value


def exact_commit_argument(repository: Repository, value: str, option: str) -> str:
    if not OBJECT_ID_RE.fullmatch(value):
        raise LauncherError(f"{option} requires a full lowercase commit object ID")
    resolved = git(
        repository.root,
        "rev-parse",
        "--verify",
        f"{value}^{{commit}}",
        check=False,
    )
    if resolved.returncode or resolved.stdout.strip() != value:
        raise LauncherError(f"{option} does not name an exact available commit")
    return value


def integration_source_ref(manifest: dict) -> str:
    run_id = manifest.get("run_id")
    if not isinstance(run_id, str):
        raise LauncherError("the retained run has no valid source-anchor identity")
    validate_run_id(run_id)
    return (
        f"{active_profile().source_anchor_prefix}{run_id}/integration-source"
    )


def retirement_anchor_ref(manifest: dict) -> str:
    run_id = manifest.get("run_id")
    if not isinstance(run_id, str):
        raise LauncherError("the retained run has no valid retirement-anchor identity")
    validate_run_id(run_id)
    return (
        f"{active_profile().source_anchor_prefix}{run_id}/retirement-discard"
    )


def retirement_receipt_ref(manifest: dict) -> str:
    run_id = manifest.get("run_id")
    if not isinstance(run_id, str):
        raise LauncherError("the retained run has no valid retirement-receipt identity")
    validate_run_id(run_id)
    return (
        f"{active_profile().source_anchor_prefix}{run_id}/retirement-receipt"
    )


def private_run_refs(repository: Repository, manifest: dict) -> set[str]:
    run_id = manifest.get("run_id")
    if not isinstance(run_id, str):
        raise LauncherError("the retained run has no valid private-ref identity")
    validate_run_id(run_id)
    prefix = f"{active_profile().source_anchor_prefix}{run_id}/"
    result = git(
        repository.root,
        "for-each-ref",
        "--format=%(refname)",
        prefix,
        check=False,
    )
    if result.returncode:
        raise LauncherError("cannot inspect the retained run's private refs")
    refs = {line for line in result.stdout.splitlines() if line}
    if any(not ref.startswith(prefix) for ref in refs):
        raise LauncherError("Git returned an unexpected retained-run private ref")
    return refs


def direct_ref_commit(repository: Repository, ref: str) -> str | None:
    symbolic = git(
        repository.root,
        "symbolic-ref",
        "--quiet",
        ref,
        check=False,
    )
    if symbolic.returncode == 0:
        raise LauncherError("a retained-run private ref was replaced by a symbolic ref")
    if symbolic.returncode != 1:
        raise LauncherError("cannot inspect a retained-run private ref")
    result = git(
        repository.root,
        "rev-parse",
        "--verify",
        ref,
        check=False,
    )
    if result.returncode == 0:
        value = result.stdout.strip()
        object_type = git(
            repository.root,
            "cat-file",
            "-t",
            value,
            check=False,
        )
        if object_type.returncode or object_type.stdout.strip() != "commit":
            raise LauncherError("a retained-run ref does not point directly to a commit")
        return value
    presence = git(
        repository.root,
        "show-ref",
        "--verify",
        "--quiet",
        ref,
        check=False,
    )
    if presence.returncode == 1:
        return None
    raise LauncherError("cannot verify a retained-run private ref")


def ensure_integration_source_anchor(
    repository: Repository,
    manifest: dict,
    source_head: str,
) -> None:
    authenticate_retained_worktree(repository, manifest)
    ref = integration_source_ref(manifest)
    current = direct_ref_commit(repository, ref)
    if current is None:
        creation = git(
            repository.root,
            "update-ref",
            "--no-deref",
            ref,
            source_head,
            "0" * len(source_head),
            check=False,
        )
        current = direct_ref_commit(repository, ref)
        if creation.returncode and current != source_head:
            raise LauncherError("cannot create the retained run's private source anchor")
    if current != source_head:
        raise LauncherError("the retained run's private source anchor changed")


def recorded_integration_source(repository: Repository, manifest: dict) -> str:
    source_head = manifest.get("integration_source_head")
    if not isinstance(source_head, str) or not OBJECT_ID_RE.fullmatch(source_head):
        raise LauncherError("the retained run has no valid recorded integration source head")
    anchored = direct_ref_commit(repository, integration_source_ref(manifest))
    if anchored != source_head:
        raise LauncherError("the retained run's private source anchor is missing or changed")
    return source_head


def delete_integration_source_anchor(
    repository: Repository,
    manifest: dict,
    source_head: str,
) -> None:
    authenticate_retained_worktree(repository, manifest)
    ref = integration_source_ref(manifest)
    current = direct_ref_commit(repository, ref)
    if current is None:
        raise LauncherError("the retained run's private source anchor is missing")
    if current != source_head:
        raise LauncherError("the retained run's private source anchor changed")
    deletion = git(
        repository.root,
        "update-ref",
        "--no-deref",
        "-d",
        ref,
        source_head,
        check=False,
    )
    remaining = direct_ref_commit(repository, ref)
    if remaining is None:
        return
    raise LauncherError("cannot delete the retained run's private source anchor")


def recorded_clean_final_head(repository: Repository, manifest: dict) -> str:
    dirty = manifest.get("dirty")
    if dirty is True:
        raise LauncherError(
            "the retained run's last terminal audit recorded uncommitted changes; "
            "reopen it before cleanup or integration"
        )
    if dirty is not False:
        raise LauncherError(
            "the retained run's last terminal audit did not record a clean result; "
            "reopen it before cleanup or integration"
        )
    return recorded_commit(repository, manifest, "final_head")


def audit_matches_clean_head(manifest: dict, audit: Audit, expected_head: str) -> bool:
    return (
        audit.registered
        and audit.locked
        and audit.branch == manifest["branch"]
        and audit.head == expected_head
        and audit.clean
    )


def rebase_in_progress(worktree: Path) -> bool:
    return bool(active_rebase_directories(worktree))


def active_rebase_directories(worktree: Path) -> list[Path]:
    identity = authenticate_linked_worktree_path(worktree)
    directories: list[Path] = []
    for marker in ("rebase-apply", "rebase-merge"):
        marker_path = identity.git_dir / marker
        try:
            metadata = marker_path.lstat()
        except FileNotFoundError:
            continue
        except OSError as exc:
            raise LauncherError("cannot inspect active rebase administration") from exc
        if not stat.S_ISDIR(metadata.st_mode):
            raise LauncherError("active rebase administration is symbolic or unsafe")
        try:
            resolved = marker_path.resolve(strict=True)
        except (OSError, RuntimeError) as exc:
            raise LauncherError("active rebase administration is unavailable") from exc
        if resolved != marker_path or marker_path.parent != identity.git_dir:
            raise LauncherError(
                "active rebase administration is not an exact direct Git-admin child"
            )
        safe_admin_tree_entries(marker_path)
        directories.append(marker_path)
    return directories


def safe_admin_tree_entries(
    root: Path,
) -> list[tuple[bytes, int, bytes, bytes | None]]:
    directory_flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    file_flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        root_descriptor = os.open(root, directory_flags)
    except OSError as exc:
        raise LauncherError("active rebase administration is not a real directory") from exc
    entries: list[tuple[bytes, int, bytes, bytes | None]] = []
    total_bytes = 0

    def walk(directory_descriptor: int, prefix: bytes) -> None:
        nonlocal total_bytes
        directory_before = os.fstat(directory_descriptor)
        try:
            names = sorted(os.listdir(directory_descriptor), key=os.fsencode)
        except OSError as exc:
            raise LauncherError("cannot enumerate active rebase administration") from exc
        for name in names:
            raw_name = os.fsencode(name)
            relative = raw_name if not prefix else prefix + b"/" + raw_name
            try:
                metadata = os.stat(
                    name,
                    dir_fd=directory_descriptor,
                    follow_symlinks=False,
                )
            except OSError as exc:
                raise LauncherError("active rebase administration changed during audit") from exc
            mode = stat.S_IMODE(metadata.st_mode)
            if stat.S_ISDIR(metadata.st_mode):
                entries.append((relative, mode, b"directory", None))
                try:
                    child_descriptor = os.open(
                        name,
                        directory_flags,
                        dir_fd=directory_descriptor,
                    )
                except OSError as exc:
                    raise LauncherError(
                        "active rebase administration contains a symbolic or unsafe entry"
                    ) from exc
                try:
                    opened = os.fstat(child_descriptor)
                    if (opened.st_dev, opened.st_ino) != (
                        metadata.st_dev,
                        metadata.st_ino,
                    ):
                        raise LauncherError(
                            "active rebase administration changed during audit"
                        )
                    walk(child_descriptor, relative)
                finally:
                    os.close(child_descriptor)
                continue
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
                raise LauncherError(
                    "active rebase administration contains a symbolic or unsafe entry"
                )
            if metadata.st_size > MAX_ADMIN_FILE_BYTES:
                raise LauncherError("an active rebase administration file is unexpectedly large")
            try:
                file_descriptor = os.open(
                    name,
                    file_flags,
                    dir_fd=directory_descriptor,
                )
            except OSError as exc:
                raise LauncherError(
                    "active rebase administration contains a symbolic or unsafe entry"
                ) from exc
            try:
                before = os.fstat(file_descriptor)
                if (
                    not stat.S_ISREG(before.st_mode)
                    or before.st_nlink != 1
                    or (before.st_dev, before.st_ino) != (metadata.st_dev, metadata.st_ino)
                ):
                    raise LauncherError(
                        "active rebase administration changed during audit"
                    )
                chunks: list[bytes] = []
                remaining = MAX_ADMIN_FILE_BYTES + 1
                while remaining:
                    chunk = os.read(file_descriptor, min(1024 * 1024, remaining))
                    if not chunk:
                        break
                    chunks.append(chunk)
                    remaining -= len(chunk)
                data = b"".join(chunks)
                after = os.fstat(file_descriptor)
                if len(data) > MAX_ADMIN_FILE_BYTES:
                    raise LauncherError(
                        "an active rebase administration file is unexpectedly large"
                    )
                if (
                    (before.st_dev, before.st_ino, before.st_size)
                    != (after.st_dev, after.st_ino, after.st_size)
                    or before.st_mtime_ns != after.st_mtime_ns
                    or before.st_ctime_ns != after.st_ctime_ns
                ):
                    raise LauncherError(
                        "active rebase administration changed during audit"
                    )
            finally:
                os.close(file_descriptor)
            total_bytes += len(data)
            if total_bytes > MAX_ADMIN_TREE_BYTES:
                raise LauncherError("active rebase administration is unexpectedly large")
            entries.append((relative, mode, b"file", data))
        directory_after = os.fstat(directory_descriptor)
        if (
            (directory_before.st_dev, directory_before.st_ino)
            != (directory_after.st_dev, directory_after.st_ino)
            or directory_before.st_mtime_ns != directory_after.st_mtime_ns
            or directory_before.st_ctime_ns != directory_after.st_ctime_ns
        ):
            raise LauncherError("active rebase administration changed during audit")

    try:
        root_metadata = os.fstat(root_descriptor)
        if not stat.S_ISDIR(root_metadata.st_mode):
            raise LauncherError("active rebase administration is not a real directory")
        walk(root_descriptor, b"")
        after_root = os.fstat(root_descriptor)
        if (root_metadata.st_dev, root_metadata.st_ino) != (
            after_root.st_dev,
            after_root.st_ino,
        ):
            raise LauncherError("active rebase administration changed during audit")
    finally:
        os.close(root_descriptor)
    return sorted(entries, key=lambda entry: entry[0])


def branch_commit(repository: Repository, manifest: dict) -> str | None:
    branch_ref = f"refs/heads/{manifest['branch']}"
    symbolic = git(
        repository.root,
        "symbolic-ref",
        "--quiet",
        branch_ref,
        check=False,
    )
    if symbolic.returncode == 0:
        return None
    if symbolic.returncode != 1:
        raise LauncherError("cannot inspect the retained worker branch")
    result = git(
        repository.root,
        "rev-parse",
        "--verify",
        f"{branch_ref}^{{commit}}",
        check=False,
    )
    return result.stdout.strip() if result.returncode == 0 else None


def retirement_parameters(manifest: dict) -> tuple[str, str, str]:
    return _retirement_parameters(
        manifest,
        retirement_core_fields=RETIREMENT_CORE_FIELDS,
        object_id_pattern=OBJECT_ID_RE,
        error_type=LauncherError,
    )


def require_matching_retirement_arguments(
    manifest: dict,
    discard_head: str,
    target_contains: str,
) -> None:
    _require_matching_retirement_arguments(
        manifest,
        discard_head,
        target_contains,
        retirement_parameters=retirement_parameters,
        error_type=LauncherError,
    )


def reject_conflicting_retirement_lifecycle(manifest: dict) -> None:
    _reject_conflicting_retirement_lifecycle(
        manifest,
        error_type=LauncherError,
    )


def target_containing_retirement_checkpoint(
    repository: Repository,
    manifest: dict,
    target_contains: str,
) -> str:
    target_head = direct_ref_commit(repository, manifest["target_ref"])
    if target_head is None:
        raise LauncherError("the recorded target ref is unavailable for retirement")
    if not commit_is_ancestor(repository, target_contains, target_head):
        raise LauncherError(
            "the recorded target no longer contains the operator-selected checkpoint"
        )
    return target_head


def validate_retirement_recorded_history(
    repository: Repository,
    manifest: dict,
    discard_head: str,
    target_contains: str,
) -> None:
    final_head = recorded_commit(repository, manifest, "final_head")
    observed_head = recorded_commit(repository, manifest, "observed_head")
    base_sha = recorded_commit(repository, manifest, "base_sha")
    if observed_head != discard_head:
        raise LauncherError("the recorded observed head is not the authorized discard head")
    if manifest.get("observed_dirty") is not False:
        raise LauncherError("the rewritten quarantine was not observed clean")
    if not commit_is_ancestor(repository, base_sha, discard_head):
        raise LauncherError("the discard head no longer descends from the run's recorded base")
    if commit_is_ancestor(repository, final_head, discard_head):
        raise LauncherError(
            "the observed history still descends from its last terminal audit"
        )
    exact_commit_argument(repository, target_contains, "--target-contains")


def retirement_private_ref_pair(
    repository: Repository,
    manifest: dict,
) -> tuple[str | None, str | None]:
    anchor_ref = retirement_anchor_ref(manifest)
    receipt_ref = retirement_receipt_ref(manifest)
    refs = private_run_refs(repository, manifest)
    unexpected = refs - {anchor_ref, receipt_ref}
    if unexpected:
        raise LauncherError("the quarantined run has a conflicting private ref")
    return (
        direct_ref_commit(repository, anchor_ref),
        direct_ref_commit(repository, receipt_ref),
    )


def ensure_retirement_anchor(
    repository: Repository,
    manifest: dict,
    discard_head: str,
) -> None:
    authenticate_retained_worktree(repository, manifest)
    branch_ref = f"refs/heads/{manifest['branch']}"
    if direct_ref_commit(repository, branch_ref) != discard_head:
        raise LauncherError("the checkpointed retirement worker branch changed")
    anchor_ref = retirement_anchor_ref(manifest)
    anchor, receipt = retirement_private_ref_pair(repository, manifest)
    if receipt is not None:
        raise LauncherError("the retirement receipt exists before ref cleanup")
    if anchor is None:
        if manifest.get("retirement_anchor_created") is True:
            raise LauncherError("the retirement anchor is missing after its checkpoint")
        creation = git(
            repository.root,
            "update-ref",
            "--no-deref",
            anchor_ref,
            discard_head,
            "0" * len(discard_head),
            check=False,
        )
        anchor, receipt = retirement_private_ref_pair(repository, manifest)
        if creation.returncode and anchor != discard_head:
            raise LauncherError("cannot create the quarantined run's retirement anchor")
    if anchor != discard_head or receipt is not None:
        raise LauncherError("the quarantined run's retirement anchor changed")
    if manifest.get("retirement_anchor_created") is not True:
        manifest["retirement_anchor_created"] = True
        write_manifest(repository, manifest)


def validate_retirement_worktree(
    repository: Repository,
    manifest: dict,
    *,
    require_locked: bool,
) -> None:
    discard_head, _, _ = retirement_parameters(manifest)
    worktree = Path(manifest["worktree"])
    audit = audit_run(repository, manifest)
    if not audit.registered:
        raise LauncherError("the checkpointed retirement worktree is not registered")
    if audit.locked is not require_locked:
        expected = "locked" if require_locked else "unlocked"
        raise LauncherError(f"the checkpointed retirement worktree is not {expected}")
    if audit.branch != manifest["branch"]:
        raise LauncherError("the checkpointed retirement worktree changed branches")
    if audit.head != discard_head or not audit.clean:
        raise LauncherError("the checkpointed retirement worktree changed after its audit")
    if rebase_in_progress(worktree):
        raise LauncherError("the checkpointed retirement worktree has an active rebase")
    branch_ref = f"refs/heads/{manifest['branch']}"
    if direct_ref_commit(repository, branch_ref) != discard_head:
        raise LauncherError("the checkpointed retirement worker branch changed")
    if manifest.get("retirement_anchor_created") is not True:
        raise LauncherError("the retirement anchor has no durable creation checkpoint")
    anchor, receipt = retirement_private_ref_pair(repository, manifest)
    if anchor != discard_head or receipt is not None:
        raise LauncherError("the quarantined run's retirement anchor is missing or changed")


def rebase_head_name(worktree: Path) -> str | None:
    directories = active_rebase_directories(worktree)
    if len(directories) != 1:
        return None
    try:
        return safe_regular_file_bytes(
            directories[0] / "head-name",
            label="the active rebase head-name file",
        ).decode("utf-8").strip()
    except UnicodeDecodeError:
        return None


def rebase_recorded_commit(worktree: Path, name: str) -> str | None:
    directories = active_rebase_directories(worktree)
    if len(directories) != 1:
        return None
    try:
        value = safe_regular_file_bytes(
            directories[0] / name,
            label=f"the active rebase {name} file",
        ).decode("utf-8").strip()
    except UnicodeDecodeError:
        return None
    return value if OBJECT_ID_RE.fullmatch(value) else None


def rebase_metadata_hash(worktree: Path) -> str | None:
    directories = active_rebase_directories(worktree)
    if len(directories) != 1:
        return None
    root = directories[0]
    digest = hashlib.sha256()

    def add(value: bytes) -> None:
        digest.update(len(value).to_bytes(8, "big"))
        digest.update(value)

    for relative, mode, kind, data in safe_admin_tree_entries(root):
        add(relative)
        add(str(mode).encode("ascii"))
        add(kind)
        if data is not None:
            add(data)
    return digest.hexdigest()


def rebase_commit(worktree: Path) -> str | None:
    result = git(
        worktree,
        "rev-parse",
        "--verify",
        "REBASE_HEAD^{commit}",
        check=False,
    )
    return result.stdout.strip() if result.returncode == 0 else None


def rebase_first_done_commit(worktree: Path) -> str | None:
    directories = active_rebase_directories(worktree)
    if len(directories) != 1:
        return None
    try:
        data = safe_regular_file_bytes(
            directories[0] / "done",
            label="the active rebase done file",
        )
        first_line = data.decode("utf-8").splitlines()[0]
    except (UnicodeDecodeError, IndexError):
        return None
    fields = first_line.split(maxsplit=2)
    if len(fields) < 2 or fields[0] != "pick" or not OBJECT_ID_RE.fullmatch(fields[1]):
        return None
    return fields[1]


def commit_changed_paths(worktree: Path, commit: str) -> list[str]:
    result = git(
        worktree,
        "diff-tree",
        "--no-commit-id",
        "--name-only",
        "--no-renames",
        "-r",
        "-z",
        f"{commit}^",
        commit,
        check=False,
        text=False,
    )
    if result.returncode:
        raise LauncherError("cannot inspect the stopped rebase commit's changed paths")
    paths = sorted(os.fsdecode(path) for path in result.stdout.split(b"\0") if path)
    if not paths:
        raise LauncherError("the stopped rebase commit has no auditable changed paths")
    return paths


def tree_transition_paths(worktree: Path, old_treeish: str, new_treeish: str) -> list[str]:
    result = git(
        worktree,
        "diff-tree",
        "--no-commit-id",
        "--name-only",
        "--no-renames",
        "-r",
        "-z",
        old_treeish,
        new_treeish,
        check=False,
        text=False,
    )
    if result.returncode:
        raise LauncherError("cannot inspect a managed tree transition's paths")
    return sorted(os.fsdecode(path) for path in result.stdout.split(b"\0") if path)


def expected_rebase_index_paths(
    worktree: Path,
    current_head: str,
    rebase_commit: str,
) -> tuple[list[str], dict[str, list[bytes]], str]:
    """Reproduce the stopped three-way replay without trusting its live index."""
    parent = git(
        worktree,
        "rev-parse",
        "--verify",
        f"{rebase_commit}^{{commit}}^",
        check=False,
    ).stdout.strip()
    if not OBJECT_ID_RE.fullmatch(parent):
        raise LauncherError("cannot inspect the stopped rebase commit's parent")
    expected = git(
        worktree,
        "merge-tree",
        "--write-tree",
        f"--merge-base={parent}",
        "-z",
        current_head,
        rebase_commit,
        check=False,
        text=False,
    )
    if expected.returncode != 1:
        raise LauncherError(
            "cannot independently reproduce the stopped rebase conflict"
        )
    records = expected.stdout.split(b"\0")
    try:
        result_tree = records[0].decode("ascii", errors="strict")
        stage_end = records.index(b"", 1)
    except (UnicodeDecodeError, ValueError) as exc:
        raise LauncherError(
            "Git returned an invalid independent rebase-conflict description"
        ) from exc
    if not OBJECT_ID_RE.fullmatch(result_tree):
        raise LauncherError(
            "Git returned an invalid independent rebase-conflict tree"
        )
    expected_entries: dict[str, list[bytes]] = {}
    for record in records[1:stage_end]:
        metadata, separator, raw_path = record.partition(b"\t")
        fields = metadata.split(b" ")
        if (
            not separator
            or len(fields) != 3
            or fields[2] not in {b"1", b"2", b"3"}
        ):
            raise LauncherError(
                "Git returned an invalid independently reproduced conflict-stage entry"
            )
        try:
            object_id = fields[1].decode("ascii", errors="strict")
        except UnicodeDecodeError as exc:
            raise LauncherError(
                "Git returned an invalid independently reproduced conflict object"
            ) from exc
        if not OBJECT_ID_RE.fullmatch(object_id):
            raise LauncherError(
                "Git returned an invalid independently reproduced conflict object"
            )
        expected_entries.setdefault(os.fsdecode(raw_path), []).append(metadata)
    expected_conflicts = sorted(expected_entries)
    if not expected_entries:
        raise LauncherError(
            "Git's independent replay did not reproduce a conflict path"
        )
    allowed = sorted(
        set(commit_changed_paths(worktree, rebase_commit))
        | set(expected_conflicts)
        | set(tree_transition_paths(worktree, current_head, result_tree))
    )
    return allowed, expected_entries, result_tree


def expected_rebase_clean_tree(
    worktree: Path,
    current_head: str,
    rebase_commit: str,
) -> str:
    """Independently reproduce one clean three-way replay."""
    parent = git(
        worktree,
        "rev-parse",
        "--verify",
        f"{rebase_commit}^{{commit}}^",
        check=False,
    ).stdout.strip()
    if not OBJECT_ID_RE.fullmatch(parent):
        raise LauncherError("cannot inspect the stopped rebase commit's parent")
    expected = git(
        worktree,
        "merge-tree",
        "--write-tree",
        f"--merge-base={parent}",
        "-z",
        current_head,
        rebase_commit,
        check=False,
        text=False,
    )
    if expected.returncode:
        raise LauncherError("the stopped replay is not an independently clean application")
    try:
        result_tree = expected.stdout.split(b"\0", 1)[0].strip().decode(
            "ascii",
            errors="strict",
        )
    except UnicodeDecodeError as exc:
        raise LauncherError("Git returned an invalid independent replay tree") from exc
    if not OBJECT_ID_RE.fullmatch(result_tree):
        raise LauncherError("Git returned an invalid independent replay tree")
    return result_tree


def first_replayed_commit(
    worktree: Path,
    base_sha: str,
    source_head: str,
) -> str:
    result = git(
        worktree,
        "rev-list",
        "--reverse",
        "--ancestry-path",
        source_head,
        "--not",
        base_sha,
        check=False,
    )
    commits = result.stdout.splitlines()
    if result.returncode or not commits or any(
        not OBJECT_ID_RE.fullmatch(commit) for commit in commits
    ):
        raise LauncherError("cannot identify the first audited replay commit")
    return commits[0]


def validate_initial_rebase_precommit(
    repository: Repository,
    manifest: dict,
    audit: Audit,
    *,
    require_checkpoint: bool,
) -> tuple[str, str, str]:
    """Prove Git stopped after staging, but before committing, its first replay."""
    worktree = Path(manifest["worktree"])
    source_head = recorded_integration_source(repository, manifest)
    target_head = recorded_commit(repository, manifest, "integration_target_head")
    base_sha = recorded_commit(repository, manifest, "base_sha")
    directories = active_rebase_directories(worktree)
    current_commit = rebase_commit(worktree) or rebase_first_done_commit(worktree)
    current_metadata_hash = rebase_metadata_hash(worktree)
    expected_commit = first_replayed_commit(worktree, base_sha, source_head)
    expected_tree = (
        expected_rebase_clean_tree(worktree, target_head, expected_commit)
        if current_commit == expected_commit
        else None
    )
    index = git(worktree, "write-tree", check=False)
    index_tree = index.stdout.strip()
    checks = {
        "registration": audit.registered,
        "lock": audit.locked,
        "detached HEAD": audit.branch is None,
        "target HEAD": audit.head == target_head,
        "merge-backend administration": (
            len(directories) == 1 and directories[0].name == "rebase-merge"
        ),
        "head name": rebase_head_name(worktree)
        == f"refs/heads/{manifest['branch']}",
        "original head": rebase_recorded_commit(worktree, "orig-head") == source_head,
        "onto head": rebase_recorded_commit(worktree, "onto") == target_head,
        "worker branch": branch_commit(repository, manifest) == source_head,
        "first replay commit": current_commit == expected_commit,
        "rebase metadata": current_metadata_hash is not None,
        "unmerged paths": not unmerged_paths(worktree),
        "index tree": index.returncode == 0 and index_tree == expected_tree,
        "unstaged changes": not worktree_has_unstaged_changes(worktree),
        "untracked paths": not nonignored_untracked_paths(worktree),
    }
    valid = all(checks.values())
    if require_checkpoint:
        valid = bool(
            valid
            and manifest.get("integration_precommit_commit") == current_commit
            and manifest.get("integration_precommit_index_tree") == index_tree
            and manifest.get("integration_rebase_metadata_hash")
            == current_metadata_hash
        )
    if not valid or current_commit is None or current_metadata_hash is None:
        failed_checks = ", ".join(label for label, passed in checks.items() if not passed)
        raise LauncherError(
            "the interrupted initial rebase is not the exact staged first-replay "
            f"pre-commit checkpoint ({failed_checks or 'checkpoint mismatch'})"
        )
    return current_commit, index_tree, current_metadata_hash


def unmerged_paths(worktree: Path) -> list[str]:
    result = git(
        worktree,
        "diff",
        "--name-only",
        "--diff-filter=U",
        "-z",
        check=False,
        text=False,
    )
    if result.returncode:
        raise LauncherError(
            "cannot inspect managed conflict paths: "
            f"{result.stderr.decode(errors='replace').strip() or 'no diagnostic'}"
        )
    return sorted(os.fsdecode(path) for path in result.stdout.split(b"\0") if path)


def staged_paths(worktree: Path) -> list[str]:
    result = git(
        worktree,
        "diff",
        "--cached",
        "--name-only",
        "-z",
        check=False,
        text=False,
    )
    if result.returncode:
        raise LauncherError(
            "cannot inspect staged conflict-resolution paths: "
            f"{result.stderr.decode(errors='replace').strip() or 'no diagnostic'}"
        )
    return sorted(os.fsdecode(path) for path in result.stdout.split(b"\0") if path)


def index_stage_entries(worktree: Path) -> dict[str, list[bytes]]:
    result = git(
        worktree,
        "ls-files",
        "--stage",
        "-z",
        check=False,
        text=False,
    )
    if result.returncode:
        raise LauncherError(
            "cannot inspect the managed conflict index: "
            f"{result.stderr.decode(errors='replace').strip() or 'no diagnostic'}"
        )
    entries: dict[str, list[bytes]] = {}
    for record in result.stdout.split(b"\0"):
        if not record:
            continue
        metadata, separator, raw_path = record.partition(b"\t")
        if not separator:
            raise LauncherError("the managed conflict index has an invalid entry")
        entries.setdefault(os.fsdecode(raw_path), []).append(metadata)
    return entries


def index_entries_hash(
    entries: dict[str, list[bytes]],
    paths: Sequence[str],
) -> str:
    digest = hashlib.sha256()
    for path in sorted(paths, key=os.fsencode):
        raw_path = os.fsencode(path)
        digest.update(len(raw_path).to_bytes(8, "big"))
        digest.update(raw_path)
        for entry in sorted(entries.get(path, [])):
            digest.update(len(entry).to_bytes(8, "big"))
            digest.update(entry)
    return digest.hexdigest()


def protected_index_hash(worktree: Path, paths: Sequence[str]) -> str:
    return index_entries_hash(index_stage_entries(worktree), paths)


def tree_index_hash(worktree: Path, tree: str, paths: Sequence[str]) -> str:
    result = git(
        worktree,
        "ls-tree",
        "-r",
        "-z",
        tree,
        check=False,
        text=False,
    )
    if result.returncode:
        raise LauncherError("cannot inspect the independently reproduced conflict tree")
    wanted = set(paths)
    entries: dict[str, list[bytes]] = {}
    for record in result.stdout.split(b"\0"):
        if not record:
            continue
        metadata, separator, raw_path = record.partition(b"\t")
        fields = metadata.split(b" ")
        if not separator or len(fields) != 3:
            raise LauncherError(
                "Git returned an invalid independently reproduced tree entry"
            )
        path = os.fsdecode(raw_path)
        if path in wanted:
            mode, _, object_id = fields
            entries.setdefault(path, []).append(mode + b" " + object_id + b" 0")
    return index_entries_hash(entries, paths)


def worktree_has_unstaged_changes(worktree: Path) -> bool:
    result = git(worktree, "diff", "--quiet", "--", check=False)
    if result.returncode not in {0, 1}:
        raise LauncherError(
            "cannot inspect unstaged conflict resolutions: "
            f"{result.stderr.strip() or 'no diagnostic'}"
        )
    return result.returncode == 1


def nonignored_untracked_paths(worktree: Path) -> list[str]:
    result = git(
        worktree,
        "ls-files",
        "--others",
        "--exclude-standard",
        "-z",
        check=False,
        text=False,
    )
    if result.returncode:
        raise LauncherError(
            "cannot inspect untracked conflict-resolution files: "
            f"{result.stderr.decode(errors='replace').strip() or 'no diagnostic'}"
        )
    return sorted(os.fsdecode(path) for path in result.stdout.split(b"\0") if path)


def record_managed_conflict(
    repository: Repository,
    manifest: dict,
    audit: Audit,
    error: str,
) -> list[str]:
    worktree = Path(manifest["worktree"])
    source_head = recorded_integration_source(repository, manifest)
    target_head = recorded_commit(repository, manifest, "integration_target_head")
    paths = unmerged_paths(worktree)
    current_rebase_commit = rebase_commit(worktree)
    current_metadata_hash = rebase_metadata_hash(worktree)
    expected_head_name = f"refs/heads/{manifest['branch']}"
    if not (
        audit.registered
        and audit.locked
        and audit.branch is None
        and audit.head is not None
        and rebase_in_progress(worktree)
        and paths
        and current_rebase_commit is not None
        and current_metadata_hash is not None
        and rebase_head_name(worktree) == expected_head_name
        and rebase_recorded_commit(worktree, "orig-head") == source_head
        and rebase_recorded_commit(worktree, "onto") == target_head
        and branch_commit(repository, manifest) == source_head
        and commit_is_ancestor(repository, target_head, audit.head)
        and commit_is_ancestor(repository, current_rebase_commit, source_head)
    ):
        raise LauncherError("Git did not leave a provable managed rebase conflict")

    allowed_staged_paths, expected_conflict_entries, expected_result_tree = (
        expected_rebase_index_paths(
            worktree,
            audit.head,
            current_rebase_commit,
        )
    )
    current_staged_paths = staged_paths(worktree)
    expected_conflict_paths = sorted(expected_conflict_entries)
    protected_paths = sorted(
        (set(current_staged_paths) & set(allowed_staged_paths)) - set(paths)
    )
    if set(paths) != set(expected_conflict_paths):
        raise LauncherError(
            "the stopped rebase does not have its exact independently reproduced "
            "conflict paths"
        )
    if protected_index_hash(worktree, paths) != index_entries_hash(
        expected_conflict_entries,
        expected_conflict_paths,
    ):
        raise LauncherError(
            "the stopped rebase's conflict-stage index entries do not match its "
            "independently reproduced result"
        )
    if not set(current_staged_paths).issubset(allowed_staged_paths):
        raise LauncherError(
            "the retained worker has staged paths outside the independently reproduced "
            "rebase result"
        )
    current_protected_hash = protected_index_hash(worktree, protected_paths)
    if current_protected_hash != tree_index_hash(
        worktree,
        expected_result_tree,
        protected_paths,
    ):
        raise LauncherError(
            "the stopped rebase's non-conflicting index entries do not match its "
            "independently reproduced result"
        )

    prior_paths = manifest.get("integration_conflict_paths", [])
    manifest["state"] = "integration-conflict"
    manifest["integration_conflict_head"] = audit.head
    manifest["integration_conflict_commit"] = current_rebase_commit
    manifest["integration_conflict_paths"] = sorted(set(prior_paths) | set(paths))
    manifest["integration_unmerged_paths"] = paths
    manifest["integration_allowed_staged_paths"] = allowed_staged_paths
    manifest["integration_protected_index_paths"] = protected_paths
    manifest["integration_protected_index_hash"] = current_protected_hash
    manifest["integration_rebase_metadata_hash"] = current_metadata_hash
    manifest["integration_conflicted_at"] = utc_now()
    manifest["integration_conflict_error"] = error
    manifest.pop("integration_resolver_scope_error", None)
    manifest.pop("integration_continue_started_at", None)
    manifest.pop("integration_recovery_error", None)
    write_manifest(repository, manifest)
    return paths


def validate_managed_rebase_identity(
    repository: Repository,
    manifest: dict,
    audit: Audit,
) -> list[str]:
    if manifest.get("state") not in MANAGED_CONFLICT_STATES:
        raise LauncherError("the retained run is not in a managed conflict state")
    worktree = Path(manifest["worktree"])
    source_head = recorded_integration_source(repository, manifest)
    target_head = recorded_commit(repository, manifest, "integration_target_head")
    conflict_head = recorded_commit(repository, manifest, "integration_conflict_head")
    conflict_commit = recorded_commit(repository, manifest, "integration_conflict_commit")
    paths = unmerged_paths(worktree)
    if not (
        audit.registered
        and audit.locked
        and audit.branch is None
        and audit.head == conflict_head
        and rebase_in_progress(worktree)
        and rebase_head_name(worktree) == f"refs/heads/{manifest['branch']}"
        and rebase_recorded_commit(worktree, "orig-head") == source_head
        and rebase_recorded_commit(worktree, "onto") == target_head
        and rebase_commit(worktree) == conflict_commit
        and rebase_metadata_hash(worktree)
        == manifest.get("integration_rebase_metadata_hash")
        and branch_commit(repository, manifest) == source_head
        and commit_is_ancestor(repository, target_head, conflict_head)
        and commit_is_ancestor(repository, conflict_commit, source_head)
    ):
        raise LauncherError(
            "the retained worker no longer matches its recorded managed conflict"
        )
    return paths


def validate_managed_conflict(
    repository: Repository,
    manifest: dict,
    audit: Audit,
) -> list[str]:
    paths = validate_managed_rebase_identity(repository, manifest, audit)
    worktree = Path(manifest["worktree"])
    current_staged_paths = staged_paths(worktree)
    recorded_paths = manifest.get("integration_conflict_paths")
    if not isinstance(recorded_paths, list) or not set(paths).issubset(recorded_paths):
        raise ManagedConflictScopeError(
            "the retained worker has unexpected conflict paths"
        )
    allowed_staged_paths = manifest.get("integration_allowed_staged_paths")
    if not isinstance(allowed_staged_paths, list) or not set(
        current_staged_paths
    ).issubset(allowed_staged_paths):
        raise ManagedConflictScopeError(
            "the retained worker has unexpected staged paths; reopen the resolver to "
            "unstage or remove them"
        )
    protected_paths = manifest.get("integration_protected_index_paths")
    protected_hash = manifest.get("integration_protected_index_hash")
    if (
        not isinstance(protected_paths, list)
        or not isinstance(protected_hash, str)
        or protected_index_hash(worktree, protected_paths) != protected_hash
    ):
        raise ManagedConflictScopeError(
            "the retained worker altered a non-conflicting index entry; reopen the "
            "resolver to restore it"
        )
    manifest_scope_error = manifest.get("integration_resolver_scope_error")
    if manifest_scope_error is not None and not isinstance(manifest_scope_error, str):
        raise ManagedConflictScopeError("the resolver scope audit is invalid")
    return paths


def recorded_integration_candidate(
    repository: Repository,
    manifest: dict,
    final_head: str,
) -> str:
    candidate = manifest.get("integration_candidate_head")
    integrated = manifest.get("integrated_head")
    if candidate is not None and integrated is not None and candidate != integrated:
        raise LauncherError("the retained run has inconsistent integration commit records")
    if integrated is not None:
        return recorded_commit(repository, manifest, "integrated_head")
    if candidate is not None:
        return recorded_commit(repository, manifest, "integration_candidate_head")
    return final_head


def worker_history_has_merge(
    repository: Repository,
    worker_head: str,
    target_head: str,
) -> bool:
    result = git(
        repository.root,
        "rev-list",
        "--merges",
        "--max-count=1",
        worker_head,
        "--not",
        target_head,
        check=False,
    )
    if result.returncode:
        raise LauncherError(
            "cannot inspect retained worker history: "
            f"{result.stderr.strip() or 'no diagnostic'}"
        )
    return bool(result.stdout.strip())


def target_head_containing_commit(
    repository: Repository,
    target_ref: str,
    commit: str,
) -> str | None:
    target = git(
        repository.root,
        "rev-parse",
        "--verify",
        f"{target_ref}^{{commit}}",
        check=False,
    )
    if target.returncode:
        return None
    head = target.stdout.strip()
    return head if commit_is_ancestor(repository, commit, head) else None


def clear_integration_transaction(manifest: dict) -> None:
    _restore_integration_transaction(
        manifest,
        transaction_fields=INTEGRATION_TRANSACTION_FIELDS,
        archive_fields=(),
    )


def archive_aborted_integration(manifest: dict) -> None:
    _restore_integration_transaction(
        manifest,
        transaction_fields=INTEGRATION_TRANSACTION_FIELDS,
        archive_fields=_ABORTED_INTEGRATION_ARCHIVE_FIELDS,
    )
    manifest["last_integration_aborted_at"] = utc_now()


def record_target_mismatch(manifest: dict, observed_head: str) -> None:
    manifest["integration_target_mismatch_head"] = observed_head
    manifest["integration_target_mismatch_at"] = utc_now()


def record_integration_recovery_failure(
    repository: Repository,
    manifest: dict,
    *,
    state: str,
    audit: Audit,
    error: str,
) -> None:
    manifest["state"] = state
    manifest["integration_recovery_error"] = error
    manifest["integration_observed_head"] = audit.head
    manifest["integration_observed_dirty"] = (
        None if audit.status is None else bool(audit.status)
    )
    manifest["audit_registered"] = audit.registered
    manifest["audit_locked"] = audit.locked
    write_manifest(repository, manifest)


def retain_retryable_restoration_cleanup(
    repository: Repository,
    manifest: dict,
    *,
    source_head: str,
    pending_state: str,
    error: str,
) -> bool:
    try:
        durable = load_manifest(repository, manifest["run_id"])
        if durable.get("state") != pending_state:
            return False
        anchor = direct_ref_commit(repository, integration_source_ref(durable))
        audit = audit_run(repository, durable)
    except (KeyError, LauncherError):
        return False
    if anchor not in {None, source_head} or not audit_matches_clean_head(
        durable,
        audit,
        source_head,
    ):
        return False
    durable["integration_cleanup_error"] = error
    write_manifest(repository, durable)
    manifest.clear()
    manifest.update(durable)
    return True


def finish_restored_integration(
    repository: Repository,
    manifest: dict,
    *,
    archive: bool,
) -> None:
    if manifest.get("state") not in {
        "integration-abort-pending",
        "integration-rebase-rollback-pending",
    }:
        raise LauncherError(
            "the exact restoration lacks a durable launcher-owned checkpoint"
        )
    source_head = recorded_commit(repository, manifest, "integration_source_head")
    anchor = direct_ref_commit(repository, integration_source_ref(manifest))
    if anchor not in {None, source_head}:
        raise LauncherError("the retained run's private source anchor changed")
    audit = audit_run(repository, manifest)
    if rebase_in_progress(Path(manifest["worktree"])) or not audit_matches_clean_head(
        manifest,
        audit,
        source_head,
    ):
        raise LauncherError("the retained worker is not exactly restored to its audited source")
    if anchor == source_head:
        delete_integration_source_anchor(repository, manifest, source_head)
    if archive:
        archive_aborted_integration(manifest)
    else:
        clear_integration_transaction(manifest)
    manifest.pop("integration_recovery_error", None)
    manifest.pop("integration_cleanup_error", None)
    write_manifest(repository, manifest)


def abort_failed_integration_rebase(
    repository: Repository,
    manifest: dict,
    source_head: str,
    rebase_error: str,
) -> None:
    worktree = Path(manifest["worktree"])
    manifest["state"] = "integration-rebase-rollback-pending"
    manifest["integration_rollback_started_at"] = utc_now()
    write_manifest(repository, manifest)
    abort_error = ""
    if rebase_in_progress(worktree):
        abort = git(worktree, "rebase", "--abort", check=False)
        if abort.returncode:
            abort_error = abort.stderr.strip() or "Git reported no abort diagnostic"

    audit = audit_run(repository, manifest)
    if audit_matches_clean_head(manifest, audit, source_head):
        try:
            finish_restored_integration(repository, manifest, archive=False)
        except LauncherError as exc:
            if retain_retryable_restoration_cleanup(
                repository,
                manifest,
                source_head=source_head,
                pending_state="integration-rebase-rollback-pending",
                error=str(exc),
            ):
                raise
            record_integration_recovery_failure(
                repository,
                manifest,
                state="integration-rebase-recovery-failed",
                audit=audit,
                error=f"rebase abort restored the worker but source-anchor cleanup failed: {exc}",
            )
            raise
        if abort_error:
            manifest["last_integration_rebase_warning"] = abort_error
        manifest["last_integration_rebase_error"] = rebase_error
        manifest["last_integration_rebase_failed_at"] = utc_now()
        write_manifest(repository, manifest)
        return

    details = rebase_error
    if abort_error:
        details = f"{details}; rebase abort failed: {abort_error}"
    elif not audit_matches_clean_head(manifest, audit, source_head):
        details = f"{details}; the worker did not return to its audited commit"
    record_integration_recovery_failure(
        repository,
        manifest,
        state="integration-rebase-recovery-failed",
        audit=audit,
        error=details,
    )
    raise LauncherError(
        "rebase integration failed and the retained worker could not be confirmed at "
        f"its original audited commit: {details}"
    )


def rollback_completed_integration_rebase(
    repository: Repository,
    manifest: dict,
    source_head: str,
    error: str,
) -> None:
    worktree = Path(manifest["worktree"])
    before = audit_run(repository, manifest)
    candidate = manifest.get("integration_candidate_head")
    recognized_candidate = isinstance(candidate, str) and before.head == candidate
    if not recognized_candidate or not (
        before.registered
        and before.locked
        and before.branch == manifest["branch"]
        and before.head is not None
        and before.clean
    ):
        details = f"{error}; the rebased worker was not clean at its recorded candidate"
        record_integration_recovery_failure(
            repository,
            manifest,
            state="integration-rebase-rollback-failed",
            audit=before,
            error=details,
        )
        raise LauncherError(
            "integration did not advance the target, but the rebased worker had "
            "uncommitted or unexpected changes and was retained without reset"
        )

    manifest["state"] = "integration-rebase-rollback-pending"
    manifest["integration_rollback_started_at"] = utc_now()
    write_manifest(repository, manifest)
    reset = git(worktree, "reset", "--hard", source_head, check=False)
    audit = audit_run(repository, manifest)
    if audit_matches_clean_head(manifest, audit, source_head):
        try:
            finish_restored_integration(repository, manifest, archive=False)
        except LauncherError as exc:
            if retain_retryable_restoration_cleanup(
                repository,
                manifest,
                source_head=source_head,
                pending_state="integration-rebase-rollback-pending",
                error=str(exc),
            ):
                raise
            record_integration_recovery_failure(
                repository,
                manifest,
                state="integration-rebase-rollback-failed",
                audit=audit,
                error=f"{error}; source-anchor cleanup failed after exact rollback: {exc}",
            )
            raise
        if reset.returncode:
            manifest["last_integration_rebase_warning"] = (
                reset.stderr.strip() or "Git reported no reset diagnostic"
            )
        manifest["last_integration_rebase_error"] = error
        manifest["last_integration_rebase_failed_at"] = utc_now()
        write_manifest(repository, manifest)
        return

    reset_error = reset.stderr.strip() or "the worker did not return to its audited commit"
    details = f"{error}; rebase rollback failed: {reset_error}"
    record_integration_recovery_failure(
        repository,
        manifest,
        state="integration-rebase-rollback-failed",
        audit=audit,
        error=details,
    )
    raise LauncherError(
        "integration did not advance the target, but the rebased worker could not be "
        f"restored to its original audited commit: {details}"
    )


def retry_retained_ref_cleanup(repository: Repository, manifest: dict) -> bool:
    worktree = Path(manifest["worktree"])
    if registered_record(repository, worktree) is not None or worktree.exists():
        raise LauncherError("cannot retry branch cleanup while the retained worktree exists")

    if manifest.get("integrated_head") is not None:
        integrated_head = recorded_commit(repository, manifest, "integrated_head")
    else:
        integrated_head = recorded_commit(repository, manifest, "cleanup_expected_head")
    target_head = direct_ref_commit(repository, manifest["target_ref"])
    if target_head is None:
        raise LauncherError("the recorded target ref is unavailable during cleanup")
    manual_candidate = manifest.get("integration_manual_resolution") is True
    candidate_head = None
    if manual_candidate:
        candidate_head = recorded_commit(
            repository,
            manifest,
            "integration_candidate_head",
        )
        if integrated_head != candidate_head or target_head != candidate_head:
            raise LauncherError(
                "the manual target is not the exact reviewed candidate during cleanup"
            )
    elif not commit_is_ancestor(repository, integrated_head, target_head):
        raise LauncherError(
            "the recorded target no longer contains the integrated commit during cleanup"
        )

    branch_ref = f"refs/heads/{manifest['branch']}"
    symbolic = git(
        repository.root,
        "symbolic-ref",
        "--quiet",
        branch_ref,
        check=False,
    )
    if symbolic.returncode == 0:
        raise LauncherError("the retained worker branch was replaced by a symbolic ref")
    if symbolic.returncode != 1:
        raise LauncherError("cannot inspect the retained worker branch for cleanup")
    branch = git(
        repository.root,
        "rev-parse",
        "--verify",
        f"{branch_ref}^{{commit}}",
        check=False,
    )
    if branch.returncode:
        presence = git(
            repository.root,
            "show-ref",
            "--verify",
            "--quiet",
            branch_ref,
            check=False,
        )
        if presence.returncode == 1:
            branch_head = None
        else:
            raise LauncherError("cannot verify the retained worker branch for cleanup")
    else:
        branch_head = branch.stdout.strip()
        if not branch_is_integrated(repository, manifest, branch_head):
            raise LauncherError("the retained worker branch is not integrated into its target")
        if manual_candidate and branch_head != candidate_head:
            raise LauncherError(
                "the retained manual worker branch is not the exact reviewed candidate"
            )
        if any(record.get("branch") == branch_ref for record in worktree_records(repository)):
            raise LauncherError("the retained worker branch is checked out in another worktree")

    source_head = manifest.get("integration_source_head")
    anchor_ref = None
    anchor = None
    if source_head is not None:
        if not isinstance(source_head, str) or not OBJECT_ID_RE.fullmatch(source_head):
            raise LauncherError(
                "the retained run has no valid recorded integration source head"
            )
        anchor_ref = integration_source_ref(manifest)
        anchor = direct_ref_commit(repository, anchor_ref)
        if anchor not in {None, source_head}:
            raise LauncherError("the retained run's private source anchor changed")
        if (branch_head is None) != (anchor is None):
            raise LauncherError(
                "the transactional worker-branch and source-anchor cleanup is only partial"
            )

    retained_state = (
        "cleaned-ref-retained"
        if source_head is not None
        else "cleaned-branch-retained"
    )
    try:
        remove_run_tmpdir(repository, manifest)
    except LauncherError as exc:
        manifest["state"] = retained_state
        manifest["cleanup_warning"] = str(exc)
        write_manifest(repository, manifest)
        return False

    commands = ["start", f"verify {manifest['target_ref']} {target_head}"]
    if branch_head is not None:
        commands.append(f"delete {branch_ref} {branch_head}")
    if anchor_ref is not None and anchor == source_head:
        commands.append(f"delete {anchor_ref} {source_head}")
    commands.extend(("prepare", "commit", ""))
    deletion = git(
        repository.root,
        "update-ref",
        "--no-deref",
        "--stdin",
        check=False,
        input_data="\n".join(commands),
    )
    remaining_branch = branch_commit(repository, manifest)
    remaining_anchor = (
        direct_ref_commit(repository, anchor_ref) if anchor_ref is not None else None
    )
    if deletion.returncode or remaining_branch is not None or remaining_anchor is not None:
        manifest["state"] = retained_state
        manifest["cleanup_warning"] = (
            deletion.stderr.strip() or "private lifecycle refs were retained"
        )
        write_manifest(repository, manifest)
        return False

    manifest["state"] = "cleaned"
    manifest["branch_cleaned_at"] = utc_now()
    manifest.pop("cleanup_warning", None)
    write_manifest(repository, manifest)
    return True


def recover_removed_worktree_cleanup(repository: Repository, manifest: dict) -> bool:
    worktree = Path(manifest["worktree"])
    if registered_record(repository, worktree) is not None or worktree.exists():
        raise LauncherError("the retained worktree still exists during cleanup recovery")

    if manifest.get("integrated_head") is not None:
        integrated_head = recorded_commit(repository, manifest, "integrated_head")
    else:
        integrated_head = recorded_commit(repository, manifest, "cleanup_expected_head")
    target_head = direct_ref_commit(repository, manifest["target_ref"])
    if target_head is None:
        raise LauncherError("the recorded target ref is unavailable during cleanup recovery")
    if manifest.get("integration_manual_resolution") is True:
        candidate_head = recorded_commit(
            repository,
            manifest,
            "integration_candidate_head",
        )
        if integrated_head != candidate_head or target_head != candidate_head:
            raise LauncherError(
                "the manual target is not the exact reviewed candidate during cleanup recovery"
            )
    elif not commit_is_ancestor(repository, integrated_head, target_head):
        raise LauncherError(
            "the recorded target no longer contains the integrated commit during cleanup recovery"
        )

    branch_head = branch_commit(repository, manifest)
    if branch_head is None or not branch_is_integrated(repository, manifest, branch_head):
        raise LauncherError(
            "the pre-checkpoint worker branch is missing or not integrated during cleanup recovery"
        )
    if manifest.get("integration_source_head") is not None:
        recorded_integration_source(repository, manifest)

    manifest["state"] = (
        "cleaned-ref-retained"
        if manifest.get("integration_source_head") is not None
        else "cleaned-branch-retained"
    )
    manifest["cleaned_at"] = utc_now()
    manifest["cleanup_warning"] = "interrupted private lifecycle ref cleanup pending"
    write_manifest(repository, manifest)
    return retry_retained_ref_cleanup(repository, manifest)


def recover_unlocked_worktree_cleanup(repository: Repository, manifest: dict) -> bool:
    worktree = Path(manifest["worktree"])
    authenticate_retained_worktree(repository, manifest)
    audit = audit_run(repository, manifest)
    if not (
        audit.registered
        and audit.branch == manifest["branch"]
        and audit.head is not None
        and audit.clean
        and not rebase_in_progress(worktree)
    ):
        raise LauncherError(
            "the interrupted cleanup worker is not an exact clean managed worktree"
        )

    expected_head = recorded_commit(repository, manifest, "cleanup_expected_head")
    if manifest.get("integrated_head") is not None and recorded_commit(
        repository,
        manifest,
        "integrated_head",
    ) != expected_head:
        raise LauncherError("the interrupted cleanup checkpoint is inconsistent")
    if audit.head != expected_head:
        raise LauncherError("the interrupted cleanup worker changed after its checkpoint")

    if not audit.locked:
        authenticate_retained_worktree(repository, manifest)
        relock = git(
            repository.root,
            "worktree",
            "lock",
            "--reason",
            f"{active_profile().lock_reason_prefix}{manifest['run_id']}",
            str(worktree),
            check=False,
        )
        audit = audit_run(repository, manifest)
        if relock.returncode or not audit_matches_clean_head(
            manifest,
            audit,
            expected_head,
        ):
            raise LauncherError("the interrupted cleanup worktree could not be relocked")

    if manifest.get("integration_source_head") is not None:
        recorded_integration_source(repository, manifest)
    if manifest.get("integration_manual_resolution") is True:
        candidate_head = recorded_commit(
            repository,
            manifest,
            "integration_candidate_head",
        )
        if expected_head != candidate_head or direct_ref_commit(
            repository,
            manifest["target_ref"],
        ) != candidate_head:
            raise LauncherError(
                "the manual target is not the exact reviewed candidate during cleanup recovery"
            )

    return safe_cleanup(
        repository,
        manifest,
        allow_integrated=True,
        expected_head=expected_head,
    )


def safe_cleanup(
    repository: Repository,
    manifest: dict,
    *,
    allow_integrated: bool,
    expected_head: str | None = None,
) -> bool:
    audit = audit_run(repository, manifest)
    if not audit.registered or not audit.locked:
        raise LauncherError("the retained worktree is missing or unlocked")
    if audit.branch != manifest["branch"]:
        raise LauncherError("the retained worktree changed branches")
    if not audit.clean or audit.head is None:
        raise LauncherError("the retained worktree has uncommitted changes")
    if expected_head is not None and audit.head != expected_head:
        raise LauncherError("the retained worktree changed since its last launcher audit")
    if audit.head != manifest["base_sha"]:
        if not allow_integrated or not branch_is_integrated(repository, manifest, audit.head):
            raise LauncherError("the retained worktree contains work not integrated into its target")
    manual_candidate = manifest.get("integration_manual_resolution") is True
    if manual_candidate:
        candidate_head = recorded_commit(
            repository,
            manifest,
            "integration_candidate_head",
        )
        if expected_head != candidate_head or direct_ref_commit(
            repository,
            manifest["target_ref"],
        ) != candidate_head:
            raise LauncherError(
                "the manual target is not the exact reviewed candidate before cleanup"
            )

    worktree = Path(manifest["worktree"])
    manifest["state"] = "integration-cleanup-pending"
    manifest["integration_cleanup_started_at"] = utc_now()
    manifest["cleanup_expected_head"] = audit.head
    write_manifest(repository, manifest)
    authenticate_retained_worktree(repository, manifest)
    git(repository.root, "worktree", "unlock", str(worktree))
    authenticate_retained_worktree(repository, manifest)
    removal = git(
        repository.root,
        "worktree",
        "remove",
        str(worktree),
        check=False,
    )
    if removal.returncode:
        authenticate_retained_worktree(repository, manifest)
        git(
            repository.root,
            "worktree",
            "lock",
            "--reason",
            f"{active_profile().lock_reason_prefix}{manifest['run_id']}",
            str(worktree),
            check=False,
        )
        raise LauncherError("safe managed-worktree removal failed")

    target_changed = manual_candidate and direct_ref_commit(
        repository,
        manifest["target_ref"],
    ) != candidate_head
    retained_state = (
        "cleaned-ref-retained"
        if manifest.get("integration_source_head") is not None
        else "cleaned-branch-retained"
    )
    manifest["state"] = retained_state
    manifest["cleaned_at"] = utc_now()
    manifest["cleanup_warning"] = "private lifecycle ref cleanup pending"
    write_manifest(repository, manifest)
    if target_changed:
        manifest["cleanup_warning"] = (
            "the manual target changed before branch and source-anchor cleanup"
        )
        write_manifest(repository, manifest)
        branch_removed = False
    else:
        try:
            branch_removed = retry_retained_ref_cleanup(repository, manifest)
        except LauncherError as exc:
            manifest["state"] = retained_state
            manifest["cleanup_warning"] = str(exc)
            write_manifest(repository, manifest)
            branch_removed = False

    return branch_removed


def preserve_run(repository: Repository, manifest: dict, exit_code: int, audit: Audit) -> None:
    manifest["state"] = "preserved" if exit_code == 0 else "failed-preserved"
    manifest["child_exit_code"] = exit_code
    manifest["final_head"] = audit.head
    manifest["dirty"] = None if audit.status is None else bool(audit.status)
    manifest["audit_registered"] = audit.registered
    manifest["audit_locked"] = audit.locked
    if audit.branch != manifest.get("branch"):
        manifest["state"] = "quarantined"
    write_manifest(repository, manifest)


def quarantine_rewritten_run(
    repository: Repository,
    manifest: dict,
    exit_code: int,
    audit: Audit,
    reason: str,
) -> None:
    manifest["state"] = "quarantined"
    manifest["child_exit_code"] = exit_code
    manifest["observed_head"] = audit.head
    manifest["observed_dirty"] = None if audit.status is None else bool(audit.status)
    manifest["audit_registered"] = audit.registered
    manifest["audit_locked"] = audit.locked
    manifest["quarantine_reason"] = reason
    write_manifest(repository, manifest)


def terminal_history_discontinuity(
    repository: Repository,
    manifest: dict,
    audit: Audit,
) -> str | None:
    prior_final_head = manifest.get("final_head")
    if not isinstance(prior_final_head, str):
        return None
    if audit.head is None:
        return "the retained worker no longer has an auditable commit"
    try:
        if commit_is_ancestor(repository, prior_final_head, audit.head):
            return None
    except LauncherError as exc:
        return str(exc)
    return "the retained worker history no longer descends from its last terminal audit"


def launch_child(
    repository: Repository,
    manifest: dict,
    run_lock_stream: TextIO,
    real_codex: Path,
    arguments: Sequence[str],
) -> int:
    worktree = Path(manifest["worktree"])
    authenticate_retained_worktree(repository, manifest)
    require_run_tmp_directory(repository, manifest)
    if worktree.is_symlink():
        raise LauncherError("the retained worktree path was replaced by a symlink")
    child_cwd = worktree / Path(manifest["relative_cwd"])
    try:
        child_cwd.resolve().relative_to(worktree.resolve())
    except (OSError, RuntimeError, ValueError) as exc:
        raise LauncherError("the retained working directory escapes its worktree") from exc
    if not child_cwd.is_dir():
        raise LauncherError("the retained working directory is unavailable")
    argv = codex_argv(real_codex, child_cwd, arguments)
    manifest["state"] = "running"
    manifest["started_at"] = utc_now()
    manifest.pop("background_process_active", None)
    write_manifest(repository, manifest)
    held_lock: TextIO | None = run_lock_stream
    try:
        try:
            process = subprocess.Popen(
                argv,
                cwd=child_cwd,
                env=child_environment(manifest, real_codex),
                pass_fds=(run_lock_stream.fileno(),),
            )
        except OSError as exc:
            diagnostic(f"cannot start Codex: {exc}")
            exit_code = 127
        else:
            exit_code = normalized_exit_status(wait_for_child(process))

        with file_lock(repo_lock_path(repository)):
            held_lock.close()
            held_lock = None
            try:
                held_lock = acquire_existing_run_lock(repository, manifest["run_id"])
            except LauncherError as exc:
                audit = audit_run(repository, manifest)
                quarantine_reason = terminal_history_discontinuity(
                    repository,
                    manifest,
                    audit,
                )
                if quarantine_reason is None:
                    preserve_run(repository, manifest, exit_code, audit)
                else:
                    quarantine_rewritten_run(
                        repository,
                        manifest,
                        exit_code,
                        audit,
                        quarantine_reason,
                    )
                manifest["background_process_active"] = True
                write_manifest(repository, manifest)
                if quarantine_reason is None:
                    diagnostic(
                        f"run {manifest['run_id']} was preserved because a worker process "
                        f"still holds its lifecycle lock: {exc}"
                    )
                else:
                    diagnostic(
                        f"run {manifest['run_id']} was quarantined while a worker process "
                        f"still holds its lifecycle lock: {quarantine_reason}"
                    )
                return exit_code

            audit = audit_run(repository, manifest)
            has_prior_terminal_audit = "final_head" in manifest or "dirty" in manifest
            quarantine_reason = terminal_history_discontinuity(
                repository,
                manifest,
                audit,
            )
            if quarantine_reason is not None:
                quarantine_rewritten_run(
                    repository,
                    manifest,
                    exit_code,
                    audit,
                    quarantine_reason,
                )
                diagnostic(f"run {manifest['run_id']} was quarantined: {quarantine_reason}")
                return exit_code

            if (
                exit_code == 0
                and exact_unchanged_audit(manifest, audit)
                and not has_prior_terminal_audit
            ):
                try:
                    branch_removed = safe_cleanup(
                        repository,
                        manifest,
                        allow_integrated=False,
                    )
                    if not branch_removed:
                        diagnostic(
                            f"run {manifest['run_id']} worktree was removed, but a private lifecycle ref remains"
                        )
                except LauncherError as exc:
                    if manifest.get("state") == "integration-cleanup-pending":
                        manifest["state"] = "integration-cleanup-failed"
                        manifest["integration_cleanup_error"] = str(exc)
                        write_manifest(repository, manifest)
                        diagnostic(
                            f"run {manifest['run_id']} cleanup was interrupted: {exc}; "
                            "retry "
                            f"{active_profile().lifecycle_command('clean', manifest['run_id'])}"
                        )
                    else:
                        preserve_run(repository, manifest, exit_code, audit)
                        diagnostic(f"run {manifest['run_id']} was preserved: {exc}")
            else:
                preserve_run(repository, manifest, exit_code, audit)
                diagnostic(
                    f"run {manifest['run_id']} was preserved; reopen its worktree with "
                    f"{active_profile().lifecycle_command('reopen', manifest['run_id'])}"
                )
        return exit_code
    finally:
        if held_lock is not None and not held_lock.closed:
            held_lock.close()


def launch_resolver(
    repository: Repository,
    manifest: dict,
    run_lock_stream: TextIO,
    real_codex: Path,
) -> int:
    child_cwd = Path(manifest["worktree"])
    authenticate_retained_worktree(repository, manifest)
    require_run_tmp_directory(repository, manifest)
    argv = codex_argv(real_codex, child_cwd, [active_profile().resolver_prompt])
    manifest["resolver_started_at"] = utc_now()
    manifest.pop("background_process_active", None)
    write_manifest(repository, manifest)
    held_lock: TextIO | None = run_lock_stream
    try:
        try:
            process = subprocess.Popen(
                argv,
                cwd=child_cwd,
                env=resolver_environment(manifest, real_codex),
                pass_fds=(run_lock_stream.fileno(),),
            )
        except OSError as exc:
            diagnostic(f"cannot start the conflict resolver: {exc}")
            exit_code = 127
        else:
            exit_code = normalized_exit_status(wait_for_child(process))

        with file_lock(repo_lock_path(repository)):
            held_lock.close()
            held_lock = None
            try:
                held_lock = acquire_existing_run_lock(repository, manifest["run_id"])
            except LauncherError as exc:
                audit = audit_run(repository, manifest)
                manifest["resolver_child_exit_code"] = exit_code
                manifest["resolver_observed_head"] = audit.head
                manifest["resolver_observed_dirty"] = (
                    None if audit.status is None else bool(audit.status)
                )
                manifest["background_process_active"] = True
                write_manifest(repository, manifest)
                diagnostic(
                    f"run {manifest['run_id']} remains active because a resolver process "
                    f"still holds its lifecycle lock: {exc}"
                )
                return exit_code

            audit = audit_run(repository, manifest)
            try:
                paths = validate_managed_conflict(repository, manifest, audit)
            except ManagedConflictScopeError as exc:
                manifest["state"] = "integration-conflict"
                manifest["resolver_child_exit_code"] = exit_code
                manifest["integration_resolver_scope_error"] = str(exc)
                manifest["resolver_finished_at"] = utc_now()
                write_manifest(repository, manifest)
                raise LauncherError(
                    "the resolver exceeded its staging scope; the managed conflict "
                    "remains correctable with "
                    f"{active_profile().lifecycle_hint('resolve')} "
                    "or restorable with "
                    f"{active_profile().lifecycle_hint('abort')}"
                ) from exc
            except LauncherError as exc:
                record_integration_recovery_failure(
                    repository,
                    manifest,
                    state="integration-rebase-recovery-failed",
                    audit=audit,
                    error=f"the resolver altered the managed rebase state: {exc}",
                )
                raise LauncherError(
                    "the resolver altered or administered the managed rebase; its "
                    "unverified state was retained without abort or reset"
                ) from exc

            manifest["state"] = "integration-conflict"
            manifest.pop("integration_resolver_scope_error", None)
            manifest["resolver_child_exit_code"] = exit_code
            manifest["integration_unmerged_paths"] = paths
            manifest["resolver_finished_at"] = utc_now()
            if (
                not paths
                and not worktree_has_unstaged_changes(Path(manifest["worktree"]))
                and not nonignored_untracked_paths(Path(manifest["worktree"]))
            ):
                manifest["integration_resolution_staged_at"] = utc_now()
            else:
                manifest.pop("integration_resolution_staged_at", None)
            write_manifest(repository, manifest)

        if exit_code == 0:
            if paths:
                diagnostic(
                    f"run {manifest['run_id']} still has {len(paths)} unresolved conflict "
                    "path(s); reopen the resolver with "
                    f"{active_profile().lifecycle_hint('resolve')}"
                )
            else:
                diagnostic(
                    f"run {manifest['run_id']} resolver exited; after all resolutions are "
                    "staged, continue with "
                    f"{active_profile().lifecycle_command('continue', manifest['run_id'])}"
                )
        return exit_code
    finally:
        if held_lock is not None and not held_lock.closed:
            held_lock.close()


def pass_through_linked_worktree(
    repository: Repository,
    real_codex: Path,
    arguments: Sequence[str],
) -> int:
    profile = active_profile()
    role = os.environ.get(profile.role_environment)
    profile_marker = (
        os.environ.get(profile.profile_environment)
        if profile.profile_environment is not None
        else None
    )
    agent_marker = (
        os.environ.get(profile.agent_environment)
        if profile.agent_environment is not None
        else None
    )
    record = registered_record(repository, repository.root)
    lock_reason = record.get("locked") if record else None
    managed_lock = isinstance(lock_reason, str) and any(
        lock_reason.startswith(candidate.lock_reason_prefix)
        for candidate in BUILTIN_PROFILES.values()
    )
    branch = git(
        repository.root,
        "symbolic-ref",
        "--quiet",
        "--short",
        "HEAD",
        check=False,
    ).stdout.strip()
    managed_marker = any(
        os.environ.get(name) for name in MANAGED_CONTEXT_ENVIRONMENTS
    )
    managed_branch = any(
        branch.startswith(candidate.worker_branch_prefix)
        for candidate in BUILTIN_PROFILES.values()
    )
    if managed_marker or managed_lock or managed_branch:
        raise LauncherError(
            "nested Codex launch refused in a managed worker; reopen retained worktrees from the primary checkout"
        )
    if role is not None:
        raise LauncherError(f"unexpected {profile.role_environment} marker")
    if profile_marker is not None and profile_marker != profile.profile_id:
        raise LauncherError(
            f"unexpected {profile.profile_environment} marker"
        )
    if agent_marker is not None and agent_marker != profile.manifest_agent:
        raise LauncherError(f"unexpected {profile.agent_environment} marker")
    workdir = repository.root / repository.relative_cwd
    argv = codex_argv(real_codex, workdir, arguments)
    environment = codex_environment(real_codex)
    environment = _enrich_codex_environment(
        environment,
        profile=profile,
        role="worker",
        manifest=None,
    )
    os.execve(real_codex, argv, environment)
    raise AssertionError("unreachable")


def acquire_existing_run_lock(repository: Repository, run_id: str) -> TextIO:
    path = run_lock_path(repository, run_id)
    try:
        stream = path.open("r+", encoding="utf-8")
    except FileNotFoundError as exc:
        raise LauncherError(f"run {run_id} has no intact lifecycle lock") from exc
    os.chmod(path, 0o600)
    try:
        fcntl.flock(stream.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError as exc:
        stream.close()
        raise LauncherError(f"run {run_id} is already active") from exc
    register_lock_descriptor(stream)
    return stream


def require_recorded_target_checkout(
    repository: Repository,
    manifest: dict,
    *,
    purpose: str,
) -> str:
    target_head, current_ref = require_stable_clean_base(repository, purpose=purpose)
    target_ref = manifest["target_ref"]
    if current_ref != target_ref:
        target_name = target_ref.removeprefix("refs/heads/")
        raise LauncherError(
            f"the primary checkout must be on the recorded target branch {target_name!r}"
        )
    return target_head


def refresh_recorded_target_observation(
    repository: Repository,
    manifest: dict,
    captured: str,
) -> tuple[str | None, str | None]:
    """Observe the recorded target ref without consulting the primary checkout."""
    try:
        observed = direct_ref_commit(repository, manifest["target_ref"])
    except LauncherError as exc:
        error = f"the recorded target ref cannot be authenticated: {exc}"
        manifest["integration_target_verification_error"] = error
        return None, error
    if observed is None:
        error = "the recorded target ref is unavailable"
        manifest["integration_target_verification_error"] = error
        return None, error
    manifest.pop("integration_target_verification_error", None)
    if observed != captured:
        record_target_mismatch(manifest, observed)
    return observed, None


def reflog_records(
    worktree: Path,
    revision: str,
    *,
    limit: int,
) -> list[tuple[str, str]]:
    result = git(
        worktree,
        "reflog",
        "show",
        f"-{limit}",
        "--format=%H%x00%gs",
        revision,
        check=False,
        text=False,
    )
    if result.returncode:
        return []
    records: list[tuple[str, str]] = []
    for line in result.stdout.splitlines():
        commit, separator, subject = line.partition(b"\0")
        try:
            value = commit.decode("ascii", errors="strict")
        except UnicodeDecodeError:
            return []
        if not separator or not OBJECT_ID_RE.fullmatch(value):
            return []
        records.append((value, subject.decode("utf-8", errors="surrogateescape")))
    return records


def provable_completed_initial_rebase(
    repository: Repository,
    manifest: dict,
    audit: Audit,
    source_head: str,
) -> bool:
    """Recognize only Git's exact terminal ref transition from source to candidate."""
    if manifest.get("integration_source_anchor_created") is not True:
        return False
    if not valid_rebased_candidate_audit(repository, manifest, audit):
        return False
    candidate_head = audit.head
    if candidate_head is None:
        return False
    target_head = recorded_commit(repository, manifest, "integration_target_head")
    branch_ref = f"refs/heads/{manifest['branch']}"
    branch_records = reflog_records(
        Path(manifest["worktree"]),
        branch_ref,
        limit=2,
    )
    head_records = reflog_records(
        Path(manifest["worktree"]),
        "HEAD",
        limit=1,
    )
    return bool(
        branch_commit(repository, manifest) == candidate_head
        and len(branch_records) == 2
        and branch_records[0]
        == (
            candidate_head,
            f"rebase (finish): {branch_ref} onto {target_head}",
        )
        and branch_records[1][0] == source_head
        and head_records
        == [
            (
                candidate_head,
                f"rebase (finish): returning to {branch_ref}",
            )
        ]
    )


def valid_rebased_candidate_audit(
    repository: Repository,
    manifest: dict,
    audit: Audit,
) -> bool:
    target_head = recorded_commit(repository, manifest, "integration_target_head")
    return bool(
        not rebase_in_progress(Path(manifest["worktree"]))
        and audit.registered
        and audit.locked
        and audit.branch == manifest["branch"]
        and audit.head is not None
        and audit.clean
        and commit_is_ancestor(repository, target_head, audit.head)
        and not worker_history_has_merge(repository, audit.head, target_head)
    )


def record_review_pending_candidate(
    repository: Repository,
    manifest: dict,
    audit: Audit,
) -> str:
    recorded_integration_source(repository, manifest)
    if not valid_rebased_candidate_audit(repository, manifest, audit):
        raise LauncherError("the worker is not a clean valid review-pending candidate")
    candidate_head = audit.head
    if candidate_head is None:
        raise LauncherError("the worker candidate has no auditable commit")
    manifest["state"] = "integration-review-pending"
    manifest["integration_candidate_head"] = candidate_head
    manifest["integration_manual_resolution"] = True
    manifest["integration_unmerged_paths"] = []
    manifest["integration_rebased_at"] = utc_now()
    manifest.pop("integration_continue_started_at", None)
    manifest.pop("integration_recovery_error", None)
    manifest.pop("integration_resolver_scope_error", None)
    write_manifest(repository, manifest)
    return candidate_head


def record_initial_rebase_candidate(
    repository: Repository,
    manifest: dict,
    audit: Audit,
) -> str:
    source_head = recorded_integration_source(repository, manifest)
    if not provable_completed_initial_rebase(
        repository,
        manifest,
        audit,
        source_head,
    ):
        raise LauncherError(
            "the clean worker is not the exact completed initial-rebase candidate"
        )
    candidate_head = audit.head
    if candidate_head is None:
        raise LauncherError("the completed initial rebase has no auditable candidate")
    manifest["state"] = "integration-merge-pending"
    manifest["integration_candidate_head"] = candidate_head
    manifest["integration_rebased_at"] = utc_now()
    manifest.pop("integration_manual_resolution", None)
    manifest.pop("integration_continue_started_at", None)
    manifest.pop("integration_recovery_error", None)
    manifest.pop("integration_resolver_scope_error", None)
    write_manifest(repository, manifest)
    return candidate_head


def recover_interrupted_continue(
    repository: Repository,
    manifest: dict,
    audit: Audit,
) -> str:
    if manifest.get("state") != "integration-continue-pending":
        return "unchanged"
    worktree = Path(manifest["worktree"])
    try:
        recorded_integration_source(repository, manifest)
    except LauncherError as exc:
        record_integration_recovery_failure(
            repository,
            manifest,
            state="integration-rebase-recovery-failed",
            audit=audit,
            error=f"interrupted continuation source-anchor verification failed: {exc}",
        )
        raise LauncherError(
            "the interrupted continuation's private source anchor changed"
        ) from exc
    if rebase_in_progress(worktree):
        try:
            validate_managed_rebase_identity(repository, manifest, audit)
            return "unchanged"
        except LauncherError as original_error:
            prior_commit = recorded_commit(
                repository,
                manifest,
                "integration_conflict_commit",
            )
            current_commit = rebase_commit(worktree)
            if (
                current_commit is None
                or current_commit == prior_commit
                or not commit_is_ancestor(repository, prior_commit, current_commit)
                or not unmerged_paths(worktree)
            ):
                record_integration_recovery_failure(
                    repository,
                    manifest,
                    state="integration-rebase-recovery-failed",
                    audit=audit,
                    error=f"interrupted continuation changed its rebase administration: {original_error}",
                )
                raise LauncherError(
                    "the interrupted continuation no longer has a provable managed state"
                ) from original_error
            try:
                record_managed_conflict(
                    repository,
                    manifest,
                    audit,
                    "launcher interruption after continuation reached a later conflict",
                )
            except LauncherError as exc:
                record_integration_recovery_failure(
                    repository,
                    manifest,
                    state="integration-rebase-recovery-failed",
                    audit=audit,
                    error=f"cannot adopt the later continuation conflict: {exc}",
                )
                raise LauncherError(
                    "the interrupted continuation reached an unprovable active rebase"
                ) from exc
            return "conflict"
    if valid_rebased_candidate_audit(repository, manifest, audit):
        record_review_pending_candidate(repository, manifest, audit)
        return "review"
    record_integration_recovery_failure(
        repository,
        manifest,
        state="integration-rebase-recovery-failed",
        audit=audit,
        error="interrupted continuation left neither its recorded conflict nor a clean candidate",
    )
    raise LauncherError(
        "the interrupted continuation left an unprovable worker state"
    )


def recover_interrupted_initial_rebase(
    repository: Repository,
    manifest: dict,
    audit: Audit,
    *,
    allow_precommit_abort: bool = False,
) -> str:
    if manifest.get("state") != "integration-rebase-pending":
        return "unchanged"
    worktree = Path(manifest["worktree"])
    try:
        source_head = recorded_commit(repository, manifest, "integration_source_head")
        anchor = direct_ref_commit(repository, integration_source_ref(manifest))
    except LauncherError as exc:
        record_integration_recovery_failure(
            repository,
            manifest,
            state="integration-rebase-recovery-failed",
            audit=audit,
            error=f"interrupted initial rebase source-anchor preflight failed: {exc}",
        )
        raise LauncherError(
            "the interrupted integration rebase's private source anchor is unprovable"
        ) from exc
    anchor_checkpointed = manifest.get("integration_source_anchor_created") is True
    if rebase_in_progress(worktree):
        try:
            if not anchor_checkpointed:
                raise LauncherError(
                    "the interrupted integration rebase lacks its durable source-anchor checkpoint"
                )
            recorded_integration_source(repository, manifest)
            if allow_precommit_abort and not unmerged_paths(worktree):
                commit, index_tree, metadata_hash = validate_initial_rebase_precommit(
                    repository,
                    manifest,
                    audit,
                    require_checkpoint=False,
                )
                manifest["integration_precommit_commit"] = commit
                manifest["integration_precommit_index_tree"] = index_tree
                manifest["integration_rebase_metadata_hash"] = metadata_hash
                write_manifest(repository, manifest)
                return "precommit"
            record_managed_conflict(
                repository,
                manifest,
                audit,
                "launcher interruption after integration rebase reached a conflict",
            )
        except LauncherError as exc:
            record_integration_recovery_failure(
                repository,
                manifest,
                state="integration-rebase-recovery-failed",
                audit=audit,
                error=f"cannot adopt interrupted integration rebase: {exc}",
            )
            raise LauncherError(
                "the interrupted integration rebase has an unprovable active state: "
                f"{exc}"
            ) from exc
        return "conflict"
    if audit_matches_clean_head(manifest, audit, source_head):
        try:
            if anchor_checkpointed:
                recorded_integration_source(repository, manifest)
            else:
                if anchor not in {None, source_head}:
                    raise LauncherError("the retained run's private source anchor changed")
                ensure_integration_source_anchor(repository, manifest, source_head)
                manifest["integration_source_anchor_created"] = True
                write_manifest(repository, manifest)
        except LauncherError as exc:
            record_integration_recovery_failure(
                repository,
                manifest,
                state="integration-rebase-recovery-failed",
                audit=audit,
                error=f"interrupted initial rebase source-anchor verification failed: {exc}",
            )
            raise LauncherError(
                "the interrupted integration rebase's private source anchor changed"
            ) from exc
        return "resume"
    try:
        if anchor != source_head:
            raise LauncherError(
                "the interrupted integration rebase's private source anchor changed"
            )
        record_initial_rebase_candidate(repository, manifest, audit)
    except LauncherError as exc:
        record_integration_recovery_failure(
            repository,
            manifest,
            state="integration-rebase-recovery-failed",
            audit=audit,
            error=f"cannot adopt interrupted completed integration rebase: {exc}",
        )
        raise LauncherError(
            "the interrupted integration rebase left an unprovable worker state"
        ) from exc
    return "candidate"


def resolve_conflict_run(
    repository: Repository,
    run_id: str,
    launcher: LauncherIdentity,
) -> int:
    if repository.linked_worktree:
        raise LauncherError("open a managed conflict resolver from the primary checkout")
    initialize_state(repository)
    real_codex = resolve_real_codex(launcher)
    with file_lock(repo_lock_path(repository)):
        manifest = load_manifest(repository, run_id)
        reconcile_stale_run(repository, manifest)
        if manifest.get("state") not in {
            "integration-conflict",
            "integration-continue-pending",
        }:
            raise LauncherError(f"run {run_id} has no managed conflict to resolve")
        run_lock_stream = acquire_existing_run_lock(repository, run_id)
        try:
            target_head = recorded_commit(
                repository,
                manifest,
                "integration_target_head",
            )
            audit = audit_run(repository, manifest)
            recovery = recover_interrupted_continue(repository, manifest, audit)
            refresh_recorded_target_observation(
                repository,
                manifest,
                target_head,
            )
            if recovery == "review":
                write_manifest(repository, manifest)
                raise LauncherError(
                    f"run {run_id} already has a clean review-pending candidate"
                )
            audit = audit_run(repository, manifest)
            try:
                validate_managed_rebase_identity(repository, manifest, audit)
            except LauncherError as exc:
                record_integration_recovery_failure(
                    repository,
                    manifest,
                    state="integration-rebase-recovery-failed",
                    audit=audit,
                    error=f"the managed conflict changed before resolver launch: {exc}",
                )
                raise LauncherError(
                    "the managed conflict's rebase administration or private source "
                    "anchor changed; the resolver was not launched"
                ) from exc
            manifest["state"] = "integration-conflict"
            manifest.pop("integration_continue_started_at", None)
            write_manifest(repository, manifest)
        except Exception:
            run_lock_stream.close()
            raise
    return launch_resolver(
        repository,
        manifest,
        run_lock_stream,
        real_codex,
    )


def continue_conflict_run(repository: Repository, run_id: str) -> int:
    if repository.linked_worktree:
        raise LauncherError("continue a managed conflict from the primary checkout")
    initialize_state(repository)
    with file_lock(repo_lock_path(repository)):
        manifest = load_manifest(repository, run_id)
        reconcile_stale_run(repository, manifest)
        if manifest.get("state") not in {
            "integration-conflict",
            "integration-continue-pending",
        }:
            raise LauncherError(f"run {run_id} has no managed conflict to continue")
        run_lock_stream = acquire_existing_run_lock(repository, run_id)
        try:
            target_head = recorded_commit(
                repository,
                manifest,
                "integration_target_head",
            )
            audit = audit_run(repository, manifest)
            recovery = recover_interrupted_continue(repository, manifest, audit)
            _, target_error = refresh_recorded_target_observation(
                repository,
                manifest,
                target_head,
            )
            write_manifest(repository, manifest)
            if recovery == "review":
                if target_error is not None:
                    raise LauncherError(
                        f"run {run_id} recovered a clean review-pending candidate, but "
                        f"{target_error}; the candidate was retained"
                    )
                if manifest.get("integration_target_mismatch_head") is not None:
                    raise LauncherError(
                        f"run {run_id} recovered a clean review-pending candidate, but its "
                        "recorded target advanced during resolution; the candidate was retained"
                    )
                diagnostic(
                    f"run {run_id} recovered a clean review-pending candidate; review its "
                    f"final diff before fresh integration authorization"
                )
                return 0
            worktree = Path(manifest["worktree"])
            audit = audit_run(repository, manifest)
            try:
                paths = validate_managed_conflict(repository, manifest, audit)
            except ManagedConflictScopeError:
                raise
            except LauncherError as exc:
                record_integration_recovery_failure(
                    repository,
                    manifest,
                    state="integration-rebase-recovery-failed",
                    audit=audit,
                    error=f"the managed conflict changed before continuation: {exc}",
                )
                raise LauncherError(
                    "the managed conflict's rebase administration or private source "
                    "anchor changed; continuation was refused"
                ) from exc
            manifest["state"] = "integration-conflict"
            manifest.pop("integration_resolver_scope_error", None)
            manifest.pop("integration_continue_started_at", None)
            manifest["integration_unmerged_paths"] = paths
            if paths:
                write_manifest(repository, manifest)
                raise LauncherError(
                    f"run {run_id} still has {len(paths)} unresolved conflict path(s); "
                    "resolve and stage them with "
                    f"{active_profile().lifecycle_command('resolve', run_id)}"
                )
            if worktree_has_unstaged_changes(worktree):
                raise LauncherError(
                    "the managed resolution has unstaged changes; review and stage every "
                    "intended resolution before continuing"
                )
            untracked = nonignored_untracked_paths(worktree)
            if untracked:
                raise LauncherError(
                    "the managed resolution has non-ignored untracked files; review and "
                    "stage or remove them before continuing"
                )
            write_tree = git(worktree, "write-tree", check=False)
            if write_tree.returncode:
                raise LauncherError(
                    "the managed resolution index is not ready to continue: "
                    f"{write_tree.stderr.strip() or 'no diagnostic'}"
                )

            manifest["state"] = "integration-continue-pending"
            manifest["integration_manual_resolution"] = True
            manifest["integration_continue_started_at"] = utc_now()
            write_manifest(repository, manifest)
            continue_rebase = git(
                worktree,
                "-c",
                "rebase.autoStash=false",
                "-c",
                "rebase.backend=merge",
                "-c",
                "rebase.updateRefs=false",
                "-c",
                "rerere.enabled=false",
                "-c",
                "rerere.autoupdate=false",
                "-c",
                "core.hooksPath=/dev/null",
                "-c",
                "core.editor=true",
                "-c",
                "sequence.editor=true",
                "rebase",
                "--continue",
                check=False,
                environment={
                    "GIT_EDITOR": "true",
                    "GIT_SEQUENCE_EDITOR": "true",
                    "EDITOR": "true",
                    "VISUAL": "true",
                },
            )
            if continue_rebase.returncode:
                continue_error = (
                    continue_rebase.stderr.strip() or "Git reported no diagnostic"
                )
                continued_audit = audit_run(repository, manifest)
                if rebase_in_progress(worktree):
                    try:
                        paths = record_managed_conflict(
                            repository,
                            manifest,
                            continued_audit,
                            continue_error,
                        )
                    except LauncherError as exc:
                        record_integration_recovery_failure(
                            repository,
                            manifest,
                            state="integration-rebase-recovery-failed",
                            audit=continued_audit,
                            error=f"rebase continuation failed in an unknown state: {exc}",
                        )
                        raise LauncherError(
                            "rebase continuation failed in an unverified state; the worker "
                            "was retained without abort or reset"
                        ) from exc
                    raise LauncherError(
                        f"rebase continuation reached another managed conflict in "
                        f"{len(paths)} path(s); open "
                        f"{active_profile().lifecycle_command('resolve', run_id)}"
                    )
                record_integration_recovery_failure(
                    repository,
                    manifest,
                    state="integration-rebase-recovery-failed",
                    audit=continued_audit,
                    error=f"rebase continuation failed without an active rebase: {continue_error}",
                )
                raise LauncherError(
                    "rebase continuation failed without a provable managed conflict; its "
                    "state was retained without abort or reset"
                )

            candidate_audit = audit_run(repository, manifest)
            try:
                candidate_head = record_review_pending_candidate(
                    repository,
                    manifest,
                    candidate_audit,
                )
            except LauncherError as exc:
                record_integration_recovery_failure(
                    repository,
                    manifest,
                    state="integration-rebase-recovery-failed",
                    audit=candidate_audit,
                    error=f"Git reported a completed continuation with an unexpected worker state: {exc}",
                )
                raise LauncherError(
                    "Git reported a completed continuation, but the worker was not a clean "
                    "review-pending candidate; it was retained without reset"
                ) from exc

            _, target_error = refresh_recorded_target_observation(
                repository,
                manifest,
                target_head,
            )
            write_manifest(repository, manifest)
            if target_error is not None:
                raise LauncherError(
                    f"run {run_id} now has a clean review-pending candidate, but the "
                    f"recorded target ref could not be verified: {target_error}; the "
                    "candidate was retained"
                )
            if manifest.get("integration_target_mismatch_head") is not None:
                raise LauncherError(
                    f"run {run_id} now has a clean review-pending candidate, but its "
                    "recorded target advanced during resolution; the target was not "
                    "updated and the candidate was retained"
                )
        finally:
            run_lock_stream.close()

    diagnostic(
        f"run {run_id} has a clean review-pending candidate; after fresh review and "
        "authorization, land it with "
        f"{active_profile().lifecycle_command('integrate', run_id)}"
    )
    return 0


def abort_conflict_run(repository: Repository, run_id: str) -> int:
    if repository.linked_worktree:
        raise LauncherError("abort a managed conflict from the primary checkout")
    initialize_state(repository)
    with file_lock(repo_lock_path(repository)):
        manifest = load_manifest(repository, run_id)
        reconcile_stale_run(repository, manifest)
        state = manifest.get("state")
        pre_landing_manual_candidate = False
        if state == "integration-verification-failed":
            if manifest.get("integration_manual_resolution") is not True:
                raise LauncherError(
                    f"run {run_id} has no manually resolved integration to abort"
                )
            if "integrated_head" in manifest or any(
                field in manifest for field in MANUAL_LANDING_CHECKPOINT_FIELDS
            ):
                raise LauncherError(
                    f"run {run_id} has a recorded landing result or checkpoint; abort was "
                    "refused because its live target may already have changed"
                )
            pre_landing_manual_candidate = True
        if state not in {
            "integration-conflict",
            "integration-continue-pending",
            "integration-review-pending",
            "integration-merge-pending",
            "integration-abort-pending",
            "integration-rebase-pending",
            "integration-rebase-recovery-failed",
        } and not pre_landing_manual_candidate:
            raise LauncherError(f"run {run_id} has no managed integration to abort")
        run_lock_stream = acquire_existing_run_lock(repository, run_id)
        try:
            worktree = Path(manifest["worktree"])
            source_head = recorded_commit(repository, manifest, "integration_source_head")
            audit = audit_run(repository, manifest)
            if state == "integration-rebase-recovery-failed":
                commit, index_tree, metadata_hash = validate_initial_rebase_precommit(
                    repository,
                    manifest,
                    audit,
                    require_checkpoint=False,
                )
                manifest["integration_precommit_commit"] = commit
                manifest["integration_precommit_index_tree"] = index_tree
                manifest["integration_rebase_metadata_hash"] = metadata_hash
                write_manifest(repository, manifest)
                initial_recovery = "precommit"
            else:
                initial_recovery = recover_interrupted_initial_rebase(
                    repository,
                    manifest,
                    audit,
                    allow_precommit_abort=True,
                )
            audit = audit_run(repository, manifest)
            recover_interrupted_continue(repository, manifest, audit)
            state = manifest.get("state")
            audit = audit_run(repository, manifest)
            if initial_recovery in {"resume", "precommit"}:
                manifest["state"] = "integration-abort-pending"
                if initial_recovery == "precommit":
                    manifest["integration_abort_mode"] = "precommit-rebase"
                manifest["integration_abort_started_at"] = utc_now()
                write_manifest(repository, manifest)
                state = "integration-abort-pending"
            if state == "integration-abort-pending" and not rebase_in_progress(
                worktree
            ) and audit_matches_clean_head(
                manifest,
                audit,
                source_head,
            ):
                try:
                    finish_restored_integration(repository, manifest, archive=True)
                except LauncherError as exc:
                    if retain_retryable_restoration_cleanup(
                        repository,
                        manifest,
                        source_head=source_head,
                        pending_state="integration-abort-pending",
                        error=str(exc),
                    ):
                        raise LauncherError(
                            "the worker was exactly restored, but private source-anchor "
                            "cleanup did not complete; retry "
                            f"{active_profile().lifecycle_hint('abort')}"
                        ) from exc
                    failed = audit_run(repository, manifest)
                    record_integration_recovery_failure(
                        repository,
                        manifest,
                        state="integration-abort-recovery-failed",
                        audit=failed,
                        error=f"exact abort cleanup became unprovable: {exc}",
                    )
                    raise LauncherError(
                        "the exact abort cleanup state became unprovable; the worker was "
                        "retained without further changes"
                    ) from exc
                diagnostic(f"run {run_id} was already restored to its exact audited source")
                return 0

            try:
                recorded_integration_source(repository, manifest)
            except LauncherError as exc:
                record_integration_recovery_failure(
                    repository,
                    manifest,
                    state="integration-rebase-recovery-failed",
                    audit=audit,
                    error=f"managed integration abort found source-anchor tamper: {exc}",
                )
                raise LauncherError(
                    "the managed integration's private source anchor changed; abort was "
                    "refused without altering the worker"
                ) from exc

            mode = manifest.get("integration_abort_mode")
            if state in {
                "integration-review-pending",
                "integration-merge-pending",
            } or pre_landing_manual_candidate or mode == "candidate":
                candidate_head = recorded_commit(
                    repository,
                    manifest,
                    "integration_candidate_head",
                )
                if rebase_in_progress(worktree) or not audit_matches_clean_head(
                    manifest,
                    audit,
                    candidate_head,
                ):
                    raise LauncherError(
                        "the review-pending candidate changed; it was retained without reset"
                    )
                mode = "candidate"
            else:
                try:
                    if mode == "precommit-rebase":
                        validate_initial_rebase_precommit(
                            repository,
                            manifest,
                            audit,
                            require_checkpoint=True,
                        )
                    else:
                        validate_managed_rebase_identity(repository, manifest, audit)
                except LauncherError as exc:
                    record_integration_recovery_failure(
                        repository,
                        manifest,
                        state="integration-rebase-recovery-failed",
                        audit=audit,
                        error=f"managed integration abort found rebase tamper: {exc}",
                    )
                    raise LauncherError(
                        "the managed integration's rebase administration changed; abort "
                        "was refused without altering the worker"
                    ) from exc
                mode = "rebase"

            manifest["state"] = "integration-abort-pending"
            manifest["integration_abort_mode"] = mode
            manifest["integration_abort_started_at"] = utc_now()
            write_manifest(repository, manifest)
            if mode in {"rebase", "precommit-rebase"}:
                operation = git(
                    worktree,
                    "-c",
                    "core.hooksPath=/dev/null",
                    "-c",
                    "core.editor=true",
                    "rebase",
                    "--abort",
                    check=False,
                    environment={
                        "GIT_EDITOR": "true",
                        "GIT_SEQUENCE_EDITOR": "true",
                        "EDITOR": "true",
                        "VISUAL": "true",
                    },
                )
            else:
                operation = git(worktree, "reset", "--hard", source_head, check=False)

            restored = audit_run(repository, manifest)
            if (
                rebase_in_progress(worktree)
                or not audit_matches_clean_head(manifest, restored, source_head)
            ):
                error = operation.stderr.strip() or "the worker was not restored exactly"
                try:
                    if mode in {"rebase", "precommit-rebase"}:
                        if mode == "precommit-rebase":
                            validate_initial_rebase_precommit(
                                repository,
                                manifest,
                                restored,
                                require_checkpoint=True,
                            )
                        else:
                            validate_managed_rebase_identity(
                                repository,
                                manifest,
                                restored,
                            )
                    else:
                        candidate_head = recorded_commit(
                            repository,
                            manifest,
                            "integration_candidate_head",
                        )
                        recorded_integration_source(repository, manifest)
                        if rebase_in_progress(worktree) or not audit_matches_clean_head(
                            manifest,
                            restored,
                            candidate_head,
                        ):
                            raise LauncherError(
                                "the candidate no longer matches its recorded clean state"
                            )
                except LauncherError as exc:
                    record_integration_recovery_failure(
                        repository,
                        manifest,
                        state="integration-abort-recovery-failed",
                        audit=restored,
                        error=(
                            f"managed integration abort failed: {error}; the retained "
                            f"state is no longer provable: {exc}"
                        ),
                    )
                    raise LauncherError(
                        "the launcher could not verify an exact abort restoration or the "
                        "unchanged managed state; the worker was retained without further reset"
                    ) from exc
                manifest["integration_recovery_error"] = (
                    f"managed integration abort did not run: {error}"
                )
                write_manifest(repository, manifest)
                raise LauncherError(
                    "the managed abort did not change the still-provable retained state; "
                    "retry "
                    f"{active_profile().lifecycle_hint('abort')}"
                )
            if operation.returncode:
                manifest["last_integration_abort_warning"] = (
                    operation.stderr.strip()
                    or "Git returned a failure status after exact restoration"
                )
            try:
                finish_restored_integration(repository, manifest, archive=True)
            except LauncherError as exc:
                if retain_retryable_restoration_cleanup(
                    repository,
                    manifest,
                    source_head=source_head,
                    pending_state="integration-abort-pending",
                    error=str(exc),
                ):
                    raise LauncherError(
                        "the worker was exactly restored, but private source-anchor cleanup "
                        "did not complete; retry "
                        f"{active_profile().lifecycle_hint('abort')}"
                    ) from exc
                failed = audit_run(repository, manifest)
                record_integration_recovery_failure(
                    repository,
                    manifest,
                    state="integration-abort-recovery-failed",
                    audit=failed,
                    error=f"exact abort cleanup became unprovable: {exc}",
                )
                raise LauncherError(
                    "the exact abort cleanup state became unprovable; the worker was "
                    "retained without further changes"
                ) from exc
        finally:
            run_lock_stream.close()

    diagnostic(f"run {run_id} was restored to its exact audited source")
    return 0


def reopen_run(
    repository: Repository,
    run_id: str,
    arguments: Sequence[str],
    launcher: LauncherIdentity,
) -> int:
    if repository.linked_worktree:
        raise LauncherError("reopen a managed run from the primary checkout")
    initialize_state(repository)
    real_codex = resolve_real_codex(launcher)
    normalize_codex_arguments(arguments)
    with file_lock(repo_lock_path(repository)):
        manifest = load_manifest(repository, run_id)
        if manifest.get("state") in {
            "cleaned",
            "cleaned-branch-retained",
            "cleaned-ref-retained",
        }:
            raise LauncherError(f"run {run_id} has already been cleaned")
        if manifest.get("state") in RETIREMENT_PENDING_STATES:
            raise LauncherError(
                f"run {run_id} has a checkpointed retirement; resume it with "
                f"{active_profile().lifecycle_command('clean', run_id)}"
            )
        if manifest.get("integrated_head") is not None:
            raise LauncherError(
                f"run {run_id} has already advanced its target; retry "
                f"{active_profile().lifecycle_command('clean', run_id)} instead of "
                "reopening it"
            )
        audit = audit_run(repository, manifest)
        if not audit.registered or not audit.locked:
            raise LauncherError(f"run {run_id} is not an intact locked worktree")
        if manifest.get("state") in {
            "integration-conflict",
            "integration-continue-pending",
        }:
            raise LauncherError(
                f"run {run_id} has a managed integration conflict; open its "
                "staging-only resolver with "
                f"{active_profile().lifecycle_command('resolve', run_id)}"
            )
        if audit.branch != manifest["branch"]:
            raise LauncherError(f"run {run_id} changed branches and is quarantined")
        if manifest.get("integration_source_head") is not None:
            raise LauncherError(
                f"run {run_id} has a pending integration transaction; retry "
                f"{active_profile().lifecycle_command('integrate', run_id)}"
            )
        run_lock_stream = acquire_existing_run_lock(repository, run_id)
    return launch_child(repository, manifest, run_lock_stream, real_codex, arguments)


def confirm_cleaned_integration(repository: Repository, manifest: dict) -> int:
    integrated_head = manifest.get("integrated_head")
    if not isinstance(integrated_head, str):
        raise LauncherError("the run was already cleaned and has no retained result to integrate")
    recorded_commit(repository, manifest, "integrated_head")
    target_head, current_ref = require_stable_clean_base(
        repository,
        purpose="confirming retained-run integration",
    )
    target_ref = manifest["target_ref"]
    if current_ref != target_ref:
        target_name = target_ref.removeprefix("refs/heads/")
        raise LauncherError(
            f"the primary checkout must be on the recorded target branch {target_name!r}"
        )
    if not commit_is_ancestor(repository, integrated_head, target_head):
        raise LauncherError(
            "the run was cleaned after integration, but its recorded target no longer "
            "contains the integrated commit"
        )
    require_run_tmp_absent(repository, manifest)
    diagnostic(f"run {manifest['run_id']} was already integrated and cleaned")
    return 0


@dataclass(frozen=True)
class PrimaryCheckoutState:
    head_ref: str | None
    head: str
    index_tree: str
    worktree_matches_index: bool
    untracked: tuple[str, ...]


def commit_tree(repository: Repository, commit: str) -> str:
    result = git(
        repository.root,
        "rev-parse",
        "--verify",
        f"{commit}^{{tree}}",
        check=False,
    )
    value = result.stdout.strip()
    if result.returncode or not OBJECT_ID_RE.fullmatch(value):
        raise LauncherError("cannot inspect a landing commit's tree")
    return value


def primary_checkout_state(repository: Repository) -> PrimaryCheckoutState:
    symbolic = git(
        repository.root,
        "symbolic-ref",
        "--quiet",
        "HEAD",
        check=False,
    )
    if symbolic.returncode == 0:
        head_ref = symbolic.stdout.strip()
    elif symbolic.returncode == 1:
        head_ref = None
    else:
        raise LauncherError("cannot inspect the primary checkout's HEAD reference")
    head_result = git(
        repository.root,
        "rev-parse",
        "--verify",
        "HEAD^{commit}",
        check=False,
    )
    head = head_result.stdout.strip()
    if head_result.returncode or not OBJECT_ID_RE.fullmatch(head):
        raise LauncherError("cannot inspect the primary checkout's HEAD commit")
    index_result = git(repository.root, "write-tree", check=False)
    index_tree = index_result.stdout.strip()
    if index_result.returncode or not OBJECT_ID_RE.fullmatch(index_tree):
        raise LauncherError("the primary checkout index is not an exact tree")
    unstaged = git(
        repository.root,
        "diff-files",
        "--quiet",
        "--",
        check=False,
    )
    if unstaged.returncode not in {0, 1}:
        raise LauncherError("cannot inspect primary worktree changes")
    untracked_result = git(
        repository.root,
        "ls-files",
        "--others",
        "--exclude-standard",
        "-z",
        check=False,
        text=False,
    )
    if untracked_result.returncode:
        raise LauncherError("cannot inspect untracked primary files")
    untracked = tuple(
        sorted(
            (os.fsdecode(value) for value in untracked_result.stdout.split(b"\0") if value),
            key=os.fsencode,
        )
    )
    return PrimaryCheckoutState(
        head_ref=head_ref,
        head=head,
        index_tree=index_tree,
        worktree_matches_index=unstaged.returncode == 0,
        untracked=untracked,
    )


def primary_state_is_clean_at(
    repository: Repository,
    state: PrimaryCheckoutState,
    commit: str,
) -> bool:
    return bool(
        state.head == commit
        and state.index_tree == commit_tree(repository, commit)
        and state.worktree_matches_index
        and not state.untracked
    )


def apply_tree_transition(
    repository: Repository,
    manifest: dict,
    old_commit: str,
    new_commit: str,
    *,
    dry_run: bool,
) -> subprocess.CompletedProcess:
    """Apply an object-to-object patch without moving HEAD or overwriting untracked files."""
    authenticate_retained_worktree(repository, manifest)
    old_tree = commit_tree(repository, old_commit)
    new_tree = commit_tree(repository, new_commit)
    if old_tree == new_tree:
        return subprocess.CompletedProcess(
            args=("git", "apply"),
            returncode=0,
            stdout="",
            stderr="",
        )
    patch = git(
        repository.root,
        "--no-pager",
        "diff",
        "--binary",
        "--full-index",
        "--no-ext-diff",
        "--no-textconv",
        "--no-renames",
        old_commit,
        new_commit,
        "--",
        check=False,
        text=False,
    )
    if patch.returncode or not patch.stdout:
        raise LauncherError("cannot construct the exact primary tree transition")
    arguments = ["apply", "--index", "--binary", "--whitespace=nowarn"]
    if dry_run:
        arguments.append("--check")
    applied = git(
        repository.root,
        *arguments,
        check=False,
        text=False,
        input_data=patch.stdout,
    )
    rendered = subprocess.CompletedProcess(
        args=applied.args,
        returncode=applied.returncode,
        stdout=applied.stdout.decode(errors="replace"),
        stderr=applied.stderr.decode(errors="replace"),
    )
    if dry_run or rendered.returncode:
        return rendered
    index = git(repository.root, "write-tree", check=False)
    unstaged = git(repository.root, "diff-files", "--quiet", "--", check=False)
    if index.returncode or index.stdout.strip() != new_tree or unstaged.returncode != 0:
        raise LauncherError(
            "the primary tree transition did not produce the exact candidate tree"
        )
    return rendered


def prepare_primary_for_target_cas(
    repository: Repository,
    manifest: dict,
    target_ref: str,
    expected_target: str,
    candidate: str,
) -> None:
    """Prove a clean checkout and dry-run any target worktree transition."""
    state = primary_checkout_state(repository)
    if state.head_ref == target_ref:
        if not primary_state_is_clean_at(repository, state, expected_target):
            raise LauncherError(
                "the recorded target checkout changed before its exact landing transaction"
            )
        dry_run = apply_tree_transition(
            repository,
            manifest,
            expected_target,
            candidate,
            dry_run=True,
        )
        if dry_run.returncode:
            raise LauncherError(
                "the exact landing would overwrite or conflict with primary checkout state: "
                f"{dry_run.stderr.strip() or 'Git reported no diagnostic'}"
            )
        return
    if not primary_state_is_clean_at(repository, state, state.head):
        raise LauncherError(
            "the primary checkout changed while another branch won the landing race"
        )


def synchronize_primary_after_target_cas(
    repository: Repository,
    manifest: dict,
    target_ref: str,
    source_commits: Sequence[str],
    landed_target: str,
) -> None:
    """Synchronize files/index without ever updating HEAD or an unrelated ref."""
    landed_tree = commit_tree(repository, landed_target)
    source_by_tree = {
        commit_tree(repository, source): source for source in source_commits
    }
    for _ in range(4):
        target = direct_ref_commit(repository, target_ref)
        if target != landed_target:
            raise LauncherError(
                "the recorded target changed after the exact landing transaction"
            )
        state = primary_checkout_state(repository)
        if state.head_ref == target_ref:
            if (
                state.index_tree == landed_tree
                and state.worktree_matches_index
                and not state.untracked
            ):
                return
            source = source_by_tree.get(state.index_tree)
            if source is None or not state.worktree_matches_index or state.untracked:
                raise LauncherError(
                    "the primary target checkout changed during exact landing synchronization"
                )
            transition = apply_tree_transition(
                repository,
                manifest,
                source,
                landed_target,
                dry_run=False,
            )
            if transition.returncode:
                raise LauncherError(
                    "the target ref landed, but its primary files and index could not be "
                    "synchronized safely: "
                    f"{transition.stderr.strip() or 'Git reported no diagnostic'}"
                )
            continue

        if primary_state_is_clean_at(repository, state, state.head):
            return
        source = source_by_tree.get(state.index_tree)
        if source is not None and state.worktree_matches_index and not state.untracked:
            dry_run = apply_tree_transition(
                repository,
                manifest,
                source,
                state.head,
                dry_run=True,
            )
            if dry_run.returncode:
                raise LauncherError(
                    "the primary checkout changed branches during landing and could not "
                    "be restored without overwriting files"
                )
            restored = apply_tree_transition(
                repository,
                manifest,
                source,
                state.head,
                dry_run=False,
            )
            if restored.returncode:
                raise LauncherError(
                    "the primary checkout changed branches during landing and its files "
                    "could not be restored safely"
                )
            continue
        raise LauncherError(
            "the primary checkout changed during exact landing synchronization"
        )
    raise LauncherError(
        "the primary checkout changed repeatedly during exact landing synchronization"
    )


def land_candidate_with_cas(
    repository: Repository,
    manifest: dict,
    *,
    expected_target: str,
    candidate: str,
    manual_candidate: bool,
) -> None:
    """Durably CAS the recorded target and make primary checkout state coherent."""
    target_ref = manifest["target_ref"]
    manifest["integration_landing_expected_head"] = expected_target
    manifest["integration_landing_candidate_head"] = candidate
    manifest.setdefault("integration_landing_started_at", utc_now())
    manifest["state"] = (
        "integration-manual-landing-pending"
        if manual_candidate
        else "integration-merge-pending"
    )
    write_manifest(repository, manifest)

    observed = direct_ref_commit(repository, target_ref)
    if observed == expected_target:
        authenticate_retained_worktree(repository, manifest)
        prepare_primary_for_target_cas(
            repository,
            manifest,
            target_ref,
            expected_target,
            candidate,
        )
        authenticate_retained_worktree(repository, manifest)
        transaction = git(
            repository.root,
            "update-ref",
            "--no-deref",
            target_ref,
            candidate,
            expected_target,
            check=False,
        )
        observed = direct_ref_commit(repository, target_ref)
        transaction_reached_candidate = bool(
            observed == candidate
            or (
                not manual_candidate
                and observed is not None
                and commit_is_ancestor(repository, candidate, observed)
            )
        )
        if transaction.returncode and not transaction_reached_candidate:
            if manual_candidate:
                manifest["state"] = "integration-verification-failed"
                if observed is not None:
                    record_target_mismatch(manifest, observed)
            manifest["integration_verification_error"] = (
                transaction.stderr.strip()
                or "the expected-old target transaction was refused"
            )
            write_manifest(repository, manifest)
            raise LauncherError(
                "the recorded target changed before the expected-old landing transaction; "
                "the candidate and any source anchor were retained"
            )
    target_contains_candidate = bool(
        observed == candidate
        or (
            not manual_candidate
            and observed is not None
            and commit_is_ancestor(repository, candidate, observed)
        )
    )
    if not target_contains_candidate:
        if observed is not None:
            record_target_mismatch(manifest, observed)
        if manual_candidate:
            manifest["state"] = "integration-verification-failed"
        manifest["integration_verification_error"] = (
            "the live target is neither the expected old commit nor the exact candidate"
        )
        write_manifest(repository, manifest)
        raise LauncherError(
            "the recorded target is not eligible for exact candidate landing; the worker "
            "and any source anchor were retained"
        )

    if observed is None:
        raise LauncherError("the recorded target is unavailable after exact landing")
    landed_target = observed
    manifest["state"] = "integration-verification-pending"
    manifest["integrated_head"] = candidate
    manifest.setdefault("integrated_at", utc_now())
    write_manifest(repository, manifest)
    try:
        synchronize_primary_after_target_cas(
            repository,
            manifest,
            target_ref,
            (expected_target, candidate),
            landed_target,
        )
    except LauncherError as exc:
        manifest["state"] = "integration-verification-failed"
        manifest["integration_verification_error"] = str(exc)
        write_manifest(repository, manifest)
        raise LauncherError(
            "the exact target ref landed, but primary checkout synchronization was not "
            f"completed: {exc}; retry the same integration after preserving any external work"
        ) from exc
    final_target = direct_ref_commit(repository, target_ref)
    exact_manual_target = manual_candidate and final_target == candidate
    containing_ordinary_target = bool(
        not manual_candidate
        and final_target is not None
        and commit_is_ancestor(repository, candidate, final_target)
    )
    if not (exact_manual_target or containing_ordinary_target):
        if manual_candidate and final_target is not None:
            record_target_mismatch(manifest, final_target)
        manifest["state"] = "integration-verification-failed"
        manifest["integration_verification_error"] = (
            "the target changed after exact landing synchronization"
        )
        write_manifest(repository, manifest)
        raise LauncherError(
            "the target changed after exact landing; the worker was retained and no ref "
            "was reset"
        )
    manifest["state"] = "integrated-pending-cleanup"
    manifest["integrated_head"] = candidate
    manifest.pop("integration_verification_error", None)
    write_manifest(repository, manifest)


def integrate_run(repository: Repository, run_id: str) -> int:
    if repository.linked_worktree:
        raise LauncherError("integrate managed runs from the primary checkout")
    initialize_state(repository)
    with file_lock(repo_lock_path(repository)):
        manifest = load_manifest(repository, run_id)
        reconcile_stale_run(repository, manifest)
        if manifest.get("state") in RETIREMENT_PENDING_STATES:
            raise LauncherError(
                f"run {run_id} has a checkpointed retirement; resume it with "
                f"{active_profile().lifecycle_command('clean', run_id)}"
            )
        if manifest.get("state") == "cleaned":
            return confirm_cleaned_integration(repository, manifest)
        if manifest.get("state") in {"cleaned-branch-retained", "cleaned-ref-retained"}:
            diagnostic(
                f"run {run_id} worktree was removed, but a private lifecycle ref remains; "
                f"retry {active_profile().lifecycle_command('clean', run_id)}"
            )
            return 1

        target_ref = manifest["target_ref"]
        run_lock_stream = acquire_existing_run_lock(repository, run_id)
        try:
            audit = audit_run(repository, manifest)
            if not audit.registered or not audit.locked:
                raise LauncherError("the retained worktree is missing or unlocked")

            if (
                manifest.get("state")
                in {
                    "integration-merge-pending",
                    "integration-manual-landing-pending",
                    "integration-verification-pending",
                    "integration-verification-failed",
                }
                and manifest.get("integration_landing_expected_head") is not None
                and manifest.get("integration_landing_candidate_head") is not None
            ):
                expected_landing = recorded_commit(
                    repository,
                    manifest,
                    "integration_landing_expected_head",
                )
                pending_candidate = recorded_commit(
                    repository,
                    manifest,
                    "integration_landing_candidate_head",
                )
                if not audit_matches_clean_head(
                    manifest,
                    audit,
                    pending_candidate,
                ):
                    raise LauncherError(
                        "the checkpointed landing candidate changed; it was retained without "
                        "target or primary mutation"
                    )
                manual_pending = manifest.get("integration_manual_resolution") is True
                if manifest.get("integration_source_head") is not None:
                    recorded_integration_source(repository, manifest)
                land_candidate_with_cas(
                    repository,
                    manifest,
                    expected_target=expected_landing,
                    candidate=pending_candidate,
                    manual_candidate=manual_pending,
                )
                recovered_target = direct_ref_commit(repository, target_ref)
                try:
                    branch_removed = safe_cleanup(
                        repository,
                        manifest,
                        allow_integrated=True,
                        expected_head=pending_candidate,
                    )
                except LauncherError as exc:
                    manifest["state"] = "integration-cleanup-failed"
                    manifest["integration_cleanup_error"] = str(exc)
                    write_manifest(repository, manifest)
                    raise LauncherError(
                        f"the retained result is integrated, but cleanup failed: {exc}; "
                        f"retry {active_profile().lifecycle_command('clean', run_id)}"
                    ) from exc
                if not branch_removed:
                    diagnostic(
                        f"run {run_id} was integrated and its worktree removed, but its "
                        "worker branch remains"
                    )
                    return 1
                recovery_description = (
                    "its exact landing"
                    if recovered_target == pending_candidate
                    else "a target descendant containing its landing"
                )
                diagnostic(
                    f"run {run_id} recovered {recovery_description} and was cleaned"
                )
                return 0

            target_head, current_ref = require_stable_clean_base(
                repository,
                purpose="integrating a retained run",
            )
            if current_ref != target_ref:
                target_name = target_ref.removeprefix("refs/heads/")
                raise LauncherError(
                    f"the primary checkout must be on the recorded target branch {target_name!r}"
                )

            resume_initial_rebase = False
            transaction_state = manifest.get("state")
            if transaction_state == "integration-continue-pending":
                recover_interrupted_continue(repository, manifest, audit)
                transaction_state = manifest.get("state")
                audit = audit_run(repository, manifest)
            if transaction_state in {
                "integration-conflict",
                "integration-continue-pending",
            }:
                try:
                    paths = validate_managed_conflict(repository, manifest, audit)
                except ManagedConflictScopeError as exc:
                    raise LauncherError(
                        "the managed conflict has a correctable resolver staging-scope "
                        f"violation: {exc}"
                    ) from exc
                except LauncherError as exc:
                    record_integration_recovery_failure(
                        repository,
                        manifest,
                        state="integration-rebase-recovery-failed",
                        audit=audit,
                        error=f"the recorded managed conflict was altered: {exc}",
                    )
                    raise LauncherError(
                        "the recorded managed conflict was altered; its unverified state "
                        "was retained without abort or reset"
                    ) from exc
                raise LauncherError(
                    f"run {run_id} has a managed conflict in {len(paths)} unresolved "
                    f"path(s); use {active_profile().lifecycle_hint('resolve')}, "
                    f"{active_profile().lifecycle_hint('continue')}, or "
                    f"{active_profile().lifecycle_hint('abort')} with this run ID"
                )
            if transaction_state == "integration-abort-pending":
                raise LauncherError(
                    f"run {run_id} has an interrupted managed abort; retry "
                    f"{active_profile().lifecycle_command('abort', run_id)}"
                )
            if transaction_state in {
                "integration-rebase-pending",
                "integration-rebase-rollback-pending",
                "integration-rebase-recovery-failed",
                "integration-rebase-rollback-failed",
            }:
                if transaction_state == "integration-rebase-pending":
                    outcome = recover_interrupted_initial_rebase(
                        repository,
                        manifest,
                        audit,
                    )
                    transaction_state = manifest.get("state")
                    audit = audit_run(repository, manifest)
                    if outcome == "conflict":
                        paths = unmerged_paths(Path(manifest["worktree"]))
                        raise LauncherError(
                            f"an interrupted integration rebase was adopted as a managed "
                            f"conflict in {len(paths)} path(s); use "
                            f"{active_profile().lifecycle_hint('resolve')}, "
                            f"{active_profile().lifecycle_hint('continue')}, or "
                            f"{active_profile().lifecycle_hint('abort')}"
                        )
                    resume_initial_rebase = outcome == "resume"
                else:
                    source_head = recorded_commit(
                        repository,
                        manifest,
                        "integration_source_head",
                    )
                    if audit_matches_clean_head(manifest, audit, source_head):
                        try:
                            finish_restored_integration(
                                repository,
                                manifest,
                                archive=False,
                            )
                        except LauncherError as exc:
                            raise LauncherError(
                                "the worker was restored, but its private source anchor "
                                "could not be cleaned"
                            ) from exc
                    elif transaction_state == "integration-rebase-rollback-pending":
                        recorded_integration_source(repository, manifest)
                        rollback_completed_integration_rebase(
                            repository,
                            manifest,
                            source_head,
                            "an earlier integration rebase rollback was interrupted",
                        )
                    else:
                        raise LauncherError(
                            "an earlier integration rebase could not be restored; inspect the "
                            "retained worker before retrying"
                        )
                    audit = audit_run(repository, manifest)

            if audit.branch != manifest["branch"]:
                raise LauncherError("the retained worktree changed branches")
            if not audit.clean or audit.head is None:
                raise LauncherError("the retained worktree has uncommitted changes")
            final_head = recorded_clean_final_head(repository, manifest)
            candidate_head = recorded_integration_candidate(
                repository,
                manifest,
                final_head,
            )
            if audit.head != candidate_head:
                raise LauncherError(
                    "the retained result changed since its last launcher audit; "
                    "reopen it to review and record its current state"
                )
            if manifest.get("integration_source_head") is not None:
                recorded_integration_source(repository, manifest)

            base_sha = recorded_commit(repository, manifest, "base_sha")
            if not commit_is_ancestor(repository, base_sha, candidate_head):
                raise LauncherError("the retained result no longer descends from its recorded base")
            if not commit_is_ancestor(repository, base_sha, target_head):
                raise LauncherError("the recorded target branch no longer descends from the run's base")

            manual_candidate = manifest.get("integration_manual_resolution") is True
            if manual_candidate:
                recorded_integration_source(repository, manifest)
                attempted_target = recorded_commit(
                    repository,
                    manifest,
                    "integration_target_head",
                )
                if not commit_is_ancestor(repository, attempted_target, candidate_head):
                    raise LauncherError(
                        "the review-pending candidate does not descend from its captured target"
                    )
                if manifest.get("integrated_head") is not None:
                    if recorded_commit(
                        repository,
                        manifest,
                        "integrated_head",
                    ) != candidate_head:
                        raise LauncherError(
                            "the manually resolved integration has inconsistent candidate "
                            "and landing records"
                        )
                if target_head == candidate_head:
                    already_integrated = True
                    manifest["state"] = "integration-verification-pending"
                    manifest["integrated_head"] = candidate_head
                    manifest.setdefault("integrated_at", utc_now())
                    manifest.pop("integration_target_mismatch_head", None)
                    manifest.pop("integration_target_mismatch_at", None)
                    manifest.pop("integration_verification_error", None)
                    write_manifest(repository, manifest)
                elif target_head == attempted_target and manifest.get("integrated_head") is None:
                    already_integrated = False
                    manifest.pop("integration_target_mismatch_head", None)
                    manifest.pop("integration_target_mismatch_at", None)
                else:
                    record_target_mismatch(manifest, target_head)
                    manifest["state"] = "integration-verification-failed"
                    manifest["integration_verification_error"] = (
                        "the live target is neither the captured target nor the exact "
                        "manually resolved candidate"
                    )
                    write_manifest(repository, manifest)
                    raise LauncherError(
                        "the target is not the exact manually resolved candidate; the "
                        "retained worker and private source anchor were not cleaned"
                    )
            else:
                already_integrated = commit_is_ancestor(
                    repository,
                    candidate_head,
                    target_head,
                )
            if not already_integrated and manifest.get("integrated_head") is not None:
                raise LauncherError(
                    "the recorded target no longer contains this run's previously integrated "
                    "commit; restore or reconcile the target history before retrying cleanup"
                )
            integrated_now = False
            if not already_integrated:
                if worker_history_has_merge(repository, candidate_head, target_head):
                    raise LauncherError(
                        "the retained result contains a worker-side merge commit; "
                        "make integrate requires a linear audited worker history so "
                        "flattening cannot discard merge-only content"
                    )
                if not commit_is_ancestor(repository, target_head, candidate_head):
                    if manifest.get("integration_candidate_head") is not None:
                        source_head = recorded_integration_source(repository, manifest)
                        rollback_completed_integration_rebase(
                            repository,
                            manifest,
                            source_head,
                            "the target advanced again before the rebased result was integrated",
                        )
                        audit = audit_run(repository, manifest)
                        final_head = recorded_clean_final_head(repository, manifest)
                        candidate_head = final_head
                        if not audit_matches_clean_head(manifest, audit, candidate_head):
                            raise LauncherError(
                                "the retained result changed while restarting integration"
                            )

                    if resume_initial_rebase:
                        source_head = recorded_integration_source(repository, manifest)
                        pinned_target = recorded_commit(
                            repository,
                            manifest,
                            "integration_target_head",
                        )
                        if target_head != pinned_target or candidate_head != source_head:
                            raise LauncherError(
                                "the target or worker changed before an interrupted rebase "
                                "could be resumed"
                            )
                    else:
                        source_head = candidate_head
                        previous_state = manifest.get("state")
                        manifest["state"] = "integration-rebase-pending"
                        manifest["integration_previous_state"] = (
                            previous_state if isinstance(previous_state, str) else "preserved"
                        )
                        manifest["integration_source_head"] = source_head
                        manifest["integration_target_head"] = target_head
                        manifest["integration_started_at"] = utc_now()
                        manifest.pop("integration_candidate_head", None)
                        manifest.pop("integration_recovery_error", None)
                        write_manifest(repository, manifest)
                        ensure_integration_source_anchor(
                            repository,
                            manifest,
                            source_head,
                        )
                        manifest["integration_source_anchor_created"] = True
                        write_manifest(repository, manifest)

                    rebase = git(
                        Path(manifest["worktree"]),
                        "-c",
                        "rebase.autoStash=false",
                        "-c",
                        "rebase.backend=merge",
                        "-c",
                        "rebase.updateRefs=false",
                        "-c",
                        "rerere.enabled=false",
                        "-c",
                        "rerere.autoupdate=false",
                        "-c",
                        "core.hooksPath=/dev/null",
                        "rebase",
                        "--no-autostash",
                        "--no-update-refs",
                        "--no-rebase-merges",
                        "--no-fork-point",
                        "--reapply-cherry-picks",
                        "--empty=drop",
                        "--onto",
                        target_head,
                        base_sha,
                        check=False,
                    )
                    if rebase.returncode:
                        rebase_error = rebase.stderr.strip() or "Git reported no diagnostic"
                        conflicted_audit = audit_run(repository, manifest)
                        if rebase_in_progress(Path(manifest["worktree"])):
                            try:
                                paths = record_managed_conflict(
                                    repository,
                                    manifest,
                                    conflicted_audit,
                                    rebase_error,
                                )
                            except LauncherError as exc:
                                record_integration_recovery_failure(
                                    repository,
                                    manifest,
                                    state="integration-rebase-recovery-failed",
                                    audit=conflicted_audit,
                                    error=f"integration rebase stopped in an unknown state: {exc}",
                                )
                                raise LauncherError(
                                    "integration rebase stopped in an unverified active "
                                    "state; the worker was retained without abort or reset"
                                ) from exc
                            raise LauncherError(
                                f"integration rebase stopped at a managed conflict in "
                                f"{len(paths)} path(s); stage a source-aware resolution with "
                                f"{active_profile().lifecycle_command('resolve', run_id)}, "
                                f"then use "
                                f"{active_profile().lifecycle_command('continue', run_id)} "
                                f"or {active_profile().lifecycle_command('abort', run_id)}"
                            )
                        abort_failed_integration_rebase(
                            repository,
                            manifest,
                            source_head,
                            rebase_error,
                        )
                        try:
                            restored_target, restored_ref = require_stable_clean_base(
                                repository,
                                purpose="finishing a failed retained-run rebase",
                            )
                        except LauncherError as exc:
                            raise LauncherError(
                                "rebase integration failed and the worker was restored, but "
                                f"the primary checkout also changed: {exc}"
                            ) from exc
                        if restored_target != target_head or restored_ref != target_ref:
                            raise LauncherError(
                                "rebase integration failed and the worker was restored, but "
                                "the recorded target changed during the attempt"
                            )
                        raise LauncherError(
                            "rebase integration failed; the attempted rebase was aborted and "
                            "the retained result was restored; inspect the private run record "
                            "for Git's diagnostic"
                        )

                    rebased_audit = audit_run(repository, manifest)
                    if (
                        rebased_audit.branch != manifest["branch"]
                        or rebased_audit.head is None
                        or not commit_is_ancestor(
                            repository,
                            target_head,
                            rebased_audit.head,
                        )
                    ):
                        record_integration_recovery_failure(
                            repository,
                            manifest,
                            state="integration-rebase-recovery-failed",
                            audit=rebased_audit,
                            error="Git reported a successful rebase with an unexpected worker state",
                        )
                        raise LauncherError(
                            "Git reported a successful integration rebase, but the retained "
                            "worker did not have the expected rebased history"
                        )

                    candidate_head = rebased_audit.head
                    manifest["state"] = "integration-merge-pending"
                    manifest["integration_candidate_head"] = candidate_head
                    manifest["integration_rebased_at"] = utc_now()
                    write_manifest(repository, manifest)
                    if not rebased_audit.clean:
                        raise LauncherError(
                            "the integration rebase completed with unexpected uncommitted "
                            "worker changes; it was retained without merging or cleanup"
                        )

                    try:
                        current_target, current_ref = require_stable_clean_base(
                            repository,
                            purpose="merging a rebased retained run",
                        )
                    except LauncherError as exc:
                        landed_target = target_head_containing_commit(
                            repository,
                            target_ref,
                            candidate_head,
                        )
                        if landed_target is not None:
                            manifest["state"] = "integration-verification-failed"
                            manifest["integrated_at"] = utc_now()
                            manifest["integrated_head"] = candidate_head
                            manifest["integration_verification_error"] = str(exc)
                            write_manifest(repository, manifest)
                            raise LauncherError(
                                "the target advanced to the rebased result while the primary "
                                "checkout also became unavailable for verification; it was not "
                                "rolled back and the run was not cleaned"
                            ) from exc
                        rollback_completed_integration_rebase(
                            repository,
                            manifest,
                            source_head,
                            f"the primary checkout changed during the integration rebase: {exc}",
                        )
                        raise LauncherError(
                            "the primary checkout changed during the integration rebase; "
                            "the retained worker was restored and was not merged"
                        ) from exc
                    if current_target != target_head or current_ref != target_ref:
                        landed_target = target_head_containing_commit(
                            repository,
                            target_ref,
                            candidate_head,
                        )
                        if landed_target is None:
                            rollback_completed_integration_rebase(
                                repository,
                                manifest,
                                source_head,
                                "the recorded target changed during the integration rebase",
                            )
                            raise LauncherError(
                                "the recorded target changed during the integration rebase; "
                                "the retained worker was restored and was not merged"
                            )
                        if current_ref != target_ref:
                            manifest["state"] = "integration-verification-failed"
                            manifest["integrated_at"] = utc_now()
                            manifest["integrated_head"] = candidate_head
                            manifest["integration_verification_error"] = (
                                "the primary checkout changed branches during the "
                                "integration rebase"
                            )
                            write_manifest(repository, manifest)
                            raise LauncherError(
                                "the recorded target advanced to the rebased result, but the "
                                "primary checkout changed branches; it was not rolled back and "
                                "the run was not cleaned"
                            )

                if manual_candidate:
                    try:
                        premerge_target = require_recorded_target_checkout(
                            repository,
                            manifest,
                            purpose="landing a manually resolved retained run",
                        )
                    except LauncherError as exc:
                        manifest["integration_target_verification_error"] = str(exc)
                        write_manifest(repository, manifest)
                        raise LauncherError(
                            "the primary checkout changed before manual-candidate landing; "
                            "the exact candidate was retained without merge or cleanup"
                        ) from exc
                    if premerge_target != attempted_target:
                        record_target_mismatch(manifest, premerge_target)
                        manifest["state"] = "integration-verification-failed"
                        manifest["integration_verification_error"] = (
                            "the live target no longer equals the captured manual target"
                        )
                        write_manifest(repository, manifest)
                        raise LauncherError(
                            "the recorded target advanced before manual-candidate landing; "
                            "the exact candidate was retained without reset, rebase, merge, "
                            "or cleanup"
                        )
                    manifest["state"] = "integration-manual-landing-pending"
                    manifest["integration_manual_landing_started_at"] = utc_now()
                    manifest.pop("integration_verification_error", None)
                    write_manifest(repository, manifest)

                if manifest.get("integration_source_head") is not None:
                    try:
                        recorded_integration_source(repository, manifest)
                    except LauncherError as exc:
                        anchor_audit = audit_run(repository, manifest)
                        record_integration_recovery_failure(
                            repository,
                            manifest,
                            state="integration-rebase-recovery-failed",
                            audit=anchor_audit,
                            error=f"private source-anchor verification before landing failed: {exc}",
                        )
                        raise LauncherError(
                            "the retained integration's private source anchor changed before "
                            "target mutation; the target was not updated"
                        ) from exc

                expected_landing = attempted_target if manual_candidate else target_head
                try:
                    land_candidate_with_cas(
                        repository,
                        manifest,
                        expected_target=expected_landing,
                        candidate=candidate_head,
                        manual_candidate=manual_candidate,
                    )
                except LauncherError as exc:
                    if manual_candidate:
                        raise
                    landed_target = target_head_containing_commit(
                        repository,
                        target_ref,
                        candidate_head,
                    )
                    if landed_target is not None:
                        raise LauncherError(
                            "the target advanced to the retained result, but exact landing "
                            f"verification failed: {exc}; it was not rolled back and the run "
                            "was not cleaned"
                        ) from exc
                    if manifest.get("integration_candidate_head") is not None:
                        source_head = recorded_integration_source(repository, manifest)
                        rollback_completed_integration_rebase(
                            repository,
                            manifest,
                            source_head,
                            f"fast-forward integration failed: {exc}",
                        )
                        raise LauncherError(
                            "fast-forward integration failed after rebase; the retained "
                            f"worker was restored and not cleaned: {exc}"
                        ) from exc
                    raise LauncherError(
                        f"fast-forward integration failed; the retained run was not cleaned: {exc}"
                    ) from exc
                integrated_now = True

            try:
                final_target_head = direct_ref_commit(repository, target_ref)
                if final_target_head is None:
                    raise LauncherError("the recorded target ref is unavailable after landing")
                if manual_candidate and final_target_head != candidate_head:
                    record_target_mismatch(manifest, final_target_head)
                    manifest["state"] = "integration-verification-failed"
                    manifest["integration_verification_error"] = (
                        "the target did not stop at the exact manually resolved candidate"
                    )
                    write_manifest(repository, manifest)
                    raise LauncherError(
                        "the target changed while landing the manually resolved candidate"
                    )
                if not commit_is_ancestor(repository, candidate_head, final_target_head):
                    raise LauncherError(
                        "the retained result is not reachable from its recorded target"
                    )
            except LauncherError as exc:
                if not integrated_now:
                    raise
                if manual_candidate:
                    manifest["state"] = "integration-verification-failed"
                    observed_target = direct_ref_commit(repository, target_ref)
                    if observed_target is not None and (
                        observed_target != candidate_head
                    ):
                        record_target_mismatch(manifest, observed_target)
                else:
                    manifest["state"] = "integration-verification-failed"
                manifest["integration_verification_error"] = str(exc)
                write_manifest(repository, manifest)
                raise LauncherError(
                    f"the target advanced to the retained result, but post-integration "
                    f"verification failed: {exc}; it was not rolled back and the run was "
                    "not cleaned"
                ) from exc

            manifest["state"] = "integrated-pending-cleanup"
            manifest["integrated_head"] = candidate_head
            if not integrated_now:
                manifest["integration_confirmed_at"] = utc_now()
            manifest.pop("integration_previous_state", None)
            manifest.pop("integration_verification_error", None)
            manifest.pop("integration_cleanup_error", None)
            write_manifest(repository, manifest)
            try:
                branch_removed = safe_cleanup(
                    repository,
                    manifest,
                    allow_integrated=True,
                    expected_head=candidate_head,
                )
            except LauncherError as exc:
                manifest["state"] = "integration-cleanup-failed"
                manifest["integration_cleanup_error"] = str(exc)
                write_manifest(repository, manifest)
                raise LauncherError(
                    f"the retained result is integrated, but cleanup failed: {exc}; "
                    f"retry {active_profile().lifecycle_command('clean', run_id)}"
                ) from exc
        finally:
            run_lock_stream.close()

    if not branch_removed:
        diagnostic(
            f"run {run_id} was integrated and its worktree removed, but its worker branch "
            f"remains; retry {active_profile().lifecycle_command('clean', run_id)}"
        )
        return 1
    diagnostic(f"run {run_id} was integrated and cleaned")
    return 0


def show_final_diff(repository: Repository, run_id: str) -> int:
    if repository.linked_worktree:
        raise LauncherError("review managed-run final diffs from the primary checkout")
    initialize_state(repository)
    with file_lock(repo_lock_path(repository)):
        manifest = load_manifest(repository, run_id)
        if manifest.get("integration_manual_resolution") is not True:
            raise LauncherError(f"run {run_id} has no manually resolved final candidate")
        run_lock_stream = acquire_existing_run_lock(repository, run_id)
        try:
            target_head = recorded_commit(
                repository,
                manifest,
                "integration_target_head",
            )
            candidate_head = recorded_commit(
                repository,
                manifest,
                "integration_candidate_head",
            )
            recorded_integration_source(repository, manifest)
            audit = audit_run(repository, manifest)
            if (
                rebase_in_progress(Path(manifest["worktree"]))
                or not audit_matches_clean_head(manifest, audit, candidate_head)
                or not commit_is_ancestor(repository, target_head, candidate_head)
            ):
                raise LauncherError(
                    "the retained run has no clean exact candidate available for final-diff review"
                )
            diff = git(
                repository.root,
                "--no-pager",
                "diff",
                "--no-color",
                "--no-ext-diff",
                "--no-textconv",
                "--binary",
                "--find-renames",
                target_head,
                candidate_head,
                "--",
                check=False,
                text=False,
            )
            if diff.returncode:
                raise LauncherError("cannot render the retained candidate's final diff")
            rendered = diff.stdout
        finally:
            run_lock_stream.close()
    sys.stdout.buffer.write(rendered)
    return 0


def checkpoint_rewritten_quarantine_retirement(
    repository: Repository,
    manifest: dict,
    discard_head: str,
    target_contains: str,
) -> None:
    if manifest.get("state") != "quarantined":
        raise LauncherError("only an exact rewritten quarantine may be retired")
    validate_exact_run_tmpdir(repository, manifest)
    if any(field in manifest for field in RETIREMENT_FIELDS):
        raise LauncherError("the quarantine has invalid uncheckpointed retirement data")
    reject_conflicting_retirement_lifecycle(manifest)
    validate_retirement_recorded_history(
        repository,
        manifest,
        discard_head,
        target_contains,
    )

    worktree = Path(manifest["worktree"])
    audit = audit_run(repository, manifest)
    if not audit_matches_clean_head(manifest, audit, discard_head):
        raise LauncherError(
            "the rewritten quarantine is not a registered, locked, clean, exact worker"
        )
    if rebase_in_progress(worktree):
        raise LauncherError("the rewritten quarantine has an active rebase")
    branch_ref = f"refs/heads/{manifest['branch']}"
    if direct_ref_commit(repository, branch_ref) != discard_head:
        raise LauncherError("the rewritten quarantine's direct worker branch changed")
    if private_run_refs(repository, manifest):
        raise LauncherError("the rewritten quarantine has a conflicting private ref")
    initial_target = target_containing_retirement_checkpoint(
        repository,
        manifest,
        target_contains,
    )

    manifest["state"] = "retirement-pending"
    manifest["retirement_discard_head"] = discard_head
    manifest["retirement_target_contains"] = target_contains
    manifest["retirement_initial_target_head"] = initial_target
    manifest["retirement_started_at"] = utc_now()
    write_manifest(repository, manifest)
    ensure_retirement_anchor(repository, manifest, discard_head)


def relock_retirement_worktree(repository: Repository, manifest: dict) -> None:
    worktree = Path(manifest["worktree"])
    authenticate_retained_worktree(repository, manifest)
    relock = git(
        repository.root,
        "worktree",
        "lock",
        "--reason",
        f"{active_profile().lock_reason_prefix}{manifest['run_id']}",
        str(worktree),
        check=False,
    )
    audit = audit_run(repository, manifest)
    if relock.returncode or not audit.registered or not audit.locked:
        raise LauncherError("the checkpointed retirement worktree could not be relocked")


def refresh_retirement_cleanup_target(
    repository: Repository,
    manifest: dict,
) -> str:
    _, target_contains, _ = retirement_parameters(manifest)
    target_head = target_containing_retirement_checkpoint(
        repository,
        manifest,
        target_contains,
    )
    manifest["retirement_cleanup_target_head"] = target_head
    manifest.setdefault("retirement_ref_cleanup_started_at", utc_now())
    write_manifest(repository, manifest)
    return target_head


def mark_retirement_worktree_removed(
    repository: Repository,
    manifest: dict,
) -> None:
    refresh_retirement_cleanup_target(repository, manifest)
    manifest["state"] = "retirement-ref-cleanup-pending"
    manifest.setdefault("retirement_worktree_removed_at", utc_now())
    manifest["retirement_cleanup_warning"] = (
        "transactional worker-branch, retirement-anchor, and receipt cleanup pending"
    )
    write_manifest(repository, manifest)


def remove_checkpointed_retirement_worktree(
    repository: Repository,
    manifest: dict,
) -> None:
    worktree = Path(manifest["worktree"])
    validate_retirement_worktree(repository, manifest, require_locked=True)
    authenticate_retained_worktree(repository, manifest)
    refresh_retirement_cleanup_target(repository, manifest)
    unlock = git(
        repository.root,
        "worktree",
        "unlock",
        str(worktree),
        check=False,
    )
    if unlock.returncode:
        audit = audit_run(repository, manifest)
        if audit.registered and not audit.locked:
            relock_retirement_worktree(repository, manifest)
        raise LauncherError("the retirement worktree could not be safely unlocked")

    try:
        authenticate_retained_worktree(repository, manifest)
        validate_retirement_worktree(repository, manifest, require_locked=False)
        refresh_retirement_cleanup_target(repository, manifest)
    except LauncherError:
        try:
            relock_retirement_worktree(repository, manifest)
        except LauncherError:
            pass
        raise

    removal = git(
        repository.root,
        "worktree",
        "remove",
        str(worktree),
        check=False,
    )
    registered = registered_record(repository, worktree)
    exists = path_entry_exists(worktree, label="the retirement worktree path")
    if removal.returncode or registered is not None or exists:
        if registered is not None and exists:
            try:
                relock_retirement_worktree(repository, manifest)
            except LauncherError:
                pass
        if (registered is None) != (not exists):
            raise LauncherError(
                "retirement worktree removal left an inconsistent managed path"
            )
        raise LauncherError("authenticated retirement worktree removal failed")
    mark_retirement_worktree_removed(repository, manifest)


def retirement_ref_tuple(
    repository: Repository,
    manifest: dict,
) -> tuple[str | None, str | None, str | None]:
    anchor, receipt = retirement_private_ref_pair(repository, manifest)
    branch_ref = f"refs/heads/{manifest['branch']}"
    branch = direct_ref_commit(repository, branch_ref)
    return branch, anchor, receipt


def retirement_cleanup_target(manifest: dict) -> str:
    return _retirement_cleanup_target(
        manifest,
        object_id_pattern=OBJECT_ID_RE,
        error_type=LauncherError,
    )


@contextmanager
def exact_run_tmp_parent(
    repository: Repository,
    manifest: dict,
) -> Iterator[tuple[int, str]]:
    with _exact_run_tmp_parent(
        repository,
        manifest,
        validate_exact_run_tmpdir=validate_exact_run_tmpdir,
        directory_flag=getattr(os, "O_DIRECTORY", 0),
        nofollow_flag=getattr(os, "O_NOFOLLOW", 0),
        cloexec_flag=getattr(os, "O_CLOEXEC", 0),
        read_only_flag=os.O_RDONLY,
        directory_test=stat.S_ISDIR,
        file_open=os.open,
        file_stat=os.fstat,
        same_stat=os.path.samestat,
        file_close=os.close,
        error_type=LauncherError,
    ) as parent:
        yield parent


def run_tmp_entry(
    parent_descriptor: int,
    run_id: str,
) -> os.stat_result | None:
    return _run_tmp_entry(
        parent_descriptor,
        run_id,
        entry_stat=os.stat,
        error_type=LauncherError,
    )


def open_exact_temporary_directory(
    parent_descriptor: int,
    name: str,
    expected: os.stat_result,
) -> int:
    return _open_exact_temporary_directory(
        parent_descriptor,
        name,
        expected,
        directory_flag=getattr(os, "O_DIRECTORY", 0),
        nofollow_flag=getattr(os, "O_NOFOLLOW", 0),
        cloexec_flag=getattr(os, "O_CLOEXEC", 0),
        read_only_flag=os.O_RDONLY,
        directory_test=stat.S_ISDIR,
        file_open=os.open,
        file_stat=os.fstat,
        same_stat=os.path.samestat,
        file_close=os.close,
        error_type=LauncherError,
    )


def remove_open_temporary_contents(directory_descriptor: int) -> None:
    _remove_open_temporary_contents(
        directory_descriptor,
        list_entries=os.listdir,
        entry_metadata=run_tmp_entry,
        open_directory=open_exact_temporary_directory,
        remove_contents=remove_open_temporary_contents,
        directory_test=stat.S_ISDIR,
        same_stat=os.path.samestat,
        remove_directory=os.rmdir,
        remove_entry=os.unlink,
        file_close=os.close,
        error_type=LauncherError,
    )


def remove_run_tmpdir(repository: Repository, manifest: dict) -> None:
    _remove_run_tmpdir(
        repository,
        manifest,
        authenticate_parent=exact_run_tmp_parent,
        entry_metadata=run_tmp_entry,
        directory_test=stat.S_ISDIR,
        open_directory=open_exact_temporary_directory,
        remove_contents=remove_open_temporary_contents,
        same_stat=os.path.samestat,
        remove_directory=os.rmdir,
        file_close=os.close,
        error_type=LauncherError,
    )


def require_run_tmp_absent(repository: Repository, manifest: dict) -> None:
    _require_run_tmp_absent(
        repository,
        manifest,
        authenticate_parent=exact_run_tmp_parent,
        entry_metadata=run_tmp_entry,
        error_type=LauncherError,
    )


def require_run_tmp_directory(repository: Repository, manifest: dict) -> None:
    _require_run_tmp_directory(
        repository,
        manifest,
        authenticate_parent=exact_run_tmp_parent,
        entry_metadata=run_tmp_entry,
        directory_test=stat.S_ISDIR,
        open_directory=open_exact_temporary_directory,
        file_close=os.close,
        error_type=LauncherError,
    )


def record_retirement_cleanup_failure(
    repository: Repository,
    manifest: dict,
    warning: str,
) -> None:
    manifest["retirement_cleanup_warning"] = warning
    write_manifest(repository, manifest)


def reject_retirement_ref_tuple(
    repository: Repository,
    manifest: dict,
    warning: str,
) -> None:
    record_retirement_cleanup_failure(repository, manifest, warning)
    raise LauncherError(
        "a retirement ref changed: the branch, anchor, and receipt tuple is partial "
        "or tampered; destructive recovery was refused"
    )


def finalize_retirement(repository: Repository, manifest: dict) -> None:
    if manifest.get("state") != "retirement-ref-cleanup-pending":
        raise LauncherError("the retained run has no completed retirement transaction")
    retirement_parameters(manifest)
    retirement_cleanup_target(manifest)
    if (
        "retirement_ref_transaction_committed_at" not in manifest
        or "retirement_receipt_removed_at" not in manifest
    ):
        raise LauncherError("the retirement ref transaction is not durably complete")
    worktree = Path(manifest["worktree"])
    if registered_record(repository, worktree) is not None or path_entry_exists(
        worktree,
        label="the retirement worktree path",
    ):
        raise LauncherError("cannot finalize retirement while the worktree remains")
    if retirement_ref_tuple(repository, manifest) != (None, None, None):
        raise LauncherError("retirement refs remain after transactional cleanup")

    try:
        remove_run_tmpdir(repository, manifest)
    except LauncherError as exc:
        record_retirement_cleanup_failure(repository, manifest, str(exc))
        raise
    manifest["state"] = "cleaned"
    manifest["retirement_completed_at"] = utc_now()
    manifest["cleaned_at"] = manifest["retirement_completed_at"]
    manifest.pop("retirement_cleanup_warning", None)
    write_manifest(repository, manifest)


def remove_retirement_receipt_after_transaction(
    repository: Repository,
    manifest: dict,
    discard_head: str,
) -> bool:
    branch, anchor, receipt = retirement_ref_tuple(repository, manifest)
    if branch is not None or anchor is not None or receipt not in {None, discard_head}:
        reject_retirement_ref_tuple(
            repository,
            manifest,
            "retirement refs changed after the durable ref transaction checkpoint",
        )

    if "retirement_receipt_removed_at" in manifest:
        if receipt is not None:
            reject_retirement_ref_tuple(
                repository,
                manifest,
                "the retirement receipt exists after its durable removal checkpoint",
            )
        finalize_retirement(repository, manifest)
        return True

    if receipt == discard_head:
        receipt_ref = retirement_receipt_ref(manifest)
        deletion = git(
            repository.root,
            "update-ref",
            "--no-deref",
            "-d",
            receipt_ref,
            discard_head,
            check=False,
        )
        remaining = retirement_ref_tuple(repository, manifest)
        if remaining == (None, None, discard_head):
            record_retirement_cleanup_failure(
                repository,
                manifest,
                deletion.stderr.strip() or "the retirement receipt was retained",
            )
            return False
        if remaining != (None, None, None):
            reject_retirement_ref_tuple(
                repository,
                manifest,
                deletion.stderr.strip()
                or "retirement receipt removal became partial or tampered",
            )

    manifest["retirement_receipt_removed_at"] = utc_now()
    manifest.pop("retirement_cleanup_warning", None)
    write_manifest(repository, manifest)
    finalize_retirement(repository, manifest)
    return True


def cleanup_retirement_refs(repository: Repository, manifest: dict) -> bool:
    worktree = Path(manifest["worktree"])
    if registered_record(repository, worktree) is not None or path_entry_exists(
        worktree,
        label="the retirement worktree path",
    ):
        raise LauncherError("cannot clean retirement refs while the worktree remains")
    discard_head, _, _ = retirement_parameters(manifest)
    retirement_cleanup_target(manifest)
    current_tuple = retirement_ref_tuple(repository, manifest)

    if "retirement_ref_transaction_committed_at" in manifest:
        return remove_retirement_receipt_after_transaction(
            repository,
            manifest,
            discard_head,
        )

    pre_transaction = (discard_head, discard_head, None)
    post_transaction = (None, None, discard_head)
    if current_tuple == post_transaction:
        manifest["retirement_ref_transaction_committed_at"] = utc_now()
        manifest.pop("retirement_cleanup_warning", None)
        write_manifest(repository, manifest)
        return remove_retirement_receipt_after_transaction(
            repository,
            manifest,
            discard_head,
        )
    if current_tuple != pre_transaction:
        reject_retirement_ref_tuple(
            repository,
            manifest,
            "the pre-transaction retirement refs are partial or tampered",
        )

    target_head = refresh_retirement_cleanup_target(repository, manifest)
    branch_ref = f"refs/heads/{manifest['branch']}"
    if any(record.get("branch") == branch_ref for record in worktree_records(repository)):
        raise LauncherError("the retirement worker branch is checked out elsewhere")

    anchor_ref = retirement_anchor_ref(manifest)
    receipt_ref = retirement_receipt_ref(manifest)
    commands = [
        "start",
        f"verify {manifest['target_ref']} {target_head}",
        f"create {receipt_ref} {discard_head}",
        f"delete {branch_ref} {discard_head}",
        f"delete {anchor_ref} {discard_head}",
        "prepare",
        "commit",
        "",
    ]
    deletion = git(
        repository.root,
        "update-ref",
        "--no-deref",
        "--stdin",
        check=False,
        input_data="\n".join(commands),
    )
    remaining = retirement_ref_tuple(repository, manifest)
    if remaining == pre_transaction:
        record_retirement_cleanup_failure(
            repository,
            manifest,
            deletion.stderr.strip() or "retirement refs were retained",
        )
        return False
    if remaining != post_transaction:
        reject_retirement_ref_tuple(
            repository,
            manifest,
            deletion.stderr.strip()
            or "the retirement ref transaction became partial or tampered",
        )

    manifest["retirement_ref_transaction_committed_at"] = utc_now()
    manifest.pop("retirement_cleanup_warning", None)
    write_manifest(repository, manifest)
    return remove_retirement_receipt_after_transaction(
        repository,
        manifest,
        discard_head,
    )


def confirm_cleaned_retirement(repository: Repository, manifest: dict) -> None:
    retirement_parameters(manifest)
    retirement_cleanup_target(manifest)
    if (
        "retirement_ref_transaction_committed_at" not in manifest
        or "retirement_receipt_removed_at" not in manifest
        or "retirement_completed_at" not in manifest
    ):
        raise LauncherError("the retired run has incomplete durable metadata")
    worktree = Path(manifest["worktree"])
    if registered_record(repository, worktree) is not None or path_entry_exists(
        worktree,
        label="the retirement worktree path",
    ):
        raise LauncherError("the retired run unexpectedly retains a worktree")
    if retirement_ref_tuple(repository, manifest) != (None, None, None):
        raise LauncherError("the retired run's ref tuple was recreated or tampered")
    require_run_tmp_absent(repository, manifest)


def resume_checkpointed_retirement(
    repository: Repository,
    manifest: dict,
) -> bool:
    if manifest.get("state") not in RETIREMENT_PENDING_STATES:
        raise LauncherError("the retained run has no retryable retirement checkpoint")
    validate_exact_run_tmpdir(repository, manifest)
    reject_conflicting_retirement_lifecycle(manifest)
    discard_head, _, _ = retirement_parameters(manifest)
    worktree = Path(manifest["worktree"])
    record = registered_record(repository, worktree)
    exists = path_entry_exists(worktree, label="the retirement worktree path")

    if record is not None and exists:
        if manifest.get("state") != "retirement-pending":
            raise LauncherError(
                "the retirement ref-cleanup checkpoint unexpectedly has a worktree"
            )
        ensure_retirement_anchor(repository, manifest, discard_head)
        audit = audit_run(repository, manifest)
        if not audit.locked:
            validate_retirement_worktree(
                repository,
                manifest,
                require_locked=False,
            )
            relock_retirement_worktree(repository, manifest)
        remove_checkpointed_retirement_worktree(repository, manifest)
    elif record is None and not exists:
        branch, anchor, receipt = retirement_ref_tuple(repository, manifest)
        if manifest.get("state") == "retirement-pending" and (
            branch != discard_head
            or anchor != discard_head
            or receipt is not None
        ):
            raise LauncherError(
                "the interrupted retirement has no exact worktree-removal checkpoint"
            )
        if manifest.get("state") == "retirement-pending":
            mark_retirement_worktree_removed(repository, manifest)
    else:
        raise LauncherError("the checkpointed retirement worktree state is inconsistent")

    return cleanup_retirement_refs(repository, manifest)


def retire_run(
    repository: Repository,
    run_id: str,
    discard_head: str,
    target_contains: str,
) -> int:
    if repository.linked_worktree:
        raise LauncherError("retire managed runs from the primary checkout")
    if not OBJECT_ID_RE.fullmatch(discard_head):
        raise LauncherError("--discard-head requires a full lowercase commit object ID")
    if not OBJECT_ID_RE.fullmatch(target_contains):
        raise LauncherError("--target-contains requires a full lowercase commit object ID")
    initialize_state(repository)
    with file_lock(repo_lock_path(repository)):
        manifest = load_manifest(repository, run_id)
        run_lock_stream = acquire_existing_run_lock(repository, run_id)
        try:
            if manifest.get("state") == "cleaned" and manifest.get(
                "retirement_completed_at"
            ) is not None:
                require_matching_retirement_arguments(
                    manifest,
                    discard_head,
                    target_contains,
                )
                confirm_cleaned_retirement(repository, manifest)
                diagnostic(f"run {run_id} was already retired and cleaned")
                return 0

            if manifest.get("state") in RETIREMENT_PENDING_STATES:
                require_matching_retirement_arguments(
                    manifest,
                    discard_head,
                    target_contains,
                )
            elif manifest.get("state") != "quarantined":
                raise LauncherError("only an exact rewritten quarantine may be retired")

            if manifest.get("state") == "quarantined":
                exact_commit_argument(repository, discard_head, "--discard-head")
                exact_commit_argument(repository, target_contains, "--target-contains")
                checkpoint_rewritten_quarantine_retirement(
                    repository,
                    manifest,
                    discard_head,
                    target_contains,
                )
            retired = resume_checkpointed_retirement(repository, manifest)
        finally:
            run_lock_stream.close()
    if not retired:
        diagnostic(
            f"run {run_id} retirement is checkpointed with recoverable refs; retry the exact command"
        )
        return 1
    diagnostic(f"run {run_id} rewritten quarantine was retired and cleaned")
    return 0


def clean_run(repository: Repository, run_id: str) -> int:
    if repository.linked_worktree:
        raise LauncherError("clean managed runs from the primary checkout")
    initialize_state(repository)
    with file_lock(repo_lock_path(repository)):
        manifest = load_manifest(repository, run_id)
        if manifest.get("state") not in RETIREMENT_PENDING_STATES | {"quarantined"}:
            reconcile_stale_run(repository, manifest)
        if manifest.get("state") == "cleaned":
            if manifest.get("retirement_completed_at") is not None:
                confirm_cleaned_retirement(repository, manifest)
            else:
                require_run_tmp_absent(repository, manifest)
            return 0
        run_lock_stream = acquire_existing_run_lock(repository, run_id)
        try:
            state = manifest.get("state")
            worktree = Path(manifest["worktree"])
            if state in RETIREMENT_PENDING_STATES:
                branch_removed = resume_checkpointed_retirement(repository, manifest)
            elif state == "quarantined":
                raise LauncherError(
                    "the quarantined run has no retirement checkpoint; "
                    f"{active_profile().lifecycle_hint('clean')} cannot discard it"
                )
            elif state in {
                "integrated-pending-cleanup",
                "integration-cleanup-pending",
                "integration-cleanup-failed",
            } and registered_record(repository, worktree) is None and not worktree.exists():
                branch_removed = recover_removed_worktree_cleanup(repository, manifest)
            elif state in {
                "integration-cleanup-pending",
                "integration-cleanup-failed",
            } and manifest.get("integration_cleanup_started_at") is not None:
                branch_removed = recover_unlocked_worktree_cleanup(repository, manifest)
            elif state in {
                "cleaned-branch-retained",
                "cleaned-ref-retained",
            }:
                branch_removed = retry_retained_ref_cleanup(repository, manifest)
            else:
                if manifest.get("state") in {
                    "integration-conflict",
                    "integration-continue-pending",
                }:
                    raise LauncherError(
                        "the retained run has an active managed conflict; continue it with "
                        f"{active_profile().lifecycle_hint('continue')} {run_id} or "
                        f"restore it with {active_profile().lifecycle_hint('abort')} "
                        f"{run_id}"
                    )
                if manifest.get("state") == "integration-abort-pending":
                    raise LauncherError(
                        f"the retained run has an interrupted abort; retry "
                        f"{active_profile().lifecycle_hint('abort')} {run_id}"
                    )
                manual_candidate = manifest.get("integration_manual_resolution") is True
                if manual_candidate:
                    recorded_integration_source(repository, manifest)
                    candidate_head = recorded_commit(
                        repository,
                        manifest,
                        "integration_candidate_head",
                    )
                    audit = audit_run(repository, manifest)
                    if not audit_matches_clean_head(manifest, audit, candidate_head):
                        raise LauncherError(
                            "the retained manual candidate is not clean and exact"
                        )
                    target_head = require_recorded_target_checkout(
                        repository,
                        manifest,
                        purpose="cleaning a manually resolved retained run",
                    )
                    if target_head != candidate_head:
                        record_target_mismatch(manifest, target_head)
                        manifest["state"] = "integration-verification-failed"
                        manifest["integration_verification_error"] = (
                            "the target did not remain at the exact manually resolved "
                            "candidate before cleanup"
                        )
                        write_manifest(repository, manifest)
                        raise LauncherError(
                            "the target changed after landing the manually resolved "
                            "candidate; the retained worker was not cleaned"
                        )
                    if manifest.get("integrated_head") is not None and recorded_commit(
                        repository,
                        manifest,
                        "integrated_head",
                    ) != candidate_head:
                        raise LauncherError(
                            "the manual candidate and recorded landing are inconsistent"
                        )
                    manifest["state"] = "integrated-pending-cleanup"
                    manifest["integrated_head"] = candidate_head
                    manifest.setdefault("integrated_at", utc_now())
                    manifest.pop("integration_verification_error", None)
                    write_manifest(repository, manifest)
                expected_head = None
                if not manual_candidate and manifest.get("integration_candidate_head") is not None and manifest.get(
                    "integrated_head"
                ) is None:
                    raise LauncherError(
                        "the retained run has a pending rebased integration; retry "
                        f"{active_profile().lifecycle_command('integrate', run_id)}"
                    )
                if manifest.get("integrated_head") is not None:
                    expected_head = recorded_commit(repository, manifest, "integrated_head")
                elif "final_head" in manifest or "dirty" in manifest:
                    expected_head = recorded_clean_final_head(repository, manifest)
                branch_removed = safe_cleanup(
                    repository,
                    manifest,
                    allow_integrated=True,
                    expected_head=expected_head,
                )
        finally:
            run_lock_stream.close()
    if not branch_removed:
        diagnostic(f"run {run_id} worktree was removed, but a private lifecycle ref remains")
        return 1
    return 0


def run_is_active(repository: Repository, run_id: str) -> bool:
    path = run_lock_path(repository, run_id)
    try:
        stream = path.open("r+", encoding="utf-8")
    except OSError:
        return False
    try:
        try:
            fcntl.flock(stream.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            return True
        else:
            fcntl.flock(stream.fileno(), fcntl.LOCK_UN)
            return False
    finally:
        stream.close()


def reconcile_stale_run(repository: Repository, manifest: dict) -> bool:
    if manifest.get("background_process_active"):
        if run_is_active(repository, manifest["run_id"]):
            return False
        manifest.pop("background_process_active")
        write_manifest(repository, manifest)
        return True
    if manifest.get("state") not in {"allocating", "ready", "running"}:
        return False
    if run_is_active(repository, manifest["run_id"]):
        return False
    audit = audit_run(repository, manifest)
    manifest["state"] = "interrupted" if audit.registered else "quarantined"
    manifest["final_head"] = audit.head
    manifest["dirty"] = None if audit.status is None else bool(audit.status)
    manifest["audit_registered"] = audit.registered
    manifest["audit_locked"] = audit.locked
    write_manifest(repository, manifest)
    return True


def show_status(repository: Repository, selected: str | None) -> int:
    if repository.linked_worktree:
        raise LauncherError("inspect managed runs from the primary checkout")
    initialize_state(repository)
    with file_lock(repo_lock_path(repository)):
        if selected:
            manifests = [load_manifest(repository, selected)]
        else:
            manifests = []
            for path in sorted((repository.state_root / "runs").glob("*.json")):
                run_id = path.stem
                if RUN_ID_RE.fullmatch(run_id):
                    manifests.append(load_manifest(repository, run_id))
        for manifest in manifests:
            reconcile_stale_run(repository, manifest)
        if selected is None:
            manifests = [
                manifest
                for manifest in manifests
                if manifest.get("state") != "cleaned"
            ]
    if not manifests:
        print(f"No {active_profile().display_name} runs.")
        return 0
    print("RUN ID                               STATE                    ACTIVE")
    for manifest in manifests:
        active = "yes" if run_is_active(repository, manifest["run_id"]) else "no"
        print(f"{manifest['run_id']:<36} {manifest.get('state', 'unknown'):<24} {active}")
    return 0


def launcher_help() -> str:
    return """usage:
  scripts/triptych-codex [--] [CODEX_ARGUMENTS...]
  scripts/triptych-codex --triptych-status [RUN_ID]
  scripts/triptych-codex --triptych-reopen RUN_ID [-- CODEX_ARGUMENTS...]
  scripts/triptych-codex --triptych-resolve RUN_ID
  scripts/triptych-codex --triptych-continue RUN_ID
  scripts/triptych-codex --triptych-abort RUN_ID
  scripts/triptych-codex --triptych-final-diff RUN_ID
  scripts/triptych-codex --triptych-integrate RUN_ID
  scripts/triptych-codex --triptych-clean RUN_ID
  scripts/triptych-codex --triptych-retire RUN_ID --discard-head FULL_OID --target-contains FULL_OID
  scripts/triptych-codex --triptych-help

The default command starts Codex in a unique locked worktree. A successful
first unchanged run is cleaned automatically. Changed, committed, failed, or
inconsistent runs are preserved and identified by an opaque run ID.
Workers and resolvers receive one exact run-owned directory as TMPDIR, TMP, and
TEMP. Ordinary managed cleanup authenticates and removes it before deleting
private refs; a run is never marked cleaned while that path remains.
Status without a run ID lists only runs that still require attention; pass an
explicit run ID to inspect a cleaned record.
Reopening starts a new Codex process in the retained worktree; it does not
resume a saved Codex conversation. Only interactive, exec, and review agent
surfaces and their allowlisted options are accepted. After separate review and
authorization, integration confirms or fast-forwards an already-linear result;
when the target and worker diverged, it rebases the worker onto the current target
and then fast-forwards. It never creates a merge commit. A genuine conflict stays
active in the managed worker. The resolver may edit and stage only; launcher-owned
continue or abort commands administer the rebase with hooks and editors disabled.
A successful manual continuation stops at a clean review-pending candidate without
updating the target. The opaque final-diff command renders that candidate against
its captured target without exposing its private worktree. A later fresh integration
authorization may fast-forward that exact candidate only while the captured target
is unchanged. Target movement or unverified state retains manual work without reset,
rebase, merge, or cleanup.
Retirement is a destructive, direct-only exception for an explicitly superseded,
clean rewritten quarantine; it deliberately has no Make wrapper. Both object values
must be full exact commit IDs. The discard head is the exact worker history authorized
for deletion. The target-contains value is only an operator-selected reachability checkpoint,
not evidence of semantic equivalence, incorporation, or supersession.
Retirement never updates the target. It freshly requires selected-checkpoint containment
before avoidable worktree removal and checkpoints the exact current containing target for
the atomic branch, anchor, and receipt transaction. A target race retains those refs so an
exact retry may use a newer containing descendant; lost containment refuses until restored.
After the receipt transaction, recovery uses only durable checkpoints and strict phase refs,
and exact-argument retries remain idempotent after object pruning.
"""


def _main(
    arguments: Sequence[str] | None = None,
    *,
    invocation_path: Path,
) -> int:
    argv = list(sys.argv[1:] if arguments is None else arguments)
    try:
        launcher = authenticate_launcher(invocation_path)
        pin_git_executable()
        repository = discover_repository()
        if not repository.linked_worktree and any(
            os.environ.get(name) for name in MANAGED_CONTEXT_ENVIRONMENTS
        ):
            raise LauncherError("worker marker is invalid in the primary checkout")
        if argv and argv[0] == "--triptych-help":
            if len(argv) != 1:
                raise LauncherError("--triptych-help takes no arguments")
            print(launcher_help(), end="")
            return 0
        if argv and argv[0] == "--triptych-status":
            if len(argv) > 2:
                raise LauncherError("--triptych-status accepts at most one run ID")
            return show_status(repository, argv[1] if len(argv) == 2 else None)
        if argv and argv[0] == "--triptych-integrate":
            if len(argv) != 2:
                raise LauncherError("--triptych-integrate requires exactly one run ID")
            return integrate_run(repository, argv[1])
        if argv and argv[0] == "--triptych-continue":
            if len(argv) != 2:
                raise LauncherError("--triptych-continue requires exactly one run ID")
            return continue_conflict_run(repository, argv[1])
        if argv and argv[0] == "--triptych-abort":
            if len(argv) != 2:
                raise LauncherError("--triptych-abort requires exactly one run ID")
            return abort_conflict_run(repository, argv[1])
        if argv and argv[0] == "--triptych-final-diff":
            if len(argv) != 2:
                raise LauncherError("--triptych-final-diff requires exactly one run ID")
            return show_final_diff(repository, argv[1])
        if argv and argv[0] == "--triptych-clean":
            if len(argv) != 2:
                raise LauncherError("--triptych-clean requires exactly one run ID")
            return clean_run(repository, argv[1])
        if argv and argv[0] == "--triptych-retire":
            if (
                len(argv) != 6
                or argv[2] != "--discard-head"
                or argv[4] != "--target-contains"
            ):
                raise LauncherError(
                    "--triptych-retire requires exactly RUN_ID --discard-head "
                    "FULL_OID --target-contains FULL_OID"
                )
            return retire_run(repository, argv[1], argv[3], argv[5])
        if argv and argv[0] == "--triptych-reopen":
            if len(argv) < 2:
                raise LauncherError("--triptych-reopen requires a run ID")
            forwarded = argv[2:]
            if forwarded[:1] == ["--"]:
                forwarded = forwarded[1:]
            return reopen_run(repository, argv[1], forwarded, launcher)
        if argv and argv[0] == "--triptych-resolve":
            if len(argv) != 2:
                raise LauncherError("--triptych-resolve requires exactly one run ID")
            return resolve_conflict_run(repository, argv[1], launcher)

        real_codex = resolve_real_codex(launcher)
        normalize_codex_arguments(argv)

        if repository.linked_worktree:
            return pass_through_linked_worktree(repository, real_codex, argv)

        manifest, run_lock_stream = allocate_run(repository)
        return launch_child(repository, manifest, run_lock_stream, real_codex, argv)
    except LauncherError as exc:
        diagnostic(str(exc))
        return 2


def main(
    arguments: Sequence[str] | None = None,
    *,
    invocation_path: Path,
    profile: RuntimeProfile,
) -> int:
    with profile_context(profile):
        return _main(arguments, invocation_path=invocation_path)
