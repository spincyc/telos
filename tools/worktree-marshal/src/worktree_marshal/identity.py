"""Runtime identity records and read-only authentication policy."""

from __future__ import annotations

from collections.abc import Sized
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Protocol


@dataclass(frozen=True)
class Repository:
    root: Path
    git_dir: Path
    common_git_dir: Path
    relative_cwd: Path
    linked_worktree: bool
    state_root: Path


@dataclass(frozen=True)
class LinkedWorktreeIdentity:
    worktree: Path
    git_file: Path
    git_dir: Path
    common_git_dir: Path


@dataclass(frozen=True)
class LauncherIdentity:
    """Authenticated identity of the in-process command entry point."""

    path: Path
    device: int
    inode: int


class RegularFileMetadata(Protocol):
    st_mode: int
    st_nlink: int
    st_size: int
    st_dev: int
    st_ino: int
    st_mtime_ns: int
    st_ctime_ns: int


def path_entry_exists(
    path: Path,
    *,
    label: str,
    file_not_found_error_type: Callable[[], type[BaseException]],
    os_error_type: Callable[[], type[BaseException]],
    error_type: Callable[[], type[BaseException]],
) -> bool:
    """Inspect one directory entry without following its final component."""

    try:
        path.lstat()
    except file_not_found_error_type():
        return False
    except os_error_type() as exc:
        raise error_type()(f"cannot inspect {label}") from exc
    return True


def discover_repository(
    cwd: Path | None,
    *,
    path_factory: Callable[[], type[Path]],
    git_call: Callable[[], Callable[..., object]],
    absolute_git_path: Callable[[], Callable[[Path, str], Path]],
    digest_factory: Callable[[], Callable[[bytes], object]],
    filesystem_encode: Callable[[], Callable[[object], bytes]],
    state_base: Callable[[], Callable[[], Path]],
    repository_slug: Callable[[], Callable[[Path], str]],
    state_environment: Callable[[], str],
    repository_factory: Callable[[], Callable[..., Repository]],
    value_error_type: Callable[[], type[BaseException]],
    error_type: Callable[[], type[BaseException]],
) -> Repository:
    """Discover one working tree and derive its profile-bound state identity."""

    start = (cwd or path_factory().cwd()).resolve()
    inside = git_call()(
        start,
        "rev-parse",
        "--is-inside-work-tree",
        check=False,
    )
    if inside.returncode or inside.stdout.strip() != "true":
        raise error_type()(
            "run this launcher from inside a non-bare Git working tree"
        )

    root = path_factory()(
        git_call()(
            start,
            "rev-parse",
            "--show-toplevel",
        ).stdout.strip()
    ).resolve()
    git_dir = absolute_git_path()(root, "--git-dir")
    common_git_dir = absolute_git_path()(root, "--git-common-dir")
    try:
        relative_cwd = start.relative_to(root)
    except value_error_type() as exc:
        raise error_type()(
            "the current directory is outside the discovered worktree"
        ) from exc

    digest = digest_factory()(
        filesystem_encode()(common_git_dir)
    ).hexdigest()[:12]
    repo_state = (
        state_base()()
        / f"{repository_slug()(root)}-{digest}"
    ).resolve()
    if repo_state == root or root in repo_state.parents:
        raise error_type()(
            f"{state_environment()} must keep launcher state outside "
            "the worktree"
        )
    return repository_factory()(
        root=root,
        git_dir=git_dir,
        common_git_dir=common_git_dir,
        relative_cwd=relative_cwd,
        linked_worktree=git_dir != common_git_dir,
        state_root=repo_state,
    )


def authenticate_git_cwd(
    cwd: Path,
    *,
    path_factory: Callable[[], Callable[[Path], Path]],
    os_error_type: Callable[[], type[BaseException]],
    runtime_error_type: Callable[[], type[BaseException]],
    file_not_found_error_type: Callable[[], type[BaseException]],
    directory_test: Callable[[], Callable[[int], bool]],
    regular_file_test: Callable[[], Callable[[int], bool]],
    identity_lookup: Callable[
        [],
        Callable[[Path], LinkedWorktreeIdentity | None],
    ],
    linked_worktree_authenticator: Callable[
        [],
        Callable[..., LinkedWorktreeIdentity],
    ],
    error_type: Callable[[], type[BaseException]],
) -> None:
    """Authenticate the Git administration marker governing one directory."""

    try:
        directory = path_factory()(cwd).resolve(strict=True)
    except (os_error_type(), runtime_error_type()) as exc:
        raise error_type()("the Git working directory is unavailable") from exc
    for candidate in (directory, *directory.parents):
        marker = candidate / ".git"
        try:
            metadata = marker.lstat()
        except file_not_found_error_type():
            continue
        except os_error_type() as exc:
            raise error_type()(
                "cannot inspect the Git administration marker"
            ) from exc
        if directory_test()(metadata.st_mode):
            if marker.resolve(strict=True) != marker:
                raise error_type()(
                    "the primary Git administration directory is symbolic"
                )
            return
        if regular_file_test()(metadata.st_mode):
            prior = identity_lookup()(candidate)
            expected_common = (
                prior.common_git_dir if prior is not None else None
            )
            linked_worktree_authenticator()(
                candidate,
                expected_common_git_dir=expected_common,
            )
            return
        raise error_type()(
            "the Git administration marker is not a real file or directory"
        )


def authenticate_retained_worktree(
    repository: Repository,
    manifest: dict,
    *,
    stringifier: Callable[[], Callable[[object], str]],
    error_type: Callable[[], type[BaseException]],
    linked_worktree_authenticator: Callable[
        [],
        Callable[..., LinkedWorktreeIdentity],
    ],
    path_factory: Callable[[], Callable[[str], Path]],
) -> LinkedWorktreeIdentity:
    """Authenticate a manifest-bound retained linked worktree."""

    recorded_common = manifest.get("common_git_dir")
    if recorded_common != stringifier()(repository.common_git_dir):
        raise error_type()(
            "the retained run's common Git directory changed"
        )
    return linked_worktree_authenticator()(
        path_factory()(manifest["worktree"]),
        expected_common_git_dir=repository.common_git_dir,
    )


def exact_pointer_path(
    raw_value: str,
    *,
    relative_to: Path,
    label: str,
    path_factory: Callable[[], Callable[[str], Path]],
    absolute_path: Callable[[], Callable[[str], str]],
    filesystem_path: Callable[[], Callable[[Path], str]],
    os_error_type: Callable[[], type[BaseException]],
    runtime_error_type: Callable[[], type[BaseException]],
    error_type: Callable[[], type[BaseException]],
) -> Path:
    """Resolve a pointer without accepting symbolic-path traversal."""

    value = path_factory()(raw_value)
    candidate = value if value.is_absolute() else relative_to / value
    absolute = path_factory()(absolute_path()(filesystem_path()(candidate)))
    try:
        resolved = candidate.resolve(strict=True)
    except (os_error_type(), runtime_error_type()) as exc:
        raise error_type()(f"{label} points to an unavailable path") from exc
    if resolved != absolute:
        raise error_type()(f"{label} traverses a symbolic path")
    return resolved


def exact_real_directory(
    path: Path,
    *,
    label: str,
    path_factory: Callable[[], Callable[[str], Path]],
    absolute_path: Callable[[], Callable[[str], str]],
    filesystem_path: Callable[[], Callable[[Path], str]],
    os_error_type: Callable[[], type[BaseException]],
    runtime_error_type: Callable[[], type[BaseException]],
    directory_test: Callable[[], Callable[[int], bool]],
    error_type: Callable[[], type[BaseException]],
) -> Path:
    """Require one existing directory with an exact nonsymbolic path."""

    absolute = path_factory()(absolute_path()(filesystem_path()(path)))
    try:
        metadata = absolute.lstat()
        resolved = absolute.resolve(strict=True)
    except (os_error_type(), runtime_error_type()) as exc:
        raise error_type()(f"{label} is unavailable") from exc
    if not directory_test()(metadata.st_mode) or resolved != absolute:
        raise error_type()(f"{label} is not an exact real directory")
    return absolute


def validate_linked_worktree_path(
    worktree: Path,
    *,
    expected_common_git_dir: Path | None,
    real_directory: Callable[[], Callable[..., Path]],
    single_line: Callable[[], Callable[..., str]],
    pointer_path: Callable[[], Callable[..., Path]],
    length: Callable[[], Callable[[Sized], int]],
    error_type: Callable[[], type[BaseException]],
) -> tuple[Path, Path, Path, Path]:
    """Validate the read-only path topology of one linked worktree."""

    canonical_worktree = real_directory()(
        worktree,
        label="the retained worktree",
    )
    git_file = canonical_worktree / ".git"
    forward = single_line()(
        git_file,
        label="the retained worktree .git file",
    )
    prefix = "gitdir: "
    if not forward.startswith(prefix) or forward == prefix:
        raise error_type()(
            "the retained worktree .git file has an invalid pointer"
        )
    git_dir = pointer_path()(
        forward[length()(prefix) :],
        relative_to=canonical_worktree,
        label="the retained worktree .git file",
    )
    git_dir = real_directory()(
        git_dir,
        label="the retained worktree Git admin directory",
    )

    commondir_value = single_line()(
        git_dir / "commondir",
        label="the retained worktree commondir file",
    )
    common_git_dir = pointer_path()(
        commondir_value,
        relative_to=git_dir,
        label="the retained worktree commondir file",
    )
    common_git_dir = real_directory()(
        common_git_dir,
        label="the retained worktree common Git directory",
    )
    if expected_common_git_dir is not None:
        expected_common = real_directory()(
            expected_common_git_dir,
            label="the recorded common Git directory",
        )
        if common_git_dir != expected_common:
            raise error_type()(
                "the retained worktree has an unexpected common Git directory"
            )

    worktrees_admin = real_directory()(
        common_git_dir / "worktrees",
        label="the common linked-worktree administration directory",
    )
    if git_dir.parent != worktrees_admin or git_dir == worktrees_admin:
        raise error_type()(
            "the retained worktree Git admin directory is not its unique "
            "direct child"
        )

    backlink_value = single_line()(
        git_dir / "gitdir",
        label="the retained worktree gitdir backlink",
    )
    backlink = pointer_path()(
        backlink_value,
        relative_to=git_dir,
        label="the retained worktree gitdir backlink",
    )
    if backlink != git_file:
        raise error_type()(
            "the retained worktree Git admin backlink changed"
        )

    return canonical_worktree, git_file, git_dir, common_git_dir


def validate_linked_worktree_identity_cache(
    identity: LinkedWorktreeIdentity,
    *,
    canonical_worktree: Path,
    prior_identity: Callable[[], LinkedWorktreeIdentity | None],
    admin_owner: Callable[[], Path | None],
    error_type: Callable[[], type[BaseException]],
) -> None:
    """Validate process-local linked-worktree identity cache consistency."""

    prior = prior_identity()
    if prior is not None and prior != identity:
        raise error_type()("the retained worktree Git identity changed")
    owner = admin_owner()
    if owner is not None and owner != canonical_worktree:
        raise error_type()(
            "the retained worktree Git admin directory is not unique"
        )


def authenticate_launcher(
    path: Path,
    *,
    os_error_type: Callable[[], type[BaseException]],
    error_type: Callable[[], type[BaseException]],
    regular_file_test: Callable[[], Callable[[int], bool]],
    access_check: Callable[[], Callable[[Path, int], bool]],
    executable_mode: Callable[[], int],
    identity_factory: Callable[
        [],
        Callable[..., LauncherIdentity],
    ],
) -> LauncherIdentity:
    """Authenticate the executable launcher path with lazy dependencies."""

    if not path.is_absolute():
        raise error_type()("the launcher entry point must be an absolute path")
    try:
        resolved = path.resolve(strict=True)
        metadata = resolved.stat()
    except os_error_type() as exc:
        raise error_type()("cannot authenticate the launcher entry point") from exc
    if (
        not regular_file_test()(metadata.st_mode)
        or not access_check()(resolved, executable_mode())
    ):
        raise error_type()("the launcher entry point is not a usable executable")
    return identity_factory()(
        path=resolved,
        device=metadata.st_dev,
        inode=metadata.st_ino,
    )


def safe_regular_file_bytes(
    path: Path,
    *,
    label: str,
    open_flags: Callable[[], int],
    file_open: Callable[[], Callable[[Path, int], int]],
    os_error_type: Callable[[], type[BaseException]],
    error_type: Callable[[], type[BaseException]],
    file_stat: Callable[
        [],
        Callable[[int], RegularFileMetadata],
    ],
    regular_file_test: Callable[[], Callable[[int], bool]],
    maximum_file_bytes: Callable[[], int],
    file_read: Callable[[], Callable[[int, int], bytes]],
    minimum: Callable[[], Callable[[int, int], int]],
    length: Callable[[], Callable[[Sized], int]],
    file_close: Callable[[], Callable[[int], None]],
) -> bytes:
    """Read one bounded, stable, single-link regular file by descriptor."""

    flags = open_flags()
    try:
        descriptor = file_open()(path, flags)
    except os_error_type() as exc:
        raise error_type()(f"{label} is not an intact regular file") from exc
    try:
        before = file_stat()(descriptor)
        if (
            not regular_file_test()(before.st_mode)
            or before.st_nlink != 1
        ):
            raise error_type()(f"{label} is not an intact regular file")
        if before.st_size > maximum_file_bytes():
            raise error_type()(f"{label} is unexpectedly large")
        chunks: list[bytes] = []
        remaining = maximum_file_bytes() + 1
        while remaining:
            chunk = file_read()(
                descriptor,
                minimum()(1024 * 1024, remaining),
            )
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= length()(chunk)
        data = b"".join(chunks)
        if length()(data) > maximum_file_bytes():
            raise error_type()(f"{label} is unexpectedly large")
        after = file_stat()(descriptor)
        if (
            (before.st_dev, before.st_ino, before.st_size)
            != (after.st_dev, after.st_ino, after.st_size)
            or before.st_mtime_ns != after.st_mtime_ns
            or before.st_ctime_ns != after.st_ctime_ns
        ):
            raise error_type()(f"{label} changed while it was inspected")
        return data
    finally:
        file_close()(descriptor)


def exact_single_line(
    path: Path,
    *,
    label: str,
    file_reader: Callable[[], Callable[..., bytes]],
    decode_error_type: Callable[[], type[BaseException]],
    error_type: Callable[[], type[BaseException]],
) -> str:
    """Read and validate one exact Git-administration path line."""

    data = file_reader()(path, label=label)
    if (
        not data.endswith(b"\n")
        or data.count(b"\n") != 1
        or b"\r" in data
    ):
        raise error_type()(f"{label} does not contain one exact line")
    try:
        value = data[:-1].decode("utf-8")
    except decode_error_type() as exc:
        raise error_type()(f"{label} is not valid UTF-8") from exc
    if not value or "\0" in value:
        raise error_type()(f"{label} has an invalid path")
    return value
