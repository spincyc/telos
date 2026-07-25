"""Codex executable, argument, and base-environment policy.

This module owns read-only executable selection, the supported Codex CLI
grammar, prompt delimiting, fixed argument-level sandbox configuration, and
the sanitized base environment and deterministic marker enrichment for Codex.
Profile binding, worktree selection and authentication, role choice, manifest
authority, process creation, and lifecycle decisions remain in the lifecycle
engine.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable, Mapping, Sized
from pathlib import Path
from typing import Protocol, Sequence


ROOT_FLAG_OPTIONS = {
    "--help",
    "--no-alt-screen",
    "--oss",
    "--search",
    "--strict-config",
    "--version",
    "-V",
    "-h",
}
ROOT_VALUE_OPTIONS = {
    "--image",
    "--local-provider",
    "--model",
    "--sandbox",
    "-i",
    "-m",
    "-s",
}
EXEC_FLAG_OPTIONS = {
    "--ephemeral",
    "--help",
    "--ignore-user-config",
    "--json",
    "--oss",
    "--skip-git-repo-check",
    "--strict-config",
    "--version",
    "-V",
    "-h",
}
EXEC_VALUE_OPTIONS = {
    "--color",
    "--image",
    "--local-provider",
    "--model",
    "--output-schema",
    "--sandbox",
    "-i",
    "-m",
    "-s",
}
REVIEW_FLAG_OPTIONS = {"--help", "--strict-config", "--uncommitted", "-h"}
REVIEW_VALUE_OPTIONS = {"--base", "--commit", "--title"}
NON_AGENT_CODEX_COMMANDS = {
    "a",
    "app-server",
    "apply",
    "archive",
    "cloud",
    "completion",
    "debug",
    "delete",
    "doctor",
    "exec-server",
    "features",
    "fork",
    "help",
    "login",
    "logout",
    "mcp",
    "mcp-server",
    "plugin",
    "remote-control",
    "resume",
    "sandbox",
    "unarchive",
    "update",
}


class CodexProfile(Protocol):
    real_codex_environment: str


class CodexEnvironmentProfile(Protocol):
    role_environment: str
    run_id_environment: str
    profile_environment: str | None
    profile_id: str
    agent_environment: str | None
    manifest_agent: str | None


class LauncherSnapshot(Protocol):
    device: int
    inode: int


def select_codex_executable(
    launcher: LauncherSnapshot,
    *,
    profile: CodexProfile,
    environment: Callable[[], Mapping[str, str]],
    path_factory: Callable[[], Callable[[str], Path]],
    executable_path: Callable[[], Callable[[], list[str]]],
    current_directory: Callable[[], str],
    os_error_type: Callable[[], type[BaseException]],
    regular_file_test: Callable[[], Callable[[int], bool]],
    access_check: Callable[[], Callable[[Path, int], bool]],
    executable_mode: Callable[[], int],
    error_type: Callable[[], type[BaseException]],
) -> Path:
    """Select one usable non-launcher executable candidate for Codex."""

    override = environment().get(profile.real_codex_environment)
    if override:
        candidate = path_factory()(override)
        if not candidate.is_absolute():
            raise error_type()(
                f"{profile.real_codex_environment} must be an absolute path"
            )
        candidates = [candidate]
    else:
        candidates = [
            path_factory()(entry or current_directory()) / "codex"
            for entry in executable_path()()
        ]

    for candidate in candidates:
        try:
            metadata = candidate.stat()
        except os_error_type():
            continue
        if (
            not regular_file_test()(metadata.st_mode)
            or not access_check()(candidate, executable_mode())
        ):
            continue
        if (metadata.st_dev, metadata.st_ino) == (
            launcher.device,
            launcher.inode,
        ):
            continue
        return candidate.absolute()

    if override:
        raise error_type()(
            f"{profile.real_codex_environment} does not name a usable "
            "non-launcher executable"
        )
    raise error_type()(
        "cannot find the real Codex executable; set "
        f"{profile.real_codex_environment}"
    )


def scan_allowed_options(
    arguments: list[str],
    start: int,
    flag_options: set[str],
    value_options: set[str],
    *,
    length: Callable[[], Callable[[Sized], int]],
    error_type: Callable[[], type[BaseException]],
) -> tuple[int, bool, bool]:
    """Scan one Codex option scope and stop at a command or prompt."""

    supplied_sandbox = False
    short_value_options = {
        option
        for option in value_options
        if option.startswith("-") and not option.startswith("--")
    }
    index = start
    while index < length()(arguments):
        token = arguments[index]
        if token == "--":
            return index + 1, supplied_sandbox, True
        if token == "-" or not token.startswith("-"):
            return index, supplied_sandbox, False
        if token in flag_options:
            index += 1
            continue
        if token in value_options:
            matched_option = token
            if index + 1 >= length()(arguments):
                raise error_type()(f"Codex option {token} requires a value")
            value = arguments[index + 1]
            if matched_option in {"-i", "--image"}:
                arguments[index : index + 2] = [f"--image={value}"]
                index += 1
            else:
                index += 2
        else:
            value = None
            matched_option = None
            for option in value_options:
                if option.startswith("--") and token.startswith(f"{option}="):
                    matched_option = option
                    value = token[length()(option) + 1 :]
                    break
            if value is None and not token.startswith("--"):
                for option in short_value_options:
                    if token.startswith(option) and token != option:
                        matched_option = option
                        value = token[length()(option) :].removeprefix("=")
                        break
            if value is None:
                raise error_type()(
                    f"unsupported Codex option {token!r} in isolated sessions"
                )
            index += 1
        if matched_option in {"-s", "--sandbox"}:
            if value not in {"read-only", "workspace-write"}:
                raise error_type()(f"unsafe Codex sandbox mode {value!r}")
            supplied_sandbox = True
    return index, supplied_sandbox, False


def normalize_codex_arguments(
    arguments: Sequence[str],
    *,
    list_factory: Callable[
        [],
        Callable[[Sequence[str]], list[str]],
    ],
    length: Callable[[], Callable[[Sized], int]],
    option_scanner: Callable[
        [],
        Callable[
            [list[str], int, set[str], set[str]],
            tuple[int, bool, bool],
        ],
    ],
    root_flag_options: Callable[[], set[str]],
    root_value_options: Callable[[], set[str]],
    exec_flag_options: Callable[[], set[str]],
    exec_value_options: Callable[[], set[str]],
    review_flag_options: Callable[[], set[str]],
    review_value_options: Callable[[], set[str]],
    non_agent_commands: Callable[[], set[str]],
    reopen_hint: Callable[[], str],
    error_type: Callable[[], type[BaseException]],
) -> tuple[list[str], bool]:
    """Default-deny Codex controls and force free-form prompts to remain data."""

    normalized = list_factory()(arguments)
    index, supplied_sandbox, forced_prompt = option_scanner()(
        normalized,
        0,
        root_flag_options(),
        root_value_options(),
    )
    if forced_prompt or index >= length()(normalized):
        return normalized, supplied_sandbox

    first = normalized[index]
    if first in non_agent_commands():
        if first in {"resume", "fork"}:
            raise error_type()(
                "reopen isolated worktrees with "
                f"{reopen_hint()}"
            )
        raise error_type()(
            f"Codex subcommand {first!r} is outside the isolated agent launcher"
        )

    if first in {"exec", "e"}:
        nested_index, nested_sandbox, nested_forced = option_scanner()(
            normalized,
            index + 1,
            exec_flag_options(),
            exec_value_options(),
        )
        supplied_sandbox = supplied_sandbox or nested_sandbox
        if nested_forced or nested_index >= length()(normalized):
            return normalized, supplied_sandbox
        nested = normalized[nested_index]
        if nested == "review":
            (
                prompt_index,
                review_sandbox,
                review_forced,
            ) = option_scanner()(
                normalized,
                nested_index + 1,
                review_flag_options(),
                review_value_options(),
            )
            supplied_sandbox = supplied_sandbox or review_sandbox
            if not review_forced and prompt_index < length()(normalized):
                normalized.insert(prompt_index, "--")
            return normalized, supplied_sandbox
        if nested in {"help", "resume"}:
            raise error_type()(
                f"Codex exec subcommand {nested!r} is outside the "
                "isolated agent launcher"
            )
        normalized.insert(nested_index, "--")
        return normalized, supplied_sandbox

    if first == "review":
        (
            prompt_index,
            review_sandbox,
            review_forced,
        ) = option_scanner()(
            normalized,
            index + 1,
            review_flag_options(),
            review_value_options(),
        )
        supplied_sandbox = supplied_sandbox or review_sandbox
        if not review_forced and prompt_index < length()(normalized):
            normalized.insert(prompt_index, "--")
        return normalized, supplied_sandbox

    normalized.insert(index, "--")
    return normalized, supplied_sandbox


def codex_argv(
    real_codex: Path,
    workdir: Path,
    arguments: Sequence[str],
    *,
    argument_normalizer: Callable[
        [],
        Callable[[Sequence[str]], tuple[list[str], bool]],
    ],
    stringifier: Callable[[], Callable[[object], str]],
) -> list[str]:
    """Construct the fixed safety prefix and normalized Codex arguments."""

    normalized, supplied_sandbox = argument_normalizer()(arguments)
    enforced = [
        stringifier()(real_codex),
        "-C",
        stringifier()(workdir),
        "--disable",
        "multi_agent",
        "-c",
        "sandbox_workspace_write.writable_roots=[]",
        "-c",
        "sandbox_permissions=[]",
    ]
    if not supplied_sandbox:
        enforced.extend(("--sandbox", "workspace-write"))
    return [*enforced, *normalized]


def codex_environment(
    real_codex: Path,
    *,
    profile: CodexProfile,
    sanitized_environment: Callable[
        [],
        Callable[[], dict[str, str]],
    ],
    control_environments: Callable[[], Iterable[str]],
    stringifier: Callable[[], Callable[[object], str]],
    executable_path: Callable[
        [],
        Callable[[Mapping[str, str]], list[str]],
    ],
    path_separator: Callable[[], str],
) -> dict[str, str]:
    """Construct the sanitized base environment for a Codex process."""

    environment = sanitized_environment()()
    for name in control_environments():
        environment.pop(name, None)
    environment[profile.real_codex_environment] = stringifier()(real_codex)
    path_entries = executable_path()(environment)
    real_parent = stringifier()(real_codex.parent)
    environment["PATH"] = path_separator().join(
        [
            real_parent,
            *[
                entry
                for entry in path_entries
                if entry != real_parent
            ],
        ]
    )
    return environment


def enrich_codex_environment(
    environment: dict[str, str],
    *,
    profile: CodexEnvironmentProfile,
    role: str,
    manifest: Mapping[str, str] | None,
) -> dict[str, str]:
    """Add profile and optional retained-run markers to a Codex environment."""

    environment[profile.role_environment] = role
    if manifest is not None:
        environment[profile.run_id_environment] = manifest["run_id"]
    if profile.profile_environment is not None:
        environment[profile.profile_environment] = profile.profile_id
    if (
        profile.agent_environment is not None
        and profile.manifest_agent is not None
    ):
        environment[profile.agent_environment] = profile.manifest_agent
    if manifest is not None:
        for name in ("TMPDIR", "TMP", "TEMP"):
            environment[name] = manifest["tmpdir"]
    return environment
