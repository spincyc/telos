"""Git executable discovery and policy for hardened invocation.

This module owns read-only executable discovery and validation, deterministic
environment and argument transformation, and validation of captured
effective-configuration output. Executable caching, configuration probing,
subprocess execution, repository authentication, and ref transactions remain
in the lifecycle engine until their own parity seams are protected.
"""

from __future__ import annotations

import os
import re
from collections.abc import Callable
from pathlib import Path
from typing import Collection, Mapping, Sequence


GIT_UNSAFE_ENV = {
    "GIT_ALTERNATE_OBJECT_DIRECTORIES",
    "GIT_ASKPASS",
    "GIT_ATTR_GLOBAL",
    "GIT_ATTR_SOURCE",
    "GIT_ATTR_SYSTEM",
    "GIT_CEILING_DIRECTORIES",
    "GIT_COMMON_DIR",
    "GIT_CONFIG",
    "GIT_CONFIG_COUNT",
    "GIT_CONFIG_GLOBAL",
    "GIT_CONFIG_NOSYSTEM",
    "GIT_CONFIG_PARAMETERS",
    "GIT_CONFIG_SYSTEM",
    "GIT_DIFF_OPTS",
    "GIT_DIR",
    "GIT_DISCOVERY_ACROSS_FILESYSTEM",
    "GIT_EDITOR",
    "GIT_EXEC_PATH",
    "GIT_EXTERNAL_DIFF",
    "GIT_EXTERNAL_DIFF_TRUST_EXIT_CODE",
    "GIT_GLOB_PATHSPECS",
    "GIT_GRAFT_FILE",
    "GIT_ICASE_PATHSPECS",
    "GIT_IMPLICIT_WORK_TREE",
    "GIT_INDEX_FILE",
    "GIT_LITERAL_PATHSPECS",
    "GIT_MERGE_AUTOEDIT",
    "GIT_NAMESPACE",
    "GIT_NOGLOB_PATHSPECS",
    "GIT_NO_REPLACE_OBJECTS",
    "GIT_OBJECT_DIRECTORY",
    "GIT_OPTIONAL_LOCKS",
    "GIT_PREFIX",
    "GIT_PROXY_COMMAND",
    "GIT_QUARANTINE_PATH",
    "GIT_REDIRECT_STDERR",
    "GIT_REDIRECT_STDIN",
    "GIT_REDIRECT_STDOUT",
    "GIT_REPLACE_REF_BASE",
    "GIT_SEQUENCE_EDITOR",
    "GIT_SHALLOW_FILE",
    "GIT_SHELL_PATH",
    "GIT_SSH",
    "GIT_SSH_COMMAND",
    "GIT_SSH_VARIANT",
    "GIT_TEMPLATE_DIR",
    "GIT_WORK_TREE",
}
GIT_INDEXED_CONFIG_ENV_RE = re.compile(r"^GIT_CONFIG_(?:KEY|VALUE)_[0-9]+$")
GIT_COMMAND_CONFIG_RE = re.compile(
    r"^(?:"
    r"filter\..+\.(?:clean|smudge|process)|"
    r"merge\..+\.driver|"
    r"diff\.external|"
    r"diff\..+\.(?:command|textconv)"
    r")$",
    re.IGNORECASE,
)
GIT_BOOLEAN_VALUES = {"", "0", "1", "false", "no", "off", "on", "true", "yes"}
GIT_BASE_ARGUMENTS = (
    "--no-replace-objects",
    "-c",
    "core.hooksPath=/dev/null",
    "-c",
    "commit.gpgSign=false",
    "-c",
    "tag.gpgSign=false",
    "-c",
    "core.editor=:",
    "-c",
    "sequence.editor=:",
)


def raw_git(
    cwd: Path,
    args: Sequence[str],
    *,
    check: bool,
    text: bool,
    environment: Mapping[str, str] | None,
    input_data: str | bytes | None,
    executable: Callable[[], Path],
    base_arguments: Callable[[], Sequence[str]],
    command_call: Callable[[], Callable[..., object]],
) -> object:
    return command_call()(
        (str(executable()), *base_arguments(), *args),
        cwd=cwd,
        check=check,
        text=text,
        environment=environment,
        input_data=input_data,
    )


def authenticated_git(
    cwd: Path,
    args: Sequence[str],
    *,
    check: bool,
    text: bool,
    environment: Mapping[str, str] | None,
    input_data: str | bytes | None,
    authenticate_cwd: Callable[[], Callable[[Path], None]],
    validate_configuration: Callable[[], Callable[[Path], None]],
    harden_arguments: Callable[[], Callable[[Sequence[str]], list[str]]],
    raw_git_call: Callable[[], Callable[..., object]],
) -> object:
    authenticate_cwd()(cwd)
    validate_configuration()(cwd)
    return raw_git_call()(
        cwd,
        *harden_arguments()(args),
        check=check,
        text=text,
        environment=environment,
        input_data=input_data,
    )


def absolute_git_path(
    cwd: Path,
    selector: str,
    *,
    git_call: Callable[[], Callable[..., object]],
    path_factory: Callable[[], Callable[[str], Path]],
) -> Path:
    """Resolve one absolute path reported by authenticated Git."""

    value = git_call()(
        cwd,
        "rev-parse",
        "--path-format=absolute",
        selector,
    ).stdout.strip()
    return path_factory()(value).resolve()


def discover_git_executable(
    *,
    executable_locator: Callable[
        [],
        Callable[[str], str | None],
    ],
    path_factory: Callable[
        [],
        Callable[[str], Path],
    ],
    os_error_type: Callable[[], type[BaseException]],
    error_type: Callable[[], type[BaseException]],
    regular_file_test: Callable[[], Callable[[int], bool]],
    access_check: Callable[[], Callable[[Path, int], bool]],
    executable_mode: Callable[[], int],
) -> Path:
    """Find and validate the Git executable with lazy dependencies."""

    candidate = executable_locator()("git")
    if candidate is None:
        raise error_type()("cannot find the Git executable")
    try:
        resolved = path_factory()(candidate).resolve(strict=True)
        metadata = resolved.stat()
    except os_error_type() as exc:
        raise error_type()("cannot resolve the Git executable") from exc
    if (
        not regular_file_test()(metadata.st_mode)
        or not access_check()(resolved, executable_mode())
    ):
        raise error_type()(
            "the resolved Git executable is not a regular executable file"
        )
    return resolved


def sanitized_git_environment(
    source: Mapping[str, str],
    *,
    unsafe_names: Collection[str] = GIT_UNSAFE_ENV,
    indexed_config_pattern: re.Pattern[str] = GIT_INDEXED_CONFIG_ENV_RE,
) -> dict[str, str]:
    environment = dict(source)
    for name in list(environment):
        if (
            name in unsafe_names
            or indexed_config_pattern.fullmatch(name)
            or name.startswith("GIT_TEST_")
            or name.startswith("GIT_TRACE")
        ):
            environment.pop(name, None)
    environment.pop("CDPATH", None)
    environment.pop("SSH_ASKPASS", None)
    environment.update(
        {
            "EDITOR": ":",
            "GIT_ATTR_GLOBAL": os.devnull,
            "GIT_ATTR_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_EDITOR": ":",
            "GIT_NO_REPLACE_OBJECTS": "1",
            "GIT_OPTIONAL_LOCKS": "1",
            "GIT_PAGER": "",
            "GIT_SEQUENCE_EDITOR": ":",
            "GIT_TERMINAL_PROMPT": "0",
            "VISUAL": ":",
        }
    )
    return environment


def hardened_git_arguments(args: Sequence[str]) -> list[str]:
    hardened = list(args)
    try:
        rebase_index = hardened.index("rebase")
    except ValueError:
        return hardened
    rebase_arguments = hardened[rebase_index + 1 :]
    administrative = {"--abort", "--continue", "--edit-todo", "--quit", "--skip"}
    if not administrative.intersection(rebase_arguments) and not any(
        argument in {"--no-gpg-sign", "--gpg-sign"}
        or argument.startswith("--gpg-sign=")
        for argument in rebase_arguments
    ):
        hardened.insert(rebase_index + 1, "--no-gpg-sign")
    return hardened


def validate_effective_git_configuration(
    output: bytes,
    *,
    error_type: Callable[[], type[BaseException]],
    boolean_values: Callable[[], Collection[str]],
    command_config_pattern: Callable[[], re.Pattern[str]],
) -> None:
    """Reject command-bearing values in one captured effective configuration."""

    effective: dict[str, str] = {}
    for record in output.split(b"\0"):
        if not record:
            continue
        raw_key, separator, raw_value = record.partition(b"\n")
        if not separator or not raw_key:
            raise error_type()("Git returned malformed effective configuration")
        key = raw_key.decode("utf-8", errors="surrogateescape").casefold()
        value = raw_value.decode("utf-8", errors="surrogateescape")
        effective[key] = value
    fsmonitor = effective.get("core.fsmonitor")
    if (
        fsmonitor is not None
        and fsmonitor.strip().casefold() not in boolean_values()
    ):
        raise error_type()(
            "unsafe command-bearing Git configuration 'core.fsmonitor'"
        )
    for key, value in effective.items():
        if command_config_pattern().fullmatch(key) and value.strip():
            raise error_type()(
                f"unsafe command-bearing Git configuration {key!r}"
            )
