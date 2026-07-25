"""Installed command-line interface for Worktree Marshal."""

from __future__ import annotations

import os
import shutil
import stat
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Sequence

from . import __version__
from .profiles import BUILTIN_PROFILES


HELP = """usage: worktree-marshal --profile PROFILE COMMAND [ARGUMENTS...]
       worktree-marshal --help
       worktree-marshal --version

Profiles:
  generic-v1  Worktree Marshal's isolated generic lifecycle
  triptych    explicit compatibility access to Triptych schema 1

Commands:
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

Every stateful invocation requires exactly one case-sensitive --profile before
the command. The retire command is a destructive direct-only operation and has
no Make wrapper.
"""


class UsageError(Exception):
    """A command line is invalid before lifecycle state may be inspected."""


@dataclass(frozen=True)
class ParsedCommand:
    profile_id: str
    command: str
    run_id: str | None = None
    agent_arguments: tuple[str, ...] = ()
    agent_delimiter: bool = False
    discard_head: str | None = None
    target_contains: str | None = None


def usage_error(message: str) -> None:
    print(f"worktree-marshal: {message}", file=sys.stderr)


def parse_arguments(arguments: Sequence[str]) -> ParsedCommand:
    argv = list(arguments)
    if not argv:
        raise UsageError(
            "a stateful command requires --profile generic-v1 or --profile triptych"
        )
    if argv[0] != "--profile":
        raise UsageError(
            "a stateful command must begin with --profile generic-v1 or "
            "--profile triptych"
        )
    if len(argv) < 2:
        raise UsageError("--profile requires a value")
    profile_id = argv[1]
    if profile_id not in BUILTIN_PROFILES:
        raise UsageError(f"unknown profile {profile_id!r}")
    if len(argv) < 3:
        raise UsageError("--profile must be followed by a command")

    command = argv[2]
    operands = argv[3:]
    if command == "run":
        if operands[:2] != ["--agent", "codex"]:
            raise UsageError("run requires exactly --agent codex before agent arguments")
        forwarded = operands[2:]
        delimiter = bool(forwarded)
        if forwarded and forwarded[0] != "--":
            raise UsageError("Codex arguments after run require a -- delimiter")
        if forwarded:
            forwarded = forwarded[1:]
        return ParsedCommand(
            profile_id=profile_id,
            command=command,
            agent_arguments=tuple(forwarded),
            agent_delimiter=delimiter,
        )

    if command == "status":
        if len(operands) > 1:
            raise UsageError("status accepts at most one run ID")
        return ParsedCommand(
            profile_id=profile_id,
            command=command,
            run_id=operands[0] if operands else None,
        )

    if command == "reopen":
        if not operands:
            raise UsageError("reopen requires exactly one run ID")
        run_id = operands[0]
        forwarded = operands[1:]
        delimiter = bool(forwarded)
        if forwarded and forwarded[0] != "--":
            raise UsageError("Codex arguments after reopen require a -- delimiter")
        if forwarded:
            forwarded = forwarded[1:]
        return ParsedCommand(
            profile_id=profile_id,
            command=command,
            run_id=run_id,
            agent_arguments=tuple(forwarded),
            agent_delimiter=delimiter,
        )

    lifecycle_commands = {
        "abort",
        "clean",
        "continue",
        "final-diff",
        "integrate",
        "resolve",
    }
    if command in lifecycle_commands:
        if len(operands) != 1:
            raise UsageError(f"{command} requires exactly one run ID")
        return ParsedCommand(
            profile_id=profile_id,
            command=command,
            run_id=operands[0],
        )

    if command == "retire":
        if (
            len(operands) != 5
            or operands[1] != "--discard-head"
            or operands[3] != "--target-contains"
        ):
            raise UsageError(
                "retire requires exactly RUN_ID --discard-head FULL_OID "
                "--target-contains FULL_OID"
            )
        return ParsedCommand(
            profile_id=profile_id,
            command=command,
            run_id=operands[0],
            discard_head=operands[2],
            target_contains=operands[4],
        )

    raise UsageError(f"unknown command {command!r}")


def resolve_invocation_path(invocation_path: Path | str | None) -> Path:
    explicit = invocation_path is not None
    raw = os.fspath(invocation_path) if explicit else sys.argv[0]
    if not raw:
        raise UsageError("cannot authenticate the worktree-marshal executable")
    supplied = Path(raw)
    has_separator = os.sep in raw or (os.altsep is not None and os.altsep in raw)
    if explicit or supplied.is_absolute() or has_separator:
        candidate = supplied if supplied.is_absolute() else Path.cwd() / supplied
    else:
        located = shutil.which(raw)
        if located is None:
            raise UsageError("cannot authenticate the worktree-marshal executable")
        candidate = Path(located)
    try:
        resolved = candidate.resolve(strict=True)
        metadata = resolved.stat()
    except (OSError, RuntimeError) as exc:
        raise UsageError("cannot authenticate the worktree-marshal executable") from exc
    if not stat.S_ISREG(metadata.st_mode) or not os.access(resolved, os.X_OK):
        raise UsageError("the worktree-marshal entry point is not a usable executable")
    return resolved


def engine_arguments(command: ParsedCommand) -> list[str]:
    if command.command == "run":
        return list(command.agent_arguments)
    if command.command == "status":
        arguments = ["--triptych-status"]
        if command.run_id is not None:
            arguments.append(command.run_id)
        return arguments
    if command.command == "reopen":
        if command.run_id is None:
            raise AssertionError("parsed reopen command has no run ID")
        arguments = ["--triptych-reopen", command.run_id]
        if command.agent_delimiter:
            arguments.append("--")
            arguments.extend(command.agent_arguments)
        return arguments
    if command.command == "retire":
        if (
            command.run_id is None
            or command.discard_head is None
            or command.target_contains is None
        ):
            raise AssertionError("parsed retire command is incomplete")
        return [
            "--triptych-retire",
            command.run_id,
            "--discard-head",
            command.discard_head,
            "--target-contains",
            command.target_contains,
        ]
    if command.run_id is None:
        raise AssertionError("parsed lifecycle command has no run ID")
    return [f"--triptych-{command.command}", command.run_id]


def dispatch(command: ParsedCommand, *, invocation_path: Path) -> int:
    arguments = engine_arguments(command)
    if command.profile_id == "triptych":
        from . import triptych_compat

        return triptych_compat.main(
            arguments,
            invocation_path=invocation_path,
        )

    from . import engine

    return engine.main(
        arguments,
        invocation_path=invocation_path,
        profile=BUILTIN_PROFILES[command.profile_id],
    )


def main(
    arguments: Sequence[str] | None = None,
    *,
    invocation_path: Path | str | None = None,
) -> int:
    argv = list(sys.argv[1:] if arguments is None else arguments)
    if argv == ["--help"]:
        print(HELP, end="")
        return 0
    if argv == ["--version"]:
        print(f"worktree-marshal {__version__}")
        return 0
    try:
        command = parse_arguments(argv)
        authenticated_path = resolve_invocation_path(invocation_path)
    except UsageError as exc:
        usage_error(str(exc))
        return 2
    return dispatch(command, invocation_path=authenticated_path)


if __name__ == "__main__":
    raise SystemExit(main())
