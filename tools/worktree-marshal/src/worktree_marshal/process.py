"""Dependency-injected child-process supervision and status normalization."""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from pathlib import Path
from typing import Protocol


def command(
    argv: Sequence[str],
    *,
    cwd: Path,
    check: bool,
    text: bool,
    environment: Mapping[str, str] | None,
    input_data: str | bytes | None,
    base_environment: Callable[[], Mapping[str, str]],
    sanitize_environment: Callable[
        [],
        Callable[[dict[str, str]], dict[str, str]],
    ],
    process_run: Callable[[], Callable[..., object]],
    inherited_descriptors: Callable[[], tuple[int, ...]],
    filesystem_path: Callable[[], Callable[[object], str]],
    error_type: Callable[[], type[BaseException]],
) -> object:
    """Run one command with a sanitized environment and inherited lock FDs."""

    command_environment = dict(base_environment())
    if environment:
        command_environment.update(environment)
    command_environment = sanitize_environment()(command_environment)
    result = process_run()(
        list(argv),
        cwd=cwd,
        env=command_environment,
        check=False,
        capture_output=True,
        text=text,
        input=input_data,
        pass_fds=inherited_descriptors(),
    )
    if check and result.returncode:
        stderr = (
            result.stderr.strip()
            if text
            else result.stderr.decode(errors="replace").strip()
        )
        rendered = " ".join(
            filesystem_path()(value) for value in argv
        )
        raise error_type()(
            f"{rendered} failed: {stderr or 'no diagnostic'}"
        )
    return result


class ChildProcess(Protocol):
    def poll(self) -> int | None: ...

    def send_signal(self, signum: int) -> None: ...

    def terminate(self) -> None: ...

    def wait(self, timeout: float | None = None) -> int: ...


def wait_for_child(
    process: ChildProcess,
    *,
    forwarded_signals: Callable[[], tuple[int, int]],
    get_signal_handler: Callable[[int], object],
    set_signal_handler: Callable[[int, object], object],
    interrupt_signal: Callable[[], int],
    keyboard_interrupt: Callable[[], type[BaseException]],
    process_lookup_error: Callable[[], type[BaseException]],
    timeout_expired: Callable[[], type[BaseException]],
) -> int:
    """Wait for one child while preserving the launcher's signal semantics."""

    forwarded_handlers: dict[int, object] = {}

    def forward(signum: int, _frame: object) -> None:
        if process.poll() is None:
            try:
                process.send_signal(signum)
            except process_lookup_error():
                pass

    for signum in forwarded_signals():
        forwarded_handlers[signum] = get_signal_handler(signum)
        set_signal_handler(signum, forward)
    try:
        try:
            return process.wait()
        except keyboard_interrupt():
            if process.poll() is None:
                try:
                    process.send_signal(interrupt_signal())
                except process_lookup_error():
                    pass
            try:
                return process.wait(timeout=10)
            except timeout_expired():
                process.terminate()
                return process.wait()
    finally:
        for signum, handler in forwarded_handlers.items():
            set_signal_handler(signum, handler)


def normalized_exit_status(
    returncode: int,
    *,
    absolute: Callable[[int], int] = abs,
) -> int:
    if returncode < 0:
        return 128 + absolute(returncode)
    return returncode
