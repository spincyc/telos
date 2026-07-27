"""Bounded child cleanup and temporary signal handling for VM runners."""

from __future__ import annotations

import signal
import subprocess
from collections.abc import Iterable
from types import FrameType


HANDLED_SIGNALS = (signal.SIGINT, signal.SIGTERM, signal.SIGHUP)


class RunInterrupted(RuntimeError):
    """An operator or supervisor asked the runner to stop."""

    def __init__(self, signum: int):
        self.signum = signum
        super().__init__(f"interrupted by {signal.Signals(signum).name}")

    @property
    def exit_code(self) -> int:
        return 128 + self.signum


class SignalGuard:
    """Turn termination signals into exceptions so ``finally`` always runs."""

    def __init__(self) -> None:
        self._previous: dict[int, signal.Handlers] = {}
        self._interrupted = False

    def __enter__(self) -> SignalGuard:
        for signum in HANDLED_SIGNALS:
            self._previous[signum] = signal.getsignal(signum)
            signal.signal(signum, self._handle)
        return self

    def __exit__(self, *_exc: object) -> None:
        for signum, handler in self._previous.items():
            signal.signal(signum, handler)
        self._previous.clear()

    def _handle(self, signum: int, _frame: FrameType | None) -> None:
        # Once unwinding begins, do not let a repeated signal interrupt the
        # evidence and child-reaping ``finally`` block.
        if self._interrupted:
            return
        self._interrupted = True
        raise RunInterrupted(signum)


def terminate_children(
    children: Iterable[subprocess.Popen[bytes]],
    *,
    terminate_timeout: float = 5.0,
    kill_timeout: float = 2.0,
) -> list[str]:
    """Stop children in reverse order without an unbounded wait.

    Returns diagnostics rather than aborting early, allowing callers to write
    final evidence even when a child cannot be reaped.
    """
    processes = list(children)
    diagnostics: list[str] = []
    for child in reversed(processes):
        if child.poll() is None:
            try:
                child.terminate()
            except OSError as error:
                diagnostics.append(
                    f"cannot terminate child {child.pid}: {error}")
    for child in reversed(processes):
        try:
            child.wait(timeout=terminate_timeout)
            continue
        except subprocess.TimeoutExpired:
            pass
        try:
            child.kill()
        except OSError as error:
            diagnostics.append(f"cannot kill child {child.pid}: {error}")
            continue
        try:
            child.wait(timeout=kill_timeout)
        except subprocess.TimeoutExpired:
            diagnostics.append(
                f"child {child.pid} survived SIGKILL for {kill_timeout:g}s")
    return diagnostics
