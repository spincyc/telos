#!/usr/bin/env python3
"""Run a prepared native Windows identity acceptance attempt."""

from __future__ import annotations

import argparse
from collections.abc import Callable
from pathlib import Path
import sys

from .bootstrap_dc import DEFAULT_STATE
from .signal_cleanup import RunInterrupted, SignalGuard
from .windows_identity_run import (
    IdentityOperations,
    NativeProcessBoundary,
    WindowsIdentityRunError,
    run_lifecycle,
)


OperationsFactory = Callable[
    [NativeProcessBoundary], IdentityOperations]


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("--attempt", type=Path, required=True)
    result.add_argument(
        "--controller-state", type=Path, default=DEFAULT_STATE)
    result.add_argument("--apply", action="store_true")
    return result


def run(
    attempt: Path,
    *,
    controller_state: Path,
    apply: bool,
    operations_factory: OperationsFactory | None = None,
) -> int:
    """Validate the boundary, then delegate an applied run to core lifecycle."""
    boundary = NativeProcessBoundary(attempt, controller_state)
    boundary._validate()
    print("Boundary: loopback-only native Windows identity acceptance")
    print(f"Attempt: {boundary.attempt}")
    print(f"Controller state: {boundary.controller_state}")
    print("Installation ISO, PXE, host networking and UniFi: disabled")
    if not apply:
        print("dry run; repeat with --apply to run the identity lifecycle")
        return 0
    if operations_factory is None:
        raise WindowsIdentityRunError(
            "live control adapter unavailable; refusing applied identity run")
    with SignalGuard():
        run_lifecycle(operations_factory(boundary))
    return 0


def main(
    argv: list[str] | None = None,
    *,
    operations_factory: OperationsFactory | None = None,
) -> int:
    args = parser().parse_args(argv)
    try:
        return run(
            args.attempt,
            controller_state=args.controller_state,
            apply=args.apply,
            operations_factory=operations_factory,
        )
    except RunInterrupted as error:
        print(f"windows identity run: {error}", file=sys.stderr)
        return error.exit_code
    except WindowsIdentityRunError as error:
        print(f"windows identity run: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
