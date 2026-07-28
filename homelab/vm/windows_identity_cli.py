#!/usr/bin/env python3
"""Run a prepared native Windows identity acceptance attempt."""

from __future__ import annotations

import argparse
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
import sys

from .bootstrap_dc import DEFAULT_STATE
from .controller_join_material import ControllerJoinResult
from .signal_cleanup import RunInterrupted, SignalGuard
from .windows_identity_orchestrator import (
    AcceptanceCallbacks,
    WindowsIdentityOrchestratorError,
    execute_windows_identity_acceptance,
)
from .windows_identity_progressive import ProgressiveRotationPlan
from .windows_identity_run import (
    NativeProcessBoundary,
    WindowsIdentityRunError,
)


@dataclass(frozen=True)
class AcceptanceConfiguration:
    """All exact, externally supplied facts for one production acceptance."""

    rotation_plan: ProgressiveRotationPlan
    publication: Path
    private_root: Path
    evidence: Path
    realm: str
    callbacks: AcceptanceCallbacks
    stage_principals: Callable[[dict[str, str]], None]
    destroy_principals: Callable[[tuple[str, ...]], None]
    stage_join_principal: Callable[[str], ControllerJoinResult]
    destroy_join_principal: Callable[[], ControllerJoinResult]


AcceptanceFactory = Callable[
    [NativeProcessBoundary], AcceptanceConfiguration]


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
    acceptance_factory: AcceptanceFactory | None = None,
) -> int:
    """Validate the boundary, then enter strict production acceptance."""
    boundary = NativeProcessBoundary(attempt, controller_state)
    boundary._validate()
    print("Boundary: loopback-only native Windows identity acceptance")
    print(f"Attempt: {boundary.attempt}")
    print(f"Controller state: {boundary.controller_state}")
    print("Installation ISO, PXE, host networking and UniFi: disabled")
    if not apply:
        print("dry run; repeat with --apply to run the identity lifecycle")
        return 0
    if acceptance_factory is None:
        raise WindowsIdentityRunError(
            "complete production acceptance adapters are unavailable; "
            "refusing applied identity run")
    configuration = acceptance_factory(boundary)
    with SignalGuard():
        execute_windows_identity_acceptance(
            boundary=boundary,
            rotation_plan=configuration.rotation_plan,
            publication=configuration.publication,
            private_root=configuration.private_root,
            evidence=configuration.evidence,
            realm=configuration.realm,
            callbacks=configuration.callbacks,
            stage_principals=configuration.stage_principals,
            destroy_principals=configuration.destroy_principals,
            stage_join_principal=configuration.stage_join_principal,
            destroy_join_principal=configuration.destroy_join_principal,
        )
    return 0


def main(
    argv: list[str] | None = None,
    *,
    acceptance_factory: AcceptanceFactory | None = None,
) -> int:
    args = parser().parse_args(argv)
    try:
        return run(
            args.attempt,
            controller_state=args.controller_state,
            apply=args.apply,
            acceptance_factory=acceptance_factory,
        )
    except RunInterrupted as error:
        print(f"windows identity run: {error}", file=sys.stderr)
        return error.exit_code
    except (WindowsIdentityRunError, WindowsIdentityOrchestratorError) as error:
        print(f"windows identity run: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
