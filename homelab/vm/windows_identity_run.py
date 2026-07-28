#!/usr/bin/env python3
"""Ordered, fail-closed lifecycle for native Windows identity acceptance."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable


class WindowsIdentityRunError(RuntimeError):
    """The native identity lifecycle did not reach a safe terminal state."""


@dataclass
class IdentityOperations:
    """Secret-owning operations supplied by the native runner adapter."""

    start_switch: Callable[[], None]
    start_controller: Callable[[], None]
    start_windows: Callable[[], None]
    authenticate_qmp: Callable[[], None]
    rotate_local_credential: Callable[[], None]
    destroy_private_publication: Callable[[], None]
    stage_controller_principals: Callable[[], None]
    run_acceptance_phases: Callable[[], None]
    destroy_controller_principals: Callable[[], None]
    stop_windows: Callable[[], None]
    stop_controller: Callable[[], None]
    stop_switch: Callable[[], None]


@dataclass
class IdentityReceipt:
    """Secret-free lifecycle facts retained by the caller."""

    phases: list[str] = field(default_factory=list)
    local_credential_rotated: bool = False
    private_publication_destroyed: bool = False
    controller_principals_staged: bool = False
    controller_principals_destroyed: bool = False
    teardown_complete: bool = False


def run_lifecycle(operations: IdentityOperations) -> IdentityReceipt:
    """Run identity proof in the only ordering that may consume credentials."""
    receipt = IdentityReceipt()
    started: list[str] = []
    primary_error: BaseException | None = None
    cleanup_errors: list[str] = []
    try:
        operations.start_switch()
        started.append("switch")
        receipt.phases.append("switch-started")
        operations.start_controller()
        started.append("controller")
        receipt.phases.append("controller-started")
        operations.start_windows()
        started.append("windows")
        receipt.phases.append("windows-started")
        operations.authenticate_qmp()
        receipt.phases.append("qmp-authenticated")
        operations.rotate_local_credential()
        receipt.local_credential_rotated = True
        receipt.phases.append("local-credential-rotated")
        operations.destroy_private_publication()
        receipt.private_publication_destroyed = True
        receipt.phases.append("private-publication-destroyed")
        operations.stage_controller_principals()
        receipt.controller_principals_staged = True
        receipt.phases.append("controller-principals-staged")
        operations.run_acceptance_phases()
        receipt.phases.append("acceptance-complete")
    except BaseException as error:
        primary_error = error
    finally:
        if receipt.controller_principals_staged:
            try:
                operations.destroy_controller_principals()
                receipt.controller_principals_destroyed = True
                receipt.phases.append("controller-principals-destroyed")
            except BaseException as error:
                cleanup_errors.append(
                    f"controller principal destruction: {type(error).__name__}")
        for role, stop in (
            ("windows", operations.stop_windows),
            ("controller", operations.stop_controller),
            ("switch", operations.stop_switch),
        ):
            if role not in started:
                continue
            try:
                stop()
                receipt.phases.append(f"{role}-stopped")
            except BaseException as error:
                cleanup_errors.append(f"{role} teardown: {type(error).__name__}")
        receipt.teardown_complete = not cleanup_errors
    if primary_error is not None or cleanup_errors:
        details = []
        if primary_error is not None:
            details.append(f"lifecycle: {type(primary_error).__name__}")
        details.extend(cleanup_errors)
        raise WindowsIdentityRunError(
            "native identity lifecycle failed; " + "; ".join(details))
    required = (
        receipt.local_credential_rotated,
        receipt.private_publication_destroyed,
        receipt.controller_principals_staged,
        receipt.controller_principals_destroyed,
        receipt.teardown_complete,
    )
    if not all(required):
        raise WindowsIdentityRunError(
            "native identity lifecycle ended without complete destruction proof")
    return receipt
