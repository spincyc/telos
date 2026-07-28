#!/usr/bin/env python3
"""Production composition for progressive Windows identity acceptance."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Mapping

from .windows_identity_progressive import (
    NativeBoundaryRotationSession,
    ProgressiveRotationPlan,
    ProgressiveRotationReceipt,
    execute_progressive_rotation,
)
from .windows_identity_run import (
    NativeProcessBoundary,
    PrivateIdentityMaterial,
    WindowsIdentityRunError,
)


@dataclass(frozen=True)
class ProductionIdentityReceipt:
    """Secret-free proof that rotation and dependent acceptance completed."""

    rotation: ProgressiveRotationReceipt
    acceptance_complete: bool
    credentials_released: bool


def execute_production_identity_acceptance(
    *,
    boundary: NativeProcessBoundary,
    plan: ProgressiveRotationPlan,
    publication: Path,
    private_parent: Path,
    stage_principals: Callable[[dict[str, str]], None],
    destroy_principals: Callable[[tuple[str, ...]], None],
    run_acceptance: Callable[[str, Mapping[str, str]], None],
) -> ProductionIdentityReceipt:
    """Compose native rotation and acceptance under one credential owner.

    ``run_acceptance`` is the deliberate private-data boundary.  It receives
    the replacement local credential and a read-only disposable-principal
    mapping only while the native session and ``PrivateIdentityMaterial`` are
    alive.  No credential is included in the returned receipt or an error.
    """
    material = PrivateIdentityMaterial(
        publication,
        private_parent,
        rotate_guest=lambda _old, _new: (_ for _ in ()).throw(
            WindowsIdentityRunError(
                "legacy rotation callback is unavailable")),
        stage_principals=stage_principals,
        destroy_principals=destroy_principals,
    )
    acceptance_complete = False

    def accept(replacement: str) -> None:
        nonlocal acceptance_complete
        material.run_scoped_acceptance(
            replacement,
            lambda local, principals: run_acceptance(local, principals),
        )
        acceptance_complete = True

    try:
        rotation = execute_progressive_rotation(
            plan=plan,
            session=NativeBoundaryRotationSession(boundary),
            recovery=material.recovery,
            generate_credential=material.generate_replacement_credential,
            after_rotation=accept,
        )
    except (KeyboardInterrupt, SystemExit):
        raise
    except Exception as error:
        controller_destroyed = (
            boundary.controller_overlay is None
            and "controller" not in boundary.processes
        )
        try:
            material.close(controller_destroyed=controller_destroyed)
        except Exception as cleanup:
            raise WindowsIdentityRunError(
                "production identity acceptance and private cleanup failed: "
                f"{type(error).__name__}; {type(cleanup).__name__}"
            ) from None
        raise
    material.close()
    if not acceptance_complete:
        raise WindowsIdentityRunError(
            "production identity acceptance did not complete")
    return ProductionIdentityReceipt(
        rotation=rotation,
        acceptance_complete=True,
        credentials_released=True,
    )
