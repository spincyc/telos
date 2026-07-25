"""Frozen Triptych schema-1 entry point for the shared lifecycle engine."""

from __future__ import annotations

from pathlib import Path
from typing import Sequence

from . import engine
from .profiles import TRIPTYCH_PROFILE


def main(
    arguments: Sequence[str] | None = None,
    *,
    invocation_path: Path,
) -> int:
    return engine.main(
        arguments,
        invocation_path=invocation_path,
        profile=TRIPTYCH_PROFILE,
    )


def launcher_help() -> str:
    return engine.launcher_help()
