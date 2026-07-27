"""Validation for bounded workstation installation profiles."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


class WorkstationProfileError(ValueError):
    """A profile violates the phase-1 workstation contract."""


def _value(data: dict[str, Any], path: str) -> Any:
    current: Any = data
    for part in path.split("."):
        if not isinstance(current, dict) or part not in current:
            return None
        current = current[part]
    return current


_REQUIRED_VALUES: tuple[tuple[str, object], ...] = (
    ("schema_version", 1),
    ("firmware.boot_mode", "uefi"),
    ("firmware.partition_table", "gpt"),
    ("firmware.secure_boot", False),
    ("operating_systems.windows.release", "11"),
    ("operating_systems.windows.edition", "Pro"),
    ("operating_systems.windows.default_boot", True),
    ("operating_systems.arch_linux.default_boot", False),
    ("boot_menu.timeout_seconds", 5),
    ("phase1_security.bitlocker", False),
    ("phase1_security.luks", False),
    ("phase1_security.tpm_enrollment", False),
    ("phase1_security.recovery_keys", False),
)


def validate_profile(data: Any) -> list[str]:
    """Return every phase-1 contract violation in deterministic order."""
    if not isinstance(data, dict):
        return ["profile must be a JSON object"]

    errors: list[str] = []
    profile_id = data.get("profile_id")
    if not isinstance(profile_id, str) or not profile_id.strip():
        errors.append("profile_id must be a non-empty string")

    for path, expected in _REQUIRED_VALUES:
        actual = _value(data, path)
        if type(actual) is not type(expected) or actual != expected:
            errors.append(f"{path} must be {expected!r}; got {actual!r}")

    migrations = data.get("future_migrations")
    if not isinstance(migrations, list):
        errors.append("future_migrations must be a list")
    else:
        features = {
            item.get("feature")
            for item in migrations
            if isinstance(item, dict) and item.get("status") == "deferred"
        }
        for feature in ("windows-bitlocker", "arch-luks", "secure-boot"):
            if feature not in features:
                errors.append(
                    f"future_migrations must record deferred {feature!r}"
                )
    return errors


def require_valid_profile(data: Any) -> dict[str, Any]:
    """Return a valid profile or raise with all violations."""
    errors = validate_profile(data)
    if errors:
        raise WorkstationProfileError("; ".join(errors))
    return data


def load_profile(path: str | Path) -> dict[str, Any]:
    """Load and validate a UTF-8 JSON profile."""
    with Path(path).open(encoding="utf-8") as handle:
        return require_valid_profile(json.load(handle))
