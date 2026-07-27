"""Bounded GPT layout planning for dual-boot workstations."""

from __future__ import annotations

from dataclasses import asdict, dataclass
import argparse
import hashlib
import json
from pathlib import Path
from typing import Any, Mapping

try:
    from lib.workstation_profile import load_profile as load_workstation_profile
except ModuleNotFoundError:  # Direct invocation from the repository root.
    from homelab.lib.workstation_profile import load_profile as load_workstation_profile

MIB = 1024**2
GIB = 1024**3

ESP_MIB = 1024
MSR_MIB = 16
GPT_MARGIN_MIB = 2
DEFAULT_RECOVERY_MIB = 2048
MIN_WINDOWS_MIB = 160 * 1024
MIN_ARCH_MIB = 64 * 1024
MIN_WINDOWS_PERCENT = 50
MAX_WINDOWS_PERCENT = 90
MIN_RECOVERY_MIB = 1024
MAX_RECOVERY_MIB = 8192


class LayoutError(ValueError):
    """The requested disk layout cannot be made safely."""


@dataclass(frozen=True)
class Partition:
    number: int
    name: str
    type: str
    size_mib: int


@dataclass(frozen=True)
class LayoutPlan:
    disk_mib: int
    allocated_mib: int
    unallocated_mib: int
    mode: str
    windows_percent: int | None
    partitions: tuple[Partition, ...]

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


def load_profile(path: str | Path) -> dict[str, Any]:
    with Path(path).open(encoding="utf-8") as source:
        profile = json.load(source)
    if not isinstance(profile, dict):
        raise LayoutError("layout profile must be a JSON object")
    return profile


def _integer(config: Mapping[str, Any], key: str, default: int | None = None) -> int:
    value = config.get(key, default)
    if isinstance(value, bool) or not isinstance(value, int):
        raise LayoutError(f"{key} must be an integer")
    return value


def plan_layout(
    disk_bytes: int, config: Mapping[str, Any] | None = None
) -> LayoutPlan:
    """Return a MiB-aligned plan without touching the disk."""

    if isinstance(disk_bytes, bool) or not isinstance(disk_bytes, int):
        raise LayoutError("disk_bytes must be an integer")
    if disk_bytes <= 0:
        raise LayoutError("disk_bytes must be positive")

    settings = dict(config or {})
    mode = settings.get("mode", "ratio")
    if mode not in {"ratio", "fixed"}:
        raise LayoutError("mode must be ratio or fixed")

    recovery_mib = _integer(settings, "recovery_mib", DEFAULT_RECOVERY_MIB)
    if not MIN_RECOVERY_MIB <= recovery_mib <= MAX_RECOVERY_MIB:
        raise LayoutError(
            f"recovery_mib must be {MIN_RECOVERY_MIB}..{MAX_RECOVERY_MIB}"
        )

    disk_mib = disk_bytes // MIB
    fixed_mib = ESP_MIB + MSR_MIB + recovery_mib + GPT_MARGIN_MIB
    available_mib = disk_mib - fixed_mib
    if available_mib < MIN_WINDOWS_MIB + MIN_ARCH_MIB:
        required = fixed_mib + MIN_WINDOWS_MIB + MIN_ARCH_MIB
        raise LayoutError(
            f"disk is too small: {disk_mib} MiB available, {required} MiB required"
        )

    windows_percent: int | None
    if mode == "ratio":
        unknown = set(settings) - {
            "$schema",
            "mode",
            "windows_percent",
            "recovery_mib",
        }
        if unknown:
            raise LayoutError(f"unknown ratio setting: {sorted(unknown)[0]}")
        windows_percent = _integer(settings, "windows_percent", 75)
        if not MIN_WINDOWS_PERCENT <= windows_percent <= MAX_WINDOWS_PERCENT:
            raise LayoutError(
                f"windows_percent must be "
                f"{MIN_WINDOWS_PERCENT}..{MAX_WINDOWS_PERCENT}"
            )
        surplus_mib = available_mib - MIN_WINDOWS_MIB - MIN_ARCH_MIB
        windows_mib = (
            MIN_WINDOWS_MIB + surplus_mib * windows_percent // 100
        )
        arch_mib = available_mib - windows_mib
    else:
        unknown = set(settings) - {
            "mode",
            "windows_gib",
            "arch_gib",
            "recovery_mib",
            "leftover",
            "$schema",
        }
        if unknown:
            raise LayoutError(f"unknown fixed setting: {sorted(unknown)[0]}")
        if settings.get("leftover") != "unallocated":
            raise LayoutError("fixed layouts must set leftover to 'unallocated'")
        windows_percent = None
        windows_mib = _integer(settings, "windows_gib") * 1024
        arch_mib = _integer(settings, "arch_gib") * 1024
        if windows_mib + arch_mib > available_mib:
            raise LayoutError("fixed Windows and Arch sizes exceed the disk")

    if windows_mib < MIN_WINDOWS_MIB:
        raise LayoutError("Windows partition would be smaller than 160 GiB")
    if arch_mib < MIN_ARCH_MIB:
        raise LayoutError("Arch partition would be smaller than 64 GiB")

    partitions = (
        Partition(1, "EFI system", "esp", ESP_MIB),
        Partition(2, "Microsoft reserved", "msr", MSR_MIB),
        Partition(3, "Windows 11", "basic-data", windows_mib),
        Partition(4, "Arch Linux", "linux-root", arch_mib),
        Partition(5, "Windows recovery", "windows-recovery", recovery_mib),
    )
    allocated_mib = sum(item.size_mib for item in partitions)
    return LayoutPlan(
        disk_mib=disk_mib,
        allocated_mib=allocated_mib,
        unallocated_mib=disk_mib - GPT_MARGIN_MIB - allocated_mib,
        mode=mode,
        windows_percent=windows_percent,
        partitions=partitions,
    )


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def build_record(
    disk_bytes: int,
    layout_path: Path,
    workstation_path: Path,
) -> dict[str, Any]:
    """Validate both profiles and return one machine-readable decision record."""
    workstation = load_workstation_profile(workstation_path)
    plan = plan_layout(disk_bytes, load_profile(layout_path))
    return {
        "schema_version": 1,
        "workstation_profile_id": workstation["profile_id"],
        "disk_bytes": disk_bytes,
        "sources": {
            "layout_profile": {
                "path": str(layout_path),
                "sha256": _sha256(layout_path),
            },
            "workstation_profile": {
                "path": str(workstation_path),
                "sha256": _sha256(workstation_path),
            },
        },
        "boot_contract": {
            "firmware": workstation["firmware"],
            "operating_systems": workstation["operating_systems"],
            "boot_menu": workstation["boot_menu"],
        },
        "phase1_security": workstation["phase1_security"],
        "layout": plan.as_dict(),
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Print a bounded dual-boot GPT plan; never touch a disk"
    )
    parser.add_argument("--disk-bytes", type=int, required=True)
    parser.add_argument("--profile", type=Path, required=True)
    parser.add_argument(
        "--workstation-profile",
        type=Path,
        help="validate boot/security policy and include it in the record",
    )
    parser.add_argument(
        "--record",
        type=Path,
        help="write the validated combined record instead of printing it",
    )
    arguments = parser.parse_args()
    if arguments.record and not arguments.workstation_profile:
        parser.error("--record requires --workstation-profile")
    if arguments.workstation_profile:
        result = build_record(
            arguments.disk_bytes,
            arguments.profile,
            arguments.workstation_profile,
        )
    else:
        result = plan_layout(
            arguments.disk_bytes, load_profile(arguments.profile)
        ).as_dict()
    rendered = json.dumps(result, indent=2) + "\n"
    if arguments.record:
        arguments.record.parent.mkdir(parents=True, exist_ok=True)
        arguments.record.write_text(rendered, encoding="utf-8")
    else:
        print(rendered, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
