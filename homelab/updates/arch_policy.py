#!/usr/bin/env python3
"""Evaluate the safe gates for an automatic Arch full-system upgrade."""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
from dataclasses import asdict, dataclass
from datetime import datetime
from pathlib import Path


@dataclass(frozen=True)
class GateReport:
    ac_power: bool
    free_bytes: int
    internet: bool
    pacman_idle: bool
    allowed: bool
    reasons: tuple[str, ...]


def on_ac(power_root: Path = Path("/sys/class/power_supply")) -> bool:
    mains = list(power_root.glob("*/online"))
    if not mains:
        return True
    return any(path.read_text().strip() == "1" for path in mains)


def internet_reachable(timeout: int = 15) -> bool:
    command = ["curl", "--fail", "--silent", "--head", "--max-time", str(timeout),
               "https://geo.mirror.pkgbuild.com/core/os/x86_64/core.db"]
    return subprocess.run(command, check=False).returncode == 0


def evaluate(
    *,
    minimum_free_bytes: int = 8 * 1024**3,
    root: Path = Path("/"),
    power_root: Path = Path("/sys/class/power_supply"),
    lock: Path = Path("/var/lib/pacman/db.lck"),
    probe_internet: bool = True,
) -> GateReport:
    ac = on_ac(power_root)
    free = shutil.disk_usage(root).free
    online = internet_reachable() if probe_internet else True
    idle = not lock.exists()
    reasons = []
    if not ac:
        reasons.append("battery power")
    if free < minimum_free_bytes:
        reasons.append("less than required free space")
    if not online:
        reasons.append("official Arch mirror unavailable")
    if not idle:
        reasons.append("another pacman transaction is active")
    return GateReport(ac, free, online, idle, not reasons, tuple(reasons))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--minimum-free-gib", type=int, default=8)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    report = evaluate(minimum_free_bytes=args.minimum_free_gib * 1024**3)
    if args.json:
        print(json.dumps({**asdict(report), "checked_at": datetime.now().astimezone().isoformat()}))
    else:
        print("ready" if report.allowed else "deferred: " + ", ".join(report.reasons))
    return 0 if report.allowed else 75


if __name__ == "__main__":
    raise SystemExit(main())
