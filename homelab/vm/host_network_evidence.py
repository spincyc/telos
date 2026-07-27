#!/usr/bin/env python3
"""Capture and compare host networking state around an isolated simulation."""

from __future__ import annotations

import json
import subprocess
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Sequence


ALLOWED_QEMU_PORTS = frozenset({12971, 12972})


@dataclass(frozen=True)
class Observation:
    command: tuple[str, ...]
    returncode: int
    stdout: str
    stderr: str


COMMANDS: tuple[tuple[str, ...], ...] = (
    ("ip", "-j", "-details", "link", "show"),
    ("ip", "-j", "address", "show"),
    ("ip", "-j", "route", "show", "table", "all"),
    ("ip", "-j", "-6", "route", "show", "table", "all"),
    ("bridge", "-j", "link", "show"),
    ("bridge", "-j", "vlan", "show"),
    ("ip", "netns", "list"),
    # --stateless omits counters that can legitimately advance during a test.
    ("nft", "-j", "--stateless", "list", "ruleset"),
    ("ss", "-H", "-lntup"),
)


def _run(command: Sequence[str]) -> Observation:
    try:
        result = subprocess.run(
            command, check=False, text=True, capture_output=True)
        return Observation(
            tuple(command), result.returncode,
            result.stdout.rstrip(), result.stderr.rstrip())
    except FileNotFoundError as error:
        return Observation(tuple(command), 127, "", str(error))


def capture() -> dict[str, object]:
    """Return complete, machine-readable evidence without changing the host."""
    return {
        "schema": 1,
        "captured_at": datetime.now(timezone.utc).isoformat(),
        "observations": [asdict(_run(command)) for command in COMMANDS],
    }


def write(evidence: dict[str, object], destination: Path) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(
        json.dumps(evidence, indent=2, sort_keys=True) + "\n",
        encoding="utf-8")
    destination.chmod(0o600)


def _observations(evidence: dict[str, object]) -> dict[tuple[str, ...], dict]:
    result = {}
    for item in evidence.get("observations", []):
        command = tuple(item["command"])
        result[command] = item
    return result


def _invalid_evidence(evidence: dict[str, object], label: str) -> list[str]:
    """Return reasons a snapshot cannot be trusted as evidence."""
    violations: list[str] = []
    if evidence.get("schema") != 1:
        violations.append(f"{label} evidence has an unsupported schema")
    items = evidence.get("observations")
    if not isinstance(items, list):
        violations.append(f"{label} evidence has no observation list")
        return violations
    commands: list[tuple[str, ...]] = []
    for item in items:
        if not isinstance(item, dict):
            violations.append(f"{label} evidence contains a malformed observation")
            continue
        raw_command = item.get("command")
        if (not isinstance(raw_command, (list, tuple))
                or not all(isinstance(part, str) for part in raw_command)):
            violations.append(f"{label} evidence contains a malformed command")
            continue
        command = tuple(raw_command)
        commands.append(command)
        if not isinstance(item.get("stdout"), str) or \
                not isinstance(item.get("stderr"), str):
            violations.append(
                f"{label} command has malformed output: " + " ".join(command))
        if item.get("returncode") != 0:
            violations.append(
                f"{label} command failed ({item.get('returncode')}): "
                + " ".join(command))
    required = set(COMMANDS)
    observed = set(commands)
    for command in sorted(required - observed):
        violations.append(
            f"{label} evidence is missing command: " + " ".join(command))
    for command in sorted(observed - required):
        violations.append(
            f"{label} evidence has unexpected command: " + " ".join(command))
    if len(commands) != len(observed):
        violations.append(f"{label} evidence contains duplicate commands")
    return violations


def _socket_lines(item: dict) -> set[str]:
    return {line.strip() for line in item["stdout"].splitlines() if line.strip()}


def _allowed_socket(line: str, allowed_ports: frozenset[int]) -> bool:
    fields = line.split()
    if len(fields) < 5 or fields[0] != "tcp" or fields[1] != "LISTEN":
        return False
    local = fields[4]
    return any(
        local in {f"127.0.0.1:{port}", f"[::ffff:127.0.0.1]:{port}"}
        for port in allowed_ports
    )


def _socket_port(line: str) -> int | None:
    fields = line.split()
    if len(fields) < 5:
        return None
    local = fields[4]
    try:
        return int(local.rsplit(":", 1)[1])
    except (IndexError, ValueError):
        return None


def compare(
    before: dict[str, object],
    after: dict[str, object],
    *,
    allow_qemu_listeners: bool = False,
    allowed_ports: frozenset[int] = ALLOWED_QEMU_PORTS,
) -> list[str]:
    """Return invariant violations; an empty result means the host is unchanged."""
    violations = _invalid_evidence(before, "before")
    violations.extend(_invalid_evidence(after, "comparison"))
    if violations:
        return violations
    left = _observations(before)
    right = _observations(after)
    if set(left) != set(right):
        violations.append("the evidence command set changed")
        return violations

    socket_command = ("ss", "-H", "-lntup")
    for command in sorted(left):
        old = left[command]
        new = right[command]
        if command == socket_command and allow_qemu_listeners:
            if old["returncode"] != new["returncode"] or \
                    old["stderr"] != new["stderr"]:
                violations.append("socket observation status changed")
                continue
            added = _socket_lines(new) - _socket_lines(old)
            removed = _socket_lines(old) - _socket_lines(new)
            bad = sorted(
                line for line in added
                if not _allowed_socket(line, allowed_ports))
            observed_ports = {
                port for line in added
                if (port := _socket_port(line)) is not None
                and _allowed_socket(line, allowed_ports)
            }
            allowed_lines = [
                line for line in added
                if _allowed_socket(line, allowed_ports)
            ]
            if removed:
                violations.append(
                    "pre-existing listening sockets disappeared: "
                    + " | ".join(sorted(removed)))
            if bad:
                violations.append(
                    "unexpected listening sockets appeared: " + " | ".join(bad))
            if (observed_ports != set(allowed_ports)
                    or len(allowed_lines) != len(allowed_ports)):
                violations.append(
                    "allowed listener set did not match: expected "
                    + ",".join(str(port) for port in sorted(allowed_ports))
                    + "; observed "
                    + ",".join(str(port) for port in sorted(observed_ports)))
            continue
        for field in ("returncode", "stdout", "stderr"):
            if old[field] != new[field]:
                violations.append(
                    f"{' '.join(command)} changed field {field}")
    return violations


def assert_unchanged(
    before: dict[str, object],
    after: dict[str, object],
    *,
    allow_qemu_listeners: bool = False,
) -> None:
    violations = compare(
        before, after, allow_qemu_listeners=allow_qemu_listeners)
    if violations:
        raise RuntimeError(
            "host network invariants failed:\n- " + "\n- ".join(violations))


def compare_cycle(
    before: dict[str, object],
    during: dict[str, object],
    after: dict[str, object],
    *,
    allowed_ports: frozenset[int] = ALLOWED_QEMU_PORTS,
) -> list[str]:
    """Judge both the live simulation boundary and complete cleanup."""
    violations = [
        f"during simulation: {item}" for item in compare(
            before, during, allow_qemu_listeners=True,
            allowed_ports=allowed_ports)
    ]
    violations.extend(
        f"after simulation: {item}" for item in compare(before, after))
    return violations
