#!/usr/bin/env python3
"""Durable, secret-free state for a one-use Windows identity attempt."""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
from pathlib import Path
from typing import Mapping


STATE_NAME = "attempt-consumed.json"
TEARDOWN_NAME = "terminal-teardown.json"


def _canonical(document: Mapping[str, object]) -> bytes:
    return (json.dumps(
        document, sort_keys=True, separators=(",", ":"),
    ) + "\n").encode("utf-8")


def _publish_once(path: Path, document: Mapping[str, object]) -> str:
    """Publish one fsynced private inode without replacing an existing claim."""
    data = _canonical(document)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "wb") as stream:
            descriptor = -1
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.link(temporary, path, follow_symlinks=False)
        directory = os.open(
            path.parent,
            os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_NOFOLLOW", 0),
        )
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        temporary.unlink(missing_ok=True)
    return hashlib.sha256(data).hexdigest()


def claim(attempt: Path) -> str:
    """Irrevocably mark a validated prepared attempt as consumed."""
    attempt = Path(attempt)
    if (attempt / STATE_NAME).exists() or (attempt / STATE_NAME).is_symlink():
        raise RuntimeError("Windows identity attempt was already consumed")
    authorization = (attempt / "authorization.json").read_bytes()
    command = (attempt / "qemu-command.json").read_bytes()
    document = {
        "authorization_sha256": hashlib.sha256(authorization).hexdigest(),
        "kind": "windows-identity-attempt-consumed",
        "qemu_command_sha256": hashlib.sha256(command).hexdigest(),
        "schema": 1,
    }
    return _publish_once(attempt / STATE_NAME, document)


def terminalize(
    attempt: Path,
    *,
    claim_sha256: str,
    outcome: str,
    teardown: Mapping[str, bool],
) -> None:
    """Publish the terminal teardown audit after lifecycle unwinding."""
    if outcome not in {"succeeded", "failed", "interrupted"}:
        raise ValueError("invalid Windows identity attempt outcome")
    expected = {
        "processes_reaped", "qmp_closed", "runtime_quiescent",
        "owned_media_closed", "dependencies_released",
    }
    if set(teardown) != expected or any(
            type(value) is not bool for value in teardown.values()):
        raise ValueError("invalid Windows identity teardown audit")
    document = {
        "claim_sha256": claim_sha256,
        "kind": "windows-identity-terminal-teardown",
        "outcome": outcome,
        "schema": 1,
        "teardown": dict(teardown),
        "teardown_complete": all(teardown.values()),
    }
    _publish_once(Path(attempt) / TEARDOWN_NAME, document)
