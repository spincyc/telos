#!/usr/bin/env python3
"""Private, durable evidence for the loopback simulation cycle."""

from __future__ import annotations

import json
import os
import re
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import BinaryIO


_SECRET = re.compile(
    rb"(?i)(password|passphrase|authorization|token|secret)"
    rb"([ \t]*(?:=|:)[ \t]*)([^ \t\r\n][^\r\n]*)"
)


def redact(data: bytes) -> bytes:
    """Remove values that look like secrets while retaining useful prompts."""
    return _SECRET.sub(rb"\1\2[REDACTED]", data)


def private_directory(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    if path.is_symlink() or not path.is_dir():
        raise RuntimeError(f"evidence path is not a private directory: {path}")
    path.chmod(0o700)


def private_file(path: Path, data: bytes = b"") -> None:
    """Create or replace a private file without following a final symlink."""
    private_directory(path.parent)
    descriptor = os.open(
        path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "wb", closefd=False) as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
    finally:
        os.close(descriptor)


class RedactedLog:
    """A mode-0600 binary log which never records stdin or secret values."""

    def __init__(self, path: Path) -> None:
        private_file(path)
        self.path = path
        self._stream: BinaryIO = path.open("ab", buffering=0)
        os.chmod(path, 0o600)

    def write(self, data: bytes) -> int:
        cleaned = redact(data)
        return self._stream.write(cleaned)

    def flush(self) -> None:
        self._stream.flush()

    def fileno(self) -> int:
        return self._stream.fileno()

    def close(self) -> None:
        self._stream.close()

    def __enter__(self) -> "RedactedLog":
        return self

    def __exit__(self, *_args: object) -> None:
        self.close()


def write_result(
    evidence: Path,
    *,
    status: str,
    run_id: str,
    checks: dict[str, bool] | None = None,
    error: BaseException | str | None = None,
) -> Path:
    """Atomically publish the terminal result, including a redacted failure."""
    if status not in {"pass", "fail"}:
        raise ValueError("result status must be pass or fail")
    document: dict[str, object] = {
        "schema": 1,
        "kind": "homelab-loopback-simulation-result",
        "run_id": run_id,
        "status": status,
        "finished_at": datetime.now(timezone.utc).isoformat(),
        "checks": checks or {},
    }
    if error is not None:
        rendered = redact(str(error).encode("utf-8", "replace")).decode(
            "utf-8", "replace")
        document["error"] = {
            "type": type(error).__name__
            if isinstance(error, BaseException) else "Error",
            "message": rendered,
        }
    private_directory(evidence)
    target = evidence / "result.json"
    encoded = (
        json.dumps(document, indent=2, sort_keys=True) + "\n"
    ).encode()
    descriptor, temporary = tempfile.mkstemp(
        prefix=".result.", dir=evidence)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "wb", closefd=False) as stream:
            stream.write(encoded)
            stream.flush()
            os.fsync(stream.fileno())
        os.close(descriptor)
        descriptor = -1
        os.replace(temporary, target)
        os.chmod(target, 0o600)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
    return target


def write_serial_events(
    evidence: Path,
    *,
    qemu_exit_code: int | None,
    helper_passed: bool,
    events: tuple[str, ...] = (),
) -> Path:
    """Persist serial outcomes, never console bytes or operator input."""
    document = {
        "schema": 1,
        "kind": "controller-serial-events",
        "input_captured": False,
        "console_output_captured": False,
        "helper_passed": helper_passed,
        "qemu_exit_code": qemu_exit_code,
        "events": list(events),
    }
    target = evidence / "serial-events.json"
    private_file(
        target,
        (json.dumps(document, indent=2, sort_keys=True) + "\n").encode())
    return target
