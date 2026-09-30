#!/usr/bin/env python3
"""Private, durable evidence for the loopback simulation cycle."""

from __future__ import annotations

import json
import os
import re
import tempfile
import stat
from datetime import datetime, timezone
from pathlib import Path
from typing import BinaryIO, Iterable

try:
    from .factory_verify import EVIDENCE_LIMIT
except ImportError:  # Direct execution from homelab/vm.
    from factory_verify import EVIDENCE_LIMIT


_SECRET = re.compile(
    rb"(?i)(password|passphrase|authorization|token|secret)"
    rb"([ \t]*(?:=|:)[ \t]*)([^ \t\r\n][^\r\n]*)"
)

#: The one line an over-limit retained log carries where its middle was cut.
#: ASCII and free of every credential keyword, so neither the redactor nor
#: ``artifact_scan`` has anything to say about it.
_ELISION = (
    b"[telos evidence: %d bytes elided here to bound this retained log "
    b"to %d bytes]\n")
#: Room for the elision line with any byte count, plus the newline that ends
#: a head which had to be cut mid-line.
_ELISION_RESERVE = len(_ELISION % (10 ** 20, 10 ** 20)) + 1


def redact(data: bytes) -> bytes:
    """Remove values that look like secrets while retaining useful prompts."""
    return _SECRET.sub(rb"\1\2[REDACTED]", data)


def _is_continuation(data: bytes, index: int) -> bool:
    return 0 <= index < len(data) and data[index] & 0xC0 == 0x80


def _bound(data: bytes, limit: int) -> tuple[bytes, int]:
    """Keep the first quarter and the rest of ``limit`` from the end.

    Both cuts land on line boundaries, so no line is kept in part and no UTF-8
    sequence is split (a newline byte never occurs inside one).  Only a line
    longer than its whole budget is cut inside itself, and then at a character
    boundary.  The tail absorbs whatever budget the head's cut leaves unused.
    """
    if len(data) <= limit:
        return data, 0
    if limit < 4 * _ELISION_RESERVE:
        raise ValueError("log limit is too small to hold an elision line")
    budget = limit // 4
    cut = data.rfind(b"\n", 0, budget) + 1
    if not cut:
        cut = budget
        for _ in range(3):
            if not _is_continuation(data, cut):
                break
            cut -= 1
    head = data[:cut]
    start = len(data) - (limit - len(head) - _ELISION_RESERVE)
    newline = data.find(b"\n", start - 1, len(data) - 1)
    if newline >= 0:
        start = newline + 1
    else:
        for _ in range(3):
            if not _is_continuation(data, start):
                break
            start += 1
    elided = start - cut
    marker = _ELISION % (elided, limit)
    if head and not head.endswith(b"\n"):
        marker = b"\n" + marker
    return head + marker + data[start:], elided


def redact_and_bound(
    data: bytes, *, limit: int = EVIDENCE_LIMIT,
) -> tuple[bytes, dict[str, int]]:
    """Redact a whole log, THEN bound it to the evidence limit.

    The order is the point: redaction sees every line whole before any cut,
    so no cut can leave a credential's value behind a truncated label.  A log
    already within the limit comes back exactly as ``redact`` returns it.
    Over the limit, whole lines from its start (a quarter of the limit) and
    its end (the rest) are kept around one elision line (``_bound``): the
    head says what booted, and the tail says where it stopped.  The sizes
    record makes a truncation visible wherever the caller files it.
    """
    retained, elided = _bound(redact(data), limit)
    return retained, {
        "original_bytes": len(data),
        "retained_bytes": len(retained),
        "elided_bytes": elided,
    }


def retain_redacted_logs(
    directory: Path, names: Iterable[str],
) -> dict[str, dict[str, int]]:
    """Replace each named log with its redacted, bounded form, privately.

    Run only after every writer has stopped.  A log that does not exist is
    skipped; the result maps each retained log's name to its sizes.
    """
    retained: dict[str, dict[str, int]] = {}
    for name in names:
        path = directory / name
        try:
            data = path.read_bytes()
        except FileNotFoundError:
            continue
        kept, sizes = redact_and_bound(data)
        private_file(path, kept)
        retained[name] = sizes
    return retained


def private_directory(path: Path) -> None:
    path = path.absolute()
    for ancestor in reversed((path, *path.parents)):
        try:
            mode = ancestor.lstat().st_mode
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(mode):
            raise RuntimeError(
                f"evidence path contains a symlink: {ancestor}")
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    mode = path.lstat().st_mode
    if not stat.S_ISDIR(mode):
        raise RuntimeError(f"evidence path is not a private directory: {path}")
    path.chmod(0o700, follow_symlinks=False)


def _reject_destination(path: Path) -> None:
    try:
        mode = path.lstat().st_mode
    except FileNotFoundError:
        return
    if stat.S_ISLNK(mode) or not stat.S_ISREG(mode):
        raise RuntimeError(
            f"evidence destination is not a regular file: {path}")


def private_file(path: Path, data: bytes = b"") -> None:
    """Atomically create or replace a private regular file."""
    private_directory(path.parent)
    _reject_destination(path)
    descriptor, temporary = tempfile.mkstemp(
        prefix=f".{path.name}.", dir=path.parent)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "wb", closefd=False) as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.close(descriptor)
        descriptor = -1
        _reject_destination(path)
        os.replace(temporary, path)
        directory = os.open(
            path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


class RedactedLog:
    """A mode-0600 binary log which never records stdin or secret values."""

    def __init__(self, path: Path) -> None:
        private_file(path)
        self.path = path
        descriptor = os.open(
            path, os.O_WRONLY | os.O_APPEND | os.O_NOFOLLOW)
        os.fchmod(descriptor, 0o600)
        self._stream: BinaryIO = os.fdopen(descriptor, "ab", buffering=0)

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
    _reject_destination(target)
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
        _reject_destination(target)
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


def append_json_event(path: Path, event: dict[str, object]) -> None:
    """Append one private JSONL event without following links."""
    private_directory(path.parent)
    _reject_destination(path)
    descriptor = os.open(
        path,
        os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW,
        0o600,
    )
    try:
        os.fchmod(descriptor, 0o600)
        payload = (json.dumps(event, sort_keys=True) + "\n").encode()
        os.write(descriptor, payload)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


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
