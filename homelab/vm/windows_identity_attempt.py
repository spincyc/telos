#!/usr/bin/env python3
"""Durable, secret-free state for a one-use Windows identity attempt."""

from __future__ import annotations

import hashlib
import fcntl
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


class _AttemptClaim:
    """An OS-held capability for the exclusively published claim inode."""

    def __init__(self, descriptor: int, path: Path, digest: str) -> None:
        self.__descriptor = descriptor
        self.__path = path
        self.digest = digest

    def verify(self, attempt: Path) -> bool:
        path = Path(attempt) / STATE_NAME
        try:
            opened = os.fstat(self.__descriptor)
            current = path.stat(follow_symlinks=False)
            content = os.pread(self.__descriptor, opened.st_size, 0)
            document = json.loads(content)
            authorization = (Path(attempt) / "authorization.json").read_bytes()
            command = (Path(attempt) / "qemu-command.json").read_bytes()
            fcntl.flock(
                self.__descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except (OSError, ValueError):
            return False
        return (
            path == self.__path
            and current.st_dev == opened.st_dev
            and current.st_ino == opened.st_ino
            and hashlib.sha256(content).hexdigest() == self.digest
            and isinstance(document, dict)
            and set(document) == {
                "authorization_sha256", "kind",
                "qemu_command_sha256", "schema",
            }
            and document["schema"] == 1
            and document["kind"] == "windows-identity-attempt-consumed"
            and document["authorization_sha256"]
            == hashlib.sha256(authorization).hexdigest()
            and document["qemu_command_sha256"]
            == hashlib.sha256(command).hexdigest()
        )

    def close(self) -> None:
        if self.__descriptor >= 0:
            os.close(self.__descriptor)
            self.__descriptor = -1


class _ClaimPublicationError(RuntimeError):
    def __init__(self, claim: _AttemptClaim, error_type: str) -> None:
        super().__init__(
            f"claim publication durability failed: {error_type}")
        self.claim = claim


def _publish_once(
    path: Path, document: Mapping[str, object], *, retain: bool = False,
) -> str | _AttemptClaim:
    """Publish one fsynced private inode without replacing an existing claim."""
    data = _canonical(document)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(temporary_name)
    published = False
    digest = hashlib.sha256(data).hexdigest()
    try:
        try:
            os.fchmod(descriptor, 0o600)
            with os.fdopen(os.dup(descriptor), "wb") as stream:
                stream.write(data)
                stream.flush()
                os.fsync(stream.fileno())
            if retain:
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            os.link(temporary, path, follow_symlinks=False)
            published = True
            directory = os.open(
                path.parent,
                os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_DIRECTORY", 0)
                | getattr(os, "O_NOFOLLOW", 0),
            )
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
            if retain:
                retained = descriptor
                descriptor = -1
                return _AttemptClaim(retained, path, digest)
        except BaseException as error:
            if retain and published and descriptor >= 0:
                retained = descriptor
                descriptor = -1
                raise _ClaimPublicationError(
                    _AttemptClaim(retained, path, digest),
                    type(error).__name__,
                ) from None
            raise
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        temporary.unlink(missing_ok=True)
    return hashlib.sha256(data).hexdigest()


def claim(attempt: Path) -> _AttemptClaim:
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
    capability = _publish_once(
        attempt / STATE_NAME, document, retain=True)
    assert isinstance(capability, _AttemptClaim)
    return capability


def terminalize(
    attempt: Path,
    *,
    claim: _AttemptClaim,
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
    if not claim.verify(attempt):
        raise RuntimeError("Windows identity attempt claim changed")
    document = {
        "claim_sha256": claim.digest,
        "kind": "windows-identity-terminal-teardown",
        "outcome": outcome,
        "schema": 1,
        "teardown": dict(teardown),
        "teardown_complete": all(teardown.values()),
    }
    _publish_once(Path(attempt) / TEARDOWN_NAME, document)
