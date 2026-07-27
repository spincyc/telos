#!/usr/bin/env python3
"""Small fail-closed helpers for private simulation artifacts."""

from __future__ import annotations

import os
import stat
import tempfile
from pathlib import Path


def private_directory(path: Path, *, parents: bool = False) -> Path:
    """Create a private directory without following a final symlink."""
    path = Path(path)
    if parents:
        path.parent.mkdir(parents=True, exist_ok=True)
    try:
        mode = path.lstat().st_mode
    except FileNotFoundError:
        path.mkdir(mode=0o700)
        mode = path.lstat().st_mode
    if stat.S_ISLNK(mode) or not stat.S_ISDIR(mode):
        raise RuntimeError(f"artifact directory is not a real directory: {path}")
    path.chmod(0o700, follow_symlinks=False)
    return path


def _reject_destination(path: Path) -> None:
    try:
        mode = path.lstat().st_mode
    except FileNotFoundError:
        return
    if stat.S_ISLNK(mode) or not stat.S_ISREG(mode):
        raise RuntimeError(f"artifact destination is not a regular file: {path}")


def atomic_write(path: Path, data: bytes) -> None:
    """Atomically replace a private regular file in a private directory."""
    path = Path(path)
    private_directory(path.parent, parents=True)
    _reject_destination(path)
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
        _reject_destination(path)
        os.replace(temporary, path)
        directory_fd = os.open(
            path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def atomic_write_text(path: Path, text: str) -> None:
    atomic_write(path, text.encode("utf-8"))


def atomic_append_text(path: Path, text: str) -> None:
    """Append through an atomic replacement, rejecting link targets."""
    path = Path(path)
    _reject_destination(path)
    prior = path.read_bytes() if path.exists() else b""
    atomic_write(path, prior + text.encode("utf-8"))
