#!/usr/bin/env python3
"""Serialize and verify secret-free native Windows lifecycle receipts."""

from __future__ import annotations

import json
import os
from pathlib import Path
import stat
from typing import Protocol

from .secure_artifacts import atomic_write_text


SCHEMA = 1
KIND = "telos-windows-identity-lifecycle"
PHASES = (
    "switch-started",
    "controller-started",
    "windows-started",
    "qmp-authenticated",
    "local-credential-rotated",
    "private-publication-destroyed",
    "controller-principals-staged",
    "acceptance-complete",
    "controller-principals-destroyed",
    "windows-stopped",
    "controller-stopped",
    "switch-stopped",
)
PROOFS = (
    "local_credential_rotated",
    "private_publication_destroyed",
    "controller_principals_staged",
    "controller_principals_destroyed",
    "acceptance_complete",
    "teardown_complete",
)
KEYS = frozenset(("schema", "kind", "phases", *PROOFS))


class LifecycleReceipt(Protocol):
    """The secret-free fields produced by ``run_lifecycle``."""

    phases: list[str]
    local_credential_rotated: bool
    private_publication_destroyed: bool
    controller_principals_staged: bool
    controller_principals_destroyed: bool
    acceptance_complete: bool
    teardown_complete: bool


def validate(document: object) -> dict[str, object]:
    """Return a normalized complete receipt or reject it fail-closed."""
    if not isinstance(document, dict):
        raise ValueError("identity receipt must be a JSON object")
    if set(document) != KEYS:
        raise ValueError("identity receipt has unexpected or missing fields")
    if document["schema"] != SCHEMA or isinstance(document["schema"], bool):
        raise ValueError("identity receipt has an unsupported schema")
    if document["kind"] != KIND:
        raise ValueError("identity receipt has the wrong kind")
    phases = document["phases"]
    if not isinstance(phases, list) or tuple(phases) != PHASES:
        raise ValueError(
            "identity receipt does not prove the complete ordered lifecycle")
    for proof in PROOFS:
        if document[proof] is not True:
            raise ValueError(f"identity receipt lacks proof: {proof}")
    return {
        "schema": SCHEMA,
        "kind": KIND,
        "phases": list(PHASES),
        **{proof: True for proof in PROOFS},
    }


def serialize(receipt: LifecycleReceipt) -> str:
    """Serialize a complete lifecycle result without accepting extra data."""
    document = {
        "schema": SCHEMA,
        "kind": KIND,
        "phases": list(receipt.phases),
        **{proof: getattr(receipt, proof) for proof in PROOFS},
    }
    normalized = validate(document)
    return json.dumps(
        normalized, indent=2, sort_keys=True, ensure_ascii=True) + "\n"


def deserialize(encoded: str | bytes) -> dict[str, object]:
    """Parse and validate one secret-free lifecycle receipt."""
    try:
        document = json.loads(encoded)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError("identity receipt is not valid JSON") from error
    return validate(document)


def write(path: Path, receipt: LifecycleReceipt) -> None:
    """Atomically write a private, durable lifecycle receipt."""
    atomic_write_text(Path(path), serialize(receipt))


def read(path: Path) -> dict[str, object]:
    """Read a private regular receipt and validate its complete lifecycle."""
    path = Path(path)
    try:
        descriptor = os.open(
            path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    except OSError as error:
        raise ValueError(
            "identity receipt must be a readable regular file") from error
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise ValueError("identity receipt must be a regular file")
        if metadata.st_uid != os.getuid() or metadata.st_mode & 0o077:
            raise ValueError(
                "identity receipt must be owned by this user and mode 0600")
        with os.fdopen(descriptor, "rb") as stream:
            descriptor = -1
            encoded = stream.read()
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    return deserialize(encoded)
