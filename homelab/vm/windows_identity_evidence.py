#!/usr/bin/env python3
"""Publish one strict, secret-free Windows identity evidence stream."""

from __future__ import annotations

import json
import os
from pathlib import Path
import tempfile
from typing import Iterable, Mapping, Any

from homelab.vm.simulation_evidence import private_directory
from homelab.workstations.windows_identity_acceptance import (
    CONTRACT,
    EvidenceError,
    judge,
    load_json,
)


class EvidencePublicationError(RuntimeError):
    """Acceptance evidence cannot be published safely."""


def _publish_once(destination: Path, payload: bytes) -> None:
    private_directory(destination.parent)
    descriptor, temporary = tempfile.mkstemp(
        prefix=f".{destination.name}.", dir=destination.parent)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "wb", closefd=False) as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.close(descriptor)
        descriptor = -1
        try:
            os.link(temporary, destination, follow_symlinks=False)
        except FileExistsError as error:
            raise EvidencePublicationError(
                "Windows identity evidence is publish-once") from error
        directory = os.open(
            destination.parent,
            os.O_RDONLY | getattr(os, "O_DIRECTORY", 0),
        )
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


def _encoded_secret(secret: str | bytes) -> bytes:
    if isinstance(secret, str):
        return secret.encode("utf-8")
    if isinstance(secret, bytes):
        return secret
    raise TypeError("known secrets must be strings or bytes")


def publish_acceptance_evidence(
    destination: Path,
    events: Iterable[Mapping[str, Any]],
    *,
    known_secrets: Iterable[str | bytes] = (),
) -> Path:
    """Validate and privately publish exactly one complete acceptance stream.

    Validation happens before the destination or its parent is created, so an
    invalid or incomplete sequence leaves no partial evidence behind.
    """
    destination = Path(destination).absolute()
    if destination.exists() or destination.is_symlink():
        raise EvidencePublicationError(
            "Windows identity evidence is publish-once")

    materialized = [dict(event) for event in events]
    try:
        judge(load_json(CONTRACT), materialized)
    except (OSError, json.JSONDecodeError, EvidenceError) as error:
        raise EvidencePublicationError(
            f"invalid Windows identity evidence: {error}") from error

    payload = b"".join(
        json.dumps(event, sort_keys=True, separators=(",", ":")).encode(
            "utf-8") + b"\n"
        for event in materialized
    )
    for secret in known_secrets:
        encoded = _encoded_secret(secret)
        if encoded and encoded in payload:
            raise EvidencePublicationError(
                "Windows identity evidence contains a known secret")

    _publish_once(destination, payload)
    if destination.stat().st_mode & 0o077:
        raise EvidencePublicationError(
            "Windows identity evidence is not private")
    return destination
