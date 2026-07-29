#!/usr/bin/env python3
"""Publish one strict, secret-free Windows identity evidence stream."""

from __future__ import annotations

from datetime import datetime, timezone
import json
import os
from pathlib import Path
import tempfile
from typing import Any, Callable, Iterable, Mapping
import uuid

from homelab.vm.simulation_evidence import private_directory
from homelab.vm.secret_scan import count_secret_occurrences, secret_needles
from homelab.workstations.windows_identity_acceptance import (
    CONTRACT,
    FIELD_SETS,
    RUN_ID,
    UTC,
    EvidenceError,
    judge,
    load_json,
)


class EvidencePublicationError(RuntimeError):
    """Acceptance evidence cannot be published safely."""


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class StrictIdentityEvidenceCollector:
    """Map ordered guest observations into one strict acceptance stream.

    Callers supply only the fields observed for the current contract check.
    The collector owns the envelope, ordering, run identity, secret rejection,
    and final publish-once boundary.  It never infers a successful observation
    from a phase transition.
    """

    def __init__(
        self,
        destination: Path,
        *,
        run_id: str | None = None,
        known_secrets: Iterable[str | bytes] = (),
        observed_at: Callable[[], str] = _utc_now,
    ) -> None:
        self.destination = Path(destination).absolute()
        self.run_id = run_id or str(uuid.uuid4())
        if not RUN_ID.fullmatch(self.run_id):
            raise ValueError("run_id must be a lowercase UUID")
        supplied_secrets = tuple(known_secrets)
        self._known_secrets = (
            secret_needles(supplied_secrets) if supplied_secrets else ())
        self._observed_at = observed_at
        self._checks = tuple(FIELD_SETS)
        self._events: list[dict[str, Any]] = []
        self._published = False

    @property
    def next_check(self) -> str | None:
        """Return the only check currently accepted by the collector."""
        if len(self._events) == len(self._checks):
            return None
        return self._checks[len(self._events)]

    def record(
        self,
        check: str,
        observation: Mapping[str, Any],
        *,
        observed_at: str | None = None,
    ) -> None:
        """Record one exact, secret-free observation in contract order."""
        if self._published:
            raise EvidencePublicationError(
                "Windows identity evidence collector is sealed")
        expected = self.next_check
        if expected is None:
            raise EvidencePublicationError(
                "Windows identity evidence already has 24 observations")
        if check != expected:
            raise EvidencePublicationError(
                f"expected Windows identity observation {expected}")
        if set(observation) != FIELD_SETS[check]:
            raise EvidencePublicationError(
                f"{check} observation fields do not match the contract")
        timestamp = observed_at if observed_at is not None else self._observed_at()
        if not isinstance(timestamp, str) or not UTC.fullmatch(timestamp):
            raise EvidencePublicationError(
                f"{check} observation time is not UTC RFC3339 seconds")
        event = {
            "schema_version": 1,
            "sequence": len(self._events) + 1,
            "check": check,
            "result": "pass",
            "external_access": False,
            "observed_at": timestamp,
            "run_id": self.run_id,
            **observation,
        }
        try:
            encoded = json.dumps(
                event, sort_keys=True, separators=(",", ":"),
            ).encode("utf-8")
            # Decode the canonical encoding so mutable caller-owned containers
            # cannot alter evidence after the observation was accepted.
            retained = json.loads(encoded)
        except (TypeError, ValueError, UnicodeError):
            raise EvidencePublicationError(
                f"{check} observation is not JSON-safe") from None
        if self._known_secrets and count_secret_occurrences(
                (encoded,), self._known_secrets):
            raise EvidencePublicationError(
                f"{check} observation contains a known secret")
        self._events.append(retained)

    def publish(self) -> Path:
        """Validate all 24 observations and seal one private JSONL file."""
        if self._published:
            raise EvidencePublicationError(
                "Windows identity evidence collector is sealed")
        if self.next_check is not None:
            raise EvidencePublicationError(
                f"Windows identity evidence is incomplete; "
                f"next observation is {self.next_check}")
        result = publish_acceptance_evidence(
            self.destination,
            self._events,
            known_secrets=self._known_secrets,
        )
        self._published = True
        return result


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
    supplied_secrets = tuple(known_secrets)
    if supplied_secrets and count_secret_occurrences(
            (payload,), secret_needles(supplied_secrets)):
        raise EvidencePublicationError(
            "Windows identity evidence contains a known secret")

    _publish_once(destination, payload)
    if destination.stat().st_mode & 0o077:
        raise EvidencePublicationError(
            "Windows identity evidence is not private")
    return destination
