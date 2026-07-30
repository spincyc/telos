"""Pure v1 guest-progress framing, authentication, and receiver state.

Progress events are diagnostic observations.  Nothing in this module turns an
event into authoritative acceptance evidence or extends a host deadline.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import math
import re
import struct
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from types import MappingProxyType
from typing import Any, Mapping


MAX_FRAME_BYTES = 16 * 1024
SPEC_VERSION = "1.0"
UINT32_MAX = (1 << 32) - 1
JSON_SAFE_INTEGER_MAX = (1 << 53) - 1
EVENT_TYPES = (
    "sync",
    "phase-started",
    "heartbeat",
    "phase-finished",
    "phase-failed",
    "diagnostic-ready",
)
MAC_DOMAIN = b"telos-guest-progress-v1\x00"
ACK_MAC_DOMAIN = b"telos-guest-progress-ack-v1\x00"
CHECKPOINT_MAC_DOMAIN = b"telos-guest-progress-checkpoint-v1\x00"
MAX_CHECKPOINT_BYTES = 4 * 1024 * 1024
ACK_TIMEOUT = 5.0
RETRY_DELAYS = (0.25, 0.5, 1.0, 2.0)
EVENT_STATUSES = MappingProxyType({
    "sync": "starting",
    "phase-started": "active",
    "heartbeat": "active",
    "phase-finished": "complete",
    "phase-failed": "failed",
    "diagnostic-ready": "ready",
})
_ENVELOPE_FIELDS = frozenset(
    {
        "specversion", "id", "source", "type", "time", "attempt", "boot_id",
        "sequence", "phase", "status", "progress", "diagnostic", "nonce", "mac",
    }
)
_REQUIRED_FIELDS = frozenset(
    {
        "specversion", "id", "source", "type", "time", "attempt", "boot_id",
        "sequence", "phase", "status", "mac",
    }
)
_TOKEN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_RFC3339_UTC = re.compile(
    r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?Z\Z"
)
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_ACK_FIELDS = frozenset(
    {
        "specversion", "type", "attempt", "boot_id", "sequence", "id",
        "status", "mac",
    }
)
_ACCEPTED_EVENT_SEAL = object()


class GuestProgressError(ValueError):
    """Base class for fail-closed protocol errors."""


class FrameError(GuestProgressError):
    pass


class SchemaError(GuestProgressError):
    pass


class AuthenticationError(GuestProgressError):
    pass


class ReplayError(GuestProgressError):
    pass


class TransitionError(GuestProgressError):
    pass


class DeadlineError(GuestProgressError):
    pass


@dataclass(frozen=True)
class ProtocolConfig:
    """Closed registries and immutable receiver identity."""

    attempt: str
    producer: str
    nonce: str
    phases: tuple[str, ...]
    statuses: tuple[str, ...]
    event_types: tuple[str, ...] = EVENT_TYPES
    specversion: str = SPEC_VERSION
    max_frame_bytes: int = MAX_FRAME_BYTES
    max_events: int = 4096
    max_boots: int = 64
    heartbeat_interval: float = 10.0
    silence_limit: float = 30.0
    drain_limit: float = 5.0

    def __post_init__(self) -> None:
        for name, value in (
            ("attempt", self.attempt),
            ("producer", self.producer),
            ("nonce", self.nonce),
        ):
            _require_token(name, value)
        for name, values in (
            ("phases", self.phases),
            ("statuses", self.statuses),
            ("event_types", self.event_types),
        ):
            if type(values) is not tuple or not values or len(set(values)) != len(values):
                raise SchemaError(f"{name} must be a nonempty exact tuple of unique values")
            for value in values:
                _require_token(name, value)
        if self.event_types != EVENT_TYPES:
            raise SchemaError("event_types must equal the closed v1 registry")
        if not frozenset(EVENT_STATUSES.values()) <= frozenset(self.statuses):
            raise SchemaError("statuses must contain every closed v1 event status")
        if self.specversion != SPEC_VERSION:
            raise SchemaError("unsupported specversion")
        if type(self.max_frame_bytes) is not int or not 1 <= self.max_frame_bytes <= UINT32_MAX:
            raise SchemaError("invalid maximum frame length")
        if type(self.max_events) is not int or not 1 <= self.max_events <= UINT32_MAX:
            raise SchemaError("invalid event retention limit")
        if type(self.max_boots) is not int or not 1 <= self.max_boots <= UINT32_MAX:
            raise SchemaError("invalid boot retention limit")
        for name in ("heartbeat_interval", "silence_limit", "drain_limit"):
            limit = getattr(self, name)
            if (
                type(limit) not in (int, float)
                or not math.isfinite(limit)
                or limit <= 0
            ):
                raise SchemaError(f"{name} must be a finite positive limit")


@dataclass(frozen=True)
class AcceptedEvent:
    envelope: Mapping[str, Any]
    duplicate: bool
    authoritative: bool = False
    _seal: object | None = field(default=None, repr=False, compare=False)


def _require_token(name: str, value: Any) -> None:
    if type(value) is not str or _TOKEN.fullmatch(value) is None:
        raise SchemaError(f"{name} is not a bounded public token")


def _reject_constant(_: str) -> None:
    raise SchemaError("non-integer JSON number")


def _object_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise SchemaError("duplicate JSON object key")
        result[key] = value
    return result


def canonical_json(value: Mapping[str, Any]) -> bytes:
    """Return the protocol's deterministic JCS-compatible JSON subset."""

    try:
        text = json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        )
    except (TypeError, ValueError) as error:
        raise SchemaError("value is not canonicalizable JSON") from error
    return text.encode("utf-8")


def mac_for(envelope_without_mac: Mapping[str, Any], key: bytes) -> str:
    if type(key) is not bytes or len(key) < 32:
        raise AuthenticationError("MAC key must be exact bytes of at least 32 bytes")
    authenticated = MAC_DOMAIN + canonical_json(envelope_without_mac)
    digest = hmac.new(key, authenticated, hashlib.sha256).digest()
    return base64.b64encode(digest).decode("ascii")


def _domain_mac(envelope_without_mac: Mapping[str, Any], key: bytes, domain: bytes) -> str:
    if type(key) is not bytes or len(key) < 32:
        raise AuthenticationError("MAC key must be exact bytes of at least 32 bytes")
    digest = hmac.new(
        key, domain + canonical_json(envelope_without_mac), hashlib.sha256
    ).digest()
    return base64.b64encode(digest).decode("ascii")


def sign_envelope(envelope_without_mac: Mapping[str, Any], key: bytes) -> dict[str, Any]:
    if "mac" in envelope_without_mac:
        raise SchemaError("unsigned envelope must omit mac")
    result = dict(envelope_without_mac)
    result["mac"] = mac_for(result, key)
    return result


def ack_for(
    accepted: AcceptedEvent, config: ProtocolConfig, key: bytes
) -> dict[str, Any]:
    """Build an authenticated host acknowledgment for one exact event tuple."""

    if (
        type(accepted) is not AcceptedEvent
        or accepted._seal is not _ACCEPTED_EVENT_SEAL
    ):
        raise AuthenticationError(
            "acknowledgment requires an exact receiver-validated event"
        )
    envelope = parse_payload(canonical_json(dict(accepted.envelope)), config, key)
    unsigned = {
        "specversion": envelope["specversion"],
        "type": "ack",
        "attempt": envelope["attempt"],
        "boot_id": envelope["boot_id"],
        "sequence": envelope["sequence"],
        "id": envelope["id"],
        "status": "accepted",
    }
    result = dict(unsigned)
    result["mac"] = _domain_mac(unsigned, key, ACK_MAC_DOMAIN)
    return result


def parse_ack_payload(
    payload: bytes, config: ProtocolConfig, key: bytes
) -> dict[str, Any]:
    """Validate one canonical, direction-separated acknowledgment."""

    if type(config) is not ProtocolConfig:
        raise SchemaError("config must be an exact ProtocolConfig")
    if type(payload) is not bytes or not payload or len(payload) > config.max_frame_bytes:
        raise FrameError("invalid acknowledgment payload length")
    try:
        value = json.loads(
            payload.decode("utf-8"),
            object_pairs_hook=_object_pairs,
            parse_float=lambda _: (_ for _ in ()).throw(
                SchemaError("non-integer JSON number")
            ),
            parse_constant=_reject_constant,
        )
    except SchemaError:
        raise
    except (json.JSONDecodeError, UnicodeError) as error:
        raise SchemaError("invalid acknowledgment JSON") from error
    if type(value) is not dict or frozenset(value) != _ACK_FIELDS:
        raise SchemaError("acknowledgment must contain exactly the closed v1 fields")
    if canonical_json(value) != payload:
        raise SchemaError("noncanonical acknowledgment JSON encoding")
    if (
        value["specversion"] != config.specversion
        or value["type"] != "ack"
        or value["status"] != "accepted"
    ):
        raise SchemaError("invalid acknowledgment coordinate")
    _require_token("attempt", value["attempt"])
    _require_token("boot_id", value["boot_id"])
    if value["attempt"] != config.attempt:
        raise AuthenticationError("acknowledgment attempt binding mismatch")
    sequence = value["sequence"]
    if type(sequence) is not int or not 0 <= sequence <= JSON_SAFE_INTEGER_MAX:
        raise SchemaError("acknowledgment sequence must be a JSON-safe integer")
    try:
        parsed_id = uuid.UUID(value["id"])
    except (AttributeError, TypeError, ValueError) as error:
        raise SchemaError("acknowledgment id must be a canonical UUID") from error
    if str(parsed_id) != value["id"]:
        raise SchemaError("acknowledgment id must be a canonical lowercase UUID")
    supplied_mac = value["mac"]
    if type(supplied_mac) is not str:
        raise SchemaError("acknowledgment mac must be base64 text")
    try:
        decoded_mac = base64.b64decode(supplied_mac, validate=True)
    except (binascii.Error, ValueError) as error:
        raise SchemaError("acknowledgment mac must be canonical base64") from error
    if (
        len(decoded_mac) != hashlib.sha256().digest_size
        or base64.b64encode(decoded_mac).decode("ascii") != supplied_mac
    ):
        raise SchemaError("acknowledgment mac must be canonical HMAC-SHA-256")
    unsigned = dict(value)
    del unsigned["mac"]
    expected = _domain_mac(unsigned, key, ACK_MAC_DOMAIN)
    if not hmac.compare_digest(supplied_mac, expected):
        raise AuthenticationError("invalid acknowledgment MAC")
    return value


def encode_frame(envelope: Mapping[str, Any], *, max_bytes: int = MAX_FRAME_BYTES) -> bytes:
    payload = canonical_json(envelope)
    if not payload or len(payload) > max_bytes:
        raise FrameError("frame length is zero or exceeds the configured maximum")
    return struct.pack(">I", len(payload)) + payload


class FrameDecoder:
    """Incrementally decode fragmented or coalesced length-prefixed frames."""

    def __init__(self, *, max_bytes: int = MAX_FRAME_BYTES) -> None:
        if type(max_bytes) is not int or not 1 <= max_bytes <= UINT32_MAX:
            raise FrameError("invalid maximum frame length")
        self._maximum = max_bytes
        self._header = bytearray()
        self._payload = bytearray()
        self._expected: int | None = None
        self._poisoned = False

    def feed(self, data: bytes) -> list[bytes]:
        if self._poisoned:
            raise FrameError("decoder is poisoned until explicit reset")
        if type(data) is not bytes:
            raise FrameError("stream input must be exact bytes")
        frames: list[bytes] = []
        offset = 0
        while offset < len(data):
            if self._expected is None:
                take = min(4 - len(self._header), len(data) - offset)
                self._header.extend(data[offset:offset + take])
                offset += take
                if len(self._header) != 4:
                    continue
                length = struct.unpack(">I", self._header)[0]
                self._header.clear()
                if length == 0 or length > self._maximum:
                    self._header.clear()
                    self._payload.clear()
                    self._expected = None
                    self._poisoned = True
                    raise FrameError("invalid frame length")
                self._expected = length
            assert self._expected is not None
            take = min(self._expected - len(self._payload), len(data) - offset)
            self._payload.extend(data[offset:offset + take])
            offset += take
            if len(self._payload) == self._expected:
                frames.append(bytes(self._payload))
                self._payload.clear()
                self._expected = None
        return frames

    def finish(self) -> None:
        if self._poisoned:
            raise FrameError("decoder is poisoned until explicit reset")
        if self._header or self._payload or self._expected is not None:
            self._header.clear()
            self._payload.clear()
            self._expected = None
            self._poisoned = True
            raise FrameError("truncated frame")

    def reset(self) -> None:
        self._header.clear()
        self._payload.clear()
        self._expected = None
        self._poisoned = False


def parse_payload(payload: bytes, config: ProtocolConfig, key: bytes) -> dict[str, Any]:
    if type(config) is not ProtocolConfig:
        raise SchemaError("config must be an exact ProtocolConfig")
    if type(payload) is not bytes or not payload or len(payload) > config.max_frame_bytes:
        raise FrameError("invalid payload length")
    try:
        text = payload.decode("utf-8")
    except UnicodeDecodeError as error:
        raise FrameError("payload is not UTF-8") from error
    try:
        value = json.loads(
            text,
            object_pairs_hook=_object_pairs,
            parse_float=lambda _: (_ for _ in ()).throw(SchemaError("non-integer JSON number")),
            parse_constant=_reject_constant,
        )
    except SchemaError:
        raise
    except (json.JSONDecodeError, UnicodeError) as error:
        raise SchemaError("invalid JSON") from error
    if type(value) is not dict:
        raise SchemaError("envelope must be an object")
    if canonical_json(value) != payload:
        raise SchemaError("noncanonical JSON encoding")
    _validate_envelope(value, config)
    supplied_mac = value["mac"]
    unsigned = dict(value)
    del unsigned["mac"]
    expected_mac = mac_for(unsigned, key)
    if not hmac.compare_digest(supplied_mac, expected_mac):
        raise AuthenticationError("invalid envelope MAC")
    return value


def _validate_envelope(value: dict[str, Any], config: ProtocolConfig) -> None:
    fields = frozenset(value)
    if not _REQUIRED_FIELDS <= fields or not fields <= _ENVELOPE_FIELDS:
        raise SchemaError("missing or unknown envelope field")
    if value["specversion"] != config.specversion:
        raise SchemaError("unsupported specversion")
    for name in ("attempt", "source", "boot_id"):
        _require_token(name, value[name])
    if value["attempt"] != config.attempt or value["source"] != config.producer:
        raise AuthenticationError("attempt or producer binding mismatch")
    try:
        parsed_id = uuid.UUID(value["id"])
    except (AttributeError, TypeError, ValueError) as error:
        raise SchemaError("id must be a canonical UUID") from error
    if str(parsed_id) != value["id"]:
        raise SchemaError("id must be a canonical lowercase UUID")
    if type(value["time"]) is not str or _RFC3339_UTC.fullmatch(value["time"]) is None:
        raise SchemaError("time must be a bounded UTC RFC3339 timestamp")
    try:
        datetime.fromisoformat(value["time"].replace("Z", "+00:00"))
    except ValueError as error:
        raise SchemaError("time is not a real UTC timestamp") from error
    event_type = value["type"]
    if type(event_type) is not str or event_type not in config.event_types:
        raise SchemaError("unknown event type")
    sequence = value["sequence"]
    if type(sequence) is not int or not 0 <= sequence <= JSON_SAFE_INTEGER_MAX:
        raise SchemaError("sequence must be a nonnegative JSON-safe integer")
    phase = value["phase"]
    status = value["status"]
    if phase is not None and (type(phase) is not str or phase not in config.phases):
        raise SchemaError("unknown phase")
    if type(status) is not str or status not in config.statuses:
        raise SchemaError("unknown status")
    if status != EVENT_STATUSES[event_type]:
        raise SchemaError("status does not match event type")
    if "progress" in value and (
        type(value["progress"]) is not int or not 0 <= value["progress"] <= 100
    ):
        raise SchemaError("progress must be an integer from 0 through 100")
    if "diagnostic" in value:
        diagnostic = value["diagnostic"]
        if type(diagnostic) is not dict or frozenset(diagnostic) != {"id", "sha256"}:
            raise SchemaError("diagnostic must contain exactly id and sha256")
        _require_token("diagnostic.id", diagnostic["id"])
        if type(diagnostic["sha256"]) is not str or _SHA256.fullmatch(diagnostic["sha256"]) is None:
            raise SchemaError("diagnostic sha256 must be canonical lowercase hex")
    if type(value["mac"]) is not str:
        raise SchemaError("mac must be base64 text")
    try:
        decoded_mac = base64.b64decode(value["mac"], validate=True)
    except (binascii.Error, ValueError) as error:
        raise SchemaError("mac must be canonical base64") from error
    if len(decoded_mac) != hashlib.sha256().digest_size or (
        base64.b64encode(decoded_mac).decode("ascii") != value["mac"]
    ):
        raise SchemaError("mac must be a canonical HMAC-SHA-256 value")

    nonce_present = "nonce" in value
    if event_type == "sync":
        if phase is not None or not nonce_present:
            raise SchemaError("sync requires null phase and nonce")
        _require_token("nonce", value["nonce"])
    elif nonce_present:
        raise SchemaError("nonce is allowed only on sync")
    if event_type in ("phase-started", "heartbeat", "phase-finished", "phase-failed"):
        if phase is None:
            raise SchemaError(f"{event_type} requires a phase")
    elif event_type == "diagnostic-ready" and "diagnostic" not in value:
        raise SchemaError("diagnostic-ready requires diagnostic metadata")


class SenderState:
    """Stop-and-wait sender for one boot and one immutable operation deadline."""

    def __init__(
        self, config: ProtocolConfig, key: bytes, *, operation_deadline: float
    ) -> None:
        if type(config) is not ProtocolConfig:
            raise SchemaError("config must be an exact ProtocolConfig")
        if (
            type(operation_deadline) not in (int, float)
            or not math.isfinite(operation_deadline)
        ):
            raise DeadlineError(
                "operation deadline must be a finite monotonic number"
            )
        if type(key) is not bytes or len(key) < 32:
            raise AuthenticationError("MAC key must be exact bytes of at least 32 bytes")
        self._config = ProtocolConfig(
            attempt=config.attempt,
            producer=config.producer,
            nonce=config.nonce,
            phases=config.phases,
            statuses=config.statuses,
            event_types=config.event_types,
            specversion=config.specversion,
            max_frame_bytes=config.max_frame_bytes,
            max_events=config.max_events,
            max_boots=config.max_boots,
        )
        self._key = bytearray(key)
        self._operation_deadline = float(operation_deadline)
        self._state = "UNSYNCED"
        self._boot_id: str | None = None
        self._last_sequence: int | None = None
        self._last_ack: tuple[str, int, str] | None = None
        self._pending_tuple: tuple[str, int, str] | None = None
        self._pending_payload: bytes | None = None
        self._pending_frame: bytes | None = None
        self._ack_deadline: float | None = None
        self._next_retry: float | None = None
        self._retry_index = 0
        self._used_event_ids: set[str] = set()
        self._closed = False

    @staticmethod
    def _time(name: str, value: float) -> float:
        if type(value) not in (int, float) or not math.isfinite(value):
            raise DeadlineError(f"{name} must be a finite monotonic number")
        return float(value)

    @property
    def ack_deadline(self) -> float | None:
        return self._ack_deadline

    @property
    def operation_deadline(self) -> float:
        return self._operation_deadline

    @property
    def config(self) -> ProtocolConfig:
        return self._config

    @property
    def boot_id(self) -> str | None:
        return self._boot_id

    @property
    def last_sequence(self) -> int | None:
        return self._last_sequence

    @property
    def state(self) -> str:
        return self._state

    @property
    def pending_payload(self) -> bytes | None:
        return self._pending_payload

    def stage(self, payload: bytes, *, sent_at: float) -> bytes:
        """Stage one signed event and return its immutable framed bytes."""

        self._require_open()
        now = self._time("send time", sent_at)
        if now >= self._operation_deadline:
            self._expire()
            raise DeadlineError("event started outside the operation deadline")
        if self._state == "TIMED_OUT":
            raise DeadlineError("sender acknowledgment deadline expired")
        if self._pending_payload is not None:
            raise TransitionError("an event is already awaiting acknowledgment")
        envelope = parse_payload(payload, self._config, bytes(self._key))
        sequence = envelope["sequence"]
        boot_id = envelope["boot_id"]
        event_id = envelope["id"]
        if event_id in self._used_event_ids:
            raise ReplayError("sender event UUID was already acknowledged")
        if len(self._used_event_ids) >= self._config.max_events:
            raise ReplayError("sender event UUID retention limit reached")
        if self._state == "UNSYNCED":
            if envelope["type"] != "sync" or sequence != 0:
                raise TransitionError("first sender event must be sequence-zero sync")
            if envelope["nonce"] != self._config.nonce:
                raise AuthenticationError("synchronization nonce mismatch")
        else:
            if envelope["type"] == "sync":
                raise TransitionError("sync may only be the first sender event")
            if boot_id != self._boot_id:
                raise ReplayError("sender boot identifier changed")
            assert self._last_sequence is not None
            if sequence != self._last_sequence + 1:
                raise ReplayError("sender sequence must advance by exactly one")
        frame = encode_frame(envelope, max_bytes=self._config.max_frame_bytes)
        self._pending_tuple = (boot_id, sequence, envelope["id"])
        self._pending_payload = payload
        self._pending_frame = frame
        self._ack_deadline = min(now + ACK_TIMEOUT, self._operation_deadline)
        self._retry_index = 0
        self._next_retry = min(now + RETRY_DELAYS[0], self._ack_deadline)
        self._state = (
            "SYNC_PENDING" if self._state == "UNSYNCED" else "EVENT_PENDING"
        )
        return frame

    def retry(self, *, now: float) -> bytes:
        """Return the exact pending frame once its bounded retry time arrives."""

        self._require_open()
        current = self._time("retry time", now)
        if self._pending_frame is None:
            raise TransitionError("no event is awaiting acknowledgment")
        assert self._ack_deadline is not None
        assert self._next_retry is not None
        if current >= self._ack_deadline:
            self._expire()
            raise DeadlineError("sender acknowledgment deadline expired")
        if current < self._next_retry:
            raise DeadlineError("retry is not due")
        frame = self._pending_frame
        self._retry_index = min(self._retry_index + 1, len(RETRY_DELAYS) - 1)
        self._next_retry = min(
            current + RETRY_DELAYS[self._retry_index], self._ack_deadline
        )
        return frame

    def acknowledge(self, payload: bytes, *, received_at: float) -> bool:
        """Commit an exact ACK; return False for an idempotent or stale ACK."""

        self._require_open()
        current = self._time("acknowledgment receive time", received_at)
        if self._state == "TIMED_OUT":
            raise DeadlineError("sender acknowledgment deadline expired")
        if (
            self._pending_tuple is not None
            and self._ack_deadline is not None
            and current >= self._ack_deadline
        ):
            self._expire()
            raise DeadlineError("sender acknowledgment deadline expired")
        ack = parse_ack_payload(payload, self._config, bytes(self._key))
        observed = (ack["boot_id"], ack["sequence"], ack["id"])
        if self._pending_tuple is None:
            if observed == self._last_ack:
                return False
            if (
                self._last_ack is not None
                and observed[0] == self._last_ack[0]
                and observed[1] < self._last_ack[1]
            ):
                return False
            raise ReplayError("acknowledgment does not identify the last event")
        pending = self._pending_tuple
        if observed[0] != pending[0]:
            raise ReplayError("acknowledgment boot identifier mismatch")
        if observed[1] < pending[1]:
            return False
        if observed != pending:
            raise ReplayError("acknowledgment does not identify the pending event")
        was_sync = self._state == "SYNC_PENDING"
        self._boot_id = observed[0]
        self._last_sequence = observed[1]
        self._used_event_ids.add(observed[2])
        self._last_ack = observed
        self._clear_pending()
        self._state = "READY"
        if was_sync:
            self._boot_id = observed[0]
        return True

    def _clear_pending(self) -> None:
        self._pending_tuple = None
        self._pending_payload = None
        self._pending_frame = None
        self._ack_deadline = None
        self._next_retry = None
        self._retry_index = 0

    def _expire(self) -> None:
        self._state = "TIMED_OUT"
        self._clear_pending()

    def _require_open(self) -> None:
        if self._closed or self._key is None:
            raise AuthenticationError("sender is closed")

    def close(self) -> None:
        """Drop sender secrets and pending bytes."""

        if self._key is not None:
            for index in range(len(self._key)):
                self._key[index] = 0
            self._key = None
        self._clear_pending()
        self._boot_id = None
        self._last_sequence = None
        self._last_ack = None
        self._used_event_ids.clear()
        self._state = "CLOSED"
        self._closed = True


class ReceiverState:
    """State for one transport connection and one immutable host deadline."""

    def __init__(self, config: ProtocolConfig, key: bytes, *, deadline: float) -> None:
        if type(config) is not ProtocolConfig:
            raise SchemaError("config must be an exact ProtocolConfig")
        if type(deadline) not in (int, float) or not math.isfinite(deadline):
            raise DeadlineError("deadline must be a finite host-monotonic number")
        if type(key) is not bytes or len(key) < 32:
            raise AuthenticationError("MAC key must be exact bytes of at least 32 bytes")
        self.config = ProtocolConfig(
            attempt=config.attempt,
            producer=config.producer,
            nonce=config.nonce,
            phases=config.phases,
            statuses=config.statuses,
            event_types=config.event_types,
            specversion=config.specversion,
            max_frame_bytes=config.max_frame_bytes,
            max_events=config.max_events,
            max_boots=config.max_boots,
            heartbeat_interval=config.heartbeat_interval,
            silence_limit=config.silence_limit,
            drain_limit=config.drain_limit,
        )
        self._key = bytearray(key)
        self.deadline = float(deadline)
        self._drain_deadline: float | None = None
        self.boot_id: str | None = None
        self.last_sequence: int | None = None
        self.active_phase: str | None = None
        self.last_receive: float | None = None
        self._accepted: dict[tuple[str, str, int, str], bytes] = {}
        self._event_ids: set[str] = set()
        self._retired_boot_ids: set[str] = set()
        self._closed = False

    def accept(self, payload: bytes, *, received_at: float) -> AcceptedEvent:
        if self._closed or self._key is None:
            raise AuthenticationError("receiver is closed")
        if (
            type(received_at) not in (int, float)
            or not math.isfinite(received_at)
            or received_at >= self.deadline
        ):
            raise DeadlineError("event arrived outside the finite host timeline")
        if (
            self._drain_deadline is not None
            and received_at >= self._drain_deadline
        ):
            raise DeadlineError("event arrived after the drain deadline")
        envelope = parse_payload(payload, self.config, bytes(self._key))
        boot_id = envelope["boot_id"]
        event_type = envelope["type"]
        sequence = envelope["sequence"]
        identity = (self.config.attempt, boot_id, sequence, envelope["id"])
        fingerprint = hashlib.sha256(payload).digest()
        if boot_id in self._retired_boot_ids:
            raise ReplayError("event belongs to a retired transport boot")
        prior = self._accepted.get(identity)
        if prior is not None:
            if hmac.compare_digest(prior, fingerprint):
                return AcceptedEvent(
                    envelope=MappingProxyType(dict(envelope)),
                    duplicate=True,
                    _seal=_ACCEPTED_EVENT_SEAL,
                )
            raise ReplayError("event tuple reused with conflicting content")
        if self._drain_deadline is not None:
            raise DeadlineError("draining receiver accepts only retries")
        if envelope["id"] in self._event_ids:
            raise ReplayError("event UUID reused across sequence or boot")

        bind_boot = self.boot_id is None
        if bind_boot:
            if event_type != "sync":
                raise ReplayError("first authenticated event must be sync")
            if envelope["nonce"] != self.config.nonce:
                raise AuthenticationError("synchronization nonce mismatch")
        elif boot_id != self.boot_id:
            raise ReplayError("boot identifier changed without receiver reset")
        elif event_type == "sync":
            raise ReplayError("sync may occur only as the first event")

        expected = 0 if self.last_sequence is None else self.last_sequence + 1
        if sequence != expected:
            kind = "rollback or replay" if sequence < expected else "sequence gap"
            raise ReplayError(kind)
        if len(self._accepted) >= self.config.max_events:
            raise ReplayError("authenticated event retention limit reached")
        next_phase = self._next_phase(envelope)
        if bind_boot:
            self.boot_id = boot_id
        self.last_sequence = sequence
        self.last_receive = float(received_at)
        self.active_phase = next_phase
        self._accepted[identity] = fingerprint
        self._event_ids.add(envelope["id"])
        return AcceptedEvent(
            envelope=MappingProxyType(dict(envelope)),
            duplicate=False,
            _seal=_ACCEPTED_EVENT_SEAL,
        )

    def _next_phase(self, envelope: Mapping[str, Any]) -> str | None:
        event_type = envelope["type"]
        phase = envelope["phase"]
        if event_type == "phase-started":
            if self.active_phase is not None:
                raise TransitionError("a phase is already active")
            return phase
        elif event_type == "heartbeat":
            if phase != self.active_phase:
                raise TransitionError("heartbeat does not match the active phase")
            return self.active_phase
        elif event_type in ("phase-finished", "phase-failed"):
            if phase != self.active_phase:
                raise TransitionError("terminal event does not match the active phase")
            return None
        return self.active_phase

    def liveness(self, *, now: float) -> str:
        """Classify stream liveness: absent, live, or stalled.

        While a phase is active one missed heartbeat is tolerated, so the
        stall bound is the tighter of two heartbeat intervals and the silence
        limit.  Classification never alters any deadline.
        """

        if self._closed or self._key is None:
            raise AuthenticationError("receiver is closed")
        if type(now) not in (int, float) or not math.isfinite(now):
            raise DeadlineError("liveness requires a finite host-monotonic time")
        if self.last_receive is None:
            return "absent"
        limit = self.config.silence_limit
        if self.active_phase is not None:
            limit = min(limit, 2 * self.config.heartbeat_interval)
        return "stalled" if now - self.last_receive > limit else "live"

    def begin_drain(self, *, now: float) -> float:
        """Enter teardown drain; only retries of accepted events remain valid.

        Returns the drain deadline, clamped to the immutable receiver
        deadline; it never extends any timeline.
        """

        if self._closed or self._key is None:
            raise AuthenticationError("receiver is closed")
        if type(now) not in (int, float) or not math.isfinite(now):
            raise DeadlineError("drain requires a finite host-monotonic time")
        if self._drain_deadline is not None:
            raise DeadlineError("receiver is already draining")
        self._drain_deadline = min(
            float(now) + self.config.drain_limit, self.deadline)
        return self._drain_deadline

    def finish_drain(self) -> bytes:
        """Persist validated progress, then destroy key and receiver state."""

        if self._closed or self._key is None:
            raise AuthenticationError("receiver is closed")
        if self._drain_deadline is None:
            raise DeadlineError("receiver is not draining")
        snapshot = self.checkpoint()
        self.close()
        return snapshot

    def checkpoint(self) -> bytes:
        """Render one authenticated, restorable snapshot of accepted progress.

        The snapshot carries no deadline and no receive time: restoring never
        extends the host timeline, and the restored incarnation observes its
        own receive times.
        """

        if self._closed or self._key is None:
            raise AuthenticationError("receiver is closed")
        events = [
            {
                "boot_id": boot_id,
                "sequence": sequence,
                "id": event_id,
                "fingerprint": fingerprint.hex(),
            }
            for (_, boot_id, sequence, event_id), fingerprint
            in sorted(self._accepted.items())
        ]
        unsigned = {
            "specversion": self.config.specversion,
            "kind": "receiver-checkpoint",
            "attempt": self.config.attempt,
            "producer": self.config.producer,
            "nonce": self.config.nonce,
            "boot_id": self.boot_id,
            "last_sequence": self.last_sequence,
            "active_phase": self.active_phase,
            "retired_boot_ids": sorted(self._retired_boot_ids),
            "events": events,
        }
        document = dict(unsigned)
        document["mac"] = _domain_mac(
            unsigned, bytes(self._key), CHECKPOINT_MAC_DOMAIN)
        return canonical_json(document)

    @classmethod
    def restore(
        cls,
        data: bytes,
        config: ProtocolConfig,
        key: bytes,
        *,
        deadline: float,
    ) -> "ReceiverState":
        """Rebuild a receiver from checkpoint() under a caller-owned deadline."""

        receiver = cls(config, key, deadline=deadline)
        if type(data) is not bytes or not data or len(data) > MAX_CHECKPOINT_BYTES:
            raise SchemaError("invalid checkpoint length")
        try:
            value = json.loads(
                data.decode("utf-8"),
                object_pairs_hook=_object_pairs,
                parse_float=lambda _: (_ for _ in ()).throw(
                    SchemaError("non-integer JSON number")),
                parse_constant=_reject_constant,
            )
        except SchemaError:
            raise
        except (json.JSONDecodeError, UnicodeError) as error:
            raise SchemaError("invalid checkpoint JSON") from error
        if type(value) is not dict or canonical_json(value) != data:
            raise SchemaError("noncanonical checkpoint encoding")
        if frozenset(value) != {
            "specversion", "kind", "attempt", "producer", "nonce", "boot_id",
            "last_sequence", "active_phase", "retired_boot_ids", "events",
            "mac",
        }:
            raise SchemaError("missing or unknown checkpoint field")
        if type(value["mac"]) is not str:
            raise SchemaError("checkpoint mac must be base64 text")
        unsigned = dict(value)
        del unsigned["mac"]
        expected = _domain_mac(unsigned, key, CHECKPOINT_MAC_DOMAIN)
        if not hmac.compare_digest(value["mac"], expected):
            raise AuthenticationError("invalid checkpoint MAC")
        if value["specversion"] != config.specversion:
            raise SchemaError("unsupported checkpoint specversion")
        if value["kind"] != "receiver-checkpoint":
            raise SchemaError("unknown checkpoint kind")
        if (
            value["attempt"] != config.attempt
            or value["producer"] != config.producer
            or value["nonce"] != config.nonce
        ):
            raise AuthenticationError("checkpoint identity binding mismatch")

        boot_id = value["boot_id"]
        last_sequence = value["last_sequence"]
        active_phase = value["active_phase"]
        if boot_id is not None:
            _require_token("boot_id", boot_id)
        if last_sequence is not None and (
            type(last_sequence) is not int
            or not 0 <= last_sequence <= JSON_SAFE_INTEGER_MAX
        ):
            raise SchemaError("checkpoint sequence is not a JSON-safe integer")
        if active_phase is not None and active_phase not in config.phases:
            raise SchemaError("checkpoint has an unknown active phase")
        if boot_id is None and (
            last_sequence is not None or active_phase is not None
        ):
            raise SchemaError("checkpoint has progress without a bound boot")
        if boot_id is not None and last_sequence is None:
            raise SchemaError("checkpoint has a bound boot without progress")

        retired = value["retired_boot_ids"]
        if type(retired) is not list or len(retired) > config.max_boots:
            raise SchemaError("invalid checkpoint boot retention")
        for item in retired:
            _require_token("retired_boot_ids", item)
        if len(set(retired)) != len(retired) or retired != sorted(retired):
            raise SchemaError("checkpoint boot retirement is not exact")
        if boot_id is not None and boot_id in retired:
            raise SchemaError("checkpoint boot is already retired")

        events = value["events"]
        if type(events) is not list or len(events) > config.max_events:
            raise SchemaError("invalid checkpoint event retention")
        known_boots = set(retired) | ({boot_id} if boot_id is not None else set())
        sequences: dict[str, set[int]] = {}
        accepted: dict[tuple[str, str, int, str], bytes] = {}
        event_ids: set[str] = set()
        for item in events:
            if type(item) is not dict or frozenset(item) != {
                "boot_id", "sequence", "id", "fingerprint",
            }:
                raise SchemaError("missing or unknown checkpoint event field")
            _require_token("events.boot_id", item["boot_id"])
            sequence = item["sequence"]
            if type(sequence) is not int or not 0 <= sequence <= JSON_SAFE_INTEGER_MAX:
                raise SchemaError("checkpoint event sequence is not JSON-safe")
            try:
                parsed_id = uuid.UUID(item["id"])
            except (AttributeError, TypeError, ValueError) as error:
                raise SchemaError("checkpoint event id must be a UUID") from error
            if str(parsed_id) != item["id"]:
                raise SchemaError("checkpoint event id must be canonical")
            fingerprint = item["fingerprint"]
            if type(fingerprint) is not str or _SHA256.fullmatch(fingerprint) is None:
                raise SchemaError("checkpoint event fingerprint is not exact")
            if item["boot_id"] not in known_boots:
                raise SchemaError("checkpoint event belongs to an unknown boot")
            identity = (config.attempt, item["boot_id"], sequence, item["id"])
            if identity in accepted or item["id"] in event_ids:
                raise SchemaError("checkpoint event identity is duplicated")
            accepted[identity] = bytes.fromhex(fingerprint)
            event_ids.add(item["id"])
            sequences.setdefault(item["boot_id"], set()).add(sequence)
        for observed in sequences.values():
            if observed != set(range(len(observed))):
                raise SchemaError("checkpoint boot progress is not contiguous")
        if boot_id is not None:
            observed = sequences.get(boot_id, set())
            if observed != set(range(last_sequence + 1)):
                raise SchemaError("checkpoint progress differs from its events")

        receiver.boot_id = boot_id
        receiver.last_sequence = last_sequence
        receiver.active_phase = active_phase
        receiver._retired_boot_ids = set(retired)
        receiver._accepted = accepted
        receiver._event_ids = event_ids
        return receiver

    def reconnect(self) -> None:
        """Reset synchronization state; callers must also reset stream framing."""

        if self._closed:
            raise AuthenticationError("receiver is closed")
        if self.boot_id is not None:
            if len(self._retired_boot_ids) >= self.config.max_boots:
                raise ReplayError("transport boot retention limit reached")
            self._retired_boot_ids.add(self.boot_id)
        self.boot_id = None
        self.last_sequence = None
        self.active_phase = None
        self.last_receive = None

    def close(self) -> None:
        """Drop receiver secrets and state; Python does not promise zeroization."""

        if self._key is not None:
            for index in range(len(self._key)):
                self._key[index] = 0
            self._key = None
        self.boot_id = None
        self.last_sequence = None
        self.active_phase = None
        self.last_receive = None
        self._accepted.clear()
        self._event_ids.clear()
        self._retired_boot_ids.clear()
        self._closed = True
