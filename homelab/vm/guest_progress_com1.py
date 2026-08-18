"""One-way COM1 guest-progress reader: diagnostic by construction.

Windows guests have no virtio-serial driver in this factory (every Windows
QEMU command pins `e1000e` and nothing ships `virtio-win`), so the named
`virtserialport` the v1 protocol prefers cannot exist in the guest.  The only
channel reachable today is COM1, which is one-way host-inbound and shared with
arbitrary human-readable console output.

Three properties keep that channel honest, and each is enforced here rather
than asserted in prose:

* **One-way.**  This reader owns its `ReceiverState` privately and never
  returns the sealed `AcceptedEvent` that `ack_for` requires, so no COM1 event
  can ever produce a host acknowledgment.  The guest reporter correspondingly
  never reads COM1.
* **Channel-separated.**  COM1 events carry a fixed producer of their own
  (`COM1_PRODUCER`).  `_validate_envelope` binds `source` to the configured
  producer, so a COM1 frame replayed into an authoritative receiver fails
  authentication, and this reader refuses any config that is not the COM1
  producer.
* **Never authoritative.**  `com1_progress_record` takes no parameter that
  could mark the channel authoritative or acknowledged; both coordinates are
  constants.

Nothing here turns a guest report into acceptance evidence or extends a
deadline.  A COM1 event may improve failure classification and nothing more.
"""

from __future__ import annotations

import base64
import binascii
import re
import time
from dataclasses import dataclass
from typing import Any, Callable, Mapping

from .guest_progress_host import (
    CLASSIFICATIONS,
    classify,
    classify_liveness,
)
from .guest_progress_protocol import (
    JSON_SAFE_INTEGER_MAX,
    AcceptedEvent,
    GuestProgressError,
    ProtocolConfig,
    ReceiverState,
)


# Public framing constants.  The marker is line-anchored and separated from
# its payload by exactly one space; the payload alphabet excludes the space,
# so "marker followed by a space" can occur at exactly one position in a
# well-formed line and nowhere inside a payload.
MARKER = "TELOS-PROGRESS-V1"
SEPARATOR = " "
# Base64url without padding.  Deliberately disjoint from the JSON-shaped
# records the join, credential-action, and probe protocols already write to
# COM1: a payload can contain no space, quote, brace, colon, comma, CR, or LF,
# so no console line from those protocols can ever be read as an event and no
# event payload can ever be mistaken for console text.
_PAYLOAD_ALPHABET = "A-Za-z0-9_-"
# The decoded canonical envelope is far smaller than the 16 KiB protocol
# frame; COM1 is a shared console, so bound it much harder.
MAX_EVENT_BYTES = 2048
MAX_LINE_BYTES = 4096
_MAX_PAYLOAD_CHARS = -(-MAX_EVENT_BYTES * 4 // 3)
_LINE = re.compile(
    f"{re.escape(MARKER)}{re.escape(SEPARATOR)}"
    f"([{_PAYLOAD_ALPHABET}]{{4,{_MAX_PAYLOAD_CHARS}}})"
)

# Fixed COM1-only producer.  Distinct from every authoritative producer, so
# the protocol's own `source` binding keeps the two streams apart.
COM1_PRODUCER = "windows-com1-diagnostic"
# Closed COM1 phase vocabulary: exactly what a boot-triggered guest task can
# observe about itself.  No verdict reads these.
COM1_PHASES = (
    "windows-firstboot",
    "windows-identity",
    "windows-acceptance",
)
COM1_STATUSES = ("starting", "active", "complete", "failed", "ready")

CHANNEL = "com1"
# COM1 is one-way host-inbound and shared with console output.  These are
# constants, not defaults: no argument anywhere in this module can change
# either one.
AUTHORITATIVE = False
ACKNOWLEDGED = False


class Com1ProgressError(GuestProgressError):
    """A marked COM1 line did not carry a valid event; fail closed."""

    def __init__(self, message: str, classification: str) -> None:
        super().__init__(message)
        if classification not in CLASSIFICATIONS:
            raise ValueError("unknown progress classification")
        self.classification = classification


@dataclass(frozen=True)
class Com1Observation:
    """One bounded, public COM1 coordinate.

    Deliberately *not* an `AcceptedEvent`: `ack_for` refuses anything that is
    not the receiver's own sealed object, so an observation cannot be turned
    into a host acknowledgment.  `authoritative` is a read-only property, not
    a field, so no constructor argument can set it.
    """

    type: str
    phase: str | None
    status: str
    sequence: int
    boot_id: str
    progress: int | None
    duplicate: bool

    @property
    def authoritative(self) -> bool:
        return AUTHORITATIVE

    @property
    def acknowledged(self) -> bool:
        return ACKNOWLEDGED


def com1_config(
    *, attempt: str, nonce: str,
    phases: tuple[str, ...] = COM1_PHASES,
) -> ProtocolConfig:
    """Build the only ProtocolConfig this channel accepts."""

    return ProtocolConfig(
        attempt=attempt,
        producer=COM1_PRODUCER,
        nonce=nonce,
        phases=phases,
        statuses=COM1_STATUSES,
        max_frame_bytes=MAX_EVENT_BYTES,
    )


def frame_line(payload: bytes) -> str:
    """Render one canonical envelope as its exact COM1 line, without LF."""

    if type(payload) is not bytes or not payload:
        raise Com1ProgressError("payload must be exact nonempty bytes",
                                "malformed")
    if len(payload) > MAX_EVENT_BYTES:
        raise Com1ProgressError("payload exceeds the COM1 event bound",
                                "malformed")
    encoded = base64.urlsafe_b64encode(payload).decode("ascii").rstrip("=")
    line = MARKER + SEPARATOR + encoded
    if _LINE.fullmatch(line) is None:
        raise Com1ProgressError("rendered line is not a COM1 frame",
                                "malformed")
    return line


def decode_line(line: str) -> bytes | None:
    """Decode one complete COM1 line.

    Returns the canonical envelope bytes for a well-formed progress line,
    `None` for ordinary console text, and raises `Com1ProgressError` for a
    line that claims to be a progress frame but is not one.  The distinction
    matters: unmarked console text is expected traffic, while a marked line
    that fails to decode is a fault the caller must record.
    """

    if type(line) is not str:
        raise Com1ProgressError("line must be exact text", "malformed")
    # `fullmatch` anchors both ends.  A line that merely *contains* the marker
    # ("note: TELOS-PROGRESS-V1 ..."), or extends it ("TELOS-PROGRESS-V10 ..."),
    # or appends anything after the payload, is console text and never an
    # event.  Anchoring is not decoration: an unanchored pattern once
    # truncated `10001` to `1` in this repository.
    match = _LINE.fullmatch(line)
    if match is None:
        return None
    encoded = match.group(1)
    padding = "=" * (-len(encoded) % 4)
    if len(encoded) % 4 == 1:
        raise Com1ProgressError("progress payload has an impossible length",
                                "malformed")
    try:
        payload = base64.urlsafe_b64decode(encoded + padding)
    except (binascii.Error, ValueError) as error:
        raise Com1ProgressError(
            "progress payload is not base64url", "malformed") from error
    if base64.urlsafe_b64encode(payload).decode("ascii").rstrip("=") != encoded:
        raise Com1ProgressError(
            "progress payload is not canonical base64url", "malformed")
    if not payload or len(payload) > MAX_EVENT_BYTES:
        raise Com1ProgressError(
            "progress payload length is out of bounds", "malformed")
    return payload


class Com1ProgressReader:
    """Turn a COM1 byte stream into bounded diagnostic observations.

    The reader owns its receiver privately.  Callers get `Com1Observation`
    values and a secret-free record; they never get an ackable event and never
    get a handle on the receiver, so this channel has no path to a host
    acknowledgment at all.
    """

    def __init__(
        self,
        config: ProtocolConfig,
        key: bytes,
        *,
        deadline: float,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        if type(config) is not ProtocolConfig:
            raise Com1ProgressError(
                "config must be an exact ProtocolConfig", "malformed")
        if config.producer != COM1_PRODUCER:
            raise Com1ProgressError(
                "the COM1 channel accepts only its own diagnostic producer",
                "unauthenticated")
        if config.max_frame_bytes > MAX_EVENT_BYTES:
            raise Com1ProgressError(
                "COM1 events must stay inside the shared-console bound",
                "malformed")
        if not callable(clock):
            raise Com1ProgressError("clock must be callable", "malformed")
        # Private by construction: no attribute here exposes the receiver or
        # any AcceptedEvent it produces.
        self.__receiver = ReceiverState(config, key, deadline=deadline)
        self._clock = clock
        self._buffer = bytearray()
        self._resynchronising = False
        self._failure: str | None = None
        self._skipped = 0
        self._discarded = 0
        self._accepted = 0
        self._last_phase: str | None = None
        self._last_sequence: int | None = None
        self._final: dict | None = None
        self._closed = False

    @property
    def skipped_lines(self) -> int:
        """Console lines that were never progress frames."""

        return self._skipped

    @property
    def discarded_lines(self) -> int:
        """Overlong console lines dropped whole during resynchronisation."""

        return self._discarded

    @property
    def failure(self) -> str | None:
        return self._failure

    def feed(self, data: bytes) -> tuple[Com1Observation, ...]:
        """Consume COM1 bytes, emitting one observation per accepted event."""

        if self._closed:
            raise Com1ProgressError("reader is closed", "unavailable")
        if self._failure is not None:
            raise Com1ProgressError(
                "reader failed closed on an earlier line", self._failure)
        if type(data) is not bytes:
            raise Com1ProgressError("stream input must be exact bytes",
                                    "malformed")
        self._buffer.extend(data)
        observations: list[Com1Observation] = []
        while True:
            index = self._buffer.find(b"\n")
            if index < 0:
                if len(self._buffer) > MAX_LINE_BYTES:
                    # A partial read can split a real line, so a line is only
                    # ever formed at an LF.  An overlong unterminated line is
                    # console noise: drop it whole rather than let its tail
                    # start a synthetic frame.
                    self._buffer.clear()
                    self._resynchronising = True
                break
            raw = bytes(self._buffer[:index])
            del self._buffer[:index + 1]
            if self._resynchronising:
                self._resynchronising = False
                self._discarded += 1
                continue
            observation = self._consume(raw)
            if observation is not None:
                observations.append(observation)
        return tuple(observations)

    def _consume(self, raw: bytes) -> Com1Observation | None:
        if len(raw) > MAX_LINE_BYTES:
            self._discarded += 1
            return None
        # A CR anywhere makes this not one exact line; the guest sets its
        # serial newline to LF, so CR means foreign console output.
        if b"\r" in raw:
            self._skipped += 1
            return None
        try:
            text = raw.decode("ascii")
        except UnicodeDecodeError:
            self._skipped += 1
            return None
        try:
            payload = decode_line(text)
        except Com1ProgressError as error:
            self._failure = error.classification
            raise
        if payload is None:
            self._skipped += 1
            return None
        try:
            accepted = self.__receiver.accept(
                payload, received_at=self._clock())
        except GuestProgressError as error:
            self._failure = classify(error)
            raise Com1ProgressError(
                "COM1 event failed closed", self._failure) from error
        # The sealed event dies here.  Nothing downstream can acknowledge it.
        return self._observe(accepted)

    def _observe(self, accepted: AcceptedEvent) -> Com1Observation:
        envelope: Mapping[str, Any] = accepted.envelope
        if not accepted.duplicate:
            self._accepted += 1
            self._last_sequence = envelope["sequence"]
            if envelope["phase"] is not None:
                self._last_phase = envelope["phase"]
        return Com1Observation(
            type=envelope["type"],
            phase=envelope["phase"],
            status=envelope["status"],
            sequence=envelope["sequence"],
            boot_id=envelope["boot_id"],
            progress=envelope.get("progress"),
            duplicate=accepted.duplicate,
        )

    def liveness(self, *, now: float | None = None) -> str:
        if self._closed:
            # Closing destroys the receiver, so the last observed coordinate
            # is the honest one; inventing "absent" would erase real events.
            return "absent" if self._final is None else self._final["liveness"]
        moment = self._clock() if now is None else now
        return self.__receiver.liveness(now=moment)

    def record(self) -> dict:
        """Compose the secret-free COM1 observation block; never raises."""

        if self._final is not None:
            return dict(self._final)
        try:
            liveness = self.liveness()
        except GuestProgressError:
            liveness = "absent"
        try:
            return com1_progress_record(
                liveness=liveness,
                classification=self._failure,
                last_phase=self._last_phase,
                last_sequence=self._last_sequence,
                events_accepted=self._accepted,
                skipped_lines=self._skipped,
                discarded_lines=self._discarded,
            )
        except Exception:
            # Composition can never mask a run verdict; fall back to the
            # weakest honest observation.
            return com1_progress_record(
                liveness="absent", classification="unavailable")

    def close(self) -> None:
        """Snapshot the observation, then destroy key and stream state."""

        if not self._closed:
            self._final = self.record()
            self.__receiver.close()
            self._closed = True
        self._buffer.clear()


def com1_progress_record(
    *,
    liveness,
    classification=None,
    last_phase=None,
    last_sequence=None,
    events_accepted=0,
    skipped_lines=0,
    discarded_lines=0,
) -> dict:
    """Render one secret-free COM1 observation block.

    There is deliberately no `authoritative` or `acknowledged` parameter:
    both coordinates are module constants, so no caller can promote this
    channel by passing an argument.
    """

    state = classify_liveness(liveness)
    if classification is not None and (
        type(classification) is not str
        or classification not in CLASSIFICATIONS
    ):
        raise Com1ProgressError("unknown progress classification", "malformed")
    if last_phase is not None and (
        type(last_phase) is not str or last_phase not in COM1_PHASES
    ):
        raise Com1ProgressError("unknown COM1 phase", "malformed")
    for name, value in (
        ("last_sequence", last_sequence),
        ("events_accepted", events_accepted),
        ("skipped_lines", skipped_lines),
        ("discarded_lines", discarded_lines),
    ):
        if value is None and name == "last_sequence":
            continue
        if type(value) is not int or not 0 <= value <= JSON_SAFE_INTEGER_MAX:
            raise Com1ProgressError(
                f"{name} must be a nonnegative JSON-safe integer", "malformed")
    if state == "absent" and (
        last_phase is not None
        or last_sequence is not None
        or events_accepted != 0
    ):
        raise Com1ProgressError(
            "absent stream cannot carry progress", "malformed")
    if last_sequence is not None and events_accepted == 0:
        raise Com1ProgressError(
            "a last sequence requires at least one accepted event",
            "malformed")
    record = {
        "channel": CHANNEL,
        "marker": MARKER,
        "producer": COM1_PRODUCER,
        "authoritative": AUTHORITATIVE,
        "acknowledged": ACKNOWLEDGED,
        "liveness": state,
        "classification": classification,
        "last_phase": last_phase,
        "last_sequence": last_sequence,
        "events_accepted": events_accepted,
        "skipped_lines": skipped_lines,
        "discarded_lines": discarded_lines,
    }
    # Belt and braces: the constants above are the property, and this refuses
    # to emit a record that somehow contradicts them.
    if record["authoritative"] is not False or record["acknowledged"] is not False:
        raise Com1ProgressError(
            "the COM1 channel cannot be recorded as authoritative",
            "malformed")
    return record
