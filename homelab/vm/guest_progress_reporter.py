"""Guest-side progress reporter over the pure v1 protocol.

Builds, signs, and stages canonical envelopes through `SenderState` and
pumps them across injected byte streams.  Every clock, wall clock, and
UUID source is injected: nothing here reads real time or randomness,
sleeps, opens a device, extends a deadline, or turns a progress event
into acceptance evidence.
"""

from __future__ import annotations

import math
import uuid
from datetime import datetime, timezone
from typing import Callable

from .guest_progress_protocol import (
    EVENT_STATUSES,
    AuthenticationError,
    DeadlineError,
    FrameDecoder,
    FrameError,
    ProtocolConfig,
    SchemaError,
    SenderState,
    TransitionError,
    canonical_json,
    sign_envelope,
)


class ProgressReporter:
    """Stop-and-wait envelope builder for one boot of one attempt.

    Sequence numbers derive from the sender's acknowledged state, so a
    failed build or stage never consumes a sequence, and the boot
    identifier derives from the injected UUID source, so identical
    injections yield byte-identical frames.
    """

    def __init__(
        self,
        config: ProtocolConfig,
        key: bytes,
        *,
        operation_deadline: float,
        clock: Callable[[], float],
        uuid_source: Callable[[], uuid.UUID],
        wall_clock: Callable[[], float],
    ) -> None:
        for name, value in (
            ("clock", clock),
            ("uuid_source", uuid_source),
            ("wall_clock", wall_clock),
        ):
            if not callable(value):
                raise SchemaError(f"{name} must be callable")
        # SenderState validates config, key, and the operation deadline.
        self._sender = SenderState(
            config, key, operation_deadline=operation_deadline
        )
        self._key: bytearray | None = bytearray(key)
        self._clock = clock
        self._uuid_source = uuid_source
        self._wall_clock = wall_clock
        self._boot_id = "boot-" + self._next_uuid()
        self._pending_frame: bytes | None = None

    def _next_uuid(self) -> str:
        value = self._uuid_source()
        if type(value) is not uuid.UUID:
            raise SchemaError("uuid_source must return an exact uuid.UUID")
        return str(value)

    def _render_time(self) -> str:
        moment = self._wall_clock()
        if type(moment) not in (int, float) or not math.isfinite(moment):
            raise SchemaError("wall clock must be a finite unix time")
        try:
            stamp = datetime.fromtimestamp(float(moment), tz=timezone.utc)
        except (OverflowError, OSError, ValueError) as error:
            raise SchemaError("wall clock is outside the UTC range") from error
        # Whole seconds keep exactly one canonical rendering per instant.
        return stamp.strftime("%Y-%m-%dT%H:%M:%SZ")

    @property
    def config(self) -> ProtocolConfig:
        return self._sender.config

    @property
    def boot_id(self) -> str:
        return self._boot_id

    @property
    def state(self) -> str:
        return self._sender.state

    @property
    def last_sequence(self) -> int | None:
        return self._sender.last_sequence

    @property
    def operation_deadline(self) -> float:
        return self._sender.operation_deadline

    @property
    def ack_deadline(self) -> float | None:
        return self._sender.ack_deadline

    @property
    def pending_frame(self) -> bytes | None:
        # The sender owns pending truth; expiry there clears this view.
        if self._sender.pending_payload is None:
            return None
        return self._pending_frame

    def _emit(self, event_type: str, phase: str | None, extra: dict) -> bytes:
        if self._key is None:
            raise AuthenticationError("reporter is closed")
        sequence = (
            0 if self._sender.last_sequence is None
            else self._sender.last_sequence + 1
        )
        unsigned = {
            "specversion": self._sender.config.specversion,
            "id": self._next_uuid(),
            "source": self._sender.config.producer,
            "type": event_type,
            "time": self._render_time(),
            "attempt": self._sender.config.attempt,
            "boot_id": self._boot_id,
            "sequence": sequence,
            "phase": phase,
            "status": EVENT_STATUSES[event_type],
        }
        unsigned.update(extra)
        payload = canonical_json(sign_envelope(unsigned, bytes(self._key)))
        frame = self._sender.stage(payload, sent_at=self._clock())
        self._pending_frame = frame
        return frame

    def sync(self) -> bytes:
        return self._emit("sync", None, {"nonce": self._sender.config.nonce})

    def phase_started(self, phase: str) -> bytes:
        return self._emit("phase-started", phase, {})

    def heartbeat(self, phase: str, progress: int | None = None) -> bytes:
        extra = {} if progress is None else {"progress": progress}
        return self._emit("heartbeat", phase, extra)

    def phase_finished(self, phase: str) -> bytes:
        return self._emit("phase-finished", phase, {})

    def phase_failed(self, phase: str) -> bytes:
        return self._emit("phase-failed", phase, {})

    def diagnostic_ready(self, identifier: str, sha256: str) -> bytes:
        return self._emit(
            "diagnostic-ready",
            None,
            {"diagnostic": {"id": identifier, "sha256": sha256}},
        )

    def retry(self, *, now: float | None = None) -> bytes:
        moment = self._clock() if now is None else now
        return self._sender.retry(now=moment)

    def acknowledge(
        self, payload: bytes, *, received_at: float | None = None
    ) -> bool:
        moment = self._clock() if received_at is None else received_at
        committed = self._sender.acknowledge(payload, received_at=moment)
        if self._sender.pending_payload is None:
            self._pending_frame = None
        return committed

    def close(self) -> None:
        """Drop the signing key copy and pending bytes."""

        if self._key is not None:
            for index in range(len(self._key)):
                self._key[index] = 0
            self._key = None
        self._pending_frame = None
        self._sender.close()


def run_over_stream(
    reporter: ProgressReporter,
    read_fn: Callable[[], bytes],
    write_fn: Callable[[bytes], None],
    *,
    clock: Callable[[], float],
) -> None:
    """Deliver the one pending frame until it is acknowledged.

    Writes go through `write_fn`; `read_fn` returns any available ack
    bytes or `b""` when the stream is idle.  Time advances only through
    the injected clock, and the sender's bounded retry schedule and
    deadlines govern expiry, which raises the protocol's DeadlineError.
    """

    if type(reporter) is not ProgressReporter:
        raise SchemaError("reporter must be an exact ProgressReporter")
    for name, value in (
        ("read_fn", read_fn),
        ("write_fn", write_fn),
        ("clock", clock),
    ):
        if not callable(value):
            raise SchemaError(f"{name} must be callable")
    frame = reporter.pending_frame
    if frame is None:
        raise TransitionError("no event is awaiting acknowledgment")
    decoder = FrameDecoder(max_bytes=reporter.config.max_frame_bytes)
    write_fn(frame)
    previous: float | None = None
    while True:
        data = read_fn()
        if type(data) is not bytes:
            raise FrameError("stream input must be exact bytes")
        if data:
            for payload in decoder.feed(data):
                reporter.acknowledge(payload, received_at=clock())
                if reporter.pending_frame is None:
                    return
            previous = None
            continue
        now = clock()
        try:
            write_fn(reporter.retry(now=now))
        except DeadlineError:
            if reporter.state == "TIMED_OUT":
                raise
            # Retry not yet due: the injected clock must advance or an
            # idle stream would spin this pump forever.
            if previous is not None and now <= previous:
                raise DeadlineError("pump requires an advancing clock")
            previous = now
        else:
            previous = None
