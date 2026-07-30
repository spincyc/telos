"""Bounded duplex transport carrying one authenticated guest progress stream.

The transport moves bytes and nothing else. Validation, replay rejection, and
phase semantics stay in `guest_progress_protocol`; the immutable host deadline
stays with the caller. A transport fault is never guest progress, and progress
never extends a deadline.
"""

from __future__ import annotations

from dataclasses import dataclass
import socket
import time
from typing import Callable

from .guest_progress_protocol import (
    AcceptedEvent,
    DeadlineError,
    FrameDecoder,
    GuestProgressError,
    ReceiverState,
    encode_frame,
)


READ_CHUNK = 4096


class TransportError(GuestProgressError):
    """The transport could not carry the stream within its bounds."""


@dataclass(frozen=True)
class TransportResult:
    events: tuple[AcceptedEvent, ...]
    liveness: str
    drained: bool
    checkpoint: bytes


class GuestProgressTransport:
    """One connection feeding one receiver until its deadline or a terminal.

    The caller owns the socket and the receiver. `collect` never blocks past
    the receiver's deadline, and a closed peer ends collection without
    inventing a result.
    """

    def __init__(
        self,
        connection: socket.socket,
        receiver: ReceiverState,
        *,
        clock: Callable[[], float] = time.monotonic,
    ):
        if type(receiver) is not ReceiverState:
            raise TransportError("receiver must be an exact ReceiverState")
        self.connection = connection
        self.receiver = receiver
        self._clock = clock
        self._decoder = FrameDecoder(max_bytes=receiver.config.max_frame_bytes)
        self._closed = False

    def _arm(self) -> float:
        remaining = self.receiver.deadline - self._clock()
        if remaining <= 0:
            raise DeadlineError("transport deadline expired")
        self.connection.settimeout(remaining)
        return remaining

    def _acknowledge(self, event: AcceptedEvent) -> None:
        """Write one acknowledgment, translating every write fault.

        A failed write may have emitted a partial frame, so the transport is
        closed rather than left resumable onto a desynchronised stream.
        """

        ack = self.receiver.acknowledgment(event)
        self._arm()
        try:
            self.connection.sendall(encode_frame(ack))
        except socket.timeout as error:
            self._closed = True
            raise DeadlineError(
                "transport deadline expired while acknowledging") from error
        except OSError as error:
            self._closed = True
            raise TransportError(
                f"transport acknowledgment failed: {error}") from error

    def collect(self, *, until_terminal: bool = True) -> TransportResult:
        """Read, validate, and acknowledge events until the stream settles."""

        if self._closed:
            raise TransportError("transport is closed")
        events: list[AcceptedEvent] = []
        while True:
            try:
                self._arm()
                data = self.connection.recv(READ_CHUNK)
            except socket.timeout as error:
                raise DeadlineError("transport deadline expired") from error
            except OSError as error:
                raise TransportError(f"transport read failed: {error}") from error
            if not data:
                self._decoder.finish()
                break
            for payload in self._decoder.feed(data):
                accepted = self.receiver.accept(
                    payload, received_at=self._clock())
                self._acknowledge(accepted)
                if not accepted.duplicate:
                    events.append(accepted)
                if until_terminal and accepted.envelope["type"] in (
                    "phase-failed", "diagnostic-ready",
                ):
                    return self._settle(events)
            continue
        return self._settle(events)

    def _settle(self, events: list[AcceptedEvent]) -> TransportResult:
        now = self._clock()
        liveness = self.receiver.liveness(now=now)
        self.receiver.begin_drain(now=now)
        checkpoint = self.receiver.finish_drain()
        self._closed = True
        return TransportResult(
            events=tuple(events),
            liveness=liveness,
            drained=True,
            checkpoint=checkpoint,
        )
