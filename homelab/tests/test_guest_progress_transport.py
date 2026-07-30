import base64
import socket
import unittest

from homelab.tests.test_guest_progress_protocol import CONFIG, KEY, event
from homelab.vm.guest_progress_protocol import (
    AuthenticationError,
    DeadlineError,
    FrameDecoder,
    ReceiverState,
    SchemaError,
    encode_frame,
    parse_ack_payload,
)
from homelab.vm.guest_progress_transport import (
    GuestProgressTransport,
    TransportError,
    TransportResult,
)


class Clock:
    def __init__(self, *values):
        self.values = list(values)
        self.last = 0.0

    def __call__(self):
        if self.values:
            self.last = self.values.pop(0)
        return self.last


class GuestProgressTransportTests(unittest.TestCase):
    def setUp(self):
        self.host, self.guest = socket.socketpair()
        self.addCleanup(self.host.close)
        self.addCleanup(self.guest.close)
        self.receiver = ReceiverState(CONFIG, KEY, deadline=100)

    def transport(self, clock=None):
        return GuestProgressTransport(
            self.host, self.receiver, clock=clock or (lambda: 1.0))

    def send(self, *envelopes):
        for envelope in envelopes:
            self.guest.sendall(encode_frame(envelope))

    def acks(self):
        self.guest.settimeout(2)
        decoder = FrameDecoder()
        payloads = []
        while True:
            try:
                data = self.guest.recv(4096)
            except socket.timeout:
                break
            if not data:
                break
            payloads.extend(decoder.feed(data))
            break
        return payloads

    def test_collects_acknowledges_and_drains_on_peer_close(self):
        self.send(
            event(),
            event(1, "phase-started", "install"),
            event(2, "phase-finished", "install"),
        )
        self.guest.shutdown(socket.SHUT_WR)
        result = self.transport().collect()
        self.assertIsInstance(result, TransportResult)
        self.assertEqual(len(result.events), 3)
        self.assertEqual(
            [item.envelope["type"] for item in result.events],
            ["sync", "phase-started", "phase-finished"],
        )
        self.assertTrue(result.drained)
        self.assertEqual(result.liveness, "live")

        payloads = self.acks()
        self.assertTrue(payloads)
        ack = parse_ack_payload(payloads[0], CONFIG, KEY)
        self.assertEqual(ack["sequence"], 0)
        self.assertEqual(ack["status"], "accepted")

    def test_checkpoint_restores_the_collected_progress(self):
        self.send(event(), event(1, "phase-started", "install"))
        self.guest.shutdown(socket.SHUT_WR)
        result = self.transport().collect()
        restored = ReceiverState.restore(
            result.checkpoint, CONFIG, KEY, deadline=200)
        self.assertEqual(restored.last_sequence, 1)
        self.assertEqual(restored.active_phase, "install")

    def test_returns_at_a_terminal_event_without_waiting(self):
        self.send(event(), event(1, "phase-started", "install"),
                  event(2, "phase-failed", "install"))
        result = self.transport().collect()
        self.assertEqual(result.events[-1].envelope["type"], "phase-failed")
        self.assertTrue(result.drained)

    def test_duplicate_retries_are_acknowledged_but_not_recollected(self):
        sync = event()
        self.send(sync, sync)
        self.guest.shutdown(socket.SHUT_WR)
        result = self.transport().collect()
        self.assertEqual(len(result.events), 1)

    def test_expired_deadline_refuses_to_read(self):
        transport = self.transport(clock=lambda: 100.0)
        with self.assertRaises(DeadlineError):
            transport.collect()

    def test_deadline_expiry_while_waiting_is_not_progress(self):
        receiver = ReceiverState(CONFIG, KEY, deadline=1.05)
        transport = GuestProgressTransport(
            self.host, receiver, clock=lambda: 1.0)
        with self.assertRaises(DeadlineError):
            transport.collect()

    def test_closed_transport_refuses_reuse(self):
        self.guest.shutdown(socket.SHUT_WR)
        transport = self.transport()
        transport.collect()
        with self.assertRaises(TransportError):
            transport.collect()

    def test_rejects_a_foreign_receiver(self):
        with self.assertRaises(TransportError):
            GuestProgressTransport(self.host, object())

    def test_malformed_frame_fails_closed_without_acknowledgment(self):
        self.guest.sendall(b"\x00\x00\x00\x05hello")
        self.guest.shutdown(socket.SHUT_WR)
        with self.assertRaises(SchemaError):
            self.transport().collect()
        self.assertEqual(self.acks(), [])

    def test_unauthenticated_event_is_never_acknowledged(self):
        forged = dict(event())
        forged["mac"] = base64.b64encode(bytes(32)).decode("ascii")
        self.guest.sendall(encode_frame(forged))
        self.guest.shutdown(socket.SHUT_WR)
        with self.assertRaises(AuthenticationError):
            self.transport().collect()
        self.assertEqual(self.acks(), [])
        self.assertIsNone(self.receiver.boot_id)

    def test_fragmented_frames_are_reassembled(self):
        payload = encode_frame(event())
        self.guest.sendall(payload[:2])
        self.guest.sendall(payload[2:])
        self.guest.shutdown(socket.SHUT_WR)
        result = self.transport().collect()
        self.assertEqual(len(result.events), 1)


if __name__ == "__main__":
    unittest.main()
