import json
import struct
import unittest
import uuid

from homelab.vm.guest_progress_protocol import (
    AcceptedEvent,
    AuthenticationError,
    DeadlineError,
    FrameDecoder,
    FrameError,
    ProtocolConfig,
    ReceiverState,
    ReplayError,
    SchemaError,
    SenderState,
    TransitionError,
    ack_for,
    canonical_json,
    encode_frame,
    parse_ack_payload,
    parse_payload,
    sign_envelope,
)


KEY = b"k" * 32
CONFIG = ProtocolConfig(
    attempt="attempt-public-1",
    producer="arch-installer",
    nonce="host-nonce-1",
    phases=("bootstrap", "install", "reboot"),
    statuses=("starting", "active", "complete", "failed", "ready"),
)


def event(sequence=0, event_type="sync", phase=None, **changes):
    value = {
        "specversion": "1.0",
        "id": str(uuid.UUID(int=sequence + 1)),
        "source": CONFIG.producer,
        "type": event_type,
        "time": "2026-07-30T01:00:00Z",
        "attempt": CONFIG.attempt,
        "boot_id": "boot-public-1",
        "sequence": sequence,
        "phase": phase,
        "status": {
            "sync": "starting",
            "phase-started": "active",
            "heartbeat": "active",
            "phase-finished": "complete",
            "phase-failed": "failed",
            "diagnostic-ready": "ready",
        }.get(event_type, "starting"),
    }
    if event_type == "sync":
        value["nonce"] = CONFIG.nonce
    value.update(changes)
    return sign_envelope(value, KEY)


class FramingTests(unittest.TestCase):
    def test_fragmented_and_coalesced_frames(self):
        first = encode_frame(event())
        second = encode_frame(event(1, "diagnostic-ready", diagnostic={
            "id": "receipt-1", "sha256": "a" * 64,
        }))
        decoder = FrameDecoder()
        self.assertEqual(decoder.feed(first[:3]), [])
        self.assertEqual(decoder.feed(first[3:] + second), [first[4:], second[4:]])
        decoder.finish()

    def test_rejects_zero_oversize_and_truncated_frames(self):
        for prefix in (struct.pack(">I", 0), struct.pack(">I", 16385)):
            with self.subTest(prefix=prefix):
                decoder = FrameDecoder()
                with self.assertRaises(FrameError):
                    decoder.feed(prefix)
                with self.assertRaises(FrameError):
                    decoder.feed(encode_frame(event()))
                decoder.reset()
                self.assertEqual(decoder.feed(encode_frame(event())), [canonical_json(event())])
        decoder = FrameDecoder()
        decoder.feed(struct.pack(">I", 2) + b"{")
        with self.assertRaises(FrameError):
            decoder.finish()
        with self.assertRaises(FrameError):
            decoder.feed(encode_frame(event()))

    def test_large_coalesced_input_is_consumed_without_unbounded_retention(self):
        framed = encode_frame(event())
        decoder = FrameDecoder()
        frames = decoder.feed(framed * 100)
        self.assertEqual(len(frames), 100)
        self.assertEqual(decoder._payload, bytearray())
        self.assertEqual(decoder._header, bytearray())


class SchemaAndAuthenticationTests(unittest.TestCase):
    def test_accepts_canonical_signed_envelope(self):
        parsed = parse_payload(canonical_json(event()), CONFIG, KEY)
        self.assertEqual(parsed["type"], "sync")

    def test_rejects_duplicate_unknown_noncanonical_and_float(self):
        valid = event()
        cases = [
            canonical_json({**valid, "unknown": "x"}),
            json.dumps(valid, sort_keys=True).encode(),
            b'{"a":1,"a":1}',
            canonical_json({**valid, "progress": 1.5}),
        ]
        for payload in cases:
            with self.subTest(payload=payload[:30]):
                with self.assertRaises(SchemaError):
                    parse_payload(payload, CONFIG, KEY)

    def test_rejects_wrong_key_attempt_producer_nonce_and_forged_mac(self):
        for envelope, key, error in (
            (event(), b"w" * 32, AuthenticationError),
            (event(attempt="other"), KEY, AuthenticationError),
            (event(source="windows-task"), KEY, AuthenticationError),
            (event(nonce="other"), KEY, AuthenticationError),
        ):
            with self.subTest(envelope=envelope):
                state = ReceiverState(CONFIG, key, deadline=100)
                with self.assertRaises(error):
                    state.accept(canonical_json(envelope), received_at=1)

    def test_closed_types_and_nested_diagnostic(self):
        for envelope in (
            event(type="other"),
            event(progress=True),
            event(0, "diagnostic-ready", diagnostic={"id": "x", "sha256": "a" * 64, "x": 1}),
        ):
            with self.assertRaises(SchemaError):
                parse_payload(canonical_json(envelope), CONFIG, KEY)
        with self.assertRaises(SchemaError):
            parse_payload(
                canonical_json(event(sequence=(1 << 53))),
                CONFIG,
                KEY,
            )

    def test_requires_exact_config_and_receiver_snapshots_it(self):
        class ForgedConfig(ProtocolConfig):
            pass

        forged = ForgedConfig(
            attempt=CONFIG.attempt,
            producer=CONFIG.producer,
            nonce=CONFIG.nonce,
            phases=CONFIG.phases,
            statuses=CONFIG.statuses,
        )
        with self.assertRaises(SchemaError):
            parse_payload(canonical_json(event()), forged, KEY)
        with self.assertRaises(SchemaError):
            ReceiverState(forged, KEY, deadline=100)

        mutable_input = ProtocolConfig(
            attempt=CONFIG.attempt,
            producer=CONFIG.producer,
            nonce=CONFIG.nonce,
            phases=CONFIG.phases,
            statuses=CONFIG.statuses,
        )
        state = ReceiverState(mutable_input, KEY, deadline=100)
        object.__setattr__(mutable_input, "attempt", "tampered")
        accepted = state.accept(canonical_json(event()), received_at=1)
        self.assertFalse(accepted.duplicate)

    def test_rejects_status_confusion_and_short_or_nonbytes_keys(self):
        confused = event(status="complete")
        with self.assertRaises(SchemaError):
            parse_payload(canonical_json(confused), CONFIG, KEY)
        unsigned = {k: v for k, v in event().items() if k != "mac"}
        for key in (b"x" * 31, bytearray(b"x" * 32)):
            with self.subTest(key=type(key)):
                with self.assertRaises(AuthenticationError):
                    sign_envelope(unsigned, key)

    def test_mac_is_domain_separated(self):
        import base64
        import hashlib
        import hmac

        signed = event()
        unsigned = {k: v for k, v in signed.items() if k != "mac"}
        undomained = base64.b64encode(
            hmac.new(KEY, canonical_json(unsigned), hashlib.sha256).digest()
        ).decode("ascii")
        forged = {**unsigned, "mac": undomained}
        with self.assertRaises(AuthenticationError):
            parse_payload(canonical_json(forged), CONFIG, KEY)

    def test_event_status_registry_is_immutable(self):
        from homelab.vm import guest_progress_protocol as subject

        with self.assertRaises(TypeError):
            subject.EVENT_STATUSES["sync"] = "failed"
        parsed = parse_payload(canonical_json(event()), CONFIG, KEY)
        self.assertEqual(parsed["status"], "starting")


class ReceiverTests(unittest.TestCase):
    def setUp(self):
        self.state = ReceiverState(CONFIG, KEY, deadline=100)

    def accept(self, envelope, at=1):
        return self.state.accept(canonical_json(envelope), received_at=at)

    def test_strict_sequence_transitions_and_non_authority(self):
        result = self.accept(event())
        self.assertFalse(result.authoritative)
        self.accept(event(1, "phase-started", "install", status="active"))
        self.accept(event(2, "heartbeat", "install", status="active", progress=40))
        self.accept(event(3, "phase-finished", "install", status="complete"))
        self.assertIsNone(self.state.active_phase)

    def test_identical_retry_is_idempotent_but_conflict_gap_and_rollback_fail(self):
        sync = event()
        self.assertFalse(self.accept(sync).duplicate)
        self.assertTrue(self.accept(sync).duplicate)
        with self.assertRaises(ReplayError):
            self.accept(event(2, "phase-started", "install"))
        self.accept(event(1, "phase-started", "install"))
        rollback = event(id=str(uuid.UUID(int=99)))
        with self.assertRaises(ReplayError):
            self.accept(rollback)

        conflict = dict(sync)
        conflict["time"] = "2026-07-30T01:00:01Z"
        conflict = sign_envelope({k: v for k, v in conflict.items() if k != "mac"}, KEY)
        with self.assertRaises(ReplayError):
            self.accept(conflict)

    def test_requires_sync_and_rejects_new_boot_without_reset(self):
        with self.assertRaises(ReplayError):
            self.accept(event(0, "phase-started", "install"))
        self.accept(event())
        with self.assertRaises(ReplayError):
            self.accept(event(1, "phase-started", "install", boot_id="boot-public-2"))

    def test_contradictory_phase_state_fails(self):
        self.accept(event())
        with self.assertRaises(TransitionError):
            self.accept(event(1, "heartbeat", "install"))
        self.accept(event(1, "phase-started", "install"))
        with self.assertRaises(TransitionError):
            self.accept(event(2, "phase-finished", "bootstrap"))

    def test_deadline_is_immutable_and_guest_time_cannot_extend_it(self):
        with self.assertRaises(DeadlineError):
            self.accept(event(time="2099-01-01T00:00:00Z"), at=100)
        self.assertEqual(self.state.deadline, 100)

    def test_rejects_nonfinite_deadlines_and_receive_times(self):
        for deadline in (float("nan"), float("inf"), float("-inf")):
            with self.subTest(deadline=deadline):
                with self.assertRaises(DeadlineError):
                    ReceiverState(CONFIG, KEY, deadline=deadline)
        for received_at in (float("nan"), float("inf"), float("-inf")):
            with self.subTest(received_at=received_at):
                with self.assertRaises(DeadlineError):
                    self.accept(event(), at=received_at)
                self.assertIsNone(self.state.boot_id)

    def test_failed_accept_is_atomic(self):
        bad_sequence = event(sequence=1)
        with self.assertRaises(ReplayError):
            self.accept(bad_sequence)
        self.assertIsNone(self.state.boot_id)
        self.assertIsNone(self.state.last_sequence)
        self.assertIsNone(self.state.last_receive)
        self.assertIsNone(self.state.active_phase)
        self.assertFalse(self.state._accepted)

    def test_event_uuid_cannot_be_reused_at_another_sequence(self):
        sync = event()
        self.accept(sync)
        reused = event(
            1,
            "phase-started",
            "install",
            id=sync["id"],
        )
        with self.assertRaises(ReplayError):
            self.accept(reused)
        self.assertEqual(self.state.last_sequence, 0)
        self.assertIsNone(self.state.active_phase)

    def test_reconnect_requires_fresh_sync_and_discards_old_retry_state(self):
        old_sync = event()
        self.accept(old_sync)
        self.state.reconnect()
        with self.assertRaises(ReplayError):
            self.accept(event(1, "phase-started", "install"))
        with self.assertRaises(ReplayError):
            self.accept(old_sync)
        new_sync = event(boot_id="boot-public-2", id=str(uuid.UUID(int=99)))
        self.assertFalse(self.accept(new_sync).duplicate)

    def test_retention_is_bounded(self):
        state = ReceiverState(
            ProtocolConfig(
                attempt=CONFIG.attempt,
                producer=CONFIG.producer,
                nonce=CONFIG.nonce,
                phases=CONFIG.phases,
                statuses=CONFIG.statuses,
                max_events=1,
            ),
            KEY,
            deadline=100,
        )
        state.accept(canonical_json(event()), received_at=1)
        with self.assertRaises(ReplayError):
            state.accept(
                canonical_json(event(1, "phase-started", "install")),
                received_at=2,
            )
        self.assertEqual(state.last_sequence, 0)
        self.assertIsNone(state.active_phase)

    def test_close_drops_key_reference_and_rejects_further_use(self):
        self.accept(event())
        internal_key = self.state._key
        self.state.close()
        self.assertIsNone(self.state._key)
        self.assertEqual(internal_key, bytearray(len(KEY)))
        self.assertFalse(self.state._accepted)
        with self.assertRaises(AuthenticationError):
            self.accept(event(), at=2)
        with self.assertRaises(AuthenticationError):
            self.state.reconnect()


class AcknowledgmentAndSenderTests(unittest.TestCase):
    def setUp(self):
        self.ack_receiver = ReceiverState(CONFIG, KEY, deadline=100)

    def validated(self, envelope):
        return self.ack_receiver.accept(canonical_json(envelope), received_at=1)

    def ack(self, envelope, **changes):
        value = ack_for(self.validated(envelope), CONFIG, KEY)
        if changes:
            unsigned = {k: v for k, v in value.items() if k != "mac"}
            unsigned.update(changes)
            from homelab.vm import guest_progress_protocol as subject

            value = dict(unsigned)
            value["mac"] = subject._domain_mac(
                unsigned, KEY, subject.ACK_MAC_DOMAIN
            )
        return canonical_json(value)

    def test_ack_is_closed_canonical_direction_separated_and_framable(self):
        sync = event()
        accepted = self.validated(sync)
        ack = ack_for(accepted, CONFIG, KEY)
        with self.assertRaises(TypeError):
            accepted.envelope["sequence"] = 99
        class ForgedAcceptedEvent(AcceptedEvent):
            pass
        with self.assertRaises(AuthenticationError):
            ack_for(
                ForgedAcceptedEvent(
                    envelope=accepted.envelope,
                    duplicate=False,
                    _seal=accepted._seal,
                ),
                CONFIG,
                KEY,
            )
        cloned_envelope = dict(accepted.envelope)
        cloned_envelope["sequence"] = 1
        with self.assertRaises(AuthenticationError):
            ack_for(
                AcceptedEvent(
                    envelope=cloned_envelope,
                    duplicate=False,
                    _seal=accepted._seal,
                ),
                CONFIG,
                KEY,
            )
        self.assertEqual(
            frozenset(ack),
            {
                "specversion", "type", "attempt", "boot_id", "sequence", "id",
                "status", "mac",
            },
        )
        self.assertEqual(parse_ack_payload(canonical_json(ack), CONFIG, KEY), ack)
        self.assertEqual(
            encode_frame(ack)[4:],
            canonical_json(ack),
        )
        event_domain_forgery = sign_envelope(
            {k: v for k, v in ack.items() if k != "mac"}, KEY
        )
        with self.assertRaises(AuthenticationError):
            parse_ack_payload(canonical_json(event_domain_forgery), CONFIG, KEY)

    def test_ack_rejects_forgery_unknown_fields_and_wrong_binding(self):
        valid = ack_for(self.validated(event()), CONFIG, KEY)
        cases = (
            (canonical_json(valid), b"x" * 32, AuthenticationError),
            (canonical_json({**valid, "extra": "x"}), KEY, SchemaError),
            (json.dumps(valid, sort_keys=True).encode(), KEY, SchemaError),
            (self.ack(event(), attempt="other"), KEY, AuthenticationError),
        )
        for payload, key, error in cases:
            with self.subTest(error=error):
                with self.assertRaises(error):
                    parse_ack_payload(payload, CONFIG, key)
        for invalid in (
            event(),
            AcceptedEvent(envelope=event(), duplicate=False),
        ):
            with self.assertRaises(AuthenticationError):
                ack_for(invalid, CONFIG, KEY)

    def test_stop_and_wait_exact_ack_and_idempotence(self):
        sender = SenderState(CONFIG, KEY, operation_deadline=100)
        sync = event()
        frame = sender.stage(canonical_json(sync), sent_at=1)
        self.assertEqual(sender.state, "SYNC_PENDING")
        self.assertEqual(frame[4:], canonical_json(sync))
        self.assertTrue(sender.acknowledge(self.ack(sync), received_at=2))
        self.assertEqual(sender.state, "READY")
        self.assertFalse(sender.acknowledge(self.ack(sync), received_at=2))

        ordinary = event(1, "phase-started", "install")
        sender.stage(canonical_json(ordinary), sent_at=3)
        with self.assertRaises(TransitionError):
            sender.stage(
                canonical_json(event(2, "heartbeat", "install")), sent_at=3
            )
        self.assertFalse(sender.acknowledge(self.ack(sync), received_at=3))
        self.assertTrue(sender.acknowledge(self.ack(ordinary), received_at=3))
        self.assertEqual(sender.last_sequence, 1)

    def test_retries_exact_bytes_on_frozen_schedule_and_deadline(self):
        sender = SenderState(CONFIG, KEY, operation_deadline=100)
        frame = sender.stage(canonical_json(event()), sent_at=10)
        self.assertEqual(sender.ack_deadline, 15)
        with self.assertRaises(DeadlineError):
            sender.retry(now=10.249)
        for moment in (10.25, 10.75, 11.75, 13.75):
            self.assertEqual(sender.retry(now=moment), frame)
        with self.assertRaises(DeadlineError):
            sender.retry(now=15)
        self.assertEqual(sender.state, "TIMED_OUT")
        with self.assertRaises(DeadlineError):
            sender.stage(canonical_json(event()), sent_at=15)

    def test_ack_deadline_is_clamped_to_operation_deadline(self):
        sender = SenderState(CONFIG, KEY, operation_deadline=12)
        sender.stage(canonical_json(event()), sent_at=10)
        self.assertEqual(sender.ack_deadline, 12)
        with self.assertRaises(DeadlineError):
            sender.acknowledge(self.ack(event()), received_at=12.001)
        self.assertEqual(sender.state, "TIMED_OUT")

    def test_deadlines_are_half_open_at_exact_boundary(self):
        sender = SenderState(CONFIG, KEY, operation_deadline=10)
        with self.assertRaises(DeadlineError):
            sender.stage(canonical_json(event()), sent_at=10)

        sender = SenderState(CONFIG, KEY, operation_deadline=100)
        sync = event()
        sender.stage(canonical_json(sync), sent_at=10)
        with self.assertRaises(DeadlineError):
            sender.acknowledge(self.ack(sync), received_at=15)
        self.assertEqual(sender.state, "TIMED_OUT")

        sender = SenderState(CONFIG, KEY, operation_deadline=100)
        sender.stage(canonical_json(sync), sent_at=10)
        with self.assertRaises(DeadlineError):
            sender.acknowledge(b"{malformed", received_at=15)
        self.assertEqual(sender.state, "TIMED_OUT")
        self.assertIsNone(sender.pending_payload)

    def test_future_wrong_tuple_attempt_and_boot_fail_closed(self):
        sender = SenderState(CONFIG, KEY, operation_deadline=100)
        sync = event()
        sender.stage(canonical_json(sync), sent_at=1)
        for ack_payload in (
            self.ack(sync, sequence=1),
            self.ack(sync, id=str(uuid.UUID(int=99))),
            self.ack(sync, boot_id="boot-public-2"),
        ):
            with self.subTest(ack=ack_payload):
                with self.assertRaises(ReplayError):
                    sender.acknowledge(ack_payload, received_at=2)
        with self.assertRaises(AuthenticationError):
            sender.acknowledge(
                self.ack(sync, attempt="other"),
                received_at=2,
            )
        self.assertEqual(sender.state, "SYNC_PENDING")

    def test_sequence_and_sync_transitions_are_sender_enforced(self):
        sender = SenderState(CONFIG, KEY, operation_deadline=100)
        with self.assertRaises(TransitionError):
            sender.stage(
                canonical_json(event(0, "phase-started", "install")), sent_at=1
            )
        sync = event()
        sender.stage(canonical_json(sync), sent_at=1)
        sender.acknowledge(self.ack(sync), received_at=1)
        for invalid in (
            event(1),
            event(2, "phase-started", "install"),
            event(1, "phase-started", "install", boot_id="boot-public-2"),
        ):
            with self.subTest(invalid=invalid):
                with self.assertRaises((TransitionError, ReplayError)):
                    sender.stage(canonical_json(invalid), sent_at=2)
        self.assertEqual(sender.state, "READY")

    def test_sender_rejects_event_uuid_reuse_and_bounds_retention_atomically(self):
        sender = SenderState(CONFIG, KEY, operation_deadline=100)
        sync = event()
        sender.stage(canonical_json(sync), sent_at=1)
        sender.acknowledge(self.ack(sync), received_at=1)
        reused = event(
            1, "phase-started", "install", id=sync["id"]
        )
        with self.assertRaises(ReplayError):
            sender.stage(canonical_json(reused), sent_at=2)
        self.assertEqual(sender.state, "READY")
        self.assertEqual(sender.last_sequence, 0)
        self.assertIsNone(sender.pending_payload)

        bounded_config = ProtocolConfig(
            attempt=CONFIG.attempt,
            producer=CONFIG.producer,
            nonce=CONFIG.nonce,
            phases=CONFIG.phases,
            statuses=CONFIG.statuses,
            max_events=1,
        )
        bounded = SenderState(bounded_config, KEY, operation_deadline=100)
        bounded.stage(canonical_json(sync), sent_at=1)
        bounded.acknowledge(self.ack(sync), received_at=1)
        with self.assertRaises(ReplayError):
            bounded.stage(
                canonical_json(event(1, "phase-started", "install")),
                sent_at=2,
            )
        self.assertEqual(bounded.state, "READY")
        self.assertIsNone(bounded.pending_payload)

    def test_sender_snapshots_config_rejects_nonfinite_time_and_wipes_key(self):
        mutable = ProtocolConfig(
            attempt=CONFIG.attempt,
            producer=CONFIG.producer,
            nonce=CONFIG.nonce,
            phases=CONFIG.phases,
            statuses=CONFIG.statuses,
        )
        sender = SenderState(mutable, KEY, operation_deadline=100)
        with self.assertRaises(AttributeError):
            sender.operation_deadline = 200
        with self.assertRaises(AttributeError):
            sender.state = "READY"
        with self.assertRaises(AttributeError):
            sender.config = CONFIG
        with self.assertRaises(AttributeError):
            sender.boot_id = "boot-public-2"
        with self.assertRaises(AttributeError):
            sender.last_sequence = 99
        object.__setattr__(mutable, "attempt", "tampered")
        sender.stage(canonical_json(event()), sent_at=1)
        for value in (float("nan"), float("inf"), float("-inf")):
            with self.subTest(value=value):
                with self.assertRaises(DeadlineError):
                    sender.retry(now=value)
        internal_key = sender._key
        sender.close()
        self.assertEqual(internal_key, bytearray(len(KEY)))
        self.assertIsNone(sender.pending_payload)
        with self.assertRaises(AuthenticationError):
            sender.acknowledge(self.ack(event()), received_at=2)


if __name__ == "__main__":
    unittest.main()
