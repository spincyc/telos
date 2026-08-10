import unittest
import uuid
from datetime import datetime, timezone

from homelab.tests.test_guest_progress_protocol import CONFIG, KEY
from homelab.vm.guest_progress_protocol import (
    AuthenticationError,
    DeadlineError,
    FrameDecoder,
    ReceiverState,
    SchemaError,
    TransitionError,
    canonical_json,
    encode_frame,
    parse_payload,
)
from homelab.vm.guest_progress_reporter import (
    ProgressReporter,
    run_over_stream,
)


WALL = datetime(2026, 7, 30, 1, 0, 0, tzinfo=timezone.utc).timestamp()


class StepClock:
    """Deterministic monotonic clock advancing a fixed step per reading."""

    def __init__(self, start=1.0, step=0.0):
        self.now = float(start)
        self.step = float(step)

    def __call__(self):
        value = self.now
        self.now += self.step
        return value


def sequential_uuids(start=1):
    state = {"next": start}

    def source():
        value = uuid.UUID(int=state["next"])
        state["next"] += 1
        return value

    return source


def make_reporter(*, operation_deadline=100.0, clock=None, wall=WALL):
    return ProgressReporter(
        CONFIG,
        KEY,
        operation_deadline=operation_deadline,
        clock=clock if clock is not None else StepClock(),
        uuid_source=sequential_uuids(),
        wall_clock=lambda: wall,
    )


class Wire:
    """In-memory host end: accept frames, queue signed acknowledgments."""

    def __init__(self, *, deadline=100.0):
        self.receiver = ReceiverState(CONFIG, KEY, deadline=deadline)
        self.host_clock = StepClock(1.0, 1.0)
        self.decoder = FrameDecoder()
        self.accepted = []
        self.acks = []
        self.frames = []

    def write(self, data):
        self.frames.append(data)
        for payload in self.decoder.feed(data):
            accepted = self.receiver.accept(
                payload, received_at=self.host_clock())
            self.accepted.append(accepted)
            self.acks.append(
                encode_frame(self.receiver.acknowledgment(accepted)))

    def read(self):
        return self.acks.pop(0) if self.acks else b""


def accept_and_ack(receiver, frame, *, at):
    accepted = receiver.accept(frame[4:], received_at=at)
    return canonical_json(receiver.acknowledgment(accepted)), accepted


class FullRunTests(unittest.TestCase):
    def run_events(self, reporter, wire, clock, stagers):
        for stage in stagers:
            stage()
            run_over_stream(reporter, wire.read, wire.write, clock=clock)

    def test_full_accepted_run_and_payload_roundtrip(self):
        clock = StepClock(1.0, 0.0)
        reporter = make_reporter(clock=clock)
        wire = Wire()
        self.run_events(reporter, wire, clock, (
            reporter.sync,
            lambda: reporter.phase_started("install"),
            lambda: reporter.heartbeat("install", progress=40),
            lambda: reporter.phase_finished("install"),
        ))
        self.assertEqual(reporter.state, "READY")
        self.assertEqual(reporter.last_sequence, 3)
        self.assertIsNone(reporter.pending_frame)
        self.assertEqual(wire.receiver.boot_id, reporter.boot_id)
        self.assertEqual(wire.receiver.last_sequence, 3)
        self.assertIsNone(wire.receiver.active_phase)
        self.assertEqual([a.duplicate for a in wire.accepted], [False] * 4)
        parsed = [parse_payload(f[4:], CONFIG, KEY) for f in wire.frames]
        self.assertEqual(
            [(p["type"], p["status"], p["phase"]) for p in parsed],
            [
                ("sync", "starting", None),
                ("phase-started", "active", "install"),
                ("heartbeat", "active", "install"),
                ("phase-finished", "complete", "install"),
            ],
        )
        self.assertEqual(parsed[2]["progress"], 40)

    def test_failure_and_diagnostic_run(self):
        clock = StepClock(1.0, 0.0)
        reporter = make_reporter(clock=clock)
        wire = Wire()
        self.run_events(reporter, wire, clock, (
            reporter.sync,
            lambda: reporter.phase_started("install"),
            lambda: reporter.phase_failed("install"),
            lambda: reporter.diagnostic_ready("receipt-1", "a" * 64),
        ))
        self.assertIsNone(wire.receiver.active_phase)
        last = wire.accepted[-1].envelope
        self.assertEqual(last["status"], "ready")
        self.assertEqual(last["diagnostic"]["sha256"], "a" * 64)
        self.assertEqual(wire.accepted[-2].envelope["status"], "failed")

    def test_deterministic_ids_times_sequence_and_bytes(self):
        runs = []
        for _ in range(2):
            clock = StepClock(1.0, 0.0)
            reporter = make_reporter(clock=clock)
            wire = Wire()
            self.run_events(reporter, wire, clock, (
                reporter.sync,
                lambda: reporter.phase_started("install"),
                lambda: reporter.phase_finished("install"),
            ))
            runs.append((reporter, wire))
        first, second = runs
        self.assertEqual(first[1].frames, second[1].frames)
        self.assertEqual(first[0].boot_id, "boot-" + str(uuid.UUID(int=1)))
        parsed = [parse_payload(f[4:], CONFIG, KEY) for f in first[1].frames]
        self.assertEqual([p["sequence"] for p in parsed], [0, 1, 2])
        self.assertEqual(
            [p["id"] for p in parsed],
            [str(uuid.UUID(int=n)) for n in (2, 3, 4)],
        )
        self.assertEqual(
            {p["time"] for p in parsed}, {"2026-07-30T01:00:00Z"})


class RetryTests(unittest.TestCase):
    def test_dropped_ack_retransmits_identical_bytes_and_dedupes(self):
        reporter = make_reporter(clock=StepClock(1.0, 0.0))
        receiver = ReceiverState(CONFIG, KEY, deadline=100)
        frame = reporter.sync()
        _, first = accept_and_ack(receiver, frame, at=1)
        self.assertFalse(first.duplicate)  # ack dropped on the floor
        retried = reporter.retry(now=1.3)
        self.assertEqual(retried, frame)
        ack, duplicate = accept_and_ack(receiver, retried, at=2)
        self.assertTrue(duplicate.duplicate)
        self.assertTrue(reporter.acknowledge(ack, received_at=1.4))
        self.assertEqual(reporter.state, "READY")
        self.assertIsNone(reporter.pending_frame)

    def test_pump_retries_on_silence_then_commits(self):
        clock = StepClock(1.0, 0.25)
        reporter = make_reporter(clock=clock)
        wire = Wire()
        empty_reads = [b""]

        def read():
            return empty_reads.pop(0) if empty_reads else wire.read()

        reporter.sync()
        run_over_stream(reporter, read, wire.write, clock=clock)
        self.assertEqual(len(wire.frames), 2)
        self.assertEqual(wire.frames[0], wire.frames[1])
        self.assertEqual(
            [a.duplicate for a in wire.accepted], [False, True])
        self.assertEqual(reporter.state, "READY")


class DeadlineTests(unittest.TestCase):
    def test_ack_deadline_expiry_raises_and_stops_emission(self):
        clock = StepClock(9.5, 0.5)
        reporter = make_reporter(operation_deadline=10.0, clock=clock)
        wire = Wire()
        reporter.sync()
        with self.assertRaises(DeadlineError):
            run_over_stream(reporter, lambda: b"", wire.write, clock=clock)
        self.assertEqual(reporter.state, "TIMED_OUT")
        self.assertIsNone(reporter.pending_frame)
        with self.assertRaises(DeadlineError):
            reporter.heartbeat("install")
        self.assertEqual(len(wire.frames), 1)

    def test_stage_outside_operation_deadline_fails_closed(self):
        reporter = make_reporter(
            operation_deadline=10.0, clock=StepClock(10.0, 0.0))
        with self.assertRaises(DeadlineError):
            reporter.sync()
        self.assertIsNone(reporter.pending_frame)

    def test_pump_requires_an_advancing_clock(self):
        clock = StepClock(1.0, 0.0)
        reporter = make_reporter(clock=clock)
        reporter.sync()
        with self.assertRaises(DeadlineError):
            run_over_stream(
                reporter, lambda: b"", lambda data: None, clock=clock)
        self.assertEqual(reporter.state, "SYNC_PENDING")

    def test_pump_without_pending_event_fails_closed(self):
        reporter = make_reporter()
        with self.assertRaises(TransitionError):
            run_over_stream(
                reporter, lambda: b"", lambda data: None, clock=StepClock())


class FailClosedTests(unittest.TestCase):
    def setUp(self):
        self.reporter = make_reporter(clock=StepClock(1.0, 0.0))
        self.receiver = ReceiverState(CONFIG, KEY, deadline=100)

    def settle(self):
        ack, _ = accept_and_ack(
            self.receiver, self.reporter.pending_frame, at=1)
        self.reporter.acknowledge(ack, received_at=1.5)

    def test_invalid_builds_fail_before_consuming_sequence(self):
        with self.assertRaises(TransitionError):
            self.reporter.phase_started("install")  # sync must come first
        self.reporter.sync()
        self.settle()
        for build in (
            lambda: self.reporter.phase_started("unknown-phase"),
            lambda: self.reporter.heartbeat("install", progress=150),
            lambda: self.reporter.diagnostic_ready("receipt-1", "z" * 64),
        ):
            with self.assertRaises(SchemaError):
                build()
            self.assertEqual(self.reporter.state, "READY")
            self.assertIsNone(self.reporter.pending_frame)
        frame = self.reporter.phase_started("install")
        self.assertEqual(
            parse_payload(frame[4:], CONFIG, KEY)["sequence"], 1)

    def test_constructor_requires_callables(self):
        with self.assertRaises(SchemaError):
            ProgressReporter(
                CONFIG,
                KEY,
                operation_deadline=100.0,
                clock=1.0,
                uuid_source=sequential_uuids(),
                wall_clock=lambda: WALL,
            )

    def test_wall_clock_and_uuid_source_are_validated(self):
        broken = make_reporter(wall=float("nan"))
        with self.assertRaises(SchemaError):
            broken.sync()
        with self.assertRaises(SchemaError):
            ProgressReporter(
                CONFIG,
                KEY,
                operation_deadline=100.0,
                clock=StepClock(),
                uuid_source=lambda: "not-a-uuid",
                wall_clock=lambda: WALL,
            )

    def test_close_drops_key_and_rejects_further_use(self):
        self.reporter.sync()
        self.reporter.close()
        self.assertIsNone(self.reporter.pending_frame)
        with self.assertRaises(AuthenticationError):
            self.reporter.sync()
        with self.assertRaises(AuthenticationError):
            self.reporter.retry(now=2.0)


if __name__ == "__main__":
    unittest.main()
