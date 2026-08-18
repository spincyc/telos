"""Contract tests for host-side progress arming and reconnect-aware collection.

Nothing here upgrades a guest report to acceptance evidence.  The load-bearing
invariants proved below are the negative ones: an armed port with no reporter
records an absent stream, a reconnection never moves the host deadline, and a
retired transport boot can never replay into the restored receiver.
"""

import os
import socket
import stat
import tempfile
import time
import unittest
import uuid
from pathlib import Path

from homelab.vm import factory_runner
from homelab.vm.guest_progress_collector import (
    MAX_SESSIONS,
    PROGRESS_SOCKET_NAME,
    GuestProgressCollector,
    attach_planned_progress_port,
    audit_progress_port,
    prepare_socket_directory,
    progress_port_arguments,
    remove_socket_root,
)
from homelab.vm.guest_progress_credentials import mint_credential
from homelab.vm.guest_progress_host import (
    PROGRESS_CHARDEV_ID,
    PROGRESS_PORT_NAME,
    GuestProgressHostError,
    attach_progress_port,
)
from homelab.vm.guest_progress_reporter import ProgressReporter, run_over_stream


class PlannedArmingTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        os.chmod(self.root, 0o700)
        self.socket_path = self.root / PROGRESS_SOCKET_NAME

    def test_planned_argv_is_byte_identical_to_the_launch_time_argv(self):
        """One channel, one rendering: the two arming paths cannot drift."""
        strict, strict_chardev = attach_progress_port(
            ["qemu-system-x86_64"], self.socket_path)
        planned, planned_chardev = attach_planned_progress_port(
            ["qemu-system-x86_64"], self.socket_path)
        self.assertEqual(strict, planned)
        self.assertEqual(strict_chardev, planned_chardev)
        fragment, chardev = progress_port_arguments(self.socket_path)
        self.assertEqual(fragment, strict[1:])
        self.assertEqual(chardev, strict_chardev)
        self.assertEqual(fragment[0], "-chardev")
        self.assertIn(f"name={PROGRESS_PORT_NAME}", fragment[-1])

    def test_a_planned_path_needs_no_directory_but_must_be_safe(self):
        # The whole point: the socket's parent may not exist yet.
        missing = self.root / "not-yet" / PROGRESS_SOCKET_NAME
        fragment, chardev = progress_port_arguments(missing)
        self.assertIn(str(missing), chardev)
        self.assertEqual(len(fragment), 6)
        for bad in (
            Path("relative/progress.sock"),
            self.root / "a,b.sock",
            Path("/" + "x" * 120 + "/progress.sock"),
            b"/tmp/progress.sock",
        ):
            with self.subTest(bad=bad):
                with self.assertRaises(GuestProgressHostError):
                    progress_port_arguments(bad)

    def test_planned_arming_tolerates_a_foreign_chardev_but_not_a_second_port(
            self):
        base = [
            "qemu-system-x86_64", "-serial", "chardev:telosidentity",
            "-chardev", "socket,id=telosidentity,path=/run/x,server=on",
        ]
        armed, chardev = attach_planned_progress_port(base, self.socket_path)
        self.assertEqual(armed[:len(base)], base)
        self.assertEqual(audit_progress_port(armed), (chardev,))
        with self.assertRaises(GuestProgressHostError):
            attach_planned_progress_port(armed, self.socket_path)
        # The strict launch-time helper still refuses any existing chardev.
        with self.assertRaises(GuestProgressHostError):
            attach_progress_port(base, self.socket_path)

    def test_audit_reports_an_unarmed_command_and_refuses_a_partial_one(self):
        bare = ["qemu-system-x86_64", "-nodefaults"]
        self.assertEqual(audit_progress_port(bare), ())
        armed, chardev = attach_planned_progress_port(bare, self.socket_path)
        self.assertEqual(audit_progress_port(armed), (chardev,))
        for broken in (
            # A chardev with no device: a port nobody can reach.
            bare + ["-chardev", chardev],
            # The devices with no chardev: a channel named, never armed.
            bare + [
                "-device", f"virtserialport,chardev={PROGRESS_CHARDEV_ID}"],
            # The canonical triple twice.
            armed + progress_port_arguments(self.socket_path)[0],
            # A hand-edited chardev value.
            [
                item.replace("server=on", "server=off") for item in armed
            ],
        ):
            with self.subTest(broken=broken[-1]):
                with self.assertRaises(GuestProgressHostError):
                    audit_progress_port(broken)

    def test_socket_directory_preparation_proves_launch_time_privacy(self):
        directory = self.root / "run"
        path = prepare_socket_directory(directory)
        self.assertEqual(path, directory / PROGRESS_SOCKET_NAME)
        self.assertEqual(stat.S_IMODE(directory.stat().st_mode), 0o700)
        # Idempotent for a second channel in the same private root.
        other = prepare_socket_directory(directory, name="controller.sock")
        self.assertEqual(other.parent, directory)
        path.touch()
        with self.assertRaises(GuestProgressHostError):
            prepare_socket_directory(directory)
        path.unlink()
        directory.chmod(0o755)
        with self.assertRaises(GuestProgressHostError):
            prepare_socket_directory(directory)

    def test_socket_root_removal_is_proved_and_fails_closed(self):
        self.assertEqual(remove_socket_root(self.root / "absent"), [])
        populated = self.root / "populated"
        populated.mkdir(mode=0o700)
        (populated / PROGRESS_SOCKET_NAME).write_bytes(b"")
        self.assertEqual(remove_socket_root(populated), [])
        self.assertFalse(populated.exists())
        target = self.root / "target"
        target.mkdir(mode=0o700)
        link = self.root / "link"
        link.symlink_to(target)
        failures = remove_socket_root(link)
        self.assertTrue(failures)
        self.assertTrue(
            all("progress socket root" in failure for failure in failures))


class CollectorTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        os.chmod(self.root, 0o700)
        self.socket_path = self.root / PROGRESS_SOCKET_NAME
        self.credential = mint_credential(prefix="collector-test")
        self.deadline = time.monotonic() + 20

    def _collector(self, **options):
        collector = GuestProgressCollector(
            self.socket_path, deadline=self.deadline,
            credential=self.credential,
            producer=factory_runner.PROGRESS_PRODUCER,
            phases=factory_runner.PROGRESS_PHASES,
            statuses=factory_runner.PROGRESS_STATUSES, **options)
        self.addCleanup(collector.close)
        return collector

    def _server(self):
        server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.addCleanup(server.close)
        server.bind(str(self.socket_path))
        server.listen(4)
        server.settimeout(5)
        return server

    def _report(self, peer, reporter, events):
        """Drive one guest boot's events; return each delivered frame."""
        peer.settimeout(0.05)

        def read_fn():
            try:
                return peer.recv(4096)
            except socket.timeout:
                return b""

        frames = []
        clock = time.monotonic
        for build in events:
            build(reporter)
            frames.append(reporter.pending_frame)
            run_over_stream(reporter, read_fn, peer.sendall, clock=clock)
        return frames

    def _reporter(self):
        return ProgressReporter(
            self.credential.protocol_config(
                producer=factory_runner.PROGRESS_PRODUCER,
                phases=factory_runner.PROGRESS_PHASES,
                statuses=factory_runner.PROGRESS_STATUSES),
            self.credential.key, operation_deadline=time.monotonic() + 20,
            clock=time.monotonic, uuid_source=uuid.uuid4,
            wall_clock=time.time)

    def _drain_session(self, collector):
        """Finish the live session and let the collector reconnect."""
        thread = collector._thread
        if thread is not None:
            thread.join(timeout=5)
        collector.poll()

    def _settle(self, collector):
        """Finish the live session and compose without reconnecting."""
        thread = collector._thread
        if thread is not None:
            thread.join(timeout=5)
        return collector.record()

    def test_an_absent_peer_records_an_absent_stream_honestly(self):
        collector = self._collector()
        for _ in range(3):
            collector.poll()
        record = collector.record()
        self.assertEqual(record["liveness"], "absent")
        self.assertEqual(record["classification"], "unavailable")
        self.assertEqual(record["events_accepted"], 0)
        self.assertIsNone(record["last_phase"])
        self.assertIsNone(record["last_sequence"])
        self.assertIs(record["authoritative"], False)
        self.assertEqual(collector.sessions, 0)
        self.assertEqual(collector.close(), [])

    def test_a_connected_peer_that_says_nothing_is_still_absent(self):
        server = self._server()
        collector = self._collector()
        collector.poll()
        peer, _ = server.accept()
        self.addCleanup(peer.close)
        peer.close()
        record = self._settle(collector)
        self.assertEqual(collector.sessions, 1)
        self.assertEqual(record["liveness"], "absent")
        self.assertEqual(record["events_accepted"], 0)
        self.assertIsNone(record["last_sequence"])

    def test_collection_survives_a_guest_restart_without_moving_the_deadline(
            self):
        """The reconnect case: disconnect, re-poll, a second boot accepted."""
        server = self._server()
        collector = self._collector()
        deadline_before = collector.deadline

        collector.poll()
        first_peer, _ = server.accept()
        first = self._reporter()
        self._report(first_peer, first, [
            lambda reporter: reporter.sync(),
            lambda reporter: reporter.phase_started("installer"),
        ])
        first_peer.close()
        self._drain_session(collector)

        self.assertEqual(collector.sessions, 2)
        self.assertEqual(collector.events_accepted, 2)
        # A new receiver was restored for the second connection, bound to the
        # very same host deadline: progress never buys time.
        self.assertEqual(collector.deadline, deadline_before)
        self.assertEqual(collector._receiver.deadline, deadline_before)

        second_peer, _ = server.accept()
        second = self._reporter()
        self._report(second_peer, second, [
            lambda reporter: reporter.sync(),
            lambda reporter: reporter.phase_started("installer"),
            lambda reporter: reporter.heartbeat("installer"),
        ])
        second_peer.close()
        record = self._settle(collector)
        self.assertEqual(collector.deadline, deadline_before)
        self.assertEqual(len(collector.boots), 2)
        self.assertNotEqual(collector.boots[0], collector.boots[1])
        self.assertEqual(record["events_accepted"], 5)
        self.assertEqual(record["liveness"], "live")
        self.assertEqual(record["last_phase"], "installer")
        # Per-boot sequences restart at zero; the second boot reached two.
        self.assertEqual(record["last_sequence"], 2)
        self.assertIsNone(record["classification"])
        self.assertIs(record["authoritative"], False)

    def test_a_guest_restart_resumes_on_the_unbroken_connection(self):
        """B5's real shape: the unit restarts, QEMU's socket never drops."""
        server = self._server()
        collector = self._collector()
        deadline_before = collector.deadline
        collector.poll()
        peer, _ = server.accept()
        first = self._reporter()
        self._report(peer, first, [lambda item: item.sync()])
        self.assertEqual(collector.sessions, 1)

        # The guest's unit restarts: a new boot identifier arrives on the very
        # same connection, which the receiver must refuse until it is reset.
        second = self._reporter()
        second.sync()
        restarted_frame = second.pending_frame
        assert restarted_frame is not None
        peer.sendall(restarted_frame)
        thread = collector._thread
        assert thread is not None
        thread.join(timeout=5)
        collector.poll()
        # Resumed in place: same connection, restored receiver, new session.
        self.assertEqual(collector.restarts, 1)
        self.assertEqual(collector.sessions, 2)
        self.assertEqual(collector.deadline, deadline_before)
        self.assertEqual(collector._receiver.deadline, deadline_before)

        # The stop-and-wait sender still holds that unacknowledged frame and
        # retransmits it byte for byte; the reset receiver accepts it.
        self._report(peer, second, [])
        peer.settimeout(0.05)

        def read_fn():
            try:
                return peer.recv(4096)
            except socket.timeout:
                return b""

        run_over_stream(second, read_fn, peer.sendall, clock=time.monotonic)
        peer.close()
        record = self._settle(collector)
        self.assertEqual(len(collector.boots), 2)
        self.assertEqual(record["events_accepted"], 2)
        self.assertEqual(record["liveness"], "live")
        # A restart is not a replay: the deferred rejection is cleared once
        # the resumed stream delivers.
        self.assertIsNone(record["classification"])
        self.assertEqual(collector.deadline, deadline_before)

    def test_a_retired_boot_cannot_replay_into_the_restored_receiver(self):
        """Replay resistance carries across the reconnection, not just within it."""
        server = self._server()
        collector = self._collector()
        collector.poll()
        peer, _ = server.accept()
        reporter = self._reporter()
        frames = self._report(peer, reporter, [lambda item: item.sync()])
        retired_frame = frames[0]
        self.assertIsNotNone(retired_frame)
        peer.close()
        self._drain_session(collector)

        stale_peer, _ = server.accept()
        # Byte for byte the frame the retired boot already delivered.
        stale_peer.sendall(retired_frame)
        stale_peer.close()
        record = self._settle(collector)
        self.assertEqual(record["classification"], "replayed")
        self.assertEqual(record["events_accepted"], 1)
        self.assertEqual(len(collector.boots), 1)
        self.assertEqual(collector.deadline, self.deadline)

    def test_reconnection_is_bounded(self):
        server = self._server()
        collector = self._collector(max_sessions=2)
        for _ in range(6):
            collector.poll()
            if collector._thread is not None:
                try:
                    peer, _ = server.accept()
                except socket.timeout:  # pragma: no cover - defensive
                    break
                peer.close()
                collector._thread.join(timeout=5)
        collector.poll()
        self.assertEqual(collector.sessions, 2)
        self.assertLessEqual(collector.sessions, MAX_SESSIONS)

    def test_a_deadline_that_already_passed_opens_no_session(self):
        self._server()
        collector = GuestProgressCollector(
            self.socket_path, deadline=time.monotonic() - 1,
            credential=self.credential,
            producer=factory_runner.PROGRESS_PRODUCER,
            phases=factory_runner.PROGRESS_PHASES,
            statuses=factory_runner.PROGRESS_STATUSES)
        self.addCleanup(collector.close)
        collector.poll()
        self.assertEqual(collector.sessions, 0)
        self.assertEqual(collector.record()["liveness"], "absent")

    def test_the_credential_seam_stages_and_destroys_one_document(self):
        collector = self._collector()
        directory = self.root / "delivery"
        directory.mkdir(mode=0o700)
        path = collector.stage_credential(directory)
        self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
        self.assertEqual(
            path.read_bytes(), collector.credential_document_bytes())
        self.assertNotIn(
            self.credential.key.hex(), collector.record()["classification"]
            or "")
        self.assertEqual(collector.close(), [])
        self.assertFalse(path.exists())


if __name__ == "__main__":
    unittest.main()
