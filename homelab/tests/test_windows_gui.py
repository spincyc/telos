import json
import os
import socket
import struct
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from homelab.vm.windows_gui import (
    Checkpoint,
    Image,
    WindowsGuiError,
    WindowsSetupDriver,
    crop_image,
    image_distance,
    load_plan,
    read_ppm,
    useful_frame,
)
from homelab.vm import windows_gui


def ppm(path: Path, width=320, height=200, value=80):
    pixels = bytes([value, value + 30, value + 60]) * width * height
    path.write_bytes(f"P6\n{width} {height}\n255\n".encode() + pixels)


class FakeQmp:
    def __init__(self, source):
        self.source = source
        self.keys = []

    def screenshot(self, path):
        path.write_bytes(self.source.read_bytes())

    def key(self, name):
        self.keys.append(name)


class WindowsGuiTests(unittest.TestCase):
    def qmp_pair(self, *, event_limit=256, response_limit=256):
        client_socket, peer = socket.socketpair()
        self.addCleanup(client_socket.close)
        self.addCleanup(peer.close)
        return (
            windows_gui.QmpClient(
                client_socket,
                event_limit=event_limit,
                response_limit=response_limit,
            ),
            peer,
        )

    @staticmethod
    def send_qmp(peer, *messages):
        peer.sendall(b"".join(
            json.dumps(message).encode() + b"\r\n" for message in messages))

    def test_qmp_connect_requires_exact_unix_peer_credentials(self):
        connection = mock.Mock()
        connection.fileno.return_value = 12
        connection.getsockopt.return_value = struct.pack(
            "3i", os.getpid(), os.geteuid(), os.getegid())
        with (
            mock.patch.object(
                windows_gui.socket, "socket", return_value=connection),
            mock.patch.object(
                windows_gui.QmpClient, "_message",
                return_value={"QMP": {}}),
            mock.patch.object(
                windows_gui.QmpClient, "execute") as execute,
        ):
            client = windows_gui.QmpClient.connect(
                Path("/private/windows.qmp"),
                expected_peer_pid=os.getpid())

        self.assertIs(connection, client.connection)
        connection.getsockopt.assert_called_once_with(
            socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i"))
        execute.assert_called_once_with("qmp_capabilities")
        connection.close.assert_not_called()

    def test_qmp_connect_closes_every_peer_credential_mismatch(self):
        expected = (731, os.geteuid(), os.getegid())
        mismatches = (
            (732, expected[1], expected[2]),
            (expected[0], expected[1] + 1, expected[2]),
            (expected[0], expected[1], expected[2] + 1),
        )
        for observed in mismatches:
            with self.subTest(observed=observed):
                connection = mock.Mock()
                connection.fileno.return_value = 12
                connection.getsockopt.return_value = struct.pack(
                    "3i", *observed)
                with mock.patch.object(
                        windows_gui.socket, "socket",
                        return_value=connection):
                    with self.assertRaisesRegex(
                            WindowsGuiError, "peer credentials"):
                        windows_gui.QmpClient.connect(
                            Path("/private/windows.qmp"),
                            expected_peer_pid=expected[0])
                connection.close.assert_called_once_with()

    def test_qmp_connect_rejects_invalid_expected_pid_before_opening_socket(self):
        with mock.patch.object(windows_gui.socket, "socket") as socket_factory:
            with self.assertRaisesRegex(ValueError, "positive integer"):
                windows_gui.QmpClient.connect(
                    Path("/private/windows.qmp"), expected_peer_pid=True)
        socket_factory.assert_not_called()

    def test_ppm_and_distance(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            one, two = root / "one.ppm", root / "two.ppm"
            ppm(one, value=40)
            ppm(two, value=42)
            image = read_ppm(one)
            self.assertTrue(useful_frame(image))
            self.assertEqual(2.0, image_distance(image, read_ppm(two)))
            cropped = crop_image(image, (10, 20, 40, 30))
            self.assertEqual((40, 30), (cropped.width, cropped.height))

    def test_ppm_preserves_whitespace_pixel(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "frame.ppm"
            pixels = b"\x0a\x20\x09" + b"\x40" * (320 * 200 * 3 - 3)
            path.write_bytes(b"P6\n320 200\n255\n" + pixels)
            self.assertEqual(pixels, read_ppm(path).pixels)

    def test_bad_and_blank_frames_fail(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "bad.ppm"
            path.write_bytes(b"P6\n1 1\n255\n\x00\x00\x00")
            with self.assertRaises(WindowsGuiError):
                read_ppm(path)
            self.assertFalse(useful_frame(Image(320, 200, b"\x00" * 192000)))

    def test_driver_observes_before_input(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            reference = root / "reference.ppm"
            ppm(reference)
            qmp = FakeQmp(reference)
            driver = WindowsSetupDriver(
                qmp, root, pause=lambda _: None)
            events = driver.run((
                Checkpoint("locale", reference, ("tab", "ret"), timeout=1),
            ))
            self.assertEqual(["tab", "ret"], qmp.keys)
            self.assertEqual(
                ("observed:locale", "key:tab", "key:ret"), events)
            self.assertTrue((root / "0001-locale.ppm").exists())

    def test_mismatch_never_sends_input(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            actual, reference = root / "actual.ppm", root / "reference.ppm"
            ppm(actual, value=20)
            ppm(reference, value=180)
            qmp = FakeQmp(actual)
            ticks = iter((0.0, 0.0, 2.0))
            driver = WindowsSetupDriver(
                qmp, root, interval=0, clock=lambda: next(ticks),
                pause=lambda _: None)
            with self.assertRaises(WindowsGuiError):
                driver.run((Checkpoint(
                    "wrong", reference, ("ret",), timeout=1),))
            self.assertEqual([], qmp.keys)

    def test_plan_rejects_text_keys_and_escape(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            plan = root / "plan.json"
            plan.write_text(json.dumps({
                "schema": 1,
                "steps": [{
                    "name": "bad", "reference": "screen.ppm", "keys": ["a"],
                }],
            }))
            with self.assertRaises(WindowsGuiError):
                load_plan(plan, root)
            plan.write_text(json.dumps({
                "schema": 1,
                "steps": [{
                    "name": "bad", "reference": "../screen.ppm", "keys": [],
                }],
            }))
            with self.assertRaises(WindowsGuiError):
                load_plan(plan, root)

    def test_plan_loads_bounded_navigation(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            plan = root / "plan.json"
            plan.write_text(json.dumps({
                "schema": 1,
                "steps": [{
                    "name": "license", "reference": "license.ppm",
                    "keys": ["tab", "spc", "ret"], "timeout": 120,
                    "threshold": 4, "crop": [20, 20, 100, 100],
                }],
            }))
            loaded = load_plan(plan, root)
            self.assertEqual(("tab", "spc", "ret"), loaded[0].keys)
            self.assertEqual(120, loaded[0].timeout)
            self.assertEqual((20, 20, 100, 100), loaded[0].crop)

    def test_qmp_text_typing_uses_key_events_without_echoing_failures(self):
        client = object.__new__(windows_gui.QmpClient)
        requests = []
        client._clock = lambda: 0.0
        client._pause = lambda interval: None
        client._key_interval = 0.10
        client.execute = (
            lambda command, arguments=None, timeout=None:
            requests.append((command, arguments))
        )
        client.type_text("Aa1-_! .")
        keys = [
            tuple(key["data"] for key in arguments["keys"])
            for command, arguments in requests
            if command == "send-key"
        ]
        self.assertEqual(
            [
                ("shift", "a"), ("a",), ("1",), ("minus",),
                ("shift", "minus"), ("shift", "1"), ("spc",), ("dot",),
            ],
            keys,
        )
        with self.assertRaisesRegex(
                WindowsGuiError, "offset 1") as failure:
            client.type_text("x\nsecret")
        self.assertNotIn("secret", str(failure.exception))
        self.assertEqual(8, len(requests))

    def test_qmp_key_allows_backspace_and_rejects_unlisted_keys(self):
        client = object.__new__(windows_gui.QmpClient)
        client.execute = mock.Mock()

        client.key("backspace", timeout=2.0)

        client.execute.assert_called_once_with(
            "send-key",
            {
                "keys": [{"type": "qcode", "data": "backspace"}],
                "hold-time": 60,
            },
            timeout=2.0,
        )
        with self.assertRaisesRegex(WindowsGuiError, "unsafe GUI key"):
            client.key("delete")
        self.assertEqual(1, client.execute.call_count)

    def test_qmp_text_typing_shares_one_aggregate_timeout(self):
        client = object.__new__(windows_gui.QmpClient)
        now = [10.0]
        client._clock = lambda: now[0]
        client._pause = lambda interval: now.__setitem__(0, now[0] + interval)
        client._key_interval = 0.10
        requests = []

        def execute(command, arguments=None, *, timeout=None):
            requests.append((command, arguments, timeout))
            now[0] += 0.6

        client.execute = execute
        with self.assertRaisesRegex(
                WindowsGuiError, "timed out") as failure:
            client.type_text("abc", timeout=1.0)

        self.assertEqual(2, len(requests))
        self.assertEqual([1.0, 0.3], [
            round(request[2], 1) for request in requests])
        self.assertNotIn("abc", str(failure.exception))

    def test_qmp_text_prevalidates_before_sending_any_key(self):
        client = object.__new__(windows_gui.QmpClient)
        client._clock = lambda: 0.0
        client._pause = lambda interval: None
        client._key_interval = 0.10
        client.execute = mock.Mock()

        with self.assertRaisesRegex(WindowsGuiError, "offset 2"):
            client.type_text("ab\nsecret", timeout=1.0)

        client.execute.assert_not_called()

    def test_qmp_text_typing_paces_between_keys_with_one_deadline(self):
        client = object.__new__(windows_gui.QmpClient)
        now = [4.0]
        pauses = []
        requests = []
        client._clock = lambda: now[0]
        client._key_interval = 0.10

        def pause(interval):
            pauses.append(interval)
            now[0] += interval

        def execute(command, arguments=None, *, timeout=None):
            requests.append((command, timeout))
            now[0] += 0.1

        client._pause = pause
        client.execute = execute
        client.type_text("abc", timeout=1.0)

        self.assertEqual([0.10, 0.10], pauses)
        self.assertEqual(
            [1.0, 0.8, 0.6],
            [round(timeout, 2) for _, timeout in requests],
        )

    def test_qmp_text_pacing_cannot_exceed_aggregate_deadline(self):
        client = object.__new__(windows_gui.QmpClient)
        now = [8.0]
        client._clock = lambda: now[0]
        client._key_interval = 0.10
        client.execute = mock.Mock()

        def pause(interval):
            now[0] += interval

        client._pause = pause
        with self.assertRaisesRegex(WindowsGuiError, "timed out"):
            client.type_text("ab", timeout=0.02)

        client.execute.assert_called_once()

    def test_qmp_execute_clamps_and_restores_socket_timeout(self):
        client = object.__new__(windows_gui.QmpClient)
        connection = mock.Mock()
        connection.gettimeout.return_value = 5.0
        reader = mock.Mock()
        reader.readline.side_effect = socket.timeout("private backend detail")
        client.connection = connection
        client.reader = reader
        client.sequence = 0
        client._events = []
        client._responses = {}
        client._event_limit = 256
        client._response_limit = 256
        ticks = iter((20.0, 20.25, 20.5))
        client._clock = lambda: next(ticks)

        with self.assertRaisesRegex(
                WindowsGuiError, "^QMP command timed out$"):
            client.execute("send-key", timeout=1.0)

        self.assertEqual(
            [mock.call(0.75), mock.call(0.5), mock.call(5.0)],
            connection.settimeout.call_args_list,
        )

    def test_qmp_awaits_exact_device_deleted_and_retains_other_events(self):
        client, peer = self.qmp_pair()
        self.send_qmp(
            peer,
            {"event": "DEVICE_DELETED", "data": {"device": "other"}},
            {"event": "RESET", "data": {}},
            {"event": "DEVICE_DELETED", "data": {"device": "join-media"}},
        )
        event = client.await_device_deleted("join-media", timeout=0.5)
        self.assertEqual("join-media", event["data"]["device"])
        self.assertEqual(
            ["DEVICE_DELETED", "RESET"],
            [queued["event"] for queued in client._events],
        )

    def test_qmp_await_preserves_response_for_correlated_execute(self):
        client, peer = self.qmp_pair()
        self.send_qmp(
            peer,
            {"return": {"preserved": True}, "id": "windows-gui-1"},
            {"event": "DEVICE_DELETED", "data": {"device": "join-media"}},
        )
        client.await_device_deleted("join-media", timeout=0.5)
        self.assertEqual(
            {"preserved": True}, client.execute("query-status"))
        request = json.loads(peer.recv(4096).splitlines()[0])
        self.assertEqual("windows-gui-1", request["id"])

    def test_qmp_event_queue_is_bounded_and_timeout_restored(self):
        client, peer = self.qmp_pair(event_limit=1)
        peer_timeout = client.connection.gettimeout()
        self.send_qmp(
            peer,
            {"event": "RESET"},
            {"event": "STOP"},
        )
        with self.assertRaisesRegex(
                WindowsGuiError, "event queue limit exceeded"):
            client.await_device_deleted("join-media", timeout=0.5)
        self.assertEqual(peer_timeout, client.connection.gettimeout())

    def test_qmp_device_deleted_timeout_is_bounded(self):
        client, _peer = self.qmp_pair()
        with self.assertRaisesRegex(
                WindowsGuiError, "timed out awaiting DEVICE_DELETED"):
            client.await_device_deleted("join-media", timeout=0.01)


if __name__ == "__main__":
    unittest.main()
