import json
import socket
import tempfile
import unittest
from pathlib import Path

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
        client.execute = lambda command, arguments=None: requests.append(
            (command, arguments))
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
