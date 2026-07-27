import json
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


if __name__ == "__main__":
    unittest.main()
