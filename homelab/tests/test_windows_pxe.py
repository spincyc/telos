import importlib.util
import json
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
WINDOWS = ROOT / "pxe" / "windows"


def load_common():
    spec = importlib.util.spec_from_file_location("windows_pxe_common", WINDOWS / "common.py")
    module = importlib.util.module_from_spec(spec)
    assert spec.loader
    spec.loader.exec_module(module)
    return module


class WindowsPxeTests(unittest.TestCase):
    def setUp(self):
        self.common = load_common()

    def make_release(self, root: Path):
        for relative in (*self.common.PAYLOADS, "boot.ipxe"):
            path = root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(f"fixture:{relative}".encode())
        records = [
            {
                "path": relative,
                "bytes": (root / relative).stat().st_size,
                "sha256": self.common.sha256(root / relative),
            }
            for relative in (*self.common.PAYLOADS, "boot.ipxe")
        ]
        (root / "manifest.json").write_text(
            json.dumps(
                {
                    "schema": 1,
                    "release": root.name,
                    "target": "windows-11-pro-winpe",
                    "redistributable": False,
                    "files": records,
                }
            )
        )

    def test_valid_release(self):
        with tempfile.TemporaryDirectory() as name:
            release = Path(name) / "20260727.001"
            release.mkdir()
            self.make_release(release)
            self.assertEqual([], self.common.verify_release(release))

    def test_tampered_payload_fails(self):
        with tempfile.TemporaryDirectory() as name:
            release = Path(name) / "20260727.001"
            release.mkdir()
            self.make_release(release)
            (release / "sources/boot.wim").write_bytes(b"tampered")
            errors = self.common.verify_release(release)
            self.assertTrue(any("boot.wim" in error for error in errors))

    def test_answer_file_is_forbidden(self):
        with tempfile.TemporaryDirectory() as name:
            release = Path(name) / "20260727.001"
            release.mkdir()
            self.make_release(release)
            (release / "Autounattend.xml").write_text("secret")
            errors = self.common.verify_release(release)
            self.assertTrue(any("forbidden" in error for error in errors))

    def test_release_name_rejects_paths(self):
        with self.assertRaises(ValueError):
            self.common.validate_release_name("../current")
        self.common.validate_release_name("20260727.001")


if __name__ == "__main__":
    unittest.main()
