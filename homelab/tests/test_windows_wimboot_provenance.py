import hashlib
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[1]
WINDOWS = ROOT / "pxe" / "windows"
sys.path.insert(0, str(WINDOWS))


def load_stage():
    spec = importlib.util.spec_from_file_location("windows_stage", WINDOWS / "stage.py")
    module = importlib.util.module_from_spec(spec)
    assert spec.loader
    spec.loader.exec_module(module)
    return module


class WimbootProvenanceTests(unittest.TestCase):
    def setUp(self):
        self.stage = load_stage()

    def make_inputs(self, root: Path):
        binary = root / "wimboot"
        binary.write_bytes(b"pinned binary")
        digest = hashlib.sha256(binary.read_bytes()).hexdigest()
        metadata = root / "wimboot.json"
        metadata.write_text(json.dumps({
            "schema": 1,
            "name": "wimboot",
            "version": "2.9.0",
            "source": "https://github.com/ipxe/wimboot",
            "release": "https://github.com/ipxe/wimboot/releases/tag/v2.9.0",
            "url": "https://github.com/ipxe/wimboot/releases/download/v2.9.0/wimboot",
            "size": binary.stat().st_size,
            "sha256": digest,
        }))
        return binary, metadata

    def test_verified_provenance_is_manifest_ready(self):
        with tempfile.TemporaryDirectory() as name:
            binary, metadata = self.make_inputs(Path(name))
            record = self.stage.wimboot_provenance(binary, metadata)
            self.assertEqual("2.9.0", record["version"])
            self.assertEqual(hashlib.sha256(binary.read_bytes()).hexdigest(), record["sha256"])

    def test_changed_binary_is_rejected(self):
        with tempfile.TemporaryDirectory() as name:
            binary, metadata = self.make_inputs(Path(name))
            binary.write_bytes(b"substitution")
            with self.assertRaisesRegex(RuntimeError, "pinned provenance"):
                self.stage.wimboot_provenance(binary, metadata)


if __name__ == "__main__":
    unittest.main()
