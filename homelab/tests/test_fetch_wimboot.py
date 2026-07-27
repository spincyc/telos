import importlib.machinery
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "bin" / "homelab-fetch-wimboot"


def load_script():
    loader = importlib.machinery.SourceFileLoader("fetch_wimboot", str(SCRIPT))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


class Response:
    def __init__(self, body: bytes, url: str):
        self.body = body
        self.url = url

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def geturl(self):
        return self.url

    def read(self, size):
        body, self.body = self.body[:size], self.body[size:]
        return body


class FetchWimbootTests(unittest.TestCase):
    def setUp(self):
        self.module = load_script()
        self.body = b"official fixture"

    def metadata(self, root: Path, **changes) -> Path:
        import hashlib

        record = {
            "schema": 1,
            "name": "wimboot",
            "version": "2.9.0",
            "source": "https://github.com/ipxe/wimboot",
            "release": "https://github.com/ipxe/wimboot/releases/tag/v2.9.0",
            "url": "https://github.com/ipxe/wimboot/releases/download/v2.9.0/wimboot",
            "size": len(self.body),
            "sha256": hashlib.sha256(self.body).hexdigest(),
        }
        record.update(changes)
        path = root / "wimboot.json"
        path.write_text(json.dumps(record))
        return path

    def test_repository_metadata_is_pinned_and_valid(self):
        record = self.module.load_metadata(ROOT / "media" / "wimboot.json")
        self.assertEqual("2.9.0", record["version"])
        self.assertEqual(64, len(record["sha256"]))

    def test_fetch_replaces_output_only_after_verification(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            output = root / "wimboot"
            output.write_bytes(b"old")
            response = Response(self.body, "https://release-assets.githubusercontent.com/object")
            with patch.object(self.module.urllib.request, "urlopen", return_value=response):
                self.module.fetch(self.metadata(root), output)
            self.assertEqual(self.body, output.read_bytes())
            self.assertEqual(0o755, output.stat().st_mode & 0o777)

    def test_checksum_failure_preserves_existing_output(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            output = root / "wimboot"
            output.write_bytes(b"old")
            response = Response(self.body, "https://github.com/ipxe/wimboot/releases/file")
            metadata = self.metadata(root, sha256="0" * 64)
            with patch.object(self.module.urllib.request, "urlopen", return_value=response):
                with self.assertRaisesRegex(RuntimeError, "SHA-256"):
                    self.module.fetch(metadata, output)
            self.assertEqual(b"old", output.read_bytes())
            self.assertEqual([], list(root.glob(".wimboot-*")))

    def test_nonofficial_source_is_rejected_before_network(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            metadata = self.metadata(
                root, url="https://example.test/ipxe/wimboot/releases/download/v2.9.0/wimboot")
            with patch.object(self.module.urllib.request, "urlopen") as request:
                with self.assertRaisesRegex(ValueError, "official release"):
                    self.module.fetch(metadata, root / "output")
            request.assert_not_called()


if __name__ == "__main__":
    unittest.main()
