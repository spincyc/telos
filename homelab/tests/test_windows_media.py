import json
import tempfile
import unittest
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "lib"))
import windows_media  # noqa: E402


class WindowsMediaTests(unittest.TestCase):
    def write_iso(self, path):
        content = bytearray(b"x" * windows_media.MINIMUM_ISO_BYTES)
        start = windows_media.ISO9660_MAGIC_OFFSET
        content[start : start + len(windows_media.ISO9660_MAGIC)] = (
            windows_media.ISO9660_MAGIC
        )
        path.write_bytes(content)

    def test_continuation_uses_official_page_and_exact_command(self):
        output = Path("/var/tmp/media/windows-11.iso")
        text = windows_media.continuation(output)
        self.assertIn("https://www.microsoft.com/software-download/windows11", text)
        self.assertIn("--source /path/to/downloaded.iso", text)
        self.assertIn("--expected-sha256", text)
        self.assertIn(f"--output {output}", text)
        self.assertIn("links expire", text)

    def test_import_is_atomic_and_records_provenance(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            source = root / "Win11.iso"
            self.write_iso(source)
            output = root / "cache" / "windows-11.iso"
            expected = windows_media.sha256(source)

            record = windows_media.import_iso(source, output, expected)

            self.assertEqual(source.read_bytes(), output.read_bytes())
            self.assertEqual(record["sha256"], windows_media.sha256(output))
            saved = json.loads(
                output.with_suffix(".iso.provenance.json").read_text()
            )
            self.assertEqual(record, saved)
            self.assertEqual("Microsoft Software Download", saved["source"])
            self.assertEqual(expected, saved["expected_sha256"])

    def test_rejects_missing_non_iso_and_small_inputs(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            with self.assertRaises(windows_media.MediaError):
                windows_media.validate_source(root / "missing.iso")
            wrong = root / "windows.img"
            wrong.write_bytes(b"x" * windows_media.MINIMUM_ISO_BYTES)
            with self.assertRaises(windows_media.MediaError):
                windows_media.validate_source(wrong)
            small = root / "windows.iso"
            small.write_bytes(b"x")
            with self.assertRaises(windows_media.MediaError):
                windows_media.validate_source(small)
            fake = root / "fake.iso"
            fake.write_bytes(b"x" * windows_media.MINIMUM_ISO_BYTES)
            with self.assertRaises(windows_media.MediaError):
                windows_media.validate_source(fake)

    def test_source_cannot_equal_output(self):
        with tempfile.TemporaryDirectory() as name:
            source = Path(name) / "windows.iso"
            self.write_iso(source)
            with self.assertRaises(windows_media.MediaError):
                windows_media.import_iso(
                    source, source, windows_media.sha256(source)
                )

    def test_rejects_wrong_or_malformed_expected_digest(self):
        with tempfile.TemporaryDirectory() as name:
            source = Path(name) / "windows.iso"
            self.write_iso(source)
            output = Path(name) / "cache.iso"
            with self.assertRaisesRegex(windows_media.MediaError, "64 hexadecimal"):
                windows_media.import_iso(source, output, "no")
            with self.assertRaisesRegex(windows_media.MediaError, "mismatch"):
                windows_media.import_iso(source, output, "0" * 64)
            self.assertFalse(output.exists())

    def test_rejects_output_and_receipt_symlinks(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            source = root / "windows.iso"
            self.write_iso(source)
            expected = windows_media.sha256(source)
            target = root / "target"
            target.write_text("keep")
            output = root / "cached.iso"
            output.symlink_to(target)
            with self.assertRaisesRegex(windows_media.MediaError, "symbolic link"):
                windows_media.import_iso(source, output, expected)
            output.unlink()
            receipt = output.with_suffix(".iso.provenance.json")
            receipt.symlink_to(target)
            with self.assertRaisesRegex(windows_media.MediaError, "symbolic link"):
                windows_media.import_iso(source, output, expected)
            self.assertEqual("keep", target.read_text())


if __name__ == "__main__":
    unittest.main()
