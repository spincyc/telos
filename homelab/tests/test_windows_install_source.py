import json
import stat
import sys
import tempfile
import unittest
from unittest import mock
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "lib"))
import windows_install_source as source  # noqa: E402


class FakeTools:
    def __init__(self):
        self.extracts = 0
        self.archives = []

    def run(self, command):
        if command[:2] == ["7z", "x"]:
            self.extracts += 1
            self.archives.append(Path(command[-1]))
            root = Path(next(item[2:] for item in command if item.startswith("-o")))
            for relative in (
                "setup.exe",
                "bootmgr",
                "efi/boot/bootx64.efi",
                "sources/boot.wim",
                "sources/install.wim",
            ):
                path = root / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(relative.encode())
        return ""

    @staticmethod
    def verify(_iso, _digest, *, run):
        return {"edition": "Windows 11 Pro"}


class WindowsInstallSourceTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.iso = self.root / "windows.iso"
        self.iso.write_bytes(b"source remains untouched")
        self.digest = "a" * 64
        self.output = self.root / "cache" / "source"
        self.tools = FakeTools()

    def stage(self):
        return source.stage(
            self.iso,
            self.output,
            self.digest,
            run=self.tools.run,
            verify_iso=self.tools.verify,
        )

    def test_stages_complete_read_only_tree_and_receipt(self):
        original = self.iso.read_bytes()
        receipt = self.stage()
        self.assertEqual(original, self.iso.read_bytes())
        self.assertEqual("Windows 11 Pro", receipt["edition"])
        self.assertEqual("sources/install.wim", receipt["install_image"])
        self.assertEqual(receipt, json.loads((self.output / "receipt.json").read_text()))
        self.assertEqual(0o555, stat.S_IMODE(self.output.stat().st_mode))
        self.assertEqual(
            0o444, stat.S_IMODE((self.output / "sources/install.wim").stat().st_mode)
        )
        self.assertEqual(1, self.tools.extracts)
        self.assertNotEqual(self.iso, self.tools.archives[0])
        self.assertEqual("verified-media.iso", self.tools.archives[0].name)

    def test_verified_cache_is_reused_without_extraction(self):
        first = self.stage()
        second = self.stage()
        self.assertEqual(first, second)
        self.assertEqual(1, self.tools.extracts)

    def test_tampered_cache_is_rejected(self):
        self.stage()
        target = self.output / "setup.exe"
        target.chmod(0o644)
        target.write_bytes(b"tampered")
        with self.assertRaisesRegex(source.InstallSourceError, "differs"):
            self.stage()

    def test_changed_mode_is_rejected(self):
        self.stage()
        target = self.output / "setup.exe"
        target.chmod(0o644)
        with self.assertRaisesRegex(source.InstallSourceError, "mode changed"):
            self.stage()

    def test_failed_extraction_is_never_promoted(self):
        def fail(_command):
            raise RuntimeError("extract failed")

        with self.assertRaisesRegex(RuntimeError, "extract failed"):
            source.stage(
                self.iso,
                self.output,
                self.digest,
                run=fail,
                verify_iso=self.tools.verify,
            )
        self.assertFalse(self.output.exists())

    def test_hard_link_in_extraction_is_rejected(self):
        def extract_with_link(command):
            self.tools.run(command)
            if command[:2] == ["7z", "x"]:
                root = Path(
                    next(item[2:] for item in command if item.startswith("-o"))
                )
                (root / "duplicate").hardlink_to(root / "setup.exe")

        with self.assertRaisesRegex(source.InstallSourceError, "hard-linked"):
            source.stage(
                self.iso,
                self.output,
                self.digest,
                run=extract_with_link,
                verify_iso=self.tools.verify,
            )
        self.assertFalse(self.output.exists())

    def test_output_and_lock_symlinks_are_rejected(self):
        target = self.root / "target"
        target.mkdir()
        self.output.parent.mkdir()
        self.output.symlink_to(target, target_is_directory=True)
        with self.assertRaisesRegex(source.InstallSourceError, "symbolic"):
            self.stage()
        self.output.unlink()
        self.output.with_name("source.lock").symlink_to(target)
        with self.assertRaisesRegex(source.InstallSourceError, "symbolic"):
            self.stage()

    def test_source_replacement_after_private_copy_cannot_change_extraction(self):
        original = self.iso.read_bytes()

        def verify(private_iso, _digest, *, run):
            self.assertNotEqual(self.iso, private_iso)
            self.assertEqual(original, private_iso.read_bytes())
            self.iso.write_bytes(b"replacement after private copy")
            return {"edition": "Windows 11 Pro"}

        source.stage(
            self.iso,
            self.output,
            self.digest,
            run=self.tools.run,
            verify_iso=verify,
        )
        self.assertEqual(b"replacement after private copy", self.iso.read_bytes())
        self.assertNotEqual(self.iso, self.tools.archives[0])

    def rewrite_receipt(self, change):
        receipt_path = self.output / "receipt.json"
        self.output.chmod(0o755)
        receipt_path.chmod(0o644)
        receipt = json.loads(receipt_path.read_text())
        change(receipt)
        receipt_path.write_text(json.dumps(receipt))
        receipt_path.chmod(0o444)
        self.output.chmod(0o555)

    def test_semantically_invalid_receipts_are_rejected(self):
        cases = (
            ("edition", lambda value: value.__setitem__("edition", "Windows 11 Pro N")),
            ("file list", lambda value: value.__setitem__("file_count", 999)),
            ("install image", lambda value: value.__setitem__("install_image", "../bad")),
        )
        for message, change in cases:
            with self.subTest(message=message):
                if self.output.exists():
                    for path in self.output.rglob("*"):
                        path.chmod(0o755 if path.is_dir() else 0o644)
                    self.output.chmod(0o755)
                    import shutil
                    shutil.rmtree(self.output)
                self.stage()
                self.rewrite_receipt(change)
                with self.assertRaisesRegex(source.InstallSourceError, message):
                    self.stage()

    def test_fsyncs_before_and_after_atomic_promotion(self):
        calls = 0
        real_fsync = source.os.fsync

        def counted(descriptor):
            nonlocal calls
            calls += 1
            return real_fsync(descriptor)

        with mock.patch.object(source.os, "fsync", side_effect=counted):
            self.stage()
        # Private ISO + receipt, then every file and directory on both sides
        # of rename, followed by the parent directory.
        self.assertGreater(calls, 20)


if __name__ == "__main__":
    unittest.main()
