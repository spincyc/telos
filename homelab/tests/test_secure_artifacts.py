import os
import stat
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "vm"))

from secure_artifacts import (  # noqa: E402
    atomic_append_text, atomic_write_text, private_directory,
)


class SecureArtifactTests(unittest.TestCase):
    def test_private_directory_and_atomic_file_modes(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary) / "evidence"
            private_directory(directory)
            target = directory / "receipt.json"
            atomic_write_text(target, "first\n")
            self.assertEqual(stat.S_IMODE(directory.stat().st_mode), 0o700)
            self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o600)
            self.assertEqual(target.read_text(), "first\n")

    def test_replacement_is_atomic_and_remains_private(self):
        with tempfile.TemporaryDirectory() as temporary:
            target = Path(temporary) / "evidence" / "transcript"
            atomic_write_text(target, "old")
            old_inode = target.stat().st_ino
            atomic_write_text(target, "new")
            self.assertNotEqual(target.stat().st_ino, old_inode)
            self.assertEqual(target.read_text(), "new")
            self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o600)

    def test_append_preserves_prior_records_privately(self):
        with tempfile.TemporaryDirectory() as temporary:
            target = Path(temporary) / "evidence" / "transcript"
            atomic_append_text(target, "one\n")
            atomic_append_text(target, "two\n")
            self.assertEqual(target.read_text(), "one\ntwo\n")
            self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o600)

    def test_rejects_symlink_destination_without_touching_victim(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            victim = root / "victim"
            victim.write_text("keep")
            directory = root / "evidence"
            directory.mkdir()
            target = directory / "receipt"
            target.symlink_to(victim)
            with self.assertRaisesRegex(RuntimeError, "not a regular file"):
                atomic_write_text(target, "secret")
            self.assertEqual(victim.read_text(), "keep")
            self.assertTrue(target.is_symlink())

    def test_rejects_symlink_directory(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            real = root / "real"
            real.mkdir()
            link = root / "evidence"
            link.symlink_to(real, target_is_directory=True)
            with self.assertRaisesRegex(RuntimeError, "not a real directory"):
                private_directory(link)
            with self.assertRaisesRegex(RuntimeError, "not a real directory"):
                atomic_write_text(link / "receipt", "secret")
            self.assertEqual(list(real.iterdir()), [])

    def test_rejects_symlink_custom_root_before_creating_child(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            real = root / "real"
            real.mkdir()
            custom_root = root / "custom"
            custom_root.symlink_to(real, target_is_directory=True)
            with self.assertRaisesRegex(RuntimeError, "not a real directory"):
                private_directory(custom_root)
            self.assertEqual(list(real.iterdir()), [])

    def test_rejects_fifo_destination(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary) / "evidence"
            directory.mkdir()
            target = directory / "record"
            os.mkfifo(target)
            with self.assertRaisesRegex(RuntimeError, "not a regular file"):
                atomic_write_text(target, "secret")

    def test_tightens_existing_artifact_directory(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary) / "evidence"
            directory.mkdir(mode=0o755)
            private_directory(directory)
            self.assertEqual(stat.S_IMODE(directory.stat().st_mode), 0o700)


if __name__ == "__main__":
    unittest.main()
