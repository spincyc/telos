import io
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "vm"))

from automated_controller import DisposableBootDisk, EFI_SYSTEM_GUID


class BootEntryTests(unittest.TestCase):
    def test_literal_default_entry(self):
        self.assertEqual(
            DisposableBootDisk._default_entry(
                "timeout 3\ndefault arch-linux-lts.conf\n"),
            "arch-linux-lts.conf",
        )

    def test_rejects_missing_duplicate_glob_and_traversal_defaults(self):
        bad = (
            "timeout 3\n",
            "default a.conf\ndefault b.conf\n",
            "default arch-*.conf\n",
            "default ../arch.conf\n",
        )
        for loader in bad:
            with self.subTest(loader=loader):
                with self.assertRaises(RuntimeError):
                    DisposableBootDisk._default_entry(loader)

    def test_adds_init_to_exactly_one_options_line(self):
        entry = "title Arch\nlinux /vmlinuz\noptions root=UUID=x rw\n"
        self.assertEqual(
            DisposableBootDisk._with_init_shell(entry),
            "title Arch\nlinux /vmlinuz\n"
            "options root=UUID=x rw init=/bin/bash\n",
        )

    def test_rejects_missing_duplicate_or_existing_init(self):
        bad = (
            "title Arch\n",
            "options root=x\noptions rw\n",
            "options root=x init=/usr/lib/systemd/systemd\n",
        )
        for entry in bad:
            with self.subTest(entry=entry):
                with self.assertRaises(RuntimeError):
                    DisposableBootDisk._with_init_shell(entry)


class GeometryTests(unittest.TestCase):
    def disk(self, size=1024 * 1024):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        instance = object.__new__(DisposableBootDisk)
        instance.disk = Path(temporary.name) / "disk.raw"
        with instance.disk.open("wb") as stream:
            stream.truncate(size)
        return instance

    def test_accepts_one_bounded_esp(self):
        instance = self.disk()
        with patch.object(instance, "_partition_table", return_value={
            "sectorsize": 512,
            "partitions": [{
                "type": EFI_SYSTEM_GUID.upper(), "start": 1, "size": 100,
            }],
        }):
            self.assertEqual(instance._esp_offset(), 512)

    def test_rejects_partition_past_image(self):
        instance = self.disk(4096)
        with patch.object(instance, "_partition_table", return_value={
            "sectorsize": 512,
            "partitions": [{
                "type": EFI_SYSTEM_GUID, "start": 1, "size": 8,
            }],
        }):
            with self.assertRaisesRegex(RuntimeError, "geometry"):
                instance._esp_offset()

    def test_rejects_duplicate_esp(self):
        instance = self.disk()
        part = {"type": EFI_SYSTEM_GUID, "start": 1, "size": 100}
        with patch.object(instance, "_partition_table", return_value={
            "sectorsize": 512, "partitions": [part, part],
        }):
            with self.assertRaisesRegex(RuntimeError, "exactly one"):
                instance._esp_offset()


class ConstructionTests(unittest.TestCase):
    def test_rejects_blank_or_multiline_password(self):
        from automated_controller import AutomatedSerial
        for value in (b"", b"a\nb", b"a\rb"):
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    AutomatedSerial(io.BytesIO(), io.BytesIO(), value)
