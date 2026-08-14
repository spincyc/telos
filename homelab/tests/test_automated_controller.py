import io
import subprocess
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


class DisposablePathUnchangedTests(unittest.TestCase):
    """The persistent instance mode must not have moved the disposable path.

    Gate 3 requires a *fresh offline-installed disposable* controller, gate 8
    requires a freshly provisioned domain every run, and gate 12 destroys the
    disposable state and repeats. So the disposable boot disk must still be a
    throwaway sparse raw copy, must still hash-fence the canonical, and must
    still delete itself.
    """

    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.canonical_disk = self.root / "bootstrap-dc.qcow2"
        self.canonical_disk.write_bytes(b"canonical disk")
        self.canonical_vars = self.root / "OVMF_VARS.fd"
        self.canonical_vars.write_bytes(b"canonical vars")
        self.proc = self.root / "proc"
        self.proc.mkdir()

    def prepared(self):
        from simulation_overlay import ControllerOverlay

        boot = DisposableBootDisk(
            self.canonical_disk, self.canonical_vars,
            run_root=self.root / "run")
        # Keep the audit off the host's real /proc without changing behaviour.
        boot.overlay = ControllerOverlay(
            self.canonical_disk, self.canonical_vars,
            run_root=self.root / "run" / "guard", proc_root=self.proc)
        self.calls = []

        def fake(argv, **_kwargs):
            self.calls.append(list(argv))
            if argv[0] == "qemu-img" and argv[1] in {"create", "convert"}:
                Path(argv[-1]).write_bytes(b"disposable copy")
            return subprocess.CompletedProcess(argv, 0)

        patcher = patch("subprocess.run", side_effect=fake)
        patcher.start()
        self.addCleanup(patcher.stop)
        with patch.object(DisposableBootDisk, "_inject_entry"):
            boot.prepare()
        return boot

    def test_disposable_disk_is_still_a_sparse_raw_throwaway(self):
        boot = self.prepared()
        convert = next(argv for argv in self.calls if argv[1] == "convert")
        self.assertEqual(convert[convert.index("-O") + 1], "raw")
        self.assertIn("-S", convert)
        self.assertEqual(convert[-1], str(boot.disk))
        self.assertTrue(boot.disk.name.endswith(".raw"))
        self.assertIn("format=raw", boot.qemu_disk_drive())
        boot.close()

    def test_disposable_close_still_fences_the_canonical_and_deletes_state(self):
        boot = self.prepared()
        self.canonical_disk.write_bytes(b"tampered")
        with self.assertRaisesRegex(RuntimeError, "changed during simulation"):
            boot.close()
        self.assertFalse(boot.disk.exists())
        self.assertFalse(boot.vars.exists())

    def test_disposable_clean_close_deletes_the_copies(self):
        boot = self.prepared()
        boot.close()
        self.assertFalse(boot.disk.exists())
        self.assertFalse(boot.vars.exists())
        self.assertTrue(self.canonical_disk.is_file())


class ConstructionTests(unittest.TestCase):
    def test_rejects_blank_or_multiline_password(self):
        from automated_controller import AutomatedSerial
        for value in (b"", b"a\nb", b"a\rb"):
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    AutomatedSerial(io.BytesIO(), io.BytesIO(), value)
