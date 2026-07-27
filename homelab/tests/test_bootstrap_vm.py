import contextlib
import io
import json
import subprocess
import tempfile
import unittest
import sys
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from vm import bootstrap_dc


class BootstrapVmTests(unittest.TestCase):
    def test_command_is_isolated_and_has_declared_shape(self):
        with mock.patch.object(
                bootstrap_dc, "ovmf_pair",
                return_value=(Path("/code"), Path("/vars"))):
            command = bootstrap_dc.qemu_command(Path("/state"), None)
        joined = " ".join(command)
        self.assertIn("-smp 4", joined)
        self.assertIn("-m 8192", joined)
        self.assertIn("socket,id=bootstrap,listen=127.0.0.1:12961", joined)
        self.assertNotIn("bridge", joined)
        self.assertNotIn("tap", joined)
        self.assertNotIn("user,id=", joined)

    def test_command_attaches_requested_iso_read_only(self):
        with mock.patch.object(
                bootstrap_dc, "ovmf_pair",
                return_value=(Path("/code"), Path("/vars"))):
            command = bootstrap_dc.qemu_command(
                Path("/state"), Path("/media/arch.iso"))
        self.assertIn(
            "media=cdrom,readonly=on,file=/media/arch.iso", command)

    def test_create_defaults_to_dry_run(self):
        with tempfile.TemporaryDirectory() as temp:
            state = Path(temp) / "state"
            with mock.patch.object(bootstrap_dc.shutil, "which",
                                   return_value="/usr/bin/qemu-img"), \
                    mock.patch.object(
                        bootstrap_dc, "ovmf_pair",
                        return_value=(Path("/code"), Path("/vars"))), \
                    mock.patch.object(bootstrap_dc.subprocess, "run") as run:
                self.assertEqual(bootstrap_dc.create(state, False), 0)
            self.assertFalse(state.exists())
            run.assert_not_called()

    def test_destroy_needs_exact_confirmation(self):
        with tempfile.TemporaryDirectory() as temp:
            state = Path(temp) / "state"
            state.mkdir()
            with contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(bootstrap_dc.destroy(state, None), 2)
            self.assertTrue(state.exists())

    def test_destroy_refuses_unknown_files(self):
        with tempfile.TemporaryDirectory() as temp:
            state = Path(temp) / "state"
            state.mkdir()
            (state / "keep-me").write_text("important\n")
            with contextlib.redirect_stderr(io.StringIO()):
                result = bootstrap_dc.destroy(
                    state, bootstrap_dc.NAME)
            self.assertEqual(result, 2)
            self.assertTrue((state / "keep-me").exists())

    def test_create_is_transactional_and_private(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            firmware = root / "vars"
            firmware.write_bytes(b"firmware")
            state = root / "state"

            def create_disk(command, check):
                Path(command[-2]).write_bytes(b"disk")

            with mock.patch.object(bootstrap_dc.shutil, "which",
                                   return_value="/usr/bin/qemu-img"), \
                    mock.patch.object(
                        bootstrap_dc, "ovmf_pair",
                        return_value=(Path("/code"), firmware)), \
                    mock.patch.object(
                        bootstrap_dc.subprocess, "run",
                        side_effect=create_disk):
                self.assertEqual(bootstrap_dc.create(state, True), 0)

            self.assertEqual(state.stat().st_mode & 0o777, 0o700)
            for name in ("bootstrap-dc.qcow2", "OVMF_VARS.fd", "manifest.json"):
                self.assertEqual((state / name).stat().st_mode & 0o777, 0o600)
            manifest = json.loads((state / "manifest.json").read_text())
            self.assertEqual(manifest["schema"], 1)
            self.assertEqual(
                manifest["network"]["physical_attachment"],
                "blocked-pending-network-gate")

    def test_create_cleans_up_failed_transaction(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            firmware = root / "vars"
            firmware.write_bytes(b"firmware")
            state = root / "state"
            with mock.patch.object(bootstrap_dc.shutil, "which",
                                   return_value="/usr/bin/qemu-img"), \
                    mock.patch.object(
                        bootstrap_dc, "ovmf_pair",
                        return_value=(Path("/code"), firmware)), \
                    mock.patch.object(
                        bootstrap_dc.subprocess, "run",
                        side_effect=subprocess.CalledProcessError(1, "qemu-img")):
                with self.assertRaises(subprocess.CalledProcessError):
                    bootstrap_dc.create(state, True)
            self.assertFalse(state.exists())
            self.assertEqual(list(root.glob(".state.*")), [])

    def test_status_and_destroy_refuse_symlink_state(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            actual = root / "actual"
            actual.mkdir()
            state = root / "state"
            state.symlink_to(actual, target_is_directory=True)
            with contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(bootstrap_dc.destroy(
                    state, bootstrap_dc.NAME), 2)
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(bootstrap_dc.status(state), 1)
            self.assertTrue(actual.exists())

    def test_run_refuses_world_readable_state(self):
        with tempfile.TemporaryDirectory() as temp:
            state = Path(temp) / "state"
            state.mkdir(mode=0o700)
            for name in ("bootstrap-dc.qcow2", "OVMF_VARS.fd", "manifest.json"):
                path = state / name
                path.write_text("x")
                path.chmod(0o600)
            (state / "manifest.json").chmod(0o644)
            with contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(bootstrap_dc.run(state, None, False), 2)


if __name__ == "__main__":
    unittest.main()
