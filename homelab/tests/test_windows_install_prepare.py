"""Contracts for guarded Windows installation bundle preparation."""

import subprocess
import argparse
import json
import tempfile
import unittest
from unittest import mock
from pathlib import Path

from homelab.vm import windows_install_prepare


class WindowsInstallPrepareTests(unittest.TestCase):
    def test_default_is_read_only_plan(self):
        with unittest.mock.patch.object(
                windows_install_prepare, "prepare") as prepare:
            self.assertEqual(windows_install_prepare.main([]), 0)
            prepare.assert_not_called()

    def test_apply_is_the_only_prepare_path(self):
        expected = Path("/private/run")
        with unittest.mock.patch.object(
                windows_install_prepare, "prepare",
                return_value=expected) as prepare:
            self.assertEqual(windows_install_prepare.main(["--apply"]), 0)
            prepare.assert_called_once()

    def test_direct_command_help_works(self):
        command = (
            Path(__file__).resolve().parents[1]
            / "bin/homelab-windows-install-prepare")
        result = subprocess.run(
            ["python3", str(command), "--help"],
            check=False, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("--apply", result.stdout)

    def test_apply_passes_an_absent_publication_destination(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            releases = root / "pxe"
            releases.mkdir()
            (releases / "selected-release-set.json").write_text(json.dumps({
                "schema": 1, "version": "20260727.005",
                "manifest_sha256": "a" * 64,
            }))
            firmware = root / "vars.fd"
            firmware.write_bytes(b"vars")
            arguments = argparse.Namespace(
                run_root=root / "runs", releases=releases,
                windows_source=root / "source", seed=root / "seed.iso",
                layout=root / "layout.json",
                workstation_profile=root / "workstation.json",
                switch_port=31415)
            authorization = mock.Mock(release_version="20260727.005")
            authorization.disk = {"virtual_size": 256 * 1024**3}
            private = mock.MagicMock()
            private.__enter__.return_value = private
            private.path = root / "private/run-test"
            private.render_windows_inputs.return_value = []
            private.public_receipt.return_value = {
                "schema": 1, "authorization": {}}
            def execute(command, **_kwargs):
                if command[0] == "qemu-img":
                    Path(command[-2]).write_bytes(b"disk")
                elif command[0] == "xorriso":
                    Path(command[command.index("-o") + 1]).write_bytes(b"iso")
                return subprocess.CompletedProcess(command, 0)
            with mock.patch.object(
                    windows_install_prepare.subprocess, "run",
                    side_effect=execute), \
                    mock.patch.object(
                        windows_install_prepare, "ovmf_pair",
                        return_value=(root / "code.fd", firmware)), \
                    mock.patch.object(
                        windows_install_prepare, "qemu_install_command",
                        return_value=["qemu"]), \
                    mock.patch.object(
                        windows_install_prepare, "authorize",
                        return_value=authorization), \
                    mock.patch.object(
                        windows_install_prepare, "PrivateRun",
                        return_value=private), \
                    mock.patch.object(
                        windows_install_prepare, "stage_publication",
                        return_value={
                            "selected_manifest_sha256": "a" * 64,
                            "windows_install_source": {},
                        }) as stage:
                run = windows_install_prepare.prepare(arguments)
            destination = stage.call_args.args[1]
            self.assertNotEqual(destination, Path(destination).parent)
            self.assertEqual(Path(destination).name, "publication")
            identity = private.render_windows_inputs.call_args.args[1]
            self.assertEqual(identity.install_user, "pxe-install")
            self.assertTrue(run.is_dir())


if __name__ == "__main__":
    unittest.main()
