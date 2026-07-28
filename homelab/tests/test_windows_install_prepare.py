"""Contracts for guarded Windows installation bundle preparation."""

import subprocess
import unittest
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


if __name__ == "__main__":
    unittest.main()
