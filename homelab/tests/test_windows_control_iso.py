"""Contracts for the secret-free, read-only Windows control disc."""

import json
from pathlib import Path
import tempfile
import unittest

from homelab.vm.windows_control_iso import (
    ASSET_ROOT,
    WindowsControlIsoError,
    audit_payload,
    build_control_iso,
    probe_launch_command,
)


class WindowsControlIsoTests(unittest.TestCase):
    def test_tracked_payload_is_allowlisted_read_only_and_secret_free(self):
        manifest = audit_payload()
        script = (
            ASSET_ROOT / "Invoke-TelosIdentityProbe.ps1"
        ).read_text(encoding="utf-8")
        self.assertEqual("serial-jsonl", manifest["transport"]["kind"])
        self.assertIn("ValidateSet", script)
        self.assertIn("[System.IO.Ports.SerialPort]", script)
        self.assertIn("dependency-reachability", manifest["actions"])
        self.assertIn("'10.1.31.3')) 31338", script)
        self.assertIn("'update-source:available'", script)
        self.assertIn("'10.1.31.4')) 31339", script)
        self.assertIn("'optional-storage:available'", script)
        self.assertNotIn("Password", script)
        self.assertNotIn("Credential", script)

    def test_builder_stages_only_static_payload_and_public_receipt(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            output = root / "control.iso"
            observed = {}

            def runner(command, *, check):
                self.assertTrue(check)
                stage = Path(command[-1])
                observed["names"] = sorted(
                    item.name for item in stage.iterdir()
                    if item.name != "control.iso")
                observed["receipt"] = json.loads(
                    (stage / "receipt.json").read_text(encoding="utf-8"))
                Path(command[command.index("-o") + 1]).write_bytes(b"iso")

            self.assertEqual(
                output, build_control_iso(output, runner=runner))
            self.assertEqual(0o444, output.stat().st_mode & 0o777)
            self.assertEqual([
                "Invoke-TelosIdentityProbe.ps1", "manifest.json",
                "receipt.json",
            ], observed["names"])
            self.assertFalse(observed["receipt"]["contains_secrets"])
            self.assertTrue(observed["receipt"]["read_only_actions"])
            self.assertEqual(
                set(observed["receipt"]["actions"]),
                set(audit_payload()["actions"]))

    def test_launch_command_discovers_volume_and_accepts_only_manifest_action(self):
        command = probe_launch_command("domain-state")
        self.assertIn("TELOS_CONTROL", command)
        self.assertIn("Invoke-TelosIdentityProbe.ps1", command)
        self.assertIn("-Action 'domain-state'", command)
        self.assertLessEqual(len(command), 512)
        with self.assertRaisesRegex(
                WindowsControlIsoError, "not allowlisted"):
            probe_launch_command("domain-state'; Set-LocalUser")

    def test_existing_destination_and_mutating_script_are_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            output = root / "control.iso"
            output.write_bytes(b"existing")
            with self.assertRaisesRegex(
                    WindowsControlIsoError, "destination must be absent"):
                build_control_iso(output)

            assets = root / "assets"
            assets.mkdir()
            for item in ASSET_ROOT.iterdir():
                (assets / item.name).write_bytes(item.read_bytes())
            script = assets / "Invoke-TelosIdentityProbe.ps1"
            script.write_text(
                script.read_text(encoding="utf-8") + "\nSet-LocalUser\n",
                encoding="utf-8")
            with self.assertRaisesRegex(
                    WindowsControlIsoError, "mutating"):
                audit_payload(assets)


if __name__ == "__main__":
    unittest.main()
