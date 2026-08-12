import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from homelab.vm.windows_identity_recovery import (
    RecoveredLocalCredential,
    WindowsIdentityRecoveryError,
)


XML = """<?xml version="1.0"?>
<unattend xmlns="urn:schemas-microsoft-com:unattend">
  <Password><Value>S-private-value_123</Value><PlainText>true</PlainText></Password>
  <AutoLogon><Password><Value>S-private-value_123</Value></Password></AutoLogon>
</unattend>
"""


class WindowsIdentityRecoveryTests(unittest.TestCase):
    @staticmethod
    def xorriso(command, **_kwargs):
        if "-find" in command:
            return subprocess.CompletedProcess(
                command, 0, stdout=(
                    "-rw------- 1 1000 1000 4000 Jul 28 00:00 "
                    "'/www/private/run/Autounattend.xml'\n"))
        destination = Path(command[-1])
        destination.write_text(XML)
        return subprocess.CompletedProcess(command, 0)

    def test_recovery_is_private_transient_and_publication_is_consumable(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            root.chmod(0o700)
            publication = root / "publication.iso"
            publication.write_bytes(b"iso")
            publication.chmod(0o600)
            recovery = RecoveredLocalCredential(publication, root)
            with mock.patch(
                    "homelab.vm.windows_identity_recovery.subprocess.run",
                    side_effect=self.xorriso):
                with recovery as value:
                    self.assertEqual("S-private-value_123", value)
                    recovery.destroy_publication()
                    self.assertFalse(publication.exists())
                    # The transient credential directory is removed as soon as
                    # the value is extracted, so it is already gone inside the
                    # context -- it never persists into the acceptance run.
                    self.assertFalse(any(
                        path.name.startswith(".credential-")
                        for path in root.iterdir()))
            self.assertFalse(any(
                path.name.startswith(".credential-")
                for path in root.iterdir()))
            self.assertIsNone(recovery._value)

    def test_recovery_rejects_permissive_or_ambiguous_inputs(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            root.chmod(0o700)
            publication = root / "publication.iso"
            publication.write_bytes(b"iso")
            publication.chmod(0o644)
            with self.assertRaisesRegex(
                    WindowsIdentityRecoveryError, "0600"):
                RecoveredLocalCredential(publication, root).__enter__()
            publication.chmod(0o600)
            def ambiguous(command, **kwargs):
                result = self.xorriso(command, **kwargs)
                if "-find" in command:
                    result.stdout += (
                        "-rw------- 1 1000 1000 4000 Jul 28 00:00 "
                        "'/other/Autounattend.xml'\n")
                return result
            with mock.patch(
                    "homelab.vm.windows_identity_recovery.subprocess.run",
                    side_effect=ambiguous):
                with self.assertRaisesRegex(
                        WindowsIdentityRecoveryError, "one unattend"):
                    RecoveredLocalCredential(publication, root).__enter__()
            self.assertTrue(publication.exists())

    def test_publication_substitution_is_not_destroyed(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            root.chmod(0o700)
            publication = root / "publication.iso"
            publication.write_bytes(b"original")
            publication.chmod(0o600)
            recovery = RecoveredLocalCredential(publication, root)
            recovery._value = "recovered"
            recovery._publication_identity = (
                publication.stat().st_dev, publication.stat().st_ino)
            publication.unlink()
            publication.write_bytes(b"replacement")
            publication.chmod(0o600)
            with self.assertRaisesRegex(
                    WindowsIdentityRecoveryError, "identity changed"):
                recovery.destroy_publication()
            self.assertEqual(b"replacement", publication.read_bytes())
            self.assertFalse(any(
                path.name.startswith(".credential-")
                for path in root.iterdir()))


if __name__ == "__main__":
    unittest.main()
