import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from vm import preflight_receipt


NOW = datetime(2026, 7, 27, 18, 0, tzinfo=UTC)
BOOT_ID = "11111111-2222-3333-4444-555555555555"
COMMIT = "a" * 40
GUEST_COMMIT = "b" * 40
SERIAL = "TELOS-BOOTSTRAP-DC1"


class PreflightReceiptTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.disk = self.root / "disk.qcow2"
        self.disk.write_bytes(b"disk")
        self.receipt = self.root / "private.json"

    def tearDown(self):
        self.temporary.cleanup()

    def record(self):
        return preflight_receipt.record(
            self.receipt, self.disk, SERIAL, BOOT_ID, GUEST_COMMIT, COMMIT,
            now=NOW)

    def authorize(self, token):
        preflight_receipt.authorize(
            self.receipt, f"ATTACH {token}", now=NOW + timedelta(minutes=1))

    def test_two_stages_produce_fresh_verifiable_private_receipt(self):
        token = self.record()
        self.assertEqual(self.receipt.stat().st_mode & 0o777, 0o600)
        document = json.loads(self.receipt.read_text())
        self.assertEqual(document["guest_preflight_boot_id"], BOOT_ID)
        self.assertEqual(document["guest_source_commit"], GUEST_COMMIT)
        self.assertIn("not guest attestation", document["claim"])
        with self.assertRaisesRegex(ValueError, "fields"):
            preflight_receipt.verify(
                self.receipt, self.disk, SERIAL, COMMIT, now=NOW)
        self.authorize(token)
        verified = preflight_receipt.verify(
            self.receipt, self.disk, SERIAL, COMMIT,
            now=NOW + timedelta(minutes=2))
        self.assertEqual(verified["evidence"], token)

    def test_wrong_confirmation_cannot_authorize(self):
        self.record()
        with self.assertRaisesRegex(ValueError, "confirmation must be"):
            preflight_receipt.authorize(
                self.receipt, "ATTACH wrong", now=NOW)

    def test_expired_receipt_is_rejected(self):
        token = self.record()
        self.authorize(token)
        with self.assertRaisesRegex(ValueError, "stale"):
            preflight_receipt.verify(
                self.receipt, self.disk, SERIAL, COMMIT,
                now=NOW + timedelta(minutes=16))

    def test_disk_change_is_rejected(self):
        token = self.record()
        self.authorize(token)
        self.disk.write_bytes(b"changed")
        with self.assertRaisesRegex(ValueError, "disk identity changed"):
            preflight_receipt.verify(
                self.receipt, self.disk, SERIAL, COMMIT,
                now=NOW + timedelta(minutes=2))

    def test_source_mismatch_is_rejected(self):
        token = self.record()
        self.authorize(token)
        with self.assertRaisesRegex(ValueError, "public HEAD"):
            preflight_receipt.verify(
                self.receipt, self.disk, SERIAL, "b" * 40,
                now=NOW + timedelta(minutes=2))

    def test_public_or_symlink_receipt_is_rejected(self):
        token = self.record()
        self.authorize(token)
        self.receipt.chmod(0o644)
        with self.assertRaisesRegex(ValueError, "0600"):
            preflight_receipt.verify(
                self.receipt, self.disk, SERIAL, COMMIT, now=NOW)
        self.receipt.chmod(0o600)
        link = self.root / "link"
        link.symlink_to(self.receipt)
        with self.assertRaisesRegex(ValueError, "regular file"):
            preflight_receipt.verify(link, self.disk, SERIAL, COMMIT, now=NOW)

    def test_existing_receipt_is_never_overwritten(self):
        self.receipt.write_text("keep")
        with self.assertRaisesRegex(ValueError, "replace"):
            self.record()
        self.assertEqual(self.receipt.read_text(), "keep")

    def test_identity_inputs_are_strict(self):
        with self.assertRaisesRegex(ValueError, "boot ID"):
            preflight_receipt.record(
                self.receipt, self.disk, SERIAL, "not-a-uuid", COMMIT, COMMIT,
                now=NOW)
        with self.assertRaisesRegex(ValueError, "commit"):
            preflight_receipt.record(
                self.receipt, self.disk, SERIAL, BOOT_ID, "abc", COMMIT,
                now=NOW)


if __name__ == "__main__":
    unittest.main()
