import copy
import json
import tempfile
import unittest
from pathlib import Path

from homelab.vm.windows_identity_evidence import (
    EvidencePublicationError,
    publish_acceptance_evidence,
)
from homelab.workstations import windows_identity_acceptance as acceptance
from homelab.tests.test_windows_identity_acceptance import valid_events


class WindowsIdentityEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.contract = acceptance.load_json(acceptance.CONTRACT)
        self.events = valid_events(self.contract)
        self.destination = self.root / "private" / "acceptance.jsonl"

    def test_publishes_only_complete_strict_private_jsonl(self):
        result = publish_acceptance_evidence(
            self.destination, self.events, known_secrets=("not-present",))
        self.assertEqual(self.destination, result)
        self.assertEqual(0o600, result.stat().st_mode & 0o777)
        self.assertEqual(0o700, result.parent.stat().st_mode & 0o777)
        with result.open(encoding="utf-8") as source:
            emitted = acceptance.load_events(source)
        self.assertEqual(
            acceptance.judge(self.contract, self.events),
            acceptance.judge(self.contract, emitted),
        )
        self.assertEqual(self.events, emitted)

    def test_invalid_stream_never_creates_partial_evidence(self):
        cases = {
            "missing": self.events[:-1],
            "reordered": [
                self.events[1], self.events[0], *self.events[2:]],
            "extra": [
                {**self.events[0], "password": "private"},
                *self.events[1:],
            ],
        }
        for label, events in cases.items():
            destination = self.root / label / "acceptance.jsonl"
            with self.subTest(label=label), self.assertRaises(
                    EvidencePublicationError):
                publish_acceptance_evidence(destination, events)
            self.assertFalse(destination.exists())
            self.assertFalse(destination.parent.exists())

    def test_known_secret_is_rejected_before_creating_destination(self):
        events = copy.deepcopy(self.events)
        secret = events[14]["policy_source"]
        with self.assertRaisesRegex(
                EvidencePublicationError, "known secret"):
            publish_acceptance_evidence(
                self.destination, events, known_secrets=(secret,))
        self.assertFalse(self.destination.exists())
        self.assertFalse(self.destination.parent.exists())

    def test_existing_evidence_cannot_be_replaced(self):
        self.destination.parent.mkdir(mode=0o700)
        self.destination.write_text("preserve\n", encoding="utf-8")
        self.destination.chmod(0o600)
        with self.assertRaisesRegex(
                EvidencePublicationError, "publish-once"):
            publish_acceptance_evidence(self.destination, self.events)
        self.assertEqual(
            "preserve\n", self.destination.read_text(encoding="utf-8"))

    def test_symlink_destination_is_rejected(self):
        target = self.root / "target"
        target.write_text("preserve\n", encoding="utf-8")
        self.destination.parent.mkdir(mode=0o700)
        self.destination.symlink_to(target)
        with self.assertRaisesRegex(
                EvidencePublicationError, "publish-once"):
            publish_acceptance_evidence(self.destination, self.events)
        self.assertEqual("preserve\n", target.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
