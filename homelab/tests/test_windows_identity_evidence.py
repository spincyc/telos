import base64
import copy
import json
import tempfile
import unittest
from pathlib import Path

from homelab.vm.windows_identity_evidence import (
    EvidencePublicationError,
    StrictIdentityEvidenceCollector,
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

    def collector(self, **kwargs):
        return StrictIdentityEvidenceCollector(
            self.destination,
            run_id=self.events[0]["run_id"],
            observed_at=lambda: "2026-07-28T15:00:00Z",
            **kwargs,
        )

    def test_collector_maps_exact_observations_to_24_event_contract(self):
        collector = self.collector()
        for event in self.events:
            observation = {
                field: value for field, value in event.items()
                if field in acceptance.FIELD_SETS[event["check"]]
            }
            self.assertEqual(event["check"], collector.next_check)
            collector.record(
                event["check"], observation,
                observed_at=event["observed_at"])
        self.assertIsNone(collector.next_check)

        result = collector.publish()
        with result.open(encoding="utf-8") as source:
            emitted = acceptance.load_events(source)
        self.assertEqual(self.events, emitted)
        with self.assertRaisesRegex(
                EvidencePublicationError, "sealed"):
            collector.publish()

    def test_collector_progress_records_how_far_acceptance_got(self):
        """Attempt 47 was blind between check 4 and the aggregate.
        write_progress persists the passed checks and the in-progress one
        (public names only), and never raises."""
        import json
        collector = self.collector()
        # Record the first two checks, then capture progress mid-stream.
        for event in self.events[:2]:
            observation = {
                field: value for field, value in event.items()
                if field in acceptance.FIELD_SETS[event["check"]]
            }
            collector.record(
                event["check"], observation,
                observed_at=event["observed_at"])
        self.assertEqual(
            ("controller-ready", "windows-joined"),
            collector.passed_checks)
        progress_path = self.root / "acceptance-progress.json"
        collector.write_progress(progress_path)
        record = json.loads(progress_path.read_text())
        self.assertEqual(2, record["passed_count"])
        self.assertEqual(24, record["total_checks"])
        self.assertEqual(
            ["controller-ready", "windows-joined"], record["passed_checks"])
        self.assertEqual("windows-standard-online", record["next_check"])
        self.assertEqual(0o600, progress_path.stat().st_mode & 0o777)
        # Never raises even when the target directory cannot be created.
        collector.write_progress(self.root / "nope" / "\x00" / "p.json")

    def test_collector_rejects_reordering_extra_fields_and_early_publish(self):
        collector = self.collector()
        with self.assertRaisesRegex(
                EvidencePublicationError, "controller-ready"):
            collector.record("windows-joined", {})
        first = self.events[0]
        observation = {
            field: first[field]
            for field in acceptance.FIELD_SETS[first["check"]]
        }
        with self.assertRaisesRegex(
                EvidencePublicationError, "fields"):
            collector.record(
                first["check"], {**observation, "transcript": "unsafe"})
        with self.assertRaisesRegex(
                EvidencePublicationError, "incomplete"):
            collector.publish()
        self.assertFalse(self.destination.exists())

    def test_collector_rejects_secret_before_retaining_observation(self):
        secret = "Reusable-Private-Credential-47!"
        collector = self.collector(known_secrets=(secret,))
        first = self.events[0]
        observation = {
            field: first[field]
            for field in acceptance.FIELD_SETS[first["check"]]
        }
        observation["samba_ad"] = secret
        with self.assertRaisesRegex(
                EvidencePublicationError, "known secret"):
            collector.record(first["check"], observation)
        self.assertEqual("controller-ready", collector.next_check)
        self.assertFalse(self.destination.parent.exists())

    def test_collector_rejects_base64_wrapped_secret(self):
        secret = "Reusable-Private-Credential-47!"
        collector = self.collector(known_secrets=(secret,))
        first = self.events[0]
        observation = {
            field: first[field]
            for field in acceptance.FIELD_SETS[first["check"]]
        }
        observation["samba_ad"] = base64.urlsafe_b64encode(
            json.dumps({"password": secret}).encode()).decode().rstrip("=")
        with self.assertRaisesRegex(
                EvidencePublicationError, "known secret"):
            collector.record(first["check"], observation)
        self.assertEqual("controller-ready", collector.next_check)

    def test_collector_copies_mutable_observation_values(self):
        collector = self.collector()
        for event in self.events:
            observation = {
                field: copy.deepcopy(value)
                for field, value in event.items()
                if field in acceptance.FIELD_SETS[event["check"]]
            }
            collector.record(
                event["check"], observation,
                observed_at=event["observed_at"])
            if event["check"] == "windows-identity-acceptance":
                observation["deferred"].append("mutated")
        collector.publish()
        with self.destination.open(encoding="utf-8") as source:
            emitted = acceptance.load_events(source)
        self.assertEqual(
            ["disable-reenable"], emitted[-1]["deferred"])


if __name__ == "__main__":
    unittest.main()
