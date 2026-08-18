"""The published event schema and the shared corpus, from the host side.

This is the first of the corpus's three consumers.  It proves the schema
describes the same closed vocabulary the host protocol enforces, that every
accept case survives the real parser byte-for-byte, and that every reject case
fails closed with its declared error family.  It also records, honestly, where
the schema is weaker than the transport: a schema cannot see duplicate JSON
keys, non-canonical encoding, or an unverified MAC.
"""

import json
import unittest

from homelab.tests.guest_progress_corpus import (
    SUPPORTED_KEYWORDS,
    SchemaViolation,
    load_corpus,
    load_schema,
    schema_keywords,
    validate,
    validates,
)
from homelab.vm import factory_runner
from homelab.vm import guest_progress_protocol as protocol
from homelab.vm.guest_progress_com1 import COM1_PHASES, COM1_PRODUCER
from homelab.vm.guest_progress_protocol import (
    AuthenticationError,
    DeadlineError,
    FrameError,
    ProtocolConfig,
    ReceiverState,
    ReplayError,
    SchemaError,
    TransitionError,
    canonical_json,
    parse_payload,
)

FAMILIES = {
    "SchemaError": SchemaError,
    "AuthenticationError": AuthenticationError,
    "ReplayError": ReplayError,
    "TransitionError": TransitionError,
    "FrameError": FrameError,
    "DeadlineError": DeadlineError,
}


class CorpusCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.schema = load_schema()
        cls.corpus = load_corpus()
        cls.key = bytes.fromhex(cls.corpus["key_hex"])

    def arch_config(self):
        return ProtocolConfig(
            attempt=self.corpus["attempt"],
            producer=self.corpus["producers"]["arch"],
            nonce=self.corpus["nonce"],
            phases=factory_runner.PROGRESS_PHASES,
            statuses=factory_runner.PROGRESS_STATUSES,
        )

    def windows_config(self):
        return ProtocolConfig(
            attempt=self.corpus["attempt"],
            producer=COM1_PRODUCER,
            nonce=self.corpus["nonce"],
            phases=COM1_PHASES,
            statuses=factory_runner.PROGRESS_STATUSES,
            max_frame_bytes=2048,
        )

    def config_for(self, producer):
        if producer == COM1_PRODUCER:
            return self.windows_config()
        return self.arch_config()


class SchemaVocabularyTests(CorpusCase):
    def test_the_schema_uses_only_implemented_keywords(self):
        self.assertLessEqual(schema_keywords(self.schema), SUPPORTED_KEYWORDS)

    def test_the_schema_event_types_are_the_host_closed_registry(self):
        self.assertEqual(
            self.schema["properties"]["type"]["enum"],
            list(protocol.EVENT_TYPES))

    def test_the_schema_statuses_are_the_host_closed_registry(self):
        self.assertEqual(
            set(self.schema["properties"]["status"]["enum"]),
            set(protocol.EVENT_STATUSES.values()))

    def test_the_schema_pins_every_type_to_its_exact_status(self):
        pinned = {}
        for clause in self.schema["allOf"]:
            condition = clause.get("if", {}).get("properties", {})
            event_type = condition.get("type", {}).get("const")
            status = clause.get("then", {}).get(
                "properties", {}).get("status", {}).get("const")
            if event_type is not None and status is not None:
                pinned[event_type] = status
        self.assertEqual(pinned, dict(protocol.EVENT_STATUSES))

    def test_the_schema_specversion_matches_the_host(self):
        self.assertEqual(
            self.schema["properties"]["specversion"]["const"],
            protocol.SPEC_VERSION)

    def test_required_fields_are_exactly_those_every_event_carries(self):
        envelopes = [
            json.loads(case["canonical"]) for case in self.corpus["accept"]
        ]
        always = set(envelopes[0])
        ever = set()
        for envelope in envelopes:
            always &= set(envelope)
            ever |= set(envelope)
        self.assertEqual(set(self.schema["required"]), always)
        self.assertEqual(set(self.schema["properties"]), ever)

    def test_the_corpus_exercises_every_event_type(self):
        self.assertEqual(
            {case["event_type"] for case in self.corpus["accept"]},
            set(protocol.EVENT_TYPES))

    def test_the_schema_refuses_a_non_object_instance(self):
        for instance in ([], "text", 1, None, True):
            with self.subTest(instance=instance):
                self.assertFalse(validates(self.schema, instance))

    def test_the_validator_refuses_an_unimplemented_keyword(self):
        with self.assertRaises(SchemaViolation):
            validate({"multipleOf": 2}, 4)


class HostConsumerTests(CorpusCase):
    def test_every_accept_case_validates_against_the_schema(self):
        for case in self.corpus["accept"]:
            with self.subTest(case=case["name"]):
                validate(self.schema, json.loads(case["canonical"]))

    def test_every_accept_case_is_canonical_and_parses(self):
        for case in self.corpus["accept"]:
            with self.subTest(case=case["name"]):
                payload = case["canonical"].encode("utf-8")
                envelope = json.loads(case["canonical"])
                # The corpus stores canonical bytes, not a pretty rendering:
                # re-encoding must reproduce them exactly.
                self.assertEqual(canonical_json(envelope), payload)
                parsed = parse_payload(
                    payload, self.config_for(case["producer"]), self.key)
                self.assertEqual(parsed["type"], case["event_type"])
                self.assertEqual(parsed["status"], case["status"])
                self.assertEqual(parsed["phase"], case["phase"])
                self.assertEqual(parsed["sequence"], case["sequence"])

    def test_each_stream_drives_a_real_receiver_in_order(self):
        for stream, boot_id in self.corpus["streams"].items():
            with self.subTest(stream=stream):
                cases = [
                    case for case in self.corpus["accept"]
                    if case["stream"] == stream
                ]
                self.assertTrue(cases)
                config = self.config_for(cases[0]["producer"])
                receiver = ReceiverState(config, self.key, deadline=1000.0)
                for index, case in enumerate(cases):
                    accepted = receiver.accept(
                        case["canonical"].encode("utf-8"),
                        received_at=float(index + 1))
                    self.assertFalse(accepted.duplicate)
                    # No accepted event is ever authoritative.
                    self.assertFalse(accepted.authoritative)
                self.assertEqual(receiver.boot_id, boot_id)
                self.assertEqual(receiver.last_sequence, cases[-1]["sequence"])
                self.assertIsNone(receiver.active_phase)

    def test_every_reject_case_fails_closed_in_the_host_parser(self):
        for case in self.corpus["reject"]:
            with self.subTest(case=case["name"]):
                config = (
                    self.windows_config() if case["config"] == "windows"
                    else self.arch_config())
                with self.assertRaises(FAMILIES[case["family"]]):
                    parse_payload(
                        case["payload"].encode("utf-8"), config, self.key)

    def test_every_reject_case_matches_its_declared_schema_verdict(self):
        for case in self.corpus["reject"]:
            with self.subTest(case=case["name"]):
                instance = json.loads(case["payload"])
                self.assertEqual(
                    validates(self.schema, instance), case["schema_valid"],
                    case["reason"])

    def test_the_schema_alone_never_stands_in_for_the_transport(self):
        # The cases the schema cannot see are exactly the ones that make a
        # schema insufficient: encoding, duplicate keys, and authentication.
        schema_blind = {
            case["name"] for case in self.corpus["reject"]
            if case["schema_valid"]
        }
        self.assertEqual(schema_blind, {
            "noncanonical-key-order",
            "noncanonical-whitespace",
            "duplicate-key",
            "non-integer-number",
            "unknown-phase",
            "forged-mac",
            "com1-producer-in-authoritative-config",
            "impossible-date",
        })


if __name__ == "__main__":
    unittest.main()
