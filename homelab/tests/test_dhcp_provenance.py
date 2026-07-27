import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).parents[1]
SOURCE = ROOT / "vm" / "dhcp_provenance.py"
SPEC = importlib.util.spec_from_file_location("dhcp_provenance", SOURCE)
dhcp = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = dhcp
SPEC.loader.exec_module(dhcp)


def event(sequence, kind, actor, recipient=None, server_id=None, address=None):
    return dhcp.Event(sequence, kind, actor, recipient, server_id, address)


GOOD = [
    event(1, "DISCOVER", "client"),
    event(2, "OFFER", "gateway", "client", "gateway", "10.1.31.11"),
    event(3, "REQUEST", "client", "gateway", "gateway", "10.1.31.11"),
    event(4, "ACK", "gateway", "client", "gateway", "10.1.31.11"),
    event(5, "POWEROFF", "controller"),
    event(6, "CONNECTIVITY_PASS", "client", address="10.1.31.11"),
]


class DhcpProvenanceTests(unittest.TestCase):
    def assess(self, events):
        return dhcp.assess(
            events, gateway="gateway", controller="controller", client="client")

    def test_gateway_is_sole_authority_and_client_survives_controller(self):
        self.assertEqual(self.assess(GOOD), [])

    def test_second_offer_is_rogue_even_if_gateway_also_answers(self):
        events = GOOD[:2] + [
            event(3, "OFFER", "rogue", "client", "rogue", "10.1.31.12"),
        ] + [
            event(item.sequence + 1, item.kind, item.actor, item.recipient,
                  item.server_id, item.address) for item in GOOD[2:]
        ]
        failures = self.assess(events)
        self.assertTrue(any("authority set" in failure for failure in failures))

    def test_controller_offer_is_explicit_failure(self):
        events = GOOD[:2] + [
            event(3, "OFFER", "controller", "client", "controller", "10.1.31.12"),
        ] + [
            event(item.sequence + 1, item.kind, item.actor, item.recipient,
                  item.server_id, item.address) for item in GOOD[2:]
        ]
        failures = self.assess(events)
        self.assertTrue(any("controller emitted" in failure for failure in failures))

    def test_duplicate_gateway_offer_is_failure(self):
        events = GOOD[:2] + [
            event(3, "OFFER", "gateway", "client", "gateway", "10.1.31.11"),
        ] + [
            event(item.sequence + 1, item.kind, item.actor, item.recipient,
                  item.server_id, item.address) for item in GOOD[2:]
        ]
        self.assertTrue(any("one OFFER" in failure for failure in self.assess(events)))

    def test_incomplete_exchange_is_failure(self):
        events = [item for item in GOOD if item.kind != "REQUEST"]
        self.assertTrue(any("ordered DISCOVER" in failure
                            for failure in self.assess(events)))

    def test_connectivity_before_poweroff_does_not_count(self):
        events = GOOD[:-1]
        events.insert(4, event(5, "CONNECTIVITY_PASS", "client",
                               address="10.1.31.11"))
        events[-1] = event(6, "POWEROFF", "controller")
        self.assertTrue(any("after controller poweroff" in failure
                            for failure in self.assess(events)))

    def test_changed_address_after_poweroff_does_not_count(self):
        events = GOOD[:-1] + [
            event(6, "CONNECTIVITY_PASS", "client", address="10.1.31.12")]
        self.assertTrue(any("retain its lease" in failure
                            for failure in self.assess(events)))

    def test_cli_emits_a_machine_checkable_pass(self):
        with tempfile.TemporaryDirectory() as temporary:
            transcript = Path(temporary) / "events.jsonl"
            transcript.write_text("\n".join(json.dumps({
                "sequence": item.sequence,
                "kind": item.kind,
                "actor": item.actor,
                "recipient": item.recipient,
                "server_id": item.server_id,
                "address": item.address,
            }) for item in GOOD) + "\n")
            result = subprocess.run([
                sys.executable, SOURCE, transcript,
                "--gateway", "gateway", "--controller", "controller",
                "--client", "client",
            ], text=True, capture_output=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("PASS gateway is sole DHCP authority", result.stdout)
        self.assertIn("PASS client retained connectivity", result.stdout)


if __name__ == "__main__":
    unittest.main()
