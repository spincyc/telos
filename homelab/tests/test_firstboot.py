"""Tests for first-boot activation.

ADR 0009 requires this to fail closed. The tests that matter are therefore the
ones proving it refuses: wrong interface, wrong MAC, no carrier, missing
address, and above all another DHCP server already answering on the segment.
"""

import subprocess
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "lib"))

import firstboot  # noqa: E402

MAC = "60:cf:84:77:c6:6f"
ADDRESS = "10.0.7.2"


class FakeProbes:
    def __init__(self, *, exists=True, mac=MAC, carrier=True,
                 addresses=(ADDRESS,), other_dhcp=False):
        self._exists, self._mac, self._carrier = exists, mac, carrier
        self._addresses, self._other_dhcp = list(addresses), other_dhcp

    def interface_exists(self, name): return self._exists
    def permanent_mac(self, name): return self._mac
    def has_carrier(self, name): return self._carrier
    def addresses(self, name): return self._addresses
    def dhcp_server_responds(self, name, timeout): return self._other_dhcp


def evaluate(**kwargs):
    return firstboot.evaluate(FakeProbes(**kwargs),
                              expected_mac=MAC, expected_address=ADDRESS)


class TestHappyPath(unittest.TestCase):
    def test_all_conditions_met_permits_start(self):
        activation = evaluate()
        self.assertTrue(activation.may_start, [c.detail for c in activation.failures])

    def test_it_checks_the_things_that_matter(self):
        names = {check.name for check in evaluate().checks}
        self.assertEqual(names, {"interface-exists", "interface-identity",
                                 "carrier", "service-address", "sole-dhcp-authority"})

    def test_report_says_it_is_now_the_sole_authority(self):
        text = "\n".join(firstboot.report(evaluate()))
        self.assertIn("sole DHCP authority", text)


class TestFailsClosed(unittest.TestCase):
    def test_a_competing_dhcp_server_stops_activation(self):
        # The condition this whole module exists for. ADR 0008 forbids two
        # authorities on one segment at any stage.
        activation = evaluate(other_dhcp=True)
        self.assertFalse(activation.may_start)
        self.assertIn("sole-dhcp-authority", {c.name for c in activation.failures})

    def test_a_missing_interface_stops_activation_immediately(self):
        activation = evaluate(exists=False)
        self.assertFalse(activation.may_start)
        # No point probing a network through an interface that is not there.
        self.assertEqual(len(activation.checks), 1)

    def test_the_wrong_card_stops_activation(self):
        activation = evaluate(mac="aa:bb:cc:dd:ee:ff")
        self.assertFalse(activation.may_start)
        failure = next(c for c in activation.failures if c.name == "interface-identity")
        self.assertIn("does not own", failure.remedy)

    def test_no_carrier_stops_activation(self):
        activation = evaluate(carrier=False)
        self.assertFalse(activation.may_start)
        failure = next(c for c in activation.failures if c.name == "carrier")
        self.assertIn("Connect the managed interface", failure.remedy)

    def test_a_missing_service_address_stops_activation(self):
        activation = evaluate(addresses=())
        self.assertFalse(activation.may_start)

    def test_every_failure_carries_a_remedy(self):
        # A fail-closed machine that does not say what to do is a machine
        # somebody will work around rather than fix.
        for kwargs in ({"other_dhcp": True}, {"carrier": False},
                       {"mac": "aa:bb:cc:dd:ee:ff"}, {"addresses": ()},
                       {"exists": False}):
            with self.subTest(**kwargs):
                for check in evaluate(**kwargs).failures:
                    self.assertTrue(check.remedy.strip(), check.name)

    def test_report_states_nothing_was_started(self):
        text = "\n".join(firstboot.report(evaluate(other_dhcp=True)))
        self.assertIn("NOT STARTED", text)
        self.assertIn("have NOT been started", text)
        self.assertIn("systemctl restart", text)


class TestProbeFailsClosed(unittest.TestCase):
    """A probe that cannot answer must be treated as a conflict."""

    def test_a_missing_dhcpcd_counts_as_a_server_responding(self):
        def raises(*args, **kwargs):
            raise FileNotFoundError("dhcpcd")
        self.assertTrue(firstboot.SystemProbes(run=raises)
                        .dhcp_server_responds("lan0", 3))

    def test_a_timed_out_probe_counts_as_a_server_responding(self):
        def times_out(*args, **kwargs):
            raise subprocess.TimeoutExpired(cmd="dhcpcd", timeout=3)
        self.assertTrue(firstboot.SystemProbes(run=times_out)
                        .dhcp_server_responds("lan0", 3))

    def test_a_clean_segment_reports_no_server(self):
        def no_offer(*args, **kwargs):
            return subprocess.CompletedProcess(args[0], 1, stdout="", stderr="timed out")
        self.assertFalse(firstboot.SystemProbes(run=no_offer)
                         .dhcp_server_responds("lan0", 3))

    def test_an_offer_reports_a_server(self):
        def offered(*args, **kwargs):
            return subprocess.CompletedProcess(args[0], 0, stdout="offered 10.0.7.55", stderr="")
        self.assertTrue(firstboot.SystemProbes(run=offered)
                        .dhcp_server_responds("lan0", 3))


if __name__ == "__main__":
    unittest.main()
