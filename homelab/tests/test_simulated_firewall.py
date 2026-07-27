import ipaddress
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from vm.simulated_firewall import (  # noqa: E402
    Decision,
    Flow,
    SimulatedFirewall,
    verify_acceptance,
)
from vm import simulated_gateway as gateway  # noqa: E402


def firewall():
    return SimulatedFirewall(
        gateway="10.1.31.1",
        dns="10.1.31.1",
        update_addresses=frozenset({"198.51.100.11"}),
        household_networks=("10.0.0.0/21",),
    )


class TestSimulatedFirewall(unittest.TestCase):
    def test_exact_acceptance_matrix_passes(self):
        subject = firewall()
        self.assertEqual(verify_acceptance(subject), ())
        self.assertEqual(
            subject.report(),
            (
                "allow-gateway packets=1",
                "allow-dns packets=2",
                "allow-update packets=1",
                "allow-ntp packets=1",
                "deny-household packets=2",
                "deny-private packets=3",
                "deny-default packets=4",
            ),
        )

    def test_update_allow_is_address_protocol_and_port_specific(self):
        subject = firewall()
        self.assertEqual(
            subject.decide(Flow("tcp", "198.51.100.11", 443)),
            Decision(True, "allow-update"),
        )
        for flow in (
            Flow("udp", "198.51.100.11", 443),
            Flow("tcp", "198.51.100.11", 80),
            Flow("tcp", "198.51.100.12", 443),
        ):
            with self.subTest(flow=flow):
                self.assertFalse(subject.decide(flow).allowed)

    def test_dns_allow_does_not_open_other_gateway_services(self):
        subject = firewall()
        for protocol in ("udp", "tcp"):
            self.assertTrue(subject.decide(Flow(protocol, "10.1.31.1", 53)).allowed)
            self.assertFalse(subject.decide(Flow(protocol, "10.1.31.1", 67)).allowed)

    def test_ntp_allow_is_exact_address_protocol_and_port(self):
        subject = firewall()
        self.assertEqual(
            subject.decide(Flow("udp", "198.51.100.10", 123)),
            Decision(True, "allow-ntp"),
        )
        for flow in (
            Flow("tcp", "198.51.100.10", 123),
            Flow("udp", "198.51.100.10", 124),
            Flow("udp", "198.51.100.12", 123),
        ):
            with self.subTest(flow=flow):
                self.assertFalse(subject.decide(flow).allowed)

    def test_existing_household_subnet_has_a_distinct_counter(self):
        subject = firewall()
        result = subject.decide(Flow("tcp", "10.0.3.10", 22))
        self.assertEqual(result, Decision(False, "deny-household"))
        self.assertIn("deny-household packets=1", subject.report())

    def test_other_private_ranges_are_denied(self):
        subject = firewall()
        for address in ("10.9.1.1", "172.31.255.254", "192.168.99.1"):
            with self.subTest(address=address):
                self.assertEqual(
                    subject.decide(Flow("icmp", address)),
                    Decision(False, "deny-private"),
                )

    def test_unrecognized_public_destination_is_default_denied(self):
        subject = firewall()
        self.assertEqual(
            subject.decide(Flow("tcp", "203.0.113.44", 443)),
            Decision(False, "deny-default"),
        )

    def test_only_gateway_supplies_dhcp_in_concurrent_factory(self):
        workstation = bytes.fromhex("525400311111")
        controller = bytes.fromhex("525400311102")
        policy = gateway.HubPolicy()
        discover = self._discover(workstation)

        deliveries, evidence = policy.route(1, discover, {1, 2, 3})

        self.assertEqual(set(deliveries), {1})
        self.assertEqual(
            [(item["kind"], item["peer"]) for item in evidence],
            [("DISCOVER", 1), ("OFFER", "gateway")],
        )
        self.assertNotIn(2, deliveries)
        self.assertNotIn(3, deliveries)

        rogue = bytearray(gateway.Gateway().handle(
            self._discover(controller))[0])
        rogue[6:12] = controller
        deliveries, evidence = policy.route(2, bytes(rogue), {1, 2, 3})
        self.assertEqual(deliveries, {})
        self.assertEqual(evidence[0]["kind"], "OFFER")
        self.assertTrue(evidence[0]["blocked"])

    @staticmethod
    def _discover(mac):
        fixed = bytearray(236)
        fixed[:4] = b"\x01\x01\x06\x00"
        fixed[28:34] = mac
        payload = fixed + b"\x63\x82\x53\x63\x35\x01\x01\xff"
        return gateway.ethernet(
            b"\xff" * 6,
            mac,
            0x0800,
            gateway.ipv4(
                ipaddress.IPv4Address("0.0.0.0"),
                ipaddress.IPv4Address("255.255.255.255"),
                17,
                gateway.udp(68, 67, payload),
            ),
        )


if __name__ == "__main__":
    unittest.main()
