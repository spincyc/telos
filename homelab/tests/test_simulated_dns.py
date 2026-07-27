"""DNS boundary tests for the loopback-only network simulation.

The gateway is deliberately independent of the controller.  These tests make
that boundary explicit: DNS remains available from the gateway when no
controller object or process exists, while the controller address never
receives a simulated port-53 response.
"""

import ipaddress
import struct
import unittest

from homelab.vm import simulated_gateway as sim


CLIENT_MAC = bytes.fromhex("525400311102")
CLIENT_IP = ipaddress.IPv4Address("10.1.31.11")
CONTROLLER_IP = ipaddress.IPv4Address("10.1.31.2")


def dns_query(name: str, *, transaction: bytes = b"\x53\x01") -> bytes:
    labels = b"".join(
        bytes((len(label),)) + label.encode("ascii") for label in name.split(".")
    )
    question = labels + b"\0" + struct.pack("!HH", 1, 1)
    return transaction + b"\x01\0\0\x01\0\0\0\0\0\0" + question


def frame_for(target: ipaddress.IPv4Address, query: bytes) -> bytes:
    packet = sim.udp(43153, 53, query)
    return sim.ethernet(
        sim.GATEWAY_MAC,
        CLIENT_MAC,
        0x0800,
        sim.ipv4(CLIENT_IP, target, 17, packet),
    )


def dns_payload(frame: bytes) -> bytes:
    return frame[14 + 20 + 8:]


class SimulatedDnsBoundaryTests(unittest.TestCase):
    def test_gateway_resolves_only_the_deliberate_update_name(self):
        gateway = sim.Gateway()
        query = dns_query(sim.DNS_NAME)

        replies = gateway.handle(frame_for(sim.GATEWAY_IP, query))

        self.assertEqual(len(replies), 1)
        response = dns_payload(replies[0])
        self.assertEqual(response[:2], query[:2])
        self.assertEqual(struct.unpack("!H", response[2:4])[0], 0x8180)
        self.assertEqual(struct.unpack("!H", response[6:8])[0], 1)
        self.assertTrue(response.endswith(sim.GATEWAY_IP.packed))

    def test_unknown_name_is_nxdomain_not_forwarded(self):
        gateway = sim.Gateway()

        replies = gateway.handle(
            frame_for(sim.GATEWAY_IP, dns_query("household.example"))
        )

        self.assertEqual(len(replies), 1)
        response = dns_payload(replies[0])
        self.assertEqual(struct.unpack("!H", response[2:4])[0], 0x8183)
        self.assertEqual(struct.unpack("!H", response[6:8])[0], 0)
        self.assertNotIn(CONTROLLER_IP.packed, response)

    def test_controller_port_53_is_closed_in_the_simulation(self):
        gateway = sim.Gateway()

        replies = gateway.handle(
            frame_for(CONTROLLER_IP, dns_query(sim.DNS_NAME))
        )

        self.assertEqual(replies, [])

    def test_gateway_dns_continues_with_controller_absent(self):
        # There is intentionally no controller participant here.  A fresh
        # gateway still answers the client's resolver query, which models the
        # required power-off continuity check without host or UniFi access.
        before_controller_shutdown = sim.Gateway()
        after_controller_shutdown = sim.Gateway()
        query = dns_query(sim.DNS_NAME, transaction=b"\x53\x02")

        before = before_controller_shutdown.handle(frame_for(sim.GATEWAY_IP, query))
        after = after_controller_shutdown.handle(frame_for(sim.GATEWAY_IP, query))

        self.assertEqual(len(before), 1)
        self.assertEqual(after, before)

    def test_non_dns_gateway_port_does_not_create_dns_response(self):
        gateway = sim.Gateway()
        packet = sim.udp(43153, 5353, dns_query(sim.DNS_NAME))
        frame = sim.ethernet(
            sim.GATEWAY_MAC,
            CLIENT_MAC,
            0x0800,
            sim.ipv4(CLIENT_IP, sim.GATEWAY_IP, 17, packet),
        )

        self.assertEqual(gateway.handle(frame), [])


if __name__ == "__main__":
    unittest.main()
