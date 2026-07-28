import ipaddress
import struct
import unittest

from homelab.vm import simulated_gateway as sim
from homelab.vm import simulated_topology


CLIENT_MAC = bytes.fromhex("525400311102")
CLIENT_IP = ipaddress.IPv4Address("10.1.31.11")


def request_ip(protocol, payload, target=sim.GATEWAY_IP):
    return sim.ethernet(
        sim.GATEWAY_MAC, CLIENT_MAC, 0x0800,
        sim.ipv4(CLIENT_IP, target, protocol, payload),
    )


def controller_ip(protocol, payload, target=sim.GATEWAY_IP):
    return sim.ethernet(
        sim.GATEWAY_MAC, sim.CONTROLLER_MAC, 0x0800,
        sim.ipv4(sim.CONTROLLER_IP, target, protocol, payload),
    )


class SimulatedGatewayTests(unittest.TestCase):
    def setUp(self):
        self.gateway = sim.Gateway()

    def test_controller_identity_can_bind_to_qemu_topology(self):
        controller_mac = bytes.fromhex(
            simulated_topology.MACS["controller"].replace(":", ""))
        gateway = sim.Gateway(controller_mac=controller_mac)
        query = bytearray(48)
        query[0] = 0x23
        query[40:48] = b"request!"
        request = controller_ip(
            17, sim.udp(43210, 123, bytes(query)), sim.NTP_IP)
        request = request[:6] + controller_mac + request[12:]
        self.assertEqual(len(gateway.handle(request)), 1)
        self.gateway.lease_mac = sim.CONTROLLER_MAC
        self.assertEqual(len(self.gateway.handle(request)), 0)

    def test_arp_answers_only_for_gateway(self):
        arp = struct.pack("!HHBBH", 1, 0x0800, 6, 4, 1)
        arp += CLIENT_MAC + CLIENT_IP.packed + b"\0" * 6 + sim.GATEWAY_IP.packed
        replies = self.gateway.handle(
            sim.ethernet(b"\xff" * 6, CLIENT_MAC, 0x0806, arp))
        self.assertEqual(len(replies), 1)
        self.assertEqual(replies[0][:6], CLIENT_MAC)
        self.assertEqual(replies[0][6:12], sim.GATEWAY_MAC)

    def test_dhcp_offer_has_ten_minute_scoped_lease(self):
        fixed = bytearray(236)
        fixed[0] = 1
        fixed[1] = 1
        fixed[2] = 6
        fixed[4:8] = b"test"
        fixed[28:34] = CLIENT_MAC
        discover = bytes(fixed) + b"\x63\x82\x53\x63\x35\x01\x01\xff"
        frame = request_ip(
            17, sim.udp(68, 67, discover),
            ipaddress.IPv4Address("255.255.255.255"))
        reply = self.gateway.handle(frame)[0]
        ip = reply[14:]
        payload = ip[28:]
        self.assertEqual(payload[16:20], sim.LEASE_IP.packed)
        options = sim.dhcp_options(payload)
        self.assertEqual(options[53], b"\x02")
        self.assertEqual(options[3], sim.GATEWAY_IP.packed)
        self.assertEqual(struct.unpack("!I", options[51])[0], 600)

    def test_dns_has_one_deliberate_name(self):
        question = b"\x07updates\x03sim\x04test\0" + struct.pack("!HH", 1, 1)
        query = b"\x12\x34\x01\0\0\x01\0\0\0\0\0\0" + question
        reply = self.gateway.handle(request_ip(17, sim.udp(43210, 53, query)))[0]
        dns = reply[14 + 20 + 8:]
        self.assertEqual(dns[:2], b"\x12\x34")
        self.assertEqual(struct.unpack("!H", dns[6:8])[0], 1)
        self.assertTrue(dns.endswith(sim.GATEWAY_IP.packed))

    def test_dns_has_deliberate_ntp_name(self):
        question = b"\x04time\x03sim\x04test\0" + struct.pack("!HH", 1, 1)
        query = b"\x12\x34\x01\0\0\x01\0\0\0\0\0\0" + question
        reply = self.gateway.handle(request_ip(17, sim.udp(43210, 53, query)))[0]
        self.assertTrue(reply.endswith(sim.NTP_IP.packed))

    def test_dns_has_deliberate_controller_name(self):
        question = (
            b"\x0cbootstrap-dc\x03lab\x04home\x04arpa\0"
            + struct.pack("!HH", 1, 1)
        )
        query = b"\x12\x35\x01\0\0\x01\0\0\0\0\0\0" + question
        reply = self.gateway.handle(
            request_ip(17, sim.udp(43210, 53, query)))[0]
        self.assertTrue(reply.endswith(sim.CONTROLLER_IP.packed))

    def test_ntp_response_is_from_simulated_external_peer(self):
        gateway = sim.Gateway(clock=lambda: 1_700_000_000.25)
        query = bytearray(48)
        query[0] = 0x23
        query[2] = 6
        query[40:48] = b"request!"
        reply = gateway.handle(
            request_ip(17, sim.udp(43210, 123, bytes(query)), sim.NTP_IP)
        )[0]
        ip = reply[14:]
        ntp = ip[28:]
        self.assertEqual(ip[12:16], sim.NTP_IP.packed)
        self.assertEqual(struct.unpack("!HH", ip[20:24]), (123, 43210))
        self.assertEqual(ntp[0], 0x24)
        self.assertEqual(ntp[1], 2)
        self.assertEqual(ntp[24:32], b"request!")

    def test_exact_static_controller_identity_survives_earlier_dhcp_lease(self):
        self.gateway.lease_mac = sim.CONTROLLER_MAC
        query = bytearray(48)
        query[0] = 0x23
        query[40:48] = b"request!"
        replies = self.gateway.handle(controller_ip(
            17, sim.udp(43210, 123, bytes(query)), sim.NTP_IP))
        self.assertEqual(1, len(replies))

    def test_controller_mac_with_wrong_static_address_is_rejected(self):
        self.gateway.lease_mac = sim.CONTROLLER_MAC
        wrong = sim.ethernet(
            sim.GATEWAY_MAC, sim.CONTROLLER_MAC, 0x0800,
            sim.ipv4(
                ipaddress.IPv4Address("10.1.31.3"), sim.NTP_IP, 17,
                sim.udp(43210, 123, b"\x23" + bytes(47))))
        self.assertEqual([], self.gateway.handle(wrong))

    def test_malformed_ntp_requests_fail_closed(self):
        for query in (b"", bytes(48), b"\x24" + bytes(47),
                      b"\x1b" + bytes(47)):
            frame = request_ip(
                17, sim.udp(43210, 123, query), sim.NTP_IP
            )
            self.assertEqual(self.gateway.handle(frame), [])

    def test_udp_probe_and_no_forwarding(self):
        probe = request_ip(17, sim.udp(40000, sim.UDP_PROBE_PORT, b"hello"))
        reply = self.gateway.handle(probe)[0]
        self.assertTrue(reply.endswith(b"sim-ok:hello"))
        external = request_ip(
            17, sim.udp(40000, sim.UDP_PROBE_PORT, b"hello"),
            ipaddress.IPv4Address("10.0.0.1"))
        self.assertEqual(self.gateway.handle(external), [])

    def test_icmp_echo(self):
        echo = b"\x08\0\0\0\0\x01\0\x01payload"
        echo = echo[:2] + struct.pack("!H", sim.checksum(echo)) + echo[4:]
        reply = self.gateway.handle(request_ip(1, echo))[0]
        self.assertEqual(reply[14 + 20], 0)

    def test_malformed_frames_fail_closed(self):
        self.assertEqual(self.gateway.handle(b"short"), [])
        self.assertEqual(self.gateway.handle(request_ip(6, b"tcp")), [])

    def test_truncated_lengths_and_headers_fail_closed(self):
        valid = request_ip(17, sim.udp(40000, sim.UDP_PROBE_PORT, b"x"))
        cases = [
            valid[:14] + bytes((0x44,)) + valid[15:],
            valid[:16] + b"\xff\xff" + valid[18:],
            valid[:20] + b"\x00\x01" + valid[22:],
            valid[:14 + 20 + 4],
            valid[:14 + 20 + 4] + b"\0\0\0\1",
        ]
        for frame in cases:
            with self.subTest(frame=frame):
                self.assertEqual(self.gateway.handle(frame), [])

    def test_frames_for_other_mac_and_fragments_fail_closed(self):
        probe = request_ip(17, sim.udp(40000, sim.UDP_PROBE_PORT, b"x"))
        self.assertEqual(self.gateway.handle(b"\x52\x54\0\0\0\x99" + probe[6:]), [])
        fragmented = probe[:20] + b"\x00\x01" + probe[22:]
        self.assertEqual(self.gateway.handle(fragmented), [])

    def test_bad_ipv4_and_icmp_checksums_fail_closed(self):
        probe = bytearray(
            request_ip(17, sim.udp(40000, sim.UDP_PROBE_PORT, b"x")))
        probe[24] ^= 1
        self.assertEqual(self.gateway.handle(bytes(probe)), [])
        echo = b"\x08\0\0\0\0\x01\0\x01payload"
        self.assertEqual(self.gateway.handle(request_ip(1, echo)), [])

    def test_malformed_dns_and_dhcp_options_do_not_raise(self):
        malformed_dns = (
            b"\x12\x34\x01\0\0\x01\0\0\0\0\0\0" + b"\x3fabc"
        )
        self.assertEqual(
            self.gateway.handle(request_ip(17, sim.udp(40000, 53, malformed_dns))),
            [],
        )
        fixed = bytearray(236)
        fixed[0:4] = b"\x01\x01\x06\x00"
        fixed[28:34] = CLIENT_MAC
        malformed_dhcp = bytes(fixed) + b"\x63\x82\x53\x63\x35"
        frame = request_ip(
            17, sim.udp(68, 67, malformed_dhcp),
            ipaddress.IPv4Address("255.255.255.255"),
        )
        self.assertEqual(self.gateway.handle(frame), [])

    def test_dhcp_lease_is_bound_to_one_client(self):
        def discover(mac):
            fixed = bytearray(236)
            fixed[0:4] = b"\x01\x01\x06\x00"
            fixed[28:34] = mac
            packet = bytes(fixed) + b"\x63\x82\x53\x63\x35\x01\x01\xff"
            return sim.ethernet(
                b"\xff" * 6, mac, 0x0800,
                sim.ipv4(
                    ipaddress.IPv4Address("0.0.0.0"),
                    ipaddress.IPv4Address("255.255.255.255"),
                    17, sim.udp(68, 67, packet),
                ),
            )

        self.assertEqual(len(self.gateway.handle(discover(CLIENT_MAC))), 1)
        other = bytes.fromhex("525400311199")
        self.assertEqual(self.gateway.handle(discover(other)), [])
        spoofed = sim.ethernet(
            sim.GATEWAY_MAC, other, 0x0800,
            sim.ipv4(CLIENT_IP, sim.GATEWAY_IP, 17,
                     sim.udp(40000, sim.UDP_PROBE_PORT, b"x")),
        )
        self.assertEqual(self.gateway.handle(spoofed), [])

    def test_controller_bootstrap_dhcp_does_not_consume_workstation_lease(self):
        def dhcp(mac, message, requested=None):
            fixed = bytearray(236)
            fixed[0:4] = b"\x01\x01\x06\x00"
            fixed[4:8] = b"role"
            fixed[28:34] = mac
            options = b"\x63\x82\x53\x63" + bytes((53, 1, message))
            if requested is not None:
                options += bytes((50, 4)) + requested.packed
                options += bytes((54, 4)) + sim.GATEWAY_IP.packed
            options += b"\xff"
            return sim.ethernet(
                b"\xff" * 6, mac, 0x0800,
                sim.ipv4(
                    ipaddress.IPv4Address("0.0.0.0"),
                    ipaddress.IPv4Address("255.255.255.255"),
                    17, sim.udp(68, 67, bytes(fixed) + options),
                ),
            )

        def offered_address(frame):
            return ipaddress.IPv4Address(frame[14 + 20 + 8 + 16:
                                                14 + 20 + 8 + 20])

        for mac, expected in (
            (sim.CONTROLLER_MAC, sim.CONTROLLER_IP),
            (CLIENT_MAC, sim.LEASE_IP),
        ):
            offer = self.gateway.handle(dhcp(mac, 1))
            self.assertEqual(len(offer), 1)
            self.assertEqual(offered_address(offer[0]), expected)
            acknowledgement = self.gateway.handle(dhcp(mac, 3, expected))
            self.assertEqual(len(acknowledgement), 1)
            self.assertEqual(offered_address(acknowledgement[0]), expected)

        self.assertEqual(self.gateway.lease_mac, CLIENT_MAC)
        query = bytearray(48)
        query[0] = 0x23
        query[40:48] = b"request!"
        self.assertEqual(len(self.gateway.handle(controller_ip(
            17, sim.udp(43210, 123, bytes(query)), sim.NTP_IP))), 1)
        self.assertEqual(len(self.gateway.handle(request_ip(
            17, sim.udp(43211, 123, bytes(query)), sim.NTP_IP))), 1)

        self.assertEqual(
            self.gateway.handle(dhcp(sim.CONTROLLER_MAC, 3, sim.LEASE_IP)), [])
        self.assertEqual(
            self.gateway.handle(dhcp(CLIENT_MAC, 3, sim.CONTROLLER_IP)), [])
        second_client = bytes.fromhex("525400311199")
        self.assertEqual(self.gateway.handle(dhcp(second_client, 1)), [])
        spoofed_controller_ip = sim.ethernet(
            sim.GATEWAY_MAC, CLIENT_MAC, 0x0800,
            sim.ipv4(
                sim.CONTROLLER_IP, sim.GATEWAY_IP, 17,
                sim.udp(40000, sim.UDP_PROBE_PORT, b"x")),
        )
        self.assertEqual(self.gateway.handle(spoofed_controller_ip), [])

    def test_arp_rejects_mismatched_payload_mac(self):
        other = bytes.fromhex("525400311199")
        arp = struct.pack("!HHBBH", 1, 0x0800, 6, 4, 1)
        arp += other + CLIENT_IP.packed + b"\0" * 6 + sim.GATEWAY_IP.packed
        frame = sim.ethernet(b"\xff" * 6, CLIENT_MAC, 0x0806, arp)
        self.assertEqual(self.gateway.handle(frame), [])

    def test_udp_probe_refuses_oversized_reflection(self):
        probe = request_ip(
            17, sim.udp(40000, sim.UDP_PROBE_PORT, b"x" * 1401))
        self.assertEqual(self.gateway.handle(probe), [])


if __name__ == "__main__":
    unittest.main()
