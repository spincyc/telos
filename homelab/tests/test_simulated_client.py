import socket
import ipaddress
import struct
import tempfile
import threading
import unittest
from pathlib import Path

from homelab.vm import dhcp_provenance
from homelab.vm import simulated_client
from homelab.vm import simulated_gateway


class SimulatedClientTests(unittest.TestCase):
    def setUp(self):
        self.gateway = simulated_gateway.Gateway(clock=lambda: 12345.5)
        self.xid = b"\x11\x22\x33\x44"
        self.offer = self.gateway.handle(
            simulated_client._dhcp(self.xid, 1))[0]
        self.ack = self.gateway.handle(
            simulated_client._dhcp(self.xid, 3))[0]

    @staticmethod
    def rewrite_source_ip(frame, address):
        changed = bytearray(frame)
        changed[26:30] = ipaddress.IPv4Address(address).packed
        changed[24:26] = b"\0\0"
        changed[24:26] = struct.pack(
            "!H", simulated_gateway.checksum(bytes(changed[14:34])))
        return bytes(changed)

    def test_dhcp_rejects_wrong_wire_identity_transaction_and_lease(self):
        simulated_client._parse_dhcp_reply(self.offer, self.xid, 2)
        cases = []
        changed = bytearray(self.offer)
        changed[6] ^= 1
        cases.append(bytes(changed))
        changed = bytearray(self.offer)
        changed[46:50] = b"nope"
        cases.append(bytes(changed))
        changed = bytearray(self.offer)
        changed[58:62] = ipaddress.IPv4Address("10.1.31.12").packed
        cases.append(bytes(changed))
        for frame in cases:
            with self.subTest(frame=frame[6:12]):
                with self.assertRaises(RuntimeError):
                    simulated_client._parse_dhcp_reply(frame, self.xid, 2)

    def test_dhcp_transcript_values_are_parsed_from_reply(self):
        fields = simulated_client._parse_dhcp_reply(self.ack, self.xid, 5)
        self.assertEqual(fields["server_address"], "10.1.31.1")
        self.assertEqual(fields["address"], "10.1.31.11")
        self.assertEqual(fields["lease_seconds"], 600)

    def test_dns_rejects_wrong_source_txid_name_type_and_address(self):
        query = simulated_client._dns_query()
        frame = self.gateway.handle(simulated_client._udp_request(
            simulated_gateway.GATEWAY_IP, 40001, 53, query))[0]
        simulated_client._parse_dns_reply(frame, query, 40001)
        mutations = [("source", self.rewrite_source_ip(frame, "10.1.31.2"))]
        for label, offset, value in (
                ("transaction", 42, 0x99), ("name", 55, ord("x")),
                ("type", 79, 28), ("address", 91, 2)):
            changed = bytearray(frame)
            changed[offset] = value
            mutations.append((label, bytes(changed)))
        for label, changed in mutations:
            with self.subTest(label=label):
                with self.assertRaises(RuntimeError):
                    simulated_client._parse_dns_reply(changed, query, 40001)

    def test_ntp_rejects_wrong_source_mode_originate_and_stratum(self):
        request = bytearray(48)
        request[0] = 0x23
        request[40:48] = b"12345678"
        frame = self.gateway.handle(simulated_client._udp_request(
            simulated_gateway.NTP_IP, 40002, 123, bytes(request)))[0]
        simulated_client._parse_ntp_reply(frame, bytes(request), 40002)
        mutations = [self.rewrite_source_ip(frame, "198.51.100.11")]
        for offset, value in ((42, 0x23), (43, 0), (66, ord("x"))):
            changed = bytearray(frame)
            changed[offset] = value
            mutations.append(bytes(changed))
        for changed in mutations:
            with self.assertRaises(RuntimeError):
                simulated_client._parse_ntp_reply(changed, bytes(request), 40002)

    def test_probe_rejects_wrong_source(self):
        frame = self.gateway.handle(simulated_client._udp_request(
            simulated_gateway.GATEWAY_IP, 40003,
            simulated_gateway.UDP_PROBE_PORT, b"cycle"))[0]
        self.assertEqual(
            simulated_client._parse_probe_reply(frame, 40003),
            b"sim-ok:cycle")
        with self.assertRaises(RuntimeError):
            simulated_client._parse_probe_reply(
                self.rewrite_source_ip(frame, "10.1.31.2"), 40003)

    def test_complete_wire_cycle_passes_provenance_judge(self):
        listener = socket.socket()
        self.addCleanup(listener.close)
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        port = listener.getsockname()[1]
        server = threading.Thread(
            target=simulated_gateway.serve,
            args=(port, 1, listener.detach()),
            daemon=True,
        )
        server.start()
        with tempfile.TemporaryDirectory() as temporary:
            transcript = Path(temporary) / "events.jsonl"
            transcript.write_text(
                '{"sequence":1,"kind":"POWEROFF",'
                '"actor":"controller"}\n')
            simulated_client.run(port, transcript)
            server.join(2)
            self.assertFalse(server.is_alive())
            self.assertEqual(
                dhcp_provenance.assess(
                    dhcp_provenance.load(transcript),
                    gateway="gateway", controller="controller",
                    client="client"),
                [],
            )

    def test_detector_identifies_only_dhcp_server_messages(self):
        fixed = bytearray(236)
        fixed[:4] = b"\x02\x01\x06\x00"
        payload = bytes(fixed) + b"\x63\x82\x53\x63\x35\x01\x02\xff"
        frame = simulated_gateway.ethernet(
            b"\xff" * 6, simulated_gateway.GATEWAY_MAC, 0x0800,
            simulated_gateway.ipv4(
                simulated_gateway.GATEWAY_IP,
                simulated_gateway.LEASE_IP, 17,
                simulated_gateway.udp(67, 68, payload)))
        self.assertEqual(
            simulated_gateway.dhcp_server_message(frame), "OFFER")
        self.assertIsNone(
            simulated_gateway.dhcp_server_message(frame[:30]))


if __name__ == "__main__":
    unittest.main()
