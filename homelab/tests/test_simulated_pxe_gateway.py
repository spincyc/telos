import ipaddress
import struct
import unittest

from homelab.vm import simulated_gateway as sim


CLIENT = bytes.fromhex("525400311111")
CONTROLLER = bytes.fromhex("525400311102")


def dhcp(message=1, architecture=None, ipxe=False, mac=CLIENT):
    fixed = bytearray(236)
    fixed[0:4] = b"\x01\x01\x06\x00"
    fixed[4:8] = b"pxe!"
    fixed[28:34] = mac
    options = b"\x63\x82\x53\x63" + bytes((53, 1, message))
    if architecture is not None:
        options += bytes((93, 2)) + struct.pack("!H", architecture)
    if ipxe:
        options += bytes((175, 0))
    options += b"\xff"
    return sim.ethernet(
        b"\xff" * 6, mac, 0x0800,
        sim.ipv4(
            ipaddress.IPv4Address("0.0.0.0"),
            ipaddress.IPv4Address("255.255.255.255"), 17,
            sim.udp(68, 67, bytes(fixed) + options)))


class SimulatedPxeGatewayTests(unittest.TestCase):
    def test_uefi_x64_receives_controller_boot_coordinates(self):
        reply = sim.Gateway().handle(dhcp(architecture=7))[0]
        evidence = sim.dhcp_packet_evidence(reply)
        self.assertEqual(evidence["kind"], "OFFER")
        self.assertEqual(evidence["next_server"], "10.1.31.2")
        self.assertEqual(evidence["boot_file"], "ipxe.efi")
        self.assertEqual(reply[14 + 20 + 8 + 20:14 + 20 + 8 + 24],
                         sim.CONTROLLER_IP.packed)
        options = sim.dhcp_options(reply[14 + 20 + 8:])
        self.assertEqual(options[6], sim.CONTROLLER_IP.packed)
        self.assertEqual(options[15], b"lab.home.arpa")
        self.assertEqual(options[42], sim.NTP_IP.packed)

    def test_ipxe_chainloads_immutable_http_entrypoint(self):
        reply = sim.Gateway().handle(dhcp(architecture=7, ipxe=True))[0]
        self.assertEqual(
            sim.dhcp_packet_evidence(reply)["boot_file"], sim.IPXE_SCRIPT)

    def test_unknown_architecture_gets_ordinary_lease(self):
        reply = sim.Gateway().handle(dhcp(architecture=0xffff))[0]
        evidence = sim.dhcp_packet_evidence(reply)
        self.assertNotIn("next_server", evidence)
        self.assertNotIn("boot_file", evidence)
        options = sim.dhcp_options(reply[14 + 20 + 8:])
        self.assertEqual(options[6], sim.GATEWAY_IP.packed)

    def test_bios_and_ipxe_user_class_get_correct_stages(self):
        bios = sim.Gateway().handle(dhcp(architecture=0))[0]
        self.assertEqual(
            sim.dhcp_packet_evidence(bios)["boot_file"], "undionly.kpxe")
        ipxe = sim.Gateway().handle(dhcp(architecture=7, ipxe=True))[0]
        self.assertEqual(
            sim.dhcp_packet_evidence(ipxe)["boot_file"], sim.IPXE_SCRIPT)

    def test_gateway_is_only_dhcp_authority(self):
        policy = sim.HubPolicy()
        peers = {1, 2}
        deliveries, evidence = policy.route(1, dhcp(architecture=7), peers)
        self.assertEqual(set(deliveries), {1})
        self.assertEqual([event["kind"] for event in evidence],
                         ["DISCOVER", "OFFER"])
        rogue = bytearray(policy.gateway.handle(dhcp(architecture=7))[0])
        rogue[6:12] = CONTROLLER
        deliveries, evidence = policy.route(2, bytes(rogue), peers)
        self.assertEqual(deliveries, {})
        self.assertTrue(evidence[0]["blocked"])

    def test_explicit_gateway_peer_is_the_only_dhcp_path(self):
        policy = sim.HubPolicy(gateway_peer=3)
        peers = {1, 2, 3}
        request = dhcp(architecture=7)
        deliveries, _ = policy.route(1, request, peers)
        self.assertEqual(deliveries, {3: [request]})
        reply = sim.Gateway().handle(request)[0]
        deliveries, evidence = policy.route(3, reply, peers)
        self.assertEqual(deliveries, {1: [reply]})
        self.assertEqual(evidence[0]["peer"], "gateway")

    def test_hub_forwards_controller_client_unicast_and_broadcast(self):
        policy = sim.HubPolicy()
        peers = {1, 2}
        controller_announcement = sim.ethernet(
            b"\xff" * 6, CONTROLLER, 0x0806, bytes(28))
        deliveries, _ = policy.route(2, controller_announcement, peers)
        self.assertEqual(deliveries, {1: [controller_announcement]})
        client_request = sim.ethernet(CONTROLLER, CLIENT, 0x0806, bytes(28))
        deliveries, _ = policy.route(1, client_request, peers)
        self.assertEqual(deliveries, {2: [client_request]})

    def test_evidence_is_bounded_and_records_architecture(self):
        evidence = sim.dhcp_packet_evidence(dhcp(architecture=9))
        self.assertEqual(evidence, {
            "kind": "DISCOVER",
            "source_mac": "52:54:00:31:11:11",
            "client_mac": "52:54:00:31:11:11",
            "transaction": "70786521",
            "architecture": 9,
        })


if __name__ == "__main__":
    unittest.main()
