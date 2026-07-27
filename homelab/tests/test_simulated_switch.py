import json
import random
import socket
import stat
import struct
import tempfile
import threading
import unittest
from pathlib import Path

from homelab.vm import simulated_gateway as gateway
from homelab.vm import simulated_switch as switch


CLIENT = bytes.fromhex("525400311111")
CONTROLLER = bytes.fromhex("525400311102")


def framed(frame):
    return struct.pack("!I", len(frame)) + frame


def receive(connection):
    size = struct.unpack("!I", switch.receive_exact(connection, 4))[0]
    return switch.receive_exact(connection, size)


class SimulatedSwitchTests(unittest.TestCase):
    def listener(self):
        listener = socket.socket()
        listener.bind(("127.0.0.1", 0))
        listener.listen(2)
        return listener

    def test_requires_loopback_inherited_listener(self):
        listener = socket.socket()
        listener.bind(("0.0.0.0", 0))
        listener.listen()
        with self.assertRaisesRegex(RuntimeError, "127.0.0.1"):
            switch.ConcurrentSwitch(
                listener, [switch.Port(1, "client", CLIENT)])
        listener.close()

    def test_switches_broadcast_and_learned_unicast(self):
        listener = self.listener()
        address = listener.getsockname()
        fabric = switch.ConcurrentSwitch(listener, [
            switch.Port(1, "client", CLIENT),
            switch.Port(2, "controller", CONTROLLER),
        ], idle_timeout=5)
        thread = threading.Thread(target=fabric.run)
        thread.start()
        client = socket.create_connection(address)
        controller = socket.create_connection(address)
        broadcast = gateway.ethernet(b"\xff" * 6, CLIENT, 0x88b5, b"x")
        client.sendall(framed(broadcast))
        self.assertEqual(receive(controller), broadcast)
        unicast = gateway.ethernet(CLIENT, CONTROLLER, 0x88b5, b"y")
        controller.sendall(framed(unicast))
        self.assertEqual(receive(client), unicast)
        client.close()
        controller.close()
        thread.join(5)
        self.assertFalse(thread.is_alive())

    def test_blocks_wrong_source_and_rogue_dhcp(self):
        listener = self.listener()
        address = listener.getsockname()
        with tempfile.TemporaryDirectory() as temp:
            evidence = Path(temp) / "evidence.jsonl"
            fabric = switch.ConcurrentSwitch(listener, [
                switch.Port(1, "client", CLIENT),
                switch.Port(2, "controller", CONTROLLER),
            ], evidence_path=evidence, idle_timeout=5)
            thread = threading.Thread(target=fabric.run)
            thread.start()
            client = socket.create_connection(address)
            controller = socket.create_connection(address)
            wrong = gateway.ethernet(
                b"\xff" * 6, CONTROLLER, 0x88b5, b"spoof")
            client.sendall(framed(wrong))
            rogue = bytearray(gateway.Gateway().handle(
                self._discover(CONTROLLER))[0])
            rogue[6:12] = CONTROLLER
            controller.sendall(framed(bytes(rogue)))
            client.settimeout(0.2)
            with self.assertRaises(TimeoutError):
                client.recv(1)
            client.close()
            controller.close()
            thread.join(5)
            events = [json.loads(line) for line in evidence.read_text().splitlines()]
            self.assertEqual(
                stat.S_IMODE(evidence.stat().st_mode), 0o600)
            self.assertTrue(any(
                item["event"] == "source-mac-blocked" for item in events))
            self.assertTrue(any(
                item["event"] == "dhcp" and item.get("blocked")
                for item in events))

    @staticmethod
    def _discover(mac):
        fixed = bytearray(236)
        fixed[:4] = b"\x01\x01\x06\x00"
        fixed[28:34] = mac
        payload = fixed + b"\x63\x82\x53\x63\x35\x01\x01\xff"
        return gateway.ethernet(
            b"\xff" * 6, mac, 0x0800,
            gateway.ipv4(
                gateway.ipaddress.IPv4Address("0.0.0.0"),
                gateway.ipaddress.IPv4Address("255.255.255.255"), 17,
                gateway.udp(68, 67, payload)))

    def test_rejects_duplicate_ports_and_bad_frames(self):
        listener = self.listener()
        with self.assertRaises(ValueError):
            switch.ConcurrentSwitch(listener, [
                switch.Port(1, "one", CLIENT),
                switch.Port(2, "two", CLIENT),
            ])
        listener.close()
        for value in ("bad", "01:00:00:00:00:01", "00:00:00:00:00:00"):
            with self.assertRaises(ValueError):
                switch.mac_bytes(value)

    def test_policy_survives_random_untrusted_frames(self):
        policy = gateway.HubPolicy()
        randomizer = random.Random(311)
        for _ in range(20_000):
            frame = randomizer.randbytes(randomizer.randrange(0, 2048))
            deliveries, evidence = policy.route(1, frame, {1, 2})
            self.assertLessEqual(set(deliveries), {1, 2})
            self.assertLessEqual(len(evidence), 2)


if __name__ == "__main__":
    unittest.main()
