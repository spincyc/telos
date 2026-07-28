#!/usr/bin/env python3
"""Guest-visible dependency peers on the isolated socket-backed Ethernet."""

from __future__ import annotations

import argparse
import ipaddress
import socket
import struct

from .simulated_gateway import checksum, ethernet, ipv4, receive_exact, udp


DEPENDENCIES = {
    "update-source": {
        "ip": ipaddress.IPv4Address("10.1.31.3"),
        "mac": bytes.fromhex("525400311103"),
        "port": 31338,
    },
    "optional-storage": {
        "ip": ipaddress.IPv4Address("10.1.31.4"),
        "mac": bytes.fromhex("525400311104"),
        "port": 31339,
    },
}


class DependencyPeer:
    """Pure ARP/UDP responder with one fixed L2 and L3 identity."""

    def __init__(self, role: str) -> None:
        spec = DEPENDENCIES[role]
        self.role = role
        self.ip = spec["ip"]
        self.mac = spec["mac"]
        self.port = spec["port"]

    def handle(self, frame: bytes) -> list[bytes]:
        if len(frame) < 14 or frame[:6] not in (self.mac, b"\xff" * 6):
            return []
        source_mac = frame[6:12]
        if source_mac[0] & 1:
            return []
        kind = struct.unpack("!H", frame[12:14])[0]
        body = frame[14:]
        if kind == 0x0806:
            return self._arp(source_mac, body)
        if kind != 0x0800 or len(body) < 28 or body[0] >> 4 != 4:
            return []
        ihl = (body[0] & 0x0F) * 4
        total = struct.unpack("!H", body[2:4])[0]
        if (
            ihl < 20 or total < ihl + 8 or total > len(body)
            or checksum(body[:ihl]) != 0 or body[9] != 17
            or body[16:20] != self.ip.packed
        ):
            return []
        source_ip = ipaddress.IPv4Address(body[12:16])
        source_port, target_port, length, _checksum = struct.unpack(
            "!HHHH", body[ihl:ihl + 8])
        if (
            source_port == 0 or target_port != self.port
            or length < 8 or ihl + length > total
        ):
            return []
        request = body[ihl + 8:ihl + length]
        if request != b"health":
            return []
        payload = f"{self.role}:available".encode("ascii")
        packet = udp(self.port, source_port, payload)
        return [ethernet(
            source_mac, self.mac, 0x0800,
            ipv4(self.ip, source_ip, 17, packet),
        )]

    def _arp(self, source_mac: bytes, body: bytes) -> list[bytes]:
        if (
            len(body) < 28
            or struct.unpack("!HHBBH", body[:8])
            != (1, 0x0800, 6, 4, 1)
            or body[8:14] != source_mac
            or body[24:28] != self.ip.packed
        ):
            return []
        reply = struct.pack("!HHBBH", 1, 0x0800, 6, 4, 2)
        reply += (
            self.mac + self.ip.packed + source_mac + body[14:18])
        return [ethernet(source_mac, self.mac, 0x0806, reply)]


def connect_peer(role: str, switch_port: int) -> None:
    peer = DependencyPeer(role)
    with socket.create_connection(("127.0.0.1", switch_port)) as connection:
        while True:
            header = receive_exact(connection, 4)
            if header is None:
                return
            size = struct.unpack("!I", header)[0]
            if not 14 <= size <= 65535:
                raise RuntimeError("invalid Ethernet frame size")
            frame = receive_exact(connection, size)
            if frame is None:
                raise RuntimeError("truncated Ethernet frame")
            for reply in peer.handle(frame):
                connection.sendall(struct.pack("!I", len(reply)) + reply)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--role", choices=DEPENDENCIES, required=True)
    parser.add_argument("--switch-port", type=int, required=True)
    arguments = parser.parse_args()
    connect_peer(arguments.role, arguments.switch_port)


if __name__ == "__main__":
    main()
