#!/usr/bin/env python3
"""Small, unprivileged gateway simulator for an isolated QEMU socket NIC.

It implements only ARP, DHCP, DNS, ICMP echo, NTP, and a UDP echo probe.  It
never forwards general traffic and its only host socket is a TCP listener on
127.0.0.1.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import socket
import struct
import time
from pathlib import Path

try:
    from .simulation_evidence import append_json_event
except ImportError:
    from simulation_evidence import append_json_event


GATEWAY_IP = ipaddress.IPv4Address("10.1.31.1")
LEASE_IP = ipaddress.IPv4Address("10.1.31.11")
CONTROLLER_IP = ipaddress.IPv4Address("10.1.31.2")
NETMASK = ipaddress.IPv4Address("255.255.255.240")
GATEWAY_MAC = bytes.fromhex("525400311101")
CONTROLLER_MAC = bytes.fromhex("525400111112")
DNS_NAME = "updates.sim.test"
CONTROLLER_NAME = "bootstrap-dc.lab.home.arpa"
DNS_SUFFIX = "lab.home.arpa"
IDENTITY_DNS_SUFFIX = "ad.factory.test"
NTP_NAME = "time.sim.test"
NTP_IP = ipaddress.IPv4Address("198.51.100.10")
UDP_PROBE_PORT = 31337
NTP_EPOCH = 2_208_988_800
IDENTITY_ETHERTYPE = 0x88B5
IPXE_SCRIPT = f"http://{CONTROLLER_IP}/boot/boot.ipxe"
PXE_BOOT_FILES = {
    0: "undionly.kpxe",
    6: "ipxe-i386.efi",
    7: "ipxe.efi",
    9: "ipxe.efi",
}


def checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\0"
    words = struct.unpack(f"!{len(data) // 2}H", data)
    total = sum(words)
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def ethernet(dst: bytes, src: bytes, kind: int, payload: bytes) -> bytes:
    return dst + src + struct.pack("!H", kind) + payload


def identity_announcement(source_mac: bytes, role: str) -> bytes:
    """Return a harmless public frame that authenticates a passive peer."""
    return ethernet(
        b"\xff" * 6, source_mac, IDENTITY_ETHERTYPE,
        f"telos-switch-peer:{role}".encode("ascii"),
    )


def ipv4(src: ipaddress.IPv4Address, dst: ipaddress.IPv4Address,
         protocol: int, payload: bytes, ident: int = 0) -> bytes:
    header = struct.pack(
        "!BBHHHBBH4s4s", 0x45, 0, 20 + len(payload), ident, 0,
        64, protocol, 0, src.packed, dst.packed,
    )
    header = header[:10] + struct.pack("!H", checksum(header)) + header[12:]
    return header + payload


def udp(src_port: int, dst_port: int, payload: bytes) -> bytes:
    return struct.pack("!HHHH", src_port, dst_port, 8 + len(payload), 0) + payload


def dns_name(data: bytes, offset: int) -> tuple[str, int]:
    labels: list[str] = []
    wire_size = 1
    while True:
        if offset >= len(data):
            raise ValueError("truncated DNS name")
        size = data[offset]
        offset += 1
        if size == 0:
            return ".".join(labels).lower(), offset
        if size & 0xC0 or size > 63:
            raise ValueError("invalid DNS label")
        if offset + size > len(data) or wire_size + size + 1 > 255:
            raise ValueError("truncated or oversized DNS name")
        labels.append(data[offset:offset + size].decode("ascii"))
        offset += size
        wire_size += size + 1


def dhcp_options(data: bytes) -> dict[int, bytes]:
    result: dict[int, bytes] = {}
    offset = 240
    if data[236:240] != b"\x63\x82\x53\x63":
        return result
    while offset < len(data):
        kind = data[offset]
        offset += 1
        if kind == 255:
            break
        if kind == 0:
            continue
        if offset >= len(data):
            return {}
        size = data[offset]
        offset += 1
        if offset + size > len(data):
            return {}
        result[kind] = data[offset:offset + size]
        offset += size
    return result


class Gateway:
    def __init__(
        self, clock=time.time, *, controller_mac: bytes = CONTROLLER_MAC,
        identity_mode: bool = False,
    ) -> None:
        if len(controller_mac) != 6 or controller_mac[0] & 1:
            raise ValueError("Controller MAC must be a unicast Ethernet address")
        self.lease_mac: bytes | None = None
        self.clock = clock
        self.controller_mac = controller_mac
        self.identity_mode = identity_mode

    def _valid_source(
        self, source_mac: bytes, source_ip: ipaddress.IPv4Address,
    ) -> bool:
        if source_mac == self.controller_mac and source_ip == CONTROLLER_IP:
            return True
        return (
            self.lease_mac is None
            or (source_mac == self.lease_mac and source_ip == LEASE_IP)
        )

    def handle(self, frame: bytes) -> list[bytes]:
        if len(frame) < 14:
            return []
        dst, src, kind = frame[:6], frame[6:12], struct.unpack("!H", frame[12:14])[0]
        if dst not in (GATEWAY_MAC, b"\xff" * 6):
            return []
        if src == GATEWAY_MAC or src[0] & 1:
            return []
        payload = frame[14:]
        if kind == 0x0806:
            return self._arp(src, payload)
        if kind != 0x0800 or len(payload) < 20 or payload[0] >> 4 != 4:
            return []
        ihl = (payload[0] & 0x0F) * 4
        total_length = struct.unpack("!H", payload[2:4])[0]
        fragment = struct.unpack("!H", payload[6:8])[0]
        if ihl < 20 or total_length < ihl or total_length > len(payload):
            return []
        if fragment & 0x3FFF:
            return []
        payload = payload[:total_length]
        if checksum(payload[:ihl]) != 0:
            return []
        target = ipaddress.IPv4Address(payload[16:20])
        source_ip = ipaddress.IPv4Address(payload[12:16])
        protocol = payload[9]
        body = payload[ihl:]
        if protocol == 1 and target == GATEWAY_IP:
            if not self._valid_source(src, source_ip):
                return []
            return self._icmp(src, payload, body)
        if protocol != 17 or len(body) < 8:
            return []
        src_port, dst_port, length, _ = struct.unpack("!HHHH", body[:8])
        if length < 8 or length > len(body) or src_port == 0:
            return []
        request = body[8:length]
        if src_port == 68 and dst_port == 67:
            return self._dhcp(src, request)
        if not self._valid_source(src, source_ip):
            return []
        if dst_port == 53 and target == GATEWAY_IP:
            return self._dns(src, payload[12:16], src_port, request)
        if dst_port == 123 and target == NTP_IP:
            return self._ntp(src, payload[12:16], src_port, request)
        if (dst_port == UDP_PROBE_PORT and target == GATEWAY_IP
                and len(request) <= 1400):
            return [self._udp_reply(src, payload[12:16], UDP_PROBE_PORT,
                                    src_port, b"sim-ok:" + request)]
        return []

    def _arp(self, source_mac: bytes, data: bytes) -> list[bytes]:
        if len(data) < 28:
            return []
        htype, ptype, hlen, plen, operation = struct.unpack("!HHBBH", data[:8])
        if (htype, ptype, hlen, plen, operation) != (1, 0x0800, 6, 4, 1):
            return []
        if data[8:14] != source_mac:
            return []
        sender_ip = data[14:18]
        if data[24:28] != GATEWAY_IP.packed:
            return []
        reply = struct.pack("!HHBBH", 1, 0x0800, 6, 4, 2)
        reply += GATEWAY_MAC + GATEWAY_IP.packed + source_mac + sender_ip
        return [ethernet(source_mac, GATEWAY_MAC, 0x0806, reply)]

    def _dhcp(self, source_mac: bytes, data: bytes) -> list[bytes]:
        if len(data) < 240:
            return []
        if data[0:4] != b"\x01\x01\x06\x00":
            return []
        if data[28:34] != source_mac:
            return []
        options = dhcp_options(data)
        message_option = options.get(53, b"")
        if len(message_option) != 1:
            return []
        message = message_option[0]
        if message not in (1, 3):
            return []
        controller_bootstrap = source_mac == self.controller_mac
        offered_ip = CONTROLLER_IP if controller_bootstrap else LEASE_IP
        if not controller_bootstrap and self.lease_mac not in (None, source_mac):
            return []
        if message == 3:
            requested = options.get(50)
            server = options.get(54)
            if requested not in (None, offered_ip.packed):
                return []
            if server not in (None, GATEWAY_IP.packed):
                return []
        if not controller_bootstrap:
            self.lease_mac = source_mac
        response_type = 2 if message == 1 else 5
        fixed = bytearray(data[:236])
        fixed[0] = 2
        fixed[16:20] = offered_ip.packed
        architecture = None
        if len(options.get(93, b"")) == 2:
            architecture = struct.unpack("!H", options[93])[0]
        boot_file = PXE_BOOT_FILES.get(architecture)
        if 175 in options or options.get(77, b"").lower() == b"ipxe":
            boot_file = IPXE_SCRIPT
        if self.identity_mode and not controller_bootstrap:
            boot_file = None
        # Retain the gateway identity for ordinary DHCP acceptance checks;
        # PXE leases deliberately name the separate boot controller.
        fixed[20:24] = (
            CONTROLLER_IP.packed if boot_file else GATEWAY_IP.packed)
        options = b"\x63\x82\x53\x63"
        options += bytes((53, 1, response_type))
        options += bytes((54, 4)) + GATEWAY_IP.packed
        options += bytes((1, 4)) + NETMASK.packed
        options += bytes((3, 4)) + GATEWAY_IP.packed
        identity_client = self.identity_mode and not controller_bootstrap
        dns_server = (
            CONTROLLER_IP if boot_file or identity_client else GATEWAY_IP)
        options += bytes((6, 4)) + dns_server.packed
        suffix = (
            IDENTITY_DNS_SUFFIX if identity_client else DNS_SUFFIX
        ).encode("ascii")
        options += bytes((15, len(suffix))) + suffix
        options += bytes((42, 4)) + NTP_IP.packed
        options += bytes((51, 4)) + struct.pack("!I", 600)
        if boot_file:
            server = str(CONTROLLER_IP).encode("ascii")
            filename = boot_file.encode("ascii")
            options += bytes((66, len(server))) + server
            options += bytes((67, len(filename))) + filename
        options += b"\xff"
        packet = udp(67, 68, bytes(fixed) + options)
        ip = ipv4(GATEWAY_IP, ipaddress.IPv4Address("255.255.255.255"), 17, packet)
        return [ethernet(b"\xff" * 6, GATEWAY_MAC, 0x0800, ip)]

    def _dns(self, source_mac: bytes, source_ip: bytes,
             source_port: int, data: bytes) -> list[bytes]:
        if len(data) < 12:
            return []
        flags, questions = struct.unpack("!HH", data[2:6])
        if flags & 0x8000 or questions != 1:
            return []
        try:
            name, end = dns_name(data, 12)
        except (ValueError, IndexError, UnicodeDecodeError):
            return []
        if end + 4 > len(data):
            return []
        qtype, qclass = struct.unpack("!HH", data[end:end + 4])
        addresses = {
            DNS_NAME: GATEWAY_IP,
            NTP_NAME: NTP_IP,
            CONTROLLER_NAME: CONTROLLER_IP,
        }
        found = name in addresses and qtype == 1 and qclass == 1
        flags = 0x8180 if found else 0x8183
        header = data[:2] + struct.pack("!HHHHH", flags, 1, int(found), 0, 0)
        answer = b""
        if found:
            answer = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 30, 4)
            answer += addresses[name].packed
        payload = header + data[12:end + 4] + answer
        return [self._udp_reply(source_mac, source_ip, 53, source_port, payload)]

    @staticmethod
    def _ntp_timestamp(value: float) -> bytes:
        seconds = int(value) + NTP_EPOCH
        fraction = int((value - int(value)) * (1 << 32))
        return struct.pack("!II", seconds, fraction)

    def _ntp(self, source_mac: bytes, source_ip: bytes,
             source_port: int, data: bytes) -> list[bytes]:
        version = data[0] >> 3 & 0x7 if data else 0
        if (len(data) != 48 or data[0] & 0x7 != 3 or
                version not in (3, 4) or data[40:48] == b"\0" * 8):
            return []
        now = self.clock()
        response = bytearray(48)
        response[0] = 0x24  # NTPv4, server response
        response[1] = 2     # synchronized secondary server
        response[2] = data[2]
        response[3] = 0xEC  # precision: 2^-20 seconds
        response[4:8] = struct.pack("!I", 1 << 16)
        response[8:12] = struct.pack("!I", 1 << 12)
        response[12:16] = b"SIM\0"
        response[16:24] = self._ntp_timestamp(now - 1)
        response[24:32] = data[40:48]
        response[32:40] = self._ntp_timestamp(now)
        response[40:48] = self._ntp_timestamp(now)
        return [self._udp_reply(
            source_mac, source_ip, 123, source_port, bytes(response),
            source_ip=NTP_IP,
        )]

    def _icmp(self, source_mac: bytes, ip: bytes, data: bytes) -> list[bytes]:
        if len(data) < 8 or data[0] != 8 or checksum(data) != 0:
            return []
        reply = b"\0" + data[1:2] + b"\0\0" + data[4:]
        reply = reply[:2] + struct.pack("!H", checksum(reply)) + reply[4:]
        packet = ipv4(GATEWAY_IP, ipaddress.IPv4Address(ip[12:16]), 1, reply)
        return [ethernet(source_mac, GATEWAY_MAC, 0x0800, packet)]

    def _udp_reply(self, target_mac: bytes, target_ip: bytes,
                   source_port: int, target_port: int, payload: bytes,
                   source_ip: ipaddress.IPv4Address = GATEWAY_IP) -> bytes:
        packet = udp(source_port, target_port, payload)
        ip = ipv4(source_ip, ipaddress.IPv4Address(target_ip), 17, packet)
        return ethernet(target_mac, GATEWAY_MAC, 0x0800, ip)


def receive_exact(connection: socket.socket, size: int) -> bytes | None:
    chunks = bytearray()
    while len(chunks) < size:
        chunk = connection.recv(size - len(chunks))
        if not chunk:
            return None
        chunks.extend(chunk)
    return bytes(chunks)


def dhcp_server_message(frame: bytes) -> str | None:
    """Return a server message name, if this Ethernet frame contains one."""
    if len(frame) < 14 + 20 + 8 or frame[12:14] != b"\x08\x00":
        return None
    ip = frame[14:]
    ihl = (ip[0] & 15) * 4
    if ihl < 20 or len(ip) < ihl + 8 or ip[9] != 17:
        return None
    source, target = struct.unpack("!HH", ip[ihl:ihl + 4])
    if (source, target) != (67, 68):
        return None
    options = dhcp_options(ip[ihl + 8:])
    names = {2: "OFFER", 5: "ACK", 6: "NAK"}
    value = options.get(53, b"")
    return names.get(value[0]) if len(value) == 1 else None


def dhcp_packet_evidence(frame: bytes) -> dict[str, object] | None:
    """Return bounded, human-readable DHCP evidence from an Ethernet frame."""
    if len(frame) < 14 + 20 + 8 or frame[12:14] != b"\x08\x00":
        return None
    ip = frame[14:]
    ihl = (ip[0] & 15) * 4
    if ihl < 20 or len(ip) < ihl + 8 or ip[9] != 17:
        return None
    source, target = struct.unpack("!HH", ip[ihl:ihl + 4])
    if (source, target) not in ((68, 67), (67, 68)):
        return None
    bootp = ip[ihl + 8:]
    if len(bootp) < 240:
        return None
    options = dhcp_options(bootp)
    value = options.get(53, b"")
    names = {1: "DISCOVER", 2: "OFFER", 3: "REQUEST", 5: "ACK", 6: "NAK"}
    if len(value) != 1 or value[0] not in names:
        return None
    result: dict[str, object] = {
        "kind": names[value[0]],
        "source_mac": ":".join(f"{part:02x}" for part in frame[6:12]),
        "client_mac": ":".join(f"{part:02x}" for part in bootp[28:34]),
        "transaction": bootp[4:8].hex(),
    }
    if bootp[16:20] != b"\0" * 4:
        result["offered_ip"] = str(ipaddress.IPv4Address(bootp[16:20]))
    if len(options.get(50, b"")) == 4:
        result["requested_ip"] = str(ipaddress.IPv4Address(options[50]))
    architecture = options.get(93)
    if architecture is not None and len(architecture) == 2:
        result["architecture"] = struct.unpack("!H", architecture)[0]
    if 66 in options:
        result["next_server"] = options[66].decode("ascii", "replace")
    if 67 in options:
        result["boot_file"] = options[67].decode("ascii", "replace")
    return result


class HubPolicy:
    """Pure routing policy for a concurrent isolated PXE Ethernet hub."""

    def __init__(
        self, gateway: Gateway | None = None, *, gateway_peer: int | None = None,
    ) -> None:
        self.gateway = gateway or Gateway()
        self.gateway_peer = gateway_peer
        self.learned: dict[bytes, int] = {}
        self.dhcp_clients: dict[str, int] = {}

    def route(self, sender: int, frame: bytes, peers: set[int]
              ) -> tuple[dict[int, list[bytes]], list[dict[str, object]]]:
        deliveries: dict[int, list[bytes]] = {}
        evidence: list[dict[str, object]] = []
        if len(frame) < 14:
            return deliveries, evidence
        destination, source = frame[:6], frame[6:12]
        if sender == self.gateway_peer:
            if source != GATEWAY_MAC:
                return deliveries, evidence
            dhcp = dhcp_packet_evidence(frame)
            if dhcp:
                target = self.dhcp_clients.get(str(dhcp["transaction"]))
                record = {**dhcp, "peer": "gateway"}
                if target in peers and target != sender:
                    record["delivered_to"] = target
                    deliveries[target] = [frame]
                evidence.append(record)
                return deliveries, evidence
            target = self.learned.get(destination)
            if target in peers and target != sender:
                deliveries[target] = [frame]
            return deliveries, evidence
        if source[0] & 1 or source == GATEWAY_MAC:
            return deliveries, evidence
        self.learned[source] = sender
        dhcp = dhcp_packet_evidence(frame)
        if dhcp:
            evidence.append({**dhcp, "peer": sender})
            # No peer can act as a DHCP server.  Client requests terminate at
            # the simulated gateway and are not exposed to the controller.
            if dhcp["kind"] in ("OFFER", "ACK", "NAK"):
                evidence[-1]["blocked"] = True
                return deliveries, evidence
            if self.gateway_peer in peers:
                self.dhcp_clients[str(dhcp["transaction"])] = sender
                deliveries[self.gateway_peer] = [frame]
                return deliveries, evidence
            replies = self.gateway.handle(frame)
            if replies:
                deliveries[sender] = replies
                for reply in replies:
                    reply_evidence = dhcp_packet_evidence(reply)
                    if reply_evidence:
                        evidence.append({
                            **reply_evidence, "peer": "gateway",
                            "delivered_to": sender,
                        })
            return deliveries, evidence
        if self.gateway_peer in peers and destination == GATEWAY_MAC:
            deliveries.setdefault(self.gateway_peer, []).append(frame)
        else:
            for reply in self.gateway.handle(frame):
                deliveries.setdefault(sender, []).append(reply)
        if destination == GATEWAY_MAC:
            return deliveries, evidence
        if destination == b"\xff" * 6 or destination[0] & 1:
            targets = peers - {sender}
        else:
            target = self.learned.get(destination)
            targets = {target} if target in peers and target != sender else set()
        for target in targets:
            deliveries.setdefault(target, []).append(frame)
        return deliveries, evidence


def serve(
    port: int,
    connections: int = 1,
    listener_fd: int | None = None,
    audit_first: Path | None = None,
) -> None:
    supplied = listener_fd is not None
    with (socket.socket(fileno=listener_fd) if supplied else socket.socket()) as listener:
        if supplied:
            address = listener.getsockname()
            if address[0] != "127.0.0.1":
                raise RuntimeError("inherited listener is not loopback-only")
        else:
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            listener.bind(("127.0.0.1", port))
            listener.listen(1)
        print(f"simulated gateway listening on {listener.getsockname()}", flush=True)
        for connection_number in range(connections):
            gateway = Gateway()
            connection, address = listener.accept()
            if address[0] != "127.0.0.1":
                raise RuntimeError("refusing non-loopback peer")
            with connection:
                while True:
                    header = receive_exact(connection, 4)
                    if header is None:
                        break
                    size = struct.unpack("!I", header)[0]
                    if size > 65535:
                        raise RuntimeError("invalid QEMU frame size")
                    frame = receive_exact(connection, size)
                    if frame is None:
                        break
                    if connection_number == 0 and audit_first is not None:
                        message = dhcp_server_message(frame)
                        if message:
                            append_json_event(audit_first, {
                                "kind": message,
                                "actor": "controller",
                            })
                    for reply in gateway.handle(frame):
                        connection.sendall(
                            struct.pack("!I", len(reply)) + reply)


def connect_peer(
    host: str, port: int, *, controller_mac: bytes = CONTROLLER_MAC,
    identity_mode: bool = False,
) -> None:
    if host != "127.0.0.1":
        raise RuntimeError("gateway peer must connect only to 127.0.0.1")
    gateway = Gateway(
        controller_mac=controller_mac, identity_mode=identity_mode)
    with socket.create_connection((host, port)) as connection:
        announcement = identity_announcement(GATEWAY_MAC, "gateway")
        connection.sendall(struct.pack("!I", len(announcement)) + announcement)
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
            for reply in gateway.handle(frame):
                connection.sendall(struct.pack("!I", len(reply)) + reply)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, default=12962)
    parser.add_argument("--connections", type=int, default=1)
    parser.add_argument("--listener-fd", type=int)
    parser.add_argument("--audit-first", type=Path)
    parser.add_argument("--connect", action="store_true")
    parser.add_argument("--controller-mac", default=CONTROLLER_MAC.hex(":"))
    parser.add_argument("--identity-mode", action="store_true")
    args = parser.parse_args()
    if not 1024 <= args.port <= 65535:
        parser.error("--port must be an unprivileged TCP port")
    if not 1 <= args.connections <= 8:
        parser.error("--connections must be between 1 and 8")
    if args.connect:
        if args.listener_fd is not None or args.connections != 1:
            parser.error("--connect cannot use --listener-fd or --connections")
        try:
            controller_mac = bytes.fromhex(args.controller_mac.replace(":", ""))
        except ValueError:
            parser.error("--controller-mac must be six hexadecimal octets")
        connect_peer(
            "127.0.0.1", args.port, controller_mac=controller_mac,
            identity_mode=args.identity_mode)
    else:
        serve(args.port, args.connections, args.listener_fd, args.audit_first)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
