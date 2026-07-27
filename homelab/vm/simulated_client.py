#!/usr/bin/env python3
"""Exercise the userspace simulation gateway over a QEMU socket transport."""

from __future__ import annotations

import ipaddress
import json
import secrets
import socket
import struct
from pathlib import Path

try:
    from . import simulated_gateway as gateway
except ImportError:
    import simulated_gateway as gateway


CLIENT_MAC = bytes.fromhex("525400311212")
BROADCAST = b"\xff" * 6


def _exchange(stream: socket.socket, frame: bytes) -> bytes:
    stream.sendall(struct.pack("!I", len(frame)) + frame)
    header = gateway.receive_exact(stream, 4)
    if header is None:
        raise RuntimeError("gateway closed before replying")
    size = struct.unpack("!I", header)[0]
    reply = gateway.receive_exact(stream, size)
    if reply is None:
        raise RuntimeError("gateway reply was truncated")
    return reply


def _dhcp(xid: bytes, kind: int) -> bytes:
    fixed = bytearray(236)
    fixed[:4] = b"\x01\x01\x06\x00"
    fixed[4:8] = xid
    fixed[10:12] = b"\x80\x00"
    fixed[28:34] = CLIENT_MAC
    options = b"\x63\x82\x53\x63" + bytes((53, 1, kind))
    if kind == 3:
        options += bytes((50, 4)) + gateway.LEASE_IP.packed
        options += bytes((54, 4)) + gateway.GATEWAY_IP.packed
    options += b"\xff"
    payload = gateway.udp(68, 67, bytes(fixed) + options)
    packet = gateway.ipv4(
        ipaddress.IPv4Address("0.0.0.0"),
        ipaddress.IPv4Address("255.255.255.255"), 17, payload)
    return gateway.ethernet(BROADCAST, CLIENT_MAC, 0x0800, packet)


def _udp_request(
    target: ipaddress.IPv4Address, source_port: int, target_port: int,
    payload: bytes,
) -> bytes:
    packet = gateway.udp(source_port, target_port, payload)
    packet = gateway.ipv4(gateway.LEASE_IP, target, 17, packet)
    return gateway.ethernet(
        gateway.GATEWAY_MAC, CLIENT_MAC, 0x0800, packet)


def _dns_query() -> bytes:
    labels = b"".join(
        bytes((len(part),)) + part.encode("ascii")
        for part in gateway.DNS_NAME.split("."))
    return b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00" + \
        labels + b"\x00\x00\x01\x00\x01"


def _udp_payload(frame: bytes) -> bytes:
    return _udp_reply(frame)["payload"]


def _udp_reply(frame: bytes) -> dict[str, object]:
    if len(frame) < 42 or frame[12:14] != b"\x08\x00":
        raise RuntimeError("invalid simulated IPv4 reply")
    if frame[:6] not in (CLIENT_MAC, BROADCAST):
        raise RuntimeError("reply has wrong Ethernet recipient")
    if frame[6:12] != gateway.GATEWAY_MAC:
        raise RuntimeError("reply has wrong Ethernet sender")
    ip = frame[14:]
    if ip[0] != 0x45 or ip[9] != 17:
        raise RuntimeError("reply is not unfragmented IPv4 UDP")
    if struct.unpack("!H", ip[6:8])[0] & 0x3fff:
        raise RuntimeError("fragmented reply")
    total = struct.unpack("!H", ip[2:4])[0]
    if total < 28 or total != len(ip) or gateway.checksum(ip[:20]) != 0:
        raise RuntimeError("invalid IPv4 reply length or checksum")
    source_ip = ipaddress.IPv4Address(ip[12:16])
    target_ip = ipaddress.IPv4Address(ip[16:20])
    source_port, target_port, length, _ = struct.unpack("!HHHH", ip[20:28])
    if length < 8 or length != total - 20:
        raise RuntimeError("invalid UDP reply length")
    return {
        "source_mac": frame[6:12],
        "target_mac": frame[:6],
        "source_ip": source_ip,
        "target_ip": target_ip,
        "source_port": source_port,
        "target_port": target_port,
        "payload": ip[28:20 + length],
    }


def _expect_path(
    reply: dict[str, object], source_ip: ipaddress.IPv4Address,
    target_ip: ipaddress.IPv4Address, source_port: int, target_port: int,
    target_mac: bytes = CLIENT_MAC,
) -> bytes:
    actual = (
        reply["source_ip"], reply["target_ip"],
        reply["source_port"], reply["target_port"],
    )
    expected = (source_ip, target_ip, source_port, target_port)
    if actual != expected:
        raise RuntimeError(f"reply path mismatch: {actual!r}")
    if reply["target_mac"] != target_mac:
        raise RuntimeError("reply has wrong Ethernet recipient")
    return reply["payload"]  # type: ignore[return-value]


def _parse_dhcp_reply(frame: bytes, xid: bytes, expected_kind: int) -> dict[str, object]:
    reply = _udp_reply(frame)
    payload = _expect_path(
        reply, gateway.GATEWAY_IP,
        ipaddress.IPv4Address("255.255.255.255"), 67, 68, BROADCAST)
    if reply["target_mac"] != BROADCAST or len(payload) < 240:
        raise RuntimeError("invalid DHCP reply envelope")
    if payload[:4] != b"\x02\x01\x06\x00" or payload[4:8] != xid:
        raise RuntimeError("DHCP identity or transaction mismatch")
    if payload[16:20] != gateway.LEASE_IP.packed:
        raise RuntimeError("DHCP offered unexpected address")
    if payload[20:24] != gateway.GATEWAY_IP.packed:
        raise RuntimeError("DHCP next-server identity mismatch")
    if payload[28:34] != CLIENT_MAC:
        raise RuntimeError("DHCP client identity mismatch")
    options = gateway.dhcp_options(payload)
    required = {
        53: bytes((expected_kind,)),
        54: gateway.GATEWAY_IP.packed,
        1: gateway.NETMASK.packed,
        3: gateway.GATEWAY_IP.packed,
        6: gateway.GATEWAY_IP.packed,
        51: struct.pack("!I", 600),
    }
    if any(options.get(code) != value for code, value in required.items()):
        raise RuntimeError("DHCP options mismatch")
    return {
        "server_id": "gateway",
        "server_address": str(ipaddress.IPv4Address(options[54])),
        "address": str(ipaddress.IPv4Address(payload[16:20])),
        "lease_seconds": struct.unpack("!I", options[51])[0],
    }


def _parse_dns_reply(frame: bytes, query: bytes, source_port: int) -> dict[str, object]:
    reply = _udp_reply(frame)
    data = _expect_path(
        reply, gateway.GATEWAY_IP, gateway.LEASE_IP, 53, source_port)
    name, question_end = gateway.dns_name(data, 12)
    query_name, query_end = gateway.dns_name(query, 12)
    if (len(data) < question_end + 4 + 16 or data[:2] != query[:2] or
            data[2:4] != b"\x81\x80" or data[4:12] != b"\x00\x01\x00\x01\x00\x00\x00\x00" or
            name != query_name or name != gateway.DNS_NAME or
            data[question_end:question_end + 4] != query[query_end:query_end + 4]):
        raise RuntimeError("DNS response identity or question mismatch")
    answer = data[question_end + 4:]
    if (answer[:2] != b"\xc0\x0c" or answer[2:6] != b"\x00\x01\x00\x01" or
            answer[10:12] != b"\x00\x04" or len(answer) != 16):
        raise RuntimeError("DNS answer type or size mismatch")
    address = ipaddress.IPv4Address(answer[12:16])
    if address != gateway.GATEWAY_IP:
        raise RuntimeError("DNS answer address mismatch")
    return {"name": name, "type": "A", "address": str(address)}


def _parse_ntp_reply(
    frame: bytes, request: bytes, source_port: int,
) -> dict[str, object]:
    reply = _udp_reply(frame)
    data = _expect_path(reply, gateway.NTP_IP, gateway.LEASE_IP, 123, source_port)
    mode, stratum = data[0] & 7 if data else -1, data[1] if len(data) > 1 else 0
    if (len(data) != 48 or mode != 4 or not 1 <= stratum <= 15 or
            data[24:32] != request[40:48]):
        raise RuntimeError("NTP source, mode, stratum, or originate mismatch")
    return {"source": str(reply["source_ip"]), "mode": mode, "stratum": stratum}


def _parse_probe_reply(frame: bytes, source_port: int) -> bytes:
    reply = _udp_reply(frame)
    return _expect_path(
        reply, gateway.GATEWAY_IP, gateway.LEASE_IP,
        gateway.UDP_PROBE_PORT, source_port)


def run(port: int, transcript: Path) -> None:
    xid = secrets.token_bytes(4)
    events: list[dict[str, object]] = []

    def event(kind: str, **fields: object) -> None:
        events.append({"sequence": len(events) + 2, "kind": kind,
                       "actor": "client", **fields})

    with socket.create_connection(("127.0.0.1", port), timeout=5) as stream:
        event("DISCOVER")
        offer = _exchange(stream, _dhcp(xid, 1))
        offer_fields = _parse_dhcp_reply(offer, xid, 2)
        events.append({
            "sequence": len(events) + 2, "kind": "OFFER",
            "actor": "gateway", "recipient": "client",
            **offer_fields,
        })
        event("REQUEST", recipient="gateway")
        ack = _exchange(stream, _dhcp(xid, 3))
        ack_fields = _parse_dhcp_reply(ack, xid, 5)
        events.append({
            "sequence": len(events) + 2, "kind": "ACK",
            "actor": "gateway", "recipient": "client",
            **ack_fields,
        })

        dns_query = _dns_query()
        dns_fields = _parse_dns_reply(_exchange(
            stream, _udp_request(gateway.GATEWAY_IP, 40001, 53, dns_query)),
            dns_query, 40001)
        event("DNS_PASS", **dns_fields)

        ntp = bytearray(48)
        ntp[0] = 0x23
        ntp[40:48] = b"\x01\x02\x03\x04\x05\x06\x07\x08"
        ntp_fields = _parse_ntp_reply(_exchange(
            stream, _udp_request(gateway.NTP_IP, 40002, 123, bytes(ntp))),
            bytes(ntp), 40002)
        event("NTP_PASS", **ntp_fields)

        probe = _parse_probe_reply(_exchange(
            stream, _udp_request(
                gateway.GATEWAY_IP, 40003, gateway.UDP_PROBE_PORT, b"cycle")),
            40003)
        if probe != b"sim-ok:cycle":
            raise RuntimeError("connectivity probe failed")
        event("CONNECTIVITY_PASS", address=str(gateway.LEASE_IP))

    prior = transcript.read_text() if transcript.exists() else ""
    transcript.write_text(
        prior + "".join(json.dumps(item, sort_keys=True) + "\n"
                        for item in events))
