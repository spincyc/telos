#!/usr/bin/env python3
"""Measure the isolated NTP path without changing the controller clock."""

from __future__ import annotations

import argparse
import json
import socket
import struct
import subprocess
import time

NTP_EPOCH = 2_208_988_800


def timestamp(value: float) -> bytes:
    seconds = int(value) + NTP_EPOCH
    fraction = int((value - int(value)) * (1 << 32))
    return struct.pack("!II", seconds, fraction)


def read_timestamp(value: bytes) -> float:
    seconds, fraction = struct.unpack("!II", value)
    return seconds - NTP_EPOCH + fraction / (1 << 32)


def request_packet(sent: float) -> bytes:
    packet = bytearray(48)
    packet[0] = 0x23  # NTPv4 client
    packet[40:48] = timestamp(sent)
    return bytes(packet)


def assess_response(
    packet: bytes, request: bytes, sent: float, received: float
) -> tuple[float, float, int]:
    if len(packet) != 48:
        raise ValueError("NTP response is not 48 bytes")
    if packet[0] & 0x7 != 4:
        raise ValueError("NTP response is not server mode")
    stratum = packet[1]
    if not 1 <= stratum <= 15:
        raise ValueError(f"NTP response has invalid stratum {stratum}")
    if packet[24:32] != request[40:48]:
        raise ValueError("NTP response does not echo the request timestamp")
    server_received = read_timestamp(packet[32:40])
    server_sent = read_timestamp(packet[40:48])
    offset = ((server_received - sent) + (server_sent - received)) / 2
    delay = (received - sent) - (server_sent - server_received)
    return offset, delay, stratum


def has_ntp_listener(text: str) -> bool:
    for line in text.splitlines():
        fields = line.split()
        # `ss` omits the Netid column when a protocol-specific filter is used,
        # so inspect the local endpoint rather than relying on a fixed column.
        if len(fields) >= 2 and fields[-2].rpartition(":")[2] == "123":
            return True
    return False


def query(server: str, timeout: float) -> dict[str, object]:
    sent = time.time()
    request = request_packet(sent)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
        client.settimeout(timeout)
        client.sendto(request, (server, 123))
        packet, peer = client.recvfrom(512)
    received = time.time()
    offset, delay, stratum = assess_response(packet, request, sent, received)
    return {
        "peer": peer[0],
        "offset_ms": offset * 1000,
        "delay_ms": delay * 1000,
        "stratum": stratum,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--server", required=True)
    parser.add_argument("--expected-peer", required=True)
    parser.add_argument("--max-offset-ms", type=float, default=1000)
    parser.add_argument("--timeout", type=float, default=2)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()

    failures = []
    try:
        result = query(args.server, args.timeout)
    except (OSError, ValueError) as error:
        result = {"error": str(error)}
        failures.append(f"NTP query failed: {error}")
    else:
        if result["peer"] != args.expected_peer:
            failures.append(
                f"NTP peer is {result['peer']}; expected {args.expected_peer}"
            )
        if abs(float(result["offset_ms"])) > args.max_offset_ms:
            failures.append(
                f"clock offset is {result['offset_ms']:.3f} ms; "
                f"limit is {args.max_offset_ms:.3f} ms"
            )

    sockets = subprocess.run(
        ("ss", "-H", "-n", "-lu"),
        check=False, text=True, stdout=subprocess.PIPE,
    )
    if sockets.returncode != 0:
        failures.append("could not inspect UDP listeners")
    elif has_ntp_listener(sockets.stdout):
        failures.append("controller is listening on UDP/123")

    result["ntp_authority"] = has_ntp_listener(sockets.stdout)
    result["passed"] = not failures
    if args.json:
        print(json.dumps(result, sort_keys=True))
    else:
        for failure in failures:
            print(f"FAIL {failure}")
        if not failures:
            print(
                f"PASS NTP peer {result['peer']}; "
                f"offset {result['offset_ms']:.3f} ms; "
                f"delay {result['delay_ms']:.3f} ms; "
                "no UDP/123 listener"
            )
    return int(bool(failures))


if __name__ == "__main__":
    raise SystemExit(main())
