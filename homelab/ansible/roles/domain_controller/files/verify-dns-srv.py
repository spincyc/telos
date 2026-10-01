#!/usr/bin/env python3
"""Check AD SRV wire responses over UDP and TCP, without printing site values.

RFC 2782 forbids compression in SRV Target; RFC 3597 retains that rule even
though DNS question and RR owner names may use compression. A resolver that
prints a target successfully is not evidence that strict clients can use it.
This standalone, stdlib-only guest check reports fixed categories and booleans.
It neither changes DNS nor joins a domain.
"""

from __future__ import annotations

import argparse
import json
import math
import queue
import re
import secrets
import socket
import struct
import threading
import time


HEADER = struct.Struct("!6H")
RR = struct.Struct("!HHIH")
SRV = 33
IN = 1
MAX_PACKET = 65535
MAX_NAME_STEPS = 256
HOST_LABEL = re.compile(rb"[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\Z")
SERVICES = {"ldap": "_ldap._tcp", "kerberos": "_kerberos._tcp"}


class DnsError(ValueError):
    """The message is a fixed category, never packet or runtime input text."""


def encode_name(name: str) -> bytes:
    try:
        labels = name.removesuffix(".").encode("ascii").split(b".")
    except (AttributeError, UnicodeError) as error:
        raise DnsError("arguments") from error
    if (not labels or any(not 1 <= len(label) <= 63 for label in labels)
            or any(not re.fullmatch(rb"[A-Za-z0-9_-]+", label)
                   for label in labels)):
        raise DnsError("arguments")
    wire = b"".join(bytes((len(label),)) + label for label in labels) + b"\0"
    if len(wire) > 255:
        raise DnsError("arguments")
    return wire


def read_name(packet: bytes, offset: int, *, end: int | None = None,
              compressed: bool = True) -> tuple[tuple[bytes, ...], int]:
    """Return expanded labels and the next wire offset, with bounded work.

    ``end`` confines an uncompressed RDATA name to its declared length. Owner
    and question pointers may leave their encoded name, but never the packet.
    """
    limit = len(packet) if end is None else end
    labels: list[bytes] = []
    visited: set[int] = set()
    next_offset = None
    expanded = 1  # terminal root label
    for _ in range(MAX_NAME_STEPS):
        if offset in visited:
            raise DnsError("dns-pointer")
        visited.add(offset)
        if not 0 <= offset < limit <= len(packet):
            raise DnsError("dns-length")
        length = packet[offset]
        if length & 0xC0 == 0xC0:
            if not compressed:
                raise DnsError("srv-target-compressed")
            if offset + 2 > limit:
                raise DnsError("dns-length")
            pointer = ((length & 0x3F) << 8) | packet[offset + 1]
            if not 12 <= pointer < len(packet):
                raise DnsError("dns-pointer")
            if next_offset is None:
                next_offset = offset + 2
            offset, limit = pointer, len(packet)
            continue
        if length & 0xC0:
            raise DnsError("dns-name")
        offset += 1
        if length == 0:
            return tuple(labels), offset if next_offset is None else next_offset
        if offset + length > limit:
            raise DnsError("dns-length")
        expanded += length + 1
        if expanded > 255:
            raise DnsError("dns-name")
        labels.append(packet[offset:offset + length].lower())
        offset += length
    raise DnsError("dns-pointer")


def make_query(question: str, transaction: int) -> bytes:
    return (HEADER.pack(transaction, 0x0100, 1, 0, 0, 0)
            + encode_name(question) + struct.pack("!HH", SRV, IN))


def validate_response(packet: bytes, transaction: int, question: str) -> bool:
    """Validate the whole DNS message; require a usable matching SRV answer.

    Unknown RDATA stays opaque, but every RR is bounded by its declared length
    and every SRV target, including additional records, is checked. Root Target
    denotes an unavailable service and cannot satisfy this availability check.
    """
    if not 12 <= len(packet) <= MAX_PACKET:
        raise DnsError("dns-length")
    ident, flags, questions, answers, authority, additional = HEADER.unpack_from(packet)
    if ident != transaction:
        raise DnsError("dns-transaction")
    if not flags & 0x8000 or flags & 0x7840:  # response, standard opcode, Z=0
        raise DnsError("dns-flags")
    if flags & 0x0200:
        raise DnsError("dns-truncated")
    if flags & 0x000F:
        raise DnsError("dns-rcode")
    if questions != 1:
        raise DnsError("dns-count")
    expected, _ = read_name(encode_name(question), 0)
    owner, offset = read_name(packet, 12)
    if offset + 4 > len(packet):
        raise DnsError("dns-length")
    if (owner != expected
            or struct.unpack_from("!HH", packet, offset) != (SRV, IN)):
        raise DnsError("dns-question")
    offset += 4
    records = answers + authority + additional
    # Even an empty-root owner plus a fixed RR header needs eleven bytes.
    if records > (len(packet) - offset) // 11:
        raise DnsError("dns-count")
    usable = False
    for index in range(records):
        owner, offset = read_name(packet, offset)
        if offset + RR.size > len(packet):
            raise DnsError("dns-length")
        kind, rrclass, ttl, length = RR.unpack_from(packet, offset)
        offset += RR.size
        end = offset + length
        if end > len(packet):
            raise DnsError("dns-length")
        if kind == SRV:
            if length < 7 or rrclass != IN:
                raise DnsError("srv-rdata")
            _, _, port = struct.unpack_from("!HHH", packet, offset)
            target, target_end = read_name(packet, offset + 6, end=end,
                                          compressed=False)
            if target_end != end:
                raise DnsError("srv-rdata")
            if any(not HOST_LABEL.fullmatch(label) for label in target):
                raise DnsError("srv-target")
            if index < answers and owner == expected:
                if not target or not port:
                    raise DnsError("srv-unavailable")
                usable = True
        elif kind == 41:  # EDNS carries the high eight response-code bits.
            if owner or index < answers + authority:
                raise DnsError("dns-flags")
            if ttl >> 24:
                raise DnsError("dns-rcode")
        offset = end
    if offset != len(packet):
        raise DnsError("dns-length")
    if not usable:
        raise DnsError("srv-answer-missing")
    return True


def resolve_server(server: str, timeout: float) -> tuple[int, tuple]:
    """Bound libc hostname resolution too; a blocked daemon cannot delay exit."""
    result: queue.Queue = queue.Queue(maxsize=1)

    def resolve() -> None:
        try:
            addresses = socket.getaddrinfo(server, 53, socket.AF_UNSPEC,
                                           socket.SOCK_DGRAM)
            result.put(addresses)
        except Exception:
            # Resolver exceptions can embed the private hostname.
            result.put(None)

    threading.Thread(target=resolve, daemon=True).start()
    try:
        addresses = result.get(timeout=timeout)
    except queue.Empty as error:
        raise DnsError("resolution-timeout") from error
    if addresses:
        for family, _, _, _, address in addresses:
            if family in (socket.AF_INET, socket.AF_INET6):
                return family, address
    raise DnsError("resolution-failed")


def remaining(deadline: float) -> float:
    seconds = deadline - time.monotonic()
    if seconds <= 0:
        raise DnsError("timeout")
    return seconds


def receive_exact(stream: socket.socket, length: int, deadline: float) -> bytes:
    chunks = bytearray()
    while len(chunks) < length:
        stream.settimeout(remaining(deadline))
        part = stream.recv(length - len(chunks))
        if not part:
            raise DnsError("transport-eof")
        chunks.extend(part)
    return bytes(chunks)


def query_srv(endpoint: tuple[int, tuple], question: str, transport: str,
              timeout: float) -> bool:
    if transport not in ("udp", "tcp"):
        raise DnsError("arguments")
    transaction = secrets.randbits(16)
    query = make_query(question, transaction)
    deadline = time.monotonic() + timeout
    family, address = endpoint
    kind = socket.SOCK_DGRAM if transport == "udp" else socket.SOCK_STREAM
    try:
        with socket.socket(family, kind) as stream:
            stream.settimeout(remaining(deadline))
            stream.connect(address)
            stream.settimeout(remaining(deadline))
            if transport == "udp":
                if stream.send(query) != len(query):
                    raise DnsError("transport-write")
                stream.settimeout(remaining(deadline))
                packet = stream.recv(MAX_PACKET + 1)
            else:
                stream.sendall(struct.pack("!H", len(query)) + query)
                length = struct.unpack("!H", receive_exact(stream, 2, deadline))[0]
                if length < HEADER.size:
                    raise DnsError("dns-length")
                packet = receive_exact(stream, length, deadline)
    except TimeoutError as error:
        raise DnsError("timeout") from error
    except OSError as error:
        raise DnsError("transport-error") from error
    return validate_response(packet, transaction, question)


def check(server: str, domain: str, timeout: float = 3.0) -> dict:
    if (not math.isfinite(timeout) or not 0 < timeout <= 30
            or not server or len(server) > 253
            or any(character.isspace() or ord(character) < 32 for character in server)):
        raise DnsError("arguments")
    domain_wire = encode_name(domain)
    domain_labels, _ = read_name(domain_wire, 0)
    if any(not HOST_LABEL.fullmatch(label) for label in domain_labels):
        raise DnsError("arguments")
    questions = {service: f"{prefix}.{domain.removesuffix('.')}"
                 for service, prefix in SERVICES.items()}
    for question in questions.values():
        encode_name(question)
    endpoint = resolve_server(server, timeout)
    checks = {}
    for service, question in questions.items():
        for transport in ("udp", "tcp"):
            try:
                query_srv(endpoint, question, transport, timeout)
                checks[f"{service}_{transport}"] = {"ok": True}
            except DnsError as error:
                checks[f"{service}_{transport}"] = {"ok": False, "error": str(error)}
    return {"ok": all(item["ok"] for item in checks.values()), "checks": checks}


class PrivateArgumentParser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        raise DnsError("arguments")


def main(argv: list[str] | None = None) -> int:
    parser = PrivateArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument("--server", required=True)
    parser.add_argument("--domain", required=True)
    parser.add_argument("--timeout", type=float, default=3.0,
                        help="seconds per resolution or transport (default 3; maximum 30)")
    try:
        args = parser.parse_args(argv)
        report = check(args.server, args.domain, args.timeout)
    except DnsError as error:
        report = {"ok": False, "error": str(error)}
    except Exception:
        # Never turn a host-specific exception into public output or a traceback.
        report = {"ok": False, "error": "internal-error"}
    print(json.dumps(report, sort_keys=True, separators=(",", ":")))
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
