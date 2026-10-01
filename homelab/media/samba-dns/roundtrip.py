#!/usr/bin/env python3
"""No-network NDR round trip checked by the pinned, unmodified c-ares library."""
import ctypes as c
import hashlib
import json
import sys
from pathlib import Path


class Blob(c.Structure):
    _fields_ = [("data", c.c_void_p), ("length", c.c_size_t)]


class Packet(c.Structure):
    _fields_ = [(name, c.c_uint16) for name in
                ("id", "operation", "qdcount", "ancount", "nscount", "arcount")] + [
                (name, c.c_void_p) for name in
                ("questions", "answers", "nsrecs", "additional")]


def main():
    dns_path, cares_path = sys.argv[1:]
    root = Path(__file__).resolve().parent
    ndr = c.CDLL("libndr.so.6")
    dns = c.CDLL(dns_path)
    talloc = c.CDLL("libtalloc.so.2")
    talloc.talloc_named_const.argtypes = [c.c_void_p, c.c_size_t, c.c_char_p]
    talloc.talloc_named_const.restype = c.c_void_p
    talloc._talloc_free.argtypes = [c.c_void_p, c.c_char_p]
    ndr.ndr_pull_struct_blob_all.argtypes = [c.POINTER(Blob), c.c_void_p, c.c_void_p, c.c_void_p]
    ndr.ndr_push_struct_blob.argtypes = [c.POINTER(Blob), c.c_void_p, c.c_void_p, c.c_void_p]
    cares = c.CDLL(cares_path)
    cares.ares_version.argtypes = [c.c_void_p]
    cares.ares_version.restype = c.c_char_p
    cares.ares_parse_srv_reply.argtypes = [c.c_void_p, c.c_int, c.POINTER(c.c_void_p)]
    cares.ares_free_data.argtypes = [c.c_void_p]
    expected = (root / "synthetic-srv-uncompressed.bin").read_bytes()
    results = []
    for kind in ("compressed", "uncompressed"):
        ctx = talloc.talloc_named_const(None, 0, b"srv serializer test")
        raw = (root / f"synthetic-srv-{kind}.bin").read_bytes()
        buffer = c.create_string_buffer(raw)
        source = Blob(c.cast(buffer, c.c_void_p), len(raw))
        output, packet = Blob(), Packet()
        pull = ndr.ndr_pull_struct_blob_all(c.byref(source), ctx, c.byref(packet), dns.ndr_pull_dns_name_packet)
        if pull:
            raise RuntimeError(f"NDR pull failed: {pull}")
        push = ndr.ndr_push_struct_blob(c.byref(output), ctx, c.byref(packet), dns.ndr_push_dns_name_packet)
        if push:
            raise RuntimeError(f"NDR push failed: {push}")
        emitted = c.string_at(output.data, output.length)
        srv = c.c_void_p()
        status = cares.ares_parse_srv_reply(output.data, output.length, c.byref(srv))
        if srv:
            cares.ares_free_data(srv)
        results.append({"input": kind, "ndr_pull": pull, "ndr_push": push,
                        "emitted_length": len(emitted), "emitted_sha256": hashlib.sha256(emitted).hexdigest(),
                        "matches_expected": emitted == expected, "ares_status": status})
        talloc._talloc_free(ctx, b"srv serializer test")
    print(json.dumps({"c_ares_version": cares.ares_version(None).decode(), "results": results}, sort_keys=True))


if __name__ == "__main__":
    main()
