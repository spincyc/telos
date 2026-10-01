"""Hermetic DNS wire checks: packets and socket mocks, never lab state."""

import contextlib
import importlib.util
import io
import json
from pathlib import Path
import socket
import struct
import threading
import unittest
from unittest import mock


SOURCE = (Path(__file__).resolve().parents[1] / "ansible" / "roles"
          / "domain_controller" / "files" / "verify-dns-srv.py")
SPEC = importlib.util.spec_from_file_location("verify_dns_srv", SOURCE)
dns = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(dns)

QUESTION = "_ldap._tcp.example.test"
TRANSACTION = 0x1234
ENDPOINT = (socket.AF_INET, ("127.0.0.1", 53))


def name(text):
    """Construct fixtures independently of the production encoder/parser."""
    return b"".join(bytes((len(part),)) + part.encode("ascii")
                    for part in text.split(".")) + b"\0"


def pointer(offset):
    return struct.pack("!H", 0xC000 | offset)


def record(target=None, *, owner=b"\xc0\x0c", port=389, rrclass=1,
           length=None):
    if target is None:
        target = name("dc1.example.test")
    data = struct.pack("!HHH", 0, 100, port) + target
    return (owner + struct.pack("!HHIH", 33, rrclass, 60,
                                len(data) if length is None else length) + data)


def response(*, target=None, owner=b"\xc0\x0c", question=QUESTION,
             question_wire=None, flags=0x8180, transaction=TRANSACTION,
             counts=(1, 1, 0, 0), qtype=33, qclass=1, port=389,
             rrclass=1, length=None, extra=b""):
    encoded = name(question) if question_wire is None else question_wire
    return (struct.pack("!6H", transaction, flags, *counts)
            + encoded + struct.pack("!HH", qtype, qclass)
            + record(target, owner=owner, port=port, rrclass=rrclass,
                     length=length) + extra)


class PacketTests(unittest.TestCase):
    def validate(self, packet):
        return dns.validate_response(packet, TRANSACTION, QUESTION)

    def refuses(self, packet, category=None):
        with self.assertRaises(dns.DnsError) as caught:
            self.validate(packet)
        if category:
            self.assertEqual(str(caught.exception), category)

    def test_equivalent_srv_target_compression_is_the_only_difference(self):
        # Offset 23 is "example.test" in the LDAP question. A permissive
        # decoder sees identical targets; strict SRV clients must reject one.
        plain = response(target=name("dc1.example.test"))
        compressed = response(target=b"\x03dc1" + pointer(23))
        target_offset = 12 + len(name(QUESTION)) + 4 + 2 + 10 + 6
        plain_name, _ = dns.read_name(plain, target_offset)
        compressed_name, _ = dns.read_name(compressed, target_offset)
        self.assertEqual(plain_name, compressed_name)
        self.assertTrue(self.validate(plain))
        self.refuses(compressed, "srv-target-compressed")

    def test_compressed_and_uncompressed_rr_owners_are_valid(self):
        self.assertTrue(self.validate(response()))
        self.assertTrue(self.validate(response(owner=name(QUESTION))))

    def test_compressed_question_is_decoded_and_matched(self):
        # The encoded question points at the full owner following QTYPE/QCLASS.
        packet = response(question_wire=pointer(18), owner=name(QUESTION))
        self.assertTrue(self.validate(packet))

    def test_case_insensitive_question_match(self):
        self.assertTrue(self.validate(response(question=QUESTION.upper())))

    def test_kerberos_srv_has_the_same_target_rule(self):
        question = "_kerberos._tcp.example.test"
        plain = response(question=question, port=88)
        compressed = response(question=question, port=88,
                              target=b"\x03dc1" + pointer(27))
        self.assertTrue(dns.validate_response(plain, TRANSACTION, question))
        with self.assertRaisesRegex(dns.DnsError, "^srv-target-compressed$"):
            dns.validate_response(compressed, TRANSACTION, question)

    def test_all_srv_targets_are_checked_even_after_a_good_answer(self):
        packet = response(counts=(1, 1, 0, 1),
                          extra=record(b"\x03dc1" + pointer(23)))
        self.refuses(packet, "srv-target-compressed")

    def test_unknown_additional_rdata_is_bounded_but_opaque(self):
        additional = (name("dc1.example.test")
                      + struct.pack("!HHIH", 1, 1, 60, 4) + b"\x7f\0\0\1")
        self.assertTrue(self.validate(response(counts=(1, 1, 0, 1),
                                              extra=additional)))

    def test_response_transaction_flags_rcode_and_question(self):
        bad = [
            ({"transaction": 7}, "dns-transaction"),
            ({"flags": 0x0180}, "dns-flags"),  # QR unset
            ({"flags": 0x8980}, "dns-flags"),  # unsupported opcode
            ({"flags": 0x81C0}, "dns-flags"),  # reserved Z bit
            ({"flags": 0x8380}, "dns-truncated"),
            ({"flags": 0x8183}, "dns-rcode"),
            ({"question": "_ldap._tcp.other.test"}, "dns-question"),
            ({"qtype": 1}, "dns-question"),
            ({"qclass": 3}, "dns-question"),
        ]
        for changes, category in bad:
            with self.subTest(changes=changes):
                self.refuses(response(**changes), category)

    def test_edns_extended_failure_is_not_treated_as_noerror(self):
        opt = b"\0" + struct.pack("!HHIH", 41, 1232, 1 << 24, 0)
        self.refuses(response(counts=(1, 1, 0, 1), extra=opt), "dns-rcode")

    def test_every_truncated_prefix_fails_closed(self):
        packet = response()
        for cut in range(len(packet)):
            with self.subTest(cut=cut):
                self.refuses(packet[:cut])

    def test_count_mismatches_and_trailing_data_fail_closed(self):
        for counts in ((0, 1, 0, 0), (2, 1, 0, 0), (1, 0, 0, 0),
                       (1, 2, 0, 0), (1, 1, 1, 0), (1, 1, 0, 1),
                       (1, 65535, 65535, 65535)):
            with self.subTest(counts=counts):
                self.refuses(response(counts=counts))
        self.refuses(response() + b"\0", "dns-length")

    def test_rdata_length_must_match_the_whole_target(self):
        actual = 6 + len(name("dc1.example.test"))
        for declared in (0, 6, actual - 1, actual + 1, 65535):
            with self.subTest(length=declared):
                self.refuses(response(length=declared))
        self.refuses(response(target=name("dc1.example.test") + b"\0"),
                     "srv-rdata")

    def test_pointer_cycles_and_out_of_range_are_rejected(self):
        answer_offset = 12 + len(name(QUESTION)) + 4
        self.refuses(response(owner=pointer(answer_offset)), "dns-pointer")
        self.refuses(response(owner=pointer(16383)), "dns-pointer")
        self.refuses(response(owner=pointer(0)), "dns-pointer")
        self.refuses(response(question_wire=pointer(12)), "dns-pointer")
        cyclic = b"\0" * 12 + pointer(14) + pointer(12)
        with self.assertRaisesRegex(dns.DnsError, "^dns-pointer$"):
            dns.read_name(cyclic, 12)

    def test_pointer_walk_has_a_budget_even_without_a_cycle(self):
        chain = b"\0" * 12 + b"".join(
            pointer(offset + 2) for offset in range(12, 612, 2)) + b"\0"
        with self.assertRaisesRegex(dns.DnsError, "^dns-pointer$"):
            dns.read_name(chain, 12)

    def test_truncated_pointer_and_illegal_label_forms_are_rejected(self):
        with self.assertRaisesRegex(dns.DnsError, "^dns-length$"):
            dns.read_name(b"\0" * 12 + b"\xc0", 12)
        for target in (b"\x40\0", b"\x80\0", b"\x04bad!\0",
                       b"\x04-bad\0", b"\x02\xff\xfe\0",
                       (b"\x3f" + b"a" * 63) * 4 + b"\0"):
            with self.subTest(target=target):
                self.refuses(response(target=target))

    def test_response_must_have_a_usable_matching_in_srv_answer(self):
        self.refuses(response(target=b"\0"), "srv-unavailable")
        self.refuses(response(port=0), "srv-unavailable")
        self.refuses(response(rrclass=3), "srv-rdata")
        self.refuses(response(owner=name("_ldap._tcp.other.test")),
                     "srv-answer-missing")
        # Correct SRV data solely in the additional section is not an answer.
        self.refuses(response(counts=(1, 0, 0, 1)), "srv-answer-missing")
        empty = struct.pack("!6H", TRANSACTION, 0x8180, 1, 0, 0, 0)
        empty += name(QUESTION) + struct.pack("!HH", 33, 1)
        self.refuses(empty, "srv-answer-missing")


class FakeSocket:
    """An in-memory peer; no OS socket or DNS resolver is opened."""

    def __init__(self, kind, *, flags=0x8180, fail=None, fragment=False):
        self.kind, self.flags, self.fail = kind, flags, fail
        self.fragment = fragment
        self.timeouts = []
        self.received = b""
        self.sent = b""
        self.closed = False

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.closed = True

    def settimeout(self, seconds):
        self.timeouts.append(seconds)

    def connect(self, address):
        self.address = address

    def prepare_response(self, query):
        transaction = struct.unpack_from("!H", query)[0]
        packet = (struct.pack("!6H", transaction, self.flags, 1, 1, 0, 0)
                  + query[12:] + record())
        self.received = (struct.pack("!H", len(packet)) + packet
                         if self.kind == socket.SOCK_STREAM else packet)

    def send(self, query):
        self.sent = query
        self.prepare_response(query)
        return len(query)

    def sendall(self, framed):
        self.sent = framed
        if struct.unpack_from("!H", framed)[0] != len(framed) - 2:
            raise AssertionError("incorrect TCP query length")
        self.prepare_response(framed[2:])

    def recv(self, size):
        if self.fail:
            raise self.fail
        if self.fragment:
            size = min(size, 1)
        result, self.received = self.received[:size], self.received[size:]
        return result


class TransportTests(unittest.TestCase):
    def test_both_services_use_udp_and_tcp_and_close_each_socket(self):
        sockets = []

        def create(family, kind):
            self.assertEqual(family, socket.AF_INET)
            stream = FakeSocket(kind, fragment=(kind == socket.SOCK_STREAM))
            sockets.append(stream)
            return stream

        with mock.patch.object(dns, "resolve_server", return_value=ENDPOINT), \
                mock.patch.object(dns.socket, "socket", side_effect=create):
            result = dns.check("dc.example.test", "example.test", timeout=0.5)
        self.assertTrue(result["ok"])
        self.assertEqual(set(result["checks"]),
                         {"ldap_udp", "ldap_tcp", "kerberos_udp", "kerberos_tcp"})
        self.assertEqual([stream.kind for stream in sockets],
                         [socket.SOCK_DGRAM, socket.SOCK_STREAM] * 2)
        self.assertTrue(all(stream.closed for stream in sockets))
        for stream in sockets:
            self.assertTrue(all(0 < value <= 0.5 for value in stream.timeouts))
        self.assertIn(name("_ldap._tcp.example.test"), sockets[0].sent)
        self.assertIn(name("_kerberos._tcp.example.test"), sockets[2].sent)

    def test_truncated_udp_cannot_be_hidden_by_a_passing_tcp_query(self):
        def create(family, kind):
            return FakeSocket(kind, flags=0x8380 if kind == socket.SOCK_DGRAM
                              else 0x8180)

        with mock.patch.object(dns, "resolve_server", return_value=ENDPOINT), \
                mock.patch.object(dns.socket, "socket", side_effect=create):
            result = dns.check("dc.example.test", "example.test")
        self.assertFalse(result["ok"])
        for service in ("ldap", "kerberos"):
            self.assertEqual(result["checks"][service + "_udp"]["error"],
                             "dns-truncated")
            self.assertTrue(result["checks"][service + "_tcp"]["ok"])

    def test_udp_and_tcp_timeouts_are_fixed_categories_and_close_sockets(self):
        for transport, kind in (("udp", socket.SOCK_DGRAM),
                                ("tcp", socket.SOCK_STREAM)):
            with self.subTest(transport=transport):
                stream = FakeSocket(kind, fail=TimeoutError("private server"))
                with mock.patch.object(dns.socket, "socket", return_value=stream):
                    with self.assertRaisesRegex(dns.DnsError, "^timeout$"):
                        dns.query_srv(ENDPOINT, QUESTION, transport, 0.1)
                self.assertTrue(stream.closed)

    def test_tcp_partial_reads_share_one_deadline(self):
        stream = FakeSocket(socket.SOCK_STREAM, fragment=True)
        stream.received = b"\0\x20"
        with mock.patch.object(dns.time, "monotonic", side_effect=[1.0, 4.0]):
            with self.assertRaisesRegex(dns.DnsError, "^timeout$"):
                dns.receive_exact(stream, 2, deadline=3.0)
        self.assertEqual(stream.timeouts, [2.0])

    def test_tcp_early_eof_and_invalid_frame_length_fail_closed(self):
        stream = FakeSocket(socket.SOCK_STREAM)
        with self.assertRaisesRegex(dns.DnsError, "^transport-eof$"):
            dns.receive_exact(stream, 2, deadline=dns.time.monotonic() + 1)
        with mock.patch.object(stream, "prepare_response"):
            stream.received = b"\0\x05abcde"
            with mock.patch.object(dns.socket, "socket", return_value=stream):
                with self.assertRaisesRegex(dns.DnsError, "^dns-length$"):
                    dns.query_srv(ENDPOINT, QUESTION, "tcp", 0.1)

    def test_short_udp_write_and_io_error_fail_closed(self):
        stream = FakeSocket(socket.SOCK_DGRAM)
        with mock.patch.object(stream, "send", return_value=1), \
                mock.patch.object(dns.socket, "socket", return_value=stream):
            with self.assertRaisesRegex(dns.DnsError, "^transport-write$"):
                dns.query_srv(ENDPOINT, QUESTION, "udp", 0.1)
        with mock.patch.object(dns.socket, "socket",
                               side_effect=OSError("private endpoint")):
            with self.assertRaisesRegex(dns.DnsError, "^transport-error$"):
                dns.query_srv(ENDPOINT, QUESTION, "tcp", 0.1)

    def test_hostname_resolution_is_bounded_without_live_dns(self):
        release = threading.Event()
        finished = threading.Event()

        def stalled(*args):
            try:
                release.wait(1)
                return []
            finally:
                finished.set()

        try:
            with mock.patch.object(dns.socket, "getaddrinfo", side_effect=stalled):
                with self.assertRaisesRegex(dns.DnsError, "^resolution-timeout$"):
                    dns.resolve_server("dc.example.test", 0.01)
        finally:
            release.set()
            self.assertTrue(finished.wait(1))

    def test_resolution_success_failure_and_empty_result(self):
        result = [(socket.AF_INET, socket.SOCK_DGRAM, 17, "", ENDPOINT[1])]
        with mock.patch.object(dns.socket, "getaddrinfo", return_value=result):
            self.assertEqual(dns.resolve_server("dc.example.test", 1), ENDPOINT)
        for options in ({"return_value": []},
                        {"side_effect": OSError("private server")}):
            with mock.patch.object(dns.socket, "getaddrinfo", **options):
                with self.assertRaisesRegex(dns.DnsError, "^resolution-failed$"):
                    dns.resolve_server("dc.example.test", 1)


class OutputTests(unittest.TestCase):
    def run_main(self, args):
        stdout, stderr = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            code = dns.main(args)
        self.assertEqual(stderr.getvalue(), "")
        return code, json.loads(stdout.getvalue()), stdout.getvalue()

    def test_argument_errors_never_echo_private_values(self):
        cases = [
            ["--server", "private.invalid", "--domain", "private.invalid",
             "--timeout", "private-timeout"],
            ["--private-option", "private-value"],
            ["--server", "private.invalid"],
        ]
        with mock.patch.object(dns, "resolve_server") as resolver:
            for args in cases:
                with self.subTest(args=args):
                    code, report, output = self.run_main(args)
                    self.assertEqual(code, 1)
                    self.assertEqual(report, {"ok": False, "error": "arguments"})
                    self.assertNotIn("private", output)
            resolver.assert_not_called()

    def test_invalid_domain_and_deadline_values_fail_before_network(self):
        with mock.patch.object(dns, "resolve_server") as resolver:
            for domain in ("", ".", "example..test", "example.test..",
                           "bad_label.test", "-bad.test", "\N{SNOWMAN}.test",
                           "x" * 64 + ".test", ".".join(["x" * 63] * 4)):
                with self.subTest(domain=domain):
                    with self.assertRaisesRegex(dns.DnsError, "^arguments$"):
                        dns.check("dc.example.test", domain)
            for timeout in (0, -1, float("nan"), float("inf"), 31):
                with self.subTest(timeout=timeout):
                    with self.assertRaisesRegex(dns.DnsError, "^arguments$"):
                        dns.check("dc.example.test", "example.test", timeout)
            resolver.assert_not_called()

    def test_success_and_failure_outputs_expose_only_fixed_fields(self):
        with mock.patch.object(dns, "resolve_server", return_value=ENDPOINT), \
                mock.patch.object(dns, "query_srv", return_value=True):
            code, report, output = self.run_main([
                "--server", "sensitive.example", "--domain", "private.test"])
        self.assertEqual(code, 0)
        self.assertTrue(report["ok"])
        self.assertNotIn("sensitive", output)
        self.assertNotIn("private", output)
        with mock.patch.object(dns, "resolve_server", return_value=ENDPOINT), \
                mock.patch.object(dns, "query_srv", side_effect=dns.DnsError("timeout")):
            code, report, output = self.run_main([
                "--server", "sensitive.example", "--domain", "private.test"])
        self.assertEqual(code, 1)
        self.assertFalse(report["ok"])
        self.assertEqual(len(report["checks"]), 4)
        self.assertNotIn("sensitive", output)
        self.assertNotIn("private", output)

    def test_unexpected_errors_do_not_print_tracebacks_or_inputs(self):
        with mock.patch.object(dns, "check", side_effect=RuntimeError("private-value")):
            code, report, output = self.run_main([
                "--server", "sensitive.example", "--domain", "private.test"])
        self.assertEqual(code, 1)
        self.assertEqual(report, {"ok": False, "error": "internal-error"})
        self.assertNotIn("private", output)


if __name__ == "__main__":
    unittest.main()
