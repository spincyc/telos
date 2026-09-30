"""Tests for durable, private simulation evidence."""

import json
import stat
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from homelab.vm import artifact_scan, simulation_evidence
from homelab.vm.factory_verify import EVIDENCE_LIMIT
from homelab.vm.simulation_evidence import (
    RedactedLog, append_json_event, private_directory, private_file, redact,
    redact_and_bound, retain_redacted_logs, write_result,
    write_serial_events,
)


class SimulationEvidenceTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name) / "run"

    def assert_mode(self, path, expected):
        self.assertEqual(stat.S_IMODE(path.stat().st_mode), expected)

    def test_evidence_directory_and_files_are_private(self):
        private_directory(self.root)
        private_file(self.root / "gateway.log", b"ready\n")
        self.assert_mode(self.root, 0o700)
        self.assert_mode(self.root / "gateway.log", 0o600)

    def test_log_redacts_values_but_keeps_password_prompt(self):
        with RedactedLog(self.root / "serial.log") as stream:
            self.assertGreaterEqual(stream.fileno(), 0)
            stream.write(
                b"Password: \npassword=hunter2\nTOKEN: abc123\nlogin: ")
        content = (self.root / "serial.log").read_bytes()
        self.assertIn(b"Password: \n", content)
        self.assertIn(b"password=[REDACTED]", content)
        self.assertIn(b"TOKEN: [REDACTED]", content)
        self.assertIn(b"login: ", content)
        self.assertNotIn(b"hunter2", content)
        self.assertNotIn(b"abc123", content)

    def test_sudo_prompt_without_echoed_input_is_safe(self):
        output = b"[sudo] password for local-rescue: \r\nRESULT PASS\r\n"
        self.assertNotIn(b"[REDACTED]", redact(output))
        with RedactedLog(self.root / "serial.log") as stream:
            stream.write(output)
        self.assertEqual((self.root / "serial.log").read_bytes(), output)

    def test_result_is_private_and_machine_readable(self):
        target = write_result(
            self.root, status="pass", run_id="run-1",
            checks={"host_unchanged": True})
        document = json.loads(target.read_text())
        self.assertEqual(document["status"], "pass")
        self.assertTrue(document["checks"]["host_unchanged"])
        self.assert_mode(target, 0o600)

    def test_failure_result_redacts_secret_and_replaces_prior_result(self):
        write_result(self.root, status="pass", run_id="run-1")
        target = write_result(
            self.root, status="fail", run_id="run-1",
            error=RuntimeError("token: do-not-store"))
        content = target.read_text()
        self.assertNotIn("do-not-store", content)
        self.assertIn("[REDACTED]", content)
        self.assertEqual(json.loads(content)["status"], "fail")

    def test_serial_evidence_contains_no_console_or_input(self):
        target = write_serial_events(
            self.root, qemu_exit_code=0, helper_passed=True)
        document = json.loads(target.read_text())
        self.assertFalse(document["input_captured"])
        self.assertFalse(document["console_output_captured"])
        self.assertNotIn("password", target.read_text().lower())
        self.assert_mode(target, 0o600)

    def test_refuses_final_symlink_for_log_file(self):
        private_directory(self.root)
        outside = self.root.parent / "outside"
        outside.write_bytes(b"keep")
        (self.root / "serial.log").symlink_to(outside)
        with self.assertRaisesRegex(RuntimeError, "not a regular file"):
            private_file(self.root / "serial.log", b"replace")
        self.assertEqual(outside.read_bytes(), b"keep")

    def test_refuses_symlink_in_evidence_path(self):
        real = self.root.parent / "real"
        real.mkdir()
        self.root.symlink_to(real, target_is_directory=True)
        with self.assertRaisesRegex(RuntimeError, "contains a symlink"):
            private_file(self.root / "result.json", b"secret")
        self.assertEqual(list(real.iterdir()), [])

    def test_private_file_replacement_is_atomic(self):
        target = self.root / "result.json"
        private_file(target, b"old")
        old_inode = target.stat().st_ino
        private_file(target, b"new")
        self.assertNotEqual(old_inode, target.stat().st_ino)
        self.assertEqual(target.read_bytes(), b"new")
        self.assert_mode(target, 0o600)

    def test_json_event_append_is_private_and_rejects_symlink(self):
        target = self.root / "audit.jsonl"
        append_json_event(target, {"kind": "DISCOVER"})
        self.assertEqual(
            json.loads(target.read_text()), {"kind": "DISCOVER"})
        self.assert_mode(target, 0o600)
        target.unlink()
        outside = self.root.parent / "outside"
        outside.write_text("keep")
        target.symlink_to(outside)
        with self.assertRaisesRegex(RuntimeError, "not a regular file"):
            append_json_event(target, {"kind": "OFFER"})
        self.assertEqual(outside.read_text(), "keep")


#: A synthetic credential value: long enough to be a distinctive needle, and
#: shaped like nothing the instance-leak rules know.
SECRET = b"straddle-secret-7c1e9a0b5d3f"
ELISION = b"[telos evidence: "


def console(size: int) -> bytes:
    """Line-structured, multibyte console text of at least ``size`` bytes."""
    line = "boot step {:07d}: caf\u00e9 \u20ac \U0001f600 ok\n"
    lines, total, index = [], 0, 0
    while total < size:
        encoded = line.format(index).encode("utf-8")
        lines.append(encoded)
        total += len(encoded)
        index += 1
    return b"".join(lines)


def with_secret_at(data: bytes, offset: int) -> bytes:
    """Insert a whole secret line so its label starts at byte ``offset``."""
    start = data.rfind(b"\n", 0, offset) + 1
    pad = offset - start
    return (data[:start] + b"x" * pad + b"Password: " + SECRET + b"\n"
            + data[start:])


class BoundedRetainedLogTests(unittest.TestCase):
    """Every runner's retained serial log goes through ``redact_and_bound``."""

    def split(self, retained: bytes) -> tuple[bytes, bytes, bytes]:
        index = retained.index(ELISION)
        end = retained.index(b"\n", index) + 1
        return retained[:index], retained[index:end], retained[end:]

    def test_a_log_within_the_limit_is_exactly_what_redact_returns(self):
        # Byte-identical to the old ``redact(data[-4 MiB:])`` for every log
        # the old bound never cut; only the sizes record is new.
        for size in (0, 1, 4096, EVIDENCE_LIMIT - 64):
            data = console(size)[:size]
            data = with_secret_at(data, len(data) // 2) if size else data
            retained, sizes = redact_and_bound(data)
            self.assertEqual(retained, redact(data))
            self.assertNotIn(SECRET, retained)
            self.assertEqual(sizes, {
                "original_bytes": len(data), "retained_bytes": len(retained),
                "elided_bytes": 0})
        exact = console(EVIDENCE_LIMIT)[:EVIDENCE_LIMIT]
        self.assertEqual(redact_and_bound(exact)[0], exact)

    def test_an_over_limit_log_keeps_its_head_and_tail_around_one_elision(self):
        data = console(3 * EVIDENCE_LIMIT)
        retained, sizes = redact_and_bound(data)
        self.assertLessEqual(len(retained), EVIDENCE_LIMIT)
        # Both ends survive; the scanner can read the whole file as text.
        retained.decode("utf-8")
        head, marker, tail = self.split(retained)
        self.assertEqual(retained.count(ELISION), 1)
        self.assertTrue(data.startswith(head))
        self.assertTrue(data.endswith(tail))
        # Cut on line boundaries: whole lines only, on both sides.
        self.assertTrue(head.endswith(b"\n"))
        self.assertEqual(data[len(data) - len(tail) - 1:][:1], b"\n")
        # The head is the first quarter of the limit, the tail the rest.
        self.assertLessEqual(len(head), EVIDENCE_LIMIT // 4)
        self.assertGreater(len(head), EVIDENCE_LIMIT // 4 - 64)
        self.assertGreater(len(tail), EVIDENCE_LIMIT * 3 // 4 - 256)
        elided = len(data) - len(head) - len(tail)
        self.assertEqual(
            marker,
            b"[telos evidence: %d bytes elided here to bound this retained "
            b"log to %d bytes]\n" % (elided, EVIDENCE_LIMIT))
        self.assertEqual(sizes, {
            "original_bytes": len(data), "retained_bytes": len(retained),
            "elided_bytes": elided})

    def test_a_secret_straddling_either_cut_is_still_redacted_whole(self):
        # Slide one secret line through EVERY offset of a small over-limit
        # log, so it straddles the head cut and the tail cut at every
        # alignment.  The length never changes (the line overwrites filler),
        # so the cuts stay put while the secret moves across them.
        limit = 2048
        data = b"".join(
            b"boot step %07d: ok\n" % index for index in range(400))
        line = b"\nPassword: " + SECRET + b"\n"
        fragments = {SECRET[i:i + 6] for i in range(len(SECRET) - 5)}
        where = set()
        naive_leaked = False
        for offset in range(len(data) - len(line)):
            candidate = data[:offset] + line + data[offset + len(line):]
            retained, sizes = redact_and_bound(candidate, limit=limit)
            with self.subTest(offset=offset):
                self.assertLessEqual(len(retained), limit)
                self.assertGreater(sizes["elided_bytes"], 0)
                self.assertFalse(
                    [part for part in fragments if part in retained])
                # The label survives only whole, beside its redaction.
                self.assertEqual(
                    retained.count(b"assword"),
                    retained.count(b"\nPassword: [REDACTED]\n"))
            head, _, tail = self.split(retained)
            where.add(
                "head" if b"assword" in head
                else "tail" if b"assword" in tail else "elided")
            # The old order: a byte cut a fixed distance from the end, then
            # redaction of what the cut kept.
            naive_leaked |= SECRET in redact(candidate[-(limit * 3 // 4):])
        self.assertEqual(where, {"head", "elided", "tail"})
        self.assertTrue(naive_leaked, "the sweep never straddled a cut")

    def test_a_value_in_a_line_cut_mid_line_is_redacted_before_the_cut(self):
        # A line longer than its whole budget is the one place a cut lands
        # inside a line.  Redacting first replaces the value to the end of
        # its line before any cut.  The reverse order -- this very bound with
        # redaction deferred -- keeps ``assword: <value>`` once the tail cut
        # passes through the label, which the sweep below must reach.
        limit = 2048
        fragments = {SECRET[i:i + 6] for i in range(len(SECRET) - 5)}
        reversed_leaked = False
        for trailer in range(1300, 1500):
            candidate = (
                b"y" * 3000 + b"Password: " + SECRET + b"z" * trailer)
            retained, _ = redact_and_bound(candidate, limit=limit)
            with self.subTest(trailer=trailer):
                self.assertLessEqual(len(retained), limit)
                retained.decode("utf-8")
                self.assertFalse(
                    [part for part in fragments if part in retained])
                self.assertTrue(
                    retained.endswith(b"Password: [REDACTED]"))
            with mock.patch.object(
                    simulation_evidence, "redact", lambda data: data):
                deferred, _ = redact_and_bound(candidate, limit=limit)
            reversed_leaked |= any(
                part in redact(deferred) for part in fragments)
        self.assertTrue(reversed_leaked, "the sweep never cut the label")

    def test_a_line_longer_than_its_budget_is_cut_on_a_character(self):
        # No newline anywhere: the cut falls inside the line, but never
        # inside a UTF-8 sequence, and the elision stays on its own line.
        data = "\u20ac".encode("utf-8") * EVIDENCE_LIMIT
        retained, sizes = redact_and_bound(data)
        self.assertLessEqual(len(retained), EVIDENCE_LIMIT)
        text = retained.decode("utf-8")
        self.assertEqual(text.count("\n"), 2)
        head, marker, tail = self.split(retained)
        self.assertTrue(head.endswith(b"\n"))
        self.assertTrue(data.startswith(head[:-1]))
        self.assertTrue(data.endswith(tail))
        self.assertEqual(
            sizes["elided_bytes"], len(data) - (len(head) - 1) - len(tail))

    def test_a_limit_with_no_room_for_the_elision_is_refused(self):
        with self.assertRaisesRegex(ValueError, "too small"):
            redact_and_bound(b"x\n" * 400, limit=100)

    def test_retained_logs_are_private_sized_and_scan_clean(self):
        root = Path(self.enterContext(tempfile.TemporaryDirectory()))
        big = with_secret_at(console(2 * EVIDENCE_LIMIT), EVIDENCE_LIMIT)
        small = with_secret_at(console(8192), 4096)
        (root / "big.log").write_bytes(big)
        (root / "small.log").write_bytes(small)
        recorded = retain_redacted_logs(
            root, ("big.log", "small.log", "absent.log"))
        self.assertEqual(sorted(recorded), ["big.log", "small.log"])
        for name in ("big.log", "small.log"):
            path = root / name
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            self.assertEqual(
                recorded[name]["retained_bytes"], path.stat().st_size)
            self.assertLessEqual(path.stat().st_size, EVIDENCE_LIMIT)
        self.assertEqual((root / "small.log").read_bytes(), redact(small))
        self.assertEqual(recorded["small.log"]["elided_bytes"], 0)
        self.assertGreater(recorded["big.log"]["elided_bytes"], 0)
        self.assertEqual(recorded["big.log"]["original_bytes"], len(big))
        self.assertFalse((root / "absent.log").exists())
        scan = artifact_scan.scan_paths(
            root, ["big.log", "small.log"], known_secrets=[SECRET])
        self.assertEqual(scan.findings, ())
        self.assertEqual(set(scan.counters.values()), {0})


if __name__ == "__main__":
    unittest.main()
