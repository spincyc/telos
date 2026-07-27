"""Tests for simulation host-network evidence and invariants."""

import copy
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from vm import host_network_evidence as evidence


def fixture(socket_lines: str = "") -> dict[str, object]:
    observations = []
    for command in evidence.COMMANDS:
        observations.append({
            "command": list(command),
            "returncode": 0,
            "stdout": socket_lines if command[0] == "ss" else "stable",
            "stderr": "",
        })
    return {"schema": 1, "captured_at": "ignored", "observations": observations}


class HostNetworkEvidenceTests(unittest.TestCase):
    def test_identical_snapshots_pass(self):
        self.assertEqual(evidence.compare(fixture(), fixture()), [])

    def test_in_memory_capture_tuple_commands_are_valid(self):
        captured = fixture()
        for item in captured["observations"]:
            item["command"] = tuple(item["command"])
        self.assertEqual(evidence.compare(captured, copy.deepcopy(captured)), [])

    def test_matching_failed_commands_do_not_pass(self):
        before = fixture()
        after = fixture()
        for snapshot in (before, after):
            snapshot["observations"][0]["returncode"] = 127
            snapshot["observations"][0]["stderr"] = "ip: command not found"
        violations = evidence.compare(before, after)
        self.assertTrue(any("command failed" in item for item in violations))

    def test_missing_required_command_does_not_pass(self):
        before = fixture()
        del before["observations"][0]
        violations = evidence.compare(before, fixture())
        self.assertTrue(any("missing command" in item for item in violations))

    def test_duplicate_command_does_not_pass(self):
        before = fixture()
        before["observations"].append(copy.deepcopy(before["observations"][0]))
        self.assertTrue(any(
            "duplicate commands" in item
            for item in evidence.compare(before, fixture())))

    def test_every_non_socket_surface_is_immutable(self):
        before = fixture()
        for index, command in enumerate(evidence.COMMANDS[:-1]):
            with self.subTest(command=command):
                after = copy.deepcopy(before)
                after["observations"][index]["stdout"] = "changed"
                self.assertTrue(evidence.compare(before, after))

    def test_permits_only_named_private_qemu_listeners_during_run(self):
        before = fixture()
        after = fixture(
            "tcp LISTEN 0 1 127.0.0.1:12971 0.0.0.0:* users:qemu\n"
            "tcp LISTEN 0 1 127.0.0.1:12972 0.0.0.0:* users:qemu")
        self.assertEqual(
            evidence.compare(
                before, after, allow_qemu_listeners=True,
                allowed_ports=frozenset({12971, 12972})), [])

    def test_requires_exact_dynamic_listener_set(self):
        before = fixture()
        during = fixture(
            "tcp LISTEN 0 1 127.0.0.1:43127 0.0.0.0:* users:python")
        self.assertEqual(evidence.compare(
            before, during, allow_qemu_listeners=True,
            allowed_ports=frozenset({43127})), [])
        violations = evidence.compare(
            before, during, allow_qemu_listeners=True,
            allowed_ports=frozenset({43127, 43128}))
        self.assertTrue(any("listener set did not match" in item
                            for item in violations))
        duplicate_port = fixture(
            "tcp LISTEN 0 1 127.0.0.1:43127 0.0.0.0:* users:python\n"
            "tcp LISTEN 0 1 [::ffff:127.0.0.1]:43127 [::]:* users:python")
        self.assertTrue(evidence.compare(
            before, duplicate_port, allow_qemu_listeners=True,
            allowed_ports=frozenset({43127})))

    def test_rejects_wildcard_wrong_port_and_udp(self):
        before = fixture()
        lines = (
            "tcp LISTEN 0 1 0.0.0.0:12971 0.0.0.0:*\n"
            "tcp LISTEN 0 1 127.0.0.1:12973 0.0.0.0:*\n"
            "udp UNCONN 0 0 127.0.0.1:12971 0.0.0.0:*")
        self.assertTrue(evidence.compare(
            before, fixture(lines), allow_qemu_listeners=True))

    def test_rejects_removed_preexisting_socket(self):
        before = fixture("tcp LISTEN 0 1 127.0.0.1:22 0.0.0.0:*")
        self.assertTrue(evidence.compare(
            before, fixture(), allow_qemu_listeners=True))

    def test_cycle_requires_complete_cleanup(self):
        before = fixture()
        during = fixture(
            "tcp LISTEN 0 1 127.0.0.1:12971 0.0.0.0:* users:qemu")
        ports = frozenset({12971})
        self.assertEqual(evidence.compare_cycle(
            before, during, fixture(), allowed_ports=ports), [])
        violations = evidence.compare_cycle(
            before, during, during, allowed_ports=ports)
        self.assertTrue(any(item.startswith("after simulation:") for item in violations))

    def test_written_evidence_is_private(self):
        with tempfile.TemporaryDirectory() as temp:
            target = Path(temp) / "evidence.json"
            evidence.write(fixture(), target)
            self.assertEqual(target.stat().st_mode & 0o777, 0o600)
            self.assertIn('"schema": 1', target.read_text())


if __name__ == "__main__":
    unittest.main()
