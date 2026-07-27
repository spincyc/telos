"""Mocked lifecycle tests for the sequential loopback-only simulation."""

import json
import io
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from homelab.vm import simulated_topology as runner


class Process:
    next_pid = 4100

    def __init__(self, role, events, controller_output=None):
        self.role = role
        self.events = events
        self.running = True
        self.pid = self.next_pid
        self.stdout = (
            io.BytesIO(controller_output if controller_output is not None else (
                b"RESULT PASS: safe to proceed to the separately "
                b"authorized attachment step\r\n"))
            if role == "controller" else None)
        Process.next_pid += 1

    def poll(self):
        return None if self.running else 0

    def terminate(self):
        self.events.append(("terminate", self.role))
        self.running = False

    def kill(self):
        self.events.append(("kill", self.role))
        self.running = False

    def wait(self, timeout=None):
        self.events.append(("wait", self.role))
        self.running = False
        return 0


class SimulationRunnerTests(unittest.TestCase):
    def run_cycle(
        self, acceptance=None, client_failure=None, compare_failure=None,
        controller_output=None,
    ):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        state = root / "state"
        state.mkdir()
        (state / "bootstrap-dc.qcow2").write_bytes(b"canonical-disk")
        (state / "OVMF_VARS.fd").write_bytes(b"canonical-vars")
        firmware = root / "firmware-vars.fd"
        firmware.write_bytes(b"firmware")
        events = []

        def qemu_img(argv, **_kwargs):
            if argv[:2] == ["qemu-img", "create"]:
                events.append(("overlay", "prepare"))
                Path(argv[-1]).parent.mkdir(parents=True, exist_ok=True)
                Path(argv[-1]).write_bytes(b"overlay")
                return mock.Mock(returncode=0, stdout=b"", stderr=b"")
            if argv[:2] == ["qemu-img", "info"]:
                return mock.Mock(
                    returncode=0, stdout=b'{"format":"qcow2"}', stderr=b"")
            self.fail(f"unexpected subprocess invocation: {argv}")

        def start(argv, **_kwargs):
            role = (
                "gateway" if "simulated_gateway.py" in " ".join(argv)
                else "controller")
            events.append(("start", role))
            return Process(role, events, controller_output)

        def synthetic(_port, transcript):
            events.append(("start", "client"))
            if client_failure:
                raise client_failure
            prior = transcript.read_text()
            rows = [
                (2, "DISCOVER", "client", None),
                (3, "OFFER", "gateway", "gateway"),
                (4, "REQUEST", "client", None),
                (5, "ACK", "gateway", "gateway"),
                (6, "CONNECTIVITY_PASS", "client", None),
            ]
            with transcript.open("a") as stream:
                for sequence, kind, actor, server in rows:
                    item = {
                        "sequence": sequence, "kind": kind, "actor": actor,
                    }
                    if kind in {"OFFER", "ACK"}:
                        item.update(
                            recipient="client", server_id=server,
                            address="10.1.31.11")
                    if kind == "CONNECTIVITY_PASS":
                        item["address"] = "10.1.31.11"
                    stream.write(json.dumps(item) + "\n")
            self.assertIn('"POWEROFF"', prior)

        evidence = {"observations": []}
        self.last_events = events

        def capture_evidence():
            events.append(("capture", "network"))
            return evidence

        def compare_evidence(*_args, **_kwargs):
            events.append(("compare", "cycle"))
            if compare_failure:
                raise compare_failure
            return []

        with mock.patch.object(
                runner, "ovmf_pair", return_value=(firmware, firmware)), \
                mock.patch.object(
                    runner.shutil, "which", return_value="/usr/bin/qemu"), \
                mock.patch(
                    "homelab.vm.simulation_overlay.subprocess.run",
                    side_effect=qemu_img), \
                mock.patch(
                    "homelab.vm.simulation_overlay.canonical_disk_users",
                    return_value=[]), \
                mock.patch.object(runner.subprocess, "Popen", side_effect=start), \
                mock.patch.object(runner, "audit_live_process"), \
                mock.patch.object(runner.time, "sleep"), \
                mock.patch.object(
                    runner, "capture", side_effect=capture_evidence), \
                mock.patch.object(
                    runner, "compare_cycle", side_effect=compare_evidence), \
                mock.patch.object(
                    runner, "run_synthetic_client", side_effect=synthetic):
            result = runner.run(
                state, True, evidence_root=root / "evidence",
                acceptance=acceptance)
        return result, events, state

    def test_missing_manual_pass_fails_closed_and_cleans_up(self):
        with self.assertRaisesRegex(RuntimeError, "not observed"):
            self.run_cycle(controller_output=b"RESULT FAIL: unsafe\r\n")
        self.assertNotIn(("start", "client"), self.last_events)
        self.assertIn(("wait", "controller"), self.last_events)
        self.assertIn(("terminate", "gateway"), self.last_events)

    def test_sequence_is_gateway_controller_then_synthetic_client(self):
        result, events, _state = self.run_cycle()
        self.assertEqual(result, 0)
        lifecycle = [
            event for event in events
            if event[0] in {"overlay", "start", "wait"}
        ]
        self.assertEqual(lifecycle[:3], [
            ("overlay", "prepare"),
            ("start", "gateway"),
            ("start", "controller"),
        ])
        self.assertLess(
            events.index(("wait", "controller")),
            events.index(("start", "client")))

    def test_acceptance_sees_foreground_controller_and_gateway(self):
        def accept(plans, processes):
            self.assertIn("controller-overlay.qcow2",
                          " ".join(plans["controller"]))
            self.assertEqual(set(processes), {"gateway", "controller"})
            return 7

        result, _events, _state = self.run_cycle(acceptance=accept)
        self.assertEqual(result, 7)

    def test_client_failure_tears_down_and_preserves_canonical(self):
        with self.assertRaisesRegex(RuntimeError, "client failed"):
            self.run_cycle(client_failure=RuntimeError("client failed"))
        self.assertEqual(
            self.last_events.count(("capture", "network")), 3)
        self.assertIn(("compare", "cycle"), self.last_events)

    def test_primary_and_invariant_failures_are_both_preserved(self):
        with self.assertRaisesRegex(
                RuntimeError, "cleanup/invariant verification") as caught:
            self.run_cycle(
                client_failure=ValueError("primary client failure"),
                compare_failure=RuntimeError("after mismatch"))
        self.assertIsInstance(caught.exception.__cause__, ValueError)
        self.assertIn("primary client failure", str(caught.exception.__cause__))
        self.assertIn("after mismatch", str(caught.exception))

    def test_repeat_cycles_leave_canonical_disk_unchanged(self):
        canonical = []
        for _ in range(2):
            result, events, state = self.run_cycle()
            self.assertEqual(result, 0)
            self.assertIn(("overlay", "prepare"), events)
            canonical.append((state / "bootstrap-dc.qcow2").read_bytes())
        self.assertEqual(canonical, [b"canonical-disk", b"canonical-disk"])


if __name__ == "__main__":
    unittest.main()
