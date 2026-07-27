"""Mocked lifecycle tests for the sequential loopback-only simulation."""

import json
import io
import signal
import threading
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from homelab.vm import simulated_topology as runner
from homelab.vm.serial_automation import SerialResult


class Process:
    next_pid = 4100

    def __init__(
        self, role, events, controller_output=None, wait_failure=None,
    ):
        self.role = role
        self.events = events
        self.running = True
        self.pid = self.next_pid
        self.stdout = (
            io.BytesIO(controller_output if controller_output is not None else (
                b"RESULT PASS: safe to proceed to the separately "
                b"authorized attachment step\r\n"))
            if role == "controller" else None)
        self.stdin = io.BytesIO() if role == "controller" else None
        Process.next_pid += 1
        self.wait_failure = wait_failure

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
        if self.wait_failure is not None:
            failure, self.wait_failure = self.wait_failure, None
            raise failure
        self.running = False
        return 0


class SimulationRunnerTests(unittest.TestCase):
    def run_cycle(
        self, acceptance=None, client_failure=None, compare_failure=None,
        controller_output=None, gateway_wait_failure=None, automated=False,
        signal_during_state_close=False,
    ):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        self.last_root = root
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
            return Process(
                role, events, controller_output,
                gateway_wait_failure if role == "gateway" else None,
            )

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

        automated_state = mock.MagicMock()
        automated_state.__enter__.return_value = automated_state
        automated_state.__exit__.return_value = None
        automated_state.disk = root / "controller.raw"
        automated_state.vars = root / "controller-vars.fd"
        automated_state.disk.write_bytes(b"raw")
        automated_state.vars.write_bytes(b"vars")
        if signal_during_state_close:
            automated_state.close.side_effect = (
                lambda: signal.raise_signal(signal.SIGTERM))

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
                    runner, "run_synthetic_client", side_effect=synthetic), \
                mock.patch.object(
                    runner, "DisposableBootDisk",
                    return_value=automated_state), \
                mock.patch.object(
                    runner, "AutomatedSerial") as serial:
            serial.return_value.run.return_value = SerialResult(
                True, 0, True, ("automated-proof",))
            result = runner.run(
                state, True, evidence_root=root / "evidence",
                acceptance=acceptance, automated=automated)
        return result, events, state

    def test_missing_manual_pass_fails_closed_and_cleans_up(self):
        with self.assertRaisesRegex(RuntimeError, "not observed"):
            self.run_cycle(controller_output=b"RESULT FAIL: unsafe\r\n")
        self.assertNotIn(("start", "client"), self.last_events)
        self.assertIn(("wait", "controller"), self.last_events)
        self.assertIn(("terminate", "gateway"), self.last_events)
        self.assertEqual(
            list(self.last_root.glob(
                "evidence/*/manual-verification.json")), [])

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

    def test_automated_mode_still_runs_client_and_provenance(self):
        result, events, _state = self.run_cycle(automated=True)
        self.assertEqual(result, 0)
        self.assertIn(("start", "client"), events)
        self.assertLess(
            events.index(("wait", "controller")),
            events.index(("start", "client")))
        serial = list(self.last_root.glob("evidence/*/serial-events.json"))
        self.assertEqual(len(serial), 1)
        self.assertIn("automated-proof", serial[0].read_text())

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
        transcripts = list(self.last_root.glob("evidence/*/transcript.jsonl"))
        self.assertEqual(len(transcripts), 1)
        self.assertIn('"POWEROFF"', transcripts[0].read_text())

    def test_operator_abort_cleans_up_without_creating_a_receipt(self):
        def abort(_plans, _processes):
            raise KeyboardInterrupt()

        with self.assertRaises(KeyboardInterrupt):
            self.run_cycle(acceptance=abort)
        self.assertIn(("terminate", "gateway"), self.last_events)
        self.assertIn(("terminate", "controller"), self.last_events)
        self.assertIn(("compare", "cycle"), self.last_events)
        self.assertEqual(
            list(self.last_root.glob(
                "evidence/*/manual-verification.json")), [])

    def test_repeated_signal_during_state_close_preserves_failure_result(self):
        def first_signal(_plans, _processes):
            signal.raise_signal(signal.SIGTERM)

        with self.assertRaises(runner.RunInterrupted):
            self.run_cycle(
                acceptance=first_signal,
                automated=True,
                signal_during_state_close=True)
        result_path = next(self.last_root.glob("evidence/*/result.json"))
        result = json.loads(result_path.read_text())
        self.assertEqual(result["status"], "fail")

    def test_gateway_timeout_fails_and_cleanup_still_completes(self):
        timeout = runner.subprocess.TimeoutExpired("gateway", 5)
        with self.assertRaises(runner.subprocess.TimeoutExpired):
            self.run_cycle(gateway_wait_failure=timeout)
        self.assertIn(("terminate", "gateway"), self.last_events)
        self.assertGreaterEqual(
            self.last_events.count(("wait", "gateway")), 2)
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

    def test_gateway_diagnostics_are_private_and_persistent(self):
        self.run_cycle()
        logs = list(self.last_root.glob("evidence/*/gateway.log"))
        self.assertEqual(len(logs), 1)
        self.assertEqual(logs[0].stat().st_mode & 0o777, 0o600)

    def test_success_writes_private_structured_result_and_serial_events(self):
        self.run_cycle()
        results = list(self.last_root.glob("evidence/*/result.json"))
        serial = list(self.last_root.glob("evidence/*/serial-events.json"))
        self.assertEqual(len(results), 1)
        self.assertEqual(len(serial), 1)
        result = json.loads(results[0].read_text())
        events = json.loads(serial[0].read_text())
        self.assertEqual(result["status"], "pass")
        self.assertTrue(result["checks"]["controller_preflight"])
        self.assertFalse(events["input_captured"])
        self.assertFalse(events["console_output_captured"])
        self.assertTrue(events["helper_passed"])
        self.assertEqual(results[0].stat().st_mode & 0o777, 0o600)
        self.assertEqual(serial[0].stat().st_mode & 0o777, 0o600)

    def test_failure_result_persists_without_secret_value(self):
        with self.assertRaisesRegex(RuntimeError, "token"):
            self.run_cycle(
                client_failure=RuntimeError("token: do-not-persist"))
        result_path = next(self.last_root.glob("evidence/*/result.json"))
        content = result_path.read_text()
        result = json.loads(content)
        self.assertEqual(result["status"], "fail")
        self.assertNotIn("do-not-persist", content)
        self.assertIn("[REDACTED]", result["error"]["message"])

    def test_client_timeout_is_bounded(self):
        release = threading.Event()

        def stalled(_port, _transcript):
            release.wait()

        with mock.patch.object(
                runner, "run_synthetic_client", side_effect=stalled):
            with self.assertRaises(runner.subprocess.TimeoutExpired):
                runner.run_client_bounded(
                    12345, Path("/unused"), timeout=0.01)
        release.set()

    def test_controller_timeout_terminates_guest(self):
        events = []

        class BlockingOutput:
            def read(self, _size):
                stopped.wait()
                return b""

        stopped = threading.Event()
        process = Process("controller", events)
        process.stdout = BlockingOutput()

        def terminate():
            events.append(("terminate", "controller"))
            process.running = False
            stopped.set()

        process.terminate = terminate
        with self.assertRaises(runner.subprocess.TimeoutExpired):
            runner.relay_controller_bounded(
                process, runner.SerialVerificationGate(), timeout=0.01)
        self.assertIn(("terminate", "controller"), events)


if __name__ == "__main__":
    unittest.main()
