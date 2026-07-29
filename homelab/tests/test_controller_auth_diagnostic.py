import unittest
from unittest import mock
import re
import base64
import tempfile
import json
import os
from pathlib import Path

from homelab.vm import controller_auth_diagnostic as subject
from homelab.vm.controller_auth_diagnostic import (
    ControllerAuthCode,
    ControllerAuthCollection,
    ControllerAuthExpectation,
    ControllerAuthResult,
    ControllerAuthDiagnosticSession,
    ControllerAuthDiagnosticError,
    classify_auth_events,
    supplemental_only,
    _complete_json_records,
    _observation_complete,
)
from homelab.vm.windows_identity_run import IdentityFailureDiagnostic
from homelab.vm.windows_join_iso import WindowsJoinFailureCoordinate


class ControllerAuthDiagnosticTests(unittest.TestCase):
    def setUp(self):
        self.expected = ControllerAuthExpectation(
            "operator", "FACTORY", "10.1.31.11",
            "S-1-5-21-1-2-3-1104",
        )

    def event(self, **changes):
        event = {
            "type": "Authentication",
            "account": "operator",
            "domain": "FACTORY",
            "remoteAddress": "ipv4:10.1.31.11:49152",
            "serviceDescription": "KDC",
            "authDescription": "Kerberos",
            "status": "NT_STATUS_OK",
            "sid": "S-1-5-21-1-2-3-1104",
        }
        event.update(changes)
        return event

    def test_exact_success_requires_runtime_sid(self):
        self.assertEqual(
            classify_auth_events((self.event(),), self.expected),
            ControllerAuthCode.AUTHENTICATED,
        )
        self.assertEqual(
            classify_auth_events(
                (self.event(sid="S-1-5-21-1-2-3-9999"),), self.expected),
            ControllerAuthCode.UNCORRELATED,
        )

    def test_rejection_is_closed_and_ambiguous_fails_closed(self):
        rejected = self.event(status="NT_STATUS_WRONG_PASSWORD", sid=None)
        self.assertEqual(
            classify_auth_events((rejected,), self.expected),
            ControllerAuthCode.REJECTED,
        )
        self.assertEqual(
            classify_auth_events((rejected, rejected), self.expected),
            ControllerAuthCode.AMBIGUOUS,
        )

    def test_untrusted_service_and_source_do_not_correlate(self):
        self.assertEqual(
            classify_auth_events(
                (self.event(serviceDescription="smbd"),), self.expected),
            ControllerAuthCode.UNCORRELATED,
        )
        authorization = self.event(type="Authorization")
        self.assertEqual(
            classify_auth_events((authorization,), self.expected),
            ControllerAuthCode.UNCORRELATED,
        )
        self.assertEqual(
            classify_auth_events(
                (self.event(remoteAddress="ipv4:10.1.31.4:1"),),
                self.expected),
            ControllerAuthCode.UNCORRELATED,
        )

    def test_gui_result_is_only_authority(self):
        success = ControllerAuthResult(code=ControllerAuthCode.AUTHENTICATED)
        failure = ControllerAuthResult(
            collection=ControllerAuthCollection.MALFORMED)
        self.assertFalse(supplemental_only(False, success))
        self.assertTrue(supplemental_only(True, failure))

    def test_primary_coordinate_is_exclusive(self):
        with self.assertRaises(ValueError):
            ControllerAuthResult()
        with self.assertRaises(ValueError):
            ControllerAuthResult(
                code=ControllerAuthCode.NO_EVENT,
                collection=ControllerAuthCollection.ROTATED,
            )

    def test_serial_session_returns_only_closed_coordinates(self):
        console = mock.Mock(password=None)
        console._wait.side_effect = [
            mock.Mock(), mock.Mock(),
            re.match(rb"(code|collection):([a-z-]+)", b"code:authenticated"),
            re.match(rb"(ok|absence-unproved)", b"ok"),
        ]
        session = ControllerAuthDiagnosticSession(console, self.expected)
        session.arm()
        result = session.submitted()
        self.assertEqual(result.code, ControllerAuthCode.AUTHENTICATED)
        self.assertIsNone(result.cleanup)
        self.assertTrue(
            all(
                b"Synthetic-" not in call.args[0]
                for call in console._send.call_args_list
            )
        )

    def test_serial_cancellation_reports_cleanup_failure(self):
        console = mock.Mock(password=None)
        console._wait.side_effect = [
            mock.Mock(), mock.Mock(), mock.Mock(),
            re.match(rb"(ok|absence-unproved)", b"absence-unproved"),
        ]
        session = ControllerAuthDiagnosticSession(console, self.expected)
        session.arm()
        result = session.cancel()
        self.assertEqual(
            result.collection, ControllerAuthCollection.CANCELLED)
        self.assertIsNotNone(result.cleanup)

    def test_serial_uses_one_immutable_deadline(self):
        now = [0.0]
        observed = []
        console = mock.Mock(password=None, timeout=99.0)

        def waited(*_args):
            observed.append(console.timeout)
            now[0] += 2.0
            return mock.Mock()

        console._wait.side_effect = waited
        session = ControllerAuthDiagnosticSession(
            console, self.expected, timeout=10, clock=lambda: now[0])
        session.arm()
        self.assertEqual(observed, [10.0, 8.0])
        self.assertEqual(console.timeout, 99.0)

    def test_partial_arm_failure_proves_cleanup_before_reporting(self):
        console = mock.Mock(password=None, timeout=99.0)
        console._wait.side_effect = [
            mock.Mock(),
            RuntimeError("armed receipt unavailable"),
            re.match(rb"(ok|absence-unproved)", b"ok"),
        ]
        session = ControllerAuthDiagnosticSession(
            console, self.expected, timeout=10, clock=lambda: 0)
        with self.assertRaises(ControllerAuthDiagnosticError) as caught:
            session.arm()
        self.assertTrue(caught.exception.cleanup_proved)
        self.assertIn(
            "controller-auth-abort-sent",
            [call.args[1] for call in console._send.call_args_list],
        )

    def test_gui_failure_metadata_stays_typed_and_secret_free(self):
        result = ControllerAuthResult(code=ControllerAuthCode.AUTHENTICATED)
        coordinate = WindowsJoinFailureCoordinate(
            "reboot-reauth-desktop",
            "WindowsLocalReauthenticationError",
            controller_auth=result,
        )
        diagnostic = IdentityFailureDiagnostic.join_guest(
            coordinate.phase,
            coordinate.error_type,
            controller_auth=coordinate.controller_auth,
        )
        self.assertIn("controller-auth=authenticated", diagnostic.render())
        self.assertNotIn("operator", diagnostic.render())
        self.assertFalse(supplemental_only(False, result))

    def test_partial_jsonl_tail_waits_until_complete_or_deadline(self):
        first = json.dumps({"type": "noise"}).encode() + b"\n"
        parsed, partial = _complete_json_records(
            first + b'{"type":"Authentication"', deadline_reached=False)
        self.assertEqual(parsed, ({"type": "noise"},))
        self.assertTrue(partial)
        with self.assertRaises(ValueError):
            _complete_json_records(
                first + b'{"type":"Authentication"',
                deadline_reached=True)

    def test_correlation_waits_for_quiet_tail_and_detects_ambiguity(self):
        success = self.event()
        failure = self.event(
            status="NT_STATUS_WRONG_PASSWORD", sid=None)
        first = classify_auth_events((success,), self.expected)
        self.assertFalse(_observation_complete(
            first, partial=False, now=1.1,
            last_size_change=1.0, deadline=30.0))
        self.assertFalse(_observation_complete(
            first, partial=True, now=2.0,
            last_size_change=1.0, deadline=30.0))
        second = classify_auth_events((success, failure), self.expected)
        self.assertEqual(second, ControllerAuthCode.AMBIGUOUS)
        self.assertTrue(_observation_complete(
            second, partial=False, now=2.0,
            last_size_change=1.0, deadline=30.0))

    def test_malformed_payload_still_disables_route(self):
        encoded = base64.b64encode(b"{}").decode()
        with mock.patch.object(
                subject, "_disable_and_destroy_sink",
                return_value=False) as cleanup:
            self.assertEqual(subject._controller_session(encoded), 2)
        cleanup.assert_called_once_with(None, None)

    def test_cleanup_never_unlinks_hardlink_or_replacement(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            path = root / "auth.jsonl"
            path.write_bytes(b"")
            hardlink = root / "other"
            os.link(path, hardlink)
            descriptor = os.open(path, os.O_RDONLY)
            info = os.fstat(descriptor)
            completed = mock.Mock(returncode=0, stdout="debug level 0\n")
            with (
                mock.patch.object(subject, "AUDIT_PATH", str(path)),
                mock.patch.object(
                    subject.subprocess, "run", return_value=completed),
            ):
                self.assertFalse(subject._disable_and_destroy_sink(
                    descriptor, (info.st_dev, info.st_ino)))
            self.assertTrue(path.exists())

            hardlink.unlink()
            descriptor = os.open(path, os.O_RDONLY)
            info = os.fstat(descriptor)
            path.unlink()
            path.write_bytes(b"replacement")
            with (
                mock.patch.object(subject, "AUDIT_PATH", str(path)),
                mock.patch.object(
                    subject.subprocess, "run", return_value=completed),
            ):
                self.assertFalse(subject._disable_and_destroy_sink(
                    descriptor, (info.st_dev, info.st_ino)))
            self.assertEqual(path.read_bytes(), b"replacement")

    def test_cleanup_restores_replacement_racing_quarantine(self):
        with tempfile.TemporaryDirectory() as name:
            path = Path(name) / "auth.jsonl"
            path.write_bytes(b"original")
            path.chmod(0o600)
            descriptor = os.open(path, os.O_RDONLY)
            info = os.fstat(descriptor)
            completed = mock.Mock(returncode=0, stdout="debug level 0\n")
            original_lstat = Path.lstat
            original_rename = Path.rename
            raced = [False]

            def root_lstat(candidate):
                current = original_lstat(candidate)
                values = list(current)
                values[4] = 0
                values[5] = 0
                return os.stat_result(values)

            def racing_rename(candidate, target):
                if candidate == path and not raced[0]:
                    raced[0] = True
                    candidate.unlink()
                    candidate.write_bytes(b"replacement")
                return original_rename(candidate, target)

            with (
                mock.patch.object(subject, "AUDIT_PATH", str(path)),
                mock.patch.object(
                    subject.subprocess, "run", return_value=completed),
                mock.patch.object(Path, "lstat", root_lstat),
                mock.patch.object(Path, "rename", racing_rename),
            ):
                self.assertFalse(subject._disable_and_destroy_sink(
                    descriptor, (info.st_dev, info.st_ino)))
            self.assertEqual(path.read_bytes(), b"replacement")


if __name__ == "__main__":
    unittest.main()
