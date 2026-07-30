import unittest
from unittest import mock
import re
import base64
import tempfile
import json
import os
import socket
import threading
from pathlib import Path

from homelab.vm import controller_auth_diagnostic as subject
from homelab.vm.serial_automation import SerialAutomation
from homelab.vm.controller_auth_diagnostic import (
    ControllerAuthArmSubphase,
    ControllerAuthReceiveObservation,
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
from homelab.vm.windows_identity_run import WindowsLocalReauthenticationError
from homelab.vm.windows_identity_orchestrator import (
    _local_reauthentication_coordinate,
)
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

    def test_result_rejects_untyped_primary_coordinates(self):
        with self.assertRaises(TypeError):
            ControllerAuthResult(code="authenticated")
        with self.assertRaises(TypeError):
            ControllerAuthResult(collection="malformed")

    def test_error_revalidates_exact_result_carrier(self):
        class ForgedResult(ControllerAuthResult):
            pass

        with self.assertRaises(TypeError):
            ControllerAuthDiagnosticError(
                controller_auth_result=ForgedResult(
                    code=ControllerAuthCode.NO_EVENT),
                cleanup_proved=True,
            )

        uninitialized = object.__new__(ControllerAuthResult)
        object.__setattr__(uninitialized, "code", ControllerAuthCode.NO_EVENT)
        object.__setattr__(uninitialized, "collection", None)
        object.__setattr__(uninitialized, "cleanup", None)
        object.__setattr__(uninitialized, "code", "no-event")
        with self.assertRaises(TypeError):
            ControllerAuthDiagnosticError(
                controller_auth_result=uninitialized,
                cleanup_proved=True,
            )

        mutated = ControllerAuthResult(
            collection=ControllerAuthCollection.MALFORMED)
        object.__setattr__(mutated, "collection", "malformed")
        with self.assertRaises(TypeError):
            ControllerAuthDiagnosticError(
                controller_auth_result=mutated,
                cleanup_proved=True,
            )

    def test_error_cleanup_proof_is_exact_and_consistent(self):
        clean = ControllerAuthResult(code=ControllerAuthCode.NO_EVENT)
        unproved = ControllerAuthResult(
            collection=ControllerAuthCollection.RECEIPT_UNAVAILABLE,
            cleanup=subject.ControllerAuthCleanup.SINK_ABSENCE_UNPROVED,
        )
        with self.assertRaises(TypeError):
            ControllerAuthDiagnosticError(
                controller_auth_result=clean,
                cleanup_proved=1,
            )
        with self.assertRaises(ValueError):
            ControllerAuthDiagnosticError(
                controller_auth_result=clean,
                cleanup_proved=False,
            )
        with self.assertRaises(ValueError):
            ControllerAuthDiagnosticError(
                controller_auth_result=unproved,
                cleanup_proved=True,
            )

    def test_error_rejects_forged_arm_subphase(self):
        class ForgedArmSubphase(str, subject.Enum):
            COMMAND_DISPATCH = "command-dispatch"

        with self.assertRaises(TypeError):
            ControllerAuthDiagnosticError(
                cleanup_proved=True,
                arm_subphase=ForgedArmSubphase.COMMAND_DISPATCH,
            )
        with self.assertRaises(TypeError):
            ControllerAuthDiagnosticError(
                cleanup_proved=True,
                arm_subphase="command-dispatch",
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
            re.match(
                rb"(ok|[a-z-]+)", b"sink-absence-unproved"),
        ]
        session = ControllerAuthDiagnosticSession(console, self.expected)
        session.arm()
        with self.assertRaises(ControllerAuthDiagnosticError) as caught:
            session.cancel()
        result = caught.exception.controller_auth_result
        self.assertEqual(
            result.collection, ControllerAuthCollection.CANCELLED)
        self.assertEqual(
            result.cleanup,
            subject.ControllerAuthCleanup.SINK_ABSENCE_UNPROVED)

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
            console, self.expected, timeout=25, clock=lambda: now[0])
        session.arm()
        self.assertEqual(observed, [25.0, 2.0])
        self.assertEqual(console.timeout, 99.0)
        command = console._send.call_args_list[1].args[0]
        encoded = command.rsplit(b" ", 1)[1]
        payload = json.loads(base64.b64decode(encoded))
        self.assertEqual(
            payload["observation_seconds"],
            subject.MAX_OBSERVATION_SECONDS)

    def test_submit_establishes_fresh_observation_and_cleanup_deadline(self):
        now = [100.0]
        observed = []
        console = mock.Mock(password=None, timeout=99.0)

        def waited(*_args):
            observed.append(console.timeout)
            if len(observed) == 1:
                now[0] += subject.MAX_OBSERVATION_SECONDS
                return re.search(
                    rb"(code|collection):([a-z-]+)",
                    b"code:authenticated")
            return re.match(rb"(ok|[a-z-]+)", b"ok")

        console._wait.side_effect = waited
        session = ControllerAuthDiagnosticSession(
            console, self.expected, timeout=25, post_arm_timeout=7,
            clock=lambda: now[0])
        session._state = "armed"
        session._armed_deadline = 107.0

        result = session.submitted()

        self.assertEqual(
            observed,
            [subject.MAX_OBSERVATION_SECONDS,
             subject.CLEANUP_RESERVE_SECONDS])
        self.assertIs(result.code, ControllerAuthCode.AUTHENTICATED)
        self.assertEqual(now[0], 130.0)

    def test_cancel_after_post_arm_expiry_has_fresh_cleanup_reserve(self):
        now = [100.0]
        observed = []
        console = mock.Mock(password=None, timeout=99.0)

        def waited(*_args):
            observed.append(console.timeout)
            if len(observed) == 1:
                now[0] += 1
                return mock.Mock()
            return re.match(rb"(ok|[a-z-]+)", b"ok")

        console._wait.side_effect = waited
        session = ControllerAuthDiagnosticSession(
            console, self.expected, timeout=25, post_arm_timeout=7,
            clock=lambda: now[0])
        session._state = "armed"
        session._armed_deadline = 99.0

        result = session.cancel()

        self.assertEqual(
            observed,
            [subject.CLEANUP_RECEIPT_SECONDS,
             subject.CLEANUP_BOUNDED_OPERATIONS_SECONDS])
        self.assertIs(
            result.collection, ControllerAuthCollection.CANCELLED)

    def test_timeout_reserves_worst_case_cleanup_margin(self):
        with self.assertRaises(ValueError):
            ControllerAuthDiagnosticSession(
                mock.Mock(), self.expected,
                timeout=subject.CLEANUP_RESERVE_SECONDS)
        session = ControllerAuthDiagnosticSession(
            mock.Mock(), self.expected,
            timeout=subject.CLEANUP_RESERVE_SECONDS + 1)
        self.assertEqual(
            session._observation_seconds, subject.MAX_OBSERVATION_SECONDS)

    def test_partial_arm_failure_proves_cleanup_before_reporting(self):
        console = mock.Mock(password=None, timeout=99.0)
        console._wait.side_effect = [
            mock.Mock(),
            RuntimeError("armed receipt unavailable"),
            re.match(rb"(ok|absence-unproved)", b"ok"),
        ]
        session = ControllerAuthDiagnosticSession(
            console, self.expected, timeout=25, clock=lambda: 0)
        with self.assertRaises(ControllerAuthDiagnosticError) as caught:
            session.arm()
        self.assertTrue(caught.exception.cleanup_proved)
        self.assertIs(
            caught.exception.arm_subphase,
            ControllerAuthArmSubphase.RECEIVE)
        self.assertIn(
            "controller-auth-launch-interrupted",
            [call.args[1] for call in console._send.call_args_list],
        )

    def test_launch_failures_have_exact_secret_free_subphases(self):
        scenarios = (
            (
                "command dispatch",
                [None, RuntimeError("private command dispatch failure"), None],
                [mock.Mock(), re.match(rb"(ok|absence-unproved)", b"ok")],
                ControllerAuthArmSubphase.COMMAND_DISPATCH,
            ),
            (
                "sudo prompt",
                [None, None, None],
                [
                    mock.Mock(),
                    RuntimeError("private sudo prompt failure"),
                    re.match(rb"(ok|absence-unproved)", b"ok"),
                ],
                ControllerAuthArmSubphase.SUDO_PROMPT,
            ),
            (
                "sudo credential handoff",
                [
                    None,
                    None,
                    RuntimeError("private credential handoff failure"),
                    None,
                ],
                [
                    mock.Mock(),
                    mock.Mock(),
                    re.match(rb"(ok|absence-unproved)", b"ok"),
                ],
                ControllerAuthArmSubphase.SUDO_CREDENTIAL_HANDOFF,
            ),
        )
        observed = set()
        for label, send_effects, wait_effects, expected in scenarios:
            with self.subTest(label=label):
                console = mock.Mock(password=b"private-password", timeout=99.0)
                console._send.side_effect = send_effects
                console._wait.side_effect = wait_effects
                session = ControllerAuthDiagnosticSession(
                    console, self.expected)
                with self.assertRaises(ControllerAuthDiagnosticError) as caught:
                    session.arm()
                observed.add(caught.exception.arm_subphase)
                self.assertIs(caught.exception.arm_subphase, expected)
                self.assertTrue(caught.exception.cleanup_proved)
                self.assertEqual(
                    caught.exception.controller_auth_result.collection,
                    ControllerAuthCollection.RECEIPT_UNAVAILABLE,
                )
                self.assertNotIn(
                    "private", str(caught.exception))

        self.assertNotIn(ControllerAuthArmSubphase.LAUNCH, observed)

    def test_sudo_argv_selects_noninteractive_or_stdin_mode(self):
        fixed_uuid = mock.Mock(hex="0123456789abcdef0123456789abcdef")
        for password, expected, forbidden in (
            (None, b"sudo -k -n ", b" -S "),
            (b"private-password", b"sudo -k -S -p '", b" -n "),
        ):
            with self.subTest(password=password is not None):
                console = mock.Mock(password=password, timeout=99.0)
                console._wait.side_effect = [
                    mock.Mock(),
                    *(
                        [mock.Mock()]
                        if password is not None
                        else []
                    ),
                    mock.Mock(),
                ]
                session = ControllerAuthDiagnosticSession(
                    console, self.expected)
                with mock.patch.object(
                    subject.uuid, "uuid4", return_value=fixed_uuid,
                ):
                    session.arm()
                command = console._send.call_args_list[1].args[0]
                self.assertTrue(command.startswith(expected))
                self.assertIn(
                    b"/usr/bin/python3 "
                    b"/opt/telos-factory/controller-auth-diagnostic.py "
                    b"--controller-session ",
                    command,
                )
                self.assertNotIn(forbidden, command)
                if password is not None:
                    raw_prompt = (
                        b"__TELOS_AUTH_SUDO_"
                        b"0123456789abcdef0123456789abcdef__")
                    self.assertNotIn(raw_prompt, command)
                    self.assertIn(
                        b"'__TELOS_AUTH_SUDO_''"
                        b"0123456789abcdef0123456789abcdef__'",
                        command,
                    )

    def test_receive_observations_are_closed_and_secret_free(self):
        session = ControllerAuthDiagnosticSession(
            mock.Mock(password=None), self.expected)
        session._sudo_prompt_token = b"a" * 32
        armed = b"__TELOS_AUTH_ARMED_" + b"b" * 32 + b"__"
        result = b"__TELOS_AUTH_RESULT_" + b"c" * 32 + b"__="
        scenarios = (
            (
                b"Sorry, try again.\n",
                RuntimeError("private rejection"),
                ControllerAuthReceiveObservation
                .SUDO_REJECTED_OR_REPROMPTED,
            ),
            (
                b"sudo: unable to execute "
                b"/opt/telos-factory/controller-auth-diagnostic.py: "
                b"No such file or directory\n",
                RuntimeError("private launch"),
                ControllerAuthReceiveObservation.COMMAND_LAUNCH_ERROR,
            ),
            (
                b"/usr/bin/python3: can't open file "
                b"'/opt/telos-factory/controller-auth-diagnostic.py': "
                b"[Errno 2] No such file or directory\n",
                RuntimeError("private launch"),
                ControllerAuthReceiveObservation.COMMAND_LAUNCH_ERROR,
            ),
            (
                b"sudo: /usr/bin/python3: command not found\n",
                RuntimeError("private launch"),
                ControllerAuthReceiveObservation.COMMAND_LAUNCH_ERROR,
            ),
            (
                b"sudo: a password is required\n",
                RuntimeError("private rejection"),
                ControllerAuthReceiveObservation
                .SUDO_REJECTED_OR_REPROMPTED,
            ),
            (
                b"sudo: no password was provided\n",
                RuntimeError("private rejection"),
                ControllerAuthReceiveObservation
                .SUDO_REJECTED_OR_REPROMPTED,
            ),
            (
                armed + b" trailing-output\n",
                RuntimeError("private framing"),
                ControllerAuthReceiveObservation.TOKEN_NONSTANDALONE,
            ),
            (
                b"",
                RuntimeError(
                    "serial closed while waiting for private-label"),
                ControllerAuthReceiveObservation.SERIAL_CLOSED,
            ),
            (
                b"",
                TimeoutError("private timeout"),
                ControllerAuthReceiveObservation.TIMEOUT,
            ),
            (
                b"unrecognized private output",
                RuntimeError("private failure"),
                ControllerAuthReceiveObservation.UNCLASSIFIED,
            ),
        )
        for buffer, error, expected in scenarios:
            with self.subTest(expected=expected):
                session.console.buffer = buffer
                observed = session._receive_observation(
                    error, armed, result)
                self.assertIs(observed, expected)
                self.assertNotIn("private", observed.value)

    def test_receive_failure_carries_closed_observation(self):
        console = mock.Mock(password=None, timeout=99.0, buffer=b"")
        console._wait.side_effect = [
            mock.Mock(),
            TimeoutError("private arm timeout"),
            re.match(rb"(ok|absence-unproved)", b"ok"),
        ]
        session = ControllerAuthDiagnosticSession(console, self.expected)

        with self.assertRaises(ControllerAuthDiagnosticError) as caught:
            session.arm()

        self.assertIs(
            caught.exception.arm_subphase,
            ControllerAuthArmSubphase.RECEIVE)
        self.assertIs(
            caught.exception.receive_observation,
            ControllerAuthReceiveObservation.TIMEOUT)
        self.assertNotIn("private", str(caught.exception))

    def test_receive_observation_requires_exact_receive_subphase(self):
        with self.assertRaises(ValueError):
            ControllerAuthDiagnosticError(
                cleanup_proved=True,
                arm_subphase=ControllerAuthArmSubphase.COMMAND_DISPATCH,
                receive_observation=ControllerAuthReceiveObservation.TIMEOUT,
            )
        with self.assertRaises(TypeError):
            ControllerAuthDiagnosticError(
                cleanup_proved=True,
                arm_subphase=ControllerAuthArmSubphase.RECEIVE,
                receive_observation="timeout",
            )

    def test_hostile_receive_inspection_cannot_prevent_cleanup(self):
        class HostileConsole:
            password = None
            timeout = 99.0

            def __init__(self):
                self.waits = 0

            @property
            def buffer(self):
                raise RuntimeError("private buffer")

            def _send(self, _value, _label):
                return None

            def _wait(self, _pattern, _label):
                self.waits += 1
                if self.waits == 1:
                    return mock.Mock()
                if self.waits == 2:
                    raise RuntimeError("private arm failure")
                return re.match(rb"(ok|absence-unproved)", b"ok")

        console = HostileConsole()
        session = ControllerAuthDiagnosticSession(console, self.expected)
        with self.assertRaises(ControllerAuthDiagnosticError) as caught:
            session.arm()

        self.assertTrue(caught.exception.cleanup_proved)
        self.assertIs(
            caught.exception.receive_observation,
            ControllerAuthReceiveObservation.UNCLASSIFIED)
        self.assertEqual(console.waits, 3)

    def test_receive_observation_reaches_final_secret_free_diagnostic(self):
        error = WindowsLocalReauthenticationError(
            "controller-auth-arm",
            controller_auth_result=ControllerAuthResult(
                collection=ControllerAuthCollection.RECEIPT_UNAVAILABLE),
            controller_auth_arm_subphase=ControllerAuthArmSubphase.RECEIVE,
            controller_auth_receive_observation=(
                ControllerAuthReceiveObservation.COMMAND_LAUNCH_ERROR),
        )
        coordinate = _local_reauthentication_coordinate(error)
        diagnostic = IdentityFailureDiagnostic.join_guest(
            coordinate.phase,
            coordinate.error_type,
            controller_auth=coordinate.controller_auth,
            controller_auth_arm_subphase=(
                coordinate.controller_auth_arm_subphase),
            controller_auth_receive_observation=(
                coordinate.controller_auth_receive_observation),
        )

        self.assertIn(
            "controller-auth-receive-observation=command-launch-error",
            diagnostic.render())
        self.assertNotIn("private", diagnostic.render())

    def test_real_serial_accepts_bare_cr_prompt_not_command_echo(self):
        left, right = socket.socketpair()
        reader = left.makefile("rb", buffering=0)
        writer = left.makefile("wb", buffering=0)
        prompt = b"__TELOS_AUTH_SUDO_0123456789abcdef__"
        pattern = (
            rb"(?:^|[\r\n])" + re.escape(prompt)
            + rb"[^\S\r\n]*(?=[\r\n]|$)")
        payload = (
            b"sudo -p '\r__TELOS_AUTH_SUDO_''"
            b"0123456789abcdef__' command\r"
            + prompt + b"\t \r")

        def responder():
            right.sendall(payload)

        thread = threading.Thread(target=responder, daemon=True)
        thread.start()
        try:
            console = SerialAutomation(
                reader, writer, b"private-password", timeout=1)
            match = console._wait(pattern, "bare-cr-sudo-prompt")
        finally:
            left.close()
            right.close()
        thread.join(timeout=1)
        self.assertFalse(thread.is_alive())
        self.assertEqual(match.group(0).lstrip(b"\r"), prompt + b"\t ")
        self.assertEqual(payload.count(prompt), 1)
        self.assertEqual(match.start(), payload.rfind(b"\r" + prompt))

    def test_real_serial_accepts_bare_cr_auth_receipts_only_standalone(self):
        left, right = socket.socketpair()
        reader = left.makefile("rb", buffering=0)
        writer = left.makefile("wb", buffering=0)
        peer = right.makefile("rb", buffering=0)
        errors = []
        console = SerialAutomation(reader, writer, None, timeout=1)
        session = ControllerAuthDiagnosticSession(
            console, self.expected, timeout=25)
        armed = (
            f"__TELOS_AUTH_ARMED_{session._tokens['arm']}__".encode())
        result = (
            f"__TELOS_AUTH_RESULT_{session._tokens['result']}__=".encode())
        cleanup = (
            f"__TELOS_AUTH_CLEANUP_{session._tokens['cleanup']}__=".encode())

        def responder():
            try:
                peer.readline()
                right.sendall(b"local-rescue@bootstrap-dc $ \r")
                peer.readline()
                right.sendall(
                    b"\r__TELOS_AUTH_ARMED_wrong__\r"
                    + b"echo " + armed + b"\r"
                    + b"prefix" + armed + b"\r"
                    + armed + b"\t \r")
                peer.readline()
                right.sendall(
                    b"\r__TELOS_AUTH_RESULT_wrong__=code:authenticated\r"
                    + b"echo " + result + b"code:authenticated\r"
                    + result + b"code:authenticated\t\r"
                    + cleanup + b"ok \t\r")
            except BaseException as error:
                errors.append(error)

        thread = threading.Thread(target=responder, daemon=True)
        thread.start()
        try:
            session.arm()
            outcome = session.submitted()
        finally:
            left.close()
            right.close()
        thread.join(timeout=1)
        self.assertFalse(thread.is_alive())
        self.assertEqual(errors, [])
        self.assertIs(outcome.code, ControllerAuthCode.AUTHENTICATED)
        self.assertIsNone(outcome.cleanup)

    def test_real_serial_accepts_bare_cr_prearm_result_and_cleanup(self):
        left, right = socket.socketpair()
        reader = left.makefile("rb", buffering=0)
        writer = left.makefile("wb", buffering=0)
        peer = right.makefile("rb", buffering=0)
        errors = []
        console = SerialAutomation(reader, writer, None, timeout=1)
        session = ControllerAuthDiagnosticSession(
            console, self.expected, timeout=25)
        result = (
            f"__TELOS_AUTH_RESULT_{session._tokens['result']}__=".encode())
        cleanup = (
            f"__TELOS_AUTH_CLEANUP_{session._tokens['cleanup']}__=".encode())

        def responder():
            try:
                peer.readline()
                right.sendall(b"local-rescue@bootstrap-dc $ \r")
                peer.readline()
                right.sendall(
                    b"\r" + result + b"collection:configuration-invalid\t\r"
                    + cleanup + b"ok\r")
            except BaseException as error:
                errors.append(error)

        thread = threading.Thread(target=responder, daemon=True)
        thread.start()
        try:
            with self.assertRaises(ControllerAuthDiagnosticError) as caught:
                session.arm()
        finally:
            left.close()
            right.close()
        thread.join(timeout=1)
        self.assertFalse(thread.is_alive())
        self.assertEqual(errors, [])
        self.assertIs(
            caught.exception.controller_auth_result.collection,
            ControllerAuthCollection.CONFIGURATION_INVALID)
        self.assertTrue(caught.exception.cleanup_proved)

    def test_launch_failure_preserves_primary_and_cleanup_coordinates(self):
        console = mock.Mock(password=b"private-password", timeout=99.0)
        console._send.side_effect = [
            None,
            RuntimeError("private command dispatch failure"),
            RuntimeError("private cleanup dispatch failure"),
        ]
        console._wait.side_effect = [mock.Mock()]
        session = ControllerAuthDiagnosticSession(console, self.expected)

        with self.assertRaises(ControllerAuthDiagnosticError) as caught:
            session.arm()

        self.assertIs(
            caught.exception.arm_subphase,
            ControllerAuthArmSubphase.COMMAND_DISPATCH,
        )
        self.assertFalse(caught.exception.cleanup_proved)
        self.assertIs(
            caught.exception.controller_auth_result.cleanup,
            subject.ControllerAuthCleanup.SINK_ABSENCE_UNPROVED,
        )
        self.assertNotIn("private", str(caught.exception))

    def test_arm_receipt_wait_reserves_cleanup_budget(self):
        now = [0.0]
        observed = []
        console = mock.Mock(password=None, timeout=99.0)

        def waited(*_args):
            observed.append(console.timeout)
            if len(observed) == 1:
                now[0] = 2.0
                return mock.Mock()
            if len(observed) == 2:
                now[0] += console.timeout
                raise TimeoutError("arm receipt deadline")
            return re.match(rb"(ok|absence-unproved)", b"ok")

        console._wait.side_effect = waited
        session = ControllerAuthDiagnosticSession(
            console, self.expected, timeout=25, clock=lambda: now[0])
        with self.assertRaises(ControllerAuthDiagnosticError) as caught:
            session.arm()

        self.assertEqual(observed, [25.0, 2.0, 21.0])
        self.assertTrue(caught.exception.cleanup_proved)
        self.assertIs(
            caught.exception.arm_subphase,
            ControllerAuthArmSubphase.RECEIVE)
        self.assertEqual(now[0], 4.0)
        self.assertEqual(console.timeout, 99.0)

    def test_sudo_prompt_wait_reserves_cleanup_budget(self):
        now = [0.0]
        observed = []
        console = mock.Mock(password=b"private-password", timeout=99.0)

        def waited(*_args):
            observed.append(console.timeout)
            if len(observed) == 1:
                now[0] = 2.0
                return mock.Mock()
            if len(observed) == 2:
                now[0] += console.timeout
                raise TimeoutError("sudo prompt deadline")
            return re.match(rb"(ok|absence-unproved)", b"ok")

        console._wait.side_effect = waited
        session = ControllerAuthDiagnosticSession(
            console, self.expected, timeout=25, clock=lambda: now[0])
        with self.assertRaises(ControllerAuthDiagnosticError) as caught:
            session.arm()

        self.assertEqual(observed, [25.0, 2.0, 21.0])
        self.assertTrue(caught.exception.cleanup_proved)
        self.assertIs(
            caught.exception.arm_subphase,
            ControllerAuthArmSubphase.SUDO_PROMPT)
        self.assertEqual(now[0], 4.0)
        self.assertEqual(console.timeout, 99.0)
        self.assertNotIn(
            "sudo prompt deadline", caught.exception.args)
        self.assertIn(
            "controller-auth-launch-interrupted",
            [call.args[1] for call in console._send.call_args_list],
        )
        self.assertNotIn(
            "controller-auth-abort-sent",
            [call.args[1] for call in console._send.call_args_list],
        )

    def test_sudo_prompt_shell_resync_does_not_claim_sink_absence(self):
        console = mock.Mock(password=b"private-password", timeout=99.0)
        console._wait.side_effect = [
            mock.Mock(),
            TimeoutError("private sudo prompt timeout"),
            re.match(rb"(?:(ok)|controller\$)", b"controller$"),
        ]
        session = ControllerAuthDiagnosticSession(console, self.expected)

        with self.assertRaises(ControllerAuthDiagnosticError) as caught:
            session.arm()

        self.assertIs(
            caught.exception.arm_subphase,
            ControllerAuthArmSubphase.SUDO_PROMPT,
        )
        self.assertFalse(caught.exception.cleanup_proved)
        self.assertIs(
            caught.exception.controller_auth_result.cleanup,
            subject.ControllerAuthCleanup.SINK_ABSENCE_UNPROVED,
        )
        self.assertEqual(
            [call.args for call in console._send.call_args_list],
            [
                (b"", "controller-auth-shell-requested"),
                (mock.ANY, "controller-auth-command-sent"),
                (b"\x03", "controller-auth-launch-interrupted"),
            ],
        )
        self.assertNotIn("private", str(caught.exception))

    def test_sudo_prompt_at_cleanup_boundary_cannot_spend_margin(self):
        now = [0.0]
        observed = []
        console = mock.Mock(password=b"private-password", timeout=99.0)

        def waited(*_args):
            observed.append(console.timeout)
            if len(observed) == 1:
                now[0] = 2.0
                return mock.Mock()
            if len(observed) == 2:
                now[0] += console.timeout
                return mock.Mock()
            return re.match(rb"(ok|absence-unproved)", b"ok")

        console._wait.side_effect = waited
        session = ControllerAuthDiagnosticSession(
            console, self.expected, timeout=25, clock=lambda: now[0])
        with self.assertRaises(ControllerAuthDiagnosticError) as caught:
            session.arm()

        self.assertEqual(observed, [25.0, 2.0, 21.0])
        self.assertTrue(caught.exception.cleanup_proved)
        self.assertIs(
            caught.exception.arm_subphase,
            ControllerAuthArmSubphase.RECEIVE)
        self.assertEqual(now[0], 4.0)
        self.assertEqual(console.timeout, 99.0)

    def test_arm_recovery_never_extends_outer_deadline(self):
        now = [0.0]
        observed = []
        console = mock.Mock(password=None, timeout=99.0)

        def waited(*_args):
            observed.append(console.timeout)
            if len(observed) == 1:
                now[0] = 4.0
                return mock.Mock()
            if len(observed) == 2:
                now[0] += console.timeout
                raise TimeoutError("arm receipt deadline")
            now[0] += console.timeout
            raise TimeoutError("cleanup receipt deadline")

        console._wait.side_effect = waited
        session = ControllerAuthDiagnosticSession(
            console, self.expected, timeout=25, clock=lambda: now[0])
        with self.assertRaises(ControllerAuthDiagnosticError) as caught:
            session.arm()

        self.assertEqual(observed, [25.0, 21.0])
        self.assertFalse(caught.exception.cleanup_proved)
        self.assertIs(
            caught.exception.arm_subphase,
            ControllerAuthArmSubphase.RECEIVE)
        self.assertIs(
            caught.exception.controller_auth_result.cleanup,
            subject.ControllerAuthCleanup.SINK_ABSENCE_UNPROVED)
        self.assertEqual(now[0], 25.0)
        self.assertNotIn(
            "arm receipt deadline", caught.exception.args)
        self.assertNotIn(
            "cleanup receipt deadline", caught.exception.args)

    def test_configuration_failure_is_terminal_before_arm(self):
        console = mock.Mock(password=None, timeout=99.0)
        console._wait.side_effect = [
            mock.Mock(),
            re.search(
                rb"(code|collection):([a-z-]+)",
                b"collection:configuration-invalid"),
            re.match(rb"(ok|absence-unproved)", b"ok"),
        ]
        session = ControllerAuthDiagnosticSession(console, self.expected)
        with self.assertRaises(ControllerAuthDiagnosticError) as caught:
            session.arm()
        self.assertEqual(
            caught.exception.controller_auth_result.collection,
            ControllerAuthCollection.CONFIGURATION_INVALID,
        )
        self.assertTrue(caught.exception.cleanup_proved)
        self.assertNotIn(
            "controller-auth-abort-sent",
            [call.args[1] for call in console._send.call_args_list],
        )

    def test_prearm_rejects_postarm_coordinate_and_recovers_cleanup(self):
        console = mock.Mock(password=None, timeout=99.0)
        console._wait.side_effect = [
            mock.Mock(),
            re.search(
                rb"(code|collection):([a-z-]+)",
                b"collection:cancelled"),
            re.match(rb"(ok|[a-z-]+)", b"ok"),
        ]
        session = ControllerAuthDiagnosticSession(console, self.expected)
        with self.assertRaises(ControllerAuthDiagnosticError) as caught:
            session.arm()
        self.assertTrue(caught.exception.cleanup_proved)
        self.assertIs(
            caught.exception.arm_subphase,
            ControllerAuthArmSubphase.PARSE)
        self.assertIn(
            "controller-auth-launch-interrupted",
            [call.args[1] for call in console._send.call_args_list],
        )

    def test_sink_failure_reports_unproved_terminal_cleanup(self):
        console = mock.Mock(password=None, timeout=99.0)
        console._wait.side_effect = [
            mock.Mock(),
            re.search(
                rb"(code|collection):([a-z-]+)",
                b"collection:sink-invalid"),
            re.match(
                rb"(ok|[a-z-]+)", b"sink-absence-unproved"),
        ]
        session = ControllerAuthDiagnosticSession(console, self.expected)
        with self.assertRaises(ControllerAuthDiagnosticError) as caught:
            session.arm()
        self.assertEqual(
            caught.exception.controller_auth_result.collection,
            ControllerAuthCollection.SINK_INVALID,
        )
        self.assertEqual(
            caught.exception.controller_auth_result.cleanup,
            subject.ControllerAuthCleanup.SINK_ABSENCE_UNPROVED,
        )
        self.assertFalse(caught.exception.cleanup_proved)

    def test_arm_receipt_failure_is_typed_and_recovers_cleanup(self):
        console = mock.Mock(password=None, timeout=99.0)
        console._wait.side_effect = [
            mock.Mock(),
            RuntimeError("receipt unavailable"),
            re.match(rb"(ok|absence-unproved)", b"ok"),
        ]
        session = ControllerAuthDiagnosticSession(console, self.expected)
        with self.assertRaises(ControllerAuthDiagnosticError) as caught:
            session.arm()
        self.assertEqual(
            caught.exception.controller_auth_result.collection,
            ControllerAuthCollection.RECEIPT_UNAVAILABLE,
        )
        self.assertTrue(caught.exception.cleanup_proved)
        self.assertIs(
            caught.exception.arm_subphase,
            ControllerAuthArmSubphase.RECEIVE)

    def test_arm_receipt_and_cleanup_failure_preserves_primary_subphase(self):
        console = mock.Mock(password=None, timeout=99.0)
        console._wait.side_effect = [
            mock.Mock(),
            RuntimeError("private receipt failure"),
            RuntimeError("private cleanup failure"),
        ]
        session = ControllerAuthDiagnosticSession(console, self.expected)
        with self.assertRaises(ControllerAuthDiagnosticError) as caught:
            session.arm()
        self.assertFalse(caught.exception.cleanup_proved)
        self.assertIs(
            caught.exception.arm_subphase,
            ControllerAuthArmSubphase.RECEIVE)
        self.assertIs(
            caught.exception.controller_auth_result.cleanup,
            subject.ControllerAuthCleanup.SINK_ABSENCE_UNPROVED)

    def test_final_coordinate_renders_only_closed_arm_subphase(self):
        result = ControllerAuthResult(
            collection=ControllerAuthCollection.RECEIPT_UNAVAILABLE)
        coordinate = WindowsJoinFailureCoordinate(
            "reboot-reauth-controller-auth-arm",
            "WindowsLocalReauthenticationError",
            controller_auth=result,
            controller_auth_arm_subphase=(
                ControllerAuthArmSubphase.COMMAND_DISPATCH),
        )
        diagnostic = IdentityFailureDiagnostic.join_guest(
            coordinate.phase,
            coordinate.error_type,
            controller_auth=coordinate.controller_auth,
            controller_auth_arm_subphase=(
                coordinate.controller_auth_arm_subphase),
        )
        self.assertIn(
            "controller-auth-arm-subphase=command-dispatch",
            diagnostic.render())
        self.assertNotIn("private", diagnostic.render())

    def test_final_coordinate_renders_arm_and_cleanup_coordinates(self):
        result = ControllerAuthResult(
            collection=ControllerAuthCollection.RECEIPT_UNAVAILABLE,
            cleanup=subject.ControllerAuthCleanup.SINK_ABSENCE_UNPROVED,
        )
        coordinate = WindowsJoinFailureCoordinate(
            "reboot-reauth-controller-auth-arm",
            "WindowsLocalReauthenticationError",
            controller_auth=result,
            controller_auth_arm_subphase=ControllerAuthArmSubphase.PARSE,
        )
        diagnostic = IdentityFailureDiagnostic.join_guest(
            coordinate.phase,
            coordinate.error_type,
            controller_auth=coordinate.controller_auth,
            controller_auth_arm_subphase=(
                coordinate.controller_auth_arm_subphase),
        )
        rendered = diagnostic.render()
        self.assertIn(
            "controller-auth-collection=receipt-unavailable", rendered)
        self.assertIn(
            "controller-auth-cleanup=sink-absence-unproved", rendered)
        self.assertIn("controller-auth-arm-subphase=parse", rendered)

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

    def test_effective_configuration_proves_file_syntax_and_live_route(self):
        with tempfile.TemporaryDirectory() as name:
            config = Path(name) / "smb.conf"
            config.write_text(
                "[global]\n" + subject.AUTH_JSON_CONFIG_LINE + "\n")
            syntax = mock.Mock(returncode=0)
            live = mock.Mock(
                returncode=0,
                stdout=(
                    "PID 41: debug levels:\n"
                    "  all: 0\n"
                    "  auth_json_audit: 3\n"
                ),
            )
            with (
                mock.patch.object(subject, "SMB_CONFIG_PATH", str(config)),
                mock.patch.object(
                    subject.subprocess, "run",
                    side_effect=(syntax, live),
                ) as run,
            ):
                self.assertTrue(subject._effective_configuration())
            self.assertEqual(
                run.call_args_list[0].args[0],
                ["testparm", "-s", str(config)],
            )
            self.assertEqual(
                run.call_args_list[1].args[0],
                ["smbcontrol", "all", "debuglevel"],
            )

    def test_effective_configuration_rejects_bad_config_file_or_syntax(self):
        variants = (
            "[global]\n",
            "[global]\n" + subject.AUTH_JSON_CONFIG_LINE + "\n"
            + subject.AUTH_JSON_CONFIG_LINE + "\n",
            "[global]\n " + subject.AUTH_JSON_CONFIG_LINE.lstrip() + "\n",
            "[global]\n" + subject.AUTH_JSON_CONFIG_LINE
            + "\n\tlog level = auth_json_audit:3@/tmp/other\n",
        )
        with tempfile.TemporaryDirectory() as name:
            config = Path(name) / "smb.conf"
            for text in variants:
                with self.subTest(text=text):
                    config.write_text(text)
                    with (
                        mock.patch.object(
                            subject, "SMB_CONFIG_PATH", str(config)),
                        mock.patch.object(subject.subprocess, "run") as run,
                    ):
                        self.assertFalse(subject._effective_configuration())
                        run.assert_not_called()
            config.write_text(
                "[global]\n" + subject.AUTH_JSON_CONFIG_LINE + "\n")
            with (
                mock.patch.object(subject, "SMB_CONFIG_PATH", str(config)),
                mock.patch.object(
                    subject.subprocess, "run",
                    return_value=mock.Mock(returncode=1),
                ) as run,
            ):
                self.assertFalse(subject._effective_configuration())
                self.assertEqual(run.call_count, 1)

    def test_persistent_route_removal_validates_candidate_and_fsyncs(self):
        with tempfile.TemporaryDirectory() as name:
            config = Path(name) / "smb.conf"
            config.write_text(
                "[global]\n" + subject.AUTH_JSON_CONFIG_LINE + "\n")
            config.chmod(0o600)
            completed = mock.Mock(returncode=0)
            with (
                mock.patch.object(subject, "SMB_CONFIG_PATH", str(config)),
                mock.patch.object(
                    subject.subprocess, "run", return_value=completed) as run,
            ):
                self.assertTrue(subject._remove_persistent_route())
            self.assertEqual(config.read_text(), "[global]\n")
            candidate = run.call_args.args[0][2]
            self.assertNotEqual(candidate, str(config))
            self.assertEqual(run.call_args.args[0][:2], ["testparm", "-s"])

    def test_persistent_route_removal_rejects_conflict_without_mutation(self):
        with tempfile.TemporaryDirectory() as name:
            config = Path(name) / "smb.conf"
            original = (
                "[global]\n" + subject.AUTH_JSON_CONFIG_LINE
                + "\n\tlog level = auth_json_audit:3@/tmp/other\n"
            )
            config.write_text(original)
            with (
                mock.patch.object(subject, "SMB_CONFIG_PATH", str(config)),
                mock.patch.object(subject.subprocess, "run") as run,
            ):
                self.assertFalse(subject._remove_persistent_route())
            self.assertEqual(config.read_text(), original)
            run.assert_not_called()

    def test_effective_configuration_rejects_adversarial_live_routes(self):
        outputs = (
            ("", False),
            (
                "PID 1: debug levels:\n auth_json_audit: 3\n"
                "PID 2: debug levels:\n auth_json_audit:3\n",
                True,
            ),
            (
                "PID 1: debug levels:\n auth_json_audit: 2\n",
                False,
            ),
            (
                "PID 1: auth_json_audit: 3\n"
                "PID 2: auth_json_audit: 2\n",
                False,
            ),
            (
                "PID 1: auth_json_audit:\n"
                "PID 2: auth_json_audit: 3\n",
                False,
            ),
            (
                "PID 1: prefixauth_json_audit: 9 "
                "auth_json_audit: 3\n",
                True,
            ),
        )
        with tempfile.TemporaryDirectory() as name:
            config = Path(name) / "smb.conf"
            config.write_text(
                "[global]\n" + subject.AUTH_JSON_CONFIG_LINE + "\n")
            for output, expected in outputs:
                with (
                    self.subTest(output=output),
                    mock.patch.object(
                        subject, "SMB_CONFIG_PATH", str(config)),
                    mock.patch.object(
                        subject.subprocess,
                        "run",
                        side_effect=(
                            mock.Mock(returncode=0),
                            mock.Mock(returncode=0, stdout=output),
                        ),
                    ),
                ):
                    self.assertEqual(
                        expected, subject._effective_configuration())

    def test_cleanup_never_unlinks_hardlink_or_replacement(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            path = root / "auth.jsonl"
            path.write_bytes(b"")
            hardlink = root / "other"
            os.link(path, hardlink)
            descriptor = os.open(path, os.O_RDONLY)
            info = os.fstat(descriptor)
            completed = mock.Mock(
                returncode=0, stdout="auth_json_audit: 0\n")
            with (
                mock.patch.object(subject, "AUDIT_PATH", str(path)),
                mock.patch.object(
                    subject.subprocess, "run", return_value=completed),
            ):
                self.assertEqual(
                    subject.ControllerAuthCleanup.SINK_ABSENCE_UNPROVED,
                    subject._disable_and_destroy_sink(
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
                self.assertEqual(
                    subject.ControllerAuthCleanup.SINK_ABSENCE_UNPROVED,
                    subject._disable_and_destroy_sink(
                        descriptor, (info.st_dev, info.st_ino)))
            self.assertEqual(path.read_bytes(), b"replacement")

    def test_cleanup_queries_live_debuglevel_after_disabling_route(self):
        disabled = mock.Mock(returncode=0)
        verified = mock.Mock(
            returncode=0,
            stdout=(
                "PID 1: auth_json_audit: 0\n"
                "PID 2: auth_json_audit:0\n"
            ),
        )
        with mock.patch.object(
                subject.subprocess, "run",
                side_effect=(disabled, verified)) as run:
            self.assertEqual(
                subject.ControllerAuthCleanup.CONFIGURATION_UNPROVED,
                subject._disable_and_destroy_sink(None, None))
        self.assertEqual(
            run.call_args_list[0].args[0],
            ["smbcontrol", "all", "debug", "0 auth_json_audit:0"],
        )
        self.assertEqual(
            run.call_args_list[1].args[0],
            ["smbcontrol", "all", "debuglevel"],
        )

    def test_live_auth_json_level_rejects_absent_and_conflicting_levels(self):
        self.assertFalse(subject._live_auth_json_level("all: 0\n", 0))
        self.assertFalse(subject._live_auth_json_level(
            "auth_json_audit: 0\nauth_json_audit: 3\n", 0))
        self.assertTrue(subject._live_auth_json_level(
            "PID 1: auth_json_audit: 0\n"
            "PID 2: auth_json_audit:0\n", 0))

    def test_cleanup_restores_replacement_racing_quarantine(self):
        with tempfile.TemporaryDirectory() as name:
            path = Path(name) / "auth.jsonl"
            path.write_bytes(b"original")
            path.chmod(0o600)
            descriptor = os.open(path, os.O_RDONLY)
            info = os.fstat(descriptor)
            completed = mock.Mock(
                returncode=0, stdout="auth_json_audit: 0\n")
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
                self.assertEqual(
                    subject.ControllerAuthCleanup.SINK_ABSENCE_UNPROVED,
                    subject._disable_and_destroy_sink(
                        descriptor, (info.st_dev, info.st_ino)))
            self.assertEqual(path.read_bytes(), b"replacement")


if __name__ == "__main__":
    unittest.main()
