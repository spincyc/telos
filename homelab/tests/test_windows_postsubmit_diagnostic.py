"""Tests for the bounded Windows post-submit diagnostic protocol."""

import json
from pathlib import Path
import socket
import unittest

from homelab.vm.windows_postsubmit_diagnostic import (
    GUEST_SCAN_TIMEOUT,
    PostSubmitDiagnosticCode,
    PostSubmitDiagnosticError,
    PostSubmitDiagnosticSession,
    SUBMISSION_PHASE_TIMEOUT,
)


NONCE = "ab" * 16
PRINCIPAL = "operator@FACTORY.TEST"

# The secondary evidence codes added so a silently reset operator sign-in
# reports WHY instead of a bare no-logon-event. Each must round-trip the wire
# protocol and be emitted verbatim by the guest watcher script.
SECONDARY_EVIDENCE_CODES = (
    PostSubmitDiagnosticCode.NON_INTERACTIVE_LOGON_FAILURE,
    PostSubmitDiagnosticCode.NO_LOGON_SERVERS,
    PostSubmitDiagnosticCode.SECURE_CHANNEL_ERROR,
    PostSubmitDiagnosticCode.KERBEROS_ERROR,
    PostSubmitDiagnosticCode.NON_INTERACTIVE_LOGON,
)

_WATCHER_SCRIPT = (
    Path(__file__).resolve().parents[1]
    / "vm"
    / "windows_join_control"
    / "TelosPostSubmitDiagnostic.ps1"
)


def record(value):
    return (
        json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode("ascii")


class PostSubmitDiagnosticSessionTests(unittest.TestCase):
    def test_submission_phase_reserves_guest_scan_cleanup_margin(self):
        self.assertEqual(60, GUEST_SCAN_TIMEOUT)
        self.assertGreaterEqual(
            SUBMISSION_PHASE_TIMEOUT,
            GUEST_SCAN_TIMEOUT + 5,
        )

    def session(self):
        host, guest = socket.socketpair()
        self.addCleanup(host.close)
        self.addCleanup(guest.close)
        return PostSubmitDiagnosticSession(
            host, NONCE, PRINCIPAL, timeout=5, pause=lambda _delay: None), guest

    def test_exact_ordered_protocol_returns_fixed_code(self):
        session, guest = self.session()
        guest.sendall(record({
            "schema_version": 1, "event": "armed", "nonce": NONCE,
        }))
        session.arm()
        self.assertEqual({
            "schema_version": 1, "command": "arm", "nonce": NONCE,
            "principal": PRINCIPAL,
        }, json.loads(guest.recv(1024)))
        guest.sendall(record({
            "schema_version": 1, "event": "submitted", "nonce": NONCE,
        }))
        session.submitted()
        self.assertEqual({
            "schema_version": 1, "command": "submitted", "nonce": NONCE,
        }, json.loads(guest.recv(1024)))
        guest.sendall(record({
            "schema_version": 1, "event": "result", "nonce": NONCE,
            "code": "bad-credential", "cleanup_complete": True,
        }))
        self.assertIs(
            PostSubmitDiagnosticCode.BAD_CREDENTIAL, session.result())

    def test_all_result_codes_are_accepted_and_no_others(self):
        for code in PostSubmitDiagnosticCode:
            with self.subTest(code=code.value):
                session, guest = self.session()
                session._state = "submitted"
                guest.sendall(record({
                    "schema_version": 1, "event": "result", "nonce": NONCE,
                    "code": code.value, "cleanup_complete": True,
                }))
                self.assertIs(code, session.result())
        session, guest = self.session()
        session._state = "submitted"
        guest.sendall(record({
            "schema_version": 1, "event": "result", "nonce": NONCE,
            "code": "raw-status-0xc000006a", "cleanup_complete": True,
        }))
        with self.assertRaisesRegex(
                PostSubmitDiagnosticError, "code is invalid"):
            session.result()

    def test_secondary_evidence_codes_round_trip_the_wire(self):
        for code in SECONDARY_EVIDENCE_CODES:
            with self.subTest(code=code.value):
                session, guest = self.session()
                session._state = "submitted"
                guest.sendall(record({
                    "schema_version": 1, "event": "result", "nonce": NONCE,
                    "code": code.value, "cleanup_complete": True,
                }))
                self.assertIs(code, session.result())

    def test_secondary_evidence_unknown_neighbour_fails_closed(self):
        session, guest = self.session()
        session._state = "submitted"
        guest.sendall(record({
            "schema_version": 1, "event": "result", "nonce": NONCE,
            "code": "non-interactive-logon-timeout", "cleanup_complete": True,
        }))
        with self.assertRaisesRegex(
                PostSubmitDiagnosticError, "code is invalid"):
            session.result()

    def test_watcher_script_emits_each_secondary_code_once(self):
        text = _WATCHER_SCRIPT.read_text(encoding="ascii")
        for code in SECONDARY_EVIDENCE_CODES:
            with self.subTest(code=code.value):
                # Match the quoted literal so 'non-interactive-logon' is not
                # counted inside 'non-interactive-logon-failure'.
                self.assertEqual(
                    1, text.count("'" + code.value + "'"),
                    f"{code.value} must be emitted exactly once")
        # The genuine no-evidence code and the Type-2 correlation both remain.
        self.assertEqual(1, text.count("'no-logon-event'"))
        self.assertIn("LogonType -cne '2'", text)

    def test_rejects_stale_nonce_extra_fields_and_noncanonical_json(self):
        invalid_records = (
            record({
                "schema_version": 1, "event": "result",
                "nonce": "cd" * 32, "code": "bad-credential",
                "cleanup_complete": True,
            }),
            record({
                "schema_version": 1, "event": "result", "nonce": NONCE,
                "code": "bad-credential", "identity": PRINCIPAL,
                "cleanup_complete": True,
            }),
            (
                '{"schema_version": 1, "event": "result", '
                f'"nonce": "{NONCE}", "code": "bad-credential", '
                '"cleanup_complete": true}\n'
            ).encode("ascii"),
        )
        for invalid in invalid_records:
            with self.subTest(invalid=invalid):
                session, guest = self.session()
                session._state = "submitted"
                guest.sendall(invalid)
                with self.assertRaises(PostSubmitDiagnosticError):
                    session.result()

    def test_rejects_invalid_inputs_and_out_of_order_calls(self):
        host, guest = socket.socketpair()
        self.addCleanup(host.close)
        self.addCleanup(guest.close)
        for nonce, principal in (
            ("short", PRINCIPAL),
            (NONCE.upper(), PRINCIPAL),
            (NONCE, "operator name"),
            (NONCE, "operator@bad@FACTORY.TEST"),
            (NONCE, "operator@FACTORY"),
        ):
            with self.subTest(nonce=nonce, principal=principal):
                with self.assertRaises(PostSubmitDiagnosticError):
                    PostSubmitDiagnosticSession(
                        host, nonce, principal, timeout=5)
        session, _ = self.session()
        with self.assertRaisesRegex(
                PostSubmitDiagnosticError, "out of order"):
            session.submitted()
        with self.assertRaisesRegex(
                PostSubmitDiagnosticError, "out of order"):
            session.result()

    def test_line_framing_is_strict_and_bounded(self):
        for payload, message, subphase in (
            (b"{}\r\n", "contains CR", "parse"),
            (b"\xff\n", "canonical JSON", "parse"),
            (b"x" * 129, "exceeds bound", "parse"),
        ):
            with self.subTest(message=message):
                host, guest = socket.socketpair()
                self.addCleanup(host.close)
                self.addCleanup(guest.close)
                session = PostSubmitDiagnosticSession(
                    host, NONCE, PRINCIPAL, timeout=5, maximum_line=128)
                guest.sendall(payload)
                with self.assertRaisesRegex(
                        PostSubmitDiagnosticError, message) as caught:
                    session._read()
                self.assertEqual(subphase, caught.exception.arm_subphase)

    def test_context_manager_closes_exclusive_connection(self):
        session, _ = self.session()
        with session as entered:
            self.assertIs(session, entered)
            self.assertFalse(session.closed)
        self.assertTrue(session.closed)
        with self.assertRaisesRegex(
                PostSubmitDiagnosticError, "closed"):
            session.arm()

    def test_cancel_requires_nonce_bound_cleanup_receipt(self):
        session, guest = self.session()
        session._state = "armed"
        guest.sendall(record({
            "schema_version": 1,
            "event": "cancelled",
            "nonce": NONCE,
            "cleanup_complete": True,
        }))
        session.cancel()
        self.assertEqual({
            "schema_version": 1, "command": "cancel", "nonce": NONCE,
        }, json.loads(guest.recv(1024)))
        self.assertEqual("finished", session._state)

    def test_arm_sends_command_before_rejecting_stale_receipt(self):
        session, guest = self.session()
        guest.sendall(record({
            "schema_version": 1,
            "event": "armed",
            "nonce": "cd" * 16,
        }))
        with self.assertRaisesRegex(
                PostSubmitDiagnosticError, "armed receipt") as caught:
            session.arm()
        self.assertEqual("guest", caught.exception.arm_subphase)
        self.assertEqual({
            "schema_version": 1, "command": "arm", "nonce": NONCE,
            "principal": PRINCIPAL,
        }, json.loads(guest.recv(1024)))

    def test_result_rejects_unproved_cleanup(self):
        session, guest = self.session()
        session._state = "submitted"
        guest.sendall(record({
            "schema_version": 1, "event": "result", "nonce": NONCE,
            "code": "bad-credential", "cleanup_complete": False,
        }))
        with self.assertRaisesRegex(
                PostSubmitDiagnosticError, "result is invalid"):
            session.result()

    def test_submitted_accepts_only_exact_terminal_guest_result(self):
        session, guest = self.session()
        session._state = "armed"
        guest.sendall(record({
            "schema_version": 1, "event": "result", "nonce": NONCE,
            "code": "watcher-error", "cleanup_complete": True,
        }))

        self.assertIs(
            PostSubmitDiagnosticCode.WATCHER_ERROR,
            session.submitted(),
        )
        self.assertEqual("finished", session._state)
        self.assertEqual({
            "schema_version": 1, "command": "submitted", "nonce": NONCE,
        }, json.loads(guest.recv(1024)))

        for mutation in (
            {"nonce": "cd" * 16},
            {"cleanup_complete": False},
            {"code": "raw-private-code"},
            {"private": "detail"},
        ):
            with self.subTest(mutation=mutation):
                session, guest = self.session()
                session._state = "armed"
                candidate = {
                    "schema_version": 1, "event": "result",
                    "nonce": NONCE, "code": "watcher-error",
                    "cleanup_complete": True,
                }
                candidate.update(mutation)
                guest.sendall(record(candidate))
                with self.assertRaises(PostSubmitDiagnosticError):
                    session.submitted()

    def test_submission_and_cleanup_have_fresh_bounded_phase_deadlines(self):
        host, guest = socket.socketpair()
        self.addCleanup(host.close)
        self.addCleanup(guest.close)
        elapsed = [0.0]
        session = PostSubmitDiagnosticSession(
            host,
            NONCE,
            PRINCIPAL,
            timeout=5,
            submission_timeout=70,
            clock=lambda: elapsed[0],
            pause=lambda _delay: None,
        )
        session._state = "armed"

        # Secret entry consumed more than the arm phase's entire budget.
        elapsed[0] = 9
        guest.sendall(record({
            "schema_version": 1, "event": "submitted", "nonce": NONCE,
        }))
        self.assertIsNone(session.submitted())
        self.assertEqual(79, session._deadline)
        self.assertEqual({
            "schema_version": 1, "command": "submitted", "nonce": NONCE,
        }, json.loads(guest.recv(1024)))

        # Ordinary receive-timeout refreshes cannot extend the phase.
        elapsed[0] = 20
        session._set_operation_timeout()
        self.assertEqual(79, session._deadline)

        # A failed result phase can likewise exhaust its deadline without
        # preventing the independently bounded cleanup command.
        guest.sendall(record({
            "schema_version": 1, "event": "cancelled", "nonce": NONCE,
            "cleanup_complete": True,
        }))
        session.cancel()
        self.assertEqual(25, session._deadline)
        self.assertEqual({
            "schema_version": 1, "command": "cancel", "nonce": NONCE,
        }, json.loads(guest.recv(1024)))

    def test_terminal_state_rejects_duplicate_result_and_cancel(self):
        session, guest = self.session()
        session._state = "submitted"
        guest.sendall(record({
            "schema_version": 1, "event": "result", "nonce": NONCE,
            "code": "bad-credential", "cleanup_complete": True,
        }))
        session.result()
        with self.assertRaisesRegex(
                PostSubmitDiagnosticError, "result is out of order"):
            session.result()
        with self.assertRaisesRegex(
                PostSubmitDiagnosticError, "cancellation is out of order"):
            session.cancel()


if __name__ == "__main__":
    unittest.main()
