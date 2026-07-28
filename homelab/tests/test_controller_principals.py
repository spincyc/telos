import base64
import io
import json
import socket
import threading
import unittest

from homelab.vm.controller_principals import (
    ControllerPrincipalError,
    ControllerPrincipalResult,
    ControllerPrincipalSerial,
)


VALUES = {
    "student": "Student-secret-47!",
    "operator": "Operator-secret-47!",
    "directory-admin": "Directory-secret-47!",
}


class ControllerPrincipalSerialTests(unittest.TestCase):
    def run_operation(self, invoke, returncode=0):
        left, right = socket.socketpair()
        observed = []

        def responder():
            stream = right.makefile("rb", buffering=0)
            right.sendall(b"[local-rescue@bootstrap-dc ~]$ ")
            command = stream.readline()
            observed.append(command)
            token = command.split(
                b"__TELOS_PRINCIPAL_READY_", 1)[1].split(b"__", 1)[0]
            result = command.split(
                b"__TELOS_PRINCIPAL_RC_", 1)[1].split(b"=", 1)[0]
            # The public command may be echoed.  It must contain no secret.
            right.sendall(command)
            self.assertFalse(any(
                secret.encode() in command for secret in VALUES.values()))
            right.sendall(
                b"__TELOS_PRINCIPAL_READY_" + token + b"__\r\n")
            payload = stream.readline()
            observed.append(payload)
            right.sendall(
                b"\r\n__TELOS_PRINCIPAL_RC_" + result + b"="
                + str(returncode).encode() + b"\r\n")

        thread = threading.Thread(target=responder, daemon=True)
        thread.start()
        try:
            serial = ControllerPrincipalSerial(
                left.makefile("rb", buffering=0),
                left.makefile("wb", buffering=0),
                timeout=1,
            )
            result = invoke(serial)
        finally:
            left.close()
            right.close()
        thread.join(timeout=1)
        self.assertFalse(thread.is_alive())
        return result, observed

    def test_stage_suppresses_echo_and_transmits_only_encoded_stdin(self):
        result, observed = self.run_operation(
            lambda serial: serial.stage(VALUES))
        self.assertEqual("stage", result.operation)
        self.assertEqual(tuple(VALUES), result.principals)
        self.assertIn(b"stty -echo || exit 91", observed[0])
        self.assertIn(b"sudo -n python3", observed[0])
        self.assertIn(b"2>/dev/null", observed[0])
        self.assertNotIn(b"samba-tool", observed[0])
        self.assertEqual(
            VALUES,
            json.loads(base64.b64decode(observed[1]).decode("utf-8")),
        )
        for secret in VALUES.values():
            self.assertNotIn(secret, repr(result))
            self.assertNotIn(secret.encode(), observed[0])

    def test_destroy_uses_same_non_echo_boundary_and_no_credentials(self):
        names = tuple(VALUES)
        result, observed = self.run_operation(
            lambda serial: serial.destroy(names))
        self.assertEqual("destroy", result.operation)
        self.assertEqual(names, result.principals)
        self.assertEqual(
            list(names),
            json.loads(base64.b64decode(observed[1]).decode("utf-8")),
        )
        self.assertFalse(any(
            secret.encode() in b"".join(observed)
            for secret in VALUES.values()))

    def test_result_shape_cannot_retain_payload_or_transcript(self):
        self.assertEqual(
            ("operation", "principals", "events"),
            tuple(ControllerPrincipalResult.__dataclass_fields__),
        )

    def test_rejects_missing_duplicate_or_multiline_credentials(self):
        serial = ControllerPrincipalSerial(
            io.BytesIO(), io.BytesIO(),
        )
        with self.assertRaisesRegex(ValueError, "roster"):
            serial.stage({"student": "value"})
        duplicate = dict(VALUES)
        duplicate["operator"] = duplicate["student"]
        with self.assertRaisesRegex(ValueError, "distinct"):
            serial.stage(duplicate)
        multiline = dict(VALUES)
        multiline["operator"] = "unsafe\nvalue"
        with self.assertRaisesRegex(ValueError, "credential"):
            serial.stage(multiline)

    def test_nonzero_guest_result_is_fail_closed(self):
        with self.assertRaisesRegex(
                ControllerPrincipalError, "stage returned 7"):
            self.run_operation(
                lambda serial: serial.stage(VALUES), returncode=7)

    def test_destroy_refuses_partial_roster(self):
        left, right = socket.socketpair()
        try:
            serial = ControllerPrincipalSerial(
                left.makefile("rb"), left.makefile("wb"))
            with self.assertRaisesRegex(ValueError, "roster"):
                serial.destroy(("student", "operator"))
        finally:
            left.close()
            right.close()


if __name__ == "__main__":
    unittest.main()
