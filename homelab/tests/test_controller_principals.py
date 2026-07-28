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
from homelab.vm.serial_automation import SerialAutomation


VALUES = {
    "student": "Student-secret-47!",
    "operator": "Operator-secret-47!",
    "directory-admin": "Directory-secret-47!",
}


class ControllerPrincipalSerialTests(unittest.TestCase):
    def run_operation(self, invoke, returncode=0, sudo_password=None):
        left, right = socket.socketpair()
        observed = []

        def responder():
            stream = right.makefile("rb", buffering=0)
            self.assertEqual(b"\n", stream.readline())
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
            if sudo_password is not None:
                prompt = command.split(
                    b"__TELOS_PRINCIPAL_SUDO_", 1)[1].split(b"__", 1)[0]
                right.sendall(
                    b"\r\n__TELOS_PRINCIPAL_SUDO_" + prompt + b"__\r\n")
                observed.append(stream.readline())
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
            serial.console.password = sudo_password
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
        self.assertIn(b"os.close(2)", observed[0])
        self.assertNotIn(b"2>/dev/null", observed[0])
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

    def test_password_authenticated_sudo_is_secret_safe(self):
        password = b"Controller-private-47!"
        result, observed = self.run_operation(
            lambda serial: serial.stage(VALUES), sudo_password=password)
        self.assertEqual("stage", result.operation)
        self.assertIn(b"sudo -k -p", observed[0])
        self.assertNotIn(b"sudo -S", observed[0])
        self.assertNotIn(password, observed[0])
        self.assertEqual(password + b"\n", observed[2])

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

    def test_disposable_controller_session_starts_systemd_and_logs_in(self):
        left, right = socket.socketpair()
        password = b"Controller-private-47!"
        observed = []

        def responder():
            stream = right.makefile("rb", buffering=0)
            right.sendall(b"bash-5.2# ")
            remount = stream.readline()
            observed.append(remount)
            marker = remount.split(
                b"__TELOS_CONTROLLER_INIT_", 1)[1].split(b"__", 1)[0]
            right.sendall(
                b"\r\n__TELOS_CONTROLLER_INIT_" + marker + b"__\r\n"
                b"bash-5.2# ")
            observed.append(stream.readline())
            right.sendall(b"New password: ")
            observed.append(stream.readline())
            right.sendall(b"Retype new password: ")
            observed.append(stream.readline())
            right.sendall(
                b"passwd: password updated successfully\r\nbash-5.2# ")
            observed.append(stream.readline())
            right.sendall(b"bootstrap-dc login: ")
            observed.append(stream.readline())
            right.sendall(b"Password: ")
            observed.append(stream.readline())
            right.sendall(b"[local-rescue@bootstrap-dc ~]$ ")
            services = stream.readline()
            observed.append(services)
            token = services.split(
                b"__TELOS_CONTROLLER_SERVICES_", 1)[1].split(b"=", 1)[0]
            right.sendall(
                b"\r\n__TELOS_CONTROLLER_SERVICES_" + token + b"=0\r\n")

        thread = threading.Thread(target=responder, daemon=True)
        thread.start()
        try:
            console = SerialAutomation(
                left.makefile("rb", buffering=0),
                left.makefile("wb", buffering=0),
                password,
                timeout=1,
            )
            console.establish_disposable_controller_session()
        finally:
            left.close()
            right.close()
        thread.join(timeout=1)
        self.assertFalse(thread.is_alive())
        self.assertIn(b"mount -o remount,rw /", observed[0])
        self.assertEqual(b"/usr/bin/passwd local-rescue\n", observed[1])
        self.assertEqual(password + b"\n", observed[2])
        self.assertEqual(password + b"\n", observed[3])
        self.assertEqual(
            b"exec /usr/lib/systemd/systemd\n", observed[4])
        self.assertEqual(b"local-rescue\n", observed[5])
        self.assertEqual(password + b"\n", observed[6])
        self.assertNotIn(password, observed[0])
        self.assertIn(b"systemctl is-active --quiet", observed[7])


if __name__ == "__main__":
    unittest.main()
