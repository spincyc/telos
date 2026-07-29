import base64
import socket
import threading
import unittest
from unittest import mock

from homelab.vm import controller_join_material
from homelab.vm.controller_join_material import (
    ControllerJoinFailureCoordinate,
    ControllerJoinMaterialError,
    ControllerJoinResult,
    ControllerJoinSerial,
    OneUseDomainJoinMaterial,
)


SECRET = "Join-secret-DoNotDisclose-47!"


class ControllerJoinSerialTests(unittest.TestCase):
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
                b"__TELOS_JOIN_READY_", 1)[1].split(b"__", 1)[0]
            result = command.split(
                b"__TELOS_JOIN_RC_", 1)[1].split(b"=", 1)[0]
            right.sendall(command)
            right.sendall(b"__TELOS_JOIN_READY_" + token + b"__\r\n")
            observed.append(stream.readline())
            if sudo_password is not None:
                prompt = command.split(
                    b"__TELOS_JOIN_SUDO_", 1)[1].split(b"__", 1)[0]
                right.sendall(
                    b"\r\n__TELOS_JOIN_SUDO_" + prompt + b"__\r\n")
                observed.append(stream.readline())
            right.sendall(
                b"\r\n__TELOS_JOIN_RC_" + result + b"="
                + str(returncode).encode() + b"\r\n")

        thread = threading.Thread(target=responder, daemon=True)
        thread.start()
        try:
            serial = ControllerJoinSerial(
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

    def test_stage_delivers_secret_only_in_echo_suppressed_stdin(self):
        result, observed = self.run_operation(
            lambda serial: serial.stage(SECRET))
        self.assertEqual("stage", result.operation)
        self.assertFalse(result.destruction_proved)
        self.assertIn(b"stty -echo || exit 91", observed[0])
        self.assertIn(b"sudo -n python3", observed[0])
        self.assertNotIn(SECRET.encode(), observed[0])
        payload = __import__("json").loads(base64.b64decode(observed[1]))
        self.assertEqual(SECRET, payload.pop("credential"))
        self.assertRegex(payload["principal"], r"^tj-[0-9a-f]{16}$")
        self.assertRegex(payload["ownership_token"], r"^[0-9a-f]{64}$")
        self.assertNotIn(SECRET, repr(result))

    def test_destroy_program_requires_verified_absence(self):
        result, observed = self.run_operation(
            lambda serial: serial.destroy())
        self.assertTrue(result.destruction_proved)
        self.assertIn(b"samdb.deleteuser", base64.b64decode(
            observed[0].split(
                b"exec(base64.b64decode('", 1)[1].split(b"'))", 1)[0]))
        self.assertNotIn(SECRET.encode(), b"".join(observed))
        payload = __import__("json").loads(base64.b64decode(observed[1]))
        self.assertEqual(result.principal, payload["principal"])
        self.assertRegex(payload["ownership_token"], r"^[0-9a-f]{64}$")

    def test_password_authenticated_sudo_is_secret_safe(self):
        password = b"Controller-private-47!"
        result, observed = self.run_operation(
            lambda serial: serial.stage(SECRET), sudo_password=password)
        self.assertEqual("stage", result.operation)
        self.assertIn(b"sudo -k -p", observed[0])
        self.assertNotIn(b"sudo -S", observed[0])
        self.assertNotIn(password, observed[0])
        self.assertEqual(password + b"\n", observed[2])

    def test_stage_and_destroy_share_unique_ownership_identity(self):
        left = __import__("io").BytesIO()
        serial_a = ControllerJoinSerial(left, __import__("io").BytesIO())
        serial_b = ControllerJoinSerial(left, __import__("io").BytesIO())
        self.assertNotEqual(serial_a._principal, serial_b._principal)
        self.assertNotEqual(
            serial_a._ownership_token, serial_b._ownership_token)

    def test_programs_reconcile_stage_and_require_token_before_destroy(self):
        stage = controller_join_material._STAGE_PROGRAM
        destroy = controller_join_material._DESTROY_PROGRAM
        self.assertIn("if results:", stage)
        self.assertIn("descriptions != [marker]", stage)
        self.assertIn("description=marker", stage)
        self.assertIn(
            'expected_upn = values["principal"] + "@" + '
            'str(lp.get("realm")).upper()',
            stage,
        )
        self.assertIn("FLAG_MOD_REPLACE", stage)
        self.assertIn("upns != [expected_upn]", stage)
        self.assertLess(
            destroy.index("descriptions != [marker]"),
            destroy.index("samdb.deleteuser"))

    def test_guest_failure_is_secret_free_and_fail_closed(self):
        with self.assertRaisesRegex(
                ControllerJoinMaterialError,
                "join-material.stage.return-code") as caught:
            self.run_operation(
                lambda serial: serial.stage(SECRET), returncode=7)
        self.assertNotIn(SECRET, str(caught.exception))
        self.assertEqual(
            ControllerJoinFailureCoordinate(
                "stage", "return-code", "ControllerJoinReturnCode"),
            caught.exception.coordinate,
        )
        self.assertNotIn("returned 7", str(caught.exception))

    def test_timeout_is_normalized_at_an_allowlisted_safe_subphase(self):
        serial = ControllerJoinSerial(
            __import__("io").BytesIO(), __import__("io").BytesIO())
        serial.console._send = mock.Mock()
        serial.console._wait = mock.Mock(
            side_effect=controller_join_material.SerialAutomationError(
                "timed out waiting for private-value-" + SECRET))

        with self.assertRaises(ControllerJoinMaterialError) as caught:
            serial.stage(SECRET)

        self.assertEqual(
            ControllerJoinFailureCoordinate(
                "stage", "shell-prompt", "TimeoutError"),
            caught.exception.coordinate,
        )
        self.assertEqual(
            "Controller join stage protocol failed; "
            "operation=join-material.stage.shell-prompt; "
            "error=TimeoutError",
            str(caught.exception),
        )
        self.assertNotIn(SECRET, str(caught.exception))
        self.assertIsNone(caught.exception.__cause__)
        self.assertIsNone(caught.exception.__context__)

    def test_destroy_io_failure_does_not_copy_private_exception_context(self):
        serial = ControllerJoinSerial(
            __import__("io").BytesIO(), __import__("io").BytesIO())
        serial.console._send = mock.Mock(
            side_effect=OSError("private-value-" + SECRET))

        with self.assertRaises(ControllerJoinMaterialError) as caught:
            serial.destroy()

        self.assertEqual(
            ControllerJoinFailureCoordinate(
                "destroy", "shell-prompt-request", "OSError"),
            caught.exception.coordinate,
        )
        self.assertNotIn(SECRET, str(caught.exception))
        self.assertIsNone(caught.exception.__cause__)
        self.assertIsNone(caught.exception.__context__)

    def test_unexpected_protocol_failure_is_normalized(self):
        serial = ControllerJoinSerial(
            __import__("io").BytesIO(), __import__("io").BytesIO())
        serial.console._send = mock.Mock(
            side_effect=ValueError("private-value-" + SECRET))

        with self.assertRaises(ControllerJoinMaterialError) as caught:
            serial.stage(SECRET)

        self.assertEqual(
            ControllerJoinFailureCoordinate(
                "stage", "shell-prompt-request", "UnexpectedError"),
            caught.exception.coordinate,
        )
        self.assertNotIn("ValueError", str(caught.exception))
        self.assertNotIn(SECRET, str(caught.exception))


class OneUseDomainJoinMaterialTests(unittest.TestCase):
    def result(self, operation, destroyed=False):
        return ControllerJoinResult(
            operation, "tj-0123456789abcdef", destroyed, ())

    def test_material_is_available_once_and_destroyed_after_consumption(self):
        observed = []
        stage = mock.Mock(side_effect=lambda secret: (
            observed.append(secret), self.result("stage"))[1])
        destroy = mock.Mock(return_value=self.result("destroy", True))
        material = OneUseDomainJoinMaterial(
            "synthetic.test", stage=stage, destroy=destroy)

        with mock.patch.object(
                material, "_generate", return_value=SECRET):
            value, proof = material.use(
                lambda values: observed.append(dict(values)) or "joined")

        self.assertEqual("joined", value)
        self.assertTrue(proof.destruction_proved)
        self.assertEqual(SECRET, observed[0])
        self.assertEqual(SECRET, observed[1]["credential"])
        self.assertEqual(
            "operator@SYNTHETIC.TEST", observed[1]["operator"])
        self.assertNotIn(SECRET, repr(material))
        with self.assertRaisesRegex(
                ControllerJoinMaterialError, "one-use"):
            material.use(lambda _values: None)

    def test_consumer_failure_still_destroys_and_redacts_errors(self):
        material = OneUseDomainJoinMaterial(
            "synthetic.test",
            stage=lambda _secret: self.result("stage"),
            destroy=lambda: self.result("destroy", True),
        )

        def fail(_values):
            raise RuntimeError("failure exposed " + SECRET)

        with mock.patch.object(
                material, "_generate", return_value=SECRET):
            with self.assertRaisesRegex(
                    ControllerJoinMaterialError,
                    "stage/consumer: RuntimeError") as caught:
                material.use(fail)
        self.assertNotIn(SECRET, str(caught.exception))

    def test_lost_stage_acknowledgement_attempts_ownership_bound_cleanup(self):
        destroy = mock.Mock(return_value=self.result("destroy", True))
        material = OneUseDomainJoinMaterial(
            "synthetic.test",
            stage=mock.Mock(side_effect=RuntimeError(SECRET)),
            destroy=destroy,
        )
        with self.assertRaisesRegex(
                ControllerJoinMaterialError, "stage/consumer"):
            material.use(lambda _values: None)
        destroy.assert_called_once_with()
        self.assertNotIn("cleanup-pending", repr(material))

    def test_destruction_failure_does_not_claim_proof(self):
        destroy = mock.Mock(side_effect=[
            self.result("destroy", False),
            self.result("destroy", True),
        ])
        material = OneUseDomainJoinMaterial(
            "synthetic.test",
            stage=lambda _secret: self.result("stage"),
            destroy=destroy,
        )
        with self.assertRaisesRegex(
                ControllerJoinMaterialError, "destruction"):
            material.use(lambda _values: None)
        self.assertIn("cleanup-pending", repr(material))
        self.assertTrue(material.retry_destruction().destruction_proved)
        self.assertNotIn("cleanup-pending", repr(material))
        with self.assertRaisesRegex(
                ControllerJoinMaterialError, "not pending"):
            material.retry_destruction()

    def test_stage_and_destroy_failure_coordinates_are_both_preserved(self):
        stage_coordinate = ControllerJoinFailureCoordinate(
            "stage", "return-code", "ControllerJoinReturnCode")
        destroy_coordinate = ControllerJoinFailureCoordinate(
            "destroy", "shell-prompt", "TimeoutError")
        material = OneUseDomainJoinMaterial(
            "synthetic.test",
            stage=mock.Mock(side_effect=ControllerJoinMaterialError(
                "private-stage-" + SECRET, coordinate=stage_coordinate)),
            destroy=mock.Mock(side_effect=ControllerJoinMaterialError(
                "private-destroy-" + SECRET,
                coordinate=destroy_coordinate)),
        )

        with self.assertRaises(ControllerJoinMaterialError) as caught:
            material.use(lambda _values: None)

        self.assertIs(stage_coordinate, caught.exception.coordinate)
        self.assertIs(
            destroy_coordinate, caught.exception.cleanup_coordinate)
        self.assertNotIn(SECRET, str(caught.exception))
        self.assertIsNone(caught.exception.__cause__)
        self.assertIsNone(caught.exception.__context__)

    def test_rejects_invalid_realms_and_multiline_credentials(self):
        with self.assertRaisesRegex(ValueError, "realm"):
            OneUseDomainJoinMaterial(
                "unsafe realm", stage=mock.Mock(), destroy=mock.Mock())
        serial = ControllerJoinSerial(
            __import__("io").BytesIO(), __import__("io").BytesIO())
        with self.assertRaisesRegex(ValueError, "credential"):
            serial.stage("unsafe\nsecret")


if __name__ == "__main__":
    unittest.main()
