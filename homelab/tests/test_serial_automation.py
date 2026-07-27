import io
import socket
import sys
import threading
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "vm"))

from serial_automation import (
    ANSI, PASS_LINE, SerialAutomation, SerialAutomationError, normalized,
)


class NormalizationTests(unittest.TestCase):
    def test_removes_ansi_and_normalizes_carriage_returns(self):
        value = b"\x1b[31mPASS\x1b[0m\r\nnext\r"
        self.assertEqual(normalized(value), "PASS\nnext\n")

    def test_ansi_expression_does_not_consume_plain_output(self):
        self.assertEqual(ANSI.sub(b"", b"RESULT PASS"), b"RESULT PASS")

    def test_adjacent_osc_records_do_not_consume_plain_output_between_them(self):
        value = (
            b"\x1b]3008;start=x\x1b\\"
            b"__TELOS_FACTORY_RC_token=1\r\n"
            b"\x1b]3008;end=x\x1b\\")
        self.assertIn(
            b"__TELOS_FACTORY_RC_token=1", ANSI.sub(b"", value))


class ConstructionTests(unittest.TestCase):
    def test_rejects_blank_and_multiline_credentials(self):
        for password in (b"", b"a\nb", b"a\rb"):
            with self.subTest(password=password):
                with self.assertRaises(ValueError):
                    SerialAutomation(io.BytesIO(), io.BytesIO(), password)

    def test_password_is_not_exposed_by_result_shape(self):
        fields = SerialAutomation.__init__.__annotations__
        self.assertNotIn("result", fields)
        self.assertNotIn("transcript", fields)

    def test_none_selects_disposable_autologin_mode(self):
        automation = SerialAutomation(io.BytesIO(), io.BytesIO(), None)
        self.assertIsNone(automation.password)

    def test_protocol_uses_exact_installed_result(self):
        self.assertEqual(
            PASS_LINE,
            "RESULT PASS: safe to proceed to the separately authorized "
            "attachment step",
        )


class ProtocolTests(unittest.TestCase):
    def run_script(self, responder):
        left, right = socket.socketpair()
        reader = left.makefile("rb", buffering=0)
        writer = left.makefile("wb", buffering=0)
        thread = threading.Thread(target=responder, args=(right,), daemon=True)
        thread.start()
        try:
            result = SerialAutomation(
                reader, writer, None, timeout=1.0).run()
        finally:
            left.close()
            right.close()
        thread.join(timeout=1)
        self.assertFalse(thread.is_alive())
        return result

    def test_fragmented_ansi_console_is_accepted_without_password(self):
        commands = []

        def responder(sock):
            stream = sock.makefile("rb", buffering=0)
            sock.sendall(b"\x1b[32m[local-rescue@bootstrap-dc ~]$")
            sock.sendall(b"\x1b[0m ")
            commands.append(stream.readline())
            begin = commands[0].split(
                b"__TELOS_BEGIN_", 1)[1].split(b"__", 1)[0]
            token = commands[0].split(b"__TELOS_RC_", 1)[1].split(b"=", 1)[0]
            sock.sendall(b"__TELOS_BEGIN_" + begin + b"__\r\n")
            sock.sendall((PASS_LINE + "\r\n").encode())
            sock.sendall(b"__TELOS_RC_" + token + b"=0\r\n")
            sock.sendall(b"[local-rescue@bootstrap-dc ~]$ ")
            commands.append(stream.readline())
            power = commands[1].split(
                b"__TELOS_POWEROFF_", 1)[1].split(b"__", 1)[0]
            sock.sendall(b"__TELOS_POWEROFF_" + power + b"__\r\n")
            sock.sendall(b"[ OK ] Reached target System Power Off.\r\n")

        result = self.run_script(responder)
        self.assertTrue(result.helper_passed)
        self.assertTrue(result.powered_off)
        self.assertIn(b"sudo -n ", commands[0])
        self.assertNotIn(b"-S", commands[0])
        self.assertEqual(
            b"sudo -n /usr/bin/systemctl poweroff\n",
            commands[1][-len(b"sudo -n /usr/bin/systemctl poweroff\n"):],
        )

    def test_pass_line_with_nonzero_result_is_rejected(self):
        def responder(sock):
            stream = sock.makefile("rb")
            sock.sendall(b"[local-rescue@bootstrap-dc ~]$ ")
            command = stream.readline()
            begin = command.split(
                b"__TELOS_BEGIN_", 1)[1].split(b"__", 1)[0]
            token = command.split(b"__TELOS_RC_", 1)[1].split(b"=", 1)[0]
            sock.sendall(b"__TELOS_BEGIN_" + begin + b"__\n")
            sock.sendall((PASS_LINE + "\n").encode())
            sock.sendall(b"__TELOS_RC_" + token + b"=1\n")

        with self.assertRaisesRegex(
                SerialAutomationError, "printed PASS but returned 1"):
            self.run_script(responder)

    def test_near_miss_pass_line_times_out(self):
        def responder(sock):
            stream = sock.makefile("rb")
            sock.sendall(b"[local-rescue@bootstrap-dc ~]$ ")
            command = stream.readline()
            begin = command.split(
                b"__TELOS_BEGIN_", 1)[1].split(b"__", 1)[0]
            sock.sendall(b"__TELOS_BEGIN_" + begin + b"__\n")
            sock.sendall(b"RESULT PASS: almost\n")

        left, right = socket.socketpair()
        thread = threading.Thread(target=responder, args=(right,), daemon=True)
        thread.start()
        with self.assertRaises(SerialAutomationError):
            SerialAutomation(
                left.makefile("rb", buffering=0),
                left.makefile("wb", buffering=0),
                None,
                timeout=0.05,
            ).run()
        left.close()
        right.close()

    def test_stale_pass_before_unique_begin_does_not_satisfy_protocol(self):
        def responder(sock):
            stream = sock.makefile("rb")
            sock.sendall(
                b"[local-rescue@bootstrap-dc ~]$ \n"
                + PASS_LINE.encode() + b"\n")
            command = stream.readline()
            begin = command.split(
                b"__TELOS_BEGIN_", 1)[1].split(b"__", 1)[0]
            token = command.split(b"__TELOS_RC_", 1)[1].split(b"=", 1)[0]
            sock.sendall(b"__TELOS_BEGIN_" + begin + b"__\n")
            sock.sendall(b"__TELOS_RC_" + token + b"=0\n")

        with self.assertRaises(SerialAutomationError):
            self.run_script(responder)


if __name__ == "__main__":
    unittest.main()
