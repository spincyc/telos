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


class ControllerSeedProtocolTests(unittest.TestCase):
    def run_seed(self, responder):
        left, right = socket.socketpair()
        reader = left.makefile("rb", buffering=0)
        writer = left.makefile("wb", buffering=0)
        thread = threading.Thread(target=responder, args=(right,), daemon=True)
        thread.start()
        automation = SerialAutomation(
            reader, writer, b"ephemeral-password", timeout=1.0)
        try:
            automation.install_offline_controller_dependencies(timeout=1.0)
        finally:
            left.close()
            right.close()
        thread.join(timeout=1)
        self.assertFalse(thread.is_alive())
        return automation

    def test_verifies_installs_probes_and_releases_seed(self):
        commands = []

        def responder(sock):
            stream = sock.makefile("rb", buffering=0)
            sock.sendall(b"[local-rescue@bootstrap-dc ~]$ ")
            self.assertEqual(stream.readline(), b"\n")
            commands.append(stream.readline())
            prompt = commands[0].split(
                b"__TELOS_SEED_SUDO_", 1)[1].split(b"__", 1)[0]
            result = commands[0].split(
                b"__TELOS_SEED_RC_", 1)[1].split(b"=", 1)[0]
            verified = commands[0].split(
                b"__TELOS_SEED_VERIFIED_", 1)[1].split(b"__", 1)[0]
            installed = commands[0].split(
                b"__TELOS_SEED_INSTALLED_", 1)[1].split(b"__", 1)[0]
            packages = commands[0].split(
                b"__TELOS_SEED_PACKAGES_", 1)[1].split(b"__", 1)[0]
            imported = commands[0].split(
                b"__TELOS_SEED_IMPORT_", 1)[1].split(b"__", 1)[0]
            released = commands[0].split(
                b"__TELOS_SEED_RELEASED_", 1)[1].split(b"=", 1)[0]
            sock.sendall(b"\r__TELOS_SEED_SUDO_" + prompt + b"__")
            self.assertEqual(
                stream.readline(), b"ephemeral-password\n")
            sock.sendall(
                b"__TELOS_SEED_VERIFIED_" + verified + b"__\r\n"
                b"__TELOS_SEED_INSTALLED_" + installed + b"__\r\n"
                b"__TELOS_SEED_PACKAGES_" + packages + b"__\r\n"
                b"__TELOS_SEED_IMPORT_" + imported + b"__\r\n"
                b"__TELOS_SEED_RELEASED_" + released + b"=0\r\n"
                b"__TELOS_SEED_RC_" + result + b"=0\r\n")
            self.assertEqual(stream.readline(), b"\n")
            sock.sendall(b"\n[local-rescue@bootstrap-dc ~]$ ")

        automation = self.run_seed(responder)
        self.assertIn(b"mount -o ro -L TELOS_SEED", commands[0])
        self.assertIn(b"verify-seed", commands[0])
        self.assertIn(b"install-controller-deps", commands[0])
        self.assertIn(b"import dns, dns.resolver", commands[0])
        self.assertIn(b"umount /run/telos-seed", commands[0])
        self.assertEqual(commands[0].count(b"__TELOS_SEED_RC_"), 1)
        self.assertNotIn(b"ephemeral-password", b"".join(commands))
        self.assertIn(
            "controller-seed-post-shell-ready", automation.events)

    def failure_responder(
        self, *, markers=(), returncode=b"1", release_code=b"0",
        split_returncode=False,
    ):
        def responder(sock):
            stream = sock.makefile("rb", buffering=0)
            sock.sendall(b"[local-rescue@bootstrap-dc ~]$ ")
            stream.readline()
            command = stream.readline()
            prompt = command.split(
                b"__TELOS_SEED_SUDO_", 1)[1].split(b"__", 1)[0]
            result = command.split(
                b"__TELOS_SEED_RC_", 1)[1].split(b"=", 1)[0]
            released = command.split(
                b"__TELOS_SEED_RELEASED_", 1)[1].split(b"=", 1)[0]
            sock.sendall(b"__TELOS_SEED_SUDO_" + prompt + b"__")
            stream.readline()
            for marker in markers:
                token = command.split(marker, 1)[1].split(b"__", 1)[0]
                sock.sendall(marker + token + b"__\r\n")
            sock.sendall(
                b"__TELOS_SEED_RELEASED_" + released + b"="
                + release_code + b"\r\n")
            final = (
                b"__TELOS_SEED_RC_" + result + b"=" + returncode + b"\r\n")
            if split_returncode:
                sock.sendall(final[:-1])
                sock.sendall(final[-1:])
            else:
                sock.sendall(final)
        return responder

    def test_verify_failure_returns_after_release(self):
        with self.assertRaisesRegex(
                SerialAutomationError, "installation returned 7"):
            self.run_seed(self.failure_responder(returncode=b"7"))

    def test_package_failure_after_receipt_returns_after_release(self):
        with self.assertRaisesRegex(
                SerialAutomationError, "installation returned 9"):
            self.run_seed(self.failure_responder(
                markers=(
                    b"__TELOS_SEED_VERIFIED_",
                    b"__TELOS_SEED_INSTALLED_",
                ),
                returncode=b"9",
            ))

    def test_result_requires_complete_newline_terminated_bytes(self):
        with self.assertRaisesRegex(
                SerialAutomationError, "installation returned 12"):
            self.run_seed(self.failure_responder(
                returncode=b"12", split_returncode=True))

    def test_release_failure_is_distinct(self):
        with self.assertRaisesRegex(
                SerialAutomationError, "media release failed"):
            self.run_seed(self.failure_responder(
                returncode=b"0", release_code=b"5"))

    def test_zero_result_without_all_exact_proofs_fails_closed(self):
        with self.assertRaisesRegex(
                SerialAutomationError, "success proof is incomplete"):
            self.run_seed(self.failure_responder(
                markers=(
                    b"__TELOS_SEED_VERIFIED_",
                    b"__TELOS_SEED_INSTALLED_",
                    b"__TELOS_SEED_PACKAGES_",
                ),
                returncode=b"0",
            ))


if __name__ == "__main__":
    unittest.main()
