import io
import socket
import sys
import threading
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "vm"))
NONCE = "a" * 64

from controller_factory_install import (  # noqa: E402
    DisposableFactoryController,
    FactoryConvergenceSerial,
    FactoryInstallSerial,
    FactoryInstallResult,
    RedactedSerialCapture,
    run_convergence,
    run_install,
)


class ConstructionTests(unittest.TestCase):
    def test_rejects_blank_or_multiline_password(self):
        for password in (b"", b"a\nb", b"a\rb"):
            with self.subTest(password=password):
                with self.assertRaises(ValueError):
                    FactoryInstallSerial(io.BytesIO(), io.BytesIO(), password)
                with self.assertRaises(ValueError):
                    FactoryConvergenceSerial(
                        io.BytesIO(), io.BytesIO(), password, NONCE)

    def test_result_does_not_carry_password_or_transcript(self):
        self.assertEqual(
            ("installed", "powered_off", "events"),
            tuple(FactoryInstallResult.__dataclass_fields__))

    def test_diagnostic_capture_is_private_bounded_and_redacts_split_secrets(self):
        import tempfile
        with tempfile.TemporaryDirectory() as name:
            path = Path(name) / "serial.log"
            source = io.BytesIO(b"before secr" b"et after nonce tail")
            capture = RedactedSerialCapture(
                source, path, (b"secret", b"nonce"), limit=24)
            while capture.read1(4):
                pass
            content = path.read_bytes()
            self.assertNotIn(b"secret", content)
            self.assertNotIn(b"nonce", content)
            self.assertLessEqual(len(content), 24)
            self.assertEqual(0o600, path.stat().st_mode & 0o777)


class ProtocolTests(unittest.TestCase):
    def run_script(self, responder):
        left, right = socket.socketpair()
        thread = threading.Thread(target=responder, args=(right,), daemon=True)
        thread.start()
        try:
            result = FactoryInstallSerial(
                left.makefile("rb", buffering=0),
                left.makefile("wb", buffering=0),
                b"ephemeral-password",
                timeout=1,
            ).run()
        finally:
            left.close()
            right.close()
        thread.join(timeout=1)
        self.assertFalse(thread.is_alive())
        return result

    def test_drives_exact_disk_confirmation_and_console_password(self):
        commands = []

        def responder(sock):
            stream = sock.makefile("rb", buffering=0)
            sock.sendall(b"archiso login: ")
            commands.append(stream.readline())
            sock.sendall(b"root@archiso ~ # ")
            commands.append(stream.readline())
            token = commands[-1].split(b"__TELOS_SEED_", 1)[1].split(b"__", 1)[0]
            sock.sendall(b"seed receipt verified\n__TELOS_SEED_" + token + b"__\n# ")
            commands.append(stream.readline())
            sock.sendall(
                b"Type ERASE TELOS-BOOTSTRAP-DC1 to continue: ")
            commands.append(stream.readline())
            sock.sendall(b"New password: ")
            commands.append(stream.readline())
            sock.sendall(b"Retype new password: ")
            commands.append(stream.readline())
            sock.sendall(
                b"passwd: password updated successfully\n"
                b"Controller installation complete. Remove both ISOs and reboot.\n# ")
            commands.append(stream.readline())
            sock.sendall(b"Reached target System Power Off.\n")

        result = self.run_script(responder)
        self.assertTrue(result.installed)
        self.assertTrue(result.powered_off)
        self.assertEqual(b"root\n", commands[0])
        self.assertEqual(
            b"ERASE TELOS-BOOTSTRAP-DC1\n", commands[3])
        self.assertEqual(b"ephemeral-password\n", commands[4])
        self.assertEqual(b"ephemeral-password\n", commands[5])
        self.assertNotIn(b"ephemeral-password", commands[0])
        self.assertNotIn(b"ephemeral-password", commands[2])

    def test_convergence_uses_stdin_secret_and_requires_exact_pass(self):
        commands = []
        left, right = socket.socketpair()

        def responder(sock):
            stream = sock.makefile("rb", buffering=0)
            sock.sendall(b"bootstrap-dc login: ")
            commands.append(stream.readline())
            sock.sendall(b"Password: ")
            commands.append(stream.readline())
            sock.sendall(b"[local-rescue@bootstrap-dc ~]$ ")
            commands.append(stream.readline())
            prompt = commands[-1].split(
                b"__TELOS_FACTORY_SUDO_", 1)[1].split(b"__", 1)[0]
            result = commands[-1].split(
                b"__TELOS_FACTORY_RC_", 1)[1].split(b"=", 1)[0]
            # Echoing the command exposes the prompt token in the middle of a
            # line.  The driver must not send the password until the real,
            # standalone sudo prompt follows.
            sock.sendall(commands[-1].rstrip() + b"\r\n")
            with self.assertRaises(BlockingIOError):
                sock.recv(1, socket.MSG_DONTWAIT)
            sock.sendall(b"__TELOS_FACTORY_SUDO_" + prompt + b"__")
            commands.append(stream.readline())
            sock.sendall(
                b"TELOS FACTORY CONTROLLER PASS\n"
                b"__TELOS_FACTORY_RC_" + result + b"=0\n"
                b"[local-rescue@bootstrap-dc ~]$ ")
            commands.append(stream.readline())
            sock.sendall(b"Reached target System Power Off.\n")

        thread = threading.Thread(target=responder, args=(right,), daemon=True)
        thread.start()
        try:
            result = FactoryConvergenceSerial(
                left.makefile("rb", buffering=0),
                left.makefile("wb", buffering=0),
                b"ephemeral-password", NONCE, timeout=1).run()
        finally:
            left.close()
            right.close()
        thread.join(timeout=1)
        self.assertTrue(result.converged)
        self.assertEqual(b"local-rescue\n", commands[0])
        self.assertEqual(b"ephemeral-password\n", commands[1])
        self.assertEqual(b"ephemeral-password\n", commands[3])
        self.assertNotIn(b"ephemeral-password", commands[2])


class CommandBoundaryTests(unittest.TestCase):
    def state(self):
        instance = object.__new__(DisposableFactoryController)
        instance.arch_iso = Path("/media/arch.iso")
        instance.seed_iso = Path("/media/seed.iso")
        instance.root = Path("/private/run")
        instance.disk = instance.root / "controller.raw"
        instance.vars = instance.root / "OVMF_VARS.fd"
        instance.kernel = instance.root / "vmlinuz-linux"
        instance.initramfs = instance.root / "initramfs-linux.img"
        instance.arch_label = "ARCH_202607"
        instance.code = Path("/usr/share/OVMF_CODE.fd")
        instance.prepared = True
        return instance

    def test_install_has_no_network_backend_and_read_only_media(self):
        command = self.state().install_command()
        joined = " ".join(command)
        self.assertIn("-nic none", joined)
        self.assertIn("-kernel /private/run/vmlinuz-linux", joined)
        self.assertIn("archisolabel=ARCH_202607", joined)
        self.assertNotIn("-netdev", command)
        self.assertIn("serial=TELOS-BOOTSTRAP-DC1", joined)
        self.assertIn("readonly=on,file=/media/arch.iso", joined)
        self.assertIn("readonly=on,file=/media/seed.iso", joined)

    def test_convergence_connects_only_to_loopback_and_attaches_bundle_readonly(self):
        state = self.state()
        state._factory_media = lambda path: Path("/private/factory.iso")
        command = state.convergence_command(
            Path("/private/factory.iso"), 31111)
        joined = " ".join(command)
        self.assertIn(
            "socket,id=simnet,connect=127.0.0.1:31111", joined)
        self.assertIn("readonly=on,file=/private/factory.iso", joined)
        self.assertIn("mac=52:54:00:11:11:12", joined)
        self.assertNotIn("user,", joined)
        self.assertNotIn("tap,", joined)

    def test_process_runner_never_places_password_in_qemu_argv(self):
        state = self.state()
        process = MagicMock()
        process.stdin = io.BytesIO()
        process.stdout = io.BytesIO()
        process.wait.return_value = 0
        with patch("controller_factory_install.subprocess.Popen",
                   return_value=process) as popen, patch.object(
                       FactoryInstallSerial, "run",
                       return_value=FactoryInstallResult(True, True, ())):
            run_install(state, b"secret")
        self.assertNotIn("secret", " ".join(popen.call_args.args[0]))


if __name__ == "__main__":
    unittest.main()
