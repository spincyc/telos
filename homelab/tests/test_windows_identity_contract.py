import socket
import tempfile
import unittest
from pathlib import Path

from homelab.vm.windows_control_serial import WindowsControlSerialError
from homelab.vm.windows_identity_contract import qemu_identity_command


class WindowsIdentityContractTests(unittest.TestCase):
    def test_live_reconstruction_accepts_the_running_serial_socket(self):
        # The mid-run acceptance secret scan re-derives the argv while the
        # private COM1 server socket already exists. Launch-time construction
        # demands the socket be absent; reconstruction demands a live private
        # socket and yields identical argv so authorization comparison holds.
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            disk = root / "windows.qcow2"
            variables = root / "OVMF_VARS.fd"
            control = root / "control.iso"
            for path in (disk, variables, control):
                path.write_bytes(path.name.encode())
            control.chmod(0o444)
            kwargs = dict(
                disk=disk, variables=variables,
                qmp_socket=root / "windows.qmp", switch_port=31415,
                serial_socket=root / "windows.serial", control_iso=control)
            launch = qemu_identity_command(**kwargs)
            # Reconstruction before QEMU created the socket must fail closed.
            with self.assertRaisesRegex(
                    WindowsControlSerialError, "live private socket"):
                qemu_identity_command(
                    **kwargs, require_absent_serial_socket=False)
            server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            self.addCleanup(server.close)
            server.bind(str(root / "windows.serial"))
            reconstructed = qemu_identity_command(
                **kwargs, require_absent_serial_socket=False)
            self.assertEqual(launch, reconstructed)

    def test_command_boots_only_overlay_and_optional_read_only_control_iso(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            disk = root / "windows.qcow2"
            variables = root / "OVMF_VARS.fd"
            control = root / "control.iso"
            for path in (disk, variables, control):
                path.write_bytes(path.name.encode())
            control.chmod(0o444)
            original_control = control.read_bytes()
            command = qemu_identity_command(
                disk=disk, variables=variables,
                qmp_socket=root / "windows.qmp", switch_port=31415,
                serial_socket=root / "windows.serial",
                control_iso=control)
            joined = " ".join(command)
            self.assertIn("-boot menu=off,strict=on", joined)
            self.assertNotIn("order=", joined)
            self.assertNotIn("once=", joined)
            self.assertEqual(1, joined.count("bootindex="))
            self.assertIn(
                "nvme,drive=osdisk,serial=TELOS-WIN-0001,bootindex=1",
                command,
            )
            self.assertIn("e1000e,netdev=factory", joined)
            self.assertIn(",romfile=", joined)
            nic = next(
                value for value in command
                if value.startswith("e1000e,netdev=factory,"))
            self.assertNotIn("bootindex=", nic)
            self.assertIn(f"file={disk.resolve()}", joined)
            self.assertIn(f"file={control.resolve()}", joined)
            self.assertIn("media=cdrom,readonly=on", joined)
            self.assertIn(
                "ide-cd,bus=ide.1,drive=controlmedia,"
                "id=telos-control-cd",
                command)
            self.assertNotIn("virtio-scsi", joined)
            self.assertNotIn("scsi-cd", joined)
            self.assertIn("qemu-xhci,id=identityusb", command)
            self.assertNotIn("bus=identityusb.0", joined)
            writable = [
                command[index + 1]
                for index, item in enumerate(command[:-1])
                if item == "-drive"
                and "readonly=on" not in command[index + 1]
                and "if=pflash" not in command[index + 1]
            ]
            self.assertEqual(1, len(writable))
            self.assertEqual(original_control, control.read_bytes())
            self.assertEqual(0o444, control.stat().st_mode & 0o777)

    def test_command_rejects_missing_or_symlinked_inputs(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            disk = root / "windows.qcow2"
            variables = root / "OVMF_VARS.fd"
            disk.write_bytes(b"disk")
            variables.symlink_to(root / "missing")
            with self.assertRaisesRegex(ValueError, "OVMF"):
                qemu_identity_command(
                    disk=disk, variables=variables,
                    qmp_socket=root / "windows.qmp",
                    serial_socket=root / "windows.serial",
                    switch_port=31415)

    def test_command_rejects_a_writable_control_iso(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            disk = root / "windows.qcow2"
            variables = root / "OVMF_VARS.fd"
            control = root / "control.iso"
            for path in (disk, variables, control):
                path.write_bytes(path.name.encode())
            with self.assertRaisesRegex(ValueError, "read-only"):
                qemu_identity_command(
                    disk=disk, variables=variables,
                    qmp_socket=root / "windows.qmp",
                    serial_socket=root / "windows.serial",
                    switch_port=31415,
                    control_iso=control)


if __name__ == "__main__":
    unittest.main()
