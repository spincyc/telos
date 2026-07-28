import tempfile
import unittest
from pathlib import Path
import socket
from unittest import mock

from homelab.vm import windows_identity_adapter as subject


class WindowsIdentityAdapterTests(unittest.TestCase):
    def adapter(self, root: Path, boundary=None):
        root.chmod(0o700)
        if boundary is None:
            boundary = mock.Mock()
            boundary.processes = {}
            boundary.qmp = None
            boundary.serial_socket = None
        return subject.NativeWindowsAcceptanceAdapter(
            boundary,
            root,
            realm="factory.test",
            local_principal="telosadmin",
            scan_secrets=mock.sentinel.scanner,
            timeout=1,
        )

    def test_callbacks_bind_exact_adapter_methods(self):
        with tempfile.TemporaryDirectory() as name:
            adapter = self.adapter(Path(name))
            callbacks = adapter.callbacks()
            self.assertEqual("telosadmin", callbacks.local_principal)
            self.assertIs(mock.sentinel.scanner, callbacks.scan_secrets)
            self.assertEqual(adapter.launch_guest, callbacks.launch_guest)
            self.assertEqual(
                adapter.await_device_deleted,
                callbacks.await_device_deleted,
            )
            self.assertEqual(
                adapter.reauthenticate_local,
                callbacks.reauthenticate_local,
            )

    def test_guest_launch_fails_closed_without_run_dialog_reference(self):
        with tempfile.TemporaryDirectory() as name:
            adapter = self.adapter(Path(name))
            with self.assertRaisesRegex(
                    subject.WindowsIdentityAdapterError, "Run-dialog"):
                adapter.launch_guest("powershell.exe -NoProfile")

    def test_device_deletion_awaits_exact_qmp_event(self):
        with tempfile.TemporaryDirectory() as name:
            process = mock.Mock()
            process.poll.return_value = None
            qmp = mock.Mock()
            qmp.await_device_deleted.return_value = {
                "event": "DEVICE_DELETED",
                "data": {"device": "telos-join-cd"},
            }
            boundary = mock.Mock(
                processes={"windows": process}, qmp=qmp,
                serial_socket=None,
            )
            adapter = self.adapter(Path(name), boundary)
            adapter.await_device_deleted("telos-join-cd")
            qmp.await_device_deleted.assert_called_once_with(
                "telos-join-cd", timeout=1)

    def test_device_deletion_rejects_wrong_event(self):
        with tempfile.TemporaryDirectory() as name:
            process = mock.Mock()
            process.poll.return_value = None
            boundary = mock.Mock(
                processes={"windows": process},
                qmp=mock.Mock(
                    await_device_deleted=mock.Mock(return_value={
                        "event": "DEVICE_DELETED",
                        "data": {"device": "other"},
                    })),
                serial_socket=None,
            )
            adapter = self.adapter(Path(name), boundary)
            with self.assertRaisesRegex(
                    subject.WindowsIdentityAdapterError, "event"):
                adapter.await_device_deleted("telos-join-cd")

    def test_static_probe_never_connects_after_unproved_gui_transition(self):
        with tempfile.TemporaryDirectory() as name:
            adapter = self.adapter(Path(name))
            with self.assertRaises(subject.WindowsIdentityAdapterError):
                adapter.static_probe("domain-state")

    def test_post_reboot_reauthentication_fails_without_calibrated_plan(self):
        with tempfile.TemporaryDirectory() as name:
            adapter = self.adapter(Path(name))
            with self.assertRaisesRegex(
                    subject.WindowsIdentityAdapterError, "sign-in plan"):
                adapter.reauthenticate_local("private")

    def test_credential_action_maps_local_and_domain_material_exactly(self):
        with tempfile.TemporaryDirectory() as name, mock.patch.object(
            subject, "build_credential_action_iso",
        ) as build, mock.patch.object(
            subject, "CredentialActionMediaChannel",
        ), mock.patch.object(
            subject.DuplexCredentialActionSerial, "connect",
            return_value=mock.sentinel.serial,
        ), mock.patch.object(
            subject, "execute_credential_action",
            return_value={"result": "pass"},
        ) as execute:
            raw_serial = mock.Mock(closed=False)
            subject.DuplexCredentialActionSerial.connect.return_value = (
                raw_serial)
            boundary = mock.Mock()
            boundary.processes = {"windows": mock.Mock(
                poll=mock.Mock(return_value=None))}
            boundary.qmp = mock.sentinel.qmp
            serial = Path(name) / "serial"
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as listener:
                listener.bind(str(serial))
                boundary.serial_socket = serial
                adapter = self.adapter(Path(name), boundary)

                result = adapter.credential_action(
                    "windows-standard-online", "student", "secret")

            self.assertEqual({"result": "pass"}, result)
            material = build.call_args.args[1]
            self.assertEqual("connected-domain-login", material["action"])
            self.assertEqual("FACTORY.TEST", material["domain"])
            self.assertEqual(
                "FACTORY\\student",
                execute.call_args.kwargs["expected_principal"],
            )

    def test_unmapped_credential_check_fails_before_media_creation(self):
        with tempfile.TemporaryDirectory() as name, mock.patch.object(
            subject, "build_credential_action_iso",
        ) as build:
            adapter = self.adapter(Path(name))
            with self.assertRaisesRegex(
                    subject.WindowsIdentityAdapterError, "not mapped"):
                adapter.credential_action("unknown", "student", "secret")
            build.assert_not_called()

    def test_credential_serial_failure_precedes_private_iso_creation(self):
        with tempfile.TemporaryDirectory() as name, mock.patch.object(
            subject.DuplexCredentialActionSerial, "connect",
            side_effect=OSError("unavailable"),
        ), mock.patch.object(
            subject, "build_credential_action_iso",
        ) as build:
            boundary = mock.Mock()
            boundary.processes = {"windows": mock.Mock(
                poll=mock.Mock(return_value=None))}
            boundary.qmp = mock.sentinel.qmp
            serial = Path(name) / "serial"
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as listener:
                listener.bind(str(serial))
                boundary.serial_socket = serial
                adapter = self.adapter(Path(name), boundary)

                with self.assertRaisesRegex(
                        subject.WindowsIdentityAdapterError,
                        "serial acquisition"):
                    adapter.credential_action(
                        "windows-standard-online", "student", "secret")

            build.assert_not_called()

    def test_partial_credential_media_is_destroyed_and_error_is_sanitized(self):
        secret = "Never-Retain-This-47!"
        with tempfile.TemporaryDirectory() as name, mock.patch.object(
            subject.DuplexCredentialActionSerial, "connect",
        ) as connect, mock.patch.object(
            subject, "build_credential_action_iso",
        ) as build:
            raw_serial = mock.Mock(closed=False)
            connect.return_value = raw_serial
            boundary = mock.Mock()
            boundary.processes = {"windows": mock.Mock(
                poll=mock.Mock(return_value=None))}
            boundary.qmp = mock.sentinel.qmp
            serial_path = Path(name) / "serial"
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as listener:
                listener.bind(str(serial_path))
                boundary.serial_socket = serial_path
                adapter = self.adapter(Path(name), boundary)

                def partial(output, _material):
                    output.write_bytes(secret.encode())
                    output.chmod(0o600)
                    raise RuntimeError(secret)

                build.side_effect = partial
                with self.assertRaises(
                        subject.WindowsIdentityAdapterError) as caught:
                    adapter.credential_action(
                        "windows-standard-online", "student", secret)

            self.assertNotIn(secret, str(caught.exception))
            self.assertEqual([], list(
                Path(name).glob("windows-credential-*.iso")))
            raw_serial.close.assert_called_once_with()
            self.assertFalse(adapter._com1_owned)

    def test_regular_file_is_not_accepted_as_com1_transport(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            path = root / "not-a-socket"
            path.touch()
            boundary = mock.Mock(serial_socket=path)
            adapter = self.adapter(root, boundary)
            with self.assertRaisesRegex(
                    subject.WindowsIdentityAdapterError, "Unix socket"):
                adapter._serial_socket()

    def test_channel_initialization_failure_destroys_built_media(self):
        with tempfile.TemporaryDirectory() as name, mock.patch.object(
            subject.DuplexCredentialActionSerial, "connect",
        ) as connect, mock.patch.object(
            subject, "build_credential_action_iso",
        ) as build, mock.patch.object(
            subject, "CredentialActionMediaChannel",
            side_effect=RuntimeError("backend detail"),
        ):
            raw_serial = mock.Mock(closed=False)
            connect.return_value = raw_serial
            boundary = mock.Mock()
            boundary.processes = {"windows": mock.Mock(
                poll=mock.Mock(return_value=None))}
            boundary.qmp = mock.sentinel.qmp
            serial_path = Path(name) / "serial"
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as listener:
                listener.bind(str(serial_path))
                boundary.serial_socket = serial_path
                adapter = self.adapter(Path(name), boundary)

                def create(output, _material):
                    output.write_bytes(b"private")
                    output.chmod(0o600)
                    return output

                build.side_effect = create
                with self.assertRaisesRegex(
                        subject.WindowsIdentityAdapterError,
                        "media creation failed"):
                    adapter.credential_action(
                        "windows-standard-online", "student", "secret")

            self.assertEqual([], list(
                Path(name).glob("windows-credential-*.iso")))
            self.assertFalse(adapter._com1_owned)

    def test_join_serial_lease_blocks_overlap_and_releases_on_close(self):
        with tempfile.TemporaryDirectory() as name, mock.patch.object(
            subject.DuplexJoinSerial, "connect",
        ) as connect:
            root = Path(name)
            path = root / "serial"
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as listener:
                listener.bind(str(path))
                boundary = mock.Mock(serial_socket=path)
                first = mock.Mock(closed=False)
                second = mock.Mock(closed=False)
                connect.side_effect = (first, second)
                adapter = self.adapter(root, boundary)

                serial = adapter.open_join_serial()
                with self.assertRaisesRegex(
                        subject.WindowsIdentityAdapterError,
                        "exclusive owner"):
                    adapter.open_join_serial()
                serial.close()
                later = adapter.open_join_serial()
                later.close()

            self.assertFalse(adapter._com1_owned)

    def test_controller_principal_and_join_drivers_share_one_parser(self):
        with tempfile.TemporaryDirectory() as name, mock.patch.object(
            subject.ControllerPrincipalSerial, "stage",
            return_value=mock.sentinel.principals,
        ), mock.patch.object(
            subject.ControllerJoinSerial, "stage",
            return_value=mock.sentinel.join,
        ):
            process = mock.Mock()
            process.poll.return_value = None
            process.stdout = mock.sentinel.reader
            process.stdin = mock.sentinel.writer
            boundary = mock.Mock(processes={"controller": process})
            adapter = self.adapter(Path(name), boundary)

            self.assertIs(
                mock.sentinel.principals,
                adapter.stage_principals({
                    "student": "one",
                    "operator": "two",
                    "directory-admin": "three",
                }),
            )
            self.assertIs(
                mock.sentinel.join,
                adapter.stage_join_principal("four"),
            )
            self.assertIs(
                adapter._principal_serial.console,
                adapter._join_material_serial.console,
            )

    def test_private_root_must_be_exact_mode_0700(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            root.chmod(0o755)
            with self.assertRaisesRegex(
                    subject.WindowsIdentityAdapterError, "mode-0700"):
                subject.NativeWindowsAcceptanceAdapter(
                    mock.Mock(),
                    root,
                    realm="factory.test",
                    local_principal="telosadmin",
                    scan_secrets=mock.Mock(),
                )


if __name__ == "__main__":
    unittest.main()
