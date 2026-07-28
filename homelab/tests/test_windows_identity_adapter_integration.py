"""Integration contracts for the concrete Windows identity callback adapter.

All transports are mocked: these tests exercise composition and ordering
without attaching media, opening COM1, or driving a live guest.
"""

import tempfile
import unittest
from pathlib import Path
import socket
from unittest import mock

from homelab.vm import windows_identity_adapter as subject


class WindowsIdentityAdapterIntegrationTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.root.chmod(0o700)
        self.serial_socket = self.root / "com1.sock"
        self.serial_listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.serial_listener.bind(str(self.serial_socket))
        self.addCleanup(self.serial_listener.close)
        self.windows = mock.Mock()
        self.windows.poll.return_value = None
        self.qmp = mock.Mock()
        self.boundary = mock.Mock(
            processes={"windows": self.windows},
            qmp=self.qmp,
            serial_socket=self.serial_socket,
        )

    def adapter(self, **changes):
        arguments = {
            "realm": "factory.test",
            "local_principal": "telosadmin",
            "scan_secrets": mock.sentinel.scan_secrets,
            "timeout": 7,
        }
        arguments.update(changes)
        return subject.NativeWindowsAcceptanceAdapter(
            self.boundary, self.root, **arguments)

    @mock.patch.object(subject, "execute_credential_action")
    @mock.patch.object(
        subject.DuplexCredentialActionSerial, "connect",
        return_value=mock.sentinel.serial,
    )
    @mock.patch.object(subject, "CredentialActionMediaChannel")
    @mock.patch.object(subject, "build_credential_action_iso")
    @mock.patch.object(subject.uuid, "uuid4")
    def test_every_acceptance_check_maps_to_the_exact_guest_action(
        self, make_uuid, build, channel_type, connect, execute,
    ):
        make_uuid.return_value.hex = "a" * 32
        execute.return_value = {"result": "pass"}
        raw_serial = mock.Mock(closed=False)
        connect.return_value = raw_serial
        adapter = self.adapter()
        expected = {
            "windows-standard-online": "connected-domain-login",
            "windows-daily-admin": "operator-local-administrators-check",
            "windows-cached-login": "cached-domain-login",
            "windows-cached-admin-login": "cached-domain-login",
            "windows-uncached-denied": "uncached-domain-user-denied",
            "windows-local-rescue": "local-rescue-login",
            "gateway-offline": "connected-domain-login",
            "update-source-offline": "connected-domain-login",
            "optional-storage-offline": "connected-domain-login",
            "optional-storage-access-denied": "connected-domain-login",
            "ad-dns-offline": "cached-domain-login",
        }

        for check, action in expected.items():
            with self.subTest(check=check):
                build.reset_mock()
                execute.reset_mock()
                principal = (
                    "telosadmin"
                    if action == "local-rescue-login"
                    else "student"
                )
                adapter.credential_action(check, principal, "private")
                material = build.call_args.args[1]
                self.assertEqual(action, material["action"])
                self.assertEqual(principal, material["username"])
                self.assertEqual(
                    "." if action == "local-rescue-login"
                    else "FACTORY.TEST",
                    material["domain"],
                )
                self.assertEqual(
                    (
                        "TELOS-WIN-01\\telosadmin"
                        if action == "local-rescue-login"
                        else "FACTORY\\student"
                    ),
                    execute.call_args.kwargs["expected_principal"],
                )

        build.reset_mock()
        execute.reset_mock()
        adapter.credential_action(
            "combined-dependencies-offline", "student", "private")
        self.assertEqual(
            "cached-domain-login", build.call_args.args[1]["action"])

        build.reset_mock()
        execute.reset_mock()
        adapter.credential_action(
            "combined-dependencies-offline", "telosadmin", "private")
        material = build.call_args.args[1]
        self.assertEqual("local-rescue-login", material["action"])
        self.assertEqual(".", material["domain"])
        self.assertEqual(
            "TELOS-WIN-01\\telosadmin",
            execute.call_args.kwargs["expected_principal"],
        )

    @mock.patch.object(
        subject, "build_credential_action_iso")
    @mock.patch.object(subject, "CredentialActionMediaChannel")
    @mock.patch.object(
        subject.DuplexCredentialActionSerial, "connect",
        return_value=mock.sentinel.serial,
    )
    @mock.patch.object(
        subject, "execute_credential_action",
        return_value={"result": "pass"},
    )
    def test_credential_action_uses_one_exclusive_com1_session(
        self, execute, connect, channel_type, build,
    ):
        raw_serial = mock.Mock(closed=False)
        connect.return_value = raw_serial
        adapter = self.adapter()

        adapter.credential_action(
            "windows-standard-online", "student", "private")

        connect.assert_called_once_with(self.serial_socket, timeout=7)
        self.assertIs(
            raw_serial, execute.call_args.kwargs["serial"]._serial)
        self.assertEqual(1, channel_type.call_count)
        self.assertEqual(1, build.call_count)

    def test_device_deletion_wait_is_correlated_and_bounded(self):
        self.qmp.await_device_deleted.return_value = {
            "event": "DEVICE_DELETED",
            "data": {"device": "telos-credential-action-cd"},
        }
        adapter = self.adapter(timeout=120)

        adapter.await_device_deleted("telos-credential-action-cd")

        self.qmp.await_device_deleted.assert_called_once_with(
            "telos-credential-action-cd", timeout=30.0)

    @mock.patch.object(subject, "ControllerJoinSerial")
    @mock.patch.object(subject, "ControllerPrincipalSerial")
    def test_controller_drivers_share_one_console_and_transport_pair(
        self, principal_type, join_type,
    ):
        controller = mock.Mock()
        controller.poll.return_value = None
        controller.stdout = mock.sentinel.reader
        controller.stdin = mock.sentinel.writer
        self.boundary.processes["controller"] = controller
        console = mock.sentinel.console
        self.boundary.controller_console = console
        adapter = self.adapter()

        adapter.stage_principals({"student": "private"})
        adapter.stage_join_principal("private")

        principal_type.assert_called_once_with(
            mock.sentinel.reader, mock.sentinel.writer, timeout=7)
        join_type.assert_called_once_with(
            mock.sentinel.reader, mock.sentinel.writer, timeout=7)
        self.assertIs(console, principal_type.return_value.console)
        self.assertIs(console, join_type.return_value.console)

    @mock.patch.object(subject, "WindowsPublicCommandLauncher")
    def test_calibrated_public_launch_uses_live_qmp_and_private_evidence(
        self, launcher_type,
    ):
        plan = mock.sentinel.command_plan
        adapter = self.adapter(command_plan=plan)

        adapter.launch_guest("Write-Output 'public'")

        evidence = self.root / "public-command-evidence"
        launcher_type.assert_called_once_with(self.qmp, evidence)
        launcher_type.return_value.launch.assert_called_once_with(
            "Write-Output 'public'", plan)
        self.assertEqual(0o700, evidence.stat().st_mode & 0o777)

    @mock.patch.object(subject.time, "sleep")
    @mock.patch.object(subject, "_GuiInteraction")
    @mock.patch.object(subject, "_private_evidence_root")
    @mock.patch.object(subject, "_load_references")
    def test_calibrated_reauthentication_observes_before_secret_entry(
        self, load_references, private_evidence_root, interaction_type, sleep,
    ):
        sign_in = mock.Mock(
            state_kind="sign-in",
            state="focused password field for local account telosadmin",
        )
        desktop = mock.sentinel.desktop
        load_references.return_value = (
            sign_in, desktop, mock.sentinel.security, mock.sentinel.change)
        evidence = self.root / "reauth-evidence"
        private_evidence_root.return_value = evidence
        interaction = interaction_type.return_value
        manager = mock.Mock()
        manager.attach_mock(interaction.observe, "observe")
        manager.attach_mock(interaction.type_secret, "type_secret")
        manager.attach_mock(interaction.key, "key")
        plan = mock.Mock(
            initial_sign_in_delay=0,
            wake_after_lock_keys=("ctrl-alt-delete",),
            checkpoint_timeout=11,
        )
        adapter = self.adapter(rotation_plan=plan)

        adapter.reauthenticate_local("private")

        self.assertEqual(
            [
                mock.call.key("ctrl-alt-delete"),
                mock.call.observe(sign_in, 11),
                mock.call.observe(sign_in, 11),
                mock.call.type_secret("private"),
                mock.call.key("ret"),
                mock.call.observe(desktop, 11),
            ],
            manager.mock_calls,
        )
        interaction_type.assert_called_once_with(self.qmp, evidence)
        sleep.assert_not_called()

    @mock.patch.object(subject, "_load_references")
    def test_reauthentication_rejects_reference_for_another_account(
        self, load_references,
    ):
        load_references.return_value = (
            mock.Mock(
                state_kind="sign-in",
                state="focused password field for local account somebody-else",
            ),
            mock.sentinel.desktop,
            mock.sentinel.security,
            mock.sentinel.change,
        )
        adapter = self.adapter(rotation_plan=mock.Mock())

        with self.assertRaisesRegex(
                subject.WindowsIdentityAdapterError, "different account"):
            adapter.reauthenticate_local("private")


if __name__ == "__main__":
    unittest.main()
