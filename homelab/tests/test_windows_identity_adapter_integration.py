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
        manager.attach_mock(
            interaction.disable_durable_capture, "disable_durable_capture")
        manager.attach_mock(
            interaction.observe_ephemeral, "observe_ephemeral")
        manager.attach_mock(interaction.type_secret, "type_secret")
        manager.attach_mock(interaction.key, "key")
        plan = mock.Mock(
            initial_sign_in_delay=0,
            lock_settle_delay=2,
            wake_after_lock_keys=("spc",),
            post_join_local_account_keys=(),
            post_join_local_account_calibrated=True,
            post_join_sign_in_manifest=None,
            checkpoint_timeout=11,
        )
        adapter = self.adapter(rotation_plan=plan)

        adapter.reauthenticate_local("private")

        self.assertEqual(
            [
                mock.call.key("spc"),
                mock.call.key("tab"),
                mock.call.observe(sign_in, mock.ANY),
                mock.call.observe(sign_in, mock.ANY),
                mock.call.disable_durable_capture(),
                mock.call.type_secret("private"),
                mock.call.key("ret"),
                mock.call.observe_ephemeral(
                    desktop,
                    mock.ANY,
                    alternatives=(("sign-in", sign_in),),
                ),
            ],
            manager.mock_calls,
        )
        interaction_type.assert_called_once_with(self.qmp, evidence)
        final_timeout = interaction.observe_ephemeral.call_args.args[1]
        self.assertGreater(final_timeout, 0)
        self.assertLessEqual(final_timeout, 11)
        observe_timeouts = [
            call.args[1] for call in interaction.observe.call_args_list]
        self.assertGreaterEqual(observe_timeouts[0], observe_timeouts[1])
        self.assertGreaterEqual(observe_timeouts[1], final_timeout)
        self.qmp.type_text.assert_called_once_with(".\\telosadmin")
        self.assertEqual([mock.call(2)], sleep.call_args_list)

    @mock.patch.object(subject, "_GuiInteraction")
    @mock.patch.object(subject, "_private_evidence_root")
    @mock.patch.object(subject, "_load_references")
    def test_reauthentication_classifies_persisted_sign_in_after_submit(
        self, load_references, private_evidence_root, interaction_type,
    ):
        sign_in = mock.Mock(
            state_kind="sign-in",
            state="focused password field for local account telosadmin",
        )
        desktop = mock.sentinel.desktop
        load_references.return_value = (
            sign_in, desktop, mock.sentinel.security, mock.sentinel.change)
        private_evidence_root.return_value = self.root / "reauth-evidence"
        interaction_type.return_value.observe_ephemeral.side_effect = (
            subject.WindowsIdentityGuiAlternateState("sign-in"))
        adapter = self.adapter(rotation_plan=mock.Mock(
            initial_sign_in_delay=0,
            lock_settle_delay=0,
            wake_after_lock_keys=("spc",),
            post_join_local_account_keys=(),
            post_join_local_account_calibrated=True,
            post_join_sign_in_manifest=None,
            checkpoint_timeout=11,
        ))

        with self.assertRaises(
                subject.WindowsLocalReauthenticationError) as caught:
            adapter.reauthenticate_local("private")

        self.assertEqual(
            "desktop-sign-in-persisted",
            caught.exception.reauth_operation,
        )

    @mock.patch.object(subject, "_GuiInteraction")
    @mock.patch.object(subject, "_private_evidence_root")
    @mock.patch.object(subject, "_load_references")
    def test_reauthentication_maps_terminal_near_references(
        self, load_references, private_evidence_root, interaction_type,
    ):
        sign_in = mock.Mock(
            state_kind="sign-in",
            state="focused password field for local account telosadmin",
        )
        desktop = mock.Mock(state_kind="desktop")
        load_references.return_value = (
            sign_in, desktop, mock.sentinel.security, mock.sentinel.change)
        private_evidence_root.return_value = self.root / "reauth-evidence"
        adapter = self.adapter(rotation_plan=mock.Mock(
            initial_sign_in_delay=0,
            lock_settle_delay=0,
            wake_after_lock_keys=("spc",),
            post_join_local_account_keys=(),
            post_join_local_account_calibrated=True,
            post_join_sign_in_manifest=None,
            checkpoint_timeout=11,
        ))

        for state, operation in (
            ("desktop", "desktop-near-reference"),
            ("sign-in", "desktop-sign-in-near-reference"),
        ):
            with self.subTest(state=state):
                interaction_type.return_value.reset_mock()
                interaction_type.return_value.observe_ephemeral.side_effect = (
                    subject.WindowsIdentityGuiNearReference(state))
                with self.assertRaises(
                    subject.WindowsLocalReauthenticationError,
                ) as caught:
                    adapter.reauthenticate_local("private")
                self.assertEqual(operation, caught.exception.reauth_operation)

    @mock.patch.object(subject, "_GuiInteraction")
    @mock.patch.object(subject, "_private_evidence_root")
    @mock.patch.object(subject, "_load_references")
    @mock.patch.object(subject.time, "sleep")
    def test_reauthentication_deadline_starts_after_boot_settle(
        self, sleep, load_references, private_evidence_root, interaction_type,
    ):
        sign_in = mock.Mock(
            state_kind="sign-in",
            state="focused password field for local account telosadmin",
        )
        desktop = mock.sentinel.desktop
        load_references.return_value = (
            sign_in, desktop, mock.sentinel.security, mock.sentinel.change)
        private_evidence_root.return_value = self.root / "reauth-evidence"
        elapsed = [0.0]
        sleep.side_effect = lambda delay: elapsed.__setitem__(
            0, elapsed[0] + delay)
        adapter = self.adapter(
            timeout=10,
            clock=lambda: elapsed[0],
            rotation_plan=mock.Mock(
                initial_sign_in_delay=5,
                lock_settle_delay=0,
                wake_after_lock_keys=("spc",),
                post_join_local_account_keys=(),
                post_join_local_account_calibrated=True,
                post_join_sign_in_manifest=None,
                checkpoint_timeout=20,
            ),
        )

        adapter.reauthenticate_local("private")

        self.assertEqual([mock.call(5)], sleep.call_args_list)
        self.assertEqual(
            10,
            interaction_type.return_value.observe.call_args_list[0].args[1],
        )
        self.assertEqual(
            10,
            interaction_type.return_value.observe_ephemeral.call_args.args[1],
        )

    @mock.patch.object(subject, "_GuiInteraction")
    @mock.patch.object(subject, "_private_evidence_root")
    @mock.patch.object(subject, "_load_references")
    @mock.patch.object(subject, "retain_post_join_calibration")
    @mock.patch.object(subject, "sample_post_join_calibration")
    @mock.patch.object(subject.time, "sleep")
    def test_reauthentication_fails_before_secret_without_account_selection(
        self, sleep, sample_calibration, retain_calibration, load_references,
        private_evidence_root, interaction_type,
    ):
        load_references.return_value = (
            mock.Mock(
                state_kind="sign-in",
                state="focused password field for local account telosadmin",
            ),
            mock.sentinel.desktop,
            mock.sentinel.security,
            mock.sentinel.change,
        )
        private_evidence_root.return_value = self.root / "reauth-evidence"
        def frame(content):
            return subject.PostJoinCalibrationFrame(
                content, mock.Mock(width=1280, height=800))
        baseline = frame(b"baseline")
        generic = frame(b"generic")
        password = frame(b"password")
        sample_calibration.side_effect = (
            baseline, generic, generic, generic,
            password, password, password,
        )
        ordering = mock.Mock()
        ordering.attach_mock(sleep, "sleep")
        ordering.attach_mock(sample_calibration, "sample")
        ordering.attach_mock(interaction_type.return_value.key, "key")
        adapter = self.adapter(rotation_plan=mock.Mock(
            initial_sign_in_delay=5,
            lock_settle_delay=2,
            wake_after_lock_keys=("spc",),
            post_join_local_account_keys=(),
            post_join_local_account_calibrated=False,
            post_join_sign_in_manifest=None,
            expected_guest=mock.sentinel.guest,
        ))

        with self.assertRaisesRegex(
                subject.WindowsLocalReauthenticationError,
                "calibration-required"):
            adapter.reauthenticate_local("private")

        self.assertEqual(
            retain_calibration.call_args_list,
            [
                mock.call(
                    generic,
                    self.root / "reauth-evidence",
                    mock.sentinel.guest,
                    state="generic-prompt",
                    stability_samples=3,
                ),
                mock.call(
                    password,
                    self.root / "reauth-evidence",
                    mock.sentinel.guest,
                    state="password-target",
                    stability_samples=3,
                ),
            ],
        )
        self.assertEqual(
            interaction_type.return_value.key.call_args_list,
            [mock.call("spc"), mock.call("tab")],
        )
        interaction_type.return_value.type_secret.assert_not_called()
        self.qmp.type_text.assert_called_once_with(".\\telosadmin")
        self.assertEqual(
            [
                mock.call.sleep(5),
                mock.call.sample(
                    self.qmp, self.root / "reauth-evidence"),
                mock.call.key("spc"),
                mock.call.sample(
                    self.qmp, self.root / "reauth-evidence"),
            ],
            ordering.mock_calls[:4],
        )
        self.assertEqual(
            [mock.call(5)] + [mock.call(2)] * 4,
            sleep.call_args_list,
        )

    @mock.patch.object(subject, "_GuiInteraction")
    @mock.patch.object(subject, "_private_evidence_root")
    @mock.patch.object(subject, "_load_references")
    @mock.patch.object(subject, "retain_post_join_calibration")
    @mock.patch.object(subject, "sample_post_join_calibration")
    @mock.patch.object(subject.time, "sleep")
    def test_unchanged_calibration_frames_exhaust_total_deadline(
        self, sleep, sample_calibration, retain_calibration, load_references,
        private_evidence_root, interaction_type,
    ):
        load_references.return_value = (
            mock.Mock(
                state_kind="sign-in",
                state="focused password field for local account telosadmin",
            ),
            mock.sentinel.desktop,
            mock.sentinel.security,
            mock.sentinel.change,
        )
        private_evidence_root.return_value = self.root / "reauth-evidence"
        unchanged = subject.PostJoinCalibrationFrame(
            b"unchanged", mock.Mock(width=1280, height=800))
        sample_calibration.return_value = unchanged
        elapsed = [0.0]
        sleep.side_effect = lambda delay: elapsed.__setitem__(
            0, elapsed[0] + delay)
        adapter = self.adapter(
            timeout=3,
            clock=lambda: elapsed[0],
            rotation_plan=mock.Mock(
                initial_sign_in_delay=0,
                lock_settle_delay=2,
                wake_after_lock_keys=("spc",),
                post_join_local_account_keys=(),
                post_join_local_account_calibrated=False,
                post_join_sign_in_manifest=None,
                expected_guest=mock.sentinel.guest,
            ),
        )

        with self.assertRaises(
                subject.WindowsLocalReauthenticationError) as caught:
            adapter.reauthenticate_local("private")

        self.assertEqual(
            "calibration-capture", caught.exception.reauth_operation)
        self.assertEqual([mock.call(2), mock.call(1)], sleep.call_args_list)
        self.assertEqual(3, sample_calibration.call_count)
        retain_calibration.assert_not_called()
        self.qmp.type_text.assert_not_called()
        interaction_type.return_value.type_secret.assert_not_called()
        interaction_type.return_value.disable_durable_capture.assert_not_called()

    @mock.patch.object(subject, "_GuiInteraction")
    @mock.patch.object(subject, "_private_evidence_root")
    @mock.patch.object(subject, "_load_references")
    @mock.patch.object(subject, "retain_post_join_calibration")
    @mock.patch.object(subject, "sample_post_join_calibration")
    @mock.patch.object(subject.time, "sleep")
    def test_transient_calibration_frames_are_never_retained(
        self, sleep, sample_calibration, retain_calibration, load_references,
        private_evidence_root, interaction_type,
    ):
        load_references.return_value = (
            mock.Mock(
                state_kind="sign-in",
                state="focused password field for local account telosadmin",
            ),
            mock.sentinel.desktop,
            mock.sentinel.security,
            mock.sentinel.change,
        )
        private_evidence_root.return_value = self.root / "reauth-evidence"
        frames = [
            subject.PostJoinCalibrationFrame(
                content, mock.Mock(width=1280, height=800))
            for content in (b"baseline", b"a", b"b", b"a", b"b", b"a")
        ]
        sample_calibration.side_effect = frames
        elapsed = [0.0]
        sleep.side_effect = lambda delay: elapsed.__setitem__(
            0, elapsed[0] + delay)
        adapter = self.adapter(
            timeout=4,
            clock=lambda: elapsed[0],
            rotation_plan=mock.Mock(
                initial_sign_in_delay=0,
                lock_settle_delay=1,
                wake_after_lock_keys=("spc",),
                post_join_local_account_keys=(),
                post_join_local_account_calibrated=False,
                post_join_sign_in_manifest=None,
                expected_guest=mock.sentinel.guest,
            ),
        )

        with self.assertRaises(
                subject.WindowsLocalReauthenticationError) as caught:
            adapter.reauthenticate_local("private")

        self.assertEqual(
            "calibration-capture", caught.exception.reauth_operation)
        self.assertEqual([mock.call(1)] * 4, sleep.call_args_list)
        retain_calibration.assert_not_called()
        self.qmp.type_text.assert_not_called()
        interaction_type.return_value.type_secret.assert_not_called()

    @mock.patch.object(subject, "_GuiInteraction")
    @mock.patch.object(subject, "_private_evidence_root")
    @mock.patch.object(subject, "_load_references")
    def test_reauthentication_total_deadline_expires_before_secret(
        self, load_references, private_evidence_root, interaction_type,
    ):
        sign_in = mock.Mock(
            state_kind="sign-in",
            state="focused password field for local account telosadmin",
        )
        load_references.return_value = (
            sign_in, mock.sentinel.desktop,
            mock.sentinel.security, mock.sentinel.change,
        )
        private_evidence_root.return_value = self.root / "reauth-evidence"
        ticks = iter((0.0, 0.1, 8.0))
        adapter = self.adapter(
            rotation_plan=mock.Mock(
                initial_sign_in_delay=0,
                lock_settle_delay=0,
                wake_after_lock_keys=("spc",),
                post_join_local_account_keys=("end", "ret"),
                post_join_local_account_calibrated=True,
                post_join_sign_in_manifest=None,
                checkpoint_timeout=11,
            ),
            clock=lambda: next(ticks),
        )

        with self.assertRaises(
                subject.WindowsLocalReauthenticationError) as caught:
            adapter.reauthenticate_local("private")

        self.assertEqual(
            "select-local-account", caught.exception.reauth_operation)
        interaction_type.return_value.type_secret.assert_not_called()
        interaction_type.return_value.disable_durable_capture.assert_not_called()

    @mock.patch.object(subject, "_GuiInteraction")
    @mock.patch.object(subject, "_private_evidence_root")
    @mock.patch.object(subject, "_load_references")
    def test_reauthentication_reports_password_target_without_typing_secret(
        self, load_references, private_evidence_root, interaction_type,
    ):
        sign_in = mock.Mock(
            state_kind="sign-in",
            state="focused password field for local account telosadmin",
        )
        load_references.return_value = (
            sign_in, mock.sentinel.desktop,
            mock.sentinel.security, mock.sentinel.change,
        )
        private_evidence_root.return_value = self.root / "reauth-evidence"
        interaction = interaction_type.return_value
        interaction.observe.side_effect = RuntimeError("backend-private")
        adapter = self.adapter(rotation_plan=mock.Mock(
            initial_sign_in_delay=0,
            lock_settle_delay=0,
            wake_after_lock_keys=("spc",),
            post_join_local_account_keys=("end",),
            post_join_local_account_calibrated=True,
            post_join_sign_in_manifest=None,
            checkpoint_timeout=11,
        ))

        with self.assertRaises(
                subject.WindowsLocalReauthenticationError) as caught:
            adapter.reauthenticate_local("private")

        self.assertEqual(
            "prove-password-target", caught.exception.reauth_operation)
        self.assertNotIn("backend-private", str(caught.exception))
        interaction.type_secret.assert_not_called()

    @mock.patch.object(subject, "_GuiInteraction")
    @mock.patch.object(subject, "_private_evidence_root")
    @mock.patch.object(subject, "_load_references")
    def test_reauthentication_interruption_never_submits_secret(
        self, load_references, private_evidence_root, interaction_type,
    ):
        sign_in = mock.Mock(
            state_kind="sign-in",
            state="focused password field for local account telosadmin",
        )
        load_references.return_value = (
            sign_in, mock.sentinel.desktop,
            mock.sentinel.security, mock.sentinel.change,
        )
        private_evidence_root.return_value = self.root / "reauth-evidence"
        interaction = interaction_type.return_value
        plan = mock.Mock(
            initial_sign_in_delay=0,
            lock_settle_delay=0,
            wake_after_lock_keys=("spc",),
            post_join_local_account_keys=("end",),
            post_join_local_account_calibrated=True,
            post_join_sign_in_manifest=None,
            checkpoint_timeout=11,
        )
        for interruption in (
            KeyboardInterrupt(),
            SystemExit(17),
            subject.RunInterrupted(15),
        ):
            with self.subTest(
                interruption=type(interruption).__name__,
            ), self.assertRaises(type(interruption)):
                interaction.reset_mock()
                interaction.observe.side_effect = interruption
                self.adapter(
                    rotation_plan=plan,
                ).reauthenticate_local("private")
            self.assertNotIn(
                mock.call("ret"), interaction.key.call_args_list)
            interaction.type_secret.assert_not_called()
            interaction.observe_ephemeral.assert_not_called()

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
        adapter = self.adapter(rotation_plan=mock.Mock(
            post_join_local_account_calibrated=True))

        with self.assertRaisesRegex(
                subject.WindowsLocalReauthenticationError,
                "prove-password-target"):
            adapter.reauthenticate_local("private")


if __name__ == "__main__":
    unittest.main()
