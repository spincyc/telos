"""Integration contracts for the concrete Windows identity callback adapter.

All transports are mocked: these tests exercise composition and ordering
without attaching media, opening COM1, or driving a live guest.
"""

import tempfile
import unittest
from pathlib import Path
import socket
from types import SimpleNamespace
from unittest import mock

from homelab.vm import windows_identity_adapter as subject
from homelab.vm.windows_gui import Image
from homelab.vm.windows_postsubmit_diagnostic import (
    PostSubmitDiagnosticCode,
)
from homelab.vm.controller_auth_diagnostic import (
    ControllerAuthArmSubphase,
    ControllerAuthCode,
    ControllerAuthCollection,
    ControllerAuthCleanup,
    ControllerAuthDiagnosticError,
    ControllerAuthExpectation,
    ControllerAuthReceiveObservation,
    ControllerAuthResult,
)


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

    def _domain_reauthentication_fixture(self):
        sign_in = mock.Mock(
            state_kind="sign-in",
            state="focused password field for domain account "
            "operator@FACTORY.TEST",
        )
        return sign_in, mock.sentinel.desktop, mock.Mock(
            initial_sign_in_delay=0,
            lock_settle_delay=0,
            wake_after_lock_keys=(),
            post_join_operator_account_keys=(),
            post_join_operator_account_calibrated=True,
            post_join_operator_sign_in_manifest=None,
            checkpoint_timeout=11,
        )

    def test_controller_arm_unavailable_with_cleanup_cannot_veto_gui(self):
        sign_in, desktop, plan = self._domain_reauthentication_fixture()
        with (
            mock.patch.object(
                subject, "_load_references",
                return_value=(
                    sign_in, desktop, mock.sentinel.security,
                    mock.sentinel.change)),
            mock.patch.object(
                subject, "_private_evidence_root",
                return_value=self.root / "reauth-evidence"),
            mock.patch.object(subject, "_GuiInteraction") as interaction_type,
            mock.patch.object(subject, "_prove_secret_entry_departure"),
            mock.patch.object(
                subject, "ControllerAuthDiagnosticSession") as controller_type,
        ):
            controller_type.return_value.arm.side_effect = (
                ControllerAuthDiagnosticError(
                    controller_auth_result=ControllerAuthResult(
                        collection=(
                            ControllerAuthCollection.CONFIGURATION_INVALID)),
                    cleanup_proved=True))
            adapter = self.adapter(rotation_plan=plan)
            adapter.reauthenticate_domain_operator(
                "operator@FACTORY.TEST", "private", "a" * 32)
        interaction_type.return_value.type_secret.assert_called_once()
        self.assertEqual(
            adapter.controller_auth_result.collection.value,
            "configuration-invalid")

    def test_controller_prelaunch_unavailable_cannot_veto_gui(self):
        sign_in, desktop, plan = self._domain_reauthentication_fixture()
        with (
            mock.patch.object(
                subject, "_load_references",
                return_value=(
                    sign_in, desktop, mock.sentinel.security,
                    mock.sentinel.change)),
            mock.patch.object(
                subject, "_private_evidence_root",
                return_value=self.root / "reauth-evidence"),
            mock.patch.object(subject, "_GuiInteraction") as interaction_type,
            mock.patch.object(subject, "_prove_secret_entry_departure"),
            mock.patch.object(
                subject, "ControllerAuthDiagnosticSession",
                side_effect=RuntimeError("prelaunch unavailable")),
        ):
            adapter = self.adapter(rotation_plan=plan)
            adapter.reauthenticate_domain_operator(
                "operator@FACTORY.TEST", "private", "a" * 32)
        interaction_type.return_value.type_secret.assert_called_once()
        self.assertEqual(
            adapter.controller_auth_result.collection.value,
            "receipt-unavailable")

    def test_controller_arm_unproved_cleanup_aborts_before_secret(self):
        for collection in (
            ControllerAuthCollection.SINK_INVALID,
            ControllerAuthCollection.RECEIPT_UNAVAILABLE,
        ):
            with self.subTest(collection=collection):
                sign_in, desktop, plan = (
                    self._domain_reauthentication_fixture())
                result = ControllerAuthResult(
                    collection=collection,
                    cleanup=ControllerAuthCleanup.SINK_ABSENCE_UNPROVED,
                )
                with (
                    mock.patch.object(
                        subject, "_load_references",
                        return_value=(
                            sign_in, desktop, mock.sentinel.security,
                            mock.sentinel.change)),
                    mock.patch.object(
                        subject, "_private_evidence_root",
                        return_value=self.root / "reauth-evidence"),
                    mock.patch.object(
                        subject, "_GuiInteraction") as interaction_type,
                    mock.patch.object(subject, "_prove_secret_entry_departure"),
                    mock.patch.object(
                        subject, "ControllerAuthDiagnosticSession",
                    ) as controller_type,
                ):
                    controller_type.return_value.arm.side_effect = (
                        ControllerAuthDiagnosticError(
                            controller_auth_result=result,
                            cleanup_proved=False,
                            arm_subphase=(
                                ControllerAuthArmSubphase.RECEIVE
                                if collection is
                                ControllerAuthCollection.RECEIPT_UNAVAILABLE
                                else None
                            ),
                            receive_observation=(
                                ControllerAuthReceiveObservation.TIMEOUT
                                if collection is
                                ControllerAuthCollection.RECEIPT_UNAVAILABLE
                                else None
                            ),
                        ))
                    adapter = self.adapter(rotation_plan=plan)
                    with self.assertRaises(
                            subject.WindowsLocalReauthenticationError
                    ) as caught:
                        adapter.reauthenticate_domain_operator(
                            "operator@FACTORY.TEST", "private", "a" * 32)
                self.assertEqual(
                    caught.exception.reauth_operation, "controller-auth-arm")
                self.assertIs(
                    caught.exception.controller_auth_result, result)
                self.assertIs(
                    caught.exception.controller_auth_arm_subphase,
                    (
                        ControllerAuthArmSubphase.RECEIVE
                        if collection is
                        ControllerAuthCollection.RECEIPT_UNAVAILABLE
                        else None
                    ))
                self.assertIs(
                    caught.exception.controller_auth_receive_observation,
                    (
                        ControllerAuthReceiveObservation.TIMEOUT
                        if collection is
                        ControllerAuthCollection.RECEIPT_UNAVAILABLE
                        else None
                    ))
                interaction_type.return_value.type_secret.assert_not_called()

    def test_forged_controller_arm_carriers_fail_closed_before_secret(self):
        class ForgedControllerAuthDiagnosticError(
                ControllerAuthDiagnosticError):
            pass

        valid_result = ControllerAuthResult(
            collection=ControllerAuthCollection.RECEIPT_UNAVAILABLE)
        mutated = ControllerAuthDiagnosticError(
            controller_auth_result=valid_result,
            cleanup_proved=True,
        )
        object.__setattr__(valid_result, "collection", "private-detail")
        forged_errors = (
            ForgedControllerAuthDiagnosticError(
                controller_auth_result=ControllerAuthResult(
                    collection=(
                        ControllerAuthCollection.RECEIPT_UNAVAILABLE)),
                cleanup_proved=True,
            ),
            mutated,
        )
        for forged_error in forged_errors:
            with self.subTest(error=type(forged_error).__name__):
                sign_in, desktop, plan = (
                    self._domain_reauthentication_fixture())
                with (
                    mock.patch.object(
                        subject, "_load_references",
                        return_value=(
                            sign_in, desktop, mock.sentinel.security,
                            mock.sentinel.change)),
                    mock.patch.object(
                        subject, "_private_evidence_root",
                        return_value=self.root / "reauth-evidence"),
                    mock.patch.object(
                        subject, "_GuiInteraction") as interaction_type,
                    mock.patch.object(subject, "_prove_secret_entry_departure"),
                    mock.patch.object(
                        subject, "ControllerAuthDiagnosticSession",
                    ) as controller_type,
                ):
                    controller_type.return_value.arm.side_effect = forged_error
                    adapter = self.adapter(rotation_plan=plan)
                    with self.assertRaises(
                            subject.WindowsLocalReauthenticationError
                    ) as caught:
                        adapter.reauthenticate_domain_operator(
                            "operator@FACTORY.TEST", "private", "a" * 32)
                self.assertEqual(
                    caught.exception.reauth_operation, "controller-auth-arm")
                self.assertEqual(
                    caught.exception.controller_auth_result.collection,
                    ControllerAuthCollection.RECEIPT_UNAVAILABLE)
                self.assertEqual(
                    caught.exception.controller_auth_result.cleanup,
                    ControllerAuthCleanup.SINK_ABSENCE_UNPROVED)
                interaction_type.return_value.type_secret.assert_not_called()

    def test_controller_arm_generic_failure_closes_before_secret(self):
        sign_in, desktop, plan = self._domain_reauthentication_fixture()
        with (
            mock.patch.object(
                subject, "_load_references",
                return_value=(
                    sign_in, desktop, mock.sentinel.security,
                    mock.sentinel.change)),
            mock.patch.object(
                subject, "_private_evidence_root",
                return_value=self.root / "reauth-evidence"),
            mock.patch.object(subject, "_GuiInteraction") as interaction_type,
            mock.patch.object(subject, "_prove_secret_entry_departure"),
            mock.patch.object(
                subject, "ControllerAuthDiagnosticSession") as controller_type,
        ):
            controller_type.return_value.arm.side_effect = RuntimeError(
                "private Controller detail")
            adapter = self.adapter(rotation_plan=plan)
            with self.assertRaises(
                    subject.WindowsLocalReauthenticationError) as caught:
                adapter.reauthenticate_domain_operator(
                    "operator@FACTORY.TEST", "private", "a" * 32)
        self.assertEqual(
            caught.exception.reauth_operation, "controller-auth-arm")
        self.assertEqual(
            caught.exception.controller_auth_result.collection,
            ControllerAuthCollection.RECEIPT_UNAVAILABLE)
        self.assertEqual(
            caught.exception.controller_auth_result.cleanup,
            ControllerAuthCleanup.SINK_ABSENCE_UNPROVED)
        interaction_type.return_value.type_secret.assert_not_called()

    def test_controller_collection_unavailable_cannot_veto_gui(self):
        sign_in, desktop, plan = self._domain_reauthentication_fixture()
        with (
            mock.patch.object(
                subject, "_load_references",
                return_value=(
                    sign_in, desktop, mock.sentinel.security,
                    mock.sentinel.change)),
            mock.patch.object(
                subject, "_private_evidence_root",
                return_value=self.root / "reauth-evidence"),
            mock.patch.object(subject, "_GuiInteraction"),
            mock.patch.object(subject, "_prove_secret_entry_departure"),
            mock.patch.object(
                subject, "ControllerAuthDiagnosticSession") as controller_type,
        ):
            controller_type.return_value.submitted.side_effect = (
                ControllerAuthDiagnosticError(
                    controller_auth_result=ControllerAuthResult(
                        collection=(
                            ControllerAuthCollection.RECEIPT_UNAVAILABLE),
                        cleanup=(
                            ControllerAuthCleanup.SINK_ABSENCE_UNPROVED),
                    ),
                    cleanup_proved=False,
                ))
            controller_type.return_value.armed = False
            adapter = self.adapter(rotation_plan=plan)
            adapter.reauthenticate_domain_operator(
                "operator@FACTORY.TEST", "private", "a" * 32)
        self.assertEqual(
            adapter.controller_auth_result.collection.value,
            "receipt-unavailable")
        self.assertEqual(
            adapter.controller_auth_result.cleanup.value,
            "sink-absence-unproved")

    def test_controller_cancel_result_survives_secret_and_submit_failures(self):
        for failure_operation in ("type-secret", "submit"):
            with self.subTest(failure_operation=failure_operation):
                sign_in, desktop, plan = (
                    self._domain_reauthentication_fixture())
                with (
                    mock.patch.object(
                        subject, "_load_references",
                        return_value=(
                            sign_in, desktop, mock.sentinel.security,
                            mock.sentinel.change)),
                    mock.patch.object(
                        subject, "_private_evidence_root",
                        return_value=self.root / "reauth-evidence"),
                    mock.patch.object(
                        subject, "_GuiInteraction") as interaction_type,
                    mock.patch.object(
                        subject, "_prove_secret_entry_departure"),
                    mock.patch.object(
                        subject, "ControllerAuthDiagnosticSession",
                    ) as controller_type,
                ):
                    interaction = interaction_type.return_value
                    if failure_operation == "type-secret":
                        interaction.type_secret.side_effect = RuntimeError(
                            "private backend detail")
                    else:
                        interaction.key.side_effect = lambda key, **_kwargs: (
                            (_ for _ in ()).throw(
                                RuntimeError("private backend detail"))
                            if key == "ret" else None
                        )
                    controller = controller_type.return_value
                    controller.armed = True
                    cancel_result = ControllerAuthResult(
                        collection=ControllerAuthCollection.CANCELLED)
                    controller.cancel.return_value = cancel_result
                    adapter = self.adapter(rotation_plan=plan)
                    with self.assertRaises(
                            subject.WindowsLocalReauthenticationError
                    ) as caught:
                        adapter.reauthenticate_domain_operator(
                            "operator@FACTORY.TEST", "private", "a" * 32)

                self.assertEqual(
                    failure_operation, caught.exception.reauth_operation)
                self.assertIs(
                    cancel_result,
                    caught.exception.controller_auth_result,
                )
                controller.cancel.assert_called_once_with()
                self.assertNotIn(
                    "private backend detail", str(caught.exception))

    def test_controller_cancel_result_survives_windows_diagnostic_arm_failure(
        self,
    ):
        sign_in, desktop, plan = self._domain_reauthentication_fixture()
        diagnostic_factory = mock.Mock()
        diagnostic = diagnostic_factory.return_value
        diagnostic.__enter__ = mock.Mock(return_value=diagnostic)
        diagnostic.__exit__ = mock.Mock(return_value=False)
        diagnostic.arm.side_effect = RuntimeError("private watcher detail")
        with (
            mock.patch.object(
                subject, "_load_references",
                return_value=(
                    sign_in, desktop, mock.sentinel.security,
                    mock.sentinel.change)),
            mock.patch.object(
                subject, "_private_evidence_root",
                return_value=self.root / "reauth-evidence"),
            mock.patch.object(subject, "_GuiInteraction"),
            mock.patch.object(subject, "_prove_secret_entry_departure"),
            mock.patch.object(
                subject, "ControllerAuthDiagnosticSession") as controller_type,
        ):
            controller = controller_type.return_value
            controller.armed = True
            cancel_result = ControllerAuthResult(
                collection=ControllerAuthCollection.CANCELLED,
                cleanup=ControllerAuthCleanup.SINK_ABSENCE_UNPROVED,
            )
            controller.cancel.return_value = cancel_result
            adapter = self.adapter(
                post_submit_diagnostic=diagnostic_factory,
                rotation_plan=plan,
            )
            with self.assertRaises(
                    subject.WindowsLocalReauthenticationError) as caught:
                adapter.reauthenticate_domain_operator(
                    "operator@FACTORY.TEST", "private", "a" * 32)

        self.assertEqual(
            "diagnostic-arm-launch", caught.exception.reauth_operation)
        self.assertIs(
            cancel_result, caught.exception.controller_auth_result)
        controller.cancel.assert_called_once_with()
        self.assertNotIn("private watcher detail", str(caught.exception))

    def test_secret_entry_departure_is_ephemeral_and_requires_two_frames(self):
        evidence = self.root / "evidence"
        evidence.mkdir(mode=0o700)
        width, height = 320, 200
        empty_pixels = bytes(reversed(range(256))) * 750
        departed_pixels = bytes(range(256)) * 750
        reference = SimpleNamespace(
            geometry=(width, height),
            crop=None,
            image=Image(width, height, empty_pixels),
        )
        paths = []

        def screenshot(path):
            paths.append(path)
            path.write_bytes(
                f"P6\n{width} {height}\n255\n".encode() + departed_pixels)

        qmp = mock.Mock()
        qmp.screenshot.side_effect = screenshot
        pause = mock.Mock()

        subject._prove_secret_entry_departure(
            qmp,
            evidence,
            reference,
            timeout=1,
            clock=lambda: 0,
            pause=pause,
        )

        self.assertEqual(2, qmp.screenshot.call_count)
        self.assertEqual([mock.call(0.5)], pause.call_args_list)
        self.assertTrue(paths)
        self.assertTrue(all(not path.exists() for path in paths))
        self.assertEqual([], list(evidence.iterdir()))

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

    @mock.patch.object(subject, "retain_submit_focus_calibration")
    @mock.patch.object(subject, "sample_post_join_calibration")
    @mock.patch.object(subject, "load_identity_reference")
    @mock.patch.object(subject, "_GuiInteraction")
    @mock.patch.object(subject, "_private_evidence_root")
    @mock.patch.object(subject, "_load_references")
    def test_operator_submit_focus_calibration_never_submits(
        self, load_references, private_evidence_root, interaction_type,
        load_identity_reference, sample_calibration, retain_calibration,
    ):
        sign_in = mock.Mock(
            state_kind="sign-in",
            state="focused password field for domain account "
            "operator@FACTORY.TEST",
        )
        load_references.return_value = (
            sign_in, mock.sentinel.desktop,
            mock.sentinel.security, mock.sentinel.change,
        )
        load_identity_reference.return_value = sign_in
        private_evidence_root.return_value = self.root / "reauth-evidence"
        frames = tuple(
            subject.PostJoinCalibrationFrame(
                f"frame-{offset}".encode(),
                mock.Mock(width=1280, height=800),
            )
            for offset in range(2)
        )
        sample_calibration.side_effect = (
            frames[0], frames[0], frames[0],
            frames[1], frames[1], frames[1],
        )
        diagnostic_factory = mock.Mock()
        adapter = self.adapter(
            post_submit_diagnostic=diagnostic_factory,
            rotation_plan=mock.Mock(
                initial_sign_in_delay=0,
                lock_settle_delay=0,
                wake_after_lock_keys=(),
                post_join_operator_account_keys=(),
                post_join_operator_account_calibrated=True,
                post_join_operator_sign_in_manifest=Path("reviewed.json"),
                post_join_operator_submit_focus_calibration=True,
                post_join_operator_submit_focus_tabs=2,
                expected_guest=mock.sentinel.guest,
                checkpoint_timeout=11,
            ),
        )

        with self.assertRaisesRegex(
            subject.WindowsLocalReauthenticationError,
            "calibration-required",
        ):
            adapter.reauthenticate_domain_operator(
                "operator@FACTORY.TEST", "private", "a" * 32)

        self.qmp.type_text.assert_any_call(
            "TelosPublicCalibration1", timeout=mock.ANY)
        self.assertEqual(
            interaction_type.return_value.key.call_args_list,
            [
                mock.call("backspace", timeout=mock.ANY),
                mock.call("tab", timeout=mock.ANY),
                mock.call("tab", timeout=mock.ANY),
                mock.call("tab", timeout=mock.ANY),
            ],
        )
        self.assertNotIn(
            mock.call("ret", timeout=mock.ANY),
            interaction_type.return_value.key.call_args_list,
        )
        interaction_type.return_value.type_secret.assert_not_called()
        interaction_type.return_value.disable_durable_capture.assert_not_called()
        diagnostic_factory.assert_not_called()
        retain_calibration.assert_called_once_with(
            frames,
            self.root / "reauth-evidence",
            mock.sentinel.guest,
        )

    @mock.patch.object(subject.time, "sleep")
    @mock.patch.object(subject, "_prove_secret_entry_departure")
    @mock.patch.object(subject, "_GuiInteraction")
    @mock.patch.object(subject, "_private_evidence_root")
    @mock.patch.object(subject, "_load_references")
    def test_calibrated_reauthentication_observes_before_secret_entry(
        self, load_references, private_evidence_root, interaction_type,
        prove_departure, sleep,
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
        manager.attach_mock(interaction.chord, "chord")
        manager.attach_mock(self.qmp.type_text, "type_text")
        manager.attach_mock(sleep, "sleep")
        manager.attach_mock(prove_departure, "prove_departure")
        plan = mock.Mock(
            initial_sign_in_delay=0,
            lock_settle_delay=2,
            wake_after_lock_keys=("spc",),
            post_join_local_account_keys=(),
            post_join_local_account_calibrated=True,
            post_join_sign_in_manifest=None,
            checkpoint_timeout=11,
        )
        diagnostic_factory = mock.Mock()
        adapter = self.adapter(
            rotation_plan=plan,
            post_submit_diagnostic=diagnostic_factory,
        )

        adapter.reauthenticate_local("private")

        diagnostic_factory.assert_not_called()
        self.assertFalse(adapter._com1_owned)
        self.assertEqual(
            [
                mock.call.key("spc", timeout=mock.ANY),
                mock.call.chord("ctrl", "a", timeout=mock.ANY),
                mock.call.key("backspace", timeout=mock.ANY),
                mock.call.type_text(
                    ".\\telosadmin", timeout=mock.ANY),
                mock.call.sleep(2),
                mock.call.key("tab", timeout=mock.ANY),
                mock.call.observe(sign_in, mock.ANY),
                mock.call.observe(sign_in, mock.ANY),
                mock.call.disable_durable_capture(),
                mock.call.type_secret("private", timeout=mock.ANY),
                mock.call.prove_departure(
                    self.qmp,
                    evidence,
                    sign_in,
                    timeout=mock.ANY,
                    clock=adapter.clock,
                ),
                mock.call.sleep(2),
                mock.call.key("ret", timeout=mock.ANY),
                mock.call.sleep(2),
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
        self.assertEqual(11, final_timeout)
        self.qmp.type_text.assert_called_once_with(
            ".\\telosadmin", timeout=mock.ANY)
        self.assertEqual(
            [mock.call(2), mock.call(2), mock.call(2)],
            sleep.call_args_list,
        )

    @mock.patch.object(subject, "_prove_secret_entry_departure")
    @mock.patch.object(subject, "_GuiInteraction")
    @mock.patch.object(subject, "_private_evidence_root")
    @mock.patch.object(subject, "_load_references")
    def test_reauthentication_never_submits_without_secret_entry_departure(
        self, load_references, private_evidence_root, interaction_type,
        prove_departure,
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
        prove_departure.side_effect = RuntimeError("private backend detail")
        interaction = interaction_type.return_value
        adapter = self.adapter(rotation_plan=mock.Mock(
            initial_sign_in_delay=0,
            lock_settle_delay=0,
            wake_after_lock_keys=(),
            post_join_local_account_keys=(),
            post_join_local_account_calibrated=True,
            post_join_sign_in_manifest=None,
            checkpoint_timeout=11,
        ))

        with self.assertRaises(
                subject.WindowsLocalReauthenticationError) as caught:
            adapter.reauthenticate_local("private")

        self.assertEqual("type-secret", caught.exception.reauth_operation)
        self.assertNotIn("private backend detail", str(caught.exception))
        interaction.type_secret.assert_called_once_with(
            "private", timeout=mock.ANY)
        self.assertNotIn(mock.call("ret"), interaction.key.call_args_list)
        interaction.observe_ephemeral.assert_not_called()

    @mock.patch.object(subject, "_prove_secret_entry_departure")
    @mock.patch.object(subject, "_GuiInteraction")
    @mock.patch.object(subject, "_private_evidence_root")
    @mock.patch.object(subject, "_load_references")
    def test_reauthentication_classifies_persisted_sign_in_after_submit(
        self, load_references, private_evidence_root, interaction_type,
        prove_departure,
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

    @mock.patch.object(subject, "_prove_secret_entry_departure")
    @mock.patch.object(subject, "_GuiInteraction")
    @mock.patch.object(subject, "_private_evidence_root")
    @mock.patch.object(subject, "_load_references")
    @mock.patch.object(subject, "ControllerAuthDiagnosticSession")
    def test_post_submit_diagnostic_lifecycle_surrounds_gui_submission(
        self, controller_type, load_references, private_evidence_root,
        interaction_type, prove_departure,
    ):
        sign_in = mock.Mock(
            state_kind="sign-in",
            state="focused password field for domain account "
            "operator@FACTORY.TEST",
        )
        desktop = mock.sentinel.desktop
        load_references.return_value = (
            sign_in, desktop, mock.sentinel.security, mock.sentinel.change)
        private_evidence_root.return_value = self.root / "reauth-evidence"
        diagnostic_factory = mock.Mock()
        diagnostic = diagnostic_factory.return_value
        diagnostic.__enter__ = mock.Mock(return_value=diagnostic)
        diagnostic.__exit__ = mock.Mock(return_value=False)
        controller = controller_type.return_value
        controller.submitted.return_value = ControllerAuthResult(
            code=ControllerAuthCode.AUTHENTICATED)
        controller.armed = False
        interaction = interaction_type.return_value
        ordering = mock.Mock()
        ordering.attach_mock(interaction.observe, "observe")
        ordering.attach_mock(diagnostic.arm, "arm")
        ordering.attach_mock(interaction.disable_durable_capture, "disable")
        ordering.attach_mock(interaction.type_secret, "type_secret")
        ordering.attach_mock(prove_departure, "prove_departure")
        ordering.attach_mock(interaction.key, "key")
        ordering.attach_mock(diagnostic.submitted, "submitted")
        ordering.attach_mock(diagnostic.result, "result")
        ordering.attach_mock(controller.arm, "controller_arm")
        ordering.attach_mock(controller.submitted, "controller_submitted")
        ordering.attach_mock(
            interaction.observe_ephemeral, "observe_ephemeral")
        adapter = self.adapter(
            post_submit_diagnostic=diagnostic_factory,
            rotation_plan=mock.Mock(
                initial_sign_in_delay=0,
                lock_settle_delay=0,
                wake_after_lock_keys=(),
                post_join_operator_account_keys=(),
                post_join_operator_account_calibrated=True,
                post_join_operator_sign_in_manifest=None,
                checkpoint_timeout=11,
            ),
        )

        adapter.reauthenticate_domain_operator(
            "operator@FACTORY.TEST", "private", "a" * 32)

        diagnostic_factory.assert_called_once()
        controller_type.assert_called_once_with(
            self.boundary.controller_console,
            ControllerAuthExpectation("operator", "FACTORY", "10.1.31.11"),
            timeout=mock.ANY,
        )
        self.assertGreater(controller_type.call_args.kwargs["timeout"], 0)
        self.assertLessEqual(
            controller_type.call_args.kwargs["timeout"], 7)
        diagnostic_arguments = diagnostic_factory.call_args.kwargs
        self.assertEqual(
            "operator@FACTORY.TEST", diagnostic_arguments["principal"])
        self.assertGreater(diagnostic_arguments["timeout"], 0)
        self.assertLessEqual(diagnostic_arguments["timeout"], 7)
        self.assertEqual("a" * 32, diagnostic_arguments["nonce"])
        self.assertEqual(
            [
                mock.call.key("backspace", timeout=mock.ANY),
                mock.call.key("tab", timeout=mock.ANY),
                mock.call.observe(sign_in, mock.ANY),
                mock.call.observe(sign_in, mock.ANY),
                mock.call.controller_arm(),
                mock.call.arm(),
                mock.call.disable(),
                mock.call.type_secret("private", timeout=mock.ANY),
                mock.call.prove_departure(
                    self.qmp,
                    self.root / "reauth-evidence",
                    sign_in,
                    timeout=mock.ANY,
                    clock=adapter.clock,
                ),
                mock.call.key("ret", timeout=mock.ANY),
                mock.call.submitted(),
                mock.call.result(),
                mock.call.controller_submitted(),
                mock.call.observe_ephemeral(
                    desktop,
                    mock.ANY,
                    alternatives=(("sign-in", sign_in),),
                ),
            ],
            ordering.mock_calls,
        )
        diagnostic.__enter__.assert_called_once_with()
        diagnostic.__exit__.assert_called_once_with(None, None, None)
        self.assertFalse(adapter._com1_owned)

    @mock.patch.object(subject, "_prove_secret_entry_departure")
    @mock.patch.object(subject, "_GuiInteraction")
    @mock.patch.object(subject, "_private_evidence_root")
    @mock.patch.object(subject, "_load_references")
    def test_reviewed_domain_submit_focus_uses_exactly_one_tab_and_return(
        self, load_references, private_evidence_root, interaction_type,
        prove_departure,
    ):
        sign_in = mock.Mock(
            state_kind="sign-in",
            state="focused password field for domain account "
            "operator@FACTORY.TEST",
        )
        load_references.return_value = (
            sign_in, mock.sentinel.desktop,
            mock.sentinel.security, mock.sentinel.change,
        )
        private_evidence_root.return_value = self.root / "reauth-evidence"
        diagnostic_factory = mock.Mock()
        diagnostic = diagnostic_factory.return_value
        diagnostic.__enter__ = mock.Mock(return_value=diagnostic)
        diagnostic.__exit__ = mock.Mock(return_value=False)
        interaction = interaction_type.return_value
        ordering = mock.Mock()
        ordering.attach_mock(interaction.type_secret, "type_secret")
        ordering.attach_mock(prove_departure, "prove_departure")
        ordering.attach_mock(interaction.key, "key")
        ordering.attach_mock(diagnostic.submitted, "submitted")
        with mock.patch.object(subject.time, "sleep") as sleep:
            ordering.attach_mock(sleep, "sleep")
            adapter = self.adapter(
                post_submit_diagnostic=diagnostic_factory,
                rotation_plan=mock.Mock(
                    initial_sign_in_delay=0,
                    lock_settle_delay=2,
                    wake_after_lock_keys=(),
                    post_join_operator_account_keys=(),
                    post_join_operator_account_calibrated=True,
                    post_join_operator_sign_in_manifest=None,
                    post_join_operator_submit_focus_calibration=False,
                    post_join_operator_submit_focus_tabs=0,
                    post_join_operator_submit_focus_authorized=True,
                    post_join_operator_submit_focus_reference=Path(
                        "tracked-reviewed-reference.json"),
                    checkpoint_timeout=11,
                ),
            )

            adapter.reauthenticate_domain_operator(
                "operator@FACTORY.TEST", "private", "b" * 32)

        secret_index = ordering.mock_calls.index(
            mock.call.type_secret("private", timeout=mock.ANY))
        submitted_index = ordering.mock_calls.index(mock.call.submitted())
        submission_calls = ordering.mock_calls[secret_index + 1:submitted_index]
        self.assertEqual(
            [
                mock.call.prove_departure(
                    self.qmp,
                    self.root / "reauth-evidence",
                    sign_in,
                    timeout=mock.ANY,
                    clock=adapter.clock,
                ),
                mock.call.sleep(2),
                mock.call.key("tab", timeout=mock.ANY),
                mock.call.sleep(2),
                mock.call.key("ret", timeout=mock.ANY),
                mock.call.sleep(2),
            ],
            submission_calls,
        )

    @mock.patch.object(subject, "_prove_secret_entry_departure")
    @mock.patch.object(subject, "_GuiInteraction")
    @mock.patch.object(subject, "_private_evidence_root")
    @mock.patch.object(subject, "_load_references")
    def test_reviewed_submit_focus_timeout_never_issues_return(
        self, load_references, private_evidence_root, interaction_type,
        prove_departure,
    ):
        sign_in = mock.Mock(
            state_kind="sign-in",
            state="focused password field for domain account "
            "operator@FACTORY.TEST",
        )
        load_references.return_value = (
            sign_in, mock.sentinel.desktop,
            mock.sentinel.security, mock.sentinel.change,
        )
        private_evidence_root.return_value = self.root / "reauth-evidence"
        diagnostic = mock.Mock()
        diagnostic.__enter__ = mock.Mock(return_value=diagnostic)
        diagnostic.__exit__ = mock.Mock(return_value=False)
        now = {"value": 0.0}
        sleeps = {"count": 0}

        def sleep(_delay):
            sleeps["count"] += 1
            # The third drain follows the authorized Tab and deliberately
            # exhausts the deadline. Earlier drains settle public username
            # entry and secret entry respectively.
            if sleeps["count"] == 3:
                now["value"] = 8.0

        adapter = self.adapter(
            clock=lambda: now["value"],
            post_submit_diagnostic=mock.Mock(return_value=diagnostic),
            rotation_plan=mock.Mock(
                initial_sign_in_delay=0,
                lock_settle_delay=2,
                wake_after_lock_keys=(),
                post_join_operator_account_keys=(),
                post_join_operator_account_calibrated=True,
                post_join_operator_sign_in_manifest=None,
                post_join_operator_submit_focus_calibration=False,
                post_join_operator_submit_focus_tabs=0,
                post_join_operator_submit_focus_authorized=True,
                post_join_operator_submit_focus_reference=Path(
                    "tracked-reviewed-reference.json"),
                checkpoint_timeout=11,
            ),
        )
        with (
            mock.patch.object(subject.time, "sleep", side_effect=sleep),
            self.assertRaises(
                subject.WindowsLocalReauthenticationError
            ) as caught,
        ):
            adapter.reauthenticate_domain_operator(
                "operator@FACTORY.TEST", "private", "c" * 32)

        self.assertEqual("submit", caught.exception.reauth_operation)
        keys = interaction_type.return_value.key.call_args_list
        self.assertEqual(2, sum(call.args[0] == "tab" for call in keys))
        self.assertEqual(0, sum(call.args[0] == "ret" for call in keys))

    @mock.patch.object(subject, "_prove_secret_entry_departure")
    @mock.patch.object(subject, "_GuiInteraction")
    @mock.patch.object(subject, "_private_evidence_root")
    @mock.patch.object(subject, "_load_references")
    def test_post_submit_diagnostic_arm_failure_precedes_secret_entry(
        self, load_references, private_evidence_root, interaction_type,
        prove_departure,
    ):
        sign_in = mock.Mock(
            state_kind="sign-in",
            state="focused password field for domain account "
            "operator@FACTORY.TEST",
        )
        load_references.return_value = (
            sign_in, mock.sentinel.desktop,
            mock.sentinel.security, mock.sentinel.change,
        )
        private_evidence_root.return_value = self.root / "reauth-evidence"
        diagnostic_factory = mock.Mock()
        diagnostic = diagnostic_factory.return_value
        diagnostic.__enter__ = mock.Mock(return_value=diagnostic)
        diagnostic.__exit__ = mock.Mock(return_value=False)
        diagnostic.arm.side_effect = RuntimeError("private watcher detail")
        interaction = interaction_type.return_value
        adapter = self.adapter(
            post_submit_diagnostic=diagnostic_factory,
            rotation_plan=mock.Mock(
                initial_sign_in_delay=0,
                lock_settle_delay=0,
                wake_after_lock_keys=(),
                post_join_operator_account_keys=(),
                post_join_operator_account_calibrated=True,
                post_join_operator_sign_in_manifest=None,
                checkpoint_timeout=11,
            ),
        )

        with self.assertRaises(
                subject.WindowsLocalReauthenticationError) as caught:
            adapter.reauthenticate_domain_operator(
                "operator@FACTORY.TEST", "private", "a" * 32)

        self.assertEqual(
            "diagnostic-arm-launch", caught.exception.reauth_operation)
        self.assertNotIn("private watcher detail", str(caught.exception))
        interaction.disable_durable_capture.assert_not_called()
        interaction.type_secret.assert_not_called()
        prove_departure.assert_not_called()
        self.assertNotIn(
            mock.call("ret", timeout=mock.ANY),
            interaction.key.call_args_list,
        )
        diagnostic.submitted.assert_not_called()
        diagnostic.result.assert_not_called()
        diagnostic.__exit__.assert_called_once()
        self.assertFalse(adapter._com1_owned)

    @mock.patch.object(subject, "_prove_secret_entry_departure")
    @mock.patch.object(subject, "_GuiInteraction")
    @mock.patch.object(subject, "_private_evidence_root")
    @mock.patch.object(subject, "_load_references")
    def test_post_submit_diagnostic_result_cannot_authorize_acceptance(
        self, load_references, private_evidence_root, interaction_type,
        prove_departure,
    ):
        sign_in = mock.Mock(
            state_kind="sign-in",
            state="focused password field for domain account "
            "operator@FACTORY.TEST",
        )
        load_references.return_value = (
            sign_in, mock.sentinel.desktop,
            mock.sentinel.security, mock.sentinel.change,
        )
        private_evidence_root.return_value = self.root / "reauth-evidence"
        diagnostic_factory = mock.Mock()
        diagnostic = diagnostic_factory.return_value
        diagnostic.__enter__ = mock.Mock(return_value=diagnostic)
        elapsed = [0.0]
        diagnostic.result.side_effect = lambda: (
            elapsed.__setitem__(0, elapsed[0] + 20)
            or PostSubmitDiagnosticCode.INTERACTIVE_LOGON_SUCCESS
        )
        diagnostic.__exit__ = mock.Mock(side_effect=lambda *_args: (
            elapsed.__setitem__(0, elapsed[0] + 20) or False))
        interaction_type.return_value.observe_ephemeral.side_effect = (
            subject.WindowsIdentityGuiNearReference("sign-in"))
        adapter = self.adapter(
            clock=lambda: elapsed[0],
            post_submit_diagnostic=diagnostic_factory,
            rotation_plan=mock.Mock(
                initial_sign_in_delay=0,
                lock_settle_delay=0,
                wake_after_lock_keys=(),
                post_join_operator_account_keys=(),
                post_join_operator_account_calibrated=True,
                post_join_operator_sign_in_manifest=None,
                checkpoint_timeout=11,
            ),
        )

        with self.assertRaises(
                subject.WindowsLocalReauthenticationError) as caught:
            adapter.reauthenticate_domain_operator(
                "operator@FACTORY.TEST", "private", "a" * 32)

        self.assertEqual(
            "desktop-sign-in-near-reference",
            caught.exception.reauth_operation,
        )
        self.assertIs(
            PostSubmitDiagnosticCode.INTERACTIVE_LOGON_SUCCESS,
            caught.exception.post_submit_diagnostic,
        )
        self.assertNotIn("private", str(caught.exception))
        diagnostic.result.assert_called_once_with()
        diagnostic.__exit__.assert_called_once()
        self.assertEqual(
            11,
            interaction_type.return_value.observe_ephemeral.call_args.args[1],
        )
        self.assertFalse(adapter._com1_owned)

    @mock.patch.object(subject, "_prove_secret_entry_departure")
    @mock.patch.object(subject, "_GuiInteraction")
    @mock.patch.object(subject, "_private_evidence_root")
    @mock.patch.object(subject, "_load_references")
    def test_bad_credential_diagnostic_cannot_veto_exact_gui_desktop(
        self, load_references, private_evidence_root, interaction_type,
        prove_departure,
    ):
        sign_in = mock.Mock(
            state_kind="sign-in",
            state="focused password field for domain account "
            "operator@FACTORY.TEST",
        )
        desktop = mock.sentinel.desktop
        load_references.return_value = (
            sign_in, desktop, mock.sentinel.security, mock.sentinel.change)
        private_evidence_root.return_value = self.root / "reauth-evidence"
        diagnostic_factory = mock.Mock()
        diagnostic = diagnostic_factory.return_value
        diagnostic.__enter__ = mock.Mock(return_value=diagnostic)
        diagnostic.__exit__ = mock.Mock(return_value=False)
        diagnostic.result.return_value = (
            PostSubmitDiagnosticCode.BAD_CREDENTIAL)
        adapter = self.adapter(
            post_submit_diagnostic=diagnostic_factory,
            rotation_plan=mock.Mock(
                initial_sign_in_delay=0,
                lock_settle_delay=0,
                wake_after_lock_keys=(),
                post_join_operator_account_keys=(),
                post_join_operator_account_calibrated=True,
                post_join_operator_sign_in_manifest=None,
                checkpoint_timeout=11,
            ),
        )

        adapter.reauthenticate_domain_operator(
            "operator@FACTORY.TEST", "private", "a" * 32)

        interaction_type.return_value.observe_ephemeral.assert_called_once_with(
            desktop, 11, alternatives=(("sign-in", sign_in),))
        self.assertIs(
            PostSubmitDiagnosticCode.BAD_CREDENTIAL,
            adapter._post_submit_diagnostic_code,
        )

        interaction_type.return_value.observe_ephemeral.side_effect = (
            RuntimeError("private desktop backend detail"))
        diagnostic.result.side_effect = RuntimeError(
            "private result transport detail")
        adapter = self.adapter(
            post_submit_diagnostic=diagnostic_factory,
            rotation_plan=adapter.rotation_plan,
        )
        with self.assertRaises(
                subject.WindowsLocalReauthenticationError) as caught:
            adapter.reauthenticate_domain_operator(
                "operator@FACTORY.TEST", "private", "b" * 32)
        self.assertEqual("desktop", caught.exception.reauth_operation)
        self.assertIsNone(caught.exception.post_submit_diagnostic)
        self.assertIs(
            subject.PostSubmitDiagnosticCollection.
            RESULT_RECEIPT_UNAVAILABLE,
            caught.exception.post_submit_collection,
        )
        self.assertNotIn("private desktop", str(caught.exception))
        self.assertIsNone(caught.exception.__cause__)
        self.assertIsNone(caught.exception.__context__)

        diagnostic.submitted.side_effect = RuntimeError(
            "private submitted transport detail")
        diagnostic.result.side_effect = None
        diagnostic.result.return_value = PostSubmitDiagnosticCode.BAD_CREDENTIAL
        adapter = self.adapter(
            post_submit_diagnostic=diagnostic_factory,
            rotation_plan=adapter.rotation_plan,
        )
        with self.assertRaises(
                subject.WindowsLocalReauthenticationError) as caught:
            adapter.reauthenticate_domain_operator(
                "operator@FACTORY.TEST", "private", "c" * 32)
        self.assertIs(
            subject.PostSubmitDiagnosticCollection.
            SUBMITTED_RECEIPT_UNAVAILABLE,
            caught.exception.post_submit_collection,
        )

        diagnostic.submitted.side_effect = None
        diagnostic.submitted.return_value = None
        diagnostic.result.side_effect = RuntimeError(
            "private root result transport detail")
        diagnostic.__exit__.side_effect = RuntimeError(
            "private cleanup transport detail")
        adapter = self.adapter(
            post_submit_diagnostic=diagnostic_factory,
            rotation_plan=adapter.rotation_plan,
        )
        with self.assertRaises(
                subject.WindowsLocalReauthenticationError) as caught:
            adapter.reauthenticate_domain_operator(
                "operator@FACTORY.TEST", "private", "d" * 32)
        self.assertIs(
            subject.PostSubmitDiagnosticCleanup.
            CLEANUP_RECEIPT_UNAVAILABLE,
            caught.exception.post_submit_cleanup,
        )
        self.assertIs(
            subject.PostSubmitDiagnosticCollection.
            RESULT_RECEIPT_UNAVAILABLE,
            caught.exception.post_submit_collection,
        )
        self.assertNotIn("private cleanup", str(caught.exception))
        self.assertNotIn("private root", str(caught.exception))

    @mock.patch.object(subject, "_prove_secret_entry_departure")
    @mock.patch.object(subject, "_GuiInteraction")
    @mock.patch.object(subject, "_private_evidence_root")
    @mock.patch.object(subject, "_load_references")
    def test_armed_diagnostic_cleanup_failure_stops_at_reauth_boundary(
        self, load_references, private_evidence_root, interaction_type,
        prove_departure,
    ):
        sign_in = mock.Mock(
            state_kind="sign-in",
            state="focused password field for domain account "
            "operator@FACTORY.TEST",
        )
        desktop = mock.sentinel.desktop
        load_references.return_value = (
            sign_in, desktop, mock.sentinel.security, mock.sentinel.change)
        private_evidence_root.return_value = self.root / "reauth-evidence"
        diagnostic_factory = mock.Mock()
        diagnostic = diagnostic_factory.return_value
        diagnostic.__enter__ = mock.Mock(return_value=diagnostic)
        diagnostic.__exit__ = mock.Mock(
            side_effect=RuntimeError("private cleanup transport detail"))
        diagnostic.result.return_value = (
            PostSubmitDiagnosticCode.INTERACTIVE_LOGON_SUCCESS)
        adapter = self.adapter(
            post_submit_diagnostic=diagnostic_factory,
            rotation_plan=mock.Mock(
                initial_sign_in_delay=0,
                lock_settle_delay=0,
                wake_after_lock_keys=(),
                post_join_operator_account_keys=(),
                post_join_operator_account_calibrated=True,
                post_join_operator_sign_in_manifest=None,
                checkpoint_timeout=11,
            ),
        )

        with self.assertRaises(
                subject.WindowsLocalReauthenticationError) as caught:
            adapter.reauthenticate_domain_operator(
                "operator@FACTORY.TEST", "private", "e" * 32)

        self.assertEqual(
            "diagnostic-cleanup", caught.exception.reauth_operation)
        self.assertIs(
            PostSubmitDiagnosticCode.INTERACTIVE_LOGON_SUCCESS,
            caught.exception.post_submit_diagnostic,
        )
        self.assertIs(
            subject.PostSubmitDiagnosticCleanup.
            CLEANUP_RECEIPT_UNAVAILABLE,
            caught.exception.post_submit_cleanup,
        )
        self.assertNotIn("private cleanup", str(caught.exception))
        self.assertIsNone(caught.exception.__cause__)
        self.assertIsNone(caught.exception.__context__)
        interaction_type.return_value.observe_ephemeral.assert_called_once_with(
            desktop, 11, alternatives=(("sign-in", sign_in),))
        self.assertTrue(adapter._static_probe_poisoned)
        self.assertFalse(adapter._com1_owned)

    @mock.patch.object(subject, "_prove_secret_entry_departure")
    @mock.patch.object(subject, "_GuiInteraction")
    @mock.patch.object(subject, "_private_evidence_root")
    @mock.patch.object(subject, "_load_references")
    def test_reauthentication_maps_terminal_near_references(
        self, load_references, private_evidence_root, interaction_type,
        prove_departure,
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

    @mock.patch.object(subject, "_prove_secret_entry_departure")
    @mock.patch.object(subject, "_GuiInteraction")
    @mock.patch.object(subject, "_private_evidence_root")
    @mock.patch.object(subject, "_load_references")
    @mock.patch.object(subject.time, "sleep")
    def test_reauthentication_deadline_starts_after_boot_settle(
        self, sleep, load_references, private_evidence_root, interaction_type,
        prove_departure,
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
                lock_settle_delay=2,
                wake_after_lock_keys=("spc",),
                post_join_local_account_keys=(),
                post_join_local_account_calibrated=True,
                post_join_sign_in_manifest=None,
                checkpoint_timeout=20,
            ),
        )

        adapter.reauthenticate_local("private")

        self.assertEqual(
            [mock.call(5), mock.call(2), mock.call(2), mock.call(2)],
            sleep.call_args_list,
        )
        self.assertEqual(
            8,
            interaction_type.return_value.observe.call_args_list[0].args[1],
        )
        self.assertEqual(
            20,
            interaction_type.return_value.observe_ephemeral.call_args.args[1],
        )

    @mock.patch.object(subject, "_GuiInteraction")
    @mock.patch.object(subject, "_private_evidence_root")
    @mock.patch.object(subject, "_load_references")
    def test_local_and_operator_public_text_receive_remaining_deadline(
        self, load_references, private_evidence_root, interaction_type,
    ):
        private_evidence_root.return_value = self.root / "reauth-evidence"
        desktop = mock.sentinel.desktop
        plan = mock.Mock(
            expected_guest=mock.sentinel.guest,
            initial_sign_in_delay=0,
            lock_settle_delay=0,
            wake_after_lock_keys=(),
            post_join_local_account_keys=("down",),
            post_join_operator_account_keys=("up",),
            post_join_local_account_calibrated=True,
            post_join_operator_account_calibrated=True,
            post_join_sign_in_manifest=None,
            post_join_operator_sign_in_manifest=None,
            checkpoint_timeout=20,
        )

        for domain_operator, principal, state in (
            (False, ".\\telosadmin",
             "focused password field for local account telosadmin"),
            (True, "operator@FACTORY.TEST",
             "focused password field for domain account "
             "operator@FACTORY.TEST"),
        ):
            with self.subTest(domain_operator=domain_operator):
                self.qmp.reset_mock()
                interaction_type.return_value.reset_mock()
                load_references.return_value = (
                    mock.Mock(state_kind="sign-in", state=state),
                    desktop,
                    mock.sentinel.security,
                    mock.sentinel.change,
                )
                self.qmp.type_text.side_effect = RuntimeError(
                    "private backend detail")
                adapter = self.adapter(rotation_plan=plan)

                with self.assertRaises(
                        subject.WindowsLocalReauthenticationError) as caught:
                    if domain_operator:
                        adapter.reauthenticate_domain_operator(
                            principal, "private", "a" * 32)
                    else:
                        adapter.reauthenticate_local("private")

                self.assertEqual(
                    "type-public-username",
                    caught.exception.reauth_operation,
                )
                self.assertNotIn(
                    "private backend detail", str(caught.exception))
                self.assertIsNone(caught.exception.__cause__)
                self.assertIsNone(caught.exception.__context__)
                timeout = self.qmp.type_text.call_args.kwargs["timeout"]
                self.assertGreater(timeout, 0)
                self.assertLessEqual(timeout, 7)
                self.assertEqual(
                    [
                        mock.call(
                            "up" if domain_operator else "down",
                            timeout=mock.ANY,
                        ),
                        mock.call("backspace", timeout=mock.ANY),
                    ],
                    interaction_type.return_value.key.call_args_list,
                )
                interaction_type.return_value.chord.assert_called_once_with(
                    "ctrl", "a", timeout=mock.ANY)
                interaction_type.return_value.type_secret.assert_not_called()

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
            [
                mock.call("spc", timeout=mock.ANY),
                mock.call("tab", timeout=mock.ANY),
            ],
        )
        interaction_type.return_value.type_secret.assert_not_called()
        self.qmp.type_text.assert_called_once_with(
            ".\\telosadmin", timeout=mock.ANY)
        self.assertEqual(
            [
                mock.call.sleep(5),
                mock.call.sample(
                    self.qmp, self.root / "reauth-evidence"),
                mock.call.key("spc", timeout=mock.ANY),
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
