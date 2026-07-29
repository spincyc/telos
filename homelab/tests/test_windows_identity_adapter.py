import tempfile
import unittest
from pathlib import Path
import socket
from unittest import mock

from homelab.vm import windows_identity_adapter as subject


class WindowsIdentityAdapterTests(unittest.TestCase):
    def test_local_reauthentication_operations_drop_backend_context(self):
        for operation in sorted(
            subject.WindowsLocalReauthenticationError._OPERATIONS
        ):
            with self.subTest(operation=operation), self.assertRaises(
                subject.WindowsLocalReauthenticationError,
            ) as caught:
                subject._run_local_reauthentication_operation(
                    operation,
                    lambda: (_ for _ in ()).throw(
                        RuntimeError("backend-private")),
                )
            self.assertEqual(operation, caught.exception.reauth_operation)
            self.assertNotIn("backend-private", str(caught.exception))
            self.assertIsNone(caught.exception.__cause__)
            self.assertIsNone(caught.exception.__context__)

    def test_local_reauthentication_operations_preserve_interruptions(self):
        interruptions = (
            KeyboardInterrupt(),
            SystemExit(17),
            subject.RunInterrupted(15),
        )
        for interruption in interruptions:
            with (
                self.subTest(interruption=type(interruption).__name__),
                self.assertRaises(type(interruption)) as caught,
            ):
                subject._run_local_reauthentication_operation(
                    "type-secret",
                    lambda interruption=interruption: (
                        _ for _ in ()).throw(interruption),
                )
            self.assertIs(interruption, caught.exception)

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
            self.assertEqual(
                adapter.reauthenticate_domain_operator,
                callbacks.reauthenticate_domain_operator,
            )

    def test_domain_operator_reauthentication_is_exactly_allowlisted(self):
        with tempfile.TemporaryDirectory() as name:
            adapter = self.adapter(Path(name))
            adapter._reauthenticate = mock.Mock()
            adapter.reauthenticate_domain_operator(
                "operator@FACTORY.TEST", "private", "ab" * 16)
            adapter._reauthenticate.assert_called_once_with(
                "operator@FACTORY.TEST",
                "private",
                domain_operator=True,
                diagnostic_nonce="ab" * 16,
            )
            adapter._reauthenticate.reset_mock()
            with self.assertRaisesRegex(
                    subject.WindowsLocalReauthenticationError,
                    "prove-password-target"):
                adapter.reauthenticate_domain_operator(
                    "other@FACTORY.TEST", "private", "ab" * 16)
            adapter._reauthenticate.assert_not_called()

    def test_local_reauthentication_remains_a_distinct_wrapper(self):
        with tempfile.TemporaryDirectory() as name:
            adapter = self.adapter(Path(name))
            adapter._reauthenticate = mock.Mock()
            adapter.reauthenticate_local("private")
            adapter._reauthenticate.assert_called_once_with(
                r".\telosadmin", "private", domain_operator=False)

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
            adapter._static_probe_poisoned = True
            with self.assertRaises(
                subject.WindowsIdentityAdapterError,
            ) as caught:
                adapter.static_probe("domain-state")
        self.assertEqual(
            "static-probe.domain-state.preflight",
            caught.exception.diagnostic.operation,
        )
        self.assertEqual(
            "WindowsIdentityAdapterError",
            caught.exception.diagnostic.error_type,
        )
        self.assertIsNone(caught.exception.__cause__)
        self.assertIsNone(caught.exception.__context__)

    def test_static_probe_reports_com1_lease_acquisition_failure(self):
        with tempfile.TemporaryDirectory() as name:
            adapter = self.adapter(Path(name))
            adapter._static_probe_poisoned = False
            adapter._com1_owned = True
            with self.assertRaises(
                subject.WindowsIdentityAdapterError,
            ) as caught:
                adapter.static_probe("interactive-operator")
        self.assertEqual(
            "static-probe.interactive-operator.lease",
            caught.exception.diagnostic.operation,
        )
        self.assertEqual(
            "WindowsIdentityAdapterError",
            caught.exception.diagnostic.error_type,
        )
        self.assertIsNone(caught.exception.__cause__)
        self.assertIsNone(caught.exception.__context__)

    @staticmethod
    def launcher():
        return b"3\n"

    @staticmethod
    def start(action="controller-readiness"):
        return (
            b'{"schema_version":1,"action":"' + action.encode()
            + b'","result":"start"}\n'
        )

    @staticmethod
    def outcome(action="controller-readiness"):
        return (
            b'{"schema_version":1,"action":"' + action.encode()
            + b'","result":"pass","observed_at":"2026-07-28T15:00:00Z",'
            b'"observation":{"samba_ad":true,"dns":true,"kerberos":true,'
            b'"time":true,"synthetic_directory":true}}\n'
        )

    def test_controller_readiness_probe_reports_each_fixed_subphase(self):
        class SecretFailure(RuntimeError):
            pass

        for phase in (
            "connect", "launch", "launcher-receive", "launcher-parse",
            "start-receive", "start-parse",
            "outcome-receive", "outcome-parse",
        ):
            with self.subTest(phase=phase), tempfile.TemporaryDirectory() as name:
                adapter = self.adapter(Path(name))
                adapter._serial_socket = mock.Mock(return_value=Path("/socket"))
                stream = mock.MagicMock()
                stream.__enter__.return_value = stream
                stream.recv.side_effect = [
                    self.launcher(), self.start(), self.outcome()]
                if phase == "connect":
                    stream.connect.side_effect = SecretFailure("private")
                elif phase == "launch":
                    adapter.launch_guest = mock.Mock(
                        side_effect=SecretFailure("private"))
                elif phase == "launcher-receive":
                    adapter.launch_guest = mock.Mock()
                    stream.recv.side_effect = TimeoutError("private")
                elif phase == "launcher-parse":
                    adapter.launch_guest = mock.Mock()
                    stream.recv.side_effect = [b"invalid\n"]
                elif phase == "start-receive":
                    adapter.launch_guest = mock.Mock()
                    stream.recv.side_effect = [
                        self.launcher(), TimeoutError("private")]
                elif phase == "start-parse":
                    adapter.launch_guest = mock.Mock()
                    stream.recv.side_effect = [
                        self.launcher(), b"invalid\n"]
                elif phase == "outcome-receive":
                    adapter.launch_guest = mock.Mock()
                    stream.recv.side_effect = [
                        self.launcher(), self.start(), TimeoutError("private")]
                else:
                    adapter.launch_guest = mock.Mock()
                    stream.recv.side_effect = [
                        self.launcher(), self.start(), b"invalid\n"]
                with mock.patch.object(
                    subject.socket, "socket", return_value=stream,
                ), self.assertRaises(
                    subject.WindowsIdentityAdapterError,
                ) as caught:
                    adapter.static_probe("controller-readiness")
                error = caught.exception
                self.assertEqual(
                    "static-probe.controller-readiness." + phase,
                    error.diagnostic.operation,
                )
                self.assertEqual(
                    (
                        "TimeoutError"
                        if phase in {
                            "launcher-receive", "start-receive",
                            "outcome-receive",
                        }
                        else "WindowsControlSerialError"
                        if phase in {
                            "launcher-parse", "start-parse", "outcome-parse",
                        }
                        else "UnexpectedError"
                    ),
                    error.diagnostic.error_type,
                )
                self.assertNotIn("private", str(error))
                self.assertIsNone(error.__cause__)
                self.assertIsNone(error.__context__)

    def test_fixed_guest_probe_failure_is_distinct_from_malformed_record(self):
        secret = "private-guest-detail"
        failure = (
            b'{"schema_version":1,"action":"controller-readiness",'
            b'"result":"fail","observed_at":"2026-07-28T15:00:00Z",'
            b'"failure":{"phase":"observation",'
            b'"code":"guest-probe-error"}}\n'
        )
        for payload, expected_phase, expected_error in (
            (failure, "guest", "WindowsGuestProbeError"),
            (secret.encode() + b"\n", "outcome-parse",
             "WindowsControlSerialError"),
        ):
            with self.subTest(
                phase=expected_phase,
            ), tempfile.TemporaryDirectory() as name:
                adapter = self.adapter(Path(name))
                adapter._serial_socket = mock.Mock(return_value=Path("/socket"))
                adapter.launch_guest = mock.Mock()
                stream = mock.MagicMock()
                stream.__enter__.return_value = stream
                stream.recv.side_effect = [
                    self.launcher(), self.start(), payload]
                with mock.patch.object(
                    subject.socket, "socket", return_value=stream,
                ), self.assertRaises(
                    subject.WindowsIdentityAdapterError,
                ) as caught:
                    adapter.static_probe("controller-readiness")
                error = caught.exception
                self.assertEqual(
                    "static-probe.controller-readiness." + expected_phase,
                    error.diagnostic.operation,
                )
                self.assertEqual(
                    expected_error, error.diagnostic.error_type)
                self.assertNotIn(secret, str(error))
                self.assertIsNone(error.__cause__)
                self.assertIsNone(error.__context__)

    def test_probe_accepts_fragmented_and_coalesced_two_record_stream(self):
        payload = self.launcher() + self.start() + self.outcome()
        for chunks in (
            [payload],
            [payload[:7], payload[7:41], payload[41:]],
        ):
            with self.subTest(chunks=len(chunks)), \
                    tempfile.TemporaryDirectory() as name:
                adapter = self.adapter(Path(name))
                adapter._serial_socket = mock.Mock(return_value=Path("/socket"))
                adapter.launch_guest = mock.Mock()
                stream = mock.MagicMock()
                stream.__enter__.return_value = stream
                stream.recv.side_effect = chunks
                with mock.patch.object(
                    subject.socket, "socket", return_value=stream,
                ):
                    result = adapter.static_probe("controller-readiness")
                self.assertEqual("pass", result["result"])

    def test_probe_rejects_reordered_duplicate_extra_and_wrong_action(self):
        invalid_streams = (
            self.launcher() + self.outcome() + self.start(),
            self.launcher() + self.launcher() + self.start() + self.outcome(),
            self.launcher() + self.start() + self.start(),
            self.launcher() + self.start() + self.outcome() + self.outcome(),
            b"4\n" + self.start() + self.outcome(),
            self.launcher() + self.start("domain-state") + self.outcome(),
            self.launcher() + self.start() + self.outcome("domain-state"),
        )
        for payload in invalid_streams:
            with self.subTest(payload=payload), \
                    tempfile.TemporaryDirectory() as name:
                adapter = self.adapter(Path(name))
                adapter._serial_socket = mock.Mock(return_value=Path("/socket"))
                adapter.launch_guest = mock.Mock()
                stream = mock.MagicMock()
                stream.__enter__.return_value = stream
                stream.recv.return_value = payload
                with mock.patch.object(
                    subject.socket, "socket", return_value=stream,
                ), self.assertRaises(subject.WindowsIdentityAdapterError):
                    adapter.static_probe("controller-readiness")

    def test_outcome_receive_failure_poisons_session_without_second_launch(self):
        with tempfile.TemporaryDirectory() as name:
            adapter = self.adapter(Path(name))
            adapter._serial_socket = mock.Mock(return_value=Path("/socket"))
            adapter.launch_guest = mock.Mock()
            stream = mock.MagicMock()
            stream.__enter__.return_value = stream
            stream.recv.side_effect = [
                self.launcher(), self.start(), TimeoutError("private")]
            with mock.patch.object(
                subject.socket, "socket", return_value=stream,
            ), self.assertRaises(subject.WindowsIdentityAdapterError) as first:
                adapter.static_probe("controller-readiness")
            self.assertEqual(
                "static-probe.controller-readiness.outcome-receive",
                first.exception.diagnostic.operation,
            )
            with mock.patch.object(
                subject.socket, "socket",
            ) as socket_factory, self.assertRaisesRegex(
                subject.WindowsIdentityAdapterError, "VM teardown",
            ):
                adapter.static_probe("controller-readiness")
            adapter.launch_guest.assert_called_once()
            socket_factory.assert_not_called()

    def test_launch_failure_after_connect_poisons_without_second_attempt(self):
        with tempfile.TemporaryDirectory() as name:
            adapter = self.adapter(Path(name))
            adapter._serial_socket = mock.Mock(return_value=Path("/socket"))
            adapter.launch_guest = mock.Mock(
                side_effect=RuntimeError("private-post-submit-state"))
            first_stream = mock.MagicMock()
            first_stream.__enter__.return_value = first_stream
            with mock.patch.object(
                subject.socket, "socket", return_value=first_stream,
            ), self.assertRaises(
                subject.WindowsIdentityAdapterError,
            ) as first:
                adapter.static_probe("controller-readiness")
            self.assertEqual(
                "static-probe.controller-readiness.launch",
                first.exception.diagnostic.operation,
            )
            self.assertNotIn("private", str(first.exception))
            self.assertIsNone(first.exception.__cause__)
            self.assertIsNone(first.exception.__context__)
            with mock.patch.object(
                subject.socket, "socket",
            ) as socket_factory, self.assertRaisesRegex(
                subject.WindowsIdentityAdapterError, "VM teardown",
            ):
                adapter.static_probe("controller-readiness")
            adapter.launch_guest.assert_called_once()
            first_stream.connect.assert_called_once()
            socket_factory.assert_not_called()

    def test_every_post_launch_protocol_failure_poisons_session(self):
        for payload in (b"", b'{"private":"guest-secret"}\n'):
            with self.subTest(payload=payload), \
                    tempfile.TemporaryDirectory() as name:
                adapter = self.adapter(Path(name))
                adapter._serial_socket = mock.Mock(return_value=Path("/socket"))
                adapter.launch_guest = mock.Mock()
                stream = mock.MagicMock()
                stream.__enter__.return_value = stream
                stream.recv.return_value = payload
                with mock.patch.object(
                    subject.socket, "socket", return_value=stream,
                ), self.assertRaises(
                    subject.WindowsIdentityAdapterError,
                ) as first:
                    adapter.static_probe("controller-readiness")
                self.assertNotIn("guest-secret", str(first.exception))
                self.assertIsNone(first.exception.__cause__)
                self.assertIsNone(first.exception.__context__)
                with self.assertRaisesRegex(
                    subject.WindowsIdentityAdapterError, "VM teardown",
                ):
                    adapter.static_probe("controller-readiness")
                adapter.launch_guest.assert_called_once()

    def test_two_record_transport_has_one_total_byte_cap(self):
        with tempfile.TemporaryDirectory() as name:
            adapter = self.adapter(Path(name))
            adapter._serial_socket = mock.Mock(return_value=Path("/socket"))
            adapter.launch_guest = mock.Mock()
            start = self.start()
            stream = mock.MagicMock()
            stream.__enter__.return_value = stream
            stream.recv.side_effect = [
                self.launcher(), start,
                b" " * (
                    subject.MAX_RECORD_BYTES
                    - len(self.launcher()) - len(start)
                ),
            ]
            with mock.patch.object(
                subject.socket, "socket", return_value=stream,
            ), self.assertRaises(
                subject.WindowsIdentityAdapterError,
            ) as caught:
                adapter.static_probe("controller-readiness")
            self.assertEqual(
                "static-probe.controller-readiness.outcome-receive",
                caught.exception.diagnostic.operation,
            )
            self.assertIsNone(caught.exception.__cause__)
            self.assertIsNone(caught.exception.__context__)

    def test_static_probe_uses_one_absolute_three_stage_deadline(self):
        with tempfile.TemporaryDirectory() as name:
            adapter = subject.NativeWindowsAcceptanceAdapter(
                self.adapter(Path(name)).boundary,
                Path(name),
                realm="factory.test",
                local_principal="telosadmin",
                scan_secrets=mock.sentinel.scanner,
                timeout=1,
                clock=mock.Mock(side_effect=[0.0, 0.1, 0.3, 0.7, 1.01]),
            )
            adapter._serial_socket = mock.Mock(return_value=Path("/socket"))
            adapter.launch_guest = mock.Mock()
            stream = mock.MagicMock()
            stream.__enter__.return_value = stream
            stream.recv.side_effect = [
                self.launcher(), self.start(), self.outcome()]
            with mock.patch.object(
                subject.socket, "socket", return_value=stream,
            ), self.assertRaises(
                subject.WindowsIdentityAdapterError,
            ) as caught:
                adapter.static_probe("controller-readiness")
            self.assertEqual(
                "static-probe.controller-readiness.outcome-receive",
                caught.exception.diagnostic.operation,
            )
            self.assertEqual(
                "TimeoutError", caught.exception.diagnostic.error_type)
            self.assertEqual(2, stream.recv.call_count)
            self.assertIsNone(caught.exception.__cause__)
            self.assertIsNone(caught.exception.__context__)

    def test_post_reboot_reauthentication_fails_without_calibrated_plan(self):
        with tempfile.TemporaryDirectory() as name:
            adapter = self.adapter(Path(name))
            with self.assertRaisesRegex(
                    subject.WindowsLocalReauthenticationError,
                    "prove-password-target"):
                adapter.reauthenticate_local("private")

    @mock.patch.object(subject, "_load_references")
    def test_reauthentication_reference_failure_drops_context(
        self, load_references,
    ):
        load_references.side_effect = RuntimeError("backend-private")
        with tempfile.TemporaryDirectory() as name:
            adapter = self.adapter(Path(name))
            adapter.rotation_plan = mock.Mock(
                post_join_local_account_calibrated=True)
            with self.assertRaises(
                subject.WindowsLocalReauthenticationError,
            ) as caught:
                adapter.reauthenticate_local("private")
        self.assertEqual(
            "prove-password-target", caught.exception.reauth_operation)
        self.assertIsNone(caught.exception.__cause__)
        self.assertIsNone(caught.exception.__context__)

    @mock.patch.object(subject, "_load_references")
    def test_reauthentication_reference_property_failure_drops_context(
        self, load_references,
    ):
        class HostileReference:
            @property
            def state_kind(self):
                backend = RuntimeError("backend-private")
                backend.__context__ = ValueError("nested-private")
                raise backend

        load_references.return_value = (
            HostileReference(), mock.sentinel.desktop,
            mock.sentinel.security, mock.sentinel.change,
        )
        with tempfile.TemporaryDirectory() as name:
            adapter = self.adapter(Path(name))
            adapter.rotation_plan = mock.Mock(
                post_join_local_account_calibrated=True)
            with self.assertRaises(
                subject.WindowsLocalReauthenticationError,
            ) as caught:
                adapter.reauthenticate_local("private")
        self.assertEqual(
            "prove-password-target", caught.exception.reauth_operation)
        self.assertNotIn("private", str(caught.exception))
        self.assertIsNone(caught.exception.__cause__)
        self.assertIsNone(caught.exception.__context__)

    @mock.patch.object(subject, "_GuiInteraction")
    @mock.patch.object(subject, "_private_evidence_root")
    @mock.patch.object(subject, "_load_references")
    def test_reauthentication_selection_property_failure_drops_context(
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
        private_evidence_root.return_value = mock.sentinel.evidence

        class HostilePlan:
            post_join_sign_in_manifest = None
            post_join_local_account_calibrated = True

            @property
            def post_join_local_account_keys(self):
                raise RuntimeError("backend-private")

        with tempfile.TemporaryDirectory() as name:
            adapter = self.adapter(Path(name))
            adapter.rotation_plan = HostilePlan()
            adapter._qmp = mock.Mock(return_value=mock.sentinel.qmp)
            with self.assertRaises(
                subject.WindowsLocalReauthenticationError,
            ) as caught:
                adapter.reauthenticate_local("private")
        self.assertEqual(
            "select-local-account", caught.exception.reauth_operation)
        self.assertNotIn("private", str(caught.exception))
        self.assertIsNone(caught.exception.__cause__)
        self.assertIsNone(caught.exception.__context__)
        interaction_type.return_value.type_secret.assert_not_called()

    @mock.patch.object(subject, "_private_evidence_root")
    @mock.patch.object(subject, "_load_references")
    def test_reauthentication_setup_failure_drops_context(
        self, load_references, private_evidence_root,
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
        private_evidence_root.side_effect = RuntimeError("backend-private")
        with tempfile.TemporaryDirectory() as name:
            adapter = self.adapter(Path(name))
            adapter.rotation_plan = mock.Mock(
                post_join_local_account_calibrated=True)
            with self.assertRaises(
                subject.WindowsLocalReauthenticationError,
            ) as caught:
                adapter.reauthenticate_local("private")
        self.assertEqual(
            "prove-password-target", caught.exception.reauth_operation)
        self.assertIsNone(caught.exception.__cause__)
        self.assertIsNone(caught.exception.__context__)

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
