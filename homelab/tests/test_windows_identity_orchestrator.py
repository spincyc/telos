import tempfile
import unittest
from pathlib import Path
from unittest import mock

from homelab.vm import windows_identity_orchestrator as subject
from homelab.vm.controller_join_material import (
    ControllerJoinFailureCoordinate,
    ControllerJoinMaterialError,
    ControllerJoinResult,
)
from homelab.vm.controller_auth_diagnostic import (
    ControllerAuthCollection,
    ControllerAuthCleanup,
    ControllerAuthResult,
)
from homelab.vm.windows_identity_operations import ProductionIdentityReceipt
from homelab.vm.windows_identity_progressive import ProgressiveRotationReceipt
from homelab.vm.windows_postsubmit_diagnostic import (
    PostSubmitDiagnosticCleanup,
    PostSubmitDiagnosticCode,
    PostSubmitDiagnosticCollection,
)

from homelab.tests.test_windows_identity_acceptance import details


class WindowsIdentityOrchestratorTests(unittest.TestCase):
    def test_reboot_reauthentication_preserves_gui_failure_type(self):
        for error_type in (
            "WindowsIdentityGuiError",
            "WindowsLocalReauthenticationError",
        ):
            with self.subTest(error_type=error_type):
                coordinate = subject.WindowsJoinFailureCoordinate(
                    "reboot-reauth", error_type)
                diagnostic = subject.IdentityFailureDiagnostic.join_guest(
                    coordinate.phase, coordinate.error_type)

                self.assertEqual("windows-joined", diagnostic.check)
                self.assertEqual(
                    "join-guest.reboot-reauth", diagnostic.operation)
                self.assertEqual(error_type, diagnostic.error_type)

    def test_reboot_reauthentication_maps_only_allowlisted_subphases(self):
        forged_error_type = type(
            "WindowsLocalReauthenticationError",
            (RuntimeError,),
            {},
        )
        for operation in sorted(subject._LOCAL_REAUTH_OPERATIONS):
            with self.subTest(operation=operation):
                error = subject.WindowsLocalReauthenticationError(operation)
                coordinate = subject._local_reauthentication_coordinate(error)
                self.assertEqual(
                    f"reboot-reauth-{operation}", coordinate.phase)
                self.assertEqual(
                    "WindowsLocalReauthenticationError",
                    coordinate.error_type)

        persisted = subject.WindowsLocalReauthenticationError(
            "desktop-sign-in-persisted")
        coordinate = subject._local_reauthentication_coordinate(persisted)
        diagnostic = subject.IdentityFailureDiagnostic.join_guest(
            coordinate.phase, coordinate.error_type)
        self.assertEqual(
            "reboot-reauth-desktop-sign-in-persisted",
            coordinate.phase,
        )
        self.assertEqual("windows-joined", diagnostic.check)
        self.assertEqual(
            "join-guest.reboot-reauth-desktop-sign-in-persisted",
            diagnostic.operation,
        )

        result = ControllerAuthResult(
            collection=ControllerAuthCollection.SINK_INVALID,
            cleanup=ControllerAuthCleanup.SINK_ABSENCE_UNPROVED,
        )
        error = subject.WindowsLocalReauthenticationError(
            "controller-auth-arm", controller_auth_result=result)
        coordinate = subject._local_reauthentication_coordinate(error)
        diagnostic = subject.IdentityFailureDiagnostic.join_guest(
            coordinate.phase,
            coordinate.error_type,
            controller_auth=coordinate.controller_auth,
        )
        self.assertEqual(
            "reboot-reauth-controller-auth-arm", coordinate.phase)
        self.assertIs(result, coordinate.controller_auth)
        self.assertIn(
            "controller-auth-collection=sink-invalid", diagnostic.render())
        self.assertIn(
            "controller-auth-cleanup=sink-absence-unproved",
            diagnostic.render(),
        )

        cleanup = subject.WindowsLocalReauthenticationError(
            "diagnostic-cleanup",
            post_submit_diagnostic=(
                PostSubmitDiagnosticCode.INTERACTIVE_LOGON_SUCCESS),
            post_submit_cleanup=(
                PostSubmitDiagnosticCleanup.CLEANUP_RECEIPT_UNAVAILABLE),
            controller_auth_result=result,
        )
        coordinate = subject._local_reauthentication_coordinate(cleanup)
        diagnostic = subject.IdentityFailureDiagnostic.join_guest(
            coordinate.phase,
            coordinate.error_type,
            coordinate.post_submit_diagnostic,
            coordinate.post_submit_collection,
            coordinate.post_submit_cleanup,
            coordinate.controller_auth,
        )
        self.assertEqual(
            "join-guest.reboot-reauth-diagnostic-cleanup",
            diagnostic.operation,
        )
        self.assertIn(
            "post-submit-cleanup=cleanup-receipt-unavailable",
            diagnostic.render(),
        )
        self.assertIn(
            "controller-auth-cleanup=sink-absence-unproved",
            diagnostic.render(),
        )

        supplemental = subject.WindowsLocalReauthenticationError(
            "desktop-sign-in-persisted",
            post_submit_diagnostic=PostSubmitDiagnosticCode.BAD_CREDENTIAL,
            post_submit_collection=(
                PostSubmitDiagnosticCollection.RESULT_RECEIPT_UNAVAILABLE),
            post_submit_cleanup=(
                PostSubmitDiagnosticCleanup.CLEANUP_RECEIPT_UNAVAILABLE),
        )
        coordinate = subject._local_reauthentication_coordinate(supplemental)
        diagnostic = subject.IdentityFailureDiagnostic.join_guest(
            coordinate.phase,
            coordinate.error_type,
            coordinate.post_submit_diagnostic,
            coordinate.post_submit_collection,
            coordinate.post_submit_cleanup,
        )
        self.assertEqual(
            "reboot-reauth-desktop-sign-in-persisted",
            coordinate.phase,
        )
        self.assertEqual("bad-credential", coordinate.post_submit_diagnostic)
        self.assertEqual(
            "join-guest.reboot-reauth-desktop-sign-in-persisted",
            diagnostic.operation,
        )
        self.assertIn(
            "post-submit-diagnostic=bad-credential",
            diagnostic.render(),
        )
        self.assertIn(
            "post-submit-collection=result-receipt-unavailable",
            diagnostic.render(),
        )
        self.assertIn(
            "post-submit-cleanup=cleanup-receipt-unavailable",
            diagnostic.render(),
        )
        self.assertNotIn("private", diagnostic.render())

        forged = forged_error_type("private")
        forged.reauth_operation = "private-arbitrary-value"
        forged.post_submit_diagnostic = "private-raw-result"
        coordinate = subject._local_reauthentication_coordinate(forged)
        self.assertEqual("reboot-reauth", coordinate.phase)
        self.assertEqual("UnexpectedError", coordinate.error_type)
        self.assertIsNone(coordinate.post_submit_diagnostic)

        unrelated = RuntimeError("private")
        unrelated.reauth_operation = "wake"
        coordinate = subject._local_reauthentication_coordinate(unrelated)
        self.assertEqual("reboot-reauth", coordinate.phase)
        self.assertEqual("UnexpectedError", coordinate.error_type)

        forged = forged_error_type("private")
        forged.reauth_operation = "wake"
        coordinate = subject._local_reauthentication_coordinate(forged)
        self.assertEqual("reboot-reauth", coordinate.phase)
        self.assertEqual("UnexpectedError", coordinate.error_type)

        class Hostile(RuntimeError):
            @property
            def reauth_operation(self):
                raise AssertionError("hostile property was evaluated")

            @property
            def post_submit_diagnostic(self):
                raise AssertionError("hostile property was evaluated")

        coordinate = subject._local_reauthentication_coordinate(Hostile())
        self.assertEqual("reboot-reauth", coordinate.phase)
        self.assertEqual("UnexpectedError", coordinate.error_type)

        class StringSubclass(str):
            pass

        for phase, error_type, value in (
            ("reboot-reauth-wake",
             "WindowsLocalReauthenticationError", "bad-credential"),
            ("reboot-reauth-desktop", "UnexpectedError", "bad-credential"),
            ("reboot-reauth-desktop",
             "WindowsLocalReauthenticationError",
             StringSubclass("bad-credential")),
        ):
            with self.subTest(
                    phase=phase, error_type=error_type, value=value):
                with self.assertRaises(ValueError):
                    subject.WindowsJoinFailureCoordinate(
                        phase, error_type, value)

        with self.assertRaises(ValueError):
            subject.IdentityFailureDiagnostic(
                "windows-joined",
                "join-guest.reboot-reauth-wake",
                "WindowsLocalReauthenticationError",
                "bad-credential",
            )
        with self.assertRaises(ValueError):
            subject.WindowsJoinFailureCoordinate(
                "reboot-reauth-wake",
                "WindowsLocalReauthenticationError",
                None,
                "result-receipt-unavailable",
            )

    def test_join_stage_failure_is_rebound_to_secret_free_acceptance_coordinate(
        self,
    ):
        private = "private-stage-message"
        coordinate = ControllerJoinFailureCoordinate(
            "stage", "shell-prompt", "TimeoutError")

        with tempfile.TemporaryDirectory() as name, self.assertRaises(
            subject.WindowsIdentityOrchestratorError,
        ) as caught:
            subject._execute_join(
                realm="FACTORY.TEST",
                private_root=Path(name),
                operator_credential="private-operator",
                callbacks=self.callbacks([]),
                stage_join_principal=mock.Mock(side_effect=(
                    ControllerJoinMaterialError(
                        private, coordinate=coordinate))),
                destroy_join_principal=mock.Mock(return_value=(
                    ControllerJoinResult(
                        "destroy", "tj-0123456789abcdef", True, ()))),
            )

        error = caught.exception
        self.assertEqual("windows-joined", error.diagnostic.check)
        self.assertEqual(
            "join-material.stage.shell-prompt",
            error.diagnostic.operation,
        )
        self.assertEqual("TimeoutError", error.diagnostic.error_type)
        self.assertNotIn(private, str(error))
        self.assertIsNone(error.__cause__)
        self.assertIsNone(error.__context__)

    def test_join_failure_reports_separate_allowlisted_cleanup_coordinate(self):
        primary = ControllerJoinFailureCoordinate(
            "stage", "secret-input-send", "OSError")
        cleanup = ControllerJoinFailureCoordinate(
            "destroy", "return-code", "ControllerJoinReturnCode")
        failure = ControllerJoinMaterialError(
            "private combined failure",
            coordinate=primary,
            cleanup_coordinate=cleanup,
        )
        with mock.patch.object(
            subject.OneUseDomainJoinMaterial, "use", side_effect=failure,
        ), tempfile.TemporaryDirectory() as name, self.assertRaises(
            subject.WindowsIdentityOrchestratorError,
        ) as caught:
            subject._execute_join(
                realm="FACTORY.TEST",
                private_root=Path(name),
                operator_credential="private-operator",
                callbacks=self.callbacks([]),
                stage_join_principal=mock.Mock(),
                destroy_join_principal=mock.Mock(),
            )

        rendered = str(caught.exception)
        self.assertIn(
            "check=windows-joined; "
            "operation=join-material.stage.secret-input-send; error=OSError",
            rendered,
        )
        self.assertIn(
            "cleanup-check=windows-joined; "
            "operation=join-material.destroy.return-code; "
            "error=ControllerJoinReturnCode",
            rendered,
        )
        self.assertNotIn("private combined failure", rendered)

    def test_guest_failure_remains_primary_when_controller_destroy_also_fails(
        self,
    ):
        primary = subject.IdentityFailureDiagnostic.join_guest(
            "marker-receive", "TimeoutError")
        cleanup = ControllerJoinFailureCoordinate(
            "destroy", "return-code", "ControllerJoinReturnCode")
        failure = ControllerJoinMaterialError(
            "private guest and cleanup failure",
            cleanup_coordinate=cleanup,
            diagnostic=primary,
        )
        with mock.patch.object(
            subject.OneUseDomainJoinMaterial, "use", side_effect=failure,
        ), tempfile.TemporaryDirectory() as name, self.assertRaises(
            subject.WindowsIdentityOrchestratorError,
        ) as caught:
            subject._execute_join(
                realm="FACTORY.TEST",
                private_root=Path(name),
                operator_credential="private-operator",
                callbacks=self.callbacks([]),
                stage_join_principal=mock.Mock(),
                destroy_join_principal=mock.Mock(),
            )
        error = caught.exception
        self.assertIs(error.diagnostic, primary)
        self.assertIn(primary.render(), str(error))
        self.assertIn(
            "cleanup-check=windows-joined; "
            "operation=join-material.destroy.return-code; "
            "error=ControllerJoinReturnCode",
            str(error),
        )
        self.assertNotIn("private guest and cleanup failure", str(error))
        self.assertIsNone(error.__cause__)

    def callbacks(self, observed):
        def credential_action(check, principal, credential):
            actions = {
                "windows-standard-online": "connected-domain-login",
                "windows-daily-admin":
                    "operator-local-administrators-check",
                "windows-cached-login": "cached-domain-login",
                "windows-cached-admin-login": "cached-domain-login",
                "windows-uncached-denied": "uncached-domain-user-denied",
                "windows-local-rescue": "local-rescue-login",
                "gateway-offline": "connected-domain-login",
                "update-source-offline": "connected-domain-login",
                "optional-storage-offline": "connected-domain-login",
                "optional-storage-access-denied":
                    "connected-domain-login",
                "ad-dns-offline": "cached-domain-login",
                "combined-dependencies-offline": (
                    "local-rescue-login" if principal == "telosadmin"
                    else "cached-domain-login"),
            }
            return {
                "schema_version": 1,
                "action": actions[check],
                "check": check,
                "principal": principal,
                "credential_owned": bool(credential),
            }

        return subject.AcceptanceCallbacks(
            qmp=mock.Mock(),
            launch_guest=mock.Mock(),
            await_device_deleted=mock.Mock(),
            open_join_serial=mock.Mock(),
            reauthenticate_local=mock.Mock(),
            reauthenticate_domain_operator=mock.Mock(),
            static_probe=lambda action: {
                "schema_version": 1,
                "action": action,
                "result": "pass",
                "observed_at": "2026-07-28T15:00:00Z",
                "observation": {},
            },
            credential_action=credential_action,
            scan_secrets=lambda _secrets: details()[
                "windows-diagnostics-sanitized"],
            local_principal="telosadmin",
        )

    def test_composes_exact_order_and_publishes_only_after_restoration(self):
        observed = []
        callbacks = self.callbacks(observed)
        boundary = mock.Mock()
        production = ProductionIdentityReceipt(
            rotation=ProgressiveRotationReceipt(
                phases=("post-rotation-acceptance-complete",),
                publication_destroyed=True,
                replacement_sign_in_proved=True,
            ),
            acceptance_complete=True,
            credentials_released=True,
        )

        def execute_production(**kwargs):
            kwargs["run_acceptance"]("Local-Secret-47!", {
                "student": "Student-Secret-47!",
                "operator": "Operator-Secret-47!",
                "directory-admin": "Directory-Secret-47!",
            })
            return production

        join_result = ControllerJoinResult(
            operation="destroy",
            principal="tj-0123456789abcdef",
            destruction_proved=True,
            events=(),
        )
        def map_observation(check, context):
            observed.append((check, context))
            return details()[check]

        with tempfile.TemporaryDirectory() as name, mock.patch.object(
            subject, "execute_production_identity_acceptance",
            side_effect=execute_production,
        ), mock.patch.object(
            subject, "_execute_join",
            return_value=({
                "schema_version": 1,
                "join_media_destroyed": True,
                "joined_after_reboot": True,
                "domain": "FACTORY.TEST",
            }, True),
        ), mock.patch.object(
            subject, "map_exact_observation",
            side_effect=map_observation,
        ):
            root = Path(name)
            root.chmod(0o700)
            receipt = subject.execute_windows_identity_acceptance(
                boundary=boundary,
                rotation_plan=mock.Mock(),
                publication=root / "recovery.iso",
                private_root=root,
                evidence=root / "evidence.jsonl",
                realm="FACTORY.TEST",
                callbacks=callbacks,
                stage_principals=mock.Mock(),
                destroy_principals=mock.Mock(),
                stage_join_principal=mock.Mock(return_value=join_result),
                destroy_join_principal=mock.Mock(return_value=join_result),
            )
            self.assertTrue(receipt.evidence.read_text().endswith("\n"))

        self.assertEqual(
            list(details()), [check for check, _ in observed])
        self.assertEqual(24, receipt.checks)
        self.assertTrue(receipt.dependencies_restored)
        self.assertEqual([
            mock.call(False), mock.call(True),
            mock.call(False), mock.call(True),
        ], boundary.set_controller_available.call_args_list)

    def test_observation_failure_leaves_destination_absent(self):
        callbacks = self.callbacks([])
        def execute_production(**kwargs):
            kwargs["run_acceptance"]("Local-Secret-47!", {
                "student": "Student-Secret-47!",
                "operator": "Operator-Secret-47!",
                "directory-admin": "Directory-Secret-47!",
            })

        with tempfile.TemporaryDirectory() as name, mock.patch.object(
            subject, "execute_production_identity_acceptance",
            side_effect=execute_production,
        ), mock.patch.object(
            subject, "_execute_join", return_value=({}, True),
        ), mock.patch.object(
            subject, "map_exact_observation",
            side_effect=lambda check, _context: (
                {} if check == "windows-daily-admin"
                else details()[check]),
        ):
            root = Path(name)
            root.chmod(0o700)
            destination = root / "evidence.jsonl"
            with self.assertRaises(Exception):
                subject.execute_windows_identity_acceptance(
                    boundary=mock.Mock(),
                    rotation_plan=mock.Mock(),
                    publication=root / "recovery.iso",
                    private_root=root,
                    evidence=destination,
                    realm="FACTORY.TEST",
                    callbacks=callbacks,
                    stage_principals=mock.Mock(),
                    destroy_principals=mock.Mock(),
                    stage_join_principal=mock.Mock(),
                    destroy_join_principal=mock.Mock(),
                )
            self.assertFalse(destination.exists())

    def test_outer_private_cleanup_failure_leaves_destination_absent(self):
        callbacks = self.callbacks([])

        def execute_production(**kwargs):
            kwargs["run_acceptance"]("Local-Secret-47!", {
                "student": "Student-Secret-47!",
                "operator": "Operator-Secret-47!",
                "directory-admin": "Directory-Secret-47!",
            })
            raise RuntimeError("principal cleanup failed")

        with tempfile.TemporaryDirectory() as name, mock.patch.object(
            subject, "execute_production_identity_acceptance",
            side_effect=execute_production,
        ), mock.patch.object(
            subject, "_execute_join", return_value=({}, True),
        ), mock.patch.object(
            subject, "map_exact_observation",
            side_effect=lambda check, _context: details()[check],
        ):
            root = Path(name)
            root.chmod(0o700)
            destination = root / "evidence.jsonl"
            with self.assertRaisesRegex(RuntimeError, "cleanup"):
                subject.execute_windows_identity_acceptance(
                    boundary=mock.Mock(),
                    rotation_plan=mock.Mock(),
                    publication=root / "recovery.iso",
                    private_root=root,
                    evidence=destination,
                    realm="FACTORY.TEST",
                    callbacks=callbacks,
                    stage_principals=mock.Mock(),
                    destroy_principals=mock.Mock(),
                    stage_join_principal=mock.Mock(),
                    destroy_join_principal=mock.Mock(),
                )
            self.assertFalse(destination.exists())

    def test_unproved_semantic_observation_is_rejected(self):
        callbacks = self.callbacks([])
        collector = mock.Mock()
        with self.assertRaisesRegex(
                subject.WindowsIdentityOrchestratorError,
                "exact observation"):
            subject._record(
                collector,
                callbacks,
                "windows-joined",
                local_credential="Local-Secret-47!",
                principals={
                    "student": "Student-Secret-47!",
                    "operator": "Operator-Secret-47!",
                    "directory-admin": "Directory-Secret-47!",
                },
                join_proof={"schema_version": 1},
            )
        collector.record.assert_not_called()

    def test_join_callbacks_are_explicit_and_controller_destruction_is_required(
        self,
    ):
        callbacks = self.callbacks([])
        qmp = mock.Mock()
        callbacks = subject.AcceptanceCallbacks(
            **{
                **callbacks.__dict__,
                "qmp": lambda: qmp,
                "static_probe": lambda action: {
                    "schema_version": 1,
                    "action": action,
                    "result": "pass",
                    "observed_at": "2026-07-28T15:00:00Z",
                    "observation": ({
                        "principal": r"FACTORY\operator",
                        "principal_sid": "S-1-5-21-1-2-3-1104",
                        "operator": "operator@FACTORY.TEST",
                        "operator_sid": "S-1-5-21-1-2-3-1104",
                        "console_principal": r"FACTORY\operator",
                        "console_sid": "S-1-5-21-1-2-3-1104",
                        "authenticated": True,
                        "authentication_type": "Kerberos",
                        "session_id": 1,
                        "profile_sid": "S-1-5-21-1-2-3-1104",
                        "profile_loaded": True,
                        "local_profile": True,
                    } if action == "interactive-operator" else {
                        "part_of_domain": True,
                        "domain": "FACTORY.TEST",
                        "secure_channel": True,
                        "operator": "operator@FACTORY.TEST",
                        "operator_local_administrator": True,
                    }),
                },
            }
        )
        staged = ControllerJoinResult(
            "stage", "tj-0123456789abcdef", False, ())
        destroyed = ControllerJoinResult(
            "destroy", "tj-0123456789abcdef", True, ())

        def fake_build(path, material):
            path.write_bytes(b"private")
            path.chmod(0o600)
            self.assertEqual(
                "tj-0123456789abcdef@FACTORY.TEST",
                material["username"],
            )
            self.assertEqual("FACTORY.TEST", material["realm"])
            self.assertEqual("operator@FACTORY.TEST", material["operator"])

        with tempfile.TemporaryDirectory() as name, mock.patch.object(
            subject, "build_join_iso", side_effect=fake_build,
        ), mock.patch.object(
            subject, "JoinMediaChannel", return_value=mock.Mock(),
        ), mock.patch.object(
            subject, "execute_join_and_prove",
            return_value={"schema_version": 1},
        ) as execute:
            root = Path(name)
            root.chmod(0o700)
            proof, destroyed_flag = subject._execute_join(
                realm="FACTORY.TEST",
                private_root=root,
                operator_credential="Operator-Secret-47!",
                callbacks=callbacks,
                stage_join_principal=mock.Mock(return_value=staged),
                destroy_join_principal=mock.Mock(return_value=destroyed),
            )

        self.assertEqual({"schema_version": 1}, proof)
        self.assertTrue(destroyed_flag)
        self.assertIs(callbacks.launch_guest, execute.call_args.kwargs[
            "launch_guest"])
        self.assertIs(callbacks.await_device_deleted, execute.call_args.kwargs[
            "await_device_deleted"])
        self.assertEqual({
            "schema_version": 2,
            "boot_completed": True,
            "domain_joined": True,
            "domain": "FACTORY.TEST",
            "operator": "operator@FACTORY.TEST",
            "operator_local_administrator": True,
        }, execute.call_args.kwargs["probe_after_reboot"]())
        callbacks.reauthenticate_domain_operator.assert_called_once()
        reauth_args = (
            callbacks.reauthenticate_domain_operator.call_args.args)
        self.assertEqual(
            ("operator@FACTORY.TEST", "Operator-Secret-47!"),
            reauth_args[:2],
        )
        self.assertRegex(reauth_args[2], r"^[a-f0-9]{32}$")
        callbacks.reauthenticate_local.assert_not_called()
        with self.assertRaisesRegex(
                subject.WindowsIdentityOrchestratorError,
                "already attempted"):
            execute.call_args.kwargs["probe_after_reboot"]()

        integer_boolean = {
            **callbacks.__dict__,
            "static_probe": lambda action: {
                "schema_version": 1,
                "action": action,
                "result": "pass",
                "observation": {
                    "part_of_domain": 1,
                    "domain": "FACTORY.TEST",
                    "secure_channel": True,
                    "operator": "operator@FACTORY.TEST",
                    "operator_local_administrator": True,
                },
            },
        }
        callbacks = subject.AcceptanceCallbacks(**integer_boolean)
        with self.assertRaisesRegex(
                subject.WindowsIdentityOrchestratorError, "probe is invalid"):
            subject._post_reboot_proof(
                callbacks, "operator@FACTORY.TEST")

    def test_post_reboot_probe_rebinds_receive_and_parse_failures(self):
        secret = "post-reboot-private-message"
        for phase in ("outcome-receive", "guest", "outcome-parse"):
            with self.subTest(phase=phase):
                failure = subject.WindowsIdentityRunError(secret)
                failure.diagnostic = (
                    subject.IdentityFailureDiagnostic.adapter_static_probe(
                        "interactive-operator", phase, failure))
                callbacks = self.callbacks([])
                callbacks = subject.AcceptanceCallbacks(**{
                    **callbacks.__dict__,
                    "static_probe": lambda _action, failure=failure: (
                        _ for _ in ()).throw(failure),
                })
                with self.assertRaises(
                    subject.WindowsIdentityOrchestratorError,
                ) as caught:
                    subject._post_reboot_proof(
                        callbacks, "operator@FACTORY.TEST")
                error = caught.exception
                self.assertEqual(
                    "windows-rebooted-joined", error.diagnostic.check)
                self.assertEqual(
                    "static-probe.interactive-operator." + phase,
                    error.diagnostic.operation,
                )
                self.assertEqual("UnexpectedError",
                                 error.diagnostic.error_type)
                self.assertNotIn(secret, str(error))
                self.assertIsNone(error.__cause__)
                self.assertIsNone(error.__context__)

    def test_post_reboot_semantic_validation_has_static_probe_coordinate(self):
        interactive = {
            "schema_version": 1,
            "action": "interactive-operator",
            "result": "pass",
            "observation": {
                "principal": r"FACTORY\operator",
                "principal_sid": "S-1-5-21-1-2-3-1104",
                "operator": "operator@FACTORY.TEST",
                "operator_sid": "S-1-5-21-1-2-3-1104",
                "console_principal": r"FACTORY\operator",
                "console_sid": "S-1-5-21-1-2-3-1104",
                "authenticated": True,
                "authentication_type": "Kerberos",
                "session_id": 1,
                "profile_sid": "S-1-5-21-1-2-3-1104",
                "profile_loaded": True,
                "local_profile": True,
            },
        }
        domain = {
            "schema_version": 1,
            "action": "domain-state",
            "result": "pass",
            "observation": {
                "part_of_domain": True,
                "domain": "FACTORY.TEST",
                "secure_channel": True,
                "operator": "operator@FACTORY.TEST",
                "operator_local_administrator": True,
            },
        }
        invalid_by_action = {
            "interactive-operator": {
                **interactive,
                "observation": {
                    **interactive["observation"],
                    "authenticated": False,
                },
            },
            "domain-state": {
                **domain,
                "observation": {
                    **domain["observation"],
                    "part_of_domain": 1,
                },
            },
        }
        for action, invalid in invalid_by_action.items():
            with self.subTest(action=action):
                callbacks = self.callbacks([])

                def static_probe(requested, action=action, invalid=invalid):
                    if requested == action:
                        return invalid
                    return (
                        interactive
                        if requested == "interactive-operator"
                        else domain
                    )

                callbacks = subject.AcceptanceCallbacks(**{
                    **callbacks.__dict__,
                    "static_probe": static_probe,
                })
                with self.assertRaises(
                    subject.WindowsIdentityOrchestratorError,
                ) as caught:
                    subject._post_reboot_proof(
                        callbacks, "operator@FACTORY.TEST")
                error = caught.exception
                self.assertEqual(
                    "windows-rebooted-joined", error.diagnostic.check)
                self.assertEqual(
                    f"static-probe.{action}.validate",
                    error.diagnostic.operation,
                )
                self.assertEqual(
                    "WindowsIdentityOrchestratorError",
                    error.diagnostic.error_type,
                )
                self.assertNotIn("authenticated", str(error))

    def test_execute_join_preserves_post_reboot_validation_coordinate(self):
        staged = ControllerJoinResult(
            "stage", "tj-0123456789abcdef", False, ())
        destroyed = ControllerJoinResult(
            "destroy", "tj-0123456789abcdef", True, ())
        interactive = {
            "schema_version": 1,
            "action": "interactive-operator",
            "result": "pass",
            "observation": {
                "principal": r"FACTORY\operator",
                "principal_sid": "S-1-5-21-1-2-3-1104",
                "operator": "operator@FACTORY.TEST",
                "operator_sid": "S-1-5-21-1-2-3-1104",
                "console_principal": r"FACTORY\operator",
                "console_sid": "S-1-5-21-1-2-3-1104",
                "authenticated": True,
                "authentication_type": "Kerberos",
                "session_id": 1,
                "profile_sid": "S-1-5-21-1-2-3-1104",
                "profile_loaded": True,
                "local_profile": True,
            },
        }

        def execute(**kwargs):
            return kwargs["probe_after_reboot"]()

        def fake_build(path, _material):
            path.write_bytes(b"private")
            path.chmod(0o600)

        for action in ("interactive-operator", "domain-state"):
            with self.subTest(action=action):
                callbacks = self.callbacks([])

                def static_probe(requested, action=action):
                    if requested == action:
                        return {
                            "schema_version": 1,
                            "action": requested,
                            "result": "pass",
                            "observation": {},
                        }
                    return interactive

                callbacks = subject.AcceptanceCallbacks(**{
                    **callbacks.__dict__,
                    "static_probe": static_probe,
                })
                channel = mock.Mock()
                with tempfile.TemporaryDirectory() as name, mock.patch.object(
                    subject, "build_join_iso", side_effect=fake_build,
                ), mock.patch.object(
                    subject, "JoinMediaChannel", return_value=channel,
                ), mock.patch.object(
                    subject, "execute_join_and_prove", side_effect=execute,
                ):
                    root = Path(name)
                    root.chmod(0o700)
                    with self.assertRaises(
                        subject.WindowsIdentityOrchestratorError,
                    ) as caught:
                        subject._execute_join(
                            realm="FACTORY.TEST",
                            private_root=root,
                            operator_credential="Operator-Secret-47!",
                            callbacks=callbacks,
                            stage_join_principal=mock.Mock(
                                return_value=staged),
                            destroy_join_principal=mock.Mock(
                                return_value=destroyed),
                        )
                error = caught.exception
                self.assertEqual(
                    "windows-rebooted-joined", error.diagnostic.check)
                self.assertEqual(
                    f"static-probe.{action}.validate",
                    error.diagnostic.operation,
                )
                self.assertEqual(
                    "WindowsIdentityOrchestratorError",
                    error.diagnostic.error_type,
                )
                self.assertNotIn("private", str(error))
                self.assertIsNone(error.__cause__)

    def test_post_reboot_preserves_preflight_lease_and_connect_coordinates(self):
        interactive = {
            "schema_version": 1,
            "action": "interactive-operator",
            "result": "pass",
            "observation": {
                "principal": r"FACTORY\operator",
                "principal_sid": "S-1-5-21-1-2-3-1104",
                "operator": "operator@FACTORY.TEST",
                "operator_sid": "S-1-5-21-1-2-3-1104",
                "console_principal": r"FACTORY\operator",
                "console_sid": "S-1-5-21-1-2-3-1104",
                "authenticated": True,
                "authentication_type": "Kerberos",
                "session_id": 1,
                "profile_sid": "S-1-5-21-1-2-3-1104",
                "profile_loaded": True,
                "local_profile": True,
            },
        }
        for action in ("interactive-operator", "domain-state"):
            for phase in ("preflight", "lease", "connect"):
                with self.subTest(action=action, phase=phase):
                    private = RuntimeError("private-static-probe-detail")
                    diagnostic = (
                        subject.IdentityFailureDiagnostic.adapter_static_probe(
                            action, phase, private))
                    failure = subject.WindowsIdentityRunError(
                        "private-wrapper", diagnostic=diagnostic)

                    def static_probe(requested):
                        if requested == action:
                            raise failure
                        return interactive

                    callbacks = self.callbacks([])
                    callbacks = subject.AcceptanceCallbacks(**{
                        **callbacks.__dict__,
                        "static_probe": static_probe,
                    })
                    with self.assertRaises(
                        subject.WindowsIdentityOrchestratorError,
                    ) as caught:
                        subject._post_reboot_proof(
                            callbacks, "operator@FACTORY.TEST")
                    error = caught.exception
                    self.assertEqual(
                        "windows-rebooted-joined",
                        error.diagnostic.check,
                    )
                    self.assertEqual(
                        f"static-probe.{action}.{phase}",
                        error.diagnostic.operation,
                    )
                    self.assertEqual(
                        "UnexpectedError", error.diagnostic.error_type)
                    self.assertNotIn("private", str(error))
                    self.assertIsNone(error.__cause__)
                    self.assertIsNone(error.__context__)

    def test_execute_join_preserves_post_reboot_static_probe_diagnostic(self):
        staged = ControllerJoinResult(
            "stage", "tj-0123456789abcdef", False, ())
        destroyed = ControllerJoinResult(
            "destroy", "tj-0123456789abcdef", True, ())
        diagnostic = subject.IdentityFailureDiagnostic.adapter_static_probe(
            "interactive-operator",
            "connect",
            OSError("private-connect-detail"),
        )
        static_failure = subject.WindowsIdentityOrchestratorError(
            "private-static-probe-detail",
            diagnostic=diagnostic,
        )
        callbacks = self.callbacks([])
        callbacks = subject.AcceptanceCallbacks(**{
            **callbacks.__dict__,
            "static_probe": lambda _action: (
                _ for _ in ()).throw(static_failure),
        })
        channel = mock.Mock()

        def execute(**kwargs):
            return kwargs["probe_after_reboot"]()

        def fake_build(path, _material):
            path.write_bytes(b"private")
            path.chmod(0o600)

        with tempfile.TemporaryDirectory() as name, mock.patch.object(
            subject, "build_join_iso", side_effect=fake_build,
        ), mock.patch.object(
            subject, "JoinMediaChannel", return_value=channel,
        ), mock.patch.object(
            subject, "execute_join_and_prove", side_effect=execute,
        ):
            root = Path(name)
            root.chmod(0o700)
            with self.assertRaises(
                subject.WindowsIdentityOrchestratorError,
            ) as caught:
                subject._execute_join(
                    realm="FACTORY.TEST",
                    private_root=root,
                    operator_credential="Operator-Secret-47!",
                    callbacks=callbacks,
                    stage_join_principal=mock.Mock(return_value=staged),
                    destroy_join_principal=mock.Mock(return_value=destroyed),
                )
        error = caught.exception
        self.assertEqual(
            "windows-rebooted-joined", error.diagnostic.check)
        self.assertEqual(
            "static-probe.interactive-operator.connect",
            error.diagnostic.operation,
        )
        self.assertEqual("OSError", error.diagnostic.error_type)
        self.assertNotIn("private", str(error))
        self.assertIsNone(error.__cause__)

    def test_post_reboot_probe_rejects_unbound_interactive_operator(self):
        identity = {
            "principal": r"FACTORY\operator",
            "principal_sid": "S-1-5-21-1-2-3-1104",
            "operator": "operator@FACTORY.TEST",
            "operator_sid": "S-1-5-21-1-2-3-1104",
            "console_principal": r"FACTORY\operator",
            "console_sid": "S-1-5-21-1-2-3-1104",
            "authenticated": True,
            "authentication_type": "Kerberos",
            "session_id": 1,
            "profile_sid": "S-1-5-21-1-2-3-1104",
            "profile_loaded": True,
            "local_profile": True,
        }
        mutations = {
            "wrong operator": {"operator": "operator@OTHER.TEST"},
            "wrong principal": {"principal": r"FACTORY\student"},
            "wrong console name": {
                "console_principal": r"FACTORY\student"},
            "wrong token": {"principal_sid": "S-1-5-21-1-2-3-1105"},
            "wrong console": {"console_sid": "S-1-5-21-1-2-3-1105"},
            "wrong profile": {"profile_sid": "S-1-5-21-1-2-3-1105"},
            "unauthenticated": {"authenticated": False},
            "session zero": {"session_id": 0},
            "profile unloaded": {"profile_loaded": False},
            "nonlocal profile": {"local_profile": False},
            "empty authentication type": {"authentication_type": ""},
        }
        for label, changes in mutations.items():
            with self.subTest(label=label):
                candidate = {**identity, **changes}
                observed = []

                def static_probe(action):
                    observed.append(action)
                    return {
                        "schema_version": 1,
                        "action": action,
                        "result": "pass",
                        "observation": candidate,
                    }

                callbacks = self.callbacks([])
                callbacks = subject.AcceptanceCallbacks(**{
                    **callbacks.__dict__,
                    "static_probe": static_probe,
                })
                with self.assertRaisesRegex(
                        subject.WindowsIdentityOrchestratorError,
                        "interactive operator"):
                    subject._post_reboot_proof(
                        callbacks, "operator@FACTORY.TEST")
                self.assertEqual(["interactive-operator"], observed)

    def test_static_probe_rebind_preserves_only_normalized_error_type(self):
        for supplied, expected in (
            ("TimeoutError", "TimeoutError"),
            ("SecretFailure-private-message", "UnexpectedError"),
        ):
            with self.subTest(supplied=supplied):
                failure = subject.WindowsIdentityRunError(
                    "private-wrapper-message")
                failure.diagnostic = (
                    subject.IdentityFailureDiagnostic.static_probe(
                        "controller-ready",
                        "controller-readiness",
                        failure,
                        phase="outcome-receive",
                        normalized_error_type=supplied,
                    ))
                callbacks = self.callbacks([])
                callbacks = subject.AcceptanceCallbacks(**{
                    **callbacks.__dict__,
                    "static_probe": lambda _action, failure=failure: (
                        _ for _ in ()).throw(failure),
                })
                with self.assertRaises(
                    subject.WindowsIdentityOrchestratorError,
                ) as caught:
                    subject._validated_static_probes(
                        callbacks, "controller-ready")
                diagnostic = caught.exception.diagnostic
                self.assertEqual(expected, diagnostic.error_type)
                self.assertEqual("controller-ready", diagnostic.check)
                self.assertEqual(
                    "static-probe.controller-readiness.outcome-receive",
                    diagnostic.operation,
                )
                self.assertNotIn("private", str(caught.exception))
                self.assertNotIn("SecretFailure", str(caught.exception))
                self.assertIsNone(caught.exception.__cause__)
                self.assertIsNone(caught.exception.__context__)

        forged = subject.WindowsIdentityRunError("private-forged-message")
        forged.probe_action = "controller-readiness"
        forged.probe_phase = "outcome-receive"
        forged.probe_error_type = "TimeoutError"
        callbacks = self.callbacks([])
        callbacks = subject.AcceptanceCallbacks(**{
            **callbacks.__dict__,
            "static_probe": lambda _action: (_ for _ in ()).throw(forged),
        })
        with self.assertRaises(
            subject.WindowsIdentityOrchestratorError,
        ) as caught:
            subject._validated_static_probes(callbacks, "controller-ready")
        self.assertEqual(
            "static-probe.controller-readiness",
            caught.exception.diagnostic.operation,
        )
        self.assertEqual(
            "UnexpectedError", caught.exception.diagnostic.error_type)
        self.assertNotIn("private", str(caught.exception))

    def test_join_serial_connects_before_private_media_is_created(self):
        callbacks = self.callbacks([])
        order = []
        serial = mock.Mock()
        callbacks = subject.AcceptanceCallbacks(**{
            **callbacks.__dict__,
            "open_join_serial": lambda: (order.append("serial") or serial),
        })
        staged = ControllerJoinResult(
            "stage", "tj-0123456789abcdef", False, ())
        destroyed = ControllerJoinResult(
            "destroy", "tj-0123456789abcdef", True, ())

        def fail_build(path, _material):
            order.append("build")
            path.write_bytes(b"partial-private-media")
            raise RuntimeError("build failed")

        with tempfile.TemporaryDirectory() as name, mock.patch.object(
            subject, "build_join_iso", side_effect=fail_build,
        ):
            root = Path(name)
            root.chmod(0o700)
            with self.assertRaises(
                    subject.WindowsIdentityOrchestratorError) as caught:
                subject._execute_join(
                    realm="FACTORY.TEST",
                    private_root=root,
                    operator_credential="Operator-Secret-47!",
                    callbacks=callbacks,
                    stage_join_principal=mock.Mock(return_value=staged),
                    destroy_join_principal=mock.Mock(return_value=destroyed),
                )
            self.assertEqual(["serial", "build"], order)
            self.assertEqual([], list(root.iterdir()))
            self.assertEqual(
                "join-guest.prepare",
                caught.exception.diagnostic.operation,
            )
            self.assertEqual(
                "UnexpectedError",
                caught.exception.diagnostic.error_type,
            )
            self.assertNotIn("build failed", str(caught.exception))
            self.assertIsNone(caught.exception.__cause__)
            serial.close.assert_called_once_with()

    def test_guest_join_coordinates_are_preserved_by_one_use_owner(self):
        for phase in (
            "prepare", "attach", "launch", "marker-receive",
            "marker-guest-diagnostic-source", "media-destroy", "release",
            "result", "reboot-reauth",
            "reboot-probe", "cleanup",
        ):
            with self.subTest(phase=phase):
                guest = subject.WindowsIdentityOrchestratorError(
                    "secret-free guest failure",
                    diagnostic=subject.IdentityFailureDiagnostic.join_guest(
                        phase, "WindowsJoinIsoError"),
                )
                wrapped = subject.ControllerJoinMaterialError(
                    "domain join material lifecycle failed")
                # The production material owner does not own guest diagnostic
                # typing; PrivateIdentityMaterial must preserve the validated
                # diagnostic carrier supplied by the orchestrator.
                self.assertEqual(
                    f"join-guest.{phase}", guest.diagnostic.operation)
                self.assertIsNone(wrapped.coordinate)


if __name__ == "__main__":
    unittest.main()
