import tempfile
import unittest
from pathlib import Path
from unittest import mock

from homelab.vm import windows_identity_orchestrator as subject
from homelab.vm.controller_join_material import ControllerJoinResult
from homelab.vm.windows_identity_operations import ProductionIdentityReceipt
from homelab.vm.windows_identity_progressive import ProgressiveRotationReceipt

from homelab.tests.test_windows_identity_acceptance import details


class WindowsIdentityOrchestratorTests(unittest.TestCase):
    def callbacks(self, observed):
        def observe(check, context):
            sources = {f"guest:{check}"}
            if context.static_probe is not None:
                sources.add(f"static:{context.static_probe['action']}")
            if context.credential_action is not None:
                sources.add(f"credential:{check}")
            if context.join_proof is not None:
                sources.add("join:post-reboot")
            observed.append((check, context))
            return subject.ExactObservation(
                check, frozenset(sources), details()[check])

        return subject.AcceptanceCallbacks(
            qmp=mock.Mock(),
            launch_guest=mock.Mock(),
            await_device_deleted=mock.Mock(),
            open_join_serial=mock.Mock(),
            static_probe=lambda action: {
                "schema_version": 1,
                "action": action,
                "result": "pass",
                "observed_at": "2026-07-28T15:00:00Z",
                "observation": {},
            },
            credential_action=lambda check, principal, credential: {
                "schema_version": 1,
                "check": check,
                "principal": principal,
                "credential_owned": bool(credential),
            },
            observe=observe,
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
            list(details())[:-2], [check for check, _ in observed])
        self.assertEqual(24, receipt.checks)
        self.assertTrue(receipt.dependencies_restored)
        self.assertEqual([
            mock.call(False), mock.call(True),
            mock.call(False), mock.call(True),
        ], boundary.set_controller_available.call_args_list)

    def test_observation_failure_leaves_destination_absent(self):
        callbacks = self.callbacks([])
        callbacks = subject.AcceptanceCallbacks(
            **{
                **callbacks.__dict__,
                "observe": lambda check, _context: subject.ExactObservation(
                    check,
                    frozenset({f"guest:{check}"}),
                    {} if check == "windows-daily-admin"
                    else details()[check],
                ),
            }
        )

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

    def test_unbound_semantic_observation_is_rejected(self):
        callbacks = self.callbacks([])
        callbacks = subject.AcceptanceCallbacks(
            **{
                **callbacks.__dict__,
                "observe": lambda check, _context: subject.ExactObservation(
                    check, frozenset({f"guest:{check}"}), details()[check]),
            }
        )
        collector = mock.Mock()
        with self.assertRaisesRegex(
                subject.WindowsIdentityOrchestratorError, "source binding"):
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
            **{**callbacks.__dict__, "qmp": lambda: qmp}
        )
        staged = ControllerJoinResult(
            "stage", "tj-0123456789abcdef", False, ())
        destroyed = ControllerJoinResult(
            "destroy", "tj-0123456789abcdef", True, ())

        def fake_build(path, material):
            path.write_bytes(b"private")
            path.chmod(0o600)
            self.assertEqual("tj-0123456789abcdef", material["username"])
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


if __name__ == "__main__":
    unittest.main()
