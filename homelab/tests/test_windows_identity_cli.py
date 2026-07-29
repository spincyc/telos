import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from homelab.vm import windows_identity_cli
from homelab.vm.windows_identity_run import IdentityFailureDiagnostic
from homelab.tests.windows_identity_fixture import (
    write_prepared_authorization,
)


class WindowsIdentityCliTests(unittest.TestCase):
    def private_attempt(self, root: Path) -> tuple[Path, Path]:
        attempt = root / "attempt"
        controller = root / "controller"
        attempt.mkdir(mode=0o700)
        controller.mkdir(mode=0o700)
        for path in (
            attempt / "windows.qcow2",
            attempt / "OVMF_VARS.fd",
            controller / "bootstrap-dc.qcow2",
            controller / "OVMF_VARS.fd",
        ):
            path.write_bytes(b"fixture")
            path.chmod(0o600)
        write_prepared_authorization(attempt, controller)
        return attempt, controller

    def test_default_is_validating_dry_run(self):
        with tempfile.TemporaryDirectory() as name:
            attempt, controller = self.private_attempt(Path(name))
            with mock.patch("builtins.print") as output:
                result = windows_identity_cli.main([
                    "--attempt", str(attempt),
                    "--controller-state", str(controller),
                ])
        self.assertEqual(0, result)
        self.assertIn(
            "dry run; repeat with --apply",
            " ".join(str(call) for call in output.call_args_list),
        )

    def test_apply_delegates_to_strict_production_acceptance(self):
        with tempfile.TemporaryDirectory() as name:
            attempt, controller = self.private_attempt(Path(name))
            configuration = windows_identity_cli.AcceptanceConfiguration(
                rotation_plan=mock.sentinel.rotation_plan,
                publication=Path(name) / "publication.iso",
                private_root=Path(name),
                evidence=Path(name) / "evidence.jsonl",
                realm="FACTORY.TEST",
                callbacks=mock.sentinel.callbacks,
                stage_principals=mock.sentinel.stage_principals,
                destroy_principals=mock.sentinel.destroy_principals,
                stage_join_principal=mock.sentinel.stage_join_principal,
                destroy_join_principal=mock.sentinel.destroy_join_principal,
            )
            factory = mock.Mock(return_value=configuration)
            with mock.patch.object(
                windows_identity_cli, "execute_windows_identity_acceptance",
            ) as acceptance:
                result = windows_identity_cli.main(
                    [
                        "--attempt", str(attempt),
                        "--controller-state", str(controller),
                        "--apply",
                    ],
                    acceptance_factory=factory,
                )
        self.assertEqual(0, result)
        factory.assert_called_once()
        boundary = factory.call_args.args[0]
        acceptance.assert_called_once_with(
            boundary=boundary,
            rotation_plan=configuration.rotation_plan,
            publication=configuration.publication,
            private_root=configuration.private_root,
            evidence=configuration.evidence,
            realm=configuration.realm,
            callbacks=configuration.callbacks,
            stage_principals=configuration.stage_principals,
            destroy_principals=configuration.destroy_principals,
            stage_join_principal=configuration.stage_join_principal,
            destroy_join_principal=configuration.destroy_join_principal,
        )

    def test_claim_owner_can_revalidate_during_real_cli_composition(self):
        with tempfile.TemporaryDirectory() as name:
            attempt, controller = self.private_attempt(Path(name))
            configuration = mock.Mock()
            for field in (
                "rotation_plan", "publication", "private_root", "evidence",
                "realm", "callbacks", "stage_principals",
                "destroy_principals", "stage_join_principal",
                "destroy_join_principal",
            ):
                setattr(configuration, field, mock.sentinel.configuration)

            def acceptance(**arguments):
                # Production start_switch begins by validating again after the
                # CLI has published its one-use claim.
                arguments["boundary"]._validate()

            with mock.patch.object(
                windows_identity_cli,
                "execute_windows_identity_acceptance",
                side_effect=acceptance,
            ):
                result = windows_identity_cli.main(
                    [
                        "--attempt", str(attempt),
                        "--controller-state", str(controller),
                        "--apply",
                    ],
                    acceptance_factory=lambda _boundary: configuration,
                )
            receipt = json.loads(
                (attempt / "terminal-teardown.json").read_text(
                    encoding="utf-8"))
        self.assertEqual(0, result)
        self.assertTrue(receipt["teardown"]["owned_media_closed"])
        self.assertTrue(receipt["teardown_complete"])

    def test_prestart_failure_releases_validation_media_before_receipt(self):
        with tempfile.TemporaryDirectory() as name:
            attempt, controller = self.private_attempt(Path(name))
            configuration = mock.Mock()
            for field in (
                "rotation_plan", "publication", "private_root", "evidence",
                "realm", "callbacks", "stage_principals",
                "destroy_principals", "stage_join_principal",
                "destroy_join_principal",
            ):
                setattr(configuration, field, mock.sentinel.configuration)
            with mock.patch.object(
                windows_identity_cli,
                "execute_windows_identity_acceptance",
                side_effect=(
                    windows_identity_cli.WindowsIdentityOrchestratorError(
                        "pre-start")),
            ):
                result = windows_identity_cli.main(
                    [
                        "--attempt", str(attempt),
                        "--controller-state", str(controller),
                        "--apply",
                    ],
                    acceptance_factory=lambda _boundary: configuration,
                )
            receipt = json.loads(
                (attempt / "terminal-teardown.json").read_text(
                    encoding="utf-8"))
        self.assertEqual(2, result)
        self.assertEqual("failed", receipt["outcome"])
        self.assertTrue(receipt["teardown"]["owned_media_closed"])
        self.assertTrue(receipt["teardown_complete"])

    def test_incomplete_teardown_receipt_cannot_return_success(self):
        with tempfile.TemporaryDirectory() as name:
            attempt, controller = self.private_attempt(Path(name))
            configuration = mock.Mock()
            for field in (
                "rotation_plan", "publication", "private_root", "evidence",
                "realm", "callbacks", "stage_principals",
                "destroy_principals", "stage_join_principal",
                "destroy_join_principal",
            ):
                setattr(configuration, field, mock.sentinel.configuration)
            incomplete = {
                "processes_reaped": True,
                "qmp_closed": True,
                "runtime_quiescent": True,
                "owned_media_closed": False,
                "dependencies_released": True,
            }
            with mock.patch.object(
                windows_identity_cli, "execute_windows_identity_acceptance",
            ), mock.patch.object(
                windows_identity_cli.NativeProcessBoundary,
                "audit_teardown",
                return_value=incomplete,
            ):
                result = windows_identity_cli.main(
                    [
                        "--attempt", str(attempt),
                        "--controller-state", str(controller),
                        "--apply",
                    ],
                    acceptance_factory=lambda _boundary: configuration,
                )
            receipt = json.loads(
                (attempt / "terminal-teardown.json").read_text(
                    encoding="utf-8"))
        self.assertEqual(2, result)
        self.assertFalse(receipt["teardown_complete"])

    def test_apply_without_live_adapter_fails_closed(self):
        with tempfile.TemporaryDirectory() as name:
            attempt, controller = self.private_attempt(Path(name))
            result = windows_identity_cli.main([
                "--attempt", str(attempt),
                "--controller-state", str(controller),
                "--apply",
            ])
        self.assertEqual(2, result)

    def test_production_acceptance_refusal_is_reported(self):
        with tempfile.TemporaryDirectory() as name:
            attempt, controller = self.private_attempt(Path(name))
            configuration = windows_identity_cli.AcceptanceConfiguration(
                rotation_plan=mock.sentinel.rotation_plan,
                publication=Path(name) / "publication.iso",
                private_root=Path(name),
                evidence=Path(name) / "evidence.jsonl",
                realm="FACTORY.TEST",
                callbacks=mock.sentinel.callbacks,
                stage_principals=mock.sentinel.stage_principals,
                destroy_principals=mock.sentinel.destroy_principals,
                stage_join_principal=mock.sentinel.stage_join_principal,
                destroy_join_principal=mock.sentinel.destroy_join_principal,
            )
            with mock.patch.object(
                windows_identity_cli,
                "execute_windows_identity_acceptance",
                side_effect=(
                    windows_identity_cli.WindowsIdentityOrchestratorError(
                        "observation unavailable")),
            ):
                result = windows_identity_cli.main(
                    [
                        "--attempt", str(attempt),
                        "--controller-state", str(controller),
                        "--apply",
                    ],
                    acceptance_factory=lambda _boundary: configuration,
                )
        self.assertEqual(2, result)

    def test_typed_join_failure_renders_only_allowlisted_coordinate(self):
        diagnostic = IdentityFailureDiagnostic.join_material(
            "stage", "shell-prompt", "TimeoutError")
        with tempfile.TemporaryDirectory() as name:
            attempt, controller = self.private_attempt(Path(name))
            configuration = mock.Mock()
            configuration.rotation_plan = mock.sentinel.rotation_plan
            configuration.publication = Path(name) / "publication.iso"
            configuration.private_root = Path(name)
            configuration.evidence = Path(name) / "evidence.jsonl"
            configuration.realm = "FACTORY.TEST"
            configuration.callbacks = mock.sentinel.callbacks
            configuration.stage_principals = mock.sentinel.stage_principals
            configuration.destroy_principals = (
                mock.sentinel.destroy_principals)
            configuration.stage_join_principal = (
                mock.sentinel.stage_join_principal)
            configuration.destroy_join_principal = (
                mock.sentinel.destroy_join_principal)
            failure = windows_identity_cli.WindowsIdentityOrchestratorError(
                "domain join material failed; " + diagnostic.render(),
                diagnostic=diagnostic,
            )
            with mock.patch.object(
                windows_identity_cli,
                "execute_windows_identity_acceptance",
                side_effect=failure,
            ), mock.patch("sys.stderr") as stderr:
                result = windows_identity_cli.main(
                    [
                        "--attempt", str(attempt),
                        "--controller-state", str(controller),
                        "--apply",
                    ],
                    acceptance_factory=lambda _boundary: configuration,
                )
        self.assertEqual(2, result)
        rendered = " ".join(
            str(call) for call in stderr.write.call_args_list)
        self.assertIn(
            "check=windows-joined; "
            "operation=join-material.stage.shell-prompt; error=TimeoutError",
            rendered,
        )

    def test_adapter_configuration_errors_are_normalized(self):
        from homelab.vm.windows_identity_adapter import (
            WindowsIdentityAdapterError,
        )
        with tempfile.TemporaryDirectory() as name:
            attempt, controller = self.private_attempt(Path(name))
            factory = mock.Mock(side_effect=WindowsIdentityAdapterError(
                "trusted adapter unavailable"))
            with mock.patch("sys.stderr"):
                result = windows_identity_cli.main(
                    [
                        "--attempt", str(attempt),
                        "--controller-state", str(controller),
                        "--apply",
                    ],
                    acceptance_factory=factory,
                )
        self.assertEqual(2, result)


if __name__ == "__main__":
    unittest.main()
