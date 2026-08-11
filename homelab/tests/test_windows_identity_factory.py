import json
from pathlib import Path
import socket
import tempfile
import unittest
from unittest import mock

from homelab.vm import windows_identity_factory as factory_subject
from homelab.tests.windows_identity_fixture import (
    write_prepared_authorization,
)
from homelab.vm.windows_identity_factory import (
    WindowsIdentityFactoryError,
    default_acceptance_factory,
)
from homelab.vm.windows_identity_run import NativeProcessBoundary


SOURCE_DISK_SHA256 = (
    "eb002be58d216908e5724512682523f70f4f1afeaa6d93ad9de9c942dc11977d"
)


class WindowsIdentityFactoryTests(unittest.TestCase):
    def bind_live_serial(self, path: Path) -> None:
        """Model the mid-run COM1 server socket QEMU already owns.

        The acceptance secret scan re-derives the running argv while the
        private serial socket exists, so scan_secrets requires a live private
        socket rather than the launch-time absence.
        """
        server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        server.bind(str(path))
        self.addCleanup(server.close)

    def factory(self, boundary, bundle):
        with mock.patch(
            "homelab.vm.windows_identity_factory._sha256",
            return_value=SOURCE_DISK_SHA256,
        ), mock.patch(
            "homelab.vm.windows_identity_factory._actual_overlay_backing",
            return_value=(bundle / "windows.qcow2").resolve(),
        ):
            return default_acceptance_factory(boundary)

    def prepared(self, root: Path):
        attempt = root / "attempt"
        controller = root / "controller"
        bundle = root / "bundle"
        attempt.mkdir(mode=0o700)
        controller.mkdir(mode=0o700)
        bundle.mkdir(mode=0o700)
        for path in (
            attempt / "windows.qcow2",
            attempt / "OVMF_VARS.fd",
            controller / "bootstrap-dc.qcow2",
            controller / "OVMF_VARS.fd",
        ):
            path.write_bytes(b"fixture")
            path.chmod(0o600)
        publication = bundle / "publication.iso"
        publication.write_bytes(b"private recovery")
        publication.chmod(0o600)
        evidence = bundle / "evidence"
        (evidence / "screens").mkdir(parents=True)
        (evidence / "controller/guard").mkdir(parents=True)
        (evidence / "screens/001.ppm").write_bytes(b"public frame")
        (evidence / "workstation.log").write_bytes(b"public log")
        write_prepared_authorization(attempt, controller)
        authorization_path = attempt / "authorization.json"
        authorization = json.loads(authorization_path.read_text())
        source_disk = bundle / "windows.qcow2"
        source_disk.write_bytes(b"source")
        source_disk.chmod(0o600)
        authorization["source"] = {
            "bundle": str(bundle.resolve()),
            "disk": {
                "path": str(source_disk.resolve()),
                "sha256": SOURCE_DISK_SHA256,
            },
        }
        authorization["overlay"]["backing_path"] = str(source_disk.resolve())
        authorization_path.write_text(json.dumps(authorization))
        authorization_path.chmod(0o600)
        boundary = NativeProcessBoundary(attempt, controller)
        boundary._validate()
        boundary.controller_console = mock.Mock(
            password=b"Synthetic-Controller-Fixture-47!")
        return boundary, bundle

    def test_builds_exact_default_configuration_and_scanner(self):
        with tempfile.TemporaryDirectory() as name:
            boundary, bundle = self.prepared(Path(name))
            configuration = self.factory(boundary, bundle)
            self.assertEqual(
                bundle / "publication.iso", configuration.publication)
            self.assertEqual(boundary.attempt, configuration.private_root)
            self.assertEqual("AD.FACTORY.TEST", configuration.realm)
            self.assertEqual(
                "run-dialog",
                configuration.callbacks.launch_guest.__self__.
                command_plan.run_dialog.state_kind,
            )
            self.assertEqual(
                ("down", "down", "down", "ret"),
                configuration.rotation_plan.change_password_keys,
            )
            self.assertTrue(
                configuration.rotation_plan.
                post_join_local_account_calibrated,
            )
            self.assertEqual(
                "post-join-sign-in.json",
                configuration.rotation_plan.
                post_join_sign_in_manifest.name,
            )
            self.assertTrue(
                configuration.rotation_plan.
                post_join_operator_account_calibrated,
            )
            self.assertEqual(
                "post-join-operator-sign-in.json",
                configuration.rotation_plan.
                post_join_operator_sign_in_manifest.name,
            )
            self.assertFalse(
                configuration.rotation_plan.
                post_join_operator_submit_focus_calibration,
            )
            self.assertEqual(
                0,
                configuration.rotation_plan.
                post_join_operator_submit_focus_tabs,
            )
            self.assertFalse(
                configuration.rotation_plan.
                post_join_operator_submit_focus_authorized,
            )
            self.assertIsNone(
                configuration.rotation_plan.
                post_join_operator_submit_focus_reference,
            )
            adapter = configuration.callbacks.launch_guest.__self__
            with self.assertRaisesRegex(
                WindowsIdentityFactoryError, "serial endpoint"
            ):
                adapter.post_submit_diagnostic(
                    nonce="a" * 64,
                    principal="operator@AD.FACTORY.TEST",
                    timeout=47.0,
                )

            boundary.serial_socket = Path(name) / "live-windows.serial"
            diagnostic = object()
            with mock.patch.object(
                factory_subject.PostSubmitDiagnosticSession,
                "connect",
                return_value=diagnostic,
            ) as connect:
                self.assertIs(
                    diagnostic,
                    adapter.post_submit_diagnostic(
                        nonce="b" * 64,
                        principal="operator@AD.FACTORY.TEST",
                        timeout=47.0,
                    ),
                )
            connect.assert_called_once_with(
                boundary.serial_socket,
                nonce="b" * 64,
                principal="operator@AD.FACTORY.TEST",
                timeout=47.0,
            )
            runtime = boundary.attempt / "runtime"
            (runtime / "controller/guard").mkdir(parents=True, mode=0o700)
            for relative in (
                "switch.jsonl", "windows-qemu.log",
                "controller/controller.raw", "controller/OVMF_VARS.fd",
                "controller/guard/controller-overlay.qcow2",
                "controller/guard/OVMF_VARS.fd",
            ):
                (runtime / relative).write_bytes(b"clean")
            for surface_name in (
                "rotation-evidence", "public-command-evidence",
                "post-join-reauthentication",
            ):
                evidence = boundary.attempt / surface_name
                evidence.mkdir(mode=0o700)
                if surface_name == "post-join-reauthentication":
                    (
                        evidence / "post-join-generic-prompt.ppm"
                    ).write_bytes(b"public frame")
                    (
                        evidence / "post-join-generic-prompt.json"
                    ).write_text('{"secret_input_since_post_join_reboot":false}')
                    for state in (
                        "operator-generic-prompt",
                        "operator-password-target",
                    ):
                        (evidence / f"post-join-{state}.ppm").write_bytes(
                            b"public frame")
                        (evidence / f"post-join-{state}.json").write_text(
                            '{"secret_input_since_post_join_reboot":false}')
                else:
                    (evidence / "proof.ppm").write_bytes(b"public frame")
            boundary.qmp_root = Path(name) / "runtime-qmp"
            boundary.qmp_root.mkdir(mode=0o700)
            boundary.serial_socket = boundary.qmp_root / "windows.serial"
            self.bind_live_serial(boundary.serial_socket)
            boundary.port = 31415
            boundary.processes["windows"] = mock.Mock(
                poll=mock.Mock(return_value=None))
            scan = configuration.callbacks.scan_secrets(
                tuple(f"Synthetic-Unique-{index}-47!"
                      for index in range(4)))
            self.assertEqual(0, scan["secrets_found"])
            self.assertTrue(scan["logs_secret_free"])

    def test_prepared_calibration_authority_configures_exact_count(self):
        with tempfile.TemporaryDirectory() as name:
            boundary, bundle = self.prepared(Path(name))
            path = boundary.attempt / "authorization.json"
            authorization = json.loads(path.read_text())
            authorization["post_join_submit_focus_calibration"] = {
                "enabled": True,
                "tabs": 3,
            }
            path.write_text(json.dumps(authorization))
            path.chmod(0o600)

            configuration = self.factory(boundary, bundle)

        self.assertTrue(
            configuration.rotation_plan.
            post_join_operator_submit_focus_calibration)
        self.assertEqual(
            3,
            configuration.rotation_plan.post_join_operator_submit_focus_tabs)

    def test_reviewed_activation_authority_loads_tracked_reference(self):
        with tempfile.TemporaryDirectory() as name:
            boundary, bundle = self.prepared(Path(name))
            path = boundary.attempt / "authorization.json"
            authorization = json.loads(path.read_text())
            authorization["post_join_submit_focus_activation"] = {
                "enabled": True,
                "reference": "post-join-operator-submit-focus.json",
                "sha256": factory_subject._trusted_reference_sha256(
                    factory_subject.REFERENCE_ROOT
                    / "post-join-operator-submit-focus.json"),
            }
            path.write_text(json.dumps(authorization))
            path.chmod(0o600)

            configuration = self.factory(boundary, bundle)

        plan = configuration.rotation_plan
        self.assertTrue(plan.post_join_operator_submit_focus_authorized)
        self.assertEqual(
            "post-join-operator-submit-focus.json",
            plan.post_join_operator_submit_focus_reference.name,
        )

    def test_rejects_overlapping_submit_focus_authorities(self):
        with tempfile.TemporaryDirectory() as name:
            boundary, bundle = self.prepared(Path(name))
            path = boundary.attempt / "authorization.json"
            authorization = json.loads(path.read_text())
            authorization["post_join_submit_focus_calibration"] = {
                "enabled": True, "tabs": 1}
            authorization["post_join_submit_focus_activation"] = {
                "enabled": True,
                "reference": "post-join-operator-submit-focus.json",
                "sha256": factory_subject._trusted_reference_sha256(
                    factory_subject.REFERENCE_ROOT
                    / "post-join-operator-submit-focus.json"),
            }
            path.write_text(json.dumps(authorization))
            path.chmod(0o600)
            with self.assertRaisesRegex(
                WindowsIdentityFactoryError, "mutually exclusive"
            ):
                self.factory(boundary, bundle)

    def test_rejects_reviewed_reference_digest_mismatch(self):
        with tempfile.TemporaryDirectory() as name:
            boundary, bundle = self.prepared(Path(name))
            path = boundary.attempt / "authorization.json"
            authorization = json.loads(path.read_text())
            authorization["post_join_submit_focus_activation"] = {
                "enabled": True,
                "reference": "post-join-operator-submit-focus.json",
                "sha256": "0" * 64,
            }
            path.write_text(json.dumps(authorization))
            path.chmod(0o600)
            with self.assertRaisesRegex(
                WindowsIdentityFactoryError, "digest does not match"
            ):
                self.factory(boundary, bundle)

    def test_rejects_schema_tampered_reviewed_reference(self):
        source = (
            factory_subject.REFERENCE_ROOT
            / "post-join-operator-submit-focus.json")
        document = json.loads(source.read_text())
        document["activation"]["fallback_authorized"] = True
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            (root / source.name).write_text(json.dumps(document))
            guest = factory_subject.GuestProvenance(**document["guest"])
            with (
                mock.patch.object(factory_subject, "REFERENCE_ROOT", root),
                self.assertRaisesRegex(
                    WindowsIdentityFactoryError,
                    "reviewed submit-focus reference is invalid",
                ),
            ):
                factory_subject._reviewed_submit_focus_reference(guest)

    def test_rejects_invalid_enabled_operator_reference_before_runtime(self):
        original = factory_subject.load_identity_reference

        def load(path, **kwargs):
            if path.name == "post-join-operator-sign-in.json":
                raise factory_subject.WindowsIdentityReferenceError(
                    "invalid operator reference")
            return original(path, **kwargs)

        with tempfile.TemporaryDirectory() as name:
            boundary, bundle = self.prepared(Path(name))
            with mock.patch.object(
                    factory_subject, "load_identity_reference",
                    side_effect=load):
                with self.assertRaisesRegex(
                        WindowsIdentityFactoryError,
                        "trusted Windows references"):
                    self.factory(boundary, bundle)

    def test_scanner_detects_attempt_runtime_and_gui_evidence_leaks(self):
        secret = "Synthetic-Runtime-Leak-47!"
        for relative in (
            "runtime/windows-qemu.log",
            "rotation-evidence/proof.ppm",
            "public-command-evidence/proof.ppm",
            "post-join-reauthentication/post-join-generic-prompt.ppm",
        ):
            with self.subTest(relative=relative), tempfile.TemporaryDirectory(
            ) as name:
                boundary, _bundle = self.prepared(Path(name))
                configuration = self.factory(boundary, _bundle)
                runtime = boundary.attempt / "runtime"
                (runtime / "controller/guard").mkdir(
                    parents=True, mode=0o700)
                for item in (
                    "switch.jsonl", "windows-qemu.log",
                    "controller/controller.raw", "controller/OVMF_VARS.fd",
                    "controller/guard/controller-overlay.qcow2",
                    "controller/guard/OVMF_VARS.fd",
                ):
                    (runtime / item).write_bytes(b"clean")
                for surface in (
                    "rotation-evidence", "public-command-evidence",
                    "post-join-reauthentication",
                ):
                    target = boundary.attempt / surface
                    target.mkdir(mode=0o700)
                    proof_name = (
                        "post-join-generic-prompt.ppm"
                        if surface == "post-join-reauthentication"
                        else "proof.ppm"
                    )
                    (target / proof_name).write_bytes(b"clean")
                (boundary.attempt / relative).write_bytes(secret.encode())
                boundary.qmp_root = Path(name) / "qmp"
                boundary.qmp_root.mkdir(mode=0o700)
                boundary.serial_socket = boundary.qmp_root / "windows.serial"
                self.bind_live_serial(boundary.serial_socket)
                boundary.port = 31415
                boundary.processes["windows"] = mock.Mock(
                    poll=mock.Mock(return_value=None))
                result = configuration.callbacks.scan_secrets(
                    (secret, "two", "three", "four"))
                self.assertGreater(result["secrets_found"], 0)

    def test_scanner_rejects_unallowlisted_post_join_ppm(self):
        with tempfile.TemporaryDirectory() as name:
            boundary, bundle = self.prepared(Path(name))
            configuration = self.factory(boundary, bundle)
            runtime = boundary.attempt / "runtime"
            (runtime / "controller/guard").mkdir(parents=True, mode=0o700)
            for relative in (
                "switch.jsonl", "windows-qemu.log",
                "controller/controller.raw", "controller/OVMF_VARS.fd",
                "controller/guard/controller-overlay.qcow2",
                "controller/guard/OVMF_VARS.fd",
            ):
                (runtime / relative).write_bytes(b"clean")
            for surface in (
                "rotation-evidence", "public-command-evidence",
                "post-join-reauthentication",
            ):
                target = boundary.attempt / surface
                target.mkdir(mode=0o700)
                frame = (
                    "unreviewed.ppm"
                    if surface == "post-join-reauthentication"
                    else "proof.ppm"
                )
                (target / frame).write_bytes(b"clean")
            boundary.qmp_root = Path(name) / "qmp"
            boundary.qmp_root.mkdir(mode=0o700)
            boundary.serial_socket = boundary.qmp_root / "windows.serial"
            self.bind_live_serial(boundary.serial_socket)
            boundary.port = 31415
            boundary.processes["windows"] = mock.Mock(
                poll=mock.Mock(return_value=None))

            with self.assertRaisesRegex(
                WindowsIdentityFactoryError, "unexpected retained path"
            ):
                configuration.callbacks.scan_secrets(
                    ("one", "two", "three", "four"))

    def test_rejects_missing_recovery_publication(self):
        with tempfile.TemporaryDirectory() as name:
            boundary, bundle = self.prepared(Path(name))
            (bundle / "publication.iso").unlink()
            with self.assertRaisesRegex(
                    WindowsIdentityFactoryError, "publication"):
                self.factory(boundary, bundle)

    def test_rejects_source_hash_and_actual_backing_mismatch(self):
        with tempfile.TemporaryDirectory() as name:
            boundary, bundle = self.prepared(Path(name))
            with mock.patch(
                "homelab.vm.windows_identity_factory._sha256",
                return_value="0" * 64,
            ), mock.patch(
                "homelab.vm.windows_identity_factory._actual_overlay_backing",
                return_value=(bundle / "windows.qcow2").resolve(),
            ), self.assertRaisesRegex(
                WindowsIdentityFactoryError, "source disk"):
                default_acceptance_factory(boundary)
            with mock.patch(
                "homelab.vm.windows_identity_factory._sha256",
                return_value=SOURCE_DISK_SHA256,
            ), mock.patch(
                "homelab.vm.windows_identity_factory._actual_overlay_backing",
                return_value=(bundle / "different.qcow2").resolve(),
            ), self.assertRaisesRegex(
                WindowsIdentityFactoryError, "source disk"):
                default_acceptance_factory(boundary)

    def test_rejects_stale_acceptance_state(self):
        with tempfile.TemporaryDirectory() as name:
            boundary, bundle = self.prepared(Path(name))
            (boundary.attempt / "rotation-evidence").mkdir(mode=0o700)
            with mock.patch(
                "homelab.vm.windows_identity_factory._sha256",
                return_value=SOURCE_DISK_SHA256,
            ), mock.patch(
                "homelab.vm.windows_identity_factory._actual_overlay_backing",
                return_value=(bundle / "windows.qcow2").resolve(),
            ), self.assertRaisesRegex(
                WindowsIdentityFactoryError, "stale"):
                default_acceptance_factory(boundary)


if __name__ == "__main__":
    unittest.main()
