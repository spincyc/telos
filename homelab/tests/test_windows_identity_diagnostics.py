import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from homelab.vm.windows_identity_diagnostics import (
    CredentialOwnershipState,
    ProductionSecretScanner,
    RetainedInventory,
    WindowsIdentityDiagnosticError,
)


class ProductionSecretScannerTests(unittest.TestCase):
    secret = "Known-Secret-47!"

    def scanner(
        self,
        root: Path,
        *,
        qemu_arguments: tuple[str, ...] = ("qemu-system-x86_64", "-nodefaults"),
        ownership: CredentialOwnershipState | None = None,
    ) -> ProductionSecretScanner:
        (root / "artifacts").mkdir(parents=True)
        (root / "logs").mkdir()
        (root / "artifacts/authorization.json").write_bytes(
            b'{"contains_secrets":false}\n')
        (root / "logs/windows-qemu.log").write_bytes(b"QEMU booted\n")
        return ProductionSecretScanner(
            retained=(RetainedInventory(
                root,
                tracked_artifacts=("artifacts/authorization.json",),
                logs=("logs/windows-qemu.log",),
            ),),
            qemu_arguments=qemu_arguments,
            credential_ownership=ownership or CredentialOwnershipState(
                acceptance_scope_active=True,
                scoped_credentials=1,
                credentials_outside_scope=0,
                recovery_publication_exists=False,
                recovered_credential_invalidated=True,
            ),
        )

    def test_derives_closed_clean_facts_from_all_exact_sources(self):
        with tempfile.TemporaryDirectory() as name:
            scanner = self.scanner(Path(name))
            self.assertEqual(scanner((self.secret,)), {
                "secrets_found": 0,
                "reusable_credentials_retained": False,
                "qemu_arguments_secret_free": True,
                "tracked_artifacts_secret_free": True,
                "logs_secret_free": True,
            })

    def test_counts_utf8_and_windows_utf16_secret_encodings_by_surface(self):
        with tempfile.TemporaryDirectory() as name:
            scanner = self.scanner(
                Path(name),
                qemu_arguments=("qemu-system-x86_64", f"token={self.secret}"),
                ownership=CredentialOwnershipState(True, 1, 1, False, True),
            )
            scanner.retained[0].root.joinpath(
                "artifacts/authorization.json").write_bytes(
                    self.secret.encode("utf-16-le"))
            scanner.retained[0].root.joinpath(
                "logs/windows-qemu.log").write_bytes(self.secret.encode())
            self.assertEqual(scanner((self.secret,)), {
                "secrets_found": 3,
                "reusable_credentials_retained": True,
                "qemu_arguments_secret_free": False,
                "tracked_artifacts_secret_free": False,
                "logs_secret_free": False,
            })

    def test_secret_split_across_read_blocks_is_detected_once(self):
        with tempfile.TemporaryDirectory() as name:
            scanner = self.scanner(Path(name))
            scanner.retained[0].root.joinpath(
                "logs/windows-qemu.log").write_bytes(
                    b"x" * (1024 * 1024 - 4) + self.secret.encode())
            result = scanner((self.secret,))
            self.assertEqual(result["secrets_found"], 1)
            self.assertFalse(result["logs_secret_free"])

    def test_inventory_rejects_missing_extra_symlink_and_nonregular_entries(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            scanner = self.scanner(root)
            log = root / "logs/windows-qemu.log"
            log.unlink()
            with self.assertRaises(WindowsIdentityDiagnosticError):
                scanner((self.secret,))
            log.write_bytes(b"clean")
            extra = root / "forgotten-secret.txt"
            extra.write_bytes(self.secret.encode())
            with self.assertRaises(WindowsIdentityDiagnosticError):
                scanner((self.secret,))
            extra.unlink()
            extra.mkdir()
            with self.assertRaises(WindowsIdentityDiagnosticError):
                scanner((self.secret,))
            extra.rmdir()
            target = root / "target"
            target.write_bytes(b"clean")
            log.unlink()
            log.symlink_to(target)
            with self.assertRaises(WindowsIdentityDiagnosticError):
                scanner((self.secret,))
            log.unlink()
            target.unlink()
            os.mkfifo(log)
            with self.assertRaises(WindowsIdentityDiagnosticError):
                scanner((self.secret,))

    def test_ownership_must_exactly_describe_the_active_secret_scope(self):
        with tempfile.TemporaryDirectory() as name:
            for state in (
                CredentialOwnershipState(False, 1, 0, False, True),
                CredentialOwnershipState(True, 0, 0, False, True),
                CredentialOwnershipState(True, 1, -1, False, True),
            ):
                root = Path(name) / str(len(tuple(Path(name).iterdir())))
                root.mkdir()
                scanner = self.scanner(root, ownership=state)
                with self.subTest(state=state), self.assertRaises(
                        WindowsIdentityDiagnosticError):
                    scanner((self.secret,))

    def test_only_reusable_recovery_publication_is_reported_as_retained(self):
        with tempfile.TemporaryDirectory() as name:
            scanner = self.scanner(
                Path(name) / "reusable",
                ownership=CredentialOwnershipState(True, 1, 0, True, False),
            )
            self.assertTrue(
                scanner((self.secret,))["reusable_credentials_retained"])
            scanner = self.scanner(
                Path(name) / "invalidated",
                ownership=CredentialOwnershipState(True, 1, 0, True, True),
            )
            self.assertFalse(
                scanner((self.secret,))["reusable_credentials_retained"])

    def test_invalid_secret_and_qemu_arguments_fail_closed(self):
        with tempfile.TemporaryDirectory() as name:
            scanner = self.scanner(Path(name))
            for secrets in ((), ("",)):
                with self.subTest(secrets=secrets), self.assertRaises(
                        WindowsIdentityDiagnosticError):
                    scanner(secrets)
        with self.assertRaises(WindowsIdentityDiagnosticError):
            ProductionSecretScanner(
                retained=(RetainedInventory(
                    Path("/unread"), tracked_artifacts=("one",), logs=("two",),
                ),),
                qemu_arguments=("qemu", ""),
                credential_ownership=CredentialOwnershipState(
                    True, 1, 0, False, True),
            )

    def test_source_mutation_during_scan_fails_closed(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            scanner = self.scanner(root)
            real_fstat = os.fstat
            calls = 0

            def changing_fstat(descriptor):
                nonlocal calls
                result = real_fstat(descriptor)
                calls += 1
                if calls == 2:
                    path = root / "artifacts/authorization.json"
                    os.utime(path, ns=(
                        result.st_atime_ns, result.st_mtime_ns + 1_000_000))
                    result = real_fstat(descriptor)
                return result

            with mock.patch(
                    "homelab.vm.windows_identity_diagnostics.os.fstat",
                    side_effect=changing_fstat), self.assertRaises(
                        WindowsIdentityDiagnosticError):
                scanner((self.secret,))


if __name__ == "__main__":
    unittest.main()
