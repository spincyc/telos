import base64
import json
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

    def test_counts_base64_wrapped_json_secret_by_surface(self):
        wire = base64.urlsafe_b64encode(json.dumps({
            "prefix": "x",
            "password": self.secret,
        }, separators=(",", ":")).encode()).rstrip(b"=")
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            scanner = self.scanner(
                root, qemu_arguments=("qemu-system-x86_64", wire.decode()))
            (root / "artifacts/authorization.json").write_bytes(wire)
            (root / "logs/windows-qemu.log").write_bytes(wire)
            self.assertEqual(scanner((self.secret,)), {
                "secrets_found": 3,
                "reusable_credentials_retained": False,
                "qemu_arguments_secret_free": False,
                "tracked_artifacts_secret_free": False,
                "logs_secret_free": False,
            })

    def test_base64_wrapped_secret_split_across_blocks_is_detected(self):
        wire = base64.b64encode(json.dumps({
            "padding": "xx",
            "password": self.secret,
        }).encode())
        with tempfile.TemporaryDirectory() as name:
            scanner = self.scanner(Path(name))
            scanner.retained[0].root.joinpath(
                "logs/windows-qemu.log").write_bytes(
                    b"!" * (1024 * 1024 - len(wire) // 2)
                    + wire + b"!")
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

    def test_explicit_empty_directories_are_exhaustively_accounted_for(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            (root / "artifact").write_bytes(b"clean")
            (root / "empty/nested").mkdir(parents=True)
            scanner = ProductionSecretScanner(
                retained=(RetainedInventory(
                    root,
                    tracked_artifacts=("artifact",),
                    logs=(),
                    directories=("empty/nested",),
                ),),
                qemu_arguments=("qemu",),
                credential_ownership=CredentialOwnershipState(
                    True, 1, 0, False, True),
            )
            self.assertEqual(0, scanner((self.secret,))["secrets_found"])

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

    def test_inventory_change_after_file_scan_fails_closed(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            scanner = self.scanner(root)
            from homelab.vm import windows_identity_diagnostics as diagnostics
            real_scan = diagnostics._scan_regular_file
            calls = 0

            def scan_and_add(path, needles, **kwargs):
                nonlocal calls
                result = real_scan(path, needles, **kwargs)
                calls += 1
                if calls == 2:
                    (root / "late-sidecar").write_bytes(self.secret.encode())
                return result

            with mock.patch.object(
                    diagnostics, "_scan_regular_file",
                    side_effect=scan_and_add), self.assertRaises(
                        WindowsIdentityDiagnosticError):
                scanner((self.secret,))


class LiveInventoryScannerTests(unittest.TestCase):
    """Mid-run scans of the live acceptance attempt directory.

    The attempt tree is scanned while the guest QEMU and the simulated switch
    still append to their runtime logs and drop new evidence files. These
    tests pin exactly which motion is tolerated (append-only log growth, new
    evidence files appearing) and which is still rejected (an in-place rewrite
    of any scanned file, a symlink or nonregular entry, or a secret anywhere).
    """

    secret = "Known-Secret-47!"

    def live_scanner(
        self,
        root: Path,
        *,
        live_logs: tuple[str, ...] = ("logs/live.jsonl",),
        ownership: CredentialOwnershipState | None = None,
    ) -> ProductionSecretScanner:
        (root / "artifacts").mkdir(parents=True)
        (root / "logs").mkdir()
        (root / "artifacts/authorization.json").write_bytes(
            b'{"contains_secrets":false}\n')
        (root / "logs/live.jsonl").write_bytes(b'{"event":"boot"}\n')
        return ProductionSecretScanner(
            retained=(RetainedInventory(
                root,
                tracked_artifacts=("artifacts/authorization.json",),
                logs=("logs/live.jsonl",),
                live_logs=live_logs,
            ),),
            qemu_arguments=("qemu-system-x86_64", "-nodefaults"),
            credential_ownership=ownership or CredentialOwnershipState(
                acceptance_scope_active=True,
                scoped_credentials=1,
                credentials_outside_scope=0,
                recovery_publication_exists=False,
                recovered_credential_invalidated=True,
            ),
        )

    def test_live_log_requires_a_declared_log(self):
        with tempfile.TemporaryDirectory() as name:
            with self.assertRaises(WindowsIdentityDiagnosticError):
                RetainedInventory(
                    Path(name),
                    tracked_artifacts=("a",),
                    logs=("b.log",),
                    live_logs=("c.log",),
                )

    def test_quiescent_live_tree_scans_clean(self):
        with tempfile.TemporaryDirectory() as name:
            scanner = self.live_scanner(Path(name))
            self.assertEqual(scanner((self.secret,)), {
                "secrets_found": 0,
                "reusable_credentials_retained": False,
                "qemu_arguments_secret_free": True,
                "tracked_artifacts_secret_free": True,
                "logs_secret_free": True,
            })

    def test_mid_run_append_to_live_log_is_tolerated(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            scanner = self.live_scanner(root)
            from homelab.vm import windows_identity_diagnostics as diagnostics
            real_scan = diagnostics._scan_regular_file
            live_log = root / "logs/live.jsonl"

            def growing_scan(path, needles, **kwargs):
                # Model the switch/QEMU appending a line to the live log while
                # the rest of the tree is being scanned.
                result = real_scan(path, needles, **kwargs)
                with open(live_log, "ab") as handle:
                    handle.write(b'{"event":"tick"}\n')
                return result

            with mock.patch.object(
                    diagnostics, "_scan_regular_file",
                    side_effect=growing_scan):
                result = scanner((self.secret,))
            self.assertEqual(result["secrets_found"], 0)
            self.assertTrue(result["logs_secret_free"])

    def test_secret_appended_to_live_log_is_still_detected(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            scanner = self.live_scanner(root)
            with open(root / "logs/live.jsonl", "ab") as handle:
                handle.write(self.secret.encode() + b"\n")
            result = scanner((self.secret,))
            self.assertEqual(result["secrets_found"], 1)
            self.assertFalse(result["logs_secret_free"])

    def test_new_evidence_file_present_at_walk_is_scanned(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            scanner = self.live_scanner(root)
            # A benign evidence file that appeared after the caller's snapshot
            # is tolerated and scanned as found.
            (root / "runtime").mkdir()
            (root / "runtime/windows-boot-attempt-1.json").write_bytes(
                b'{"boot":1}')
            self.assertEqual(0, scanner((self.secret,))["secrets_found"])
            # And a secret hiding in that new evidence file is still caught.
            (root / "runtime/windows-boot-attempt-1.json").write_bytes(
                self.secret.encode())
            result = scanner((self.secret,))
            self.assertEqual(result["secrets_found"], 1)
            self.assertFalse(result["tracked_artifacts_secret_free"])

    def test_new_evidence_file_appearing_during_scan_is_tolerated(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            scanner = self.live_scanner(root)
            from homelab.vm import windows_identity_diagnostics as diagnostics
            real_scan = diagnostics._scan_regular_file
            calls = 0

            def scan_then_drop(path, needles, **kwargs):
                nonlocal calls
                result = real_scan(path, needles, **kwargs)
                calls += 1
                if calls == 1:
                    (root / "late-evidence.json").write_bytes(b'{"late":1}')
                return result

            with mock.patch.object(
                    diagnostics, "_scan_regular_file",
                    side_effect=scan_then_drop):
                # A new file appearing after the pre-scan walk is not scanned
                # this pass but must not fail the live scan.
                self.assertEqual(0, scanner((self.secret,))["secrets_found"])

    def test_artifact_rewritten_after_its_scan_fails_closed(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            scanner = self.live_scanner(root)
            from homelab.vm import windows_identity_diagnostics as diagnostics
            real_scan = diagnostics._scan_regular_file
            artifact = root / "artifacts/authorization.json"

            def scan_then_touch_artifact(path, needles, **kwargs):
                result = real_scan(path, needles, **kwargs)
                if Path(path) == artifact:
                    info = os.stat(artifact)
                    os.utime(artifact, ns=(
                        info.st_atime_ns, info.st_mtime_ns + 1_000_000))
                return result

            with mock.patch.object(
                    diagnostics, "_scan_regular_file",
                    side_effect=scan_then_touch_artifact), self.assertRaises(
                        WindowsIdentityDiagnosticError):
                scanner((self.secret,))

    def test_live_log_rewritten_after_its_scan_fails_closed(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            scanner = self.live_scanner(root)
            from homelab.vm import windows_identity_diagnostics as diagnostics
            real_scan = diagnostics._scan_regular_file
            live_log = root / "logs/live.jsonl"

            def scan_then_replace_log(path, needles, **kwargs):
                result = real_scan(path, needles, **kwargs)
                if Path(path) == live_log:
                    # A fresh inode is a rewrite, not an append: rejected even
                    # though it is a live log.
                    live_log.unlink()
                    live_log.write_bytes(b'{"event":"rewritten"}\n')
                return result

            with mock.patch.object(
                    diagnostics, "_scan_regular_file",
                    side_effect=scan_then_replace_log), self.assertRaises(
                        WindowsIdentityDiagnosticError):
                scanner((self.secret,))

    def test_symlink_or_nonregular_appearing_fails_closed(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            scanner = self.live_scanner(root)
            fifo = root / "logs/pipe.jsonl"
            os.mkfifo(fifo)
            with self.assertRaises(WindowsIdentityDiagnosticError):
                scanner((self.secret,))
            fifo.unlink()
            target = root / "artifacts/authorization.json"
            link = root / "logs/alias.jsonl"
            link.symlink_to(target)
            with self.assertRaises(WindowsIdentityDiagnosticError):
                scanner((self.secret,))

    def test_declared_file_vanishing_fails_closed(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            scanner = self.live_scanner(root)
            (root / "artifacts/authorization.json").unlink()
            with self.assertRaises(WindowsIdentityDiagnosticError):
                scanner((self.secret,))

    def test_frozen_inventory_still_rejects_append_growth(self):
        # The sealed source publication is a frozen inventory: even append-only
        # growth of one of its logs between the two walks is rejected, because
        # nothing is meant to touch it during the scan.
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            (root / "logs").mkdir()
            (root / "artifact").write_bytes(b"clean")
            (root / "logs/frozen.log").write_bytes(b"line\n")
            scanner = ProductionSecretScanner(
                retained=(RetainedInventory(
                    root,
                    tracked_artifacts=("artifact",),
                    logs=("logs/frozen.log",),
                ),),
                qemu_arguments=("qemu",),
                credential_ownership=CredentialOwnershipState(
                    True, 1, 0, False, True),
            )
            from homelab.vm import windows_identity_diagnostics as diagnostics
            real_scan = diagnostics._scan_regular_file
            frozen_log = root / "logs/frozen.log"

            def scan_then_grow(path, needles, **kwargs):
                result = real_scan(path, needles, **kwargs)
                if Path(path) == frozen_log:
                    with open(frozen_log, "ab") as handle:
                        handle.write(b"appended\n")
                return result

            with mock.patch.object(
                    diagnostics, "_scan_regular_file",
                    side_effect=scan_then_grow), self.assertRaises(
                        WindowsIdentityDiagnosticError):
                scanner((self.secret,))


if __name__ == "__main__":
    unittest.main()
