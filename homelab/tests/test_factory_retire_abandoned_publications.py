"""Destructive retirement guards use only temporary bundles and a fake /proc."""
from contextlib import contextmanager
import fcntl
import hashlib
from importlib.machinery import SourceFileLoader
import importlib.util
import json
import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest import mock

TOOL = Path(__file__).resolve().parents[2] / "tools/factory-retire-abandoned-publications"
SPEC = importlib.util.spec_from_loader("retire_publications", SourceFileLoader("retire_publications", str(TOOL)))
tool = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(tool)


class PublicationRetirementTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.repository = self.root / "repo"
        self.repository.mkdir(mode=0o700)
        self.proc = self.root / "proc"
        self.proc.mkdir()
        self.receipts = self.root / "receipts"
        self.receipts.mkdir(mode=0o700)
        self.receipt = self.receipts / "retired.jsonl"
        self.write(self.repository / tool.LOCK, b"")
        self.bundle = self.make_bundle(1)

    @staticmethod
    def write(path, data):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        path.chmod(0o600)

    def make_bundle(self, number):
        bundle = self.repository / tool.BUNDLES / f"run-20261001T000000Z-{number:012x}"
        bundle.mkdir(parents=True, mode=0o700)
        (bundle / "evidence").mkdir(mode=0o700)
        self.write(bundle / "evidence/result.json", json.dumps({
            "schema": 1, "status": "fail", "phase": "windows-setup",
            "error_type": "RunInterrupted", "private_publication_retained_for_identity": True,
            "retained_logs": {"workstation-serial.log": {
                "elided_bytes": 0, "original_bytes": len(b"WinPE has started\n"),
                "retained_bytes": len(b"WinPE has started\n")}}}).encode())
        self.write(bundle / "evidence/workstation-serial.log", b"WinPE has started\n")
        argv = ["qemu-system-x86_64", "-drive", str(bundle / "windows.qcow2")]
        self.write(bundle / "qemu-command.json", json.dumps({"schema": 1, "argv": argv}).encode())
        self.write(bundle / "authorization.json", json.dumps({"schema": 1, "authorization": {
            "qemu_argv_sha256": hashlib.sha256(json.dumps(argv, separators=(",", ":")).encode()).hexdigest()}}).encode())
        for name in ("windows.qcow2", "OVMF_VARS.fd", "publication.iso"):
            self.write(bundle / name, f"synthetic {number} {name}\n".encode())
        return bundle

    def run_tool(self, bundles=None, apply=False, receipt=None):
        return tool.run(bundles or [self.bundle], repository=self.repository,
                        proc=self.proc, apply=apply, receipt=receipt)

    def apply(self, bundles=None):
        return self.run_tool(bundles, apply=True, receipt=self.receipt)

    def unchanged_files(self):
        return {str(p.relative_to(self.repository)): p.read_bytes()
                for p in self.repository.rglob("*") if p.is_file() and p.name != tool.ISO}

    def refused(self, bundles=None):
        with self.assertRaises((tool.Refused, OSError, ValueError)):
            self.apply(bundles)
        for bundle in bundles or [self.bundle]:
            self.assertTrue((bundle / tool.ISO).exists())

    def test_plan_is_deterministic_and_does_not_mutate(self):
        original = self.unchanged_files()
        iso = (self.bundle / tool.ISO).read_bytes()
        first = self.run_tool()
        self.assertEqual(first, self.run_tool())
        self.assertEqual("plan", first["status"])
        self.assertEqual(hashlib.sha256(iso).hexdigest(), first["publications"][0]["sha256"])
        self.assertEqual(original, self.unchanged_files())
        self.assertFalse(self.receipt.exists())
        self.assertEqual(iso, (self.bundle / tool.ISO).read_bytes())

    def test_apply_removes_only_named_isos_and_keeps_private_durable_receipt(self):
        second = self.make_bundle(2)
        untouched = self.make_bundle(3)
        before = self.unchanged_files()
        plan = self.run_tool([self.bundle, second])
        result = self.apply([self.bundle, second])
        self.assertEqual("retired", result["status"])
        self.assertFalse((self.bundle / tool.ISO).exists())
        self.assertFalse((second / tool.ISO).exists())
        self.assertTrue((untouched / tool.ISO).exists())
        self.assertEqual(before, self.unchanged_files())
        self.assertEqual(0o600, stat.S_IMODE(self.receipt.stat().st_mode))
        events = [json.loads(line) for line in self.receipt.read_text().splitlines()]
        self.assertEqual(["prepared", "retired", "retired", "complete"], [e["status"] for e in events])
        self.assertEqual(plan["publications"], events[0]["publications"])
        self.assertEqual(plan["bytes"], events[-1]["bytes"])

    def test_nonfailure_unknown_phase_or_custody_refused_before_any_unlink(self):
        result = self.bundle / "evidence/result.json"
        original = json.loads(result.read_bytes())
        for change in ({"status": "observed"}, {"status": "pass"}, {"phase": "native-windows-clean-shutdown"},
                       {"schema": True}, {"error_type": "PxeLoop"}, {"private_publication_retained_for_identity": False}):
            with self.subTest(change=change):
                self.write(result, json.dumps({**original, **change}).encode())
                self.refused()
                self.assertFalse(self.receipt.exists())

    def test_bad_later_bundle_is_preflighted_before_first_unlink(self):
        second = self.make_bundle(2)
        self.write(second / "evidence/result.json", b"{}")
        self.refused([self.bundle, second])
        self.assertFalse(self.receipt.exists())

    def test_native_ready_marker_refused(self):
        self.write(self.bundle / "evidence/workstation-serial.log", tool.NATIVE)
        path = self.bundle / "evidence/result.json"
        value = json.loads(path.read_bytes())
        value["retained_logs"]["workstation-serial.log"].update(
            original_bytes=len(tool.NATIVE), retained_bytes=len(tool.NATIVE))
        self.write(path, json.dumps(value).encode())
        self.refused()

    def test_elided_or_missing_completeness_cannot_hide_native_marker(self):
        path = self.bundle / "evidence/result.json"
        original = json.loads(path.read_bytes())
        for record in (None, {}, {"elided_bytes": 26, "original_bytes": 43, "retained_bytes": 17},
                       {"elided_bytes": 0, "original_bytes": 18, "retained_bytes": 17},
                       {"elided_bytes": False, "original_bytes": 17, "retained_bytes": 17}):
            with self.subTest(record=record):
                value = {**original, "retained_logs": {"workstation-serial.log": record}}
                self.write(path, json.dumps(value).encode())
                self.refused()

    def test_identity_reservation_or_unknown_bundle_entry_refused(self):
        for name in ("identity", "reservation.json", "keeper", "unexpected"):
            with self.subTest(name=name):
                path = self.bundle / name
                path.mkdir()
                self.refused()
                path.rmdir()

    def test_external_metadata_references_refused(self):
        for relative in ("homelab/var/factory/arch-installs/run/authorization.json",
                         "build/homelab/vm/workstations/kept/workstation-instance.json",
                         "homelab/instance/reservation.yaml"):
            with self.subTest(relative=relative):
                path = self.repository / relative
                self.write(path, json.dumps({"source": str(self.bundle)}).encode())
                self.refused()
                path.unlink()

    def test_invalid_or_symlinked_reference_inventory_refused(self):
        path = self.repository / "homelab/instance/reservation.json"
        path.parent.mkdir(parents=True)
        path.symlink_to(self.root / "absent")
        self.refused()

    def test_malformed_or_escaped_json_reference_refused(self):
        path = self.repository / "homelab/instance/reservation.json"
        for data in (b"{invalid", json.dumps({"bundle": str(self.bundle)}).replace("run-", "\\u0072un-").encode()):
            with self.subTest(data=data):
                self.write(path, data)
                self.refused()

    def test_duplicate_json_keys_cannot_hide_an_escaped_reference(self):
        escaped = json.dumps(str(self.bundle)).replace("run-", "\\u0072un-")
        raw = ('{"source":' + escaped + ',"source":"unrelated"}\n').encode()
        self.assertNotIn(self.bundle.name.encode(), raw)
        for suffix in (".json", ".jsonl"):
            with self.subTest(suffix=suffix):
                path = self.repository / "homelab/instance" / ("reservation" + suffix)
                self.write(path, raw)
                with self.assertRaisesRegex(tool.Refused, "duplicate JSON field"):
                    self.apply()
                self.assertTrue((self.bundle / tool.ISO).exists())
                self.assertFalse(self.receipt.exists())
                path.unlink()

    def test_iso_symlink_hardlink_fifo_public_mode_refused(self):
        iso = self.bundle / tool.ISO
        original = iso.read_bytes()
        iso.chmod(0o644)
        self.refused()
        iso.chmod(0o600)
        alias = self.root / "alias"
        os.link(iso, alias)
        self.refused()
        alias.unlink()
        iso.unlink()
        self.write(alias, original)
        iso.symlink_to(alias)
        self.refused()
        iso.unlink()
        os.mkfifo(iso, 0o600)
        self.refused()

    def test_missing_or_nonregular_result_refused(self):
        result = self.bundle / "evidence/result.json"
        result.unlink()
        self.refused()
        os.mkfifo(result, 0o600)
        self.refused()

    def test_nondefault_and_symlinked_bundle_refused(self):
        alias = self.root / "alias"
        alias.symlink_to(self.bundle, target_is_directory=True)
        self.refused([alias])
        moved = self.root / self.bundle.name
        self.bundle.rename(moved)
        self.refused([moved])

    def test_duplicate_bundle_refused(self):
        self.refused([self.bundle, self.bundle])

    def test_live_qemu_or_prepare_process_refused(self):
        process = self.proc / "123456789"
        process.mkdir()
        for command in (b"qemu-system-x86_64\0-drive\0x", b"python3\0-m\0homelab.vm.windows_install_prepare\0",
                        b"make\0homelab-windows-install-run\0", b"qemu-img\0check\0x",
                        b"python3\0homelab/vm/factory_repeat.py\0",
                        b"python3\0/synthetic/repo/homelab/vm/windows_identity_prepare.py\0"):
            with self.subTest(command=command):
                (process / "cmdline").write_bytes(command)
                self.refused()

    def test_held_or_missing_simulation_lock_refused(self):
        lock = self.repository / tool.LOCK
        with lock.open("rb") as stream:
            fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
            self.refused()
        lock.unlink()
        self.refused()

    def test_existing_public_or_in_runtime_receipt_refused(self):
        self.write(self.receipt, b"original receipt\n")
        self.refused()
        self.assertEqual(b"original receipt\n", self.receipt.read_bytes())
        self.receipt.unlink()
        self.receipts.chmod(0o755)
        self.refused()
        self.receipts.chmod(0o700)
        self.receipt = self.bundle / "retirement.jsonl"
        self.refused()

    def test_apply_requires_explicit_paths_and_receipt(self):
        for bundles, receipt in (([], self.receipt), ([self.bundle], None)):
            with self.assertRaises(tool.Refused):
                tool.run(bundles, apply=True, receipt=receipt, repository=self.repository, proc=self.proc)
        self.assertTrue((self.bundle / tool.ISO).exists())

    def test_same_size_iso_mutation_after_plan_refused_and_prepared_receipt_kept(self):
        real = tool.references
        calls = 0
        def references(*args):
            nonlocal calls
            calls += 1
            if calls == 2:
                iso = self.bundle / tool.ISO
                self.write(iso, b"x" * iso.stat().st_size)
            return real(*args)
        with mock.patch.object(tool, "references", side_effect=references):
            self.refused()
        self.assertEqual(["prepared"], [json.loads(x)["status"] for x in self.receipt.read_text().splitlines()])

    def test_result_mutation_after_plan_refused(self):
        real = tool.references
        calls = 0
        def references(*args):
            nonlocal calls
            calls += 1
            if calls == 2:
                path = self.bundle / "evidence/result.json"
                value = json.loads(path.read_bytes())
                value["status"] = "observed"
                self.write(path, json.dumps(value).encode())
            return real(*args)
        with mock.patch.object(tool, "references", side_effect=references):
            self.refused()

    def test_new_reference_after_plan_refused(self):
        real = tool.references
        calls = 0
        def references(*args):
            nonlocal calls
            calls += 1
            if calls == 2:
                self.write(self.repository / "homelab/instance/keeper.json", self.bundle.name.encode())
            return real(*args)
        with mock.patch.object(tool, "references", side_effect=references):
            self.refused()

    def test_later_mutation_preserves_partial_completion_audit(self):
        second = self.make_bundle(2)
        real = tool.references
        calls = 0
        def references(*args):
            nonlocal calls
            calls += 1
            if calls == 3:
                self.write(second / tool.ISO, b"changed")
            return real(*args)
        with mock.patch.object(tool, "references", side_effect=references):
            with self.assertRaises(tool.Refused):
                self.apply([self.bundle, second])
        self.assertFalse((self.bundle / tool.ISO).exists())
        self.assertTrue((second / tool.ISO).exists())
        events = [json.loads(x) for x in self.receipt.read_text().splitlines()]
        self.assertEqual(["prepared", "retired"], [e["status"] for e in events])

    def test_last_moment_path_replacement_refused(self):
        real = tool.inspect_bundle
        calls = 0
        @contextmanager
        def inspect(*args):
            nonlocal calls
            calls += 1
            with real(*args) as result:
                if calls == 2:
                    iso = self.bundle / tool.ISO
                    iso.rename(self.root / "original.iso")
                    self.write(iso, b"replacement")
                yield result
        with mock.patch.object(tool, "inspect_bundle", side_effect=inspect):
            self.refused()

    def test_last_moment_hardlink_refused(self):
        real = tool.inspect_bundle
        calls = 0
        @contextmanager
        def inspect(*args):
            nonlocal calls
            calls += 1
            with real(*args) as result:
                if calls == 2:
                    os.link(self.bundle / tool.ISO, self.root / "late-link")
                yield result
        with mock.patch.object(tool, "inspect_bundle", side_effect=inspect):
            self.refused()

    def test_identity_prepared_while_hashing_refused(self):
        real = tool.inspect_bundle
        calls = 0
        @contextmanager
        def inspect(*args):
            nonlocal calls
            calls += 1
            with real(*args) as result:
                if calls == 2:
                    (self.bundle / "identity").mkdir(mode=0o700)
                yield result
        with mock.patch.object(tool, "inspect_bundle", side_effect=inspect):
            self.refused()

    def test_evidence_and_preserved_files_changed_during_final_hash_refused(self):
        real = tool.inspect_bundle
        for name in ("evidence/workstation-serial.log", "authorization.json", "qemu-command.json",
                     "windows.qcow2", "OVMF_VARS.fd"):
            with self.subTest(name=name):
                path = self.bundle / name
                original = path.read_bytes()
                calls = 0
                @contextmanager
                def inspect(*args):
                    nonlocal calls
                    calls += 1
                    with real(*args) as result:
                        if calls == 2:
                            # Same-length replacement after inspection's
                            # final ISO hash, before the actual unlink.
                            self.write(path, b"x" * len(original))
                        yield result
                with mock.patch.object(tool, "inspect_bundle", side_effect=inspect):
                    with self.assertRaisesRegex(tool.Refused, "changed while hashing publication"):
                        self.apply()
                self.assertTrue((self.bundle / tool.ISO).exists())
                events = [json.loads(line) for line in self.receipt.read_text().splitlines()]
                self.assertEqual(["prepared"], [event["status"] for event in events])
                self.receipt.unlink()
                self.write(path, original)


if __name__ == "__main__":
    unittest.main()
