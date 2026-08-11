"""Prove gate-8 prepare is fail-closed, read-only, and consumer-exact.

These tests never boot QEMU.  They build a synthetic passing gate-7 install
bundle (real qcow2 files via qemu-img, the recorded pass-shape result, and a
serial transcript), run ``arch_identity_prepare.prepare``, and prove:

* a failed, missing, or malformed gate-7 result is refused;
* the produced authorization round-trips through the *consumer's* own
  fail-closed validation (``ArchIdentityBundle``);
* the produced overlay backs the gate-7 disk and the install bundle is
  byte-for-byte untouched;
* Windows lifecycle evidence is extracted verbatim, in contract order,
  fail-closed;
* the gate-7 join-marker seam is lenient today and trips the moment the
  parallel gate-7 join lane lands a marker.
"""

import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
import unittest

from homelab.vm import arch_identity_prepare as prepare_module
from homelab.vm.arch_identity_prepare import (
    ARCH_JOIN_MARKER,
    ArchIdentityPrepareError,
    inspect_install_bundle,
    load_windows_lifecycle_evidence,
    prepare,
)
from homelab.vm.arch_identity_run import (
    ArchIdentityBundle,
    WINDOWS_CHECKS,
)
from homelab.tests.test_arch_identity_run import passing_windows_events
from homelab.workstations import arch_second


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def make_install_bundle(
    root: Path,
    *,
    status: str = "observed",
    phase: str = "arch-installed-windows-preserved",
    windows_preserved: bool = True,
    with_result: bool = True,
    with_disk: bool = True,
    with_serial: bool = True,
    join_marker: bool = True,
) -> Path:
    """A synthetic passing gate-7 run directory with a real qcow2 chain."""
    base = root / "windows.qcow2"
    subprocess.run(
        ["qemu-img", "create", "-f", "qcow2", str(base), "1M"],
        check=True, capture_output=True)
    base.chmod(0o600)
    bundle = root / "install-run"
    bundle.mkdir(mode=0o700)
    if with_disk:
        disk = bundle / "arch.qcow2"
        subprocess.run(
            ["qemu-img", "create", "-f", "qcow2", "-F", "qcow2",
             "-b", str(base.resolve()), str(disk)],
            check=True, capture_output=True)
        disk.chmod(0o600)
    evidence = bundle / "evidence"
    evidence.mkdir(mode=0o700)
    if with_result:
        result = {
            "schema": 1,
            "status": status,
            "phase": phase,
            "windows_preserved": windows_preserved,
            "pxe_firmware_boots": 1,
            "release_version": "2026.08.01",
        }
        path = evidence / "result.json"
        path.write_text(
            json.dumps(result, indent=2, sort_keys=True) + "\n",
            encoding="utf-8")
        path.chmod(0o600)
    if with_serial:
        lines = [
            "TELOS ARCH INSTALL BEGIN",
            "Arch installed; Windows partitions and filesystems were "
            "not modified.",
            "TELOS ARCH INSTALL COMPLETE",
        ]
        if join_marker:
            lines.append(ARCH_JOIN_MARKER)
        serial = evidence / "workstation-serial.log"
        serial.write_text("\n".join(lines) + "\n", encoding="utf-8")
        serial.chmod(0o600)
    return bundle


def write_windows_evidence(path: Path, events=None) -> Path:
    if events is None:
        events = passing_windows_events()
    path.write_text(
        "".join(json.dumps(item, sort_keys=True) + "\n" for item in events),
        encoding="utf-8")
    path.chmod(0o600)
    return path


def make_vars_template(root: Path) -> Path:
    template = root / "pristine-OVMF_VARS.fd"
    template.write_bytes(b"pristine-ovmf-variables-template")
    template.chmod(0o600)
    return template


class InstallBundleValidationTests(unittest.TestCase):
    def _refused(self, message: str, **kwargs) -> None:
        with tempfile.TemporaryDirectory() as name:
            bundle = make_install_bundle(Path(name), **kwargs)
            with self.assertRaisesRegex(ArchIdentityPrepareError, message):
                inspect_install_bundle(bundle)

    def test_missing_result_is_refused(self):
        self._refused("execution result", with_result=False)

    def test_failed_status_is_refused(self):
        self._refused("status", status="fail")

    def test_wrong_phase_is_refused(self):
        self._refused("phase", phase="arch-install-driving")

    def test_unpreserved_windows_is_refused(self):
        self._refused("preservation", windows_preserved=False)

    def test_missing_disk_is_refused(self):
        self._refused("installed Arch disk", with_disk=False)

    def test_missing_serial_transcript_is_refused(self):
        self._refused("serial transcript", with_serial=False)

    def test_group_readable_bundle_is_refused(self):
        with tempfile.TemporaryDirectory() as name:
            bundle = make_install_bundle(Path(name))
            bundle.chmod(0o750)
            with self.assertRaisesRegex(ArchIdentityPrepareError, "private"):
                inspect_install_bundle(bundle)

    def test_missing_bundle_is_refused(self):
        with tempfile.TemporaryDirectory() as name:
            with self.assertRaisesRegex(ArchIdentityPrepareError, "missing"):
                inspect_install_bundle(Path(name) / "absent")

    def test_unjoined_transcript_is_refused(self):
        # A gate-7 transcript without the verified join marker belongs to an
        # unjoined disk; gate 8 must never accept it.
        self._refused("join marker", join_marker=False)

    def test_joined_transcript_is_recorded(self):
        with tempfile.TemporaryDirectory() as name:
            bundle = make_install_bundle(Path(name), join_marker=True)
            source = inspect_install_bundle(bundle)
            self.assertTrue(source["join_marker_observed"])


class WindowsEvidenceExtractionTests(unittest.TestCase):
    def test_extraction_is_ordered_and_verbatim(self):
        events = passing_windows_events()
        # Real acceptance streams carry an envelope and non-lifecycle
        # checks; both must survive/filter respectively.
        for sequence, item in enumerate(events, 1):
            item["sequence"] = sequence
            item["observed_at"] = "2026-08-10T00:00:00Z"
        extras = [
            {"check": "windows-rebooted-joined", "result": "pass",
             "external_access": False, "native_boot": True},
            {"check": "controller-ready", "result": "pass",
             "external_access": False},
        ]
        shuffled = extras + list(reversed(events))
        with tempfile.TemporaryDirectory() as name:
            source = write_windows_evidence(
                Path(name) / "acceptance.jsonl", shuffled)
            extracted = load_windows_lifecycle_evidence(source)
        self.assertEqual(
            [item["check"] for item in extracted], list(WINDOWS_CHECKS))
        by_check = {item["check"]: item for item in events}
        for item in extracted:
            self.assertEqual(item, by_check[item["check"]])

    def test_missing_check_is_refused(self):
        with tempfile.TemporaryDirectory() as name:
            source = write_windows_evidence(
                Path(name) / "acceptance.jsonl",
                passing_windows_events()[:-1])
            with self.assertRaisesRegex(
                    ArchIdentityPrepareError, "missing"):
                load_windows_lifecycle_evidence(source)

    def test_failing_check_is_refused(self):
        events = passing_windows_events()
        events[2]["result"] = "fail"
        with tempfile.TemporaryDirectory() as name:
            source = write_windows_evidence(
                Path(name) / "acceptance.jsonl", events)
            with self.assertRaisesRegex(
                    ArchIdentityPrepareError, "did not pass"):
                load_windows_lifecycle_evidence(source)

    def test_missing_file_is_refused(self):
        with tempfile.TemporaryDirectory() as name:
            with self.assertRaisesRegex(
                    ArchIdentityPrepareError, "regular"):
                load_windows_lifecycle_evidence(Path(name) / "absent.jsonl")


class PrepareTests(unittest.TestCase):
    def _prepare(self, root: Path, **bundle_kwargs):
        install = make_install_bundle(root, **bundle_kwargs)
        evidence = write_windows_evidence(root / "windows-acceptance.jsonl")
        template = make_vars_template(root)
        run = prepare(
            install, evidence,
            run_root=root / "identity-runs",
            ovmf_vars=template)
        return install, evidence, template, run

    def test_prepared_bundle_round_trips_the_consumer_contract(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            install, evidence, template, run = self._prepare(root)
            controller = root / "controller"
            controller.mkdir(mode=0o700)
            bundle = ArchIdentityBundle(run, controller)
            bundle.validate()
            self.assertEqual(bundle.realm, prepare_module.DEFAULT_REALM)
            self.assertEqual(
                [item["check"] for item in bundle.read_windows_evidence()],
                list(WINDOWS_CHECKS))
            authorization = json.loads(
                (run / "authorization.json").read_text(encoding="utf-8"))
            self.assertEqual(authorization["status"], "prepared")
            self.assertFalse(authorization["external_access"])
            self.assertFalse(authorization["installation_media_attached"])
            self.assertFalse(authorization["pxe_boot_enabled"])
            self.assertTrue(authorization["domain_joined"])
            self.assertTrue(authorization["join_marker_observed"])
            self.assertEqual(
                authorization["firmware_copy"]["policy"],
                "pristine-esp-auto-discovery")
            self.assertEqual(
                (run / "OVMF_VARS.fd").read_bytes(), template.read_bytes())
            self.assertEqual(run.stat().st_mode & 0o777, 0o700)
            for artifact in ("arch-workstation.qcow2", "OVMF_VARS.fd",
                             "authorization.json", "windows-evidence.jsonl"):
                self.assertEqual(
                    (run / artifact).stat().st_mode & 0o777, 0o600, artifact)

    def test_overlay_backs_the_gate7_disk(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            install, _evidence, _template, run = self._prepare(root)
            info = json.loads(subprocess.run(
                ["qemu-img", "info", "--output=json",
                 str(run / "arch-workstation.qcow2")],
                check=True, capture_output=True, text=True).stdout)
            backing = info.get(
                "full-backing-filename") or info.get("backing-filename")
            self.assertEqual(
                str(Path(backing).resolve()),
                str((install / "arch.qcow2").resolve()))

    def test_prepare_never_mutates_the_install_bundle(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            install = make_install_bundle(root)
            before = {
                str(path): (_sha256(path), path.stat().st_mtime_ns)
                for path in sorted(install.rglob("*")) if path.is_file()
            }
            evidence = write_windows_evidence(
                root / "windows-acceptance.jsonl")
            template = make_vars_template(root)
            prepare(
                install, evidence,
                run_root=root / "identity-runs", ovmf_vars=template)
            after = {
                str(path): (_sha256(path), path.stat().st_mtime_ns)
                for path in sorted(install.rglob("*")) if path.is_file()
            }
            self.assertEqual(before, after)

    def test_windows_evidence_file_is_copied_verbatim_in_order(self):
        events = passing_windows_events()
        events[0]["observed_at"] = "2026-08-10T00:00:00Z"
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            install = make_install_bundle(root)
            evidence = write_windows_evidence(
                root / "windows-acceptance.jsonl", list(reversed(events)))
            run = prepare(
                install, evidence,
                run_root=root / "identity-runs",
                ovmf_vars=make_vars_template(root))
            produced = [
                json.loads(line)
                for line in (run / "windows-evidence.jsonl").read_text(
                    encoding="utf-8").splitlines()
            ]
            self.assertEqual(produced, events)

    def test_unjoined_bundle_is_refused_by_prepare(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            install = make_install_bundle(root, join_marker=False)
            evidence = write_windows_evidence(
                root / "windows-acceptance.jsonl")
            with self.assertRaisesRegex(
                    ArchIdentityPrepareError, "join marker"):
                prepare(
                    install, evidence,
                    run_root=root / "identity-runs",
                    ovmf_vars=make_vars_template(root))
            self.assertFalse((root / "identity-runs").exists())

    def test_join_marker_is_pinned_to_the_gate7_renderer(self):
        # The seam is the gate-7 installer renderer's own verified-join
        # marker: the installer prints it only after net ads join succeeded
        # and net ads testjoin verified the secure channel.
        self.assertEqual(ARCH_JOIN_MARKER, arch_second.JOIN_VERIFIED_MARKER)
        self.assertIn(
            arch_second.JOIN_VERIFIED_MARKER,
            arch_second.render_installer(
                disk_path="/dev/vda",
                disk_serial="TELOS-WIN-0001",
                hostname="telos-workstation",
                expected_sizes_mib=(260, 16, 200000, 40000, 1000),
            ))

    def test_failed_gate7_result_is_refused_by_prepare(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            install = make_install_bundle(root, status="fail")
            evidence = write_windows_evidence(
                root / "windows-acceptance.jsonl")
            with self.assertRaisesRegex(ArchIdentityPrepareError, "status"):
                prepare(
                    install, evidence,
                    run_root=root / "identity-runs",
                    ovmf_vars=make_vars_template(root))
            self.assertFalse((root / "identity-runs").exists())

    def test_failed_prepare_leaves_no_partial_bundle(self):
        events = passing_windows_events()[:-1]  # incomplete peer evidence
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            install = make_install_bundle(root)
            evidence = write_windows_evidence(
                root / "windows-acceptance.jsonl", events)
            with self.assertRaises(ArchIdentityPrepareError):
                prepare(
                    install, evidence,
                    run_root=root / "identity-runs",
                    ovmf_vars=make_vars_template(root))
            runs = root / "identity-runs"
            self.assertFalse(runs.exists() and any(runs.iterdir()))

    def test_empty_realm_is_refused(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            install = make_install_bundle(root)
            evidence = write_windows_evidence(
                root / "windows-acceptance.jsonl")
            with self.assertRaisesRegex(ArchIdentityPrepareError, "realm"):
                prepare(
                    install, evidence,
                    run_root=root / "identity-runs",
                    realm="",
                    ovmf_vars=make_vars_template(root))


class CliTests(unittest.TestCase):
    def test_dry_run_creates_nothing(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            install = make_install_bundle(root)
            evidence = write_windows_evidence(
                root / "windows-acceptance.jsonl")
            code = prepare_module.main([
                "--install-bundle", str(install),
                "--windows-evidence", str(evidence),
                "--run-root", str(root / "identity-runs"),
            ])
            self.assertEqual(code, 0)
            self.assertFalse((root / "identity-runs").exists())

    def test_apply_failure_returns_nonzero(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            install = make_install_bundle(root, status="fail")
            evidence = write_windows_evidence(
                root / "windows-acceptance.jsonl")
            code = prepare_module.main([
                "--install-bundle", str(install),
                "--windows-evidence", str(evidence),
                "--run-root", str(root / "identity-runs"),
                "--ovmf-vars", str(make_vars_template(root)),
                "--apply",
            ])
            self.assertEqual(code, 2)


if __name__ == "__main__":
    unittest.main()
