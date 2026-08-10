"""Tests for the gate-12 acceptance verifier and two-run comparator.

The verifier is pure and read-only: these tests fabricate retained evidence
directories and a real ``pxe_release_set`` release set, and never boot a
guest, touch the network, or require privilege.
"""

import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "lib"))
sys.path.insert(0, str(ROOT / "vm"))

import pxe_release  # noqa: E402
import pxe_release_set  # noqa: E402
import factory_verify  # noqa: E402


GATEWAY_MAC = "52:54:00:31:11:01"

GOOD_MEASUREMENTS = {
    "controller_disk_unchanged": True,
    "firmware_vars_unchanged": True,
    "guest_disks": [
        {"name": "workstation.qcow2", "disposable": True,
         "run_scoped": True, "run": "run-1"},
    ],
    "host_network_changes": {
        "tap": 0, "bridge": 0, "route": 0, "vlan": 0,
        "forwarding": 0, "listener": 0, "unifi": 0,
    },
    "external_connections_after_offline_gate": 0,
    "install_order": ["windows", "arch-workstation"],
    "default_boot": "windows",
    "login": {
        "windows": {"online": True, "offline_cached": True},
        "arch": {"online": True, "offline_cached": True},
    },
    "optional_storage_absence_nonblocking": True,
    "artifact_scan": {"media": 0, "credentials": 0, "private": 0, "oversized": 0},
}

GOOD_SWITCH = "\n".join(
    json.dumps(event) for event in (
        {"event": "dhcp", "kind": "OFFER", "peer": "gateway",
         "source_mac": GATEWAY_MAC},
        {"event": "dhcp", "kind": "ACK", "peer": "gateway",
         "source_mac": GATEWAY_MAC},
    )
) + "\n"


class VerifyRunTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)

    def evidence(self, name="20260810T000000Z-1234-pxe-handoff", *,
                 status="pass", measurements=GOOD_MEASUREMENTS,
                 switch=GOOD_SWITCH, logs=True, extra=None,
                 result_override=None):
        directory = self.root / name
        directory.mkdir()
        result = {"schema": 1, "status": status, "retained": []}
        if measurements is not None:
            result["measurements"] = measurements
        if result_override is not None:
            result = result_override
        (directory / "result.json").write_text(
            json.dumps(result), encoding="utf-8")
        if switch is not None:
            (directory / "switch.jsonl").write_text(switch, encoding="utf-8")
        if logs:
            (directory / "controller-publication.log").write_text(
                "TELOS PXE SERVICES READY\npassword=[REDACTED]\n",
                encoding="utf-8")
            (directory / "workstation-serial.log").write_text(
                "Welcome to Arch Linux\n", encoding="utf-8")
        if extra:
            for filename, content in extra.items():
                (directory / filename).write_bytes(content)
        return directory

    def release_set(self, *, tamper=False):
        seal = self.root / "seal.json"
        seal_value = {
            "schema": 1,
            "content": [
                {"name": "arch-iso", "sha256": "a" * 64},
                {"name": "windows-iso", "sha256": "b" * 64},
                {"name": "wimboot", "sha256": "c" * 64},
                {
                    "name": "windows-install-source",
                    "source_iso_sha256": "b" * 64,
                    "receipt_sha256": "d" * 64,
                    "bytes": 8_000_000_000,
                    "file_count": 976,
                },
            ],
        }
        seal.write_text(json.dumps(seal_value), encoding="utf-8")
        releases = self.root / "releases"
        version = "20260810.001"

        def stage(build_root):
            leaves = {}
            for target in pxe_release_set.TARGETS:
                source = build_root / "sources" / target
                source.mkdir(parents=True)
                (source / "boot.ipxe").write_text("#!ipxe\n", encoding="utf-8")
                (source / "target.json").write_text(json.dumps({
                    "schema": 1, "id": target, "entrypoints": ["boot.ipxe"],
                }), encoding="utf-8")
                leaves[target] = pxe_release.stage(
                    source, build_root / "releases", version=version)
            return leaves

        built = pxe_release_set.build(
            releases, version, seal, seal_value, stage)
        if tamper:
            (built / "targets" / "controller" / version / "boot.ipxe").write_text(
                "tampered\n", encoding="utf-8")
        return built

    # -- happy path -------------------------------------------------------

    def test_good_run_with_valid_release_set_is_pass(self):
        receipt = factory_verify.verify_run(
            self.evidence(), release_set=self.release_set())
        self.assertEqual("PASS", receipt["verdict"])
        self.assertEqual(0, receipt["summary"]["fail"])
        self.assertEqual(0, receipt["summary"]["not_run"])
        self.assertEqual([], receipt["needs_live_gate"])
        for name, check in receipt["checks"].items():
            self.assertEqual("PASS", check["status"], name)
        self.assertIn("release_set", receipt)

    # -- NOT-RUN is never a PASS ------------------------------------------

    def test_missing_measurement_is_not_run_not_pass(self):
        measurements = dict(GOOD_MEASUREMENTS)
        del measurements["guest_disks"]
        del measurements["default_boot"]
        receipt = factory_verify.verify_run(
            self.evidence(measurements=measurements),
            release_set=self.release_set())
        self.assertNotEqual("PASS", receipt["verdict"])
        self.assertEqual("NOT-RUN", receipt["verdict"])
        self.assertEqual(
            "NOT-RUN",
            receipt["checks"]["guest_disks_disposable_run_scoped"]["status"])
        self.assertEqual(
            "NOT-RUN", receipt["checks"]["windows_default_boot"]["status"])
        # A NOT-RUN measurement must never be reported as passing.
        self.assertEqual(0, receipt["summary"]["fail"])
        self.assertIn(
            "guest_disks_disposable_run_scoped", receipt["needs_live_gate"])

    def test_no_release_set_leaves_integrity_not_run(self):
        receipt = factory_verify.verify_run(self.evidence())
        self.assertEqual(
            "NOT-RUN", receipt["checks"]["release_set_integrity"]["status"])
        self.assertNotEqual("PASS", receipt["verdict"])
        self.assertNotIn("release_set", receipt)

    # -- FAIL closed ------------------------------------------------------

    def test_tampered_release_set_is_fail(self):
        receipt = factory_verify.verify_run(
            self.evidence(), release_set=self.release_set(tamper=True))
        self.assertEqual(
            "FAIL", receipt["checks"]["release_set_integrity"]["status"])
        self.assertEqual("FAIL", receipt["verdict"])

    def test_unreadable_evidence_is_fail(self):
        receipt = factory_verify.verify_run(self.root / "does-not-exist")
        self.assertEqual("FAIL", receipt["verdict"])
        self.assertEqual("FAIL", receipt["checks"]["evidence_readable"]["status"])
        # Nothing else may claim a pass on unreadable evidence.
        self.assertEqual(0, receipt["summary"]["pass"])

    def test_missing_result_json_is_fail(self):
        directory = self.root / "no-result"
        directory.mkdir()
        (directory / "switch.jsonl").write_text(GOOD_SWITCH, encoding="utf-8")
        receipt = factory_verify.verify_run(directory)
        self.assertEqual("FAIL", receipt["verdict"])

    def test_fail_status_is_fail(self):
        receipt = factory_verify.verify_run(self.evidence(status="fail"))
        self.assertEqual("FAIL", receipt["checks"]["run_status_pass"]["status"])
        self.assertEqual("FAIL", receipt["verdict"])

    def test_unexpected_file_is_fail(self):
        directory = self.evidence(extra={"secret.bin": b"payload"})
        receipt = factory_verify.verify_run(directory)
        self.assertEqual(
            "FAIL", receipt["checks"]["evidence_contents_expected"]["status"])
        self.assertEqual("FAIL", receipt["verdict"])

    def test_oversized_evidence_is_fail(self):
        big = b"x" * (factory_verify.EVIDENCE_LIMIT + 1)
        directory = self.evidence()
        (directory / "workstation-serial.log").write_bytes(big)
        receipt = factory_verify.verify_run(directory)
        self.assertEqual(
            "FAIL", receipt["checks"]["evidence_within_size_limit"]["status"])
        self.assertEqual("FAIL", receipt["verdict"])

    def test_credential_leak_is_fail(self):
        directory = self.evidence()
        (directory / "controller-publication.log").write_text(
            "password: hunter2\n", encoding="utf-8")
        receipt = factory_verify.verify_run(directory)
        check = receipt["checks"]["no_secret_material_in_evidence"]
        self.assertEqual("FAIL", check["status"])
        # The receipt must not echo the secret it detected.
        self.assertNotIn("hunter2", json.dumps(receipt))
        self.assertEqual("FAIL", receipt["verdict"])

    def test_rogue_dhcp_authority_is_fail(self):
        switch = GOOD_SWITCH + json.dumps({
            "event": "dhcp", "kind": "OFFER", "peer": "gateway",
            "source_mac": "52:54:00:99:99:99",
        }) + "\n"
        receipt = factory_verify.verify_run(self.evidence(switch=switch))
        self.assertEqual(
            "FAIL", receipt["checks"]["single_dhcp_authority"]["status"])
        self.assertEqual("FAIL", receipt["verdict"])

    def test_missing_switch_evidence_is_not_run(self):
        receipt = factory_verify.verify_run(self.evidence(switch=None))
        self.assertEqual(
            "NOT-RUN", receipt["checks"]["single_dhcp_authority"]["status"])

    def test_arch_before_windows_is_fail(self):
        measurements = dict(GOOD_MEASUREMENTS)
        measurements["install_order"] = ["arch-workstation", "windows"]
        receipt = factory_verify.verify_run(self.evidence(measurements=measurements))
        self.assertEqual(
            "FAIL", receipt["checks"]["windows_installed_before_arch"]["status"])

    def test_host_network_change_is_fail(self):
        measurements = dict(GOOD_MEASUREMENTS)
        measurements["host_network_changes"] = dict(
            GOOD_MEASUREMENTS["host_network_changes"], tap=1)
        receipt = factory_verify.verify_run(self.evidence(measurements=measurements))
        self.assertEqual(
            "FAIL", receipt["checks"]["no_host_network_change"]["status"])


class CompareRunsTests(unittest.TestCase):
    def receipt(self, *, evidence="run-a", version="20260810.001",
                media_seal="e" * 64, verdict="PASS"):
        return {
            "schema": 1,
            "kind": "factory-verify-run",
            "evidence": evidence,
            "verdict": verdict,
            "checks": {"run_status_pass": {"status": verdict, "detail": "x"}},
            "release_set": {
                "version": version,
                "media_seal_sha256": media_seal,
                "manifest_sha256": "f" * 64,
            },
        }

    def test_identical_receipts_are_equivalent(self):
        receipt = self.receipt()
        comparison = factory_verify.compare_runs(receipt, dict(receipt))
        self.assertTrue(comparison["equivalent"])
        self.assertEqual(0, comparison["divergent_count"])
        self.assertEqual([], comparison["differences"])

    def test_content_equivalent_pair_is_equivalent(self):
        a = self.receipt(evidence="run-a", version="20260810.001")
        b = self.receipt(evidence="run-b", version="20260810.002")
        comparison = factory_verify.compare_runs(a, b)
        self.assertTrue(comparison["equivalent"])
        self.assertEqual(0, comparison["divergent_count"])
        self.assertGreater(comparison["content_equivalent_count"], 0)
        for difference in comparison["differences"]:
            self.assertEqual("content-equivalent", difference["classification"])

    def test_divergent_verdict_is_divergent(self):
        a = self.receipt(verdict="PASS")
        b = self.receipt(verdict="FAIL")
        comparison = factory_verify.compare_runs(a, b)
        self.assertFalse(comparison["equivalent"])
        self.assertGreater(comparison["divergent_count"], 0)
        paths = {d["path"] for d in comparison["differences"]
                 if d["classification"] == "divergent"}
        self.assertIn("verdict", paths)

    def test_media_seal_divergence_is_divergent(self):
        a = self.receipt(media_seal="1" * 64)
        b = self.receipt(media_seal="2" * 64)
        comparison = factory_verify.compare_runs(a, b)
        self.assertFalse(comparison["equivalent"])
        divergent = [d for d in comparison["differences"]
                     if d["classification"] == "divergent"]
        self.assertTrue(
            any(d["path"].endswith("media_seal_sha256") for d in divergent))

    def test_manifest_digest_content_equivalent_when_version_differs(self):
        a = self.receipt(version="20260810.001")
        b = self.receipt(version="20260810.002")
        # Force the derived manifest digest to differ with the version.
        b["release_set"]["manifest_sha256"] = "9" * 64
        comparison = factory_verify.compare_runs(a, b)
        self.assertTrue(comparison["equivalent"])


if __name__ == "__main__":
    unittest.main()
