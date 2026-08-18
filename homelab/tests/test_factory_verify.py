"""Tests for the gate-12 acceptance verifier and two-run comparator.

The verifier is pure and read-only: these tests fabricate retained evidence
directories and a real ``pxe_release_set`` release set, and never boot a
guest, touch the network, or require privilege.
"""

import io
import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REPOSITORY = ROOT.parent
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
                 result_override=None, subdirectories=None):
        directory = self.root / name
        directory.mkdir()
        # A real run bundle keeps working trees beside the retained logs; the
        # mapping's values are the files staged inside each one.
        for subdirectory, contents in (subdirectories or {}).items():
            staged = directory / subdirectory
            staged.mkdir(parents=True)
            for filename, content in (contents or {}).items():
                (staged / filename).write_bytes(content)
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
        # An aggregate whole-factory claim is named as such in the receipt.
        self.assertEqual(
            {"status": "pass", "scope": "aggregate"}, receipt["run_status"])
        self.assertIn(
            "aggregate", receipt["checks"]["run_status_pass"]["detail"])

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
        # A failing run has no pass vocabulary, and the receipt says so rather
        # than leaving the reader to guess which kind of run it read.
        self.assertEqual(
            {"status": "fail", "scope": None}, receipt["run_status"])

    # -- the two pass vocabularies stay distinguishable --------------------

    def test_observed_phase_status_passes_and_is_named_a_phase_claim(self):
        # Every phase runner records "observed" (arch_install_run,
        # windows_install_run, dualboot_acceptance, lifecycle_recovery, and
        # arch_identity_prepare.PASS_STATUS).  Refusing it made every real
        # phase bundle FAIL on vocabulary alone, which measured nothing.
        receipt = factory_verify.verify_run(
            self.evidence(status="observed"), release_set=self.release_set())
        check = receipt["checks"]["run_status_pass"]
        self.assertEqual("PASS", check["status"])
        self.assertIn("phase", check["detail"])
        self.assertIn("observed", check["detail"])
        # Recognised, never flattened: the receipt still distinguishes a phase
        # runner's narrower claim from an aggregate whole-factory pass.
        self.assertEqual(
            {"status": "observed", "scope": "phase"}, receipt["run_status"])
        self.assertNotIn("aggregate", check["detail"])

    def test_an_unrecognized_status_is_still_fail(self):
        for index, status in enumerate(("prepared", "partial", "", None)):
            with self.subTest(status=status):
                receipt = factory_verify.verify_run(
                    self.evidence(name=f"status-{index}", status=status))
                self.assertEqual(
                    "FAIL", receipt["checks"]["run_status_pass"]["status"])
                self.assertEqual("FAIL", receipt["verdict"])
                self.assertIsNone(receipt["run_status"]["scope"])

    def test_unexpected_file_is_fail(self):
        directory = self.evidence(extra={"secret.bin": b"payload"})
        receipt = factory_verify.verify_run(directory)
        self.assertEqual(
            "FAIL", receipt["checks"]["evidence_contents_expected"]["status"])
        self.assertEqual("FAIL", receipt["verdict"])

    # -- real bundle layout: working trees beside the retained artifacts ---

    # As produced under homelab/var/factory/arch-installs/run-*/evidence: the
    # four retained files plus a controller guard directory and a staged
    # publication tree whose sealed payload is far over the retention limit.
    REAL_BUNDLE_TREES = {
        "controller/guard": {},
        "publication": {
            "release-set.json": b"{}\n",
            "tftp-hpa-5.2-11-x86_64.pkg.tar.zst":
                b"x" * (factory_verify.EVIDENCE_LIMIT + 1),
        },
    }

    def test_real_run_bundle_working_trees_read_cleanly(self):
        receipt = factory_verify.verify_run(
            self.evidence(subdirectories=self.REAL_BUNDLE_TREES),
            release_set=self.release_set())
        self.assertEqual("PASS", receipt["verdict"])
        self.assertEqual(
            "PASS", receipt["checks"]["evidence_readable"]["status"])
        self.assertEqual(
            "PASS", receipt["checks"]["evidence_contents_expected"]["status"])
        # The limit governs retained artifacts, not a working tree's payload.
        self.assertEqual(
            "PASS", receipt["checks"]["evidence_within_size_limit"]["status"])
        # Accepted structurally, but named: nothing is silently ignored.
        self.assertEqual(
            ["controller", "publication"], receipt["evidence_subdirectories"])
        self.assertIn(
            "publication",
            receipt["checks"]["evidence_contents_expected"]["detail"])

    def test_unknown_file_beside_working_tree_is_still_fail(self):
        directory = self.evidence(
            subdirectories=self.REAL_BUNDLE_TREES,
            extra={"secret.bin": b"payload"})
        receipt = factory_verify.verify_run(directory)
        self.assertEqual(
            "FAIL", receipt["checks"]["evidence_contents_expected"]["status"])
        self.assertIn(
            "secret.bin",
            receipt["checks"]["evidence_contents_expected"]["detail"])
        self.assertEqual("FAIL", receipt["verdict"])

    def test_symlinked_evidence_entry_is_fail(self):
        directory = self.evidence(subdirectories=self.REAL_BUNDLE_TREES)
        (directory / "smuggled.log").symlink_to(directory / "switch.jsonl")
        receipt = factory_verify.verify_run(directory)
        # A symlink is neither a retained artifact nor a working tree.
        self.assertEqual("FAIL", receipt["verdict"])
        self.assertEqual(
            "FAIL", receipt["checks"]["evidence_readable"]["status"])
        self.assertEqual(0, receipt["summary"]["pass"])

    def test_fifo_evidence_entry_is_fail(self):
        directory = self.evidence()
        os.mkfifo(directory / "pipe")
        receipt = factory_verify.verify_run(directory)
        self.assertEqual("FAIL", receipt["verdict"])
        self.assertEqual(
            "FAIL", receipt["checks"]["evidence_readable"]["status"])

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

    def test_same_line_credential_shapes_are_all_still_detected(self):
        # Tightening the post-delimiter run must not cost any same-line
        # detection: these are the shapes a redaction miss actually produces.
        for index, line in enumerate((
            "password: hunter2",
            "password=hunter2",
            "PASSWORD:hunter2",
            "passphrase:\thunter2",
            "token = hunter2",
            "secret:hunter2",
            "[root@archiso ~]# echo password=hunter2",
        )):
            with self.subTest(line=line):
                directory = self.evidence(name=f"leak-{index}")
                (directory / "controller-publication.log").write_text(
                    line + "\n", encoding="utf-8")
                receipt = factory_verify.verify_run(directory)
                self.assertEqual(
                    "FAIL",
                    receipt["checks"]["no_secret_material_in_evidence"][
                        "status"],
                    line)
                self.assertNotIn("hunter2", json.dumps(receipt))

    def test_prompt_followed_by_a_next_line_token_is_not_a_leak(self):
        # The measured defect: with ``\\s*`` after the delimiter, a bare
        # ``Password:`` prompt paired with the FIRST TOKEN OF THE NEXT LINE.
        # On real arch-install evidence that flagged 12 of 23 retained bundles,
        # every one of the 18 matches crossing a line boundary onto a shell
        # integration escape marker or the next console prompt.
        for index, tail in enumerate((
            "\n\x1b]133;D;0\x07\n",
            "\n[root@archiso ~]# \n",
            "\r\n[root@archiso ~]# efibootmgr\n",
            " \r\n\r\n[root@archiso ~]# \n",
        )):
            with self.subTest(tail=tail):
                directory = self.evidence(name=f"prompt-{index}")
                (directory / "controller-publication.log").write_text(
                    "[root@archiso ~]# passwd\nPassword:" + tail,
                    encoding="utf-8")
                receipt = factory_verify.verify_run(directory)
                check = receipt["checks"]["no_secret_material_in_evidence"]
                self.assertEqual("PASS", check["status"], tail)

    def test_a_redacted_value_is_never_reported_as_a_leak(self):
        directory = self.evidence()
        (directory / "controller-publication.log").write_text(
            "password=[REDACTED]\nPassword:\n[root@archiso ~]# \n",
            encoding="utf-8")
        receipt = factory_verify.verify_run(directory)
        self.assertEqual(
            "PASS",
            receipt["checks"]["no_secret_material_in_evidence"]["status"])

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


class MeasurementProducerTests(VerifyRunTests):
    """Every real producer's block, judged by the checks that read it.

    Nothing outside these tests used to write a ``measurements`` block at all,
    which stranded nine of sixteen checks at NOT-RUN and made a PASS verdict
    unreachable no matter how many gates passed live.  These pin each producer
    to the fields it can honestly observe AND to the fields it must leave
    absent, so a later "helpful" addition that turns a NOT-RUN into a
    fabricated PASS fails here.
    """

    # Imported through the package so the producers reach their own siblings.
    def producers(self):
        from homelab.vm import (
            arch_install_run, dualboot_acceptance, factory_runner,
            windows_install_run)
        return {
            "factory_runner": factory_runner.acceptance_measurements(
                canonical_unchanged=True,
                guest_disks=[
                    factory_runner.guest_disk(
                        "controller.raw", disposable=True, run_scoped=True,
                        run="telos-factory-abc"),
                    factory_runner.guest_disk(
                        "workstation.qcow2", disposable=True, run_scoped=True,
                        run="telos-factory-abc"),
                ],
                loopback_only_audited=True),
            "windows_install_run": windows_install_run
            .acceptance_measurements(
                canonical_unchanged=True, loopback_only_audited=True,
                windows_installed=True),
            "arch_install_run": arch_install_run.acceptance_measurements(
                canonical_unchanged=True, loopback_only_audited=True,
                arch_installed=True),
            "dualboot_acceptance": dualboot_acceptance
            .acceptance_measurements(
                run="run-20260814T000000Z-abcdef",
                events=[{
                    "check": "windows-default-boot", "result": "pass",
                    "default_os": "windows"}]),
        }

    ALWAYS_ABSENT = (
        "both_os_online_and_cached_offline_login",
        "optional_storage_absence_nonblocking",
        "no_forbidden_artifact_content",
        # A before/after host-state delta no runner captures; its honest
        # producer is host_network_evidence.capture/compare_cycle.
        "no_host_network_change",
    )

    EXPECTED = {
        "factory_runner": {
            "controller_disk_and_firmware_unchanged": "PASS",
            "guest_disks_disposable_run_scoped": "PASS",
            "no_external_connection_after_offline_gate": "PASS",
            "windows_installed_before_arch": "NOT-RUN",
            "windows_default_boot": "NOT-RUN",
        },
        "windows_install_run": {
            "controller_disk_and_firmware_unchanged": "PASS",
            # Gate 5's windows.qcow2 is deliberately persistent.
            "guest_disks_disposable_run_scoped": "NOT-RUN",
            "no_external_connection_after_offline_gate": "PASS",
            # One run cannot order Windows against Arch.
            "windows_installed_before_arch": "NOT-RUN",
            "windows_default_boot": "NOT-RUN",
        },
        "arch_install_run": {
            "controller_disk_and_firmware_unchanged": "PASS",
            "guest_disks_disposable_run_scoped": "NOT-RUN",
            "no_external_connection_after_offline_gate": "PASS",
            "windows_installed_before_arch": "NOT-RUN",
            # The authored loader default is configuration; gate 10 owns the
            # observed default-boot behaviour.
            "windows_default_boot": "NOT-RUN",
        },
        "dualboot_acceptance": {
            # Gate 10 boots no controller.
            "controller_disk_and_firmware_unchanged": "NOT-RUN",
            "guest_disks_disposable_run_scoped": "PASS",
            "no_external_connection_after_offline_gate": "PASS",
            "windows_installed_before_arch": "NOT-RUN",
            "windows_default_boot": "PASS",
        },
    }

    def test_each_producer_renders_exactly_its_observed_checks(self):
        release_set = self.release_set()
        for name, measurements in self.producers().items():
            with self.subTest(producer=name):
                receipt = factory_verify.verify_run(
                    self.evidence(
                        name=f"{name}-evidence", status="observed",
                        measurements=measurements),
                    release_set=release_set)
                checks = receipt["checks"]
                for check, status in self.EXPECTED[name].items():
                    self.assertEqual(status, checks[check]["status"], check)
                for check in self.ALWAYS_ABSENT:
                    self.assertEqual(
                        "NOT-RUN", checks[check]["status"], check)
                # A phase bundle can never be a whole-factory PASS, and it must
                # never be a FAIL for a measurement it honestly did not take.
                self.assertEqual("NOT-RUN", receipt["verdict"])
                self.assertEqual(0, receipt["summary"]["fail"])

    def test_a_single_run_install_order_is_not_run_not_pass(self):
        from homelab.vm import arch_install_run, windows_install_run
        for module, expected in (
            (windows_install_run, ["windows"]),
            (arch_install_run, ["arch-workstation"]),
        ):
            with self.subTest(module=module.__name__):
                block = module.acceptance_measurements(
                    canonical_unchanged=True, loopback_only_audited=True,
                    **({"windows_installed": True}
                       if module is windows_install_run
                       else {"arch_installed": True}))
                self.assertEqual(expected, block["install_order"])
                check = factory_verify._check_windows_before_arch(block)
                self.assertEqual("NOT-RUN", check["status"])
                self.assertIn("both Windows and Arch", check["detail"])

    def test_an_unobserved_phase_emits_no_field_at_all(self):
        from homelab.vm import (
            arch_install_run, dualboot_acceptance, windows_install_run)
        self.assertEqual({}, windows_install_run.acceptance_measurements(
            canonical_unchanged=False, loopback_only_audited=False,
            windows_installed=False))
        self.assertEqual({}, arch_install_run.acceptance_measurements(
            canonical_unchanged=False, loopback_only_audited=False,
            arch_installed=False))
        # A dual-boot run whose windows-default-boot check did not pass records
        # no default-boot claim; the two unconditional fields remain.
        block = dualboot_acceptance.acceptance_measurements(
            run="run-1", events=[{
                "check": "windows-default-boot", "result": "fail",
                "default_os": "windows"}])
        self.assertNotIn("default_boot", block)
        self.assertEqual(
            {"guest_disks", "external_connections_after_offline_gate"},
            set(block))


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


CONTROLLER_MAC = "52:54:00:31:11:12"
WORKSTATION_MAC = "52:54:00:31:12:12"

CLEAN_GATE4_SWITCH = "\n".join(
    json.dumps(event) for event in (
        {"event": "switch-ready", "ports": [
            {"port": "gateway", "mac": GATEWAY_MAC},
            {"port": "controller", "mac": CONTROLLER_MAC},
            {"port": "workstation", "mac": WORKSTATION_MAC}]},
        {"event": "port-connected", "port": "gateway", "mac": GATEWAY_MAC,
         "generation": 1},
        {"event": "port-connected", "port": "controller", "mac": CONTROLLER_MAC,
         "generation": 1},
        {"event": "port-connected", "port": "workstation",
         "mac": WORKSTATION_MAC, "generation": 1},
        {"event": "dhcp", "kind": "DISCOVER", "peer": "workstation",
         "source_mac": WORKSTATION_MAC, "client_mac": WORKSTATION_MAC},
        {"event": "dhcp", "kind": "OFFER", "peer": "gateway",
         "source_mac": GATEWAY_MAC, "client_mac": WORKSTATION_MAC,
         "delivered_to": "workstation"},
        {"event": "dhcp", "kind": "ACK", "peer": "gateway",
         "source_mac": GATEWAY_MAC, "client_mac": WORKSTATION_MAC,
         "delivered_to": "workstation"},
        {"event": "flow", "peer": "workstation", "delivered_to": "controller",
         "ethertype": 0x0800, "ip_protocol": 17, "src_port": 2070,
         "dst_port": 69},
        {"event": "flow", "peer": "controller", "delivered_to": "gateway",
         "ethertype": 0x0800, "ip_protocol": 17, "src_port": 40000,
         "dst_port": 53},
    )
) + "\n"


class PxeAuthorityAuditWiringTests(VerifyRunTests):
    """The gate-4 audit runs automatically during factory-verify (read-only)."""

    def test_clean_switch_embeds_gate4_pass(self):
        receipt = factory_verify.verify_run(
            self.evidence(switch=CLEAN_GATE4_SWITCH),
            release_set=self.release_set())
        audit = receipt["pxe_authority_audit"]
        self.assertEqual("workstation-factory-gate-4", audit["gate"])
        self.assertEqual("PASS", audit["verdict"])
        self.assertEqual("PASS",
                         audit["checks"]["gate4.controller-approved-flows-only"])
        # The distinct gate-4 result never perturbs the gate-12 verdict shape.
        self.assertNotIn("pxe_authority_audit", receipt["checks"])

    def test_rogue_controller_offer_embeds_gate4_fail(self):
        rogue = CLEAN_GATE4_SWITCH + json.dumps({
            "event": "dhcp", "kind": "OFFER", "peer": "controller",
            "source_mac": CONTROLLER_MAC, "client_mac": WORKSTATION_MAC,
            "blocked": True}) + "\n"
        receipt = factory_verify.verify_run(self.evidence(switch=rogue))
        self.assertEqual("FAIL", receipt["pxe_authority_audit"]["verdict"])

    def test_missing_switch_marks_gate4_not_run(self):
        receipt = factory_verify.verify_run(self.evidence(switch=None))
        self.assertEqual("NOT-RUN",
                         receipt["pxe_authority_audit"]["verdict"])

    def test_audit_json_is_written_when_requested(self):
        out = self.root / "pxe-authority-audit.json"
        factory_verify.verify_run(
            self.evidence(switch=CLEAN_GATE4_SWITCH), audit_out=out)
        written = json.loads(out.read_text(encoding="utf-8"))
        self.assertEqual("PASS", written["verdict"])
        # The full artifact carries the per-check detail, not just the summary.
        self.assertTrue(any(c["details"] for c in written["checks"]))


class CompareThroughMakeTests(unittest.TestCase):
    """Gate 12's comparator must be reachable through the Make target.

    A twice-through is worthless if only a direct script call can render the
    repeat verdict, so these assert the ``--compare-with`` passthrough both in
    the recipe text and by actually running the target's dry run.
    """

    MAKEFILE = REPOSITORY / "Makefile"
    VARIABLE = "FACTORY_COMPARE_EVIDENCE"

    def recipe(self) -> str:
        """The homelab-factory-verify recipe as one continuation-free block."""
        text = self.MAKEFILE.read_text(encoding="utf-8")
        body = text.split("\nhomelab-factory-verify:\n", 1)[1]
        # A recipe ends at the first line that is neither a tab-indented
        # command nor blank.
        lines = []
        for line in body.splitlines():
            if line and not line.startswith("\t"):
                break
            lines.append(line)
        return "\n".join(lines).replace("\\\n", " ")

    def test_variable_is_declared(self):
        text = self.MAKEFILE.read_text(encoding="utf-8")
        self.assertIn(f"\n{self.VARIABLE} ?=", text)

    def test_both_branches_forward_compare_with(self):
        recipe = self.recipe()
        forward = f"$(if $({self.VARIABLE}),--compare-with '$({self.VARIABLE})')"
        # The dry-run branch and the APPLY=1 branch each forward it.
        self.assertEqual(2, recipe.count(forward), recipe)

    @unittest.skipUnless(shutil.which("make"), "make is unavailable")
    def test_dry_run_forwards_compare_with(self):
        # The dry run only prints the plan, so it needs no real evidence.
        completed = subprocess.run(
            ["make", "--no-print-directory", "homelab-factory-verify",
             "FACTORY_EVIDENCE=run-a/evidence",
             f"{self.VARIABLE}=run-b/evidence"],
            cwd=REPOSITORY, capture_output=True, text=True, timeout=120,
            check=True)
        self.assertIn("compare with: run-b/evidence", completed.stdout)
        self.assertIn("evidence: run-a/evidence", completed.stdout)


class CompareCliTests(VerifyRunTests):
    """End-to-end: two retained bundles compared through the CLI."""

    def test_two_bundles_compare_equivalent(self):
        first = self.evidence(name="run-a", subdirectories={"publication": {}})
        second = self.evidence(name="run-b", subdirectories={"publication": {}})
        status = factory_verify.main(
            [str(first), "--compare-with", str(second)])
        # Only the evidence directory name differs, which is expected varying.
        self.assertEqual(0, status)

    def test_differing_working_tree_set_is_divergent(self):
        first = self.evidence(name="run-a", subdirectories={"publication": {}})
        second = self.evidence(name="run-b")
        comparison = factory_verify.compare_runs(
            factory_verify.verify_run(first), factory_verify.verify_run(second))
        self.assertFalse(comparison["equivalent"])
        self.assertTrue(any(
            difference["path"].startswith("evidence_subdirectories")
            and difference["classification"] == "divergent"
            for difference in comparison["differences"]), comparison)


class ReceiptFileTests(VerifyRunTests):
    """A receipt must survive the terminal it was printed in.

    Gate 12's deliverable IS the receipt, and before ``--receipt`` existed it
    lived only in scrollback: nothing could re-read or re-compare it without
    spending another verification.  These pin the three properties that make a
    persisted receipt trustworthy -- it is private, it is byte-identical to
    what the operator saw, and persisting it changes no exit code.
    """

    def run_cli(self, arguments):
        """Run ``main`` capturing stdout, returning (status, stdout)."""
        stream = io.StringIO()
        real_stdout, real_stderr = sys.stdout, sys.stderr
        sys.stdout, sys.stderr = stream, io.StringIO()
        try:
            status = factory_verify.main(arguments)
        finally:
            sys.stdout, sys.stderr = real_stdout, real_stderr
        return status, stream.getvalue()

    def test_the_receipt_file_matches_standard_output_byte_for_byte(self):
        receipt = self.root / "receipt.json"
        status, printed = self.run_cli(
            [str(self.evidence()), "--release-set", str(self.release_set()),
             "--receipt", str(receipt)])
        self.assertEqual(0, status)
        self.assertEqual(printed, receipt.read_text(encoding="utf-8"))
        self.assertEqual("PASS", json.loads(printed)["verdict"])

    def test_the_receipt_file_is_private(self):
        receipt = self.root / "receipt.json"
        self.run_cli([str(self.evidence()), "--receipt", str(receipt)])
        self.assertEqual(
            factory_verify.RECEIPT_MODE,
            stat.S_IMODE(receipt.lstat().st_mode))

    def test_a_pre_existing_world_readable_receipt_is_re_privatised(self):
        receipt = self.root / "receipt.json"
        receipt.write_text("stale\n", encoding="utf-8")
        receipt.chmod(0o644)
        self.run_cli([str(self.evidence()), "--receipt", str(receipt)])
        self.assertEqual(
            factory_verify.RECEIPT_MODE,
            stat.S_IMODE(receipt.lstat().st_mode))
        self.assertNotIn("stale", receipt.read_text(encoding="utf-8"))

    def test_a_symlinked_receipt_destination_is_refused(self):
        target = self.root / "target.json"
        target.write_text("{}\n", encoding="utf-8")
        link = self.root / "link.json"
        link.symlink_to(target)
        with self.assertRaises(OSError):
            factory_verify.write_receipt({"schema": 1}, link)
        # The symlink target is untouched: it is never written through.
        self.assertEqual("{}\n", target.read_text(encoding="utf-8"))

    def test_the_comparison_document_is_what_is_persisted(self):
        receipt = self.root / "receipt.json"
        first = self.evidence(name="run-a")
        second = self.evidence(name="run-b")
        status, printed = self.run_cli(
            [str(first), "--compare-with", str(second),
             "--receipt", str(receipt)])
        self.assertEqual(0, status)
        persisted = json.loads(receipt.read_text(encoding="utf-8"))
        self.assertEqual({"run_a", "run_b", "comparison"}, set(persisted))
        self.assertTrue(persisted["comparison"]["equivalent"])
        self.assertEqual(printed, receipt.read_text(encoding="utf-8"))

    def test_persisting_changes_no_exit_code(self):
        # A divergent pair still exits non-zero, and the receipt is written
        # anyway -- the failing evidence is the receipt worth keeping.
        receipt = self.root / "receipt.json"
        first = self.evidence(name="run-a")
        second = self.evidence(name="run-b", status="fail")
        status, printed = self.run_cli(
            [str(first), "--compare-with", str(second),
             "--receipt", str(receipt)])
        self.assertEqual(1, status)
        self.assertEqual(printed, receipt.read_text(encoding="utf-8"))
        self.assertFalse(
            json.loads(printed)["comparison"]["equivalent"])

    def test_stdout_is_unchanged_when_no_receipt_is_requested(self):
        evidence = self.evidence()
        _, with_flag = self.run_cli(
            [str(evidence), "--receipt", str(self.root / "receipt.json")])
        _, without = self.run_cli([str(evidence)])
        self.assertEqual(without, with_flag)

    def test_the_dry_run_names_the_receipt_and_writes_nothing(self):
        receipt = self.root / "receipt.json"
        status, printed = self.run_cli(
            [str(self.evidence()), "--receipt", str(receipt), "--plan"])
        self.assertEqual(0, status)
        self.assertIn(f"receipt: {receipt}", printed)
        self.assertFalse(receipt.exists())


if __name__ == "__main__":
    unittest.main()
