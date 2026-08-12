"""Tests for the gate-11 lifecycle-recovery runner and judge.

The runner's subprocess/QMP/serial layer is reached only through the injected
``RecoveryLab`` seam, so these tests never boot a guest, touch the network, or
require privilege.  The pure loopback scenarios (release rollback, the ADR-0075
update gate, and workstation remint) are exercised for real against a
fabricated ``pxe_release_set`` release set and the tracked policy, proving their
live path is genuine; every other proof is deferred and judged fail-closed.
"""

import copy
import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
# ROOT.parent gives the ``homelab`` package; lib/vm supply the leaf modules.
# The runner (homelab/vm) and judge (homelab/workstations) share the base name
# ``lifecycle_recovery``, so the runner is imported as a leaf module and the
# judge only through the ``homelab.workstations`` package to avoid a collision.
sys.path.insert(0, str(ROOT.parent))
sys.path.insert(0, str(ROOT / "lib"))
sys.path.insert(0, str(ROOT / "vm"))

import pxe_release  # noqa: E402
import pxe_release_set  # noqa: E402
import lifecycle_recovery as runner  # noqa: E402
from homelab.workstations import lifecycle_recovery as judge  # noqa: E402


# --------------------------------------------------------------------------
# Evidence fixtures for the judge
# --------------------------------------------------------------------------


def event(check, result="pass", **fields):
    record = {"check": check, "result": result, "external_access": False}
    record.update(fields)
    return record


PROVABLE = {
    "controller-restart": {
        "stable_service_discovery": True,
        "identity_survives_migration": True,
        "no_stale_snapshot_rollback": True},
    "pxe-release-rollback": {
        "prior_version": "20260727.001", "current_version": "20260727.005",
        "rolled_back": True, "prior_manifest_verified": True,
        "prior_manifest_served": True, "transactional": True},
    "failed-install-recovery": {
        "overlay_isolated": True, "canonical_unchanged": True,
        "writes_confined_to_overlay": True, "re_mintable": True},
    "broken-boot-repair": {
        "linux_entry": "Linux Boot Manager",
        "windows_entry": "Windows Boot Manager",
        "independent_uefi_entries": True},
    "directory-dns-loss": {
        "fault_injection": "SIGSTOP", "cached_login_policy": True,
        "offline_credentials_expiration": 0},
    "update-failure-rollback": {
        "operation": "pacman -Syu", "automatic_rollback": False,
        "failed_gate_defers": True,
        "deferral_reasons": ["less than required free space"],
        "no_partial_change": True, "lts_fallback_present": True},
    "workstation-remint": {
        "disposable_destroyed": True, "clean_inputs_verified": True,
        "reminted": True, "canonical_unchanged": True,
        "no_destructive_change": True},
    "controller-reconstruction": {
        "public_inputs_verified": True, "synthetic_private_overlay": True,
        "seed_verified": True, "reconstruction_plan_complete": True},
}
LIVE = {
    "controller-restart": {
        "controller_restarted": True, "dependent_proof_resolved": True},
    "failed-install-recovery": {
        "install_failed_as_designed": True, "disk_recoverable": True},
    "broken-boot-repair": {"bootloader_repaired": True},
    "directory-dns-loss": {
        "controller_frozen": True, "cached_operation_continued": True,
        "directory_restored": True},
    "controller-reconstruction": {"converged_from_public_inputs": True},
}


def all_pass_events():
    events = []
    for scenario in judge.SCENARIOS:
        fields = dict(PROVABLE[scenario])
        fields.update(LIVE.get(scenario, {}))
        events.append(event(scenario, "pass", **fields))
    return events


class ContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.contract = judge.load_json(judge.CONTRACT)

    def test_contract_is_valid(self):
        self.assertEqual(judge.validate_contract(self.contract), [])

    def test_contract_round_trip_names_eight_scenarios(self):
        self.assertEqual(
            self.contract["required_checks"], list(judge.SCENARIOS))
        self.assertEqual(len(judge.SCENARIOS), 8)
        self.assertEqual(
            set(self.contract["live_boot_checks"]), judge.LIVE_BOOT_CHECKS)

    def test_runner_and_judge_agree_on_scenarios(self):
        self.assertEqual(runner.SCENARIOS, judge.SCENARIOS)

    def test_update_policy_forbids_automatic_rollback(self):
        # ADR 0075: no automatic image rollback; recovery is linux-lts.
        self.assertFalse(self.contract["update_policy"]["automatic_rollback"])
        self.assertEqual(
            self.contract["update_policy"]["recovery_fallback"], "linux-lts")

    def test_contract_mutations_are_rejected(self):
        for mutation in (
            {"schema_version": 2},
            {"gate": 10},
            {"network_policy": {"mode": "routed",
                                "external_access": "allowed"}},
        ):
            contract = copy.deepcopy(self.contract)
            contract.update(mutation)
            self.assertTrue(judge.validate_contract(contract))
        contract = copy.deepcopy(self.contract)
        contract["update_policy"]["automatic_rollback"] = True
        self.assertTrue(any("automatic_rollback" in e
                            for e in judge.validate_contract(contract)))
        contract = copy.deepcopy(self.contract)
        contract["dual_boot_entries"]["linux"] = "grub"
        self.assertTrue(judge.validate_contract(contract))
        contract = copy.deepcopy(self.contract)
        contract["required_checks"] = contract["required_checks"][::-1]
        self.assertTrue(judge.validate_contract(contract))


class JudgeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.contract = judge.load_json(judge.CONTRACT)

    def test_all_pass_is_pass(self):
        result = judge.judge(self.contract, all_pass_events())
        self.assertEqual(result["result"], "pass")
        self.assertEqual(result["checks"], 8)
        self.assertEqual(result["deferred"], [])
        self.assertFalse(result["external_access"])

    def test_deferred_live_scenarios_are_partial_not_pass(self):
        events = all_pass_events()
        # Defer every guest-boot scenario, keeping the provable fields.
        for record in events:
            if record["check"] in judge.LIVE_BOOT_CHECKS:
                record["result"] = "not-run"
                record["deferred_reason"] = "needs a live guest boot"
                for field in LIVE.get(record["check"], {}):
                    record.pop(field, None)
        result = judge.judge(self.contract, events)
        self.assertEqual(result["result"], "partial")
        self.assertEqual(
            sorted(result["deferred"]), sorted(judge.LIVE_BOOT_CHECKS))

    def test_not_run_without_reason_fails_closed(self):
        events = all_pass_events()
        events[0]["result"] = "not-run"
        with self.assertRaisesRegex(judge.EvidenceError, "deferred_reason"):
            judge.judge(self.contract, events)

    def test_result_fail_is_never_a_pass(self):
        events = all_pass_events()
        events[1]["result"] = "fail"
        with self.assertRaisesRegex(judge.EvidenceError, "must be 'pass'"):
            judge.judge(self.contract, events)

    def test_missing_scenario_fails(self):
        events = all_pass_events()
        events.pop(3)
        with self.assertRaisesRegex(judge.EvidenceError, "missing evidence"):
            judge.judge(self.contract, events)

    def test_duplicate_scenario_fails(self):
        events = all_pass_events()
        events.append(copy.deepcopy(events[0]))
        with self.assertRaisesRegex(judge.EvidenceError, "duplicate"):
            judge.judge(self.contract, events)

    def test_external_access_true_fails(self):
        events = all_pass_events()
        events[0]["external_access"] = True
        with self.assertRaisesRegex(judge.EvidenceError, "external_access"):
            judge.judge(self.contract, events)

    def test_passing_scenario_missing_live_field_fails(self):
        events = all_pass_events()
        record = next(e for e in events if e["check"] == "controller-restart")
        del record["controller_restarted"]
        with self.assertRaisesRegex(
                judge.EvidenceError, "must record controller_restarted"):
            judge.judge(self.contract, events)

    # -- per-scenario field validation: each failure mode -----------------

    def test_controller_restart_field_failures(self):
        for field in PROVABLE["controller-restart"]:
            events = all_pass_events()
            record = next(
                e for e in events if e["check"] == "controller-restart")
            record[field] = False
            with self.assertRaises(judge.EvidenceError):
                judge.judge(self.contract, events)

    def test_release_rollback_field_failures(self):
        events = all_pass_events()
        record = next(
            e for e in events if e["check"] == "pxe-release-rollback")
        record["prior_version"] = "not-a-version"
        with self.assertRaisesRegex(judge.EvidenceError, "YYYYMMDD.NNN"):
            judge.judge(self.contract, events)
        events = all_pass_events()
        record = next(
            e for e in events if e["check"] == "pxe-release-rollback")
        record["prior_version"], record["current_version"] = (
            record["current_version"], record["prior_version"])
        with self.assertRaisesRegex(judge.EvidenceError, "must precede"):
            judge.judge(self.contract, events)
        for field in ("rolled_back", "prior_manifest_verified",
                      "prior_manifest_served", "transactional"):
            events = all_pass_events()
            record = next(
                e for e in events if e["check"] == "pxe-release-rollback")
            record[field] = False
            with self.assertRaises(judge.EvidenceError):
                judge.judge(self.contract, events)

    def test_broken_boot_wrong_labels_fail(self):
        for field, value in (
            ("linux_entry", "GRUB"),
            ("windows_entry", "bootmgfw"),
            ("independent_uefi_entries", False),
        ):
            events = all_pass_events()
            record = next(
                e for e in events if e["check"] == "broken-boot-repair")
            record[field] = value
            with self.assertRaises(judge.EvidenceError):
                judge.judge(self.contract, events)

    def test_directory_dns_field_failures(self):
        for field, value in (
            ("fault_injection", "SIGKILL"),
            ("cached_login_policy", False),
            ("offline_credentials_expiration", 30),
            ("offline_credentials_expiration", True),
        ):
            events = all_pass_events()
            record = next(
                e for e in events if e["check"] == "directory-dns-loss")
            record[field] = value
            with self.assertRaises(judge.EvidenceError):
                judge.judge(self.contract, events)

    def test_update_failure_field_failures(self):
        # ADR 0075: an update that claims an automatic rollback is rejected.
        events = all_pass_events()
        record = next(
            e for e in events if e["check"] == "update-failure-rollback")
        record["automatic_rollback"] = True
        with self.assertRaisesRegex(judge.EvidenceError, "automatic_rollback"):
            judge.judge(self.contract, events)
        for field, value in (
            ("operation", "pacman -Sy"),
            ("failed_gate_defers", False),
            ("deferral_reasons", []),
            ("deferral_reasons", "battery"),
            ("no_partial_change", False),
            ("lts_fallback_present", False),
        ):
            events = all_pass_events()
            record = next(
                e for e in events if e["check"] == "update-failure-rollback")
            record[field] = value
            with self.assertRaises(judge.EvidenceError):
                judge.judge(self.contract, events)

    def test_remint_field_failures(self):
        for field in PROVABLE["workstation-remint"]:
            events = all_pass_events()
            record = next(
                e for e in events if e["check"] == "workstation-remint")
            record[field] = False
            with self.assertRaises(judge.EvidenceError):
                judge.judge(self.contract, events)

    def test_deferred_scenario_with_wrong_present_field_still_fails(self):
        # A not-run scenario may omit fields, but a recorded field that is
        # wrong is fail-closed.
        events = all_pass_events()
        record = next(e for e in events if e["check"] == "broken-boot-repair")
        record["result"] = "not-run"
        record["deferred_reason"] = "live boot deferred"
        record.pop("bootloader_repaired", None)
        record["linux_entry"] = "GRUB"
        with self.assertRaises(judge.EvidenceError):
            judge.judge(self.contract, events)

    def test_jsonl_loader_reports_bad_line(self):
        with self.assertRaisesRegex(judge.EvidenceError, "line 2"):
            judge.load_events(['{"ok": true}\n', "nope\n"])


# --------------------------------------------------------------------------
# Runner: evidence assembly from mocked lab observations
# --------------------------------------------------------------------------


class FakeLab(runner.RecoveryLab):
    def __init__(self, observations):
        self._observations = observations

    def _obs(self, check):
        return self._observations[check]

    def controller_restart(self, ctx):
        return self._obs("controller-restart")

    def pxe_release_rollback(self, ctx):
        return self._obs("pxe-release-rollback")

    def failed_install_recovery(self, ctx):
        return self._obs("failed-install-recovery")

    def broken_boot_repair(self, ctx):
        return self._obs("broken-boot-repair")

    def directory_dns_loss(self, ctx):
        return self._obs("directory-dns-loss")

    def update_failure_rollback(self, ctx):
        return self._obs("update-failure-rollback")

    def workstation_remint(self, ctx):
        return self._obs("workstation-remint")

    def controller_reconstruction(self, ctx):
        return self._obs("controller-reconstruction")


def proven_observations():
    obs = {}
    for scenario in runner.SCENARIOS:
        obs[scenario] = {
            "status": runner.PROVEN,
            "fields": dict(PROVABLE[scenario]),
            "live": dict(LIVE.get(scenario, {})),
        }
    return obs


class RecordAssemblyTests(unittest.TestCase):
    def test_proven_becomes_pass(self):
        record = runner.record_from_observation(
            "workstation-remint",
            {"status": runner.PROVEN,
             "fields": PROVABLE["workstation-remint"]})
        self.assertEqual(record["result"], "pass")
        self.assertNotIn("deferred_reason", record)
        self.assertFalse(record["external_access"])

    def test_deferred_becomes_not_run_with_reason(self):
        record = runner.record_from_observation(
            "controller-restart",
            {"status": runner.DEFERRED, "reason": "needs live boot",
             "fields": PROVABLE["controller-restart"]})
        self.assertEqual(record["result"], "not-run")
        self.assertEqual(record["deferred_reason"], "needs live boot")

    def test_failed_becomes_fail(self):
        record = runner.record_from_observation(
            "pxe-release-rollback",
            {"status": runner.FAILED, "reason": "prior manifest missing"})
        self.assertEqual(record["result"], "fail")

    def test_unknown_status_raises(self):
        with self.assertRaises(runner.RecoveryError):
            runner.record_from_observation("controller-restart", {"status": "?"})

    def test_assembled_events_pass_the_judge(self):
        lab = FakeLab(proven_observations())
        ctx = runner.RunContext(
            run=Path("/tmp/x"), releases=Path("/tmp/r"),
            controller_state=Path("/tmp/c"), seed_iso=Path("/tmp/s"),
            duration=600)
        events = runner.assemble(lab, ctx)
        contract = judge.load_json(judge.CONTRACT)
        result = judge.judge(contract, events)
        self.assertEqual(result["result"], "pass")


# --------------------------------------------------------------------------
# Runner orchestration: result.json in finally, bounded duration, refusals
# --------------------------------------------------------------------------


class RunTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)

    def _ctx_inputs(self):
        return {
            "releases": self.root / "pxe",
            "controller_state": self.root / "controller",
            "seed_iso": self.root / "seed.iso",
        }

    def test_dry_run_starts_nothing(self):
        code = runner.run(
            self.root / "run", **self._ctx_inputs(), duration=600,
            apply=False, lab=FakeLab(proven_observations()))
        self.assertEqual(code, 0)
        self.assertFalse((self.root / "run").exists())

    def test_bounded_duration_is_enforced(self):
        for bad in (59, 10801, 0, -1):
            with self.assertRaisesRegex(runner.RecoveryError, "duration"):
                runner.run(
                    self.root / f"run-{bad}", **self._ctx_inputs(),
                    duration=bad, apply=True,
                    lab=FakeLab(proven_observations()))

    def test_apply_writes_result_and_evidence(self):
        run_dir = self.root / "run"
        code = runner.run(
            run_dir, **self._ctx_inputs(), duration=600, apply=True,
            lab=FakeLab(proven_observations()))
        self.assertEqual(code, 0)
        result = json.loads((run_dir / "result.json").read_text())
        self.assertEqual(result["status"], "observed")
        self.assertEqual(result["summary"]["pass"], 8)
        self.assertEqual(result["summary"]["fail"], 0)
        # The evidence stream the judge grades was written.
        lines = (run_dir / "recovery-evidence.jsonl").read_text().splitlines()
        self.assertEqual(len(lines), 8)
        contract = judge.load_json(judge.CONTRACT)
        events = [json.loads(line) for line in lines]
        self.assertEqual(judge.judge(contract, events)["result"], "pass")

    def test_result_json_written_even_when_a_scenario_fails(self):
        obs = proven_observations()
        obs["pxe-release-rollback"] = {
            "status": runner.FAILED, "reason": "prior manifest missing"}
        run_dir = self.root / "run"
        code = runner.run(
            run_dir, **self._ctx_inputs(), duration=600, apply=True,
            lab=FakeLab(obs))
        self.assertEqual(code, 1)
        result = json.loads((run_dir / "result.json").read_text())
        self.assertEqual(result["status"], "fail")
        self.assertIn("pxe-release-rollback", result["failed"])

    def test_result_json_written_when_lab_raises(self):
        class Boom(FakeLab):
            def controller_restart(self, ctx):
                raise RuntimeError("lab exploded")

        run_dir = self.root / "run"
        with self.assertRaises(RuntimeError):
            runner.run(
                run_dir, **self._ctx_inputs(), duration=600, apply=True,
                lab=Boom(proven_observations()))
        result = json.loads((run_dir / "result.json").read_text())
        self.assertEqual(result["status"], "fail")
        self.assertEqual(result["error_type"], "RuntimeError")

    def test_existing_run_bundle_is_refused(self):
        run_dir = self.root / "run"
        run_dir.mkdir()
        with self.assertRaisesRegex(runner.RecoveryError, "already exists"):
            runner.run(
                run_dir, **self._ctx_inputs(), duration=600, apply=True,
                lab=FakeLab(proven_observations()))


# --------------------------------------------------------------------------
# LiveRecoveryLab: the real loopback proofs (no guest boot)
# --------------------------------------------------------------------------


def build_release_set(root, version, *, seal_value=None):
    seal = root / f"seal-{version}.json"
    seal_value = seal_value or {
        "schema": 1,
        "content": [
            {"name": "arch-iso", "sha256": "a" * 64},
            {"name": "windows-iso", "sha256": "b" * 64},
            {"name": "wimboot", "sha256": "c" * 64},
            {"name": "windows-install-source", "source_iso_sha256": "b" * 64,
             "receipt_sha256": "d" * 64, "bytes": 8_000_000_000,
             "file_count": 976},
        ],
    }
    seal.write_text(json.dumps(seal_value), encoding="utf-8")
    releases = root / "pxe"

    def stage(build_root):
        leaves = {}
        for target in pxe_release_set.TARGETS:
            source = build_root / "sources" / target
            source.mkdir(parents=True)
            (source / "boot.ipxe").write_text("#!ipxe\n", encoding="utf-8")
            (source / "target.json").write_text(json.dumps({
                "schema": 1, "id": target, "entrypoints": ["boot.ipxe"]}),
                encoding="utf-8")
            leaves[target] = pxe_release.stage(
                source, build_root / "releases", version=version)
        return leaves

    return pxe_release_set.build(releases, version, seal, seal_value, stage)


class LiveLoopbackProofTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.lab = runner.LiveRecoveryLab()

    def _context(self):
        run_dir = self.root / "run"
        run_dir.mkdir(exist_ok=True)
        scratch = run_dir / "scratch"
        scratch.mkdir(exist_ok=True)
        ctx = runner.RunContext(
            run=run_dir, releases=self.root / "pxe",
            controller_state=self.root / "controller",
            seed_iso=self.root / "seed.iso", duration=600)
        return ctx

    def test_real_release_rollback_passes(self):
        build_release_set(self.root, "20260727.001")
        build_release_set(self.root, "20260727.005")
        observation = self.lab.pxe_release_rollback(self._context())
        record = runner.record_from_observation(
            "pxe-release-rollback", observation)
        self.assertEqual(record["result"], "pass", observation)
        self.assertEqual(record["prior_version"], "20260727.001")
        self.assertEqual(record["current_version"], "20260727.005")
        self.assertTrue(record["prior_manifest_served"])
        # The transactional pointer was restored to the newest set.
        selected = json.loads(
            (self.root / "pxe" / pxe_release_set.SELECTED).read_text())
        self.assertEqual(selected["version"], "20260727.005")

    def test_rollback_without_two_sets_is_deferred(self):
        build_release_set(self.root, "20260727.001")
        observation = self.lab.pxe_release_rollback(self._context())
        record = runner.record_from_observation(
            "pxe-release-rollback", observation)
        self.assertEqual(record["result"], "not-run")

    def test_real_update_gate_defers_and_passes(self):
        observation = self.lab.update_failure_rollback(self._context())
        record = runner.record_from_observation(
            "update-failure-rollback", observation)
        self.assertEqual(record["result"], "pass", observation)
        self.assertFalse(record["automatic_rollback"])
        self.assertTrue(record["lts_fallback_present"])
        self.assertTrue(record["deferral_reasons"])

    def test_real_remint_passes(self):
        build_release_set(self.root, "20260727.005")
        observation = self.lab.workstation_remint(self._context())
        record = runner.record_from_observation(
            "workstation-remint", observation)
        self.assertEqual(record["result"], "pass", observation)
        self.assertTrue(record["canonical_unchanged"])

    def test_remint_without_inputs_is_deferred(self):
        observation = self.lab.workstation_remint(self._context())
        record = runner.record_from_observation(
            "workstation-remint", observation)
        self.assertEqual(record["result"], "not-run")

    def test_guest_boot_scenarios_defer_with_reason(self):
        ctx = self._context()
        for scenario, method in (
            ("controller-restart", self.lab.controller_restart),
            ("broken-boot-repair", self.lab.broken_boot_repair),
            ("directory-dns-loss", self.lab.directory_dns_loss),
        ):
            observation = method(ctx)
            record = runner.record_from_observation(scenario, observation)
            self.assertEqual(record["result"], "not-run", scenario)
            self.assertTrue(record["deferred_reason"])

    def test_broken_boot_observes_independent_entries(self):
        record = runner.record_from_observation(
            "broken-boot-repair", self.lab.broken_boot_repair(self._context()))
        self.assertEqual(record["linux_entry"], "Linux Boot Manager")
        self.assertEqual(record["windows_entry"], "Windows Boot Manager")
        self.assertTrue(record["independent_uefi_entries"])

    def test_reconstruction_without_seed_is_unavailable(self):
        record = runner.record_from_observation(
            "controller-reconstruction",
            self.lab.controller_reconstruction(self._context()))
        self.assertEqual(record["result"], "not-run")

    def test_full_live_lab_run_is_partial_and_judges(self):
        build_release_set(self.root, "20260727.001")
        build_release_set(self.root, "20260727.005")
        run_dir = self.root / "recover-run"
        code = runner.run(
            run_dir, releases=self.root / "pxe",
            controller_state=self.root / "controller",
            seed_iso=self.root / "missing-seed.iso", duration=600,
            apply=True, lab=runner.LiveRecoveryLab())
        self.assertEqual(code, 0)
        events = [json.loads(line) for line in
                  (run_dir / "recovery-evidence.jsonl").read_text().splitlines()]
        contract = judge.load_json(judge.CONTRACT)
        result = judge.judge(contract, events)
        self.assertEqual(result["result"], "partial")
        # The three fully-provable loopback scenarios pass for real.
        passed = {e["check"] for e in events if e["result"] == "pass"}
        self.assertIn("pxe-release-rollback", passed)
        self.assertIn("update-failure-rollback", passed)
        self.assertIn("workstation-remint", passed)


if __name__ == "__main__":
    unittest.main()
