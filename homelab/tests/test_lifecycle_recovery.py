"""Tests for the gate-11 lifecycle-recovery runner and judge.

The runner's subprocess/QMP/serial layer is reached only through the injected
``RecoveryLab`` seam, so these tests never boot a guest, touch the network, or
require privilege.  The pure loopback scenarios (release rollback, the ADR-0075
update gate, and workstation remint) are exercised for real against a
fabricated ``pxe_release_set`` release set and the tracked policy, proving their
live path is genuine; every other proof is deferred and judged fail-closed.
"""

import copy
import io
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

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

    # -- the --boot flag is reachable end to end -------------------------

    def test_parser_exposes_boot_defaulting_off(self):
        args = runner.parser().parse_args(["--run", "run"])
        self.assertFalse(args.boot)
        args = runner.parser().parse_args(["--run", "run", "--boot"])
        self.assertTrue(args.boot)

    def _spy_lab(self, seen):
        class Spy(runner.LiveRecoveryLab):
            def __init__(self, *, boot=False):
                super().__init__(boot=boot)
                seen.append(boot)

        return Spy

    def test_run_constructs_the_live_lab_with_boot(self):
        for boot in (False, True):
            seen = []
            with mock.patch.object(runner, "LiveRecoveryLab",
                                   self._spy_lab(seen)):
                code = runner.run(
                    self.root / f"run-boot-{boot}", **self._ctx_inputs(),
                    duration=600, apply=True, boot=boot)
            self.assertEqual(code, 0)
            self.assertEqual(seen, [boot])

    def test_main_passes_boot_through_to_the_lab(self):
        for argv_extra, expected in ((["--boot"], True), ([], False)):
            seen = []
            with mock.patch.object(runner, "LiveRecoveryLab",
                                   self._spy_lab(seen)):
                code = runner.main([
                    "--run", str(self.root / f"main-{expected}"),
                    "--releases", str(self.root / "pxe"),
                    "--controller-state", str(self.root / "controller"),
                    "--seed-iso", str(self.root / "seed.iso"),
                    "--duration", "600", "--apply", *argv_extra])
            self.assertEqual(code, 0)
            self.assertEqual(seen, [expected])

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

    def test_live_hooks_are_not_called_without_boot(self):
        called = []

        class Recording(runner.LiveRecoveryLab):
            def _live_controller_restart(self, ctx):
                called.append("controller-restart")
                return None

        record = runner.record_from_observation(
            "controller-restart",
            Recording(boot=False).controller_restart(self._context()))
        self.assertEqual(record["result"], "not-run")
        self.assertEqual(called, [])

    def test_boot_reaches_the_live_hooks(self):
        called = []

        class Recording(runner.LiveRecoveryLab):
            def _live_controller_restart(self, ctx):
                called.append("controller-restart")
                return None

        record = runner.record_from_observation(
            "controller-restart",
            Recording(boot=True).controller_restart(self._context()))
        # The hook ran, returned no live proofs, and the scenario still defers:
        # --boot never turns an unproven live scenario into a pass.
        self.assertEqual(called, ["controller-restart"])
        self.assertEqual(record["result"], "not-run")
        self.assertTrue(record["deferred_reason"])

    def test_boot_lets_an_implemented_hook_prove_a_scenario(self):
        class Booted(runner.LiveRecoveryLab):
            def _live_controller_restart(self, ctx):
                return dict(LIVE["controller-restart"])

        record = runner.record_from_observation(
            "controller-restart",
            Booted(boot=True).controller_restart(self._context()))
        self.assertEqual(record["result"], "pass")
        self.assertTrue(record["controller_restarted"])
        # The same implemented hook is unreachable without the flag.
        deferred = runner.record_from_observation(
            "controller-restart",
            Booted(boot=False).controller_restart(self._context()))
        self.assertEqual(deferred["result"], "not-run")

    def test_every_live_boot_scenario_is_gated_on_boot(self):
        # All five guest-boot scenarios route through the same ``boot`` gate.
        # Give reconstruction its real inputs so the flow reaches the hook
        # rather than short-circuiting on an absent seed.
        build_release_set(self.root, "20260727.005")
        seed = self.root / "seed.iso"
        seed.write_bytes(b"seed\n")
        ctx = self._context()
        ctx.seed_iso = seed
        for scenario, method_name, hook_name in (
            ("controller-restart", "controller_restart",
             "_live_controller_restart"),
            ("broken-boot-repair", "broken_boot_repair",
             "_live_broken_boot_repair"),
            ("directory-dns-loss", "directory_dns_loss",
             "_live_directory_dns_loss"),
            ("failed-install-recovery", "failed_install_recovery",
             "_live_failed_install_recovery"),
            ("controller-reconstruction", "controller_reconstruction",
             "_live_controller_reconstruction"),
        ):
            called = []

            class Recording(runner.LiveRecoveryLab):
                pass

            setattr(Recording, hook_name,
                    lambda self, ctx, _seen=called: _seen.append(1) or None)
            record = runner.record_from_observation(
                scenario, getattr(Recording(boot=False), method_name)(ctx))
            self.assertEqual(called, [], scenario)
            self.assertEqual(record["result"], "not-run", scenario)
            record = runner.record_from_observation(
                scenario, getattr(Recording(boot=True), method_name)(ctx))
            self.assertEqual(called, [1], scenario)
            # The hook returned no proofs, so the scenario still defers.
            self.assertEqual(record["result"], "not-run", scenario)

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


# --------------------------------------------------------------------------
# The implemented live-boot hooks, driven over a scripted guest transcript
#
# These never boot anything: ``_open_identity_session`` -- the one method in
# the runner that reaches live machinery -- is replaced, and the drive it
# returns is the *real* ``ArchIdentityDrive`` reading a real
# ``SerialAutomation`` over a pipe preloaded with what a guest would print.
# So the probe patterns, the token scoping and the marker discipline are all
# exercised for real, and a transcript that merely talks about a proof cannot
# pass.
# --------------------------------------------------------------------------


from homelab.vm import arch_identity_run as identity  # noqa: E402
from serial_automation import SerialAutomation  # noqa: E402


class ScriptedGuest:
    """A real serial channel and drive over a pipe of scripted guest output."""

    def __init__(self, *, timeout=5.0, clock=None):
        self._read_fd, self._write_fd = os.pipe()
        self.reader = open(self._read_fd, "rb", buffering=0)
        self.writer = io.BytesIO()
        kwargs = {"timeout": timeout}
        if clock is not None:
            kwargs["clock"] = clock
        self.channel = SerialAutomation(self.reader, self.writer, None, **kwargs)
        self.drive = identity.ArchIdentityDrive(self.channel)

    @property
    def token(self):
        return self.channel.token

    def say(self, text):
        os.write(self._write_fd, text.encode("ascii"))

    def marker(self, check, verdict="PASS", *, token=None):
        """Print the exact token-scoped verdict marker the guest probe prints."""
        key = check.upper().replace("-", "_")
        self.say(f"\n__TELOS_ARCH_{key}_{token or self.token}={verdict}\n")

    def echo(self, check):
        """Print what the *shell* echoes: the command, never the verdict."""
        self.say(f"[operator@arch ~]$ telos-arch-identity-probe {check} "
                 f"{self.token}\n")

    def finish(self):
        """Close the write end so an unmet wait fails fast instead of hanging."""
        os.close(self._write_fd)
        self._write_fd = -1

    def close(self):
        if self._write_fd >= 0:
            os.close(self._write_fd)
            self._write_fd = -1
        self.reader.close()


class FakeIdentitySession:
    """The subset of ``ArchIdentitySession`` the implemented hooks use."""

    def __init__(self, *, ready=True, stop_problems=(), stop_error=None):
        self.calls = []
        self._ready = ready
        self._online = True
        self.stop_problems = list(stop_problems)
        self.stop_error = stop_error

    def observe_controller_ready(self):
        return self._ready

    def take_controller_offline(self):
        self.calls.append("offline")
        self._online = False

    def observe_controller_offline(self):
        return not self._online

    def restore_controller(self):
        self.calls.append("restore")
        self._online = True

    def observe_controller_restored(self):
        return self._online

    def stop(self):
        self.calls.append("stop")
        if self.stop_error is not None:
            raise self.stop_error
        return list(self.stop_problems)


class ScriptedLab(runner.LiveRecoveryLab):
    """A live lab whose only live seam hands back a scripted topology."""

    def __init__(self, opened, *, boot=True, clock=None):
        kwargs = {"boot": boot}
        if clock is not None:
            kwargs["clock"] = clock
        super().__init__(**kwargs)
        self._opened = opened
        self.opens = 0

    def _open_identity_session(self, ctx):
        self.opens += 1
        if isinstance(self._opened, BaseException):
            raise self._opened
        return self._opened


def stepping_clock(values):
    """A monotonic clock that walks *values* and then holds the last one."""
    remaining = list(values)

    def clock():
        if len(remaining) > 1:
            return remaining.pop(0)
        return remaining[0]

    return clock


class LiveHookTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)

    def _context(self, *, identity_bundle=None, duration=600):
        run_dir = self.root / "run"
        run_dir.mkdir(exist_ok=True)
        (run_dir / "scratch").mkdir(exist_ok=True)
        return runner.RunContext(
            run=run_dir, releases=self.root / "pxe",
            controller_state=self.root / "controller",
            seed_iso=self.root / "seed.iso", duration=duration,
            identity_bundle=identity_bundle)

    def _reconstruction_context(self):
        # The provable part must reach the live hook rather than short-circuit
        # on an absent seed or unverifiable public inputs.
        build_release_set(self.root, "20260727.005")
        seed = self.root / "seed.iso"
        seed.write_bytes(b"seed\n")
        return self._context()

    def _guest(self, **kwargs):
        guest = ScriptedGuest(**kwargs)
        self.addCleanup(guest.close)
        return guest

    def _judged(self, record):
        """Grade one produced scenario record beside otherwise passing peers."""
        events = [e for e in all_pass_events() if e["check"] != record["check"]]
        events.append(record)
        order = {name: index for index, name in enumerate(judge.SCENARIOS)}
        events.sort(key=lambda item: order[item["check"]])
        return judge.judge(judge.load_json(judge.CONTRACT), events)

    # -- directory/DNS loss ----------------------------------------------

    def _directory_transcript(self, guest, *, cached="PASS", denied="PASS",
                             restored="PASS"):
        guest.echo("arch-cached-login")
        guest.marker("arch-cached-login", cached)
        guest.echo("arch-uncached-denied")
        guest.marker("arch-uncached-denied", denied)
        guest.echo("arch-identity-restored")
        guest.marker("arch-identity-restored", restored)
        guest.finish()

    def test_directory_dns_loss_live_hook_proves_the_scenario(self):
        guest = self._guest()
        session = FakeIdentitySession()
        self._directory_transcript(guest)
        lab = ScriptedLab((session, guest.drive))
        record = runner.record_from_observation(
            "directory-dns-loss", lab.directory_dns_loss(self._context()))
        self.assertEqual(record["result"], "pass", record)
        for field in ("controller_frozen", "cached_operation_continued",
                      "directory_restored"):
            self.assertIs(record[field], True, field)
        # The outage really was taken and really was lifted.
        self.assertEqual(session.calls, ["offline", "restore"])
        # And the judge grades that scenario a pass on this record alone.
        self.assertEqual(self._judged(record)["result"], "pass")

    def test_directory_dns_loss_hook_is_unreachable_without_boot(self):
        guest = self._guest()
        session = FakeIdentitySession()
        self._directory_transcript(guest)
        lab = ScriptedLab((session, guest.drive), boot=False)
        record = runner.record_from_observation(
            "directory-dns-loss", lab.directory_dns_loss(self._context()))
        self.assertEqual(record["result"], "not-run")
        self.assertTrue(record["deferred_reason"])
        self.assertEqual(lab.opens, 0)
        self.assertEqual(session.calls, [])
        self.assertEqual(self._judged(record)["deferred"],
                         ["directory-dns-loss"])

    def test_directory_dns_loss_refuses_a_guest_fail_verdict(self):
        for failing in ("cached", "denied", "restored"):
            with self.subTest(failing=failing):
                guest = self._guest()
                session = FakeIdentitySession()
                self._directory_transcript(guest, **{failing: "FAIL"})
                lab = ScriptedLab((session, guest.drive))
                observation = lab.directory_dns_loss(self._context())
                record = runner.record_from_observation(
                    "directory-dns-loss", observation)
                self.assertEqual(record["result"], "not-run")
                for field in ("controller_frozen",
                              "cached_operation_continued",
                              "directory_restored"):
                    self.assertNotIn(field, record)
                # The Controller is resumed even when the proof is lost.
                self.assertIn("restore", session.calls)

    def test_directory_dns_loss_refuses_a_transcript_that_only_mentions_it(self):
        # The real bug shape this repository has hit: the shell echoes the
        # command, and a chatty guest prints a human-readable verdict, but the
        # program's own token-scoped marker is never printed.  A hook that
        # matched loose text would call this a pass.
        guest = self._guest()
        session = FakeIdentitySession()
        guest.echo("arch-cached-login")
        guest.say("cached login for the primed operator: PASS\n")
        guest.say("arch-cached-login PASS\n")
        guest.say("__TELOS_ARCH_ARCH_CACHED_LOGIN_=PASS\n")
        guest.finish()
        lab = ScriptedLab((session, guest.drive))
        record = runner.record_from_observation(
            "directory-dns-loss", lab.directory_dns_loss(self._context()))
        self.assertEqual(record["result"], "not-run")
        self.assertNotIn("cached_operation_continued", record)
        self.assertIn("restore", session.calls)

    def test_directory_dns_loss_refuses_another_sessions_marker(self):
        # A marker scoped to some other console's token is not this run's
        # observation, however well formed it looks.
        guest = self._guest()
        session = FakeIdentitySession()
        guest.marker("arch-cached-login", "PASS", token="deadbeef" * 4)
        guest.finish()
        lab = ScriptedLab((session, guest.drive))
        record = runner.record_from_observation(
            "directory-dns-loss", lab.directory_dns_loss(self._context()))
        self.assertEqual(record["result"], "not-run")

    def test_directory_dns_loss_refuses_a_frozen_flag_the_guest_denies(self):
        # The host-side "offline" flag alone is never the proof: with the
        # guest refusing to confirm the outage the scenario defers.
        guest = self._guest()
        session = FakeIdentitySession()
        self._directory_transcript(guest, denied="FAIL")
        lab = ScriptedLab((session, guest.drive))
        record = runner.record_from_observation(
            "directory-dns-loss", lab.directory_dns_loss(self._context()))
        self.assertEqual(record["result"], "not-run")
        self.assertTrue(session.observe_controller_restored())

    def test_live_probes_stop_at_the_duration_deadline(self):
        # The deadline is derived from ctx.duration when the topology opens;
        # once it has passed no further read is even started.
        guest = self._guest()
        session = FakeIdentitySession()
        self._directory_transcript(guest)
        lab = ScriptedLab((session, guest.drive),
                          clock=stepping_clock([0.0, 10.0 ** 9]))
        record = runner.record_from_observation(
            "directory-dns-loss", lab.directory_dns_loss(self._context()))
        self.assertEqual(record["result"], "not-run")
        self.assertIn("restore", session.calls)

    def test_a_console_timeout_is_never_a_pass(self):
        # The guest stays connected and simply never prints the marker: the
        # bounded wait expires and the scenario defers rather than passing.
        guest = self._guest(clock=stepping_clock([0.0, 10.0 ** 9]))
        session = FakeIdentitySession()
        guest.echo("arch-cached-login")
        lab = ScriptedLab((session, guest.drive))
        record = runner.record_from_observation(
            "directory-dns-loss", lab.directory_dns_loss(self._context()))
        self.assertEqual(record["result"], "not-run")
        self.assertNotIn("cached_operation_continued", record)
        self.assertIn("restore", session.calls)

    def test_a_probe_clamps_the_console_timeout_to_the_remaining_budget(self):
        guest = self._guest(timeout=10_000.0)
        session = FakeIdentitySession()
        self._directory_transcript(guest)
        lab = ScriptedLab((session, guest.drive))
        lab.directory_dns_loss(self._context(duration=600))
        self.assertLessEqual(guest.channel.timeout, 600.0)

    def test_a_truthy_non_boolean_verdict_is_not_a_proof(self):
        class Chatty:
            channel = None

            def prove_cached_login(self):
                return "PASS"

        lab = ScriptedLab((FakeIdentitySession(), Chatty()))
        lab._identity_lab(self._context())
        self.assertFalse(
            lab._probe(Chatty(), Chatty().prove_cached_login))

    # -- controller reconstruction ---------------------------------------

    def test_controller_reconstruction_live_hook_proves_the_scenario(self):
        guest = self._guest()
        session = FakeIdentitySession()
        guest.echo("arch-joined")
        guest.marker("arch-joined")
        guest.finish()
        lab = ScriptedLab((session, guest.drive))
        record = runner.record_from_observation(
            "controller-reconstruction",
            lab.controller_reconstruction(self._reconstruction_context()))
        self.assertEqual(record["result"], "pass", record)
        self.assertIs(record["converged_from_public_inputs"], True)
        self.assertEqual(self._judged(record)["result"], "pass")

    def test_controller_reconstruction_hook_is_unreachable_without_boot(self):
        guest = self._guest()
        guest.marker("arch-joined")
        guest.finish()
        lab = ScriptedLab((FakeIdentitySession(), guest.drive), boot=False)
        record = runner.record_from_observation(
            "controller-reconstruction",
            lab.controller_reconstruction(self._reconstruction_context()))
        self.assertEqual(record["result"], "not-run")
        self.assertEqual(lab.opens, 0)

    def test_controller_reconstruction_refuses_an_unready_controller(self):
        guest = self._guest()
        guest.marker("arch-joined")
        guest.finish()
        lab = ScriptedLab(
            (FakeIdentitySession(ready=False), guest.drive))
        record = runner.record_from_observation(
            "controller-reconstruction",
            lab.controller_reconstruction(self._reconstruction_context()))
        self.assertEqual(record["result"], "not-run")
        self.assertNotIn("converged_from_public_inputs", record)

    def test_controller_reconstruction_refuses_a_narrated_join(self):
        # ``net ads testjoin`` narration is not the probe's verdict marker.
        guest = self._guest()
        session = FakeIdentitySession()
        guest.echo("arch-joined")
        guest.say("Join is OK\n")
        guest.say("arch-joined: PASS\n")
        guest.finish()
        lab = ScriptedLab((session, guest.drive))
        record = runner.record_from_observation(
            "controller-reconstruction",
            lab.controller_reconstruction(self._reconstruction_context()))
        self.assertEqual(record["result"], "not-run")

    def test_controller_reconstruction_refuses_a_guest_fail_verdict(self):
        guest = self._guest()
        guest.echo("arch-joined")
        guest.marker("arch-joined", "FAIL")
        guest.finish()
        lab = ScriptedLab((FakeIdentitySession(), guest.drive))
        record = runner.record_from_observation(
            "controller-reconstruction",
            lab.controller_reconstruction(self._reconstruction_context()))
        self.assertEqual(record["result"], "not-run")

    # -- the shared topology ---------------------------------------------

    def test_both_live_hooks_share_one_booted_topology(self):
        guest = self._guest()
        session = FakeIdentitySession()
        self._directory_transcript(guest)
        lab = ScriptedLab((session, guest.drive))
        ctx = self._reconstruction_context()
        first = runner.record_from_observation(
            "directory-dns-loss", lab.directory_dns_loss(ctx))
        # A second guest transcript would need a second console; the point
        # here is that no second boot is attempted.
        lab.controller_reconstruction(ctx)
        self.assertEqual(first["result"], "pass")
        self.assertEqual(lab.opens, 1)

    def test_a_failed_topology_start_is_not_retried(self):
        lab = ScriptedLab(RuntimeError("no fabric"))
        ctx = self._reconstruction_context()
        for method in (lab.directory_dns_loss, lab.controller_reconstruction):
            record = runner.record_from_observation(
                "directory-dns-loss" if method is lab.directory_dns_loss
                else "controller-reconstruction", method(ctx))
            self.assertEqual(record["result"], "not-run")
        self.assertEqual(lab.opens, 1)

    def test_without_an_identity_bundle_the_real_seam_boots_nothing(self):
        # The real ``_open_identity_session`` refuses before importing or
        # spawning anything when the gate-7 bundle was not supplied.
        lab = runner.LiveRecoveryLab(boot=True)
        self.assertIsNone(lab._open_identity_session(self._context()))
        record = runner.record_from_observation(
            "directory-dns-loss", lab.directory_dns_loss(self._context()))
        self.assertEqual(record["result"], "not-run")

    def test_without_a_seed_medium_the_real_seam_boots_nothing(self):
        bundle = self.root / "identity-bundle"
        bundle.mkdir(mode=0o700)
        lab = runner.LiveRecoveryLab(boot=True)
        self.assertIsNone(
            lab._open_identity_session(self._context(identity_bundle=bundle)))

    def test_close_tears_the_topology_down_once(self):
        session = FakeIdentitySession()
        guest = self._guest()
        guest.finish()
        lab = ScriptedLab((session, guest.drive))
        lab._identity_lab(self._context())
        lab.close()
        lab.close()
        self.assertEqual(session.calls, ["stop"])

    def test_the_base_lab_close_is_always_safe(self):
        runner.RecoveryLab().close()

    # -- the three hooks that stay honest stubs ---------------------------

    def test_unimplementable_hooks_return_no_live_proof(self):
        guest = self._guest()
        guest.finish()
        lab = ScriptedLab((FakeIdentitySession(), guest.drive))
        ctx = self._context()
        for hook in (lab._live_controller_restart,
                     lab._live_broken_boot_repair,
                     lab._live_failed_install_recovery):
            self.assertIsNone(hook(ctx), hook.__name__)
        # They are reached with --boot and still defer their scenario.
        for scenario, method in (
            ("controller-restart", lab.controller_restart),
            ("broken-boot-repair", lab.broken_boot_repair),
            ("failed-install-recovery", lab.failed_install_recovery),
        ):
            record = runner.record_from_observation(scenario, method(ctx))
            self.assertEqual(record["result"], "not-run", scenario)
            self.assertTrue(record["deferred_reason"], scenario)


class LiveTopologyTeardownTests(unittest.TestCase):
    """``run`` always tears the live topology down and still writes evidence."""

    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)

    def _run(self, session):
        guest = ScriptedGuest()
        self.addCleanup(guest.close)
        guest.finish()
        lab = ScriptedLab((session, guest.drive))
        ctx = runner.RunContext(
            run=self.root / "probe", releases=self.root / "pxe",
            controller_state=self.root / "controller",
            seed_iso=self.root / "seed.iso", duration=600)
        lab._identity_lab(ctx)
        run_dir = self.root / "run"
        code = runner.run(
            run_dir, releases=self.root / "pxe",
            controller_state=self.root / "controller",
            seed_iso=self.root / "seed.iso", duration=600, apply=True,
            lab=lab)
        return code, run_dir

    def test_run_stops_the_live_topology(self):
        session = FakeIdentitySession()
        code, run_dir = self._run(session)
        self.assertEqual(code, 0)
        self.assertIn("stop", session.calls)
        self.assertTrue((run_dir / "recovery-evidence.jsonl").is_file())

    def test_a_teardown_failure_never_costs_the_evidence(self):
        session = FakeIdentitySession(stop_error=RuntimeError("stuck guest"))
        code, run_dir = self._run(session)
        self.assertEqual(code, 0)
        lines = (run_dir / "recovery-evidence.jsonl").read_text().splitlines()
        self.assertEqual(len(lines), 8)
        self.assertTrue((run_dir / "result.json").is_file())


class LiveBootRunTests(unittest.TestCase):
    """A whole ``--boot`` run: the two implemented live proofs really pass."""

    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)

    def test_a_booted_run_passes_the_two_implemented_scenarios(self):
        build_release_set(self.root, "20260727.001")
        build_release_set(self.root, "20260727.005")
        seed = self.root / "seed.iso"
        seed.write_bytes(b"seed\n")
        guest = ScriptedGuest()
        self.addCleanup(guest.close)
        session = FakeIdentitySession()
        # Exactly the order ``assemble`` drives the two live hooks in.
        for check in ("arch-cached-login", "arch-uncached-denied",
                      "arch-identity-restored", "arch-joined"):
            guest.echo(check)
            guest.marker(check)
        guest.finish()
        lab = ScriptedLab((session, guest.drive))
        run_dir = self.root / "run"
        code = runner.run(
            run_dir, releases=self.root / "pxe",
            controller_state=self.root / "controller", seed_iso=seed,
            duration=600, apply=True, boot=True, lab=lab)
        self.assertEqual(code, 0)
        events = [json.loads(line) for line in
                  (run_dir / "recovery-evidence.jsonl").read_text().splitlines()]
        passed = {e["check"] for e in events if e["result"] == "pass"}
        self.assertIn("directory-dns-loss", passed)
        self.assertIn("controller-reconstruction", passed)
        result = judge.judge(judge.load_json(judge.CONTRACT), events)
        # Five of eight pass; the gate stays honestly partial until the three
        # scenarios whose primitives do not exist can be proven live.
        self.assertEqual(result["result"], "partial")
        self.assertEqual(sorted(result["deferred"]), [
            "broken-boot-repair", "controller-restart",
            "failed-install-recovery"])
        self.assertIn("stop", session.calls)


class IdentityBundleArgumentTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)

    def test_parser_exposes_identity_bundle_defaulting_off(self):
        args = runner.parser().parse_args(["--run", "run"])
        self.assertIsNone(args.identity_bundle)
        args = runner.parser().parse_args(
            ["--run", "run", "--identity-bundle", "b"])
        self.assertEqual(args.identity_bundle, Path("b"))

    def test_main_passes_the_identity_bundle_into_the_context(self):
        seen = []

        class Spy(runner.LiveRecoveryLab):
            def controller_restart(self, ctx):
                seen.append(ctx.identity_bundle)
                return super().controller_restart(ctx)

        with mock.patch.object(runner, "LiveRecoveryLab", Spy):
            code = runner.main([
                "--run", str(self.root / "run"),
                "--releases", str(self.root / "pxe"),
                "--controller-state", str(self.root / "controller"),
                "--seed-iso", str(self.root / "seed.iso"),
                "--identity-bundle", str(self.root / "bundle"),
                "--duration", "600", "--apply"])
        self.assertEqual(code, 0)
        self.assertEqual(seen, [self.root / "bundle"])


class ControllerStateDefaultTests(unittest.TestCase):
    def test_the_default_is_the_canonical_controller_image(self):
        # It once named a directory that never existed, so every live
        # identity hook deferred with "controller state must be a real
        # directory" (2026-10-01).
        from homelab.vm import bootstrap_dc
        from homelab.vm import lifecycle_recovery
        args = lifecycle_recovery.parser().parse_args(["--run", "x"])
        self.assertEqual(args.controller_state, bootstrap_dc.DEFAULT_STATE)


if __name__ == "__main__":
    unittest.main()
