"""Tests for the gate-12 login and optional-storage measurement producers.

The producer is pure and read-only: these tests build evidence streams from the
tracked contracts and never boot a guest, touch the network, or require
privilege.  Judging the retained gate-6 and gate-8 bundles is an opt-in lab
check (``TELOS_LAB_EVIDENCE=1``, see ``RetainedEvidenceTests``), never part of
the default suite.  The two measurements are also fed through the real
``factory_verify`` checks that consume them, so the producer and the verifier
are proven compatible rather than assumed so.
"""

import copy
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REPOSITORY = ROOT.parent
sys.path.insert(0, str(ROOT / "vm"))
sys.path.insert(0, str(ROOT / "workstations"))

import factory_measurements  # noqa: E402
import factory_runner  # noqa: E402
import factory_verify  # noqa: E402
import identity_lifecycle as arch_judge  # noqa: E402
import windows_identity_acceptance as windows_judge  # noqa: E402

# The two streams' valid-evidence builders already exist beside their judges'
# own tests; reusing them keeps one definition of "a stream this contract
# accepts" instead of a second copy that could drift from the contracts.
from homelab.tests.test_identity_lifecycle import (  # noqa: E402
    valid_events as arch_events,
)
from homelab.tests.test_windows_identity_acceptance import (  # noqa: E402
    valid_events as windows_events,
)

# The retained bundles named in the gate-12 mapping.  They are untracked
# local run output (homelab/var is not in the index), and HANDOFF section 5
# forbids a unit test from reading operator lab state, so the tests that judge
# them are an explicit OPT-IN lab check: they run only with
# TELOS_LAB_EVIDENCE=1, and without it nothing here so much as looks for these
# paths.  The synthetic streams below carry every one of the same assertions
# unconditionally.
LAB_EVIDENCE_OPT_IN = "TELOS_LAB_EVIDENCE"
LAB_EVIDENCE = os.environ.get(LAB_EVIDENCE_OPT_IN) == "1"
REAL_WINDOWS = (
    REPOSITORY / "homelab/var/factory/windows-installs"
    / "run-20260813T171405Z-6729c809fcab/identity"
    / "attempt-20260813T191519Z-28a9f6ee07f5/acceptance-evidence.jsonl")
REAL_ARCH = (
    REPOSITORY / "homelab/var/factory/arch-identity"
    / "run-20260814T172142Z-495164bc7159/evidence/identity-lifecycle.jsonl")

ALL_TRUE = {
    "windows": {"online": True, "offline_cached": True},
    "arch": {"online": True, "offline_cached": True},
}
ALL_FALSE = {
    "windows": {"online": False, "offline_cached": False},
    "arch": {"online": False, "offline_cached": False},
}


def _measurements(login=None, storage=None):
    """A measurements block carrying only the two fields under test."""
    block = {}
    if login is not None:
        block["login"] = login
    if storage is not None:
        block["optional_storage_absence_nonblocking"] = storage
    return block


class MeasurementBase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.windows_contract = windows_judge.load_json(windows_judge.CONTRACT)
        cls.arch_contract = arch_judge.load_json(arch_judge.CONTRACT)

    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)

    def write(self, name, events):
        path = self.root / name
        path.write_text(
            "".join(json.dumps(event) + "\n" for event in events),
            encoding="utf-8")
        return path

    def windows_stream(self, mutate=None):
        events = copy.deepcopy(windows_events(self.windows_contract))
        if mutate is not None:
            events = mutate(events)
        return self.write("windows.jsonl", events)

    def arch_stream(self, mutate=None):
        events = copy.deepcopy(arch_events(self.arch_contract))
        if mutate is not None:
            events = mutate(events)
        return self.write("arch.jsonl", events)


class SyntheticEvidenceTests(MeasurementBase):
    """Streams built from the tracked contracts, so these always run."""

    def test_two_accepted_streams_prove_every_login_and_the_storage_field(self):
        windows = self.windows_stream()
        arch = self.arch_stream()
        self.assertEqual(
            ALL_TRUE, factory_measurements.login_measurement(windows, arch))
        self.assertIs(
            True,
            factory_measurements.optional_storage_measurement(windows, arch))
        self.assertEqual(
            {"login": ALL_TRUE, "optional_storage_absence_nonblocking": True},
            factory_measurements.identity_measurements(windows, arch))

    def test_login_shape_is_exactly_what_the_check_reads(self):
        login = factory_measurements.login_measurement(
            self.windows_stream(), self.arch_stream())
        self.assertEqual({"windows", "arch"}, set(login))
        for system in ("windows", "arch"):
            self.assertEqual({"online", "offline_cached"}, set(login[system]))
            for value in login[system].values():
                self.assertIsInstance(value, bool)

    def test_only_booleans_leave_the_producer(self):
        # No path, hostname, run identifier, or credential reaches a caller.
        block = factory_measurements.identity_measurements(
            self.windows_stream(), self.arch_stream())
        rendered = json.dumps(block, sort_keys=True)
        self.assertNotIn("/", rendered)
        for value in list(block["login"].values()) + [block["login"]]:
            self.assertIsInstance(value, dict)
        self.assertIsInstance(
            block["optional_storage_absence_nonblocking"], bool)

    def test_the_emitted_vocabulary_is_the_permitted_one(self):
        # A producer that drifted from MEASUREMENT_KEYS would emit evidence no
        # check ever reads; measurement_block refuses to widen them.
        block = factory_measurements.identity_measurements(
            self.windows_stream(), self.arch_stream())
        self.assertLessEqual(set(block), factory_runner.MEASUREMENT_KEYS)
        self.assertEqual(block, factory_runner.measurement_block(**block))

    # -- fail closed -------------------------------------------------------

    def test_missing_files_are_false_not_optimistic(self):
        absent = self.root / "does-not-exist.jsonl"
        cases = (
            ("neither stream", None, None, ALL_FALSE),
            ("both absent", absent, absent, ALL_FALSE),
            ("Windows only", self.windows_stream(), absent,
             {"windows": ALL_TRUE["windows"], "arch": ALL_FALSE["arch"]}),
            ("Arch only", None, self.arch_stream(),
             {"windows": ALL_FALSE["windows"], "arch": ALL_TRUE["arch"]}),
        )
        for label, windows, arch, expected in cases:
            with self.subTest(case=label):
                self.assertEqual(
                    expected,
                    factory_measurements.login_measurement(windows, arch))
                # Check 14 needs both sides, so every partial case is False.
                self.assertIs(
                    False,
                    factory_measurements.optional_storage_measurement(
                        windows, arch))

    def test_a_failing_cached_login_record_is_not_a_cached_login(self):
        def fail_cached(events):
            for event in events:
                if event["check"] == "arch-cached-login":
                    event["result"] = "fail"
            return events

        login = factory_measurements.login_measurement(
            self.windows_stream(), self.arch_stream(fail_cached))
        self.assertIs(False, login["arch"]["offline_cached"])
        # The whole stream is rejected, not just the one record: the judge
        # validates ordering, uniqueness, and the envelope across the file, so
        # a record lifted out of a stream the judge refuses proves nothing.
        self.assertEqual(ALL_FALSE["arch"], login["arch"])
        # The Windows stream is independent and still proves its own logins.
        self.assertEqual(ALL_TRUE["windows"], login["windows"])

    def test_an_unproven_cached_login_record_is_not_a_cached_login(self):
        def uncached(events):
            for event in events:
                if event["check"] == "arch-cached-login":
                    event["cached"] = False
            return events

        login = factory_measurements.login_measurement(
            self.windows_stream(), self.arch_stream(uncached))
        self.assertIs(False, login["arch"]["offline_cached"])

    def test_a_missing_record_is_false(self):
        def drop_cached(events):
            return [e for e in events if e["check"] != "arch-cached-login"]

        def drop_storage(events):
            return [
                e for e in events if e["check"] != "arch-storage-absent-login"]

        windows = self.windows_stream()
        self.assertEqual(
            ALL_FALSE["arch"],
            factory_measurements.login_measurement(
                windows, self.arch_stream(drop_cached))["arch"])
        self.assertIs(
            False,
            factory_measurements.optional_storage_measurement(
                windows, self.arch_stream(drop_storage)))

    def test_malformed_evidence_is_false_not_skipped(self):
        for name, content in (
                ("truncated.jsonl", '{"check": "arch-cached-login"'),
                ("not-jsonl.jsonl", "arch-cached-login: pass\n"),
                ("array.jsonl", "[1, 2, 3]\n"),
                ("empty.jsonl", "")):
            with self.subTest(name=name):
                broken = self.root / name
                broken.write_text(content, encoding="utf-8")
                self.assertEqual(
                    ALL_FALSE,
                    factory_measurements.login_measurement(broken, broken))
                self.assertIs(
                    False,
                    factory_measurements.optional_storage_measurement(
                        broken, broken))

    def test_a_symlinked_or_oversized_stream_is_refused(self):
        arch = self.arch_stream()
        link = self.root / "linked.jsonl"
        os.symlink(arch, link)
        self.assertEqual(
            ALL_FALSE["arch"],
            factory_measurements.login_measurement(None, link)["arch"])

        oversized = self.root / "oversized.jsonl"
        oversized.write_bytes(
            arch.read_bytes()
            + b"\n" * (factory_measurements.EVIDENCE_LIMIT + 1))
        self.assertEqual(
            ALL_FALSE["arch"],
            factory_measurements.login_measurement(None, oversized)["arch"])

    def test_a_directory_is_refused(self):
        self.assertEqual(
            ALL_FALSE, factory_measurements.login_measurement(
                self.root, self.root))

    def test_an_out_of_bound_login_does_not_prove_nonblocking_absence(self):
        def slow(events):
            for event in events:
                if event["check"] == "arch-storage-absent-login":
                    event["login_seconds"] = event["login_bound_seconds"] + 1
            return events

        self.assertIs(
            False,
            factory_measurements.optional_storage_measurement(
                self.windows_stream(), self.arch_stream(slow)))

    def test_one_systems_storage_proof_is_half_a_proof(self):
        # Check 14 speaks for the whole run, so an unproven side is False even
        # when the other side is impeccable.
        self.assertIs(
            False,
            factory_measurements.optional_storage_measurement(
                self.windows_stream(), None))
        self.assertIs(
            False,
            factory_measurements.optional_storage_measurement(
                None, self.arch_stream()))

    # -- the restated per-record expectations only ever narrow -------------

    def test_a_record_that_a_looser_contract_admitted_is_still_refused(self):
        # Stage 2 exists for a contract that stopped asserting a decisive
        # field; a stream is simulated as accepted and the record inspected
        # directly.  Zero is not False and one is not True here, either.
        proves = factory_measurements._proves
        stream = factory_measurements._Stream(
            {
                "arch-cached-login": {
                    "check": "arch-cached-login", "result": "pass",
                    "external_access": False, "controller_online": False,
                    "cached": True},
            },
            arch_judge.LOGIN_BOUND_SECONDS,
        )
        fields = factory_measurements._ARCH_FIELDS["arch-cached-login"]
        self.assertIs(True, proves(stream, "arch-cached-login", fields))
        for field, value in (
                ("cached", 1), ("cached", "true"), ("controller_online", 0),
                ("result", "observed"), ("external_access", None)):
            with self.subTest(field=field, value=value):
                record = dict(stream.by_check["arch-cached-login"])
                record[field] = value
                narrowed = factory_measurements._Stream(
                    {"arch-cached-login": record}, arch_judge.LOGIN_BOUND_SECONDS)
                self.assertIs(
                    False, proves(narrowed, "arch-cached-login", fields))

    def test_a_bounded_login_needs_the_contracts_own_bound(self):
        proves = factory_measurements._proves
        fields = factory_measurements._ARCH_FIELDS["arch-storage-absent-login"]
        base = {
            "check": "arch-storage-absent-login", "result": "pass",
            "external_access": False, "storage_reachable": False,
            "mount_state": "absent", "login": "allowed",
            "login_path_independent": True, "login_seconds": 4,
            "login_bound_seconds": arch_judge.LOGIN_BOUND_SECONDS,
        }
        bound = arch_judge.LOGIN_BOUND_SECONDS
        self.assertIs(
            True,
            proves(
                factory_measurements._Stream(
                    {base["check"]: base}, bound), base["check"], fields))
        for override in (
                {"login_seconds": -1}, {"login_seconds": float("nan")},
                {"login_seconds": True}, {"login_seconds": "4"},
                {"login_seconds": None},
                {"login_bound_seconds": bound * 2}):
            with self.subTest(override=override):
                record = {**base, **override}
                self.assertIs(
                    False,
                    proves(
                        factory_measurements._Stream(
                            {base["check"]: record}, bound),
                        base["check"], fields))


class VerifierCompatibilityTests(MeasurementBase):
    """The producer's output, fed through the checks that consume it."""

    def assert_renders(self, login, storage, expected):
        block = _measurements(login, storage)
        self.assertEqual(
            expected, factory_verify._check_login(block)["status"])
        self.assertEqual(
            expected, factory_verify._check_optional_storage(block)["status"])

    def test_two_accepted_streams_render_checks_13_and_14_as_pass(self):
        block = factory_measurements.identity_measurements(
            self.windows_stream(), self.arch_stream())
        self.assert_renders(
            block["login"], block["optional_storage_absence_nonblocking"],
            factory_verify.PASS)
        # And by the names the receipt actually uses.
        receipt_checks = {
            "both_os_online_and_cached_offline_login":
                factory_verify._check_login(block),
            "optional_storage_absence_nonblocking":
                factory_verify._check_optional_storage(block),
        }
        for name in receipt_checks:
            self.assertIn(name, factory_verify.CHECK_NAMES)
            self.assertEqual(factory_verify.PASS, receipt_checks[name]["status"])

    def test_an_unproven_stream_renders_fail_never_pass(self):
        block = factory_measurements.identity_measurements(None, None)
        self.assert_renders(
            block["login"], block["optional_storage_absence_nonblocking"],
            factory_verify.FAIL)

    def test_an_omitted_field_stays_not_run(self):
        # The honest outcome for a run that observed no identity evidence at
        # all: factory_runner.measurement_block drops a None, and NOT-RUN is
        # never promoted to PASS.
        block = factory_runner.measurement_block(
            login=None, optional_storage_absence_nonblocking=None)
        self.assertEqual({}, block)
        self.assertEqual(
            factory_verify.NOT_RUN, factory_verify._check_login(block)["status"])
        self.assertEqual(
            factory_verify.NOT_RUN,
            factory_verify._check_optional_storage(block)["status"])


@unittest.skipUnless(
    LAB_EVIDENCE,
    f"opt-in lab check: set {LAB_EVIDENCE_OPT_IN}=1 to judge the retained "
    "gate-6 and gate-8 evidence bundles on this host")
class RetainedEvidenceTests(unittest.TestCase):
    """OPT-IN LAB CHECK: the real retained proofs the gate-12 mapping cites.

    Not a unit test: it reads operator run state under ``homelab/var``, which
    no default-suite test may do.  Every assertion here is also made about
    synthetic streams above, so the default suite loses no coverage of the
    code; what this adds is a statement about THIS host's evidence -- that the
    bundles the mapping names still exist and still pass their own judges.
    Opting in says they should be here, so a missing bundle fails rather than
    skips.
    """

    @classmethod
    def setUpClass(cls):
        missing = [
            str(path.relative_to(REPOSITORY))
            for path in (REAL_WINDOWS, REAL_ARCH) if not path.is_file()]
        if missing:
            raise AssertionError(
                f"{LAB_EVIDENCE_OPT_IN}=1 but the retained evidence is not "
                f"on this host: {', '.join(missing)}")

    def test_the_retained_bundles_prove_every_login(self):
        self.assertEqual(
            ALL_TRUE,
            factory_measurements.login_measurement(REAL_WINDOWS, REAL_ARCH))

    def test_the_retained_bundles_prove_nonblocking_storage_absence(self):
        self.assertIs(
            True,
            factory_measurements.optional_storage_measurement(
                REAL_WINDOWS, REAL_ARCH))

    def test_the_retained_bundles_render_checks_13_and_14_as_pass(self):
        block = factory_measurements.identity_measurements(
            REAL_WINDOWS, REAL_ARCH)
        self.assertEqual(
            factory_verify.PASS, factory_verify._check_login(block)["status"])
        self.assertEqual(
            factory_verify.PASS,
            factory_verify._check_optional_storage(block)["status"])
        self.assertEqual(block, factory_runner.measurement_block(**block))

    def test_the_retained_bundles_are_what_their_own_judges_accept(self):
        # The mapping claims nothing its judge would not: both retained streams
        # pass their real judge, which is the whole of stage 1.
        windows = windows_judge.judge(
            windows_judge.load_json(windows_judge.CONTRACT),
            windows_judge.load_events(
                REAL_WINDOWS.read_text(encoding="utf-8").splitlines()))
        arch = arch_judge.judge(
            arch_judge.load_json(arch_judge.CONTRACT),
            arch_judge.load_events(
                REAL_ARCH.read_text(encoding="utf-8").splitlines()))
        self.assertEqual("pass", windows["result"])
        self.assertEqual("pass", arch["result"])

    def test_only_booleans_leave_the_producer(self):
        # No path, hostname, run identifier, or credential reaches a caller.
        block = factory_measurements.identity_measurements(
            REAL_WINDOWS, REAL_ARCH)
        rendered = json.dumps(block, sort_keys=True)
        self.assertNotIn("/", rendered)
        for value in list(block["login"].values()) + [block["login"]]:
            self.assertIsInstance(value, dict)
        self.assertIsInstance(
            block["optional_storage_absence_nonblocking"], bool)


if __name__ == "__main__":
    unittest.main()
