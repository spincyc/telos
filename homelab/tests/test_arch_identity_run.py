"""Prove the Arch identity producer and the real judge agree end-to-end.

These tests never boot QEMU or open a real serial console. They drive
``ArchIdentityDrive`` with a scripted serial double, assemble evidence, and
feed it to the *real* ``identity_lifecycle.judge`` imported from the
workstations judge, so the producer and the grader are proven to agree without
a live guest. They also assert dry-run gating and fail-closed bundle
validation.
"""

import io
import json
import os
import re
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

from homelab.vm import arch_identity_run
from homelab.vm.arch_identity_run import (
    ArchIdentityBoundary,
    ArchIdentityBundle,
    ArchIdentityDrive,
    ArchIdentityError,
    BOOT_FACTS_FILENAME,
    CHECK_DETAILS,
    DOMAIN_ONLINE_FAILURE,
    DOMAIN_ONLINE_TIMEOUT,
    GETTY_NEVER_APPEARED_FAILURE,
    JOIN_FAILURE,
    JOIN_PRINCIPAL_NOT_DESTROYED_FAILURE,
    LOGIN_ATTEMPTS,
    LOGIN_REFUSED_FAILURE,
    MAX_DURATION,
    MEASURED_CHECK_FIELDS,
    MENU_NEVER_RENDERED_FAILURE,
    MENU_NOT_COMMITTED_FAILURE,
    MENU_WINDOW_MISSED_FAILURE,
    OPERATOR_PRINCIPAL,
    REQUIRED_CHECKS,
    RESCUE_CONFIRM_PROMPT_MISSING_FAILURE,
    RESCUE_CREDENTIAL_REJECTED_FAILURE,
    RESCUE_ECHO_NOT_SUPPRESSED_FAILURE,
    RESCUE_PASSWD_EXITED_FAILURE,
    RESCUE_PASSWORD_FAILURE,
    RESCUE_PASSWORD_WRITES,
    RESCUE_PRINCIPAL,
    RESCUE_PROMPT_MISSING_FAILURE,
    RESCUE_UPDATED_DIAGNOSTIC,
    ROSTER,
    ROSTER_FINGERPRINT,
    ROSTER_MISMATCH_FAILURE,
    ROSTER_UNREPORTED_FAILURE,
    SUDO_CREDENTIAL_REFUSED_FAILURE,
    SUDO_ECHO_NOT_SUPPRESSED_FAILURE,
    SUDO_ELEVATION_FAILURE,
    SUDO_EXITED_FAILURE,
    SUDO_PROMPT_MISSING_FAILURE,
    SUDO_PROOF_ASKS,
    SUDO_ROOT_UNPROVEN_FAILURE,
    WINDOWS_CHECKS,
    WORKSTATION_LOG_FILENAME,
    assemble_evidence,
    audit_arch_identity_boot,
    await_domain_online,
    drive_boot_menu,
    elevate_operator,
    elevation_command,
    elevation_outcome_pattern,
    login_operator,
    new_boot_facts,
    rescue_outcome_pattern,
    rescue_password_command,
    rescue_prompt_pattern,
    root_proof_marker,
    run,
    run_lifecycle,
    self_judge,
    set_rescue_password,
    workstation_boot_command,
)
from homelab.vm.arch_install_run import (
    build_arch_join_iso as _REAL_BUILD_JOIN_ISO,
)
from homelab.vm.dualboot_acceptance import (
    MENU_ARCH_ENTRY,
    MENU_FIRMWARE_ENTRY,
    MENU_WINDOWS_ENTRY,
)

# The real judge, imported exactly as the shim and the producer do.
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "workstations"))
import identity_lifecycle as lifecycle  # noqa: E402

# The checks the live Arch drive is responsible for, in drive order.
ARCH_DRIVE_CHECKS = (
    "arch-joined",
    "arch-standard-online",
    "arch-daily-admin",
    "domain-admin-separate",
    "arch-cached-login",
    "arch-uncached-denied",
    "arch-local-rescue",
    "arch-identity-restored",
    "arch-storage-attached",
    "arch-storage-denied",
    "arch-storage-absent-login",
)
CONTROLLER_OUTCOME_CHECKS = (
    "controller-ready", "controller-offline", "controller-restored")

# The measured data lines each check prints before its verdict, taken from the
# same marker maps the rendered probe and the drive share, so the double cannot
# drift from the real console contract.
sys.path.insert(0, str(ROOT))
from workstations.arch_second import (  # noqa: E402
    PROBE_ROSTER_VERB,
    STORAGE_ATTACHED_MEASUREMENT_MARKERS,
    STORAGE_LOGIN_SECONDS_MARKER,
)
from vm.controller_principals import POSIX_ALLOCATION  # noqa: E402

MEASURED_MARKERS: dict[str, dict[str, str]] = {
    "arch-storage-attached": dict(STORAGE_ATTACHED_MEASUREMENT_MARKERS),
    "arch-storage-absent-login": {
        "login_seconds": STORAGE_LOGIN_SECONDS_MARKER},
}
# What a converging guest measures.  The UID/GID pair is the directory's own
# staged rfc2307 allocation for the mounting principal, not a chosen number:
# the producer refuses a storage pass whose identifiers disagree with it.
_STAGED_OPERATOR = POSIX_ALLOCATION["users"][OPERATOR_PRINCIPAL]
DEFAULT_MEASUREMENTS: dict[str, int] = {
    "owner_uid": int(_STAGED_OPERATOR["uidNumber"]),
    "owner_gid": int(_STAGED_OPERATOR["gidNumber"]),
    "file_mtime": 1786000000,
    "login_seconds": 4,
}


class _FakeMatch:
    """Match double whose numbered *and named* groups are scripted."""

    def __init__(self, groups) -> None:
        if not isinstance(groups, dict):
            groups = {1: groups}
        self._groups = groups

    def group(self, index=0):
        return self._groups.get(index)


class FakeSerialChannel:
    """A scripted stand-in for SerialAutomation's low-level surface.

    ``results`` maps a check name to "PASS", "FAIL", or "TIMEOUT". Two further
    verdicts model a guest that answers without the measurements its check
    requires: "PASS_WITHOUT_SECONDS" (historical name, storage-absent) and
    "PASS_WITHOUT_MEASUREMENT" (any measured check) withhold every data line.
    The channel records every command it is asked to send, emits one data line
    per measured field of ``MEASURED_MARKERS`` and then the scripted verdict,
    so a drive can be exercised deterministically.
    """

    def __init__(self, results: dict[str, str], *,
                 login_seconds: int = 4,
                 roster_fingerprint: str | None = None,
                 measurements: dict[str, int] | None = None) -> None:
        self.token = "deadbeefcafef00d"
        self.results = results
        # What the guest's probe answers the roster verb with.  Defaults to the
        # roster this host resolved, i.e. a disk installed under the same
        # roster; a test overrides it to model a disk installed under another.
        self.roster_fingerprint = (
            ROSTER_FINGERPRINT if roster_fingerprint is None
            else roster_fingerprint)
        self.measurements = dict(DEFAULT_MEASUREMENTS)
        self.measurements["login_seconds"] = login_seconds
        if measurements:
            self.measurements.update(measurements)
        self.sent: list[bytes] = []
        self._pending: str | None = None
        self._data_lines_sent = 0

    @property
    def login_seconds(self) -> int:
        return self.measurements["login_seconds"]

    @login_seconds.setter
    def login_seconds(self, value: int) -> None:
        self.measurements["login_seconds"] = value

    def _send(self, value: bytes, event: str) -> None:
        self.sent.append(value)
        parts = value.decode("ascii").split()
        # /usr/local/sbin/homelab-arch-identity-probe <check> <token>
        self._pending = parts[1]
        self._data_lines_sent = 0

    def _wait(self, pattern: bytes, label: str):
        check = self._pending
        verdict = self.results.get(check, "PASS")
        if verdict == "TIMEOUT":
            from homelab.vm.serial_automation import SerialAutomationError
            raise SerialAutomationError(f"timed out waiting for {label}")
        # Prove the drive built a token-scoped, check-specific marker pattern.
        key = check.upper().replace("-", "_")
        expected = f"__TELOS_ARCH_{key}_{self.token}=".encode("ascii")
        assert re.escape(expected) in pattern, (pattern, expected)
        if check == PROBE_ROSTER_VERB:
            # The roster verb answers with a fingerprint, never a verdict.
            return _FakeMatch(self.roster_fingerprint.encode("ascii"))
        markers = MEASURED_MARKERS.get(check, {})
        fields = list(markers)
        withheld = verdict in (
            "PASS_WITHOUT_SECONDS", "PASS_WITHOUT_MEASUREMENT")
        if fields and not withheld and self._data_lines_sent < len(fields):
            index = self._data_lines_sent
            field = fields[index]
            # The drive must have built a token-scoped pattern for this data
            # marker too, or a real guest's line would never be read.
            marker = f"{markers[field]}{self.token}=".encode("ascii")
            assert re.escape(marker) in pattern, (pattern, marker)
            self._data_lines_sent += 1
            groups = {position: None for position in range(1, len(fields) + 2)}
            groups[index + 1] = str(self.measurements[field]).encode("ascii")
            return _FakeMatch(groups)
        passed = verdict.startswith("PASS")
        groups = {position: None for position in range(1, len(fields) + 1)}
        groups[len(fields) + 1] = b"PASS" if passed else b"FAIL"
        return _FakeMatch(groups)


def passing_windows_events() -> list[dict[str, object]]:
    """The Windows lane's produced evidence, in its canonical passing shape."""
    return [
        {"check": check, "result": "pass", "external_access": False,
         **CHECK_DETAILS[check]}
        for check in WINDOWS_CHECKS
    ]


class FakeSession:
    """A deterministic ArchIdentitySession for run_lifecycle/run tests."""

    def __init__(
        self,
        drive_results: dict[str, str] | None = None,
        controller_results: dict[str, bool] | None = None,
        windows_events: list[dict[str, object]] | None = None,
        stop_failures: list[str] | None = None,
        roster_fingerprint: str | None = None,
    ) -> None:
        self.channel = FakeSerialChannel(
            drive_results or {}, roster_fingerprint=roster_fingerprint)
        self.controller_results = controller_results or {}
        self._windows_events = (
            passing_windows_events() if windows_events is None
            else windows_events)
        self._stop_failures = stop_failures or []
        self.events: list[str] = []

    def start(self) -> None:
        self.events.append("start")

    def open_channel(self):
        self.events.append("open_channel")
        return self.channel

    def observe_controller_ready(self) -> bool:
        return self.controller_results.get("controller-ready", True)

    def take_controller_offline(self) -> None:
        self.events.append("offline")

    def observe_controller_offline(self) -> bool:
        return self.controller_results.get("controller-offline", True)

    def restore_controller(self) -> None:
        self.events.append("restore")

    def observe_controller_restored(self) -> bool:
        return self.controller_results.get("controller-restored", True)

    def make_storage_unreachable(self) -> None:
        self.events.append("storage-absent")

    def windows_evidence(self) -> list[dict[str, object]]:
        return self._windows_events

    def stop(self) -> list[str]:
        self.events.append("stop")
        return list(self._stop_failures)


def make_bundle(root: Path, *, with_disk: bool = True,
                authorization: dict | None = None,
                with_windows: bool = True) -> ArchIdentityBundle:
    bundle = root / "bundle"
    controller = root / "controller"
    bundle.mkdir(mode=0o700)
    controller.mkdir(mode=0o700)
    if with_disk:
        for name in ("arch-workstation.qcow2", "OVMF_VARS.fd"):
            path = bundle / name
            path.write_bytes(name.encode())
            path.chmod(0o600)
    if authorization is None:
        authorization = {
            "status": "prepared",
            "external_access": False,
            "installation_media_attached": False,
            "pxe_boot_enabled": False,
            "domain_joined": True,
            "realm": "TELOS.EXAMPLE",
        }
    (bundle / "authorization.json").write_text(
        json.dumps(authorization), encoding="utf-8")
    if with_windows:
        (bundle / "windows-evidence.jsonl").write_text(
            "".join(json.dumps(item) + "\n"
                    for item in passing_windows_events()),
            encoding="utf-8")
    return ArchIdentityBundle(bundle, controller)


# --------------------------------------------------------------------------
# Producer / judge agreement.
# --------------------------------------------------------------------------

class ProducerJudgeAgreementTests(unittest.TestCase):
    def setUp(self):
        self.contract = lifecycle.load_json(lifecycle.CONTRACT)

    def test_check_details_match_the_valid_events_fixture(self):
        # The producer's field templates must equal the fixture the judge is
        # exercised with, or the two could silently diverge.  Fields the
        # producer measures live (MEASURED_CHECK_FIELDS) are excluded from the
        # static template; the fixture is the JUDGE's contract, so it carries
        # only the measured fields the judge itself grades (see
        # test_judge_graded_measurements_are_in_the_fixture).
        from homelab.tests.test_identity_lifecycle import valid_events
        for item in valid_events(self.contract):
            check = item["check"]
            fields = {k: v for k, v in item.items()
                      if k not in {"check", "result", "external_access"}}
            measured = set(MEASURED_CHECK_FIELDS.get(check, ()))
            # Nothing may appear in the fixture from nowhere: every field is
            # either a static template field or one the producer measures.
            self.assertEqual(
                set(fields) - measured, set(CHECK_DETAILS[check]), check)
            static = {k: v for k, v in fields.items() if k not in measured}
            self.assertEqual(static, CHECK_DETAILS[check], check)

    def test_probe_console_bound_covers_the_longest_probe(self):
        # A probe that is about to report a diagnosed FAIL must not be cut off
        # and reported as a bare console timeout: that loses exactly the
        # evidence the diagnostics exist to produce, which is what cost the
        # 2026-08-14 run its storage diagnosis.  The bound is therefore derived
        # from the rendered probe's own bounds, not chosen.
        from workstations.arch_second import (
            DIAGNOSTIC_COMMAND_SECONDS, PROBE_DOMAIN_WAIT_TRIES,
            PROBE_LOOKUP_WAIT_TRIES, JOIN_WAIT_SECONDS, render_installer)
        domain_wait = PROBE_DOMAIN_WAIT_TRIES * JOIN_WAIT_SECONDS
        # arch-storage-denied: domain wait, reachability, two bounded mounts,
        # the eight-field failure diagnosis and the refusal field.  The field
        # count is read off the rendered probe so adding a field cannot quietly
        # push the longest check past its own console bound.
        fields = render_installer(
            disk_path="/dev/vda", disk_serial="LAPTOP-1",
            hostname="workstation",
            expected_sizes_mib=(1024, 16, 307200, 102400, 2048),
        ).split("storage_diagnose() {")[1].split("\n}\n")[0].count("\n  note")
        self.assertEqual(fields, 8)
        worst_storage = (
            domain_wait + 5 + 20 + fields * DIAGNOSTIC_COMMAND_SECONDS
            + 20 + DIAGNOSTIC_COMMAND_SECONDS)
        # arch-identity-restored: two bounded waits and two diagnostic fields.
        worst_identity = (
            domain_wait + PROBE_LOOKUP_WAIT_TRIES * JOIN_WAIT_SECONDS
            + 2 * DIAGNOSTIC_COMMAND_SECONDS)
        self.assertGreaterEqual(
            arch_identity_run.PROBE_TIMEOUT, worst_storage)
        self.assertGreaterEqual(
            arch_identity_run.PROBE_TIMEOUT, worst_identity)
        # The lookup wait is deliberately the SHORTER of the two: it is sized
        # against the 15s nss negative-cache window, not against a reconnect.
        self.assertLess(
            PROBE_LOOKUP_WAIT_TRIES * JOIN_WAIT_SECONDS, domain_wait)
        self.assertGreater(PROBE_LOOKUP_WAIT_TRIES * JOIN_WAIT_SECONDS, 15)

    def test_judge_graded_measurements_are_in_the_fixture(self):
        # login_seconds is graded by the judge, so the judge's own fixture must
        # carry it.  The three arch-storage-attached measurements are NOT graded
        # by the judge: gate 9's contract row requires them to be RECORDED
        # ("Record UID/GID and timestamp measurements before reconsidering
        # NFS"), and an audit found the probe emitted none of them, so this
        # producer enforces them instead.  That asymmetry is deliberate and
        # stated here so a later reader does not "fix" it by loosening the
        # producer.
        from homelab.tests.test_identity_lifecycle import valid_events
        fixture = {item["check"]: item for item in valid_events(self.contract)}
        self.assertIn(
            "login_seconds", fixture["arch-storage-absent-login"])
        for name in MEASURED_CHECK_FIELDS["arch-storage-attached"]:
            self.assertNotIn(name, fixture["arch-storage-attached"])
        self.assertEqual(
            MEASURED_CHECK_FIELDS["arch-storage-attached"],
            ("owner_uid", "owner_gid", "file_mtime"))

    def test_producer_order_matches_the_contract(self):
        self.assertEqual(
            list(REQUIRED_CHECKS), self.contract["required_checks"])

    def test_simulated_successful_drive_is_accepted_by_the_real_judge(self):
        session = FakeSession()
        events = run_lifecycle(session)
        # The full, ordered required-check stream the real judge accepts.
        result = lifecycle.judge(self.contract, events)
        self.assertEqual(result["result"], "pass")
        self.assertEqual(result["checks"], len(REQUIRED_CHECKS))
        self.assertFalse(result["external_access"])
        # The whole lifecycle was driven, with the outage between the cache
        # proofs and the storage target removed before the absent proof.
        self.assertEqual(
            session.events,
            ["start", "open_channel", "offline", "restore",
             "storage-absent", "stop"])

    def test_measured_login_seconds_are_produced_not_templated(self):
        session = FakeSession()
        session.channel.login_seconds = 7
        events = run_lifecycle(session)
        absent = next(
            item for item in events
            if item["check"] == "arch-storage-absent-login")
        self.assertEqual(absent["login_seconds"], 7)
        self.assertEqual(
            absent["login_bound_seconds"],
            self.contract["login_bound_seconds"])
        lifecycle.judge(self.contract, events)

    def test_storage_absent_pass_without_measurement_is_refused(self):
        session = FakeSession(
            drive_results={
                "arch-storage-absent-login": "PASS_WITHOUT_SECONDS"})
        with self.assertRaisesRegex(
                ArchIdentityError,
                "passed without its measured login_seconds") as caught:
            run_lifecycle(session)
        self.assertEqual(
            caught.exception.check, "arch-storage-absent-login")
        self.assertIn("stop", session.events)

    def test_storage_attached_pass_without_measurements_is_refused(self):
        # Gate 9's UID/GID and timestamp measurements are enforced the same way
        # the login duration is: a guest that answers PASS without printing them
        # is a producer failure, never an event with a fabricated number in it.
        session = FakeSession(
            drive_results={
                "arch-storage-attached": "PASS_WITHOUT_MEASUREMENT"})
        with self.assertRaisesRegex(
                ArchIdentityError,
                "passed without its measured owner_uid, owner_gid, "
                "file_mtime") as caught:
            run_lifecycle(session)
        self.assertEqual(caught.exception.check, "arch-storage-attached")
        self.assertIn("stop", session.events)

    def test_a_partial_read_cannot_truncate_a_measurement(self):
        # The live 2026-08-14 run read owner_uid=1 from a guest that printed
        # 10001: the alternation had no line anchor, so a serial chunk boundary
        # inside the number matched its leading digits and the rest was trimmed
        # away with the consumed buffer. The identity guard then refused a pass
        # the guest had genuinely earned.
        import re as _re
        from homelab.vm.arch_identity_run import measured_probe_pattern

        pattern = _re.compile(
            measured_probe_pattern(
                ["__TELOS_ARCH_STORAGE_OWNER_UID_"], "tok", b"__V_tok="),
            _re.MULTILINE)
        # Every prefix of the real line, up to but not including its
        # terminator, must match nothing at all.
        line = b"__TELOS_ARCH_STORAGE_OWNER_UID_tok=10001\r\n"
        for cut in range(len(line) - 2):
            self.assertIsNone(
                pattern.search(line[:cut]),
                f"a read cut at {cut} bytes matched a partial value")
        found = pattern.search(line)
        self.assertIsNotNone(found)
        self.assertEqual(found.group(1), b"10001")

    def test_storage_measurements_reach_the_evidence(self):
        session = FakeSession()
        session.channel.measurements["file_mtime"] = 1786000123
        events = run_lifecycle(session)
        attached = next(item for item in events
                        if item["check"] == "arch-storage-attached")
        staged = POSIX_ALLOCATION["users"][OPERATOR_PRINCIPAL]
        self.assertEqual(attached["owner_uid"], int(staged["uidNumber"]))
        self.assertEqual(attached["owner_gid"], int(staged["gidNumber"]))
        self.assertEqual(attached["file_mtime"], 1786000123)
        # The measurements are additive: the judged fields are untouched.
        for name, value in CHECK_DETAILS["arch-storage-attached"].items():
            self.assertEqual(attached[name], value)
        lifecycle.judge(self.contract, events)

    def test_storage_uid_gid_must_be_the_staged_directory_identity(self):
        # Recording the identifiers proves they were observed; comparing them
        # against the Controller's deterministic rfc2307 allocation is what
        # makes them a proof of UID/GID stability.  A mismatch means SSSD
        # resolved the principal through some other mapping -- exactly what
        # ldap_id_mapping = False exists to prevent -- and that is a lifecycle
        # failure, not a number to record and move past.
        staged = POSIX_ALLOCATION["users"][OPERATOR_PRINCIPAL]
        for field, wrong in (
            ("owner_uid", int(staged["uidNumber"]) + 1),
            ("owner_gid", int(staged["gidNumber"]) + 1),
        ):
            with self.subTest(field=field):
                session = FakeSession()
                session.channel.measurements[field] = wrong
                with self.assertRaisesRegex(
                        ArchIdentityError,
                        f"measured {field}={wrong}") as caught:
                    run_lifecycle(session)
                self.assertEqual(
                    caught.exception.check, "arch-storage-attached")
                self.assertIn("stop", session.events)

    def test_drive_builds_token_scoped_probe_commands(self):
        channel = FakeSerialChannel({})
        drive = ArchIdentityDrive(channel)
        self.assertTrue(drive.prove_joined())
        self.assertTrue(drive.prove_uncached_denied())
        self.assertIn(
            b"/usr/local/sbin/homelab-arch-identity-probe arch-joined "
            b"deadbeefcafef00d",
            channel.sent)

    def test_failure_at_each_arch_stage_is_rejected_at_that_check(self):
        for stage in ARCH_DRIVE_CHECKS:
            with self.subTest(stage=stage):
                session = FakeSession(drive_results={stage: "FAIL"})
                events = run_lifecycle(session)
                # The producer still emits a full stream; the judge rejects it,
                # and the first non-pass event is exactly the failed stage.
                with self.assertRaises(lifecycle.EvidenceError) as caught:
                    lifecycle.judge(self.contract, events)
                self.assertIn(stage, str(caught.exception))
                failed = next(e for e in events if e["check"] == stage)
                self.assertEqual(failed["result"], "fail")

    def test_failure_at_each_controller_stage_is_rejected(self):
        for stage in CONTROLLER_OUTCOME_CHECKS:
            with self.subTest(stage=stage):
                session = FakeSession(controller_results={stage: False})
                events = run_lifecycle(session)
                with self.assertRaises(lifecycle.EvidenceError) as caught:
                    lifecycle.judge(self.contract, events)
                self.assertIn(stage, str(caught.exception))

    def test_serial_timeout_binds_the_error_to_its_stage(self):
        session = FakeSession(drive_results={"arch-cached-login": "TIMEOUT"})
        with self.assertRaises(ArchIdentityError) as caught:
            run_lifecycle(session)
        self.assertEqual(caught.exception.check, "arch-cached-login")
        # Teardown still ran despite the mid-lifecycle console failure.
        self.assertIn("stop", session.events)

    def test_teardown_failure_is_reported(self):
        session = FakeSession(stop_failures=["controller survived SIGKILL"])
        with self.assertRaises(ArchIdentityError) as caught:
            run_lifecycle(session)
        self.assertIn("teardown was incomplete", str(caught.exception))


# --------------------------------------------------------------------------
# Peer Windows evidence merge (fail-closed).
# --------------------------------------------------------------------------

class WindowsEvidenceMergeTests(unittest.TestCase):
    def test_missing_windows_check_is_refused(self):
        events = passing_windows_events()[:-1]
        with self.assertRaisesRegex(ArchIdentityError, "missing"):
            arch_identity_run.validate_windows_evidence(events)

    def test_non_passing_windows_check_is_refused(self):
        events = passing_windows_events()
        events[0]["result"] = "fail"
        with self.assertRaisesRegex(ArchIdentityError, "did not pass"):
            arch_identity_run.validate_windows_evidence(events)

    def test_windows_check_with_external_access_is_refused(self):
        events = passing_windows_events()
        events[0]["external_access"] = True
        with self.assertRaisesRegex(ArchIdentityError, "external access"):
            arch_identity_run.validate_windows_evidence(events)

    def test_windows_check_with_wrong_field_is_refused(self):
        events = passing_windows_events()
        secure = next(e for e in events
                      if e["check"] == "windows-secure-channel-restored")
        secure["secure_channel"] = False
        with self.assertRaisesRegex(ArchIdentityError, "secure_channel"):
            arch_identity_run.validate_windows_evidence(events)

    def test_windows_events_are_merged_verbatim(self):
        events = passing_windows_events()
        # A benign extra field on real Windows evidence is preserved verbatim.
        events[0]["observed_at"] = "2026-08-10T00:00:00Z"
        outcomes = {check: True for check in REQUIRED_CHECKS
                    if not check.startswith("windows-")}
        assembled = assemble_evidence(
            outcomes, events,
            measurements={
                "arch-storage-absent-login": {"login_seconds": 4},
                "arch-storage-attached": dict(
                    (name, DEFAULT_MEASUREMENTS[name])
                    for name in MEASURED_CHECK_FIELDS["arch-storage-attached"]
                ),
            })
        joined = next(e for e in assembled if e["check"] == "windows-joined")
        self.assertEqual(joined.get("observed_at"), "2026-08-10T00:00:00Z")


# --------------------------------------------------------------------------
# Bundle validation (fail-closed) and dry-run gating.
# --------------------------------------------------------------------------

class BundleValidationTests(unittest.TestCase):
    def test_valid_bundle_passes(self):
        with tempfile.TemporaryDirectory() as name:
            bundle = make_bundle(Path(name))
            bundle.validate()
            self.assertEqual(bundle.realm, "TELOS.EXAMPLE")

    def test_missing_disk_is_refused(self):
        with tempfile.TemporaryDirectory() as name:
            bundle = make_bundle(Path(name), with_disk=False)
            with self.assertRaisesRegex(
                    ArchIdentityError, "arch-workstation.qcow2"):
                bundle.validate()

    def test_world_readable_disk_is_refused(self):
        with tempfile.TemporaryDirectory() as name:
            bundle = make_bundle(Path(name))
            (bundle.bundle / "arch-workstation.qcow2").chmod(0o644)
            with self.assertRaisesRegex(ArchIdentityError, "mode 0600"):
                bundle.validate()

    def test_group_readable_bundle_dir_is_refused(self):
        with tempfile.TemporaryDirectory() as name:
            bundle = make_bundle(Path(name))
            bundle.bundle.chmod(0o750)
            with self.assertRaisesRegex(ArchIdentityError, "private"):
                bundle.validate()

    def test_external_access_authorization_is_refused(self):
        with tempfile.TemporaryDirectory() as name:
            bundle = make_bundle(Path(name), authorization={
                "status": "prepared",
                "external_access": True,
                "installation_media_attached": False,
                "pxe_boot_enabled": False,
                "domain_joined": True,
                "realm": "TELOS.EXAMPLE",
            })
            with self.assertRaisesRegex(ArchIdentityError, "external_access"):
                bundle.validate()

    def test_unjoined_authorization_is_refused(self):
        with tempfile.TemporaryDirectory() as name:
            bundle = make_bundle(Path(name), authorization={
                "status": "prepared",
                "external_access": False,
                "installation_media_attached": False,
                "pxe_boot_enabled": False,
                "domain_joined": False,
                "realm": "TELOS.EXAMPLE",
            })
            with self.assertRaisesRegex(ArchIdentityError, "domain_joined"):
                bundle.validate()

    def test_missing_realm_is_refused(self):
        with tempfile.TemporaryDirectory() as name:
            bundle = make_bundle(Path(name), authorization={
                "status": "prepared",
                "external_access": False,
                "installation_media_attached": False,
                "pxe_boot_enabled": False,
                "domain_joined": True,
            })
            with self.assertRaisesRegex(ArchIdentityError, "realm"):
                bundle.validate()

    def test_missing_windows_evidence_is_refused(self):
        with tempfile.TemporaryDirectory() as name:
            bundle = make_bundle(Path(name), with_windows=False)
            with self.assertRaisesRegex(
                    ArchIdentityError, "windows-evidence"):
                bundle.validate()

    def test_symlinked_disk_is_refused(self):
        with tempfile.TemporaryDirectory() as name:
            bundle = make_bundle(Path(name))
            disk = bundle.bundle / "arch-workstation.qcow2"
            disk.unlink()
            target = bundle.bundle / "elsewhere.qcow2"
            target.write_bytes(b"x")
            target.chmod(0o600)
            disk.symlink_to(target)
            with self.assertRaisesRegex(ArchIdentityError, "regular file"):
                bundle.validate()


class RunGatingTests(unittest.TestCase):
    def test_dry_run_does_not_start_a_session(self):
        with tempfile.TemporaryDirectory() as name:
            bundle = make_bundle(Path(name))
            started = []

            def factory(prepared):
                started.append(prepared)
                raise AssertionError("dry run must not build a session")

            code = run(bundle.bundle, apply=False,
                       controller_state=bundle.controller_state,
                       session_factory=factory)
            self.assertEqual(code, 0)
            self.assertEqual(started, [])
            self.assertFalse(bundle.evidence_path.exists())

    def test_dry_run_still_fails_closed_on_a_bad_bundle(self):
        with tempfile.TemporaryDirectory() as name:
            bundle = make_bundle(Path(name), with_disk=False)
            with self.assertRaises(ArchIdentityError):
                run(bundle.bundle, apply=False,
                    controller_state=bundle.controller_state,
                    session_factory=lambda prepared: FakeSession())

    def test_apply_writes_private_evidence_and_self_judges_pass(self):
        with tempfile.TemporaryDirectory() as name:
            bundle = make_bundle(Path(name))
            sessions: list[FakeSession] = []

            def factory(prepared):
                session = FakeSession()
                sessions.append(session)
                return session

            code = run(bundle.bundle, apply=True,
                       controller_state=bundle.controller_state,
                       session_factory=factory)
            self.assertEqual(code, 0)
            self.assertEqual(len(sessions), 1)
            evidence = bundle.evidence_path
            self.assertTrue(evidence.exists())
            self.assertEqual(evidence.stat().st_mode & 0o777, 0o600)
            ok, _summary = self_judge(evidence)
            self.assertTrue(ok)

    def test_apply_returns_nonzero_when_evidence_is_rejected(self):
        with tempfile.TemporaryDirectory() as name:
            bundle = make_bundle(Path(name))

            def factory(prepared):
                return FakeSession(drive_results={"arch-local-rescue": "FAIL"})

            code = run(bundle.bundle, apply=True,
                       controller_state=bundle.controller_state,
                       session_factory=factory)
            self.assertEqual(code, 2)
            # Evidence is still written so the failure can be judged and kept.
            ok, message = self_judge(bundle.evidence_path)
            self.assertFalse(ok)
            self.assertIn("arch-local-rescue", message)

    def test_out_of_bounds_duration_is_refused_before_any_session(self):
        with tempfile.TemporaryDirectory() as name:
            bundle = make_bundle(Path(name))
            for duration in (0, 59, MAX_DURATION + 1):
                with self.subTest(duration=duration):
                    with self.assertRaisesRegex(
                            ArchIdentityError, "duration"):
                        run(bundle.bundle, apply=True,
                            controller_state=bundle.controller_state,
                            session_factory=lambda prepared: FakeSession(),
                            duration=duration)
            self.assertFalse(bundle.evidence_path.exists())

    def test_explicit_duration_is_accepted(self):
        with tempfile.TemporaryDirectory() as name:
            bundle = make_bundle(Path(name))
            code = run(bundle.bundle, apply=True,
                       controller_state=bundle.controller_state,
                       session_factory=lambda prepared: FakeSession(),
                       duration=60)
            self.assertEqual(code, 0)


# --------------------------------------------------------------------------
# Live boundary: boot command, wiring, and wall-clock bound (no QEMU).
# --------------------------------------------------------------------------

class WorkstationBootCommandTests(unittest.TestCase):
    def _command(self, root: Path, port: int = 23456) -> list[str]:
        disk = root / "arch-workstation.qcow2"
        variables = root / "OVMF_VARS.fd"
        disk.write_bytes(b"disk")
        variables.write_bytes(b"vars")
        return workstation_boot_command(disk, variables, port)

    def test_boot_carries_the_empty_join_media_hotplug_port(self):
        # q35's pcie.0 supports no PCIe hotplug, so the one-use TELOS_JOIN
        # media needs a root port that was present at boot.  It carries no
        # device and no backend: the credential cannot exist until this run's
        # domain has been provisioned.
        from homelab.vm.arch_install_prepare import (
            JOIN_PORT_CHASSIS, JOIN_PORT_ID)
        with tempfile.TemporaryDirectory() as name:
            command = self._command(Path(name))
        self.assertIn(
            f"pcie-root-port,id={JOIN_PORT_ID},bus=pcie.0,"
            f"chassis={JOIN_PORT_CHASSIS}", command)
        self.assertFalse(
            any(f"bus={JOIN_PORT_ID}" in item for item in command))
        self.assertEqual(
            sum(item.startswith("pcie-root-port,") for item in command), 1)
        # Both boundary audits still hold with the extra empty port.
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            disk = root / "arch-workstation.qcow2"
            audit_arch_identity_boot(self._command(root), disk=disk)

    def test_boots_from_disk_only(self):
        from homelab.vm.arch_install_prepare import DISK_SERIAL
        with tempfile.TemporaryDirectory() as name:
            command = self._command(Path(name))
        self.assertIn("order=c,menu=off", command)
        self.assertFalse(any("order=n" in item for item in command))
        self.assertNotIn("-cdrom", command)
        self.assertFalse(any("media=cdrom" in item for item in command))
        # The joined disk is cold-plugged as the NVMe the installer targeted,
        # and the boot rides the gate-7 authored NVRAM entries: no bootindex,
        # whose fw_cfg boot order would compete with them.
        self.assertIn(f"nvme,drive=osdisk,serial={DISK_SERIAL}", command)
        self.assertFalse(any("bootindex" in item for item in command))
        # A display device, so QMP screendump can retain frame evidence.
        self.assertIn("VGA", command)
        self.assertIn(
            "socket,id=factory,connect=127.0.0.1:23456", command)
        self.assertTrue(
            any(item.startswith("e1000e,netdev=factory,")
                for item in command))

    def test_installation_media_is_refused(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            command = self._command(root)
            polluted = command + [
                "-drive", "if=none,id=media,media=cdrom,file=/x.iso"]
            with self.assertRaisesRegex(ArchIdentityError, "media"):
                audit_arch_identity_boot(
                    polluted, disk=root / "arch-workstation.qcow2")

    def test_pxe_boot_is_refused(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            command = [
                "order=n" if item == "order=c,menu=off" else item
                for item in self._command(root)
            ]
            with self.assertRaisesRegex(ArchIdentityError, "PXE"):
                audit_arch_identity_boot(
                    command, disk=root / "arch-workstation.qcow2")

    def test_second_writable_disk_is_refused(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            command = self._command(root) + [
                "-drive", "if=virtio,format=qcow2,file=/other.qcow2"]
            with self.assertRaisesRegex(ArchIdentityError, "exactly one"):
                audit_arch_identity_boot(
                    command, disk=root / "arch-workstation.qcow2")

    def test_foreign_writable_disk_is_refused(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            command = self._command(root)
            with self.assertRaisesRegex(ArchIdentityError, "authorized"):
                audit_arch_identity_boot(
                    command, disk=root / "other.qcow2")

    def test_firmware_debug_console_is_wired_and_still_audits(self):
        # The 2026-08-14 stalls could not be placed inside the firmware
        # because OVMF's print level emits two serial lines an entire boot.
        # -debugcon at OVMF's 0x402 I/O port carries the whole firmware log
        # when this build uses BaseDebugLibIoPort, and an empty file (which
        # costs nothing and is itself the answer) when it does not.  A token
        # either audit rejected would break EVERY run, so both are asserted
        # here with the extra tokens present.
        from homelab.vm.simulated_topology import audit_qemu_argv
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            disk = root / "arch-workstation.qcow2"
            variables = root / "OVMF_VARS.fd"
            disk.write_bytes(b"disk")
            variables.write_bytes(b"vars")
            log = root / "evidence" / "workstation-firmware.log"
            command = workstation_boot_command(
                disk, variables, 23456, firmware_log=log)
            self.assertIn("-debugcon", command)
            self.assertIn(f"file:{log}", command)
            self.assertIn("isa-debugcon.iobase=0x402", command)
            # No -chardev token is introduced, which audit_qemu_argv forbids.
            self.assertNotIn("-chardev", command)
            audit_qemu_argv(
                "client", command, allowed_nic_models=("e1000e",))
            audit_arch_identity_boot(command, disk=disk)
            # The debug console is a file sink only: it adds no writable
            # block device and no installation media.
            self.assertFalse(
                any("workstation-firmware.log" in item
                    for index, item in enumerate(command)
                    if index and command[index - 1] == "-drive"))

    def test_unsafe_firmware_log_path_is_refused(self):
        # A chardev spec is comma-separated: a comma in the path would be
        # parsed as another option and QEMU would refuse to start at all.
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            disk = root / "arch-workstation.qcow2"
            variables = root / "OVMF_VARS.fd"
            disk.write_bytes(b"disk")
            variables.write_bytes(b"vars")
            for bad in (root / "a,b" / "firmware.log",
                        Path("relative/firmware.log")):
                with self.assertRaisesRegex(
                        ArchIdentityError, "comma-free"):
                    workstation_boot_command(
                        disk, variables, 23456, firmware_log=bad)


class _FakeProcess:
    def __init__(self) -> None:
        self.pid = 4242
        self.stdout = io.BytesIO()
        self.stdin = io.BytesIO()
        self.signals: list[int] = []
        self.terminated = False

    def poll(self):
        return 0 if self.terminated else None

    def terminate(self):
        self.terminated = True

    def kill(self):
        self.terminated = True

    def wait(self, timeout=None):
        return 0

    def send_signal(self, signum):
        self.signals.append(signum)


class _FakeQmp:
    """Track blockdev/device lifecycle and prove inode ownership like QEMU.

    Only the join media is added with the nested ``file`` driver shape, so
    ownership tracking mirrors ``test_arch_install_run._FakeMediaQmp`` without
    disturbing the controller's seed/convergence attachments.
    """

    #: Guest run state ``query-status`` reports, and the asynchronous events
    #: QEMU queued on the socket.  A real ``QmpClient`` accumulates the latter
    #: in ``_events`` and this lane never drained them, so a stalled boot's
    #: BLOCK_IO_ERROR or STOP was discarded.
    status = {"status": "paused", "running": False}

    def __init__(self) -> None:
        self.calls: list[tuple[str, object]] = []
        self.held: set[tuple[int, int]] = set()
        self.closed = False
        self.frames: list[Path] = []
        self._events = [{
            "event": "STOP",
            "timestamp": {"seconds": 1755100000, "microseconds": 1234},
            "data": {},
        }]

    def screenshot(self, path):
        self.calls.append(("screendump", str(path)))
        self.frames.append(Path(path))
        Path(path).write_bytes(b"P6\n1 1\n255\n\x00\x00\x00")

    def execute(self, command, arguments=None, **_kw):
        self.calls.append((command, arguments))
        if command == "query-status":
            return dict(type(self).status)
        if command == "blockdev-add" and isinstance(arguments, dict):
            source = arguments.get("file")
            if isinstance(source, dict):
                info = Path(source["filename"]).stat()
                self.held.add((info.st_dev, info.st_ino))
        if command == "blockdev-del":
            self.held.clear()
        return {}

    def holds_inode(self, device, inode):
        return (device, inode) in self.held

    def await_device_deleted(self, device, timeout=None):
        self.calls.append(("await_device_deleted", device))
        return {"event": "DEVICE_DELETED", "data": {"device": device}}

    def close(self):
        self.closed = True


#: Cross-object ordering ledger for the wiring tests: process spawns and
#: principal staging append here so their relative order is provable.
TIMELINE: list[str] = []


def _build_join_iso(output, material, **_kwargs):
    """Build a real, private join ISO without needing xorriso installed.

    The genuine builder runs (so the ISO is a real mode-0600 file whose inode
    the media-ownership proofs can be checked against); only the xorriso
    process is stood in for.  The original is captured at import time because
    the module attribute itself is what gets patched.
    """
    from homelab.tests.test_arch_install_run import _iso_runner

    return _REAL_BUILD_JOIN_ISO(output, material, runner=_iso_runner)


def _menu_cell(row: int, title: str, *, selected: bool) -> bytes:
    """One positioned, attribute-run, space-padded menu cell (live shape)."""
    attributes = (
        b"\x1b[1m\x1b[30m\x1b[47m\x1b[0m\x1b[30m\x1b[47m" if selected
        else b"\x1b[1m\x1b[37m\x1b[40m\x1b[0m\x1b[37m\x1b[40m")
    return b"\x1b[%03d;103H" % row + attributes + f"{title:^36}".encode()


# systemd-boot menu renders modeled on the REAL gate-10 boot-1 serial
# transcript (cursor-positioned rows at column 103 with attribute runs and
# space padding, the Windows default highlighted, a countdown line below):
# the shape mirrors test_dualboot_acceptance.MENU, not plain log text —
# ``_menu_entries`` only counts positioned cells as rendered entries.
MENU_ARCH_FIRST = (
    b"\x1b[2J\x1b[001;001H"
    + _menu_cell(27, MENU_ARCH_ENTRY, selected=False)
    + _menu_cell(28, MENU_WINDOWS_ENTRY, selected=True)
    + _menu_cell(29, MENU_FIRMWARE_ENTRY, selected=False)
    + _menu_cell(31, "Boot in 5s.", selected=False)
)
MENU_WINDOWS_FIRST = (
    b"\x1b[2J\x1b[001;001H"
    + _menu_cell(27, MENU_WINDOWS_ENTRY, selected=True)
    + _menu_cell(28, MENU_ARCH_ENTRY, selected=False)
    + _menu_cell(29, MENU_FIRMWARE_ENTRY, selected=False)
    + _menu_cell(31, "Boot in 5s.", selected=False)
)
# The re-render after the highlight moves onto Arch: the countdown line is
# gone because any keypress cancels it, which is exactly what the live
# 2026-08-14 gate-8 transcript shows the firmware doing.
MENU_ARCH_FIRST_SELECTED = (
    b"\x1b[2J\x1b[001;001H"
    + _menu_cell(27, MENU_ARCH_ENTRY, selected=True)
    + _menu_cell(28, MENU_WINDOWS_ENTRY, selected=False)
    + _menu_cell(29, MENU_FIRMWARE_ENTRY, selected=False)
)
MENU_WINDOWS_FIRST_SELECTED = (
    b"\x1b[2J\x1b[001;001H"
    + _menu_cell(27, MENU_WINDOWS_ENTRY, selected=False)
    + _menu_cell(28, MENU_ARCH_ENTRY, selected=True)
    + _menu_cell(29, MENU_FIRMWARE_ENTRY, selected=False)
)


class _FakeSerial:
    """Stands in for SerialAutomation on both consoles.

    The workstation flow (menu -> getty login -> sudo elevation) is scripted
    per wait label; the class attributes flip individual outcomes.
    """

    instances: list["_FakeSerial"] = []
    console_banner = b"[root@telos-ws1 ~]# "
    menu_render = MENU_ARCH_FIRST
    menu_rerender = MENU_ARCH_FIRST_SELECTED
    login_outcome: bytes | None = None  # group(1): b"Login incorrect"
    sudo_outcome: bytes | None = None  # group("rc"): sudo's own exit code
    #: sudo read the credential and asked again -- its PAM stack refused it.
    sudo_refused = False
    rescue_outcome = b"0"  # group("rc"): passwd local-rescue return code
    #: passwd printed its own diagnostic instead of asking again.
    rescue_diagnostic: bytes | None = None
    root_uid = b"0"
    transcript = b""
    #: Leading ``arch-menu-rendered`` waits that stall: the guest says nothing
    #: at all, as two of eight gate-8 runs did on 2026-08-14.
    menu_stalls = 0
    menu_stall_message = "timed out waiting for arch-menu-rendered"

    def __init__(self, reader, writer, password, *, timeout=90.0,
                 clock=None) -> None:
        self.reader = reader
        self.writer = writer if writer is not None else io.BytesIO()
        self.password = password
        self.timeout = timeout
        self.buffer = b""
        self.calls: list[str] = []
        self.events: list[str] = []
        self.token = "feedfacefeedface"
        self.stalls_served = 0
        self.sudo_outcomes_served = 0
        self.rescue_outcomes_served = 0
        type(self).instances.append(self)

    def establish_disposable_controller_session(self):
        self.calls.append("establish")

    def install_offline_controller_dependencies(self, **_kw):
        self.calls.append("seed-install")

    def converge_disposable_controller(self, guest_command, **_kw):
        self.calls.append(f"converge:{guest_command}")

    def release_password(self):
        self.password = None
        self.calls.append("release")

    def _send(self, value, event):
        self.calls.append(f"send:{event}")
        self.events.append(event)

    def _wait(self, pattern, label):
        if (label == "arch-menu-rendered"
                and self.stalls_served < type(self).menu_stalls):
            # The real _wait records no label when it gives up, so neither
            # does this: a stall leaves no trace on the console but its own.
            from homelab.vm.serial_automation import SerialAutomationError
            self.stalls_served += 1
            self.calls.append(f"stall:{label}")
            raise SerialAutomationError(type(self).menu_stall_message)
        self.calls.append(f"wait:{label}")
        self.events.append(label)
        if label == "arch-menu-rendered":
            # The real console retains the raw escape-bearing render in its
            # consumption-independent transcript tail; drive_boot_menu
            # parses the rendered entries from there.
            self.transcript = self.transcript + type(self).menu_render
            return _FakeMatch({0: type(self).menu_render})
        if label == "arch-menu-rerendered":
            # The highlight has moved onto Arch; Enter now commits it.
            self.transcript = self.transcript + type(self).menu_rerender
            return _FakeMatch({0: type(self).menu_rerender})
        if label == "arch-login-outcome":
            return _FakeMatch({0: b"", 1: type(self).login_outcome})
        if label == "arch-sudo-outcome":
            # The real exchange settles in two passes: the root shell's prompt
            # says "ask for the proof", the proof answers with the uid.  A
            # scripted refusal or exit code settles it in one.
            self.sudo_outcomes_served += 1
            if type(self).sudo_refused:
                return _FakeMatch({0: b"", "refused": b"Password:"})
            if type(self).sudo_outcome is not None:
                return _FakeMatch({0: b"", "rc": type(self).sudo_outcome})
            if self.sudo_outcomes_served == 1:
                return _FakeMatch(
                    {0: b"", "root_shell": type(self).console_banner})
            return _FakeMatch({0: b"", "uid": type(self).root_uid})
        if label == "arch-rescue-outcome":
            # The real exchange is prompt-driven: pam asks, the credential is
            # written, pam asks again to confirm, then passwd's own exit code
            # settles it.  A scripted diagnostic settles it in one pass.
            self.rescue_outcomes_served += 1
            if type(self).rescue_diagnostic is not None:
                return _FakeMatch(
                    {0: b"", "diag": type(self).rescue_diagnostic})
            if self.rescue_outcomes_served == 1:
                return _FakeMatch({0: b"", "new": b"New Password: "})
            if self.rescue_outcomes_served == 2:
                return _FakeMatch(
                    {0: b"", "retype": b"Reenter new Password: "})
            return _FakeMatch({0: b"", "rc": type(self).rescue_outcome})
        if label == "storage-dns-rc-observed":
            return _FakeMatch({0: b"", 1: b"0"})
        return _FakeMatch({0: type(self).console_banner})


class _FakePrincipalSerial:
    """Records the Controller principal staging the boundary performs."""

    instances: list["_FakePrincipalSerial"] = []
    fail = False

    def __init__(self, reader, writer, *, timeout=90.0) -> None:
        self.timeout = timeout
        self.console = None
        self.staged: dict[str, str] | None = None
        type(self).instances.append(self)

    def stage(self, values):
        from homelab.vm.controller_principals import ControllerPrincipalError
        TIMELINE.append("stage-principals")
        if type(self).fail:
            raise ControllerPrincipalError("scripted staging failure")
        self.staged = dict(values)
        return mock.Mock()

    def destroy(self, names):
        TIMELINE.append("destroy-principals")
        return mock.Mock()


class _FakeJoinSerial:
    """Records the one-use domain-join principal lifecycle over the console."""

    instances: list["_FakeJoinSerial"] = []
    fail = False
    destruction_proved = True

    def __init__(self, reader, writer, *, timeout=90.0) -> None:
        self.timeout = timeout
        self.console = None
        self.principal = "tj-" + "0" * 16
        self.credential: str | None = None
        type(self).instances.append(self)

    def stage(self, credential):
        from homelab.vm.controller_join_material import (
            ControllerJoinMaterialError, ControllerJoinResult)
        TIMELINE.append("stage-join-principal")
        if type(self).fail:
            raise ControllerJoinMaterialError("scripted join staging failure")
        self.credential = credential
        return ControllerJoinResult(
            operation="stage", principal=self.principal,
            destruction_proved=False, events=())

    def destroy(self):
        from homelab.vm.controller_join_material import ControllerJoinResult
        TIMELINE.append("destroy-join-principal")
        return ControllerJoinResult(
            operation="destroy", principal=self.principal,
            destruction_proved=type(self).destruction_proved, events=())


class _FakeDisposableDisk:
    instances: list["_FakeDisposableDisk"] = []

    def __init__(self, canonical_disk, canonical_vars, *, run_root=None):
        self.canonical = (canonical_disk, canonical_vars)
        self.disk = Path(run_root or "/tmp") / "controller.raw"
        self.vars = Path(run_root or "/tmp") / "OVMF_VARS.fd"
        self.closed = False
        type(self).instances.append(self)

    def prepare(self):
        return self

    def close(self):
        self.closed = True


class _FakeFactoryBundle:
    def __init__(self, root, output, *, authorization_nonce):
        self.output = Path(output)
        self.nonce = authorization_nonce
        self.password = "factory-secret"

    def build(self):
        self.output.touch(mode=0o600)
        return self.output

    @staticmethod
    def guest_command(nonce):
        return f"converge-with-nonce-{nonce}"


class _WiredBoundary(ArchIdentityBoundary):
    """The real boundary with only the process/QMP layer replaced."""

    def __init__(self, bundle, **kw) -> None:
        super().__init__(bundle, **kw)
        self.spawned: list[tuple[str, list[str]]] = []
        self.audited: list[str] = []
        self.switch_waits: list[str] = []
        self.qmp = _FakeQmp()

    def _spawn(self, role, command, *, pass_fds=(), stdio=False):
        process = _FakeProcess()
        self.spawned.append((role, list(command)))
        TIMELINE.append(f"spawn:{role}")
        self._processes[role] = process
        return process

    def _audit(self, role, pid, **_kw):
        self.audited.append(role)

    def _wait_switch_port(self, name, mac):
        self.switch_waits.append(name)

    def _connect_qmp(self, path, pid):
        return self.qmp


class BoundaryWiringTests(unittest.TestCase):
    """Prove the live wiring without booting anything.

    Only the subprocess/QMP/serial layer is doubled; command construction,
    sequencing, media attach/release ordering, outage control, and teardown
    all run the real code.
    """

    def setUp(self):
        _FakeSerial.instances = []
        _FakeSerial.login_outcome = None
        _FakeSerial.sudo_outcome = None
        _FakeSerial.sudo_refused = False
        _FakeSerial.rescue_outcome = b"0"
        _FakeSerial.rescue_diagnostic = None
        _FakeSerial.root_uid = b"0"
        _FakeSerial.transcript = b""
        _FakeSerial.menu_stalls = 0
        _FakeSerial.menu_stall_message = (
            "timed out waiting for arch-menu-rendered")
        _FakeQmp.status = {"status": "paused", "running": False}
        _FakeDisposableDisk.instances = []
        self._patches = [
            mock.patch(
                "homelab.vm.automated_controller.DisposableBootDisk",
                _FakeDisposableDisk),
            mock.patch(
                "homelab.vm.serial_automation.SerialAutomation", _FakeSerial),
            mock.patch(
                "homelab.vm.controller_factory.FactoryBundle",
                _FakeFactoryBundle),
            mock.patch(
                "homelab.vm.controller_principals.ControllerPrincipalSerial",
                _FakePrincipalSerial),
            # The one-use join principal protocol; the media lifecycle itself
            # (build -> attach -> consumed -> destroyed) runs the real code.
            mock.patch(
                "homelab.vm.controller_join_material.ControllerJoinSerial",
                _FakeJoinSerial),
            # xorriso is not a test dependency: the real builder runs with the
            # install lane's stand-in runner, so the ISO's inode is real.
            mock.patch(
                "homelab.vm.arch_install_run.build_arch_join_iso",
                _build_join_iso),
        ]
        for patch in self._patches:
            patch.start()
            self.addCleanup(patch.stop)
        _FakePrincipalSerial.instances = []
        _FakePrincipalSerial.fail = False
        _FakeJoinSerial.instances = []
        _FakeJoinSerial.fail = False
        _FakeJoinSerial.destruction_proved = True
        TIMELINE.clear()

    def _boundary(self, root: Path) -> _WiredBoundary:
        bundle = make_bundle(root)
        # validate() is what the real run path calls before constructing the
        # boundary; it publishes the authorized realm the in-run join needs.
        bundle.validate()
        boundary = _WiredBoundary(bundle, duration=600)
        seed = root / "seed.iso"
        seed.write_bytes(b"seed")
        seed.chmod(0o600)
        boundary.seed_iso = seed
        return boundary

    def test_start_wires_identity_fabric_controller_then_workstation(self):
        with tempfile.TemporaryDirectory() as name:
            boundary = self._boundary(Path(name))
            boundary.start()
            try:
                roles = [role for role, _ in boundary.spawned]
                self.assertEqual(
                    roles, ["switch", "gateway", "controller", "workstation"])
                commands = dict(boundary.spawned)
                # The fabric runs in identity mode: the gateway's DHCP points
                # DNS at the Controller.
                self.assertIn("--identity-mode", commands["switch"])
                self.assertIn("--identity-mode", commands["gateway"])
                self.assertIn("--controller-mac", commands["gateway"])
                self.assertIn(
                    "virtio-scsi-pci,id=identityfactorybus",
                    commands["controller"])
                self.assertTrue(
                    any("nvme,drive=osdisk" in item
                        for item in commands["workstation"]))
                # The exact booted argv is retained beside the bundle, so a
                # boot that renders no menu is diagnosed from what it ran
                # with rather than reconstructed afterwards.
                recorded = boundary.bundle.bundle / "qemu-command.json"
                self.assertEqual(recorded.stat().st_mode & 0o777, 0o600)
                self.assertEqual(
                    json.loads(recorded.read_text(encoding="utf-8")),
                    {"schema": 1, "argv": commands["workstation"]})
                self.assertEqual(
                    boundary.switch_waits, ["gateway", "controller"])
                self.assertEqual(
                    boundary.audited, ["controller", "client"])
                # Controller console: session, verified seed, convergence.
                controller_console = _FakeSerial.instances[0]
                self.assertEqual(controller_console.calls[0], "establish")
                self.assertIn("seed-install", controller_console.calls)
                converge = [call for call in controller_console.calls
                            if call.startswith("converge:")]
                self.assertEqual(len(converge), 1)
                self.assertLess(
                    controller_console.calls.index("seed-install"),
                    controller_console.calls.index(converge[0]))
                # Media are attached and provably released around each phase.
                qmp_names = [name for name, _ in boundary.qmp.calls]
                self.assertEqual(qmp_names, [
                    "blockdev-add", "blockdev-add", "device_add",
                    "device_del", "await_device_deleted",
                    "blockdev-del", "blockdev-del",
                    "blockdev-add", "blockdev-add", "device_add",
                    "device_del", "await_device_deleted",
                    "blockdev-del", "blockdev-del",
                    # The in-run join media: one read-only node in the empty
                    # join root port, hot-removed and released again.
                    "blockdev-add", "device_add",
                    "device_del", "await_device_deleted", "blockdev-del",
                ])
                self.assertTrue(boundary.observe_controller_ready())
                # The convergence media and its password never survive.
                self.assertIsNone(boundary._factory_media)
                # Principals are staged after the Controller converges and
                # strictly before the workstation boots; the workstation
                # console owns the staged operator credential.
                # The one-use join principal is staged only after the
                # workstation is booting and destroyed with proof afterwards.
                self.assertEqual(TIMELINE, [
                    "spawn:switch", "spawn:gateway", "spawn:controller",
                    "stage-principals", "spawn:workstation",
                    "stage-join-principal", "destroy-join-principal"])
                join_staging = _FakeJoinSerial.instances[0]
                self.assertIs(join_staging.console, _FakeSerial.instances[0])
                self.assertEqual(join_staging.timeout,
                                 arch_identity_run.CONSOLE_READY_TIMEOUT)
                staging = _FakePrincipalSerial.instances[0]
                self.assertIs(staging.console, _FakeSerial.instances[0])
                self.assertEqual(
                    sorted(staging.staged),
                    ["directory-admin", "operator", "student"])
                workstation_console = _FakeSerial.instances[1]
                self.assertEqual(
                    workstation_console.password,
                    staging.staged[OPERATOR_PRINCIPAL].encode("ascii"))
                # The workstation boot carries the QMP power-cycle socket.
                self.assertIn("-qmp", commands["workstation"])
                # Menu -> in-run join -> domain-online gate -> getty -> login
                # -> elevation -> break-glass password, in order, over serial.
                # The join sits strictly between the menu drive and the login:
                # no login can succeed until this run's directory knows this
                # machine.  The readiness marker sits strictly between the join
                # and the getty: a joined guest whose SSSD backend is still
                # connecting refuses the operator deterministically.
                self.assertEqual(workstation_console.events, [
                    "arch-menu-rendered", "arch-menu-entry-selected",
                    "arch-menu-rerendered", "arch-menu-entry-committed",
                    "arch-handoff-observed",
                    "arch-join-media-consumed", "arch-join-verified",
                    "arch-domain-online-observed",
                    "arch-getty-observed",
                    "arch-login-username-sent", "arch-login-password-prompt",
                    "arch-login-password-sent", "arch-login-outcome",
                    # The credential is written between sudo's OWN prompt and
                    # the outcome: never before the reader asked for it.
                    "arch-sudo-command-sent", "arch-sudo-echo-off",
                    "arch-sudo-password-prompt", "arch-sudo-password-sent",
                    "arch-sudo-outcome", "arch-root-proof-requested",
                    "arch-sudo-outcome",
                    # And the break-glass credential is written only into a
                    # prompt the password stack has just printed: one outcome
                    # wait per ask, never a write ahead of one.
                    "arch-rescue-command-sent", "arch-rescue-echo-off",
                    "arch-rescue-outcome",
                    "arch-rescue-new-password-prompt",
                    "arch-rescue-password-sent",
                    "arch-rescue-outcome",
                    "arch-rescue-password-confirm-prompt",
                    "arch-rescue-password-sent",
                    "arch-rescue-outcome",
                    "arch-rescue-result",
                ])
                # The Arch entry (listed first) was selected with its raw
                # digit key and committed with Enter: no newline that would
                # be typed ahead.
                self.assertEqual(
                    workstation_console.writer.getvalue(), b"1\r")
                facts = boundary._boot_facts
                self.assertTrue(facts["menu_seen"])
                self.assertEqual(facts["entry_selected"], "1")
                self.assertTrue(facts["entry_committed"])
                self.assertTrue(facts["handoff_seen"])
                self.assertTrue(facts["getty_seen"])
                self.assertTrue(facts["login_completed"])
                self.assertTrue(facts["sudo_elevated"])
                self.assertTrue(facts["rescue_password_set"])
                self.assertEqual(facts["menu_retries"], 0)
                # The full one-use join lifecycle is recorded, secret-free.
                for name in (
                    "join_media_built", "join_media_attached",
                    "join_media_consumed", "join_media_destroyed",
                    "join_verified", "join_principal_destroyed",
                    "domain_online_observed",
                ):
                    self.assertTrue(facts[name], name)
                # The staged credential reached the ISO builder, never a fact.
                self.assertNotIn(
                    _FakeJoinSerial.instances[0].credential,
                    json.dumps(facts))
                # The run-built join ISO was destroyed by exact inode.
                self.assertFalse(
                    (boundary._runtime / "join.iso").exists())
                # Outage control drives the Controller process, not the fabric.
                import signal
                boundary.take_controller_offline()
                self.assertTrue(boundary.observe_controller_offline())
                boundary.restore_controller()
                self.assertTrue(boundary.observe_controller_restored())
                controller_process = boundary._processes["controller"]
                self.assertEqual(
                    controller_process.signals,
                    [signal.SIGSTOP, signal.SIGCONT])
                # The storage target is DNS-toggled over the retained
                # Controller console: unas is repointed from the Controller
                # address to the dead in-subnet STORAGE_ABSENT_ADDRESS.
                controller_console = _FakeSerial.instances[0]
                boundary.make_storage_unreachable()
                self.assertEqual(controller_console.events[-6:], [
                    "storage-dns-shell-requested", "storage-dns-shell-ready",
                    "storage-dns-command-sent", "storage-dns-sudo-prompt",
                    "storage-dns-password-sent", "storage-dns-rc-observed"])
                # The drive can open the workstation console.
                channel = boundary.open_channel()
                self.assertEqual(channel.timeout,
                                 arch_identity_run.PROBE_TIMEOUT)
            finally:
                failures = boundary.stop()
            self.assertEqual(failures, [])
            self.assertTrue(_FakeDisposableDisk.instances[0].closed)
            # Teardown dropped the in-memory credentials on both sides.
            self.assertEqual(boundary._principals, {})
            self.assertIsNone(_FakeSerial.instances[1].password)
            # Evidence retains the transcript and facts on success too.
            evidence = boundary.bundle.evidence_path.parent
            log = evidence / WORKSTATION_LOG_FILENAME
            facts_path = evidence / BOOT_FACTS_FILENAME
            self.assertTrue(log.is_file())
            self.assertEqual(log.stat().st_mode & 0o777, 0o600)
            recorded = json.loads(facts_path.read_text(encoding="utf-8"))
            self.assertTrue(recorded["login_completed"])

    def test_principal_staging_failure_is_named_and_torn_down(self):
        with tempfile.TemporaryDirectory() as name:
            boundary = self._boundary(Path(name))
            _FakePrincipalSerial.fail = True
            with self.assertRaisesRegex(
                    ArchIdentityError, "principal staging failed") as caught:
                boundary.start()
            self.assertEqual(caught.exception.check, "controller-ready")
            # The workstation never booted without staged principals.
            self.assertNotIn("spawn:workstation", TIMELINE)
            self.assertEqual(boundary._processes, {})
            self.assertTrue(_FakeDisposableDisk.instances[0].closed)

    def test_workstation_boot_without_principals_is_refused(self):
        with tempfile.TemporaryDirectory() as name:
            boundary = self._boundary(Path(name))
            boundary._port = 23456
            boundary._qmp_root = Path(name)
            with self.assertRaisesRegex(
                    ArchIdentityError, "staged operator principal"):
                boundary._start_workstation()

    def test_workstation_login_refusal_is_named_and_torn_down(self):
        with tempfile.TemporaryDirectory() as name:
            boundary = self._boundary(Path(name))
            _FakeSerial.login_outcome = b"Login incorrect"
            _FakeSerial.transcript = b"telos-ws1 login: "
            with self.assertRaisesRegex(
                    ArchIdentityError, "login on the ttyS0 getty") as caught:
                boundary.start()
            self.assertEqual(caught.exception.check, "arch-joined")
            # start() failed after spawning; it must have torn down itself.
            self.assertEqual(boundary._processes, {})
            self.assertTrue(_FakeDisposableDisk.instances[0].closed)
            # The failure still retained the transcript and honest facts.
            evidence = boundary.bundle.evidence_path.parent
            self.assertTrue(
                (evidence / WORKSTATION_LOG_FILENAME).is_file())
            recorded = json.loads(
                (evidence / BOOT_FACTS_FILENAME).read_text(encoding="utf-8"))
            self.assertTrue(recorded["menu_seen"])
            self.assertTrue(recorded["getty_seen"])
            self.assertFalse(recorded["login_completed"])

    def test_workstation_sudo_failure_is_named(self):
        with tempfile.TemporaryDirectory() as name:
            boundary = self._boundary(Path(name))
            _FakeSerial.sudo_outcome = b"1"
            with self.assertRaises(ArchIdentityError) as caught:
                boundary.start()
            self.assertEqual(str(caught.exception), SUDO_EXITED_FAILURE)
            self.assertEqual(caught.exception.check, "arch-joined")
            self.assertEqual(boundary._processes, {})
            recorded = json.loads(
                (boundary.bundle.evidence_path.parent / BOOT_FACTS_FILENAME)
                .read_text(encoding="utf-8"))
            # sudo's own exit code is retained, so the next run reads the
            # layer off the facts instead of re-deriving it from a transcript.
            self.assertEqual(recorded["sudo_returncode"], 1)
            self.assertTrue(recorded["sudo_prompt_seen"])
            self.assertTrue(recorded["sudo_credential_sent"])
            self.assertFalse(recorded["sudo_credential_refused"])
            self.assertFalse(recorded["sudo_elevated"])

    def test_workstation_sudo_refusal_indicts_sudo_pam_not_the_value(self):
        # The 2026-08-14 shape: the getty accepted the credential and sudo
        # refused it.  That pair is the diagnosis, so it must be readable
        # straight off the retained facts.
        with tempfile.TemporaryDirectory() as name:
            boundary = self._boundary(Path(name))
            _FakeSerial.sudo_refused = True
            with self.assertRaises(ArchIdentityError) as caught:
                boundary.start()
            self.assertEqual(
                str(caught.exception), SUDO_CREDENTIAL_REFUSED_FAILURE)
            self.assertEqual(caught.exception.check, "arch-joined")
            recorded = json.loads(
                (boundary.bundle.evidence_path.parent / BOOT_FACTS_FILENAME)
                .read_text(encoding="utf-8"))
            self.assertTrue(recorded["login_completed"])
            self.assertTrue(recorded["sudo_credential_refused"])
            self.assertFalse(recorded["sudo_elevated"])
            self.assertIsNone(recorded["sudo_returncode"])
            # The refusal is detected from sudo's second prompt and aborts
            # there: the proof line is never typed into it, so pam_faillock
            # records one failure and the stock deny=3 keeps two in hand.
            console = _FakeSerial.instances[1]
            self.assertNotIn("arch-root-proof-requested", console.events)

    def test_join_failure_is_named_and_never_blames_the_login(self):
        # The 2026-08-14 live run stopped at the login because the join had
        # never happened.  A join that cannot be staged must say so itself.
        with tempfile.TemporaryDirectory() as name:
            boundary = self._boundary(Path(name))
            _FakeJoinSerial.fail = True
            with self.assertRaises(ArchIdentityError) as caught:
                boundary.start()
            self.assertIn(JOIN_FAILURE, str(caught.exception))
            self.assertNotIn(LOGIN_REFUSED_FAILURE, str(caught.exception))
            self.assertNotIn(
                GETTY_NEVER_APPEARED_FAILURE, str(caught.exception))
            self.assertEqual(caught.exception.check, "arch-joined")
            self.assertEqual(boundary._processes, {})
            recorded = json.loads(
                (boundary.bundle.evidence_path.parent / BOOT_FACTS_FILENAME)
                .read_text(encoding="utf-8"))
            # The facts say exactly where it stopped: the boot chain worked,
            # the join never got as far as building its media, and no login
            # was ever attempted.
            self.assertTrue(recorded["handoff_seen"])
            self.assertFalse(recorded["join_media_built"])
            self.assertFalse(recorded["join_verified"])
            self.assertFalse(recorded["join_principal_destroyed"])
            self.assertFalse(recorded["getty_seen"])
            self.assertFalse(recorded["login_completed"])

    def test_join_without_proved_principal_destruction_fails_closed(self):
        class _UnprovedMaterial:
            """One-use material whose destruction proof never arrives."""

            def __init__(self, realm, *, stage, destroy) -> None:
                self.realm = realm

            def use(self, consumer):
                from homelab.vm.controller_join_material import (
                    ControllerJoinResult)
                principal = "tj-" + "0" * 16
                value = consumer({
                    "realm": "AD.FACTORY.TEST",
                    "principal": principal,
                    "credential": "Synthetic-Join-unproved-47!",
                    "operator": "operator@AD.FACTORY.TEST",
                })
                return value, ControllerJoinResult(
                    operation="destroy", principal=principal,
                    destruction_proved=False, events=())

        with tempfile.TemporaryDirectory() as name:
            boundary = self._boundary(Path(name))
            with mock.patch(
                    "homelab.vm.controller_join_material."
                    "OneUseDomainJoinMaterial", _UnprovedMaterial):
                with self.assertRaises(ArchIdentityError) as caught:
                    boundary.start()
            self.assertEqual(
                str(caught.exception), JOIN_PRINCIPAL_NOT_DESTROYED_FAILURE)
            self.assertEqual(caught.exception.check, "arch-joined")
            self.assertEqual(boundary._processes, {})
            recorded = json.loads(
                (boundary.bundle.evidence_path.parent / BOOT_FACTS_FILENAME)
                .read_text(encoding="utf-8"))
            # The media lifecycle completed; only the DC-side proof did not.
            self.assertTrue(recorded["join_media_destroyed"])
            self.assertFalse(recorded["join_principal_destroyed"])
            self.assertFalse(recorded["login_completed"])

    def test_rescue_password_failure_is_bound_to_its_own_check(self):
        with tempfile.TemporaryDirectory() as name:
            boundary = self._boundary(Path(name))
            _FakeSerial.rescue_outcome = b"1"
            with self.assertRaises(ArchIdentityError) as caught:
                boundary.start()
            self.assertEqual(
                str(caught.exception), RESCUE_PASSWD_EXITED_FAILURE)
            self.assertEqual(caught.exception.check, "arch-local-rescue")
            recorded = json.loads(
                (boundary.bundle.evidence_path.parent / BOOT_FACTS_FILENAME)
                .read_text(encoding="utf-8"))
            self.assertTrue(recorded["sudo_elevated"])
            self.assertFalse(recorded["rescue_password_set"])
            # passwd's own exit code reaches the evidence, as sudo's does, so
            # the next run never has to re-derive it from a transcript.
            self.assertEqual(recorded["rescue_returncode"], 1)
            self.assertTrue(recorded["rescue_echo_suppressed"])
            self.assertTrue(recorded["rescue_prompt_seen"])
            self.assertTrue(recorded["rescue_confirm_prompt_seen"])
            self.assertEqual(recorded["rescue_credential_writes"], 2)
            self.assertFalse(recorded["rescue_credential_rejected"])

    def test_boot_stall_is_power_cycled_and_self_diagnosing(self):
        # Two of eight gate-8 runs on 2026-08-14 rendered no menu at all with
        # a correct, active, first-in-BootOrder entry whose ESP the firmware
        # had already matched (it wrote HDDP).  The first miss must now
        # power-cycle and retry -- and it must leave behind the artifacts that
        # separate a spinning vCPU from a stalled device or host I/O, none of
        # which this lane used to keep.
        with tempfile.TemporaryDirectory() as name:
            boundary = self._boundary(Path(name))
            _FakeSerial.menu_stalls = 1
            boundary.start()
            try:
                facts = boundary._boot_facts
                # Counted as its own fault, never folded into menu_retries:
                # that one means a rendered menu whose Windows default won.
                self.assertEqual(facts["boot_stalls"], 1)
                self.assertEqual(facts["menu_retries"], 0)
                self.assertTrue(facts["menu_seen"])
                self.assertTrue(facts["handoff_seen"])
                self.assertTrue(facts["login_completed"])
                console = _FakeSerial.instances[1]
                self.assertIn("arch-workstation-power-cycled", console.events)
                self.assertIn(("system_reset", None), boundary.qmp.calls)
                # One bounded record naming the stall and its evidence.
                records = facts["boot_stall_evidence"]
                self.assertEqual(len(records), 1)
                record = records[0]
                self.assertEqual(record["reason"], "timed-out")
                self.assertEqual(record["label"], "arch-menu-rendered")
                self.assertEqual(record["attempt"], 1)
                self.assertFalse(record["terminal"])
                # paused-versus-running is what separates a stalled device or
                # a host I/O stall from a spinning vCPU.
                self.assertEqual(record["status"], "paused")
                self.assertFalse(record["running"])
                # The asynchronous QMP events the lane held a socket open for
                # and never drained.
                self.assertEqual(
                    [item["event"] for item in record["qmp_events"]], ["STOP"])
                # A frame: -device VGA was added for exactly this and
                # screendump had never been called from this module.
                frame = (
                    boundary.bundle.evidence_path.parent / record["frame"])
                self.assertTrue(frame.is_file())
                self.assertEqual(frame.stat().st_mode & 0o777, 0o600)
                self.assertEqual(record["frame_bytes"], frame.stat().st_size)
            finally:
                failures = boundary.stop()
            self.assertEqual(failures, [])
            recorded = json.loads(
                (boundary.bundle.evidence_path.parent / BOOT_FACTS_FILENAME)
                .read_text(encoding="utf-8"))
            self.assertEqual(recorded["boot_stalls"], 1)
            self.assertEqual(
                recorded["boot_stall_evidence"][0]["reason"], "timed-out")

    def test_stall_evidence_is_kept_when_the_boot_never_recovers(self):
        # The terminal miss is still the named never-rendered failure, and it
        # still retains its diagnosis -- otherwise the next occurrence costs
        # another investigation.
        with tempfile.TemporaryDirectory() as name:
            boundary = self._boundary(Path(name))
            _FakeSerial.menu_stalls = 2
            _FakeSerial.menu_stall_message = (
                "serial closed while waiting for arch-menu-rendered")
            with self.assertRaises(ArchIdentityError) as caught:
                boundary.start()
            self.assertEqual(
                str(caught.exception), MENU_NEVER_RENDERED_FAILURE)
            self.assertEqual(caught.exception.check, "arch-joined")
            recorded = json.loads(
                (boundary.bundle.evidence_path.parent / BOOT_FACTS_FILENAME)
                .read_text(encoding="utf-8"))
            # Bounded to one power-cycle: one recovered stall counted, two
            # stalls recorded, the second marked terminal.
            self.assertEqual(recorded["boot_stalls"], 1)
            self.assertFalse(recorded["menu_seen"])
            reasons = [(item["reason"], item["terminal"], item["attempt"])
                       for item in recorded["boot_stall_evidence"]]
            # EOF (QEMU exited) is recorded distinctly from a quiet guest;
            # collapsing the two cost most of the 2026-08-14 investigation.
            self.assertEqual(
                reasons, [("serial-closed", False, 1),
                          ("serial-closed", True, 2)])
            for item in recorded["boot_stall_evidence"]:
                self.assertTrue(
                    (boundary.bundle.evidence_path.parent
                     / item["frame"]).is_file())

    def test_boot_facts_carry_timing_digests_and_the_switch_log(self):
        # Every timing in the 2026-08-14 investigation was reconstructed from
        # file mtimes, the switch log had been deleted with the tempdir, and
        # comparing two runs' variable stores needed a parser.
        with tempfile.TemporaryDirectory() as name:
            boundary = self._boundary(Path(name))
            boundary.start()
            evidence = boundary.bundle.evidence_path.parent
            # The switch log lives in the runtime tempdir stop() removes.
            (boundary._runtime / "switch.jsonl").write_bytes(
                b'{"event":"port","name":"client"}\n')
            argv = dict(boundary.spawned)["workstation"]
            self.assertIn(
                f"file:{evidence / 'workstation-firmware.log'}", argv)
            failures = boundary.stop()
            self.assertEqual(failures, [])
            recorded = json.loads(
                (evidence / BOOT_FACTS_FILENAME).read_text(encoding="utf-8"))
            self.assertRegex(
                recorded["workstation_spawned_at"],
                r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
            timeline = recorded["serial_timeline"]
            self.assertEqual(timeline[0][1], "arch-menu-rendered")
            self.assertTrue(
                all(isinstance(offset, (int, float)) and offset >= 0
                    for offset, _label in timeline))
            self.assertEqual(
                [label for _offset, label in timeline],
                list(_FakeSerial.instances[1].events))
            # The variable store either side of the boot: equal here because
            # nothing really booted, and the pair is what answers "did the
            # firmware write the varstore at all" without a parser.
            from homelab.vm.windows_install_contract import sha256
            digest = sha256(boundary.bundle.firmware)
            self.assertEqual(recorded["firmware_vars_sha256_before"], digest)
            self.assertEqual(recorded["firmware_vars_sha256_after"], digest)
            # The firmware debug console was pre-created private so QEMU's
            # own O_TRUNC open keeps the mode; empty here (nothing booted),
            # which is exactly what a serial-DebugLib OVMF would also leave.
            log = evidence / "workstation-firmware.log"
            self.assertTrue(log.is_file())
            self.assertEqual(log.stat().st_mode & 0o777, 0o600)
            self.assertEqual(recorded["firmware_debug_log_bytes"], 0)
            # The fabric switch log survived the tempdir.
            switch = evidence / "workstation-switch.jsonl"
            self.assertEqual(
                switch.read_bytes(), b'{"event":"port","name":"client"}\n')
            self.assertEqual(switch.stat().st_mode & 0o777, 0o600)

    def test_wall_clock_expiry_terminates_and_is_reported(self):
        with tempfile.TemporaryDirectory() as name:
            boundary = self._boundary(Path(name))
            boundary.start()
            processes = list(boundary._processes.values())
            boundary._expire()
            self.assertTrue(all(item.terminated for item in processes))
            failures = boundary.stop()
            self.assertTrue(
                any("wall-clock bound" in item for item in failures))

    def test_unsafe_seed_media_is_refused(self):
        with tempfile.TemporaryDirectory() as name:
            boundary = self._boundary(Path(name))
            boundary.seed_iso.chmod(0o664)  # group-writable is unsafe
            with self.assertRaisesRegex(
                    ArchIdentityError, "seed media") as caught:
                boundary.start()
            self.assertEqual(caught.exception.check, "controller-ready")
            self.assertEqual(boundary._processes, {})


# --------------------------------------------------------------------------
# Boot drive against synthetic serial transcripts (real SerialAutomation).
# --------------------------------------------------------------------------

HANDOFF = b"\r\nEFI stub: Loaded initrd from LINUX_EFI_INITRD_MEDIA_GUID\n"
GETTY = b"\ntelos-ws1 login: "
PASSWORD_PROMPT = b"\nPassword: "
OPERATOR_SHELL = (
    b"\nLast login: Tue Aug 11 10:00:00\n"
    b"[operator@telos-ws1 ~]$ ")
LOGIN_INCORRECT = b"\nLogin incorrect\n"
TEST_CREDENTIAL = b"T7a" + b"c0ffee" * 5 + b"aa"


class SerialTranscriptCase(unittest.TestCase):
    """Drive the real SerialAutomation against a pre-scripted guest pipe."""

    def _console(self, *, password: bytes = TEST_CREDENTIAL,
                 timeout: float = 2.0):
        from homelab.vm.serial_automation import SerialAutomation

        guest_read, guest_write = os.pipe()  # guest serial output -> host
        sink_read, sink_write = os.pipe()    # host input -> guest
        reader = os.fdopen(guest_read, "rb", buffering=0)
        writer = os.fdopen(sink_write, "wb", buffering=0)
        feeder = os.fdopen(guest_write, "wb", buffering=0)
        console = SerialAutomation(reader, writer, password, timeout=timeout)
        self.addCleanup(reader.close)
        self.addCleanup(writer.close)
        self.addCleanup(lambda: not feeder.closed and feeder.close())
        self.addCleanup(lambda: os.close(sink_read))
        return console, feeder, sink_read

    def _sent(self, sink_read: int) -> bytes:
        os.set_blocking(sink_read, False)
        sent = b""
        while True:
            try:
                chunk = os.read(sink_read, 4096)
            except BlockingIOError:
                break
            if not chunk:
                break
            sent += chunk
        return sent


class MenuDriveTests(SerialTranscriptCase):
    def test_menu_render_digit_handoff_sequence(self):
        console, feeder, sink = self._console()
        feeder.write(MENU_ARCH_FIRST + MENU_ARCH_FIRST_SELECTED + HANDOFF)
        facts = new_boot_facts()
        resets: list[int] = []
        drive_boot_menu(
            console, facts, reset=lambda: resets.append(1),
            menu_timeout=2.0, handoff_timeout=2.0)
        self.assertTrue(facts["menu_seen"])
        self.assertEqual(facts["entry_selected"], "1")
        self.assertTrue(facts["entry_committed"])
        self.assertTrue(facts["handoff_seen"])
        self.assertEqual(facts["menu_retries"], 0)
        self.assertEqual(resets, [])
        # Raw keys only, no newline typed ahead: the digit, then the Enter
        # that actually boots the entry.  The digit already moved the
        # highlight onto Arch, so no cursor navigation is needed.
        self.assertEqual(self._sent(sink), b"1\r")
        self.assertEqual(console.events, [
            "arch-menu-rendered", "arch-menu-entry-selected",
            "arch-menu-entry-committed", "arch-handoff-observed"])

    def test_menu_digit_follows_render_order(self):
        console, feeder, sink = self._console()
        feeder.write(
            MENU_WINDOWS_FIRST + MENU_WINDOWS_FIRST_SELECTED + HANDOFF)
        facts = new_boot_facts()
        drive_boot_menu(
            console, facts, reset=lambda: None,
            menu_timeout=2.0, handoff_timeout=2.0)
        self.assertEqual(facts["entry_selected"], "2")
        self.assertEqual(self._sent(sink), b"2\r")

    def test_uncommitted_entry_power_cycles_once_and_retries(self):
        console, feeder, sink = self._console()
        feeder.write(MENU_ARCH_FIRST)  # highlight never leaves Windows

        def reset():
            feeder.write(MENU_ARCH_FIRST + MENU_ARCH_FIRST_SELECTED + HANDOFF)

        resets: list[int] = []
        facts = new_boot_facts()
        drive_boot_menu(
            console, facts,
            reset=lambda: (resets.append(1), reset()),
            menu_timeout=2.0, handoff_timeout=0.3)
        self.assertEqual(resets, [1])
        self.assertEqual(facts["menu_retries"], 1)
        self.assertTrue(facts["entry_committed"])
        self.assertTrue(facts["handoff_seen"])
        # Attempt 1: digit, one Up, then no re-render ever arrives, so the
        # entry is never committed.  Attempt 2 gets the re-render and Enter.
        self.assertEqual(self._sent(sink), b"1\x1b[A1\r")
        self.assertIn("arch-workstation-power-cycled", console.events)

    def test_missed_window_power_cycles_once_and_retries(self):
        console, feeder, sink = self._console()
        # Committed, but the EFI stub never speaks: Windows won the window.
        feeder.write(MENU_ARCH_FIRST + MENU_ARCH_FIRST_SELECTED)

        def reset():
            feeder.write(MENU_ARCH_FIRST + MENU_ARCH_FIRST_SELECTED + HANDOFF)

        resets: list[int] = []
        facts = new_boot_facts()
        drive_boot_menu(
            console, facts,
            reset=lambda: (resets.append(1), reset()),
            menu_timeout=2.0, handoff_timeout=0.3)
        self.assertEqual(resets, [1])
        self.assertEqual(facts["menu_retries"], 1)
        self.assertTrue(facts["handoff_seen"])
        self.assertEqual(self._sent(sink), b"1\r1\r")
        self.assertIn("arch-workstation-power-cycled", console.events)

    def test_second_miss_is_the_named_window_failure(self):
        console, feeder, _sink = self._console()
        feeder.write(MENU_ARCH_FIRST + MENU_ARCH_FIRST_SELECTED)
        resets: list[int] = []

        def reset():
            resets.append(1)
            # Committed again, and again no handoff.
            feeder.write(MENU_ARCH_FIRST + MENU_ARCH_FIRST_SELECTED)

        with self.assertRaisesRegex(
                ArchIdentityError,
                "missed the five-second menu window") as caught:
            drive_boot_menu(
                console, new_boot_facts(), reset=reset,
                menu_timeout=2.0, handoff_timeout=0.3)
        self.assertEqual(caught.exception.check, "arch-joined")
        self.assertEqual(resets, [1])
        self.assertEqual(str(caught.exception), MENU_WINDOW_MISSED_FAILURE)

    def test_never_committed_entry_is_its_own_named_failure(self):
        # The highlight never settles on Arch: a distinct diagnosis from
        # "the five-second window was missed", which would be a lie here.
        console, feeder, _sink = self._console()
        feeder.write(MENU_ARCH_FIRST)
        resets: list[int] = []

        def reset():
            resets.append(1)
            feeder.write(MENU_ARCH_FIRST)  # highlight stays on Windows

        facts = new_boot_facts()
        with self.assertRaises(ArchIdentityError) as caught:
            drive_boot_menu(
                console, facts, reset=reset,
                menu_timeout=2.0, handoff_timeout=0.3)
        self.assertEqual(str(caught.exception), MENU_NOT_COMMITTED_FAILURE)
        self.assertEqual(caught.exception.check, "arch-joined")
        self.assertFalse(facts["entry_committed"])
        self.assertEqual(resets, [1])

    def test_menu_that_never_renders_is_the_named_menu_failure(self):
        # Now takes TWO consecutive misses: the first is power-cycled like the
        # post-menu miss below.  The terminal one is still the same named,
        # fail-closed failure.
        console, feeder, _sink = self._console()
        feeder.write(b"BdsDxe: starting nothing interesting\n")
        feeder.close()
        resets: list[int] = []
        stalls: list[tuple] = []
        facts = new_boot_facts()
        with self.assertRaises(ArchIdentityError) as caught:
            drive_boot_menu(
                console, facts, reset=lambda: resets.append(1),
                menu_timeout=0.5, handoff_timeout=0.3,
                on_stall=lambda reason, **kw: stalls.append((reason, kw)))
        self.assertEqual(str(caught.exception), MENU_NEVER_RENDERED_FAILURE)
        self.assertEqual(caught.exception.check, "arch-joined")
        self.assertEqual(resets, [1])
        self.assertEqual(facts["boot_stalls"], 1)
        self.assertFalse(facts["menu_seen"])
        # The stall evidence is captured on the retried miss AND on the
        # terminal one, so a run that never recovers still teaches the next.
        self.assertEqual(
            stalls,
            [("serial-closed",
              {"attempt": 1, "terminal": False,
               "label": "arch-menu-rendered"}),
             ("serial-closed",
              {"attempt": 2, "terminal": True,
               "label": "arch-menu-rendered"})])

    def test_first_boot_stall_power_cycles_once_and_still_boots(self):
        # The 2026-08-14 stall: the guest says nothing at all, with the boot
        # entry, the boot order, the ESP match and the loader path all proven
        # correct from the post-run varstore.  A bounded power-cycle recovers
        # it, and the new fact keeps the flake rate visible.
        console, feeder, sink = self._console()
        resets: list[int] = []

        def reset():
            resets.append(1)
            feeder.write(MENU_ARCH_FIRST + MENU_ARCH_FIRST_SELECTED + HANDOFF)

        stalls: list[tuple] = []
        facts = new_boot_facts()
        drive_boot_menu(
            console, facts, reset=reset, menu_timeout=0.5,
            handoff_timeout=2.0,
            on_stall=lambda reason, **kw: stalls.append((reason, kw)))
        self.assertEqual(resets, [1])
        self.assertEqual(facts["boot_stalls"], 1)
        # A stall is NOT a missed five-second window; conflating the two would
        # destroy the only signal either fault has.
        self.assertEqual(facts["menu_retries"], 0)
        self.assertTrue(facts["menu_seen"])
        self.assertTrue(facts["entry_committed"])
        self.assertTrue(facts["handoff_seen"])
        self.assertEqual(self._sent(sink), b"1\r")
        self.assertIn("arch-workstation-power-cycled", console.events)
        self.assertEqual(len(stalls), 1)
        self.assertEqual(stalls[0][0], "timed-out")
        self.assertFalse(stalls[0][1]["terminal"])

    def test_stall_reason_separates_a_dead_qemu_from_a_quiet_guest(self):
        # SerialAutomation._wait raises one exception type for EOF (QEMU
        # exited) and for a live guest that went quiet, and this lane rewrote
        # both into one message.  Reconstructing that distinction from QEMU's
        # lifetime cost most of the 2026-08-14 investigation.
        #
        # ``stall_reason`` reads the distinction off the message ``_wait``
        # composes, so this drives the REAL SerialAutomation down both paths
        # rather than a double: it is the canary for that wording, and it
        # fails the moment serial_automation stops distinguishing them.
        for closed, expected in ((True, "serial-closed"),
                                 (False, "timed-out")):
            with self.subTest(closed=closed):
                console, feeder, _sink = self._console()
                if closed:
                    feeder.close()
                stalls: list[str] = []
                with self.assertRaises(ArchIdentityError):
                    drive_boot_menu(
                        console, new_boot_facts(), reset=lambda: None,
                        menu_timeout=0.4, handoff_timeout=0.3,
                        on_stall=lambda reason, **kw: stalls.append(reason))
                self.assertEqual(stalls, [expected, expected])


class DomainOnlineGateTests(SerialTranscriptCase):
    """The gate-7 readiness marker, observed between join and login."""

    def _marker(self) -> bytes:
        from homelab.workstations.arch_second import DOMAIN_ONLINE_MARKER

        return b"\n" + DOMAIN_ONLINE_MARKER.encode("ascii") + b"\n"

    def test_marker_is_observed_and_recorded(self):
        console, feeder, sink = self._console()
        feeder.write(
            self._marker() + GETTY + PASSWORD_PROMPT + OPERATOR_SHELL)
        facts = new_boot_facts()
        self.assertFalse(facts["domain_online_observed"])
        await_domain_online(console, facts, timeout=2.0)
        self.assertTrue(facts["domain_online_observed"])
        self.assertEqual(console.events, ["arch-domain-online-observed"])
        # The gate is observation only: nothing is typed at the guest, so it
        # cannot consume a login attempt or a pam_faillock slot.
        self.assertEqual(self._sent(sink), b"")
        # And the marker is consumed before the getty prompt, so the login that
        # follows still finds its own prompt in the buffer.
        login_operator(console, facts, getty_timeout=2.0, attempts=1)
        self.assertTrue(facts["getty_seen"])
        self.assertTrue(facts["login_completed"])
        self.assertEqual(console.events, [
            "arch-domain-online-observed", "arch-getty-observed",
            "arch-login-username-sent", "arch-login-password-prompt",
            "arch-login-password-sent", "arch-login-outcome"])

    def test_absent_marker_is_its_own_named_failure_not_a_login_refusal(self):
        # The whole point of the named failure: a guest that never proves its
        # domain usable must not be reported as a refused credential, because
        # the credential was never sent.
        console, feeder, sink = self._console()
        feeder.write(
            b"\n[  OK  ] Started System Security Services Daemon.\n" + GETTY)
        feeder.close()
        facts = new_boot_facts()
        with self.assertRaises(ArchIdentityError) as caught:
            await_domain_online(console, facts, timeout=0.5)
        self.assertEqual(str(caught.exception), DOMAIN_ONLINE_FAILURE)
        self.assertNotEqual(str(caught.exception), LOGIN_REFUSED_FAILURE)
        # It says so in as many words, so a transcript-reading human is not
        # left inferring which stage stopped.
        self.assertIn("never a refused login", DOMAIN_ONLINE_FAILURE)
        self.assertEqual(caught.exception.check, "arch-joined")
        self.assertFalse(facts["domain_online_observed"])
        self.assertFalse(facts["login_completed"])
        self.assertEqual(self._sent(sink), b"")

    def test_failure_marker_alone_does_not_satisfy_the_gate(self):
        # Gate 7 prints a distinct secret-free reason when its bounded wait
        # gives up; that line must never be mistaken for the success marker.
        from homelab.workstations.arch_second import (
            DOMAIN_ONLINE_FAILURE_MARKER)

        console, feeder, _sink = self._console()
        feeder.write(
            b"\n" + DOMAIN_ONLINE_FAILURE_MARKER.encode("ascii")
            + b": the SSSD domain never reported Online\n")
        feeder.close()
        with self.assertRaises(ArchIdentityError) as caught:
            await_domain_online(console, new_boot_facts(), timeout=0.5)
        self.assertEqual(str(caught.exception), DOMAIN_ONLINE_FAILURE)

    def test_default_bound_covers_both_guest_side_waits(self):
        # The guest waits up to 60 x 2s for Online and then up to 60 x 2s for
        # the principal to resolve; a host bound below that would blame the
        # harness for a guest that was still converging.
        from homelab.workstations.arch_second import (
            JOIN_WAIT_SECONDS, JOIN_WAIT_TRIES)

        self.assertGreater(
            DOMAIN_ONLINE_TIMEOUT, 2 * JOIN_WAIT_TRIES * JOIN_WAIT_SECONDS)


class LoginSequenceTests(SerialTranscriptCase):
    def test_getty_username_password_shell_sequence(self):
        console, feeder, sink = self._console()
        feeder.write(HANDOFF + GETTY + PASSWORD_PROMPT + OPERATOR_SHELL)
        facts = new_boot_facts()
        login_operator(console, facts, getty_timeout=2.0)
        self.assertTrue(facts["getty_seen"])
        self.assertTrue(facts["login_completed"])
        self.assertEqual(
            self._sent(sink),
            OPERATOR_PRINCIPAL.encode("ascii") + b"\n"
            + TEST_CREDENTIAL + b"\n")
        self.assertEqual(console.events, [
            "arch-getty-observed", "arch-login-username-sent",
            "arch-login-password-prompt", "arch-login-password-sent",
            "arch-login-outcome"])
        # The credential never appears in the retained guest transcript:
        # login(1) reads it with terminal echo disabled.
        self.assertNotIn(TEST_CREDENTIAL, console.transcript)

    def test_incorrect_first_attempt_retries_to_success(self):
        console, feeder, _sink = self._console()
        feeder.write(
            GETTY + PASSWORD_PROMPT + LOGIN_INCORRECT
            + GETTY + PASSWORD_PROMPT + OPERATOR_SHELL)
        facts = new_boot_facts()
        login_operator(console, facts, getty_timeout=2.0)
        self.assertTrue(facts["login_completed"])
        self.assertEqual(console.events.count("arch-login-username-sent"), 2)

    def test_exhausted_attempts_are_the_named_login_failure(self):
        console, feeder, _sink = self._console()
        feeder.write(
            GETTY + PASSWORD_PROMPT + LOGIN_INCORRECT
            + GETTY + PASSWORD_PROMPT + LOGIN_INCORRECT + GETTY)
        facts = new_boot_facts()
        with self.assertRaises(ArchIdentityError) as caught:
            login_operator(console, facts, attempts=2, getty_timeout=2.0)
        self.assertEqual(str(caught.exception), LOGIN_REFUSED_FAILURE)
        self.assertEqual(caught.exception.check, "arch-joined")
        self.assertFalse(facts["login_completed"])

    def test_getty_that_never_appears_is_the_named_getty_failure(self):
        console, feeder, _sink = self._console()
        feeder.write(HANDOFF + b"systemd[1]: Reached target Multi-User\n")
        feeder.close()
        with self.assertRaises(ArchIdentityError) as caught:
            login_operator(console, new_boot_facts(), getty_timeout=0.5)
        self.assertEqual(str(caught.exception), GETTY_NEVER_APPEARED_FAILURE)
        self.assertEqual(caught.exception.check, "arch-joined")

    def test_login_without_a_credential_is_refused(self):
        console, _feeder, _sink = self._console()
        console.password = None
        with self.assertRaisesRegex(
                ArchIdentityError, "credential is unavailable"):
            login_operator(console, new_boot_facts(), getty_timeout=0.2)


#: sudo(8)'s default lecture, verbatim from the 2026-08-14 live run's
#: workstation-serial.log, CRLF and all.  It is what the guest prints between
#: the shell's ready marker and sudo's password prompt, and its "#1)" lines are
#: what the old outcome pattern mistook for a root shell prompt.
SUDO_LECTURE = (
    b"We trust you have received the usual lecture from the local System\r\n"
    b"Administrator. It usually boils down to these three things:\r\n\r\n"
    b"    #1) Respect the privacy of others.\r\n"
    b"    #2) Think before you type.\r\n"
    b"    #3) With great power comes great responsibility.\r\n\r\n"
    b"For security reasons, the password you type will not be visible.\r\n\r\n"
)


class ElevationTests(SerialTranscriptCase):
    """The one exchange the 2026-08-14 live run got wrong, end to end.

    That run proved the domain login works and the elevation still failed:
    the credential was written when the shell's own pre-sudo marker appeared,
    so it was gone before sudo read stdin, and the outcome pattern then
    mistook sudo's lecture for a root prompt 18ms later.  These tests pin both
    halves of the fix: the credential is written only in response to sudo's
    own prompt, and every verdict is token-scoped.
    """

    def _ready(self, console) -> bytes:
        return (b"\n__TELOS_ARCH_SUDO_READY_"
                + console.token.encode("ascii") + b"__\n")

    def _prompt(self, console) -> bytes:
        return elevation_command(console.token)[2]

    def _root_proof(self, console, uid: bytes) -> bytes:
        return b"\n" + root_proof_marker(console.token) + uid + b"\n"

    def test_echo_off_prompt_password_root_shell_sequence(self):
        console, feeder, sink = self._console()
        feeder.write(
            self._ready(console)
            + SUDO_LECTURE + self._prompt(console)
            + b"\r\n[root@telos-ws1 ~]# "
            + self._root_proof(console, b"0"))
        facts = new_boot_facts()
        elevate_operator(console, facts, timeout=2.0)
        self.assertTrue(facts["sudo_elevated"])
        self.assertEqual(facts["sudo_uid"], 0)
        self.assertTrue(facts["sudo_echo_suppressed"])
        self.assertTrue(facts["sudo_prompt_seen"])
        self.assertTrue(facts["sudo_credential_sent"])
        self.assertTrue(facts["sudo_root_shell_seen"])
        self.assertFalse(facts["sudo_credential_refused"])
        self.assertEqual(facts["sudo_proof_asks"], 1)
        sent = self._sent(sink)
        # Echo is provably off before the credential is written, the
        # elevation is sudo -S with its own token-scoped prompt (the gate-7
        # rule is passworded), and the credential never enters the transcript.
        self.assertIn(b"stty -echo", sent)
        self.assertIn(b"sudo -k -S -p '" + self._prompt(console) + b"' -i",
                      sent)
        self.assertNotIn(b"sudo -n", sent)
        self.assertNotIn(b"-p ''", sent)
        self.assertLess(
            sent.index(b"stty -echo"), sent.index(TEST_CREDENTIAL))
        self.assertNotIn(TEST_CREDENTIAL, console.transcript)
        # Exactly one write of the credential, terminated by exactly one
        # newline: sudo -S reads one line from stdin, and a second newline
        # would become the next reader's input.
        self.assertEqual(sent.count(TEST_CREDENTIAL), 1)
        self.assertIn(TEST_CREDENTIAL + b"\n", sent)
        self.assertNotIn(TEST_CREDENTIAL + b"\n\n", sent)
        self.assertNotIn(TEST_CREDENTIAL + b"\r", sent)
        # The root proof is typed after the credential, never before it.
        self.assertLess(
            sent.index(TEST_CREDENTIAL),
            sent.index(root_proof_marker(console.token)))
        self.assertEqual(console.events, [
            "arch-sudo-command-sent", "arch-sudo-echo-off",
            "arch-sudo-password-prompt", "arch-sudo-password-sent",
            "arch-sudo-outcome", "arch-root-proof-requested",
            "arch-sudo-outcome"])

    def test_credential_is_never_written_before_sudo_asks_for_it(self):
        # THE 2026-08-14 defect.  The shell's ready marker means only that
        # echo is off; sudo has not been exec'd yet, so a credential written
        # there is at the mercy of the reader's terminal setup and was in fact
        # lost.  With no prompt on the console the credential must simply not
        # be written, and the stop must name the sudoers/policy layer rather
        # than an authentication failure.
        console, feeder, sink = self._console()
        feeder.write(self._ready(console) + SUDO_LECTURE)
        facts = new_boot_facts()
        with self.assertRaises(ArchIdentityError) as caught:
            elevate_operator(console, facts, timeout=0.5)
        self.assertEqual(str(caught.exception), SUDO_PROMPT_MISSING_FAILURE)
        self.assertEqual(caught.exception.check, "arch-joined")
        self.assertTrue(facts["sudo_echo_suppressed"])
        self.assertFalse(facts["sudo_prompt_seen"])
        self.assertFalse(facts["sudo_credential_sent"])
        self.assertNotIn(TEST_CREDENTIAL, self._sent(sink))

    def test_sudo_lecture_is_never_mistaken_for_a_root_shell(self):
        # The lecture arrives between the ready marker and the prompt, and the
        # old outcome pattern accepted any line ending in "#".  A serial read
        # that lands on the "#" of "    #1)" ends the buffer there, and "$" in
        # MULTILINE matches at end-of-string too, so the run took the lecture
        # for a root prompt.  No prefix of it may match any verdict now.
        pattern = re.compile(
            elevation_outcome_pattern("feedfacefeedface"), re.MULTILINE)
        for length in range(1, len(SUDO_LECTURE) + 1):
            self.assertIsNone(
                pattern.search(SUDO_LECTURE[:length]),
                f"lecture prefix of {length} bytes matched a verdict")
        # The old pattern did match, at three separate read boundaries.
        old = re.compile(rb"(?:^|\n)[^\n]*#[ \t]*$", re.MULTILINE)
        self.assertTrue(any(
            old.search(SUDO_LECTURE[:length])
            for length in range(1, len(SUDO_LECTURE) + 1)))

    def test_refused_credential_is_named_and_burns_one_faillock_attempt(self):
        # sudo asking a second time is proof it read a line and PAM refused
        # it.  That is its own failure, distinct from a refused getty login,
        # and the exchange stops there instead of feeding the next prompt.
        console, feeder, sink = self._console()
        prompt = self._prompt(console)
        feeder.write(
            self._ready(console) + SUDO_LECTURE + prompt
            + b"\r\nSorry, try again.\r\n" + prompt)
        facts = new_boot_facts()
        with self.assertRaises(ArchIdentityError) as caught:
            elevate_operator(console, facts, timeout=2.0)
        self.assertEqual(
            str(caught.exception), SUDO_CREDENTIAL_REFUSED_FAILURE)
        self.assertEqual(caught.exception.check, "arch-joined")
        self.assertNotEqual(
            SUDO_CREDENTIAL_REFUSED_FAILURE, LOGIN_REFUSED_FAILURE)
        self.assertTrue(facts["sudo_credential_refused"])
        self.assertTrue(facts["sudo_credential_sent"])
        self.assertFalse(facts["sudo_elevated"])
        self.assertEqual(facts["sudo_proof_asks"], 0)
        # One credential write, and nothing typed into the second prompt.
        self.assertEqual(self._sent(sink).count(TEST_CREDENTIAL), 1)
        self.assertNotIn("arch-root-proof-requested", console.events)

    def test_a_bare_pam_password_prompt_also_gates_the_write(self):
        # sudo only substitutes its -p prompt for a PAM prompt it recognises
        # as the default one, so an unrecognised "Password:" must still gate
        # the write rather than time out and waste a live run.
        console, feeder, sink = self._console()
        feeder.write(
            self._ready(console) + SUDO_LECTURE + b"Password: "
            + b"\r\n[root@telos-ws1 ~]# "
            + self._root_proof(console, b"0"))
        facts = new_boot_facts()
        elevate_operator(console, facts, timeout=2.0)
        self.assertTrue(facts["sudo_elevated"])
        self.assertTrue(facts["sudo_prompt_seen"])
        self.assertIn(TEST_CREDENTIAL, self._sent(sink))

    def test_sudo_nonzero_return_is_the_named_exit_failure(self):
        console, feeder, _sink = self._console()
        feeder.write(
            self._ready(console) + SUDO_LECTURE + self._prompt(console)
            + b"\n__TELOS_ARCH_SUDO_RC_"
            + console.token.encode("ascii") + b"=1\n")
        facts = new_boot_facts()
        with self.assertRaises(ArchIdentityError) as caught:
            elevate_operator(console, facts, timeout=2.0)
        self.assertEqual(str(caught.exception), SUDO_EXITED_FAILURE)
        self.assertEqual(caught.exception.check, "arch-joined")
        self.assertEqual(facts["sudo_returncode"], 1)
        self.assertFalse(facts["sudo_credential_refused"])

    def test_non_root_shell_is_the_named_unproven_root_failure(self):
        console, feeder, _sink = self._console()
        feeder.write(
            self._ready(console) + SUDO_LECTURE + self._prompt(console)
            + b"\r\n[root@telos-ws1 ~]# "
            + self._root_proof(console, b"1000"))
        facts = new_boot_facts()
        with self.assertRaises(ArchIdentityError) as caught:
            elevate_operator(console, facts, timeout=2.0)
        self.assertEqual(str(caught.exception), SUDO_ROOT_UNPROVEN_FAILURE)
        self.assertEqual(facts["sudo_uid"], 1000)
        self.assertFalse(facts["sudo_elevated"])

    def test_missing_ready_marker_never_writes_the_credential(self):
        console, feeder, sink = self._console()
        feeder.write(b"[operator@telos-ws1 ~]$ \n")
        facts = new_boot_facts()
        with self.assertRaises(ArchIdentityError) as caught:
            elevate_operator(console, facts, timeout=0.4)
        self.assertEqual(
            str(caught.exception), SUDO_ECHO_NOT_SUPPRESSED_FAILURE)
        self.assertFalse(facts["sudo_echo_suppressed"])
        self.assertFalse(facts["sudo_credential_sent"])
        self.assertNotIn(TEST_CREDENTIAL, self._sent(sink))

    def test_a_silent_root_shell_is_re_asked_a_bounded_number_of_times(self):
        # A proof line typed into a login shell that has not started reading
        # yet is the one race the prompt gate cannot cover, so the proof is
        # re-asked -- but only SUDO_PROOF_ASKS times, and the umbrella failure
        # still carries the whole per-layer picture.
        console, feeder, _sink = self._console()
        feeder.write(
            self._ready(console) + SUDO_LECTURE + self._prompt(console))
        facts = new_boot_facts()
        with self.assertRaises(ArchIdentityError) as caught:
            elevate_operator(console, facts, timeout=0.9, proof_timeout=0.3)
        self.assertEqual(str(caught.exception), SUDO_ELEVATION_FAILURE)
        self.assertEqual(facts["sudo_proof_asks"], SUDO_PROOF_ASKS)
        self.assertTrue(facts["sudo_credential_sent"])
        self.assertFalse(facts["sudo_credential_refused"])
        self.assertIsNone(facts["sudo_returncode"])
        self.assertEqual(
            console.events.count("arch-root-proof-requested"),
            SUDO_PROOF_ASKS)

    def test_the_elevation_never_inherits_an_unbounded_console_timeout(self):
        # The 2026-08-14 run inherited the 300s console-ready timeout here and
        # spent five minutes of a live run on an exchange it had already
        # desynchronised.  The bound is restored on the way out either way.
        console, feeder, _sink = self._console(timeout=300.0)
        feeder.write(b"nothing the elevation is waiting for\n")
        with self.assertRaises(ArchIdentityError):
            elevate_operator(console, new_boot_facts(), timeout=0.4)
        self.assertEqual(console.timeout, 300.0)

    def test_elevation_without_a_credential_is_refused(self):
        console, _feeder, sink = self._console()
        console.password = None
        with self.assertRaisesRegex(
                ArchIdentityError, "credential is unavailable"):
            elevate_operator(console, new_boot_facts(), timeout=0.2)
        self.assertEqual(self._sent(sink), b"")


# The two wordings that can appear on this disk, verbatim.  pam_sss is the
# pair the live run of 2026-08-14 actually saw (its README-visible msgids are
# capitalised differently from pam_unix's) and gate 7 puts it FIRST in the
# password stack of /etc/pam.d/system-auth.
PAM_SSS_NEW = b"New Password: "
PAM_SSS_RETYPE = b"Reenter new Password: "
PAM_UNIX_NEW = b"New password: "
PAM_UNIX_RETYPE = b"Retype new password: "
#: The exact bytes that followed the ready marker in
#: var/factory/arch-identity/run-20260814T155301Z-4b21f9334459, where the run
#: then sat out its whole 60s budget and stopped.
LIVE_RESCUE_TAIL = b"\r\n" + PAM_SSS_NEW


class RescuePasswordTests(SerialTranscriptCase):
    """The break-glass password gate 7 deliberately leaves disabled."""

    def _ready(self, console) -> bytes:
        return (b"\n__TELOS_ARCH_RESCUE_READY_"
                + console.token.encode("ascii") + b"__\n")

    def _result(self, console, code: bytes) -> bytes:
        return (b"\n__TELOS_ARCH_RESCUE_RC_"
                + console.token.encode("ascii") + b"=" + code + b"\n")

    def _updated(self) -> bytes:
        return b"\npasswd: " + RESCUE_UPDATED_DIAGNOSTIC + b"\r\n"

    def test_pam_sss_wording_is_what_the_live_guest_actually_prints(self):
        # THE 2026-08-14 defect.  The elevation's lesson was "write only after
        # the reader asks"; this step already did that and still stopped, on
        # the reader's WORDING.  These are the verbatim bytes off the console.
        console, feeder, sink = self._console()
        feeder.write(
            self._ready(console) + LIVE_RESCUE_TAIL
            + b"\r\n" + PAM_SSS_RETYPE
            + self._updated() + self._result(console, b"0"))
        facts = new_boot_facts()
        set_rescue_password(console, facts, TEST_CREDENTIAL, timeout=2.0)
        self.assertTrue(facts["rescue_password_set"])
        self.assertTrue(facts["rescue_password_updated"])
        self.assertEqual(facts["rescue_returncode"], 0)
        self.assertEqual(facts["rescue_credential_writes"], 2)
        self.assertEqual(self._sent(sink).count(TEST_CREDENTIAL + b"\n"), 2)

    def test_the_predecessor_pattern_could_not_have_matched_that_prompt(self):
        # Pin the regression itself: the pattern this step used until
        # 2026-08-14 was case-sensitive lowercase pam_unix wording, so the
        # capitalised pam_sss prompt on the console could never match it.
        superseded = re.compile(rb"New password:\s*$", re.MULTILINE)
        self.assertIsNone(superseded.search(LIVE_RESCUE_TAIL))
        current = re.compile(rescue_prompt_pattern(), re.MULTILINE)
        match = current.search(LIVE_RESCUE_TAIL)
        self.assertIsNotNone(match)
        self.assertIsNotNone(match.group("new"))
        self.assertIsNone(match.group("retype"))

    def test_password_is_set_with_echo_provably_suppressed(self):
        console, feeder, sink = self._console()
        feeder.write(
            self._ready(console)
            + PAM_UNIX_NEW
            + b"\n" + PAM_UNIX_RETYPE
            + self._result(console, b"0"))
        facts = new_boot_facts()
        set_rescue_password(console, facts, TEST_CREDENTIAL, timeout=2.0)
        self.assertTrue(facts["rescue_password_set"])
        sent = self._sent(sink)
        # Echo is provably off before either write, the account is the one the
        # lifecycle contract names, and the credential never enters the
        # retained transcript or the retained facts.
        self.assertIn(b"stty -echo", sent)
        self.assertIn(b"passwd " + RESCUE_PRINCIPAL.encode("ascii"), sent)
        self.assertLess(
            sent.index(b"stty -echo"), sent.index(TEST_CREDENTIAL))
        self.assertEqual(sent.count(TEST_CREDENTIAL + b"\n"), 2)
        self.assertNotIn(TEST_CREDENTIAL + b"\n\n", sent)
        self.assertNotIn(TEST_CREDENTIAL + b"\r", sent)
        self.assertNotIn(TEST_CREDENTIAL, console.transcript)
        self.assertNotIn(
            TEST_CREDENTIAL.decode("ascii"), json.dumps(facts))
        self.assertEqual(console.events, [
            "arch-rescue-command-sent", "arch-rescue-echo-off",
            "arch-rescue-outcome", "arch-rescue-new-password-prompt",
            "arch-rescue-password-sent",
            "arch-rescue-outcome", "arch-rescue-password-confirm-prompt",
            "arch-rescue-password-sent",
            "arch-rescue-outcome", "arch-rescue-result"])

    def test_each_write_follows_the_prompt_it_answers(self):
        # The ordering the whole exchange turns on.  Nothing past the first
        # prompt is scripted ahead here: the guest only prints the
        # confirmation prompt BECAUSE the first write arrived, and only prints
        # its exit code because the second did.  A credential typed ahead of a
        # prompt therefore cannot pass this test -- it would time out.
        console, feeder, sink = self._console()
        feeder.write(self._ready(console) + LIVE_RESCUE_TAIL)
        replies = [
            b"\r\n" + PAM_SSS_RETYPE,
            self._updated() + self._result(console, b"0"),
        ]
        real_send = console._send

        def answering_send(value, event):
            real_send(value, event)
            if event == "arch-rescue-password-sent" and replies:
                feeder.write(replies.pop(0))

        console._send = answering_send
        facts = new_boot_facts()
        set_rescue_password(console, facts, TEST_CREDENTIAL, timeout=2.0)
        self.assertEqual(replies, [])
        self.assertTrue(facts["rescue_password_set"])
        self.assertEqual(facts["rescue_credential_writes"], 2)
        self.assertEqual(self._sent(sink).count(TEST_CREDENTIAL + b"\n"), 2)
        self.assertEqual(console.events, [
            "arch-rescue-command-sent", "arch-rescue-echo-off",
            "arch-rescue-outcome", "arch-rescue-new-password-prompt",
            "arch-rescue-password-sent",
            "arch-rescue-outcome", "arch-rescue-password-confirm-prompt",
            "arch-rescue-password-sent",
            "arch-rescue-outcome", "arch-rescue-password-updated",
            "arch-rescue-outcome", "arch-rescue-result"])

    def test_both_pam_modules_may_ask_and_the_exchange_still_converges(self):
        # pam_sss asks first and only then discovers local-rescue is not a
        # domain account; whether pam_unix reuses that authtok or asks its own
        # pair is a property of the installed module.  Four writes converge.
        console, feeder, sink = self._console()
        feeder.write(
            self._ready(console)
            + b"\r\n" + PAM_SSS_NEW + b"\r\n" + PAM_SSS_RETYPE
            + b"\r\n" + PAM_UNIX_NEW + b"\r\n" + PAM_UNIX_RETYPE
            + self._updated() + self._result(console, b"0"))
        facts = new_boot_facts()
        set_rescue_password(console, facts, TEST_CREDENTIAL, timeout=2.0)
        self.assertTrue(facts["rescue_password_set"])
        self.assertEqual(facts["rescue_credential_writes"], 4)
        self.assertEqual(facts["rescue_credential_writes"],
                         RESCUE_PASSWORD_WRITES)
        self.assertEqual(self._sent(sink).count(TEST_CREDENTIAL + b"\n"), 4)

    def test_confirmation_prompt_never_satisfies_the_first_prompt(self):
        # "Reenter new Password:" literally contains "new Password:", so
        # without the line anchor the two asks would be indistinguishable and
        # the exchange could not tell a confirmation from a re-ask.
        pattern = re.compile(rescue_prompt_pattern(), re.MULTILINE)
        for retype in (PAM_SSS_RETYPE, PAM_UNIX_RETYPE):
            match = pattern.search(b"\r\n" + retype)
            self.assertIsNotNone(match, retype)
            self.assertIsNone(match.group("new"), retype)
            self.assertIsNotNone(match.group("retype"), retype)

    def test_no_partial_read_of_the_live_tail_forges_a_verdict(self):
        # The elevation lost a live run to a verdict pattern that matched a
        # prefix at a serial read boundary.  No prefix of this exchange's own
        # output may produce an rc or a passwd diagnostic.
        pattern = re.compile(
            rescue_outcome_pattern("feedfacefeedface"), re.MULTILINE)
        stream = (
            b"\r\n__TELOS_ARCH_RESCUE_READY_feedfacefeedface__\r\n"
            + PAM_SSS_NEW + b"\r\n" + PAM_SSS_RETYPE
            + b"\r\npasswd: " + RESCUE_UPDATED_DIAGNOSTIC
            + b"\r\n__TELOS_ARCH_RESCUE_RC_feedfacefeedface=10\r\n")
        for length in range(1, len(stream)):
            match = pattern.search(stream[:length])
            if match is None:
                continue
            if match.group("rc") is not None:
                self.fail(f"prefix of {length} bytes forged an exit code")
            if match.group("diag") is not None:
                self.fail(f"prefix of {length} bytes forged a diagnostic")
        # The complete stream does settle, and on the real two-digit code.
        settled = pattern.search(stream)
        self.assertIsNotNone(settled)
        tail = pattern.search(
            b"\n__TELOS_ARCH_RESCUE_RC_feedfacefeedface=10\r\n")
        self.assertEqual(tail.group("rc"), b"10")

    def test_missing_prompt_never_writes_the_credential(self):
        # THE named 2026-08-14 stop: echo off, no ask, nothing written.
        console, feeder, sink = self._console()
        feeder.write(self._ready(console))
        facts = new_boot_facts()
        with self.assertRaises(ArchIdentityError) as caught:
            set_rescue_password(
                console, facts, TEST_CREDENTIAL, timeout=0.5,
                prompt_timeout=0.3)
        self.assertEqual(str(caught.exception), RESCUE_PROMPT_MISSING_FAILURE)
        self.assertEqual(caught.exception.check, "arch-local-rescue")
        self.assertTrue(facts["rescue_echo_suppressed"])
        self.assertFalse(facts["rescue_prompt_seen"])
        self.assertFalse(facts["rescue_credential_sent"])
        self.assertEqual(facts["rescue_credential_writes"], 0)
        self.assertNotIn(TEST_CREDENTIAL, self._sent(sink))

    def test_missing_ready_marker_never_writes_the_credential(self):
        console, feeder, sink = self._console()
        feeder.write(b"[root@telos-ws1 ~]# \n")
        facts = new_boot_facts()
        with self.assertRaises(ArchIdentityError) as caught:
            set_rescue_password(
                console, facts, TEST_CREDENTIAL, timeout=0.4)
        self.assertEqual(
            str(caught.exception), RESCUE_ECHO_NOT_SUPPRESSED_FAILURE)
        self.assertFalse(facts["rescue_echo_suppressed"])
        self.assertFalse(facts["rescue_credential_sent"])
        self.assertNotIn(TEST_CREDENTIAL, self._sent(sink))

    def test_a_half_written_exchange_names_the_confirmation(self):
        console, feeder, sink = self._console()
        feeder.write(self._ready(console) + LIVE_RESCUE_TAIL)
        facts = new_boot_facts()
        with self.assertRaises(ArchIdentityError) as caught:
            set_rescue_password(
                console, facts, TEST_CREDENTIAL, timeout=1.0,
                prompt_timeout=0.3)
        self.assertEqual(
            str(caught.exception), RESCUE_CONFIRM_PROMPT_MISSING_FAILURE)
        self.assertTrue(facts["rescue_prompt_seen"])
        self.assertFalse(facts["rescue_confirm_prompt_seen"])
        self.assertEqual(facts["rescue_credential_writes"], 1)
        # Exactly one write, and nothing typed after it: a shell command typed
        # into a reader that is still waiting is how run 10 lost its sudo.
        self.assertEqual(self._sent(sink).count(TEST_CREDENTIAL + b"\n"), 1)

    def test_a_passwd_diagnostic_is_the_named_rejection(self):
        console, feeder, sink = self._console()
        feeder.write(
            self._ready(console) + LIVE_RESCUE_TAIL
            + b"\r\n" + PAM_SSS_RETYPE
            + b"\r\npasswd: Authentication token manipulation error\r\n")
        facts = new_boot_facts()
        with self.assertRaises(ArchIdentityError) as caught:
            set_rescue_password(console, facts, TEST_CREDENTIAL, timeout=2.0)
        self.assertEqual(
            str(caught.exception), RESCUE_CREDENTIAL_REJECTED_FAILURE)
        self.assertEqual(caught.exception.check, "arch-local-rescue")
        self.assertTrue(facts["rescue_credential_rejected"])
        self.assertFalse(facts["rescue_password_set"])
        self.assertFalse(facts["rescue_password_updated"])
        # The diagnostic never carries the value, and neither does the stop.
        self.assertNotIn(
            TEST_CREDENTIAL.decode("ascii"),
            str(caught.exception) + json.dumps(facts))
        self.assertEqual(self._sent(sink).count(TEST_CREDENTIAL + b"\n"), 2)

    def test_asking_past_the_write_budget_is_the_named_rejection(self):
        console, feeder, sink = self._console()
        feeder.write(
            self._ready(console)
            + (b"\r\n" + PAM_SSS_NEW + b"\r\n" + PAM_SSS_RETYPE) * 3)
        facts = new_boot_facts()
        with self.assertRaises(ArchIdentityError) as caught:
            set_rescue_password(console, facts, TEST_CREDENTIAL, timeout=2.0)
        self.assertEqual(
            str(caught.exception), RESCUE_CREDENTIAL_REJECTED_FAILURE)
        self.assertTrue(facts["rescue_credential_rejected"])
        # Bounded: the value is written RESCUE_PASSWORD_WRITES times, never
        # once more, however long the stack keeps asking.
        self.assertEqual(
            facts["rescue_credential_writes"], RESCUE_PASSWORD_WRITES)
        self.assertEqual(
            self._sent(sink).count(TEST_CREDENTIAL + b"\n"),
            RESCUE_PASSWORD_WRITES)

    def test_nonzero_passwd_return_is_the_named_exit_failure(self):
        console, feeder, _sink = self._console()
        feeder.write(
            self._ready(console)
            + PAM_UNIX_NEW
            + b"\n" + PAM_UNIX_RETYPE
            + self._result(console, b"1"))
        facts = new_boot_facts()
        with self.assertRaises(ArchIdentityError) as caught:
            set_rescue_password(console, facts, TEST_CREDENTIAL, timeout=2.0)
        self.assertEqual(str(caught.exception), RESCUE_PASSWD_EXITED_FAILURE)
        self.assertEqual(caught.exception.check, "arch-local-rescue")
        self.assertFalse(facts["rescue_password_set"])
        self.assertEqual(facts["rescue_returncode"], 1)
        self.assertFalse(facts["rescue_credential_rejected"])

    def test_a_zero_exit_without_an_ask_is_never_recorded_as_set(self):
        # passwd cannot have set a password it never asked for, whatever it
        # exited with; the fact must not be fabricated from an exit code.
        console, feeder, _sink = self._console()
        feeder.write(self._ready(console) + self._result(console, b"0"))
        facts = new_boot_facts()
        with self.assertRaises(ArchIdentityError) as caught:
            set_rescue_password(console, facts, TEST_CREDENTIAL, timeout=2.0)
        self.assertEqual(str(caught.exception), RESCUE_PROMPT_MISSING_FAILURE)
        self.assertFalse(facts["rescue_password_set"])
        self.assertEqual(facts["rescue_returncode"], 0)

    def test_every_rescue_failure_names_a_different_layer(self):
        named = [
            RESCUE_ECHO_NOT_SUPPRESSED_FAILURE,
            RESCUE_PROMPT_MISSING_FAILURE,
            RESCUE_CONFIRM_PROMPT_MISSING_FAILURE,
            RESCUE_CREDENTIAL_REJECTED_FAILURE,
            RESCUE_PASSWD_EXITED_FAILURE,
            RESCUE_PASSWORD_FAILURE,
        ]
        self.assertEqual(len(set(named)), len(named))
        # And none of them is the sudo family's, so a stop can never be read
        # as the wrong exchange.
        self.assertEqual(
            set(named) & {
                SUDO_ELEVATION_FAILURE, SUDO_CREDENTIAL_REFUSED_FAILURE,
                SUDO_ECHO_NOT_SUPPRESSED_FAILURE, SUDO_PROMPT_MISSING_FAILURE,
                SUDO_EXITED_FAILURE, SUDO_ROOT_UNPROVEN_FAILURE},
            set())

    def test_every_wait_is_bounded_below_the_exchange_budget(self):
        # The 2026-08-14 run spent its whole 60s budget in ONE wait for a
        # prompt already on the console.  A per-wait bound is what makes a
        # live stop cheap, and the console timeout is restored either way.
        console, feeder, _sink = self._console(timeout=300.0)
        feeder.write(self._ready(console))
        started = time.monotonic()
        with self.assertRaises(ArchIdentityError):
            set_rescue_password(
                console, new_boot_facts(), TEST_CREDENTIAL, timeout=30.0,
                prompt_timeout=0.3)
        self.assertLess(time.monotonic() - started, 10.0)
        self.assertEqual(console.timeout, 300.0)

    def test_an_empty_or_multiline_credential_is_refused_before_any_write(self):
        for bad in (b"", b"one\ntwo", b"one\rtwo"):
            console, _feeder, sink = self._console()
            with self.assertRaisesRegex(
                    ArchIdentityError, "one non-empty line"):
                set_rescue_password(
                    console, new_boot_facts(), bad, timeout=0.2)
            self.assertEqual(self._sent(sink), b"")

    def test_command_never_carries_the_secret(self):
        command, ready, result = rescue_password_command("feedfacefeedface")
        self.assertIn(b"stty -echo", command)
        self.assertIn(b"passwd " + RESCUE_PRINCIPAL.encode("ascii"), command)
        self.assertLess(command.index(b"stty -echo"), command.index(b"passwd"))
        self.assertIn(b"stty echo;", command)
        self.assertIn(ready, command)
        self.assertIn(result, command)
        # The prompt wording is pinned to the msgids rescue_prompt_pattern
        # knows, so a localised guest cannot silently change the exchange.
        self.assertIn(b"LC_ALL=C passwd", command)
        self.assertNotRegex(
            command.decode("ascii"), r"(?i)password[ ]*=|--stdin|chpasswd")

    def test_rescue_check_needs_the_password_gate7_never_sets(self):
        # The probe requires `passwd -S` to report P and gate 7 installs the
        # account with a disabled password, so only this run can satisfy it.
        from homelab.tests.test_arch_second import SIZES
        from homelab.workstations.arch_second import render_installer

        script = render_installer(
            disk_path="/dev/vda", disk_serial="LAPTOP-1",
            hostname="workstation", expected_sizes_mib=SIZES)
        self.assertNotIn(f"passwd {RESCUE_PRINCIPAL}", script)
        self.assertIn(
            '[ "$(passwd -S "$RESCUE_USER" 2>/dev/null | '
            "awk '{print $2}')\" = P ]", script)
        # identity_lifecycle.json gives the account no domain role, so no
        # Controller-staged principal could ever supply its credential.
        contract = json.loads(
            (Path(__file__).resolve().parents[1] / "workstations"
             / "identity_lifecycle.json").read_text(encoding="utf-8"))
        rescue = contract["principals"]["local_rescue"]
        self.assertEqual(rescue["name"], RESCUE_PRINCIPAL)
        self.assertEqual(rescue["domain_role"], "none")
        from homelab.vm.controller_principals import POSIX_ALLOCATION
        self.assertNotIn(RESCUE_PRINCIPAL, POSIX_ALLOCATION["users"])


class LoginAttemptBudgetTests(unittest.TestCase):
    """Pin the retry budget to the faillock threshold it must stay under."""

    def test_attempts_stay_below_pam_faillock_deny(self):
        from homelab.tests.test_arch_second import SIZES
        from homelab.workstations.arch_second import render_installer

        script = render_installer(
            disk_path="/dev/vda", disk_serial="LAPTOP-1",
            hostname="workstation", expected_sizes_mib=SIZES)
        # Gate 7 ships the stock Arch faillock stack with no deny= override,
        # so the default deny=3 applies and the third consecutive failure
        # locks the account for the default 600s unlock_time.  Spending the
        # whole budget would make every later proof fail on a lockout the
        # evidence would misreport as an identity failure.
        self.assertIn("pam_faillock.so      preauth", script)
        self.assertIn("pam_faillock.so      authfail", script)
        self.assertNotIn("deny=", script)
        self.assertNotIn("unlock_time=", script)
        self.assertLess(LOGIN_ATTEMPTS, 3)
        self.assertGreaterEqual(LOGIN_ATTEMPTS, 2)


class SudoPathDecisionTests(unittest.TestCase):
    """Pin the elevation decision to what gate 7 actually stages."""

    def test_gate7_operator_rule_is_passworded_so_the_drive_uses_sudo_s(self):
        from homelab.tests.test_arch_second import SIZES
        from homelab.workstations.arch_second import render_installer

        script = render_installer(
            disk_path="/dev/vda", disk_serial="LAPTOP-1",
            hostname="workstation", expected_sizes_mib=SIZES)
        # W1 stages a passworded rule for the operator: no NOPASSWD grant
        # exists anywhere on the disk, so `sudo -n` cannot elevate a fresh
        # operator session and the probe's self-elevation would be skipped.
        self.assertIn(f"{OPERATOR_PRINCIPAL} ALL=(ALL:ALL) ALL", script)
        self.assertNotIn("NOPASSWD", script)
        # The drive therefore elevates once with echo-suppressed sudo -S
        # and hands the probes a root shell; it never relies on sudo -n.
        command, _ready, prompt, _failed = elevation_command(
            "feedfacefeedface")
        self.assertIn(b"sudo -k -S", command)
        # The credential is written in response to sudo's OWN prompt, so the
        # prompt has to be a marker the harness can wait for.
        self.assertIn(b"-p '" + prompt + b"'", command)
        self.assertIn(b"feedfacefeedface", prompt)
        self.assertIn(b"stty -echo", command)
        self.assertNotIn(b"sudo -n", command)


# --------------------------------------------------------------------------
# Evidence retention: bounded, redacted, secret-free, success and failure.
# --------------------------------------------------------------------------

class EvidenceRetentionTests(unittest.TestCase):
    class _Console:
        def __init__(self, transcript: bytes) -> None:
            self.transcript = transcript
            self.password = b"unused"

        def release_password(self):
            self.password = None

    def test_transcript_is_bounded_redacted_and_private(self):
        from homelab.vm.arch_identity_run import TRANSCRIPT_RETENTION_BYTES
        with tempfile.TemporaryDirectory() as name:
            bundle = make_bundle(Path(name))
            boundary = ArchIdentityBoundary(bundle)
            transcript = (
                b"A" * (TRANSCRIPT_RETENTION_BYTES + 64)
                + b"telos-ws1 login: operator\n"
                b"Password: hunter2secret\n"
                b"token=deadbeefcafe\nTAIL")
            boundary._workstation_console = self._Console(transcript)
            boundary._boot_facts["menu_seen"] = True
            boundary._boot_facts["entry_selected"] = "1"
            failures = boundary.stop()
            self.assertEqual(failures, [])
            evidence = bundle.evidence_path.parent
            log_path = evidence / WORKSTATION_LOG_FILENAME
            log = log_path.read_bytes()
            self.assertLessEqual(len(log), TRANSCRIPT_RETENTION_BYTES)
            self.assertTrue(log.endswith(b"TAIL"))
            self.assertIn(b"Password: [REDACTED]", log)
            self.assertNotIn(b"hunter2secret", log)
            self.assertNotIn(b"deadbeefcafe", log)
            self.assertEqual(log_path.stat().st_mode & 0o777, 0o600)
            facts_path = evidence / BOOT_FACTS_FILENAME
            recorded = json.loads(facts_path.read_text(encoding="utf-8"))
            self.assertEqual(facts_path.stat().st_mode & 0o777, 0o600)
            self.assertTrue(recorded["menu_seen"])
            self.assertEqual(recorded["entry_selected"], "1")
            # Only the declared secret-free facts (plus the schema) exist.
            self.assertEqual(
                sorted(recorded),
                sorted({"schema", *new_boot_facts()}))
            # The workstation credential was released during teardown.
            self.assertEqual(boundary._principals, {})

    def test_stall_evidence_is_bounded(self):
        from homelab.vm.arch_identity_run import (
            BOOT_STALL_RETENTION_LIMIT,
            STALL_QMP_EVENT_LIMIT,
            _bounded_qmp_events,
        )
        with tempfile.TemporaryDirectory() as name:
            boundary = ArchIdentityBoundary(make_bundle(Path(name)))
            for attempt in range(BOOT_STALL_RETENTION_LIMIT + 4):
                boundary._retain_boot_stall_evidence(
                    "timed-out", attempt=attempt + 1, terminal=False,
                    label="arch-menu-rendered")
            records = boundary._boot_facts["boot_stall_evidence"]
            self.assertEqual(len(records), BOOT_STALL_RETENTION_LIMIT)
            # No QMP channel is not a crash: diagnosis never changes the run.
            self.assertEqual(records[0]["qmp"], "unavailable")
        queued = [
            {"event": "BLOCK_IO_ERROR" + "x" * 200,
             "timestamp": {"seconds": 1, "microseconds": 2, "junk": object()},
             "data": {"device": "d" * 400, "nospace": True,
                      **{f"k{index}": index for index in range(20)}}}
        ] * (STALL_QMP_EVENT_LIMIT + 10)
        bounded = _bounded_qmp_events(queued)
        self.assertEqual(len(bounded), STALL_QMP_EVENT_LIMIT)
        self.assertEqual(len(bounded[0]["event"]), 64)
        self.assertEqual(sorted(bounded[0]["timestamp"]),
                         ["microseconds", "seconds"])
        self.assertLessEqual(len(bounded[0]["data"]), 8)
        self.assertEqual(len(bounded[0]["data"]["device"]), 96)
        # Anything that is not a QMP event object is dropped, never guessed.
        self.assertEqual(_bounded_qmp_events(["not-an-event"]), [])
        self.assertEqual(_bounded_qmp_events(None), [])

    def test_switch_log_is_copied_bounded_and_line_aligned(self):
        from homelab.vm.arch_identity_run import (
            SWITCH_LOG_FILENAME, SWITCH_LOG_RETENTION_BYTES)
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            bundle = make_bundle(root)
            boundary = ArchIdentityBoundary(bundle)
            runtime = root / "runtime"
            runtime.mkdir(mode=0o700)
            boundary._runtime = runtime
            record = b'{"event":"switch","seq":%d}\n'
            lines = SWITCH_LOG_RETENTION_BYTES // len(record % 0) + 32
            (runtime / "switch.jsonl").write_bytes(
                b"".join(record % index for index in range(lines)))
            boundary._retain_switch_log()
            retained = (bundle.evidence_path.parent
                        / SWITCH_LOG_FILENAME).read_bytes()
            self.assertLessEqual(len(retained), SWITCH_LOG_RETENTION_BYTES)
            # A tail cut mid-record would leave the file unparseable.
            self.assertTrue(retained.startswith(b'{"event"'))
            self.assertTrue(retained.endswith(b"}\n"))

    def test_retention_failure_is_reported_not_raised(self):
        with tempfile.TemporaryDirectory() as name:
            bundle = make_bundle(Path(name))
            boundary = ArchIdentityBoundary(bundle)
            elsewhere = Path(name) / "elsewhere"
            elsewhere.mkdir(mode=0o700)
            (bundle.bundle / "evidence").symlink_to(elsewhere)
            boundary._workstation_console = self._Console(b"transcript")
            failures = boundary.stop()
            self.assertTrue(any(
                "evidence retention failed" in item for item in failures))


if __name__ == "__main__":
    unittest.main()
