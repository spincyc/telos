"""Prove the Arch identity producer and the real judge agree end-to-end.

These tests never boot QEMU or open a real serial console. They drive
``ArchIdentityDrive`` with a scripted serial double, assemble evidence, and
feed it to the *real* ``identity_lifecycle.judge`` imported from the
workstations judge, so the producer and the grader are proven to agree without
a live guest. They also assert dry-run gating and fail-closed bundle
validation.
"""

import json
import re
import sys
import tempfile
import unittest
from pathlib import Path

from homelab.vm import arch_identity_run
from homelab.vm.arch_identity_run import (
    ArchIdentityBundle,
    ArchIdentityDrive,
    ArchIdentityError,
    CHECK_DETAILS,
    REQUIRED_CHECKS,
    WINDOWS_CHECKS,
    assemble_evidence,
    run,
    run_lifecycle,
    self_judge,
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
)
CONTROLLER_OUTCOME_CHECKS = (
    "controller-ready", "controller-offline", "controller-restored")


class _FakeMatch:
    def __init__(self, verdict: bytes) -> None:
        self._verdict = verdict

    def group(self, index: int) -> bytes:
        return self._verdict


class FakeSerialChannel:
    """A scripted stand-in for SerialAutomation's low-level surface.

    ``results`` maps a check name to "PASS", "FAIL", or "TIMEOUT". The channel
    records every command it is asked to send and answers each probe with the
    scripted verdict, so a drive can be exercised deterministically.
    """

    def __init__(self, results: dict[str, str]) -> None:
        self.token = "deadbeefcafef00d"
        self.results = results
        self.sent: list[bytes] = []
        self._pending: str | None = None

    def _send(self, value: bytes, event: str) -> None:
        self.sent.append(value)
        parts = value.decode("ascii").split()
        # /usr/local/sbin/homelab-arch-identity-probe <check> <token>
        self._pending = parts[1]

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
        return _FakeMatch(b"PASS" if verdict == "PASS" else b"FAIL")


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
    ) -> None:
        self.channel = FakeSerialChannel(drive_results or {})
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
        # exercised with, or the two could silently diverge.
        from homelab.tests.test_identity_lifecycle import valid_events
        for item in valid_events(self.contract):
            fields = {k: v for k, v in item.items()
                      if k not in {"check", "result", "external_access"}}
            self.assertEqual(
                fields, CHECK_DETAILS[item["check"]], item["check"])

    def test_producer_order_matches_the_contract(self):
        self.assertEqual(
            list(REQUIRED_CHECKS), self.contract["required_checks"])

    def test_simulated_successful_drive_is_accepted_by_the_real_judge(self):
        session = FakeSession()
        events = run_lifecycle(session)
        # The full, ordered 18-check stream the real judge accepts.
        result = lifecycle.judge(self.contract, events)
        self.assertEqual(result["result"], "pass")
        self.assertEqual(result["checks"], len(REQUIRED_CHECKS))
        self.assertFalse(result["external_access"])
        # The whole lifecycle was driven, with the outage between cache proofs.
        self.assertEqual(
            session.events,
            ["start", "open_channel", "offline", "restore", "stop"])

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
        assembled = assemble_evidence(outcomes, events)
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


if __name__ == "__main__":
    unittest.main()
