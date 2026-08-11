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
    GETTY_NEVER_APPEARED_FAILURE,
    LOGIN_REFUSED_FAILURE,
    MAX_DURATION,
    MEASURED_CHECK_FIELDS,
    MENU_NEVER_RENDERED_FAILURE,
    MENU_WINDOW_MISSED_FAILURE,
    OPERATOR_PRINCIPAL,
    REQUIRED_CHECKS,
    SUDO_ELEVATION_FAILURE,
    WINDOWS_CHECKS,
    WORKSTATION_LOG_FILENAME,
    assemble_evidence,
    audit_arch_identity_boot,
    drive_boot_menu,
    elevate_operator,
    elevation_command,
    login_operator,
    new_boot_facts,
    run,
    run_lifecycle,
    self_judge,
    workstation_boot_command,
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


class _FakeMatch:
    """Match double whose numbered groups are scripted."""

    def __init__(self, groups) -> None:
        if not isinstance(groups, dict):
            groups = {1: groups}
        self._groups = groups

    def group(self, index: int = 0):
        return self._groups.get(index)


class FakeSerialChannel:
    """A scripted stand-in for SerialAutomation's low-level surface.

    ``results`` maps a check name to "PASS", "FAIL", or "TIMEOUT" (plus
    "PASS_WITHOUT_SECONDS" for the storage-absent probe, which then skips
    its measured data line). The channel records every command it is asked
    to send and answers each probe with the scripted verdict, so a drive
    can be exercised deterministically.
    """

    def __init__(self, results: dict[str, str], *,
                 login_seconds: int = 4) -> None:
        self.token = "deadbeefcafef00d"
        self.results = results
        self.login_seconds = login_seconds
        self.sent: list[bytes] = []
        self._pending: str | None = None
        self._data_line_sent = False

    def _send(self, value: bytes, event: str) -> None:
        self.sent.append(value)
        parts = value.decode("ascii").split()
        # /usr/local/sbin/homelab-arch-identity-probe <check> <token>
        self._pending = parts[1]
        self._data_line_sent = False

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
        if check == "arch-storage-absent-login":
            if not self._data_line_sent and verdict != "PASS_WITHOUT_SECONDS":
                self._data_line_sent = True
                return _FakeMatch(
                    {1: str(self.login_seconds).encode("ascii"), 2: None})
            passed = verdict in ("PASS", "PASS_WITHOUT_SECONDS")
            return _FakeMatch({1: None, 2: b"PASS" if passed else b"FAIL"})
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
        # producer measures live (MEASURED_CHECK_FIELDS) are excluded from
        # the static template but must exist in the fixture.
        from homelab.tests.test_identity_lifecycle import valid_events
        for item in valid_events(self.contract):
            check = item["check"]
            fields = {k: v for k, v in item.items()
                      if k not in {"check", "result", "external_access"}}
            measured = set(MEASURED_CHECK_FIELDS.get(check, ()))
            for name in measured:
                self.assertIn(name, fields, check)
            static = {k: v for k, v in fields.items() if k not in measured}
            self.assertEqual(static, CHECK_DETAILS[check], check)

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
                ArchIdentityError, "measured login duration") as caught:
            run_lifecycle(session)
        self.assertEqual(
            caught.exception.check, "arch-storage-absent-login")
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
            measurements={"arch-storage-absent-login": {"login_seconds": 4}})
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

    def test_boots_from_disk_only(self):
        from homelab.vm.arch_install_prepare import DISK_SERIAL
        with tempfile.TemporaryDirectory() as name:
            command = self._command(Path(name))
        self.assertIn("order=c,menu=off", command)
        self.assertFalse(any("order=n" in item for item in command))
        self.assertNotIn("-cdrom", command)
        self.assertFalse(any("media=cdrom" in item for item in command))
        # The joined disk is cold-plugged as the NVMe the installer targeted,
        # firmware-bootable, so OVMF's proven ESP auto-discovery boots it.
        self.assertIn(
            f"nvme,drive=osdisk,serial={DISK_SERIAL},bootindex=1", command)
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
    def __init__(self) -> None:
        self.calls: list[tuple[str, object]] = []
        self.closed = False

    def execute(self, command, arguments=None, **_kw):
        self.calls.append((command, arguments))
        return {}

    def await_device_deleted(self, device, timeout=None):
        self.calls.append(("await_device_deleted", device))

    def close(self):
        self.closed = True


#: Cross-object ordering ledger for the wiring tests: process spawns and
#: principal staging append here so their relative order is provable.
TIMELINE: list[str] = []


class _FakeSerial:
    """Stands in for SerialAutomation on both consoles.

    The workstation flow (menu -> getty login -> sudo elevation) is scripted
    per wait label; the class attributes flip individual outcomes.
    """

    instances: list["_FakeSerial"] = []
    console_banner = b"[root@telos-ws1 ~]# "
    menu_render = (
        b"Arch Linux LTS\n  Windows Boot Manager\n"
        b"  Reboot Into Firmware Interface")
    login_outcome: bytes | None = None  # group(1): b"Login incorrect"
    sudo_outcome: bytes | None = None  # group(1): failure return code
    root_uid = b"0"
    transcript = b""

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
        self.calls.append(f"wait:{label}")
        self.events.append(label)
        if label == "arch-menu-rendered":
            return _FakeMatch({0: type(self).menu_render})
        if label == "arch-login-outcome":
            return _FakeMatch({0: b"", 1: type(self).login_outcome})
        if label == "arch-sudo-outcome":
            return _FakeMatch({0: b"", 1: type(self).sudo_outcome})
        if label == "arch-root-verified":
            return _FakeMatch({0: b"", 1: type(self).root_uid})
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
        _FakeSerial.root_uid = b"0"
        _FakeSerial.transcript = b""
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
        ]
        for patch in self._patches:
            patch.start()
            self.addCleanup(patch.stop)
        _FakePrincipalSerial.instances = []
        _FakePrincipalSerial.fail = False
        TIMELINE.clear()

    def _boundary(self, root: Path) -> _WiredBoundary:
        bundle = make_bundle(root)
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
                ])
                self.assertTrue(boundary.observe_controller_ready())
                # The convergence media and its password never survive.
                self.assertIsNone(boundary._factory_media)
                # Principals are staged after the Controller converges and
                # strictly before the workstation boots; the workstation
                # console owns the staged operator credential.
                self.assertEqual(TIMELINE, [
                    "spawn:switch", "spawn:gateway", "spawn:controller",
                    "stage-principals", "spawn:workstation"])
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
                # Menu -> getty -> login -> elevation, in order, over serial.
                self.assertEqual(workstation_console.events, [
                    "arch-menu-rendered", "arch-menu-entry-selected",
                    "arch-handoff-observed", "arch-getty-observed",
                    "arch-login-username-sent", "arch-login-password-prompt",
                    "arch-login-password-sent", "arch-login-outcome",
                    "arch-sudo-command-sent", "arch-sudo-echo-off",
                    "arch-sudo-password-sent", "arch-sudo-outcome",
                    "arch-root-proof-requested", "arch-root-verified",
                ])
                # The Arch entry (listed first) was selected with its raw
                # digit key: no newline that would be typed ahead.
                self.assertEqual(
                    workstation_console.writer.getvalue(), b"1")
                facts = boundary._boot_facts
                self.assertTrue(facts["menu_seen"])
                self.assertEqual(facts["entry_selected"], "1")
                self.assertTrue(facts["handoff_seen"])
                self.assertTrue(facts["getty_seen"])
                self.assertTrue(facts["login_completed"])
                self.assertTrue(facts["sudo_elevated"])
                self.assertEqual(facts["menu_retries"], 0)
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
            with self.assertRaisesRegex(
                    ArchIdentityError, "sudo -S elevation") as caught:
                boundary.start()
            self.assertEqual(caught.exception.check, "arch-joined")
            self.assertEqual(boundary._processes, {})

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

MENU_ARCH_FIRST = (
    b"BdsDxe: loading Boot0001 \"Linux Boot Manager\"\n"
    b"  Arch Linux LTS\n"
    b"  Windows Boot Manager\n"
    b"  Reboot Into Firmware Interface\n"
)
MENU_WINDOWS_FIRST = (
    b"BdsDxe: loading Boot0001\n"
    b"  Windows Boot Manager\n"
    b"  Arch Linux LTS\n"
    b"  Reboot Into Firmware Interface\n"
)
HANDOFF = b"EFI stub: Loaded initrd from LINUX_EFI_INITRD_MEDIA_GUID\n"
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
        feeder.write(MENU_ARCH_FIRST + HANDOFF)
        facts = new_boot_facts()
        resets: list[int] = []
        drive_boot_menu(
            console, facts, reset=lambda: resets.append(1),
            menu_timeout=2.0, handoff_timeout=2.0)
        self.assertTrue(facts["menu_seen"])
        self.assertEqual(facts["entry_selected"], "1")
        self.assertTrue(facts["handoff_seen"])
        self.assertEqual(facts["menu_retries"], 0)
        self.assertEqual(resets, [])
        # The raw digit key, nothing else: no newline is typed ahead.
        self.assertEqual(self._sent(sink), b"1")
        self.assertEqual(console.events, [
            "arch-menu-rendered", "arch-menu-entry-selected",
            "arch-handoff-observed"])

    def test_menu_digit_follows_render_order(self):
        console, feeder, sink = self._console()
        feeder.write(MENU_WINDOWS_FIRST + HANDOFF)
        facts = new_boot_facts()
        drive_boot_menu(
            console, facts, reset=lambda: None,
            menu_timeout=2.0, handoff_timeout=2.0)
        self.assertEqual(facts["entry_selected"], "2")
        self.assertEqual(self._sent(sink), b"2")

    def test_missed_window_power_cycles_once_and_retries(self):
        console, feeder, sink = self._console()
        feeder.write(MENU_ARCH_FIRST)  # no handoff: Windows is booting

        def reset():
            feeder.write(MENU_ARCH_FIRST + HANDOFF)

        resets: list[int] = []
        facts = new_boot_facts()
        drive_boot_menu(
            console, facts,
            reset=lambda: (resets.append(1), reset()),
            menu_timeout=2.0, handoff_timeout=0.3)
        self.assertEqual(resets, [1])
        self.assertEqual(facts["menu_retries"], 1)
        self.assertTrue(facts["handoff_seen"])
        self.assertEqual(self._sent(sink), b"11")
        self.assertIn("arch-workstation-power-cycled", console.events)

    def test_second_miss_is_the_named_window_failure(self):
        console, feeder, _sink = self._console()
        feeder.write(MENU_ARCH_FIRST)
        resets: list[int] = []

        def reset():
            resets.append(1)
            feeder.write(MENU_ARCH_FIRST)  # still no handoff

        with self.assertRaisesRegex(
                ArchIdentityError,
                "missed the five-second menu window") as caught:
            drive_boot_menu(
                console, new_boot_facts(), reset=reset,
                menu_timeout=2.0, handoff_timeout=0.3)
        self.assertEqual(caught.exception.check, "arch-joined")
        self.assertEqual(resets, [1])
        self.assertEqual(str(caught.exception), MENU_WINDOW_MISSED_FAILURE)

    def test_menu_that_never_renders_is_the_named_menu_failure(self):
        console, feeder, _sink = self._console()
        feeder.write(b"BdsDxe: starting nothing interesting\n")
        feeder.close()
        with self.assertRaises(ArchIdentityError) as caught:
            drive_boot_menu(
                console, new_boot_facts(), reset=lambda: None,
                menu_timeout=0.5, handoff_timeout=0.3)
        self.assertEqual(str(caught.exception), MENU_NEVER_RENDERED_FAILURE)
        self.assertEqual(caught.exception.check, "arch-joined")


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


class ElevationTests(SerialTranscriptCase):
    def _ready(self, console) -> bytes:
        return (b"\n__TELOS_ARCH_SUDO_READY_"
                + console.token.encode("ascii") + b"__\n")

    def _root_proof(self, console, uid: bytes) -> bytes:
        return (b"\n__TELOS_ARCH_ROOT_"
                + console.token.encode("ascii") + b"=" + uid + b"\n")

    def test_echo_off_password_root_shell_sequence(self):
        console, feeder, sink = self._console()
        feeder.write(
            self._ready(console)
            + b"[root@telos-ws1 ~]# "
            + self._root_proof(console, b"0"))
        facts = new_boot_facts()
        elevate_operator(console, facts, timeout=2.0)
        self.assertTrue(facts["sudo_elevated"])
        sent = self._sent(sink)
        # Echo is provably off before the credential is written, the
        # elevation is sudo -S (the gate-7 rule is passworded), and the
        # credential itself never enters the guest transcript.
        self.assertIn(b"stty -echo", sent)
        self.assertIn(b"sudo -k -S -p ''", sent)
        self.assertNotIn(b"sudo -n", sent)
        self.assertLess(
            sent.index(b"stty -echo"), sent.index(TEST_CREDENTIAL))
        self.assertNotIn(TEST_CREDENTIAL, console.transcript)
        self.assertEqual(console.events[:4], [
            "arch-sudo-command-sent", "arch-sudo-echo-off",
            "arch-sudo-password-sent", "arch-sudo-outcome"])

    def test_sudo_nonzero_return_is_the_named_elevation_failure(self):
        console, feeder, _sink = self._console()
        feeder.write(
            self._ready(console)
            + b"\n__TELOS_ARCH_SUDO_RC_"
            + console.token.encode("ascii") + b"=1\n")
        with self.assertRaises(ArchIdentityError) as caught:
            elevate_operator(console, new_boot_facts(), timeout=2.0)
        self.assertEqual(str(caught.exception), SUDO_ELEVATION_FAILURE)
        self.assertEqual(caught.exception.check, "arch-joined")

    def test_non_root_shell_is_the_named_elevation_failure(self):
        console, feeder, _sink = self._console()
        feeder.write(
            self._ready(console)
            + b"[operator@telos-ws1 ~]# "
            + self._root_proof(console, b"1000"))
        facts = new_boot_facts()
        with self.assertRaises(ArchIdentityError) as caught:
            elevate_operator(console, facts, timeout=2.0)
        self.assertEqual(str(caught.exception), SUDO_ELEVATION_FAILURE)
        self.assertFalse(facts["sudo_elevated"])


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
        command, _ready, _failed = elevation_command("feedfacefeedface")
        self.assertIn(b"sudo -k -S", command)
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
