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
from unittest import mock

from homelab.vm import arch_identity_run
from homelab.vm.arch_identity_run import (
    ArchIdentityBoundary,
    ArchIdentityBundle,
    ArchIdentityDrive,
    ArchIdentityError,
    CHECK_DETAILS,
    MAX_DURATION,
    REQUIRED_CHECKS,
    WINDOWS_CHECKS,
    assemble_evidence,
    audit_arch_identity_boot,
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
        self.stdout = None
        self.stdin = None
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


class _FakeMatchBytes:
    def __init__(self, value: bytes) -> None:
        self.value = value

    def group(self, index: int) -> bytes:
        return self.value


class _FakeSerial:
    """Stands in for SerialAutomation on both consoles."""

    instances: list["_FakeSerial"] = []
    console_banner = b"[root@telos-workstation ~]# "

    def __init__(self, reader, writer, password, *, timeout=90.0,
                 clock=None) -> None:
        self.password = password
        self.timeout = timeout
        self.calls: list[str] = []
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

    def _wait(self, pattern, label):
        self.calls.append(f"wait:{label}")
        return _FakeMatchBytes(self.console_banner)


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
        ]
        for patch in self._patches:
            patch.start()
            self.addCleanup(patch.stop)

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
                # The drive can open the workstation console.
                channel = boundary.open_channel()
                self.assertEqual(channel.timeout,
                                 arch_identity_run.PROBE_TIMEOUT)
            finally:
                failures = boundary.stop()
            self.assertEqual(failures, [])
            self.assertTrue(_FakeDisposableDisk.instances[0].closed)

    def test_workstation_login_prompt_is_refused(self):
        with tempfile.TemporaryDirectory() as name:
            boundary = self._boundary(Path(name))
            banner = _FakeSerial.console_banner
            _FakeSerial.console_banner = b"telos-workstation login: "
            try:
                with self.assertRaisesRegex(
                        ArchIdentityError, "credential login") as caught:
                    boundary.start()
            finally:
                _FakeSerial.console_banner = banner
            self.assertEqual(caught.exception.check, "arch-joined")
            # start() failed after spawning; it must have torn down itself.
            self.assertEqual(boundary._processes, {})
            self.assertTrue(_FakeDisposableDisk.instances[0].closed)

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


if __name__ == "__main__":
    unittest.main()
