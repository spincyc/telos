"""The durable Arch install runner (TASK-28 step 6), with every guest faked.

Nothing here boots QEMU or reads ``build/``, ``homelab/var/`` or
``homelab/instance/``: the persistent binding is constructed, gate 7's prepare
and the live install are fakes, the kept workstation lives in a temporary
directory, and the one real installer render pins the roster overlay absent.
Every realm, SID and name is synthetic.
"""

import contextlib
import hashlib
import io
import json
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from homelab.tests.ovmf_store_fixture import store
from homelab.vm import arch_durable_install_run as durable
from homelab.vm import arch_install_run as gate7
from homelab.vm import ovmf_vars
from homelab.vm import workstation_instance as wi
from homelab.vm.durable_workstation import DurableBinding, DurableBindingError
from homelab.workstations import arch_second
from homelab.workstations.arch_second import (
    JOIN_DEFERRED_MARKER, JOIN_MEDIA_CONSUMED_MARKER, JOIN_VERIFIED_MARKER,
    NVRAM_ENTRIES_MARKER, NVRAM_ORDER_MARKER, InstallerRealm,
    synthetic_installer_realm)


DOMAIN = "durable.example.test"
REALM = DOMAIN.upper()
NETBIOS = "DURABLE"
BOOTSTRAP = f"bootstrap-dc.{DOMAIN}"
SID = "S-1-5-21-11-22-33"
FINGERPRINT = "0123456789abcdef"
INSTANCE = "synthetic-dc"
HOSTNAME = "kept-ws1"
DISK_SERIAL = "TELOS-WIN-0001"
RELEASE = "2026.09.01"
#: Values that must never reach a plan line or a result record.
PRIVATE_VALUES = (DOMAIN, REALM, BOOTSTRAP, SID, NETBIOS)


def binding(**overrides) -> DurableBinding:
    values = dict(
        instance=INSTANCE, state=Path("/nonexistent/persistent") / INSTANCE,
        dns_domain=DOMAIN, kerberos_realm=REALM, netbios_name=NETBIOS,
        controller_fqdn=BOOTSTRAP, permanent_dc_fqdn=f"dc1.{DOMAIN}",
        domain_sid=SID, roster_fingerprint=FINGERPRINT,
        identity_source="a test")
    values.update(overrides)
    return DurableBinding(**values)


def durable_realm(**overrides) -> InstallerRealm:
    values = dict(
        dns_domain=DOMAIN, kerberos_realm=REALM, workgroup=NETBIOS,
        controller_fqdn=BOOTSTRAP, durable=True, source="a test")
    values.update(overrides)
    return InstallerRealm(**values)


def realm_record(**overrides) -> dict:
    record = {
        "dns_domain": DOMAIN, "kerberos_realm": REALM,
        "netbios_name": NETBIOS, "controller_fqdn": BOOTSTRAP,
        "durable": True}
    record.update(overrides)
    return record


def synthetic_record() -> dict:
    realm = synthetic_installer_realm()
    return {
        "dns_domain": realm.dns_domain, "kerberos_realm": realm.kerberos_realm,
        "netbios_name": realm.workgroup,
        "controller_fqdn": realm.controller_fqdn, "durable": False}


def installer_script(*, controller: str = BOOTSTRAP, deferred: bool = True,
                     fingerprint: str = FINGERPRINT,
                     srv_first: bool = True) -> str:
    discovery = f"_srv_, {controller}" if srv_first else controller
    lines = [
        "#!/bin/bash", "set -euo pipefail", "[domain/synthetic]",
        f"ad_server = {discovery}", f"ROSTER_FINGERPRINT='{fingerprint}'"]
    if deferred:
        lines.append(f'echo "{JOIN_DEFERRED_MARKER}"')
    return "\n".join(lines) + "\n"


def transcript(*, join=(JOIN_DEFERRED_MARKER,), pxe: int = 1,
               attach_before_live: bool = False, fail: bool = False,
               after_complete=()) -> str:
    """A synthetic serial transcript carrying every marker gate 7 requires."""
    attached = f"{gate7.DISK_ATTACHED_MARKER} serial={DISK_SERIAL}"
    lines = ['BdsDxe: starting Boot0001 "UEFI PXEv4 (MAC:525400000002)"'] * pxe
    if attach_before_live:
        lines.append(attached)
    lines += ["Welcome to Arch Linux", "archiso login: root", gate7.BEGIN_MARKER]
    if not attach_before_live:
        lines.append(attached)
    lines += list(join)
    lines += [
        gate7.VERIFY_PASS_MARKER, gate7.PRESERVED_MARKER,
        "TELOS ARCH BOOTLOADER LINUX PRESENT",
        "TELOS ARCH BOOTLOADER WINDOWS PRESERVED",
        "TELOS ARCH DEFAULT auto-windows",
        NVRAM_ENTRIES_MARKER, NVRAM_ORDER_MARKER]
    if fail:
        lines.append(f"{gate7.FAIL_MARKER} rc=1")
    lines.append(gate7.COMPLETE_MARKER)
    lines += list(after_complete)
    return "\n".join(lines) + "\n"


def _digest(path: Path) -> str:
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def snapshot(directory: Path) -> dict:
    """Every file's content digest; the lock file is not state."""
    return {
        path.name: _digest(path) for path in sorted(directory.iterdir())
        if path.is_file() and path.name != wi.LOCK_NAME}


#: The install bundle's variables after the hot-attached install boot: the
#: authored entry, and the boot-path cache that boot's topology left behind.
INSTALLED_VARS = store("Linux Boot Manager", hddp=True)


def write_workstation(root: Path, name: str = "w1", *, ledger_extra=(),
                      recorded_sid: str = SID, pending=None) -> Path:
    """A kept workstation's state, written the way ``adopt`` leaves it."""
    state = root / name
    state.mkdir(parents=True, mode=0o700)
    disk = state / wi.DISK_NAME
    disk.write_bytes(b"synthetic kept disk\n")
    firmware = state / wi.VARS_NAME
    firmware.write_bytes(b"synthetic gate-5 firmware vars\n")
    (state / wi.PUBLICATION_NAME).write_bytes(b"synthetic publication\n")
    for path in (disk, firmware, state / wi.PUBLICATION_NAME):
        path.chmod(0o600)
    ledger = [{
        "stage": "adopt", "utc": "2026-09-30T00:00:00+00:00",
        "disk_sha256": _digest(disk), "vars_sha256": _digest(firmware),
        "source": "/runs/gate5"}]
    ledger += list(ledger_extra)
    marker = {
        "schema": wi.MARKER_SCHEMA, "kind": wi.MARKER_KIND, "workstation": name,
        "created_utc": "2026-09-30T00:00:00+00:00",
        "binding": {"persistent_instance": INSTANCE, "realm": REALM,
                    "domain_sid": recorded_sid},
        "disk": {"format": "qcow2", "name": wi.DISK_NAME, "standalone": True},
        "publication": {"name": wi.PUBLICATION_NAME,
                        "received_utc": "2026-09-30T00:00:00+00:00",
                        "from_bundle": "/runs/gate5", "note": "synthetic"},
        "machine_accounts": [],
        "ledger": ledger,
    }
    if pending is not None:
        marker["pending_fold"] = pending
    (state / wi.MARKER_NAME).write_text(json.dumps(marker, indent=2) + "\n")
    (state / wi.MARKER_NAME).chmod(0o600)
    return state


# -- the bundle's realm -------------------------------------------------------
class DurableRealmTests(unittest.TestCase):
    def check(self, record=None, script=None, bound=None):
        return durable.require_durable_bundle_realm(
            {"realm": realm_record() if record is None else record},
            installer_script() if script is None else script,
            binding() if bound is None else bound)

    def test_a_durable_bundle_for_the_bound_directory_is_accepted(self):
        realm = self.check()
        self.assertTrue(realm.durable)
        self.assertEqual(realm.controller_fqdn, BOOTSTRAP)

    def test_a_synthetic_bundle_is_refused(self):
        with self.assertRaisesRegex(DurableBindingError, "permanent realm"):
            self.check(record=synthetic_record(), script=installer_script(
                controller=synthetic_installer_realm().controller_fqdn))

    def test_a_bundle_for_another_directory_is_refused_without_values(self):
        cases = (
            binding(dns_domain="other.example.test",
                    kerberos_realm="OTHER.EXAMPLE.TEST"),
            binding(netbios_name="OTHER"),
            binding(controller_fqdn=f"dc9.{DOMAIN}"),
        )
        for bound in cases:
            with self.subTest(bound=bound):
                with self.assertRaises(DurableBindingError) as caught:
                    self.check(bound=bound)
                for value in PRIVATE_VALUES + ("other.example.test", "dc9."):
                    self.assertNotIn(value, str(caught.exception))

    def test_the_permanent_dc_pin_is_refused(self):
        permanent = f"dc1.{DOMAIN}"
        with self.assertRaisesRegex(DurableBindingError, "predates SRV-first"):
            self.check(record=realm_record(controller_fqdn=permanent),
                       script=installer_script(controller=permanent))

    def test_the_installer_bytes_are_held_to_the_record(self):
        cases = (
            (installer_script(controller=f"dc1.{DOMAIN}"), "domain controller"),
            # Rendered before TASK-42: the controller alone, no SRV first.
            (installer_script(srv_first=False), "predates SRV-first"),
            (installer_script(deferred=False), "defer the install-time join"),
            (installer_script(fingerprint="fedcba9876543210"), "roster"),
        )
        for script, reason in cases:
            with self.subTest(reason=reason):
                with self.assertRaisesRegex(
                        durable.DurableInstallError, reason) as caught:
                    self.check(script=script)
                for value in PRIVATE_VALUES:
                    self.assertNotIn(value, str(caught.exception))

    def test_an_unrecorded_or_malformed_realm_is_refused(self):
        with self.assertRaisesRegex(durable.DurableInstallError, "no realm"):
            durable.require_durable_bundle_realm(
                {}, installer_script(), binding())
        malformed = realm_record()
        del malformed["durable"]
        with self.assertRaisesRegex(durable.DurableInstallError, "shape"):
            self.check(record=malformed)
        with self.assertRaisesRegex(
                durable.DurableInstallError, "invalid") as caught:
            self.check(record=realm_record(kerberos_realm="Lower.Case"))
        self.assertNotIn("Lower.Case", str(caught.exception))

    def test_the_guards_match_a_real_durable_render(self):
        # The three installer lines are found in the bytes arch_second really
        # renders for a durable realm, and none of them in a synthetic render.
        with tempfile.TemporaryDirectory() as temporary, mock.patch.object(
                arch_second, "identity_overlay_path",
                return_value=Path(temporary) / "no-principals.json"):
            inputs = dict(
                disk_path="/dev/vda", disk_serial=DISK_SERIAL,
                hostname=HOSTNAME, expected_sizes_mib=[260, 16, 1000, 2000, 500])
            script = arch_second.render_installer(
                **inputs, realm=durable_realm())
            synthetic = arch_second.render_installer(**inputs)
            fingerprint = arch_second.identity_roster_fingerprint()
        bound = binding(roster_fingerprint=fingerprint)
        realm = durable.require_durable_bundle_realm(
            {"realm": realm_record()}, script, bound)
        self.assertTrue(realm.durable)
        self.assertNotIn(JOIN_DEFERRED_MARKER, synthetic)
        with self.assertRaises(durable.DurableInstallError):
            durable.require_durable_bundle_realm(
                {"realm": realm_record()}, synthetic, bound)


# -- the transcript -----------------------------------------------------------
class DurableLifecycleTests(unittest.TestCase):
    def test_a_deferred_install_transcript_passes(self):
        durable.validate_durable_lifecycle(transcript(), DISK_SERIAL)

    def test_it_is_gate_seven_with_the_deferral_for_the_join(self):
        # The same transcript with gate 7's two join markers where the
        # deferral stands passes gate 7's own check unchanged.
        gate7._validate_lifecycle(
            transcript(join=(JOIN_MEDIA_CONSUMED_MARKER, JOIN_VERIFIED_MARKER)),
            DISK_SERIAL)

    def test_the_deferral_is_required(self):
        with self.assertRaisesRegex(
                durable.DurableInstallError, "never printed"):
            durable.validate_durable_lifecycle(transcript(join=()), DISK_SERIAL)

    def test_install_time_join_markers_are_refused(self):
        for join in (
                (JOIN_DEFERRED_MARKER, JOIN_MEDIA_CONSUMED_MARKER),
                (JOIN_DEFERRED_MARKER, JOIN_VERIFIED_MARKER),
                (JOIN_MEDIA_CONSUMED_MARKER, JOIN_VERIFIED_MARKER)):
            with self.subTest(join=join):
                with self.assertRaisesRegex(
                        durable.DurableInstallError, "never joins"):
                    durable.validate_durable_lifecycle(
                        transcript(join=join), DISK_SERIAL)

    def test_the_deferral_must_stand_between_attach_and_complete(self):
        after = transcript(join=(), after_complete=(JOIN_DEFERRED_MARKER,))
        with self.assertRaisesRegex(durable.DurableInstallError, "order"):
            durable.validate_durable_lifecycle(after, DISK_SERIAL)
        before = transcript(join=()).replace(
            gate7.BEGIN_MARKER, f"{JOIN_DEFERRED_MARKER}\n{gate7.BEGIN_MARKER}")
        with self.assertRaisesRegex(durable.DurableInstallError, "order"):
            durable.validate_durable_lifecycle(before, DISK_SERIAL)

    def test_gate_sevens_other_checks_still_apply(self):
        cases = (
            (transcript(pxe=2), "exactly one PXE"),
            (transcript(attach_before_live=True), "before archiso was live"),
            (transcript(fail=True), "reported failure"),
        )
        for serial, reason in cases:
            with self.subTest(reason=reason):
                with self.assertRaisesRegex(durable.DurableInstallError, reason):
                    durable.validate_durable_lifecycle(serial, DISK_SERIAL)


# -- one install, faked below the bundle ---------------------------------------
class FakeInstall(durable.DurableArchInstall):
    """The real ``execute`` over a faked bundle proof and a faked boot."""

    def __init__(self, workstation, bound, *, authorization, serial="",
                 boot_error=None):
        super().__init__(
            workstation, bound, controller_state=Path("/nonexistent/canonical"),
            releases=Path("/nonexistent/releases"),
            seed_iso=Path("/nonexistent/seed.iso"), duration=1800)
        self.authorization = authorization
        self.serial = serial
        self.boot_error = boot_error
        self.boots = []

    def verified_bundle(self, bundle):
        return self.authorization, ["qemu-system-x86_64"]

    def boot_and_install(self, bundle, authorized, command, *,
                         installer_script, evidence, result):
        self.boots.append(bundle)
        if self.boot_error is not None:
            raise self.boot_error
        return self.serial


class ExecuteTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.tmp = Path(temporary.name)
        self.bundle = self.tmp / "run-synthetic"
        self.bundle.mkdir(mode=0o700)
        (self.bundle / durable.INSTALLER_NAME).write_text(installer_script())
        self.workstation = wi.WorkstationInstance(self.tmp / "w1", name="w1")

    def install(self, *, record=None, bound=None, **options) -> FakeInstall:
        authorization = {"authorization": {
            "realm": realm_record() if record is None else record,
            "disk_serial": DISK_SERIAL, "hostname": HOSTNAME,
            "release_version": RELEASE}}
        return FakeInstall(
            self.workstation, binding() if bound is None else bound,
            authorization=authorization, **options)

    def result(self) -> tuple[dict, str]:
        text = (self.bundle / "evidence" / "result.json").read_text()
        return json.loads(text), text

    def test_a_deferred_install_is_observed_with_secret_free_evidence(self):
        install = self.install(serial=transcript())
        outcome = install.execute(self.bundle)
        recorded, text = self.result()
        self.assertEqual(outcome["status"], "observed")
        self.assertEqual(recorded["status"], "observed")
        self.assertEqual(recorded["phase"], "arch-installed-join-deferred")
        self.assertIs(recorded["join_deferred"], True)
        self.assertIsNone(recorded["join_media"])
        self.assertEqual(recorded["bound_instance"], INSTANCE)
        self.assertEqual(recorded["stage"], "arch-install")
        for value in PRIVATE_VALUES:
            self.assertNotIn(value, text)

    def test_a_synthetic_bundle_is_refused_before_anything_boots(self):
        install = self.install(record=synthetic_record(), serial=transcript())
        with self.assertRaises(DurableBindingError):
            install.execute(self.bundle)
        self.assertEqual(install.boots, [])
        self.assertFalse((self.bundle / "evidence").exists())

    def test_a_joined_transcript_fails_with_evidence_retained(self):
        install = self.install(serial=transcript(
            join=(JOIN_DEFERRED_MARKER, JOIN_VERIFIED_MARKER)))
        with self.assertRaisesRegex(durable.DurableInstallError, "never joins"):
            install.execute(self.bundle)
        recorded, _ = self.result()
        self.assertEqual(recorded["status"], "fail")
        self.assertEqual(recorded["error_type"], "DurableInstallError")
        self.assertIs(recorded["join_deferred"], True)

    def test_a_boot_failure_is_recorded(self):
        install = self.install(boot_error=RuntimeError("synthetic boot fault"))
        with self.assertRaisesRegex(RuntimeError, "synthetic boot fault"):
            install.execute(self.bundle)
        recorded, _ = self.result()
        self.assertEqual(recorded["status"], "fail")
        self.assertIn("synthetic boot fault", recorded["error"])

    def test_existing_evidence_is_refused(self):
        (self.bundle / "evidence").mkdir()
        with self.assertRaisesRegex(durable.DurableInstallError, "evidence"):
            self.install(serial=transcript()).execute(self.bundle)


# -- the live path, every process seam faked -------------------------------------
class FakeProcess:
    def __init__(self, pid: int):
        self.pid = pid
        self.stdin = io.BytesIO()
        self.stdout = io.BytesIO()

    def poll(self):
        return None


class LiveSeamTests(unittest.TestCase):
    """``boot_and_install`` for real, with no process, socket or QMP behind it."""

    JOIN_SEAMS = (
        "OneUseDomainJoinMaterial", "ControllerJoinSerial", "run_join_install",
        "build_arch_join_iso", "ArchJoinMedia", "prepare_controller_domain",
        "install_controller_seed", "converge_controller",
        "establish_publication_console")

    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.tmp = Path(temporary.name)
        self.bundle = self.tmp / "run-synthetic"
        self.bundle.mkdir(mode=0o700)
        (self.bundle / durable.VERIFY_NAME).write_text("# verify\n")
        self.evidence = self.bundle / "evidence"
        self.evidence.mkdir(mode=0o700)
        self.qmp_root = self.tmp / "qmp"
        self.command = [
            "qemu-system-x86_64", "-qmp",
            f"unix:{self.qmp_root / 'arch.qmp'},server=on,wait=off",
            "-netdev", "socket,id=factory,connect=127.0.0.1:31415"]
        self.launched: list[list[str]] = []
        self.drives: list[dict] = []
        self.canonical = mock.Mock()

    def launch(self, argv, **_options):
        self.launched.append(list(argv))
        return FakeProcess(4000 + len(self.launched))

    def drive(self, process, capture, **options):
        self.drives.append(options)
        options["attach"]()
        return transcript()

    def boot_disk(self, disk, firmware, *, run_root):
        self.boot_disk_args = (disk, firmware, run_root)
        overlay = mock.Mock(disk=self.tmp / "ctl.qcow2", vars=self.tmp / "ctl.fd")
        overlay.overlay.verify_canonical = self.canonical
        return contextlib.nullcontext(overlay)

    def publication_iso(self, publication, output):
        output.write_bytes(b"synthetic publication iso")

    def test_no_join_media_no_domain_plain_pxe(self):
        boom = mock.Mock(side_effect=AssertionError("join seam reached"))
        for name in self.JOIN_SEAMS:
            self.assertFalse(hasattr(durable, name), name)
        listener = mock.Mock(**{"fileno.return_value": 99})
        seams = dict(
            _listen=mock.Mock(return_value=listener),
            DisposableBootDisk=self.boot_disk,
            stage_publication=mock.Mock(return_value={
                "version": RELEASE, "selected_manifest_sha256": "ab" * 32}),
            _build_publication_iso=self.publication_iso,
            qemu_commands=mock.Mock(return_value={
                "controller": ["qemu-system-x86_64", "-name", "controller"],
                "workstation": ["unused"]}),
            _launch=self.launch,
            wait_for_switch_port=mock.Mock(),
            audit_live_process=mock.Mock(),
            activate_publication=mock.Mock(),
            _connect_qmp=mock.Mock(),
            hot_attach_disk=mock.Mock(),
            drive_installer=self.drive,
            terminate_children=mock.Mock(return_value=[]),
            retain_redacted_logs=mock.Mock(return_value={}),
        )
        install = durable.DurableArchInstall(
            wi.WorkstationInstance(self.tmp / "w1", name="w1"), binding(),
            controller_state=self.tmp / "canonical",
            releases=self.tmp / "releases", seed_iso=self.tmp / "seed.iso",
            duration=1800)
        result: dict = {}
        authorized = {
            "disk_serial": DISK_SERIAL, "release_version": RELEASE,
            "release_manifest_sha256": "ab" * 32}
        with mock.patch.multiple(durable, **seams), mock.patch.multiple(
                gate7, **{name: boom for name in self.JOIN_SEAMS}):
            serial = install.boot_and_install(
                self.bundle, authorized, self.command,
                installer_script=installer_script(), evidence=self.evidence,
                result=result)
        boom.assert_not_called()
        self.assertIn(JOIN_DEFERRED_MARKER, serial)
        # One drive, nothing to consume, the disk attached through gate 7.
        self.assertEqual(len(self.drives), 1)
        self.assertIsNone(self.drives[0]["consume_media"])
        seams["hot_attach_disk"].assert_called_once()
        self.assertEqual(
            seams["hot_attach_disk"].call_args.args[1], DISK_SERIAL)
        # switch, gateway, controller, workstation -- in that order.
        switch, gateway, controller, workstation = self.launched
        self.assertTrue(any("switch" in part for part in switch))
        self.assertNotIn("--pxe-identity-mode", gateway)
        self.assertNotIn("--identity-mode", gateway)
        self.assertEqual(controller, ["qemu-system-x86_64", "-name", "controller"])
        self.assertNotIn("-qmp", controller)
        self.assertEqual(workstation, self.command)
        seams["activate_publication"].assert_called_once()
        self.canonical.assert_called_once_with()
        self.assertEqual(
            self.boot_disk_args[:2],
            (self.tmp / "canonical" / "bootstrap-dc.qcow2",
             self.tmp / "canonical" / "OVMF_VARS.fd"))
        # Cleanup: the runtime publication and the QMP root are gone.
        self.assertFalse((self.evidence / "publication.iso").exists())
        self.assertTrue(result["runtime_publication_destroyed"])
        self.assertFalse(self.qmp_root.exists())
        self.assertNotIn("cleanup_failures", result)
        listener.close.assert_called()

    def test_a_release_mismatch_stops_before_any_process(self):
        seams = dict(
            _listen=mock.Mock(return_value=mock.Mock(
                **{"fileno.return_value": 99})),
            DisposableBootDisk=self.boot_disk,
            stage_publication=mock.Mock(return_value={
                "version": "1999.01.01", "selected_manifest_sha256": "ab" * 32}),
            _launch=self.launch,
            terminate_children=mock.Mock(return_value=[]),
            retain_redacted_logs=mock.Mock(return_value={}),
        )
        install = durable.DurableArchInstall(
            wi.WorkstationInstance(self.tmp / "w1", name="w1"), binding(),
            controller_state=self.tmp / "canonical",
            releases=self.tmp / "releases", seed_iso=self.tmp / "seed.iso",
            duration=1800)
        with mock.patch.multiple(durable, **seams):
            with self.assertRaisesRegex(
                    durable.DurableInstallError, "authorized release"):
                install.boot_and_install(
                    self.bundle, {
                        "disk_serial": DISK_SERIAL, "release_version": RELEASE,
                        "release_manifest_sha256": "ab" * 32},
                    self.command, installer_script=installer_script(),
                    evidence=self.evidence, result={})
        self.assertEqual(self.launched, [])
        self.assertFalse(self.qmp_root.exists())


# -- the runner: the kept workstation, its lock and the fold --------------------
class RunFixture:
    """A kept workstation in a temporary tree, with prepare and install faked."""

    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.tmp = Path(temporary.name)
        self.root = self.tmp / "workstations"
        self.run_root = self.tmp / "runs"
        self.proc = self.tmp / "proc"
        self.proc.mkdir()
        self.state = write_workstation(self.root)
        self.prepared: list = []
        self.installs: list = []
        self.install_error: BaseException | None = None
        self.backing_sha: str | None = None
        self.bound = binding()
        self.realm = durable_realm()
        for name, value in (
                ("open_workstation", self.open_workstation),
                ("durable_binding", lambda *a, **k: self.bound),
                ("resolve_bundle_realm", lambda args, bound: self.realm),
                ("prepare_bundle", self.prepare),
                ("DurableArchInstall", self.install_factory),
                ("ARCH_GROWTH_BYTES", 0)):
            patcher = mock.patch.object(durable, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)

    def open_workstation(self, root, name):
        return wi.WorkstationInstance(
            wi.workstation_state(root, name), name=name, proc_root=self.proc)

    def prepare(self, prepare_args, realm):
        self.prepared.append((prepare_args, realm))
        bundle = self.run_root / "run-synthetic"
        bundle.mkdir(parents=True, mode=0o700)
        self.make_overlay(Path(prepare_args.windows_disk), bundle / "arch.qcow2")
        (bundle / "OVMF_VARS.fd").write_bytes(INSTALLED_VARS)
        disk = Path(prepare_args.windows_disk)
        (bundle / "authorization.json").write_text(json.dumps({
            "authorization": {"backing_windows_disk": {
                "path": str(disk.resolve()),
                "sha256": self.backing_sha or _digest(disk)}}}))
        return bundle

    def make_overlay(self, disk: Path, overlay: Path) -> None:
        overlay.write_bytes(b"synthetic overlay\n")

    def install_factory(self, workstation, bound, **options):
        test = self

        class Install:
            def execute(self, bundle):
                # The lock is held for the whole install, by this run.
                observer = wi.WorkstationInstance(
                    workstation.state, name=workstation.state.name)
                test.installs.append({
                    "bundle": bundle, "locked": observer.locked(),
                    "options": options, "binding": bound})
                evidence = Path(bundle) / "evidence"
                evidence.mkdir(mode=0o700)
                status = "fail" if test.install_error else "observed"
                (evidence / "result.json").write_text(json.dumps({
                    "status": status, "join_deferred": True}))
                if test.install_error is not None:
                    raise test.install_error
                return {"status": status}

        return Install()

    def args(self, *extra: str, duration: str = "1800"):
        return durable.parser().parse_args([
            "--workstation", "w1", "--root", str(self.root),
            "--persistent-dc", INSTANCE,
            "--persistent-root", str(self.tmp / "persistent"),
            "--hostname", HOSTNAME,
            "--controller-state", str(self.tmp / "canonical"),
            "--releases", str(self.tmp / "releases"),
            "--seed-iso", str(self.tmp / "seed.iso"),
            "--run-root", str(self.run_root),
            "--duration", duration, *extra])

    def run_quietly(self, *extra: str, **options) -> str:
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            durable.run(self.args(*extra, **options))
        return output.getvalue()

    def marker(self) -> dict:
        return json.loads((self.state / wi.MARKER_NAME).read_text())


class RunTests(RunFixture, unittest.TestCase):
    def test_the_dry_run_changes_nothing_and_names_only_the_instance(self):
        before = snapshot(self.state)
        with mock.patch.object(wi.WorkstationInstance, "fold") as fold:
            plan = self.run_quietly()
        self.assertEqual(snapshot(self.state), before)
        self.assertFalse(self.run_root.exists())
        self.assertEqual(self.prepared, [])
        self.assertEqual(self.installs, [])
        fold.assert_not_called()
        self.assertFalse(self.open_workstation(self.root, "w1").locked())
        self.assertIn("dry run", plan)
        self.assertIn(INSTANCE, plan)
        self.assertIn("w1", plan)
        self.assertIn("DISPOSABLE", plan)
        self.assertIn("Domain join: none", plan)
        for value in PRIVATE_VALUES:
            self.assertNotIn(value, plan)

    def test_apply_folds_once_as_arch_install_with_the_authored_vars(self):
        entry = {"stage": "arch-install", "utc": "2026-09-30T01:00:00+00:00",
                 "disk_sha256": "cd" * 32, "vars_sha256": "ef" * 32,
                 "source": "synthetic"}
        with mock.patch.object(
                wi.WorkstationInstance, "fold", autospec=True,
                return_value=entry) as fold:
            output = self.run_quietly("--apply")
        bundle = self.run_root / "run-synthetic"
        fold.assert_called_once()
        call = fold.call_args
        self.assertEqual(call.args[1:], (bundle / "arch.qcow2", "arch-install"))
        self.assertEqual(call.kwargs["firmware_vars"], bundle / "OVMF_VARS.fd")
        self.assertEqual(call.kwargs["source"], str(bundle))
        self.assertEqual(len(self.installs), 1)
        self.assertTrue(self.installs[0]["locked"])
        self.assertFalse(self.open_workstation(self.root, "w1").locked())
        self.assertFalse((bundle / "arch.qcow2").exists())
        recorded = json.loads((bundle / "evidence" / "result.json").read_text())
        self.assertIs(recorded["folded"], True)
        self.assertEqual(recorded["fold"]["disk_sha256"], "cd" * 32)
        self.assertIs(recorded["overlay_discarded"], True)
        self.assertIn("Folded stage arch-install", output)
        # TASK-42: the kept disk records that its Arch side asks SRV first,
        # with the controller it was installed against as the fallback.
        discovery = self.marker()["arch_dc_discovery"]
        self.assertEqual(
            (discovery["mode"], discovery["fallback_fqdn"]),
            ("srv-first", self.realm.controller_fqdn))

    def test_prepare_is_asked_for_a_durable_bundle_over_the_kept_disk(self):
        with mock.patch.object(wi.WorkstationInstance, "fold",
                               return_value={"disk_sha256": "cd" * 32}):
            self.run_quietly("--apply")
        (prepare_args, realm), = self.prepared
        self.assertIs(prepare_args.durable_identity, True)
        self.assertEqual(Path(prepare_args.windows_disk),
                         self.state / wi.DISK_NAME)
        self.assertEqual(prepare_args.controller_fqdn, BOOTSTRAP)
        self.assertEqual(prepare_args.hostname, HOSTNAME)
        self.assertEqual(Path(prepare_args.run_root), self.run_root)
        self.assertIs(realm, self.realm)

    def test_a_failed_install_leaves_the_workstation_unchanged(self):
        self.install_error = RuntimeError("synthetic install fault")
        before = snapshot(self.state)
        with mock.patch.object(wi.WorkstationInstance, "fold") as fold:
            with self.assertRaisesRegex(RuntimeError, "synthetic install fault"):
                self.run_quietly("--apply")
        fold.assert_not_called()
        self.assertEqual(snapshot(self.state), before)
        self.assertEqual([e["stage"] for e in self.marker()["ledger"]],
                         ["adopt"])
        bundle = self.run_root / "run-synthetic"
        self.assertFalse((bundle / "arch.qcow2").exists())
        recorded = json.loads((bundle / "evidence" / "result.json").read_text())
        self.assertIs(recorded["folded"], False)
        self.assertIsNone(recorded["fold"])
        self.assertFalse(self.open_workstation(self.root, "w1").locked())

    def test_a_disk_that_left_the_ledger_is_refused_before_the_install(self):
        self.backing_sha = "00" * 32
        with mock.patch.object(wi.WorkstationInstance, "fold") as fold:
            with self.assertRaisesRegex(
                    durable.DurableInstallError, "ledger head"):
                self.run_quietly("--apply")
        fold.assert_not_called()
        self.assertEqual(self.installs, [])
        self.assertFalse(
            (self.run_root / "run-synthetic" / "arch.qcow2").exists())

    def test_firmware_vars_that_left_the_ledger_are_refused(self):
        (self.state / wi.VARS_NAME).write_bytes(b"edited out of band\n")
        with self.assertRaisesRegex(durable.DurableInstallError, "firmware"):
            self.run_quietly("--apply")
        self.assertEqual(self.installs, [])

    def test_a_workstation_bound_elsewhere_is_refused(self):
        self.bound = binding(instance="other-dc")
        with self.assertRaisesRegex(durable.DurableInstallError, "bound to"):
            self.run_quietly()

    def test_a_workstation_of_another_directory_is_refused_without_values(self):
        for bound in (binding(domain_sid="S-1-5-21-44-55-66"),
                      binding(kerberos_realm="OTHER.EXAMPLE.TEST")):
            with self.subTest(bound=bound):
                self.bound = bound
                with self.assertRaises(durable.DurableInstallError) as caught:
                    self.run_quietly()
                for value in PRIVATE_VALUES + ("S-1-5-21-44-55-66",
                                               "OTHER.EXAMPLE.TEST"):
                    self.assertNotIn(value, str(caught.exception))

    def test_a_recorded_sid_the_instance_later_completed_is_accepted(self):
        shutil.rmtree(self.state)
        self.state = write_workstation(self.root, recorded_sid="S-1-5-21-11-22-3")
        self.assertIn("dry run", self.run_quietly())

    def test_a_synthetic_realm_is_refused_in_the_dry_run(self):
        self.realm = synthetic_installer_realm()
        with self.assertRaisesRegex(DurableBindingError, "permanent realm"):
            self.run_quietly()

    def test_only_the_next_stage_runs(self):
        shutil.rmtree(self.state)
        self.state = write_workstation(self.root, ledger_extra=[{
            "stage": "arch-install", "utc": "2026-09-30T01:00:00+00:00",
            "disk_sha256": "cd" * 32, "vars_sha256": None,
            "source": "synthetic"}])
        with self.assertRaisesRegex(durable.DurableInstallError, "arch-join"):
            self.run_quietly()

    def test_an_interrupted_fold_is_refused(self):
        shutil.rmtree(self.state)
        self.state = write_workstation(self.root, pending={
            "stage": "arch-install", "utc": "2026-09-30T01:00:00+00:00",
            "disk_sha256": "cd" * 32, "vars_sha256": None,
            "source": "synthetic"})
        with self.assertRaisesRegex(durable.DurableInstallError, "interrupted"):
            self.run_quietly("--apply")
        self.assertEqual(self.prepared, [])

    def test_a_short_duration_is_a_plan_note_and_an_apply_refusal(self):
        self.assertIn("minimum", self.run_quietly(duration="120"))
        with self.assertRaisesRegex(durable.DurableInstallError, "600"):
            self.run_quietly("--apply", duration="120")
        self.assertEqual(self.prepared, [])

    def test_too_little_free_space_is_refused_before_prepare(self):
        with mock.patch.object(durable, "ARCH_GROWTH_BYTES", 1 << 60):
            self.assertIn("INSUFFICIENT", self.run_quietly())
            with self.assertRaisesRegex(
                    durable.DurableInstallError, "free space"):
                self.run_quietly("--apply")
        self.assertEqual(self.prepared, [])

    def test_the_hostname_must_be_a_netbios_name(self):
        for hostname, code in (("a-far-too-long-hostname", 2), ("Upper", 2)):
            with self.subTest(hostname=hostname):
                error = io.StringIO()
                with contextlib.redirect_stderr(error):
                    status = durable.main([
                        "--workstation", "w1", "--root", str(self.root),
                        "--persistent-dc", INSTANCE, "--hostname", hostname])
                self.assertEqual(status, code)
                self.assertIn("error:", error.getvalue())
        self.assertEqual(self.prepared, [])

    def test_the_names_are_required(self):
        for missing in ("--workstation", "--persistent-dc", "--hostname"):
            argv = ["--workstation", "w1", "--persistent-dc", INSTANCE,
                    "--hostname", HOSTNAME]
            index = argv.index(missing)
            del argv[index:index + 2]
            with self.subTest(missing=missing), contextlib.redirect_stderr(
                    io.StringIO()), self.assertRaises(SystemExit):
                durable.parser().parse_args(argv)


@unittest.skipUnless(shutil.which("qemu-img"), "qemu-img is required")
class RealFoldTests(RunFixture, unittest.TestCase):
    """One apply against a real qcow2 kept disk and the real ``fold``."""

    def setUp(self):
        super().setUp()
        disk = self.state / wi.DISK_NAME
        disk.unlink()
        subprocess.run(
            ["qemu-img", "create", "-q", "-f", "qcow2", str(disk), "64M"],
            check=True, capture_output=True)
        disk.chmod(0o600)
        marker = self.marker()
        marker["ledger"][0]["disk_sha256"] = _digest(disk)
        (self.state / wi.MARKER_NAME).write_text(json.dumps(marker, indent=2))

    def make_overlay(self, disk: Path, overlay: Path) -> None:
        subprocess.run(
            ["qemu-img", "create", "-q", "-f", "qcow2", "-b",
             str(disk.resolve()), "-F", "qcow2", str(overlay)],
            check=True, capture_output=True)
        overlay.chmod(0o600)

    def test_the_overlay_and_authored_vars_become_the_kept_disk(self):
        self.run_quietly("--apply")
        marker = self.marker()
        self.assertEqual([entry["stage"] for entry in marker["ledger"]],
                         ["adopt", "arch-install"])
        self.assertIsNone(marker.get("pending_fold"))
        head = marker["ledger"][-1]
        disk = self.state / wi.DISK_NAME
        self.assertEqual(head["disk_sha256"], _digest(disk))
        # Kept less the cache; the bundle's own copy is retained as booted.
        self.assertEqual((self.state / wi.VARS_NAME).read_bytes(),
                         ovmf_vars.without_hddp(INSTALLED_VARS)[0])
        self.assertEqual(
            (self.run_root / "run-synthetic" / "OVMF_VARS.fd").read_bytes(),
            INSTALLED_VARS)
        self.assertEqual(head["vars_sha256"],
                         _digest(self.state / wi.VARS_NAME))
        info = json.loads(subprocess.run(
            ["qemu-img", "info", "--output=json", str(disk)],
            check=True, capture_output=True, text=True).stdout)
        self.assertNotIn("backing-filename", info)
        self.assertFalse(
            (self.run_root / "run-synthetic" / "arch.qcow2").exists())


class RecordedDcRealmTests(unittest.TestCase):
    def test_the_bound_instances_recorded_dc_is_vouched_for(self):
        """TASK-42: after a restore the bundle may name the restored DC."""
        restored = binding(controller_fqdn=f"dr-2609302105.{DOMAIN}",
                           dc_hostname="dr-2609302105")
        prepare_args = SimpleNamespace(controller_fqdn=restored.controller_fqdn)
        expected = durable_realm(controller_fqdn=restored.controller_fqdn)
        with mock.patch.object(
                durable.arch_install_prepare, "resolve_realm",
                return_value=expected) as resolve:
            realm = durable.resolve_bundle_realm(prepare_args, restored)
        self.assertIs(realm, expected)
        resolve.assert_called_once_with(
            prepare_args, recorded_dc_fqdn=f"dr-2609302105.{DOMAIN}")


if __name__ == "__main__":
    unittest.main()
