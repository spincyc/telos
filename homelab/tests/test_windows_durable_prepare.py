"""The durable Windows join attempt (TASK-28 step 8), prepared with no guest.

Nothing here boots QEMU or reads ``build/``, ``homelab/var/`` or
``homelab/instance/``: the kept workstation and the canonical state live in a
temporary directory, the roster overlay is pinned absent, and the control
disc's ``xorriso`` is faked.  Every realm, SID and name is synthetic.
"""

import hashlib
import json
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from homelab.tests.identity_overlay_pin import pinned_identity_overlay
from homelab.tests.ovmf_store_fixture import store
from homelab.vm import controller_principals
from homelab.vm import ovmf_vars
from homelab.vm import windows_durable_prepare as prepare
from homelab.vm import windows_identity_adapter
from homelab.vm import workstation_instance as wi
from homelab.vm.durable_workstation import DurableBinding
from homelab.vm.windows_control_iso import (
    ASSET_ROOT, MANIFEST, SCRIPT, audit_payload)
from homelab.vm.windows_identity_reference import load_identity_reference
from homelab.vm.windows_identity_run import NativeProcessBoundary


def setUpModule():
    # HANDOFF section 5: the control disc renders the roster, which resolves
    # from the default overlay path; pin it to a private absent one.
    unittest.enterModuleContext(pinned_identity_overlay())


DOMAIN = "durable.example.test"
REALM = DOMAIN.upper()
BOOTSTRAP = f"bootstrap-dc.{DOMAIN}"
SID = "S-1-5-21-11-22-33"
INSTANCE = "synthetic-dc"
PRIVATE_VALUES = (DOMAIN, REALM, SID)
#: ``W``'s variables as an earlier fold kept them, before folds dropped the
#: boot-path cache: an Arch boot in another disk topology left an ``HDDP``.
KEPT_VARS = store("Linux Boot Manager", hddp=True)


def binding(**overrides) -> DurableBinding:
    values = dict(
        instance=INSTANCE, state=Path("/nonexistent/persistent") / INSTANCE,
        dns_domain=DOMAIN, kerberos_realm=REALM, netbios_name="DURABLE",
        controller_fqdn=BOOTSTRAP, permanent_dc_fqdn=f"dc1.{DOMAIN}",
        domain_sid=SID, roster_fingerprint="0123456789abcdef",
        identity_source="a test")
    values.update(overrides)
    return DurableBinding(**values)


def _digest(path: Path) -> str:
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def snapshot(directory: Path) -> dict:
    return {path.name: _digest(path) for path in sorted(directory.iterdir())
            if path.is_file() and path.name != wi.LOCK_NAME}


def write_kept_workstation(root: Path, name: str = "w1", *,
                           stages=("adopt", "arch-install", "arch-join"),
                           real_disk: bool = True) -> Path:
    """A kept workstation whose next stage is windows-join."""
    state = root / name
    state.mkdir(parents=True, mode=0o700)
    disk = state / wi.DISK_NAME
    if real_disk:
        subprocess.run(["qemu-img", "create", "-q", "-f", "qcow2", str(disk),
                        "64M"], check=True, capture_output=True)
    else:
        disk.write_bytes(b"synthetic kept disk\n")
    (state / wi.VARS_NAME).write_bytes(KEPT_VARS)
    (state / wi.PUBLICATION_NAME).write_bytes(b"synthetic publication\n")
    for item in (disk, state / wi.VARS_NAME, state / wi.PUBLICATION_NAME):
        item.chmod(0o600)
    ledger = [{
        "stage": stage, "utc": "2026-09-30T00:00:00+00:00",
        "disk_sha256": _digest(disk),
        "vars_sha256": _digest(state / wi.VARS_NAME),
        "source": "/runs/synthetic"} for stage in stages]
    marker = {
        "schema": wi.MARKER_SCHEMA, "kind": wi.MARKER_KIND,
        "workstation": name, "created_utc": "2026-09-30T00:00:00+00:00",
        "binding": {"persistent_instance": INSTANCE, "realm": REALM,
                    "domain_sid": SID},
        "disk": {"format": "qcow2", "name": wi.DISK_NAME, "standalone": True},
        "publication": {"name": wi.PUBLICATION_NAME,
                        "received_utc": "2026-09-30T00:00:00+00:00",
                        "from_bundle": "/runs/gate5", "note": "synthetic"},
        "machine_accounts": [], "ledger": ledger,
    }
    (state / wi.MARKER_NAME).write_text(json.dumps(marker, indent=2) + "\n")
    (state / wi.MARKER_NAME).chmod(0o600)
    return state


def canonical_state(root: Path) -> Path:
    """The disposable canonical gate 6's ``_validate`` requires to exist."""
    state = root / "canonical"
    state.mkdir(mode=0o700)
    for name in ("bootstrap-dc.qcow2", "OVMF_VARS.fd"):
        (state / name).write_bytes(b"synthetic canonical\n")
        (state / name).chmod(0o600)
    return state


def fake_control_iso(output, *, dns_domain, controller_fqdn):
    output.write_bytes(b"synthetic control iso\n")
    output.chmod(0o444)
    return output


class RenderProbeTests(unittest.TestCase):
    def source(self) -> str:
        return (ASSET_ROOT / SCRIPT.name).read_text(encoding="ascii")

    def test_only_the_two_realm_lines_change(self):
        source = self.source()
        rendered = prepare.render_durable_probe(
            source, dns_domain=DOMAIN, controller_fqdn=BOOTSTRAP)
        before, after = source.splitlines(), rendered.splitlines()
        self.assertEqual(len(before), len(after))
        changed = [(old, new) for old, new in zip(before, after) if old != new]
        self.assertEqual(changed, [
            (prepare.CONTROLLER_DOMAIN_LINE,
             f"$ControllerDomain = '{DOMAIN}'"),
            (prepare.CONTROLLER_FQDN_LINE,
             f"$ControllerFqdn = '{BOOTSTRAP}'")])

    def test_names_that_are_not_bound_dns_names_are_refused_quietly(self):
        for domain, fqdn in (
                ("Durable.Example.Test", BOOTSTRAP),
                (DOMAIN, "bootstrap-dc"),
                (DOMAIN, "bootstrap-dc.other.example.test"),
                ("durable'; Remove-Item x; '", BOOTSTRAP)):
            with self.subTest(domain=domain, fqdn=fqdn):
                with self.assertRaises(
                        prepare.DurableWindowsPrepareError) as caught:
                    prepare.render_durable_probe(
                        self.source(), dns_domain=domain,
                        controller_fqdn=fqdn)
                for value in (domain, fqdn):
                    self.assertNotIn(value, str(caught.exception))

    def test_a_probe_that_moved_its_realm_lines_is_refused(self):
        source = self.source()
        for broken in (
                source.replace(prepare.CONTROLLER_DOMAIN_LINE, ""),
                source + prepare.CONTROLLER_FQDN_LINE + "\n"):
            with self.subTest():
                with self.assertRaisesRegex(
                        prepare.DurableWindowsPrepareError, "exactly once"):
                    prepare.render_durable_probe(
                        broken, dns_domain=DOMAIN, controller_fqdn=BOOTSTRAP)

    def test_the_staged_payload_passes_gate_sixs_audit(self):
        with tempfile.TemporaryDirectory() as name:
            staged = prepare.stage_durable_control_assets(
                Path(name) / "payload", dns_domain=DOMAIN,
                controller_fqdn=BOOTSTRAP)
            audit_payload(staged)
            self.assertEqual((staged / MANIFEST.name).read_bytes(),
                             MANIFEST.read_bytes())
            self.assertIn(f"'{DOMAIN}'", (staged / SCRIPT.name).read_text())

    def test_the_control_disc_is_gate_sixs_build_over_the_rendered_payload(self):
        captured = {}

        def runner(argv, check):
            stage = Path(argv[-1])
            captured["probe"] = (stage / SCRIPT.name).read_text()
            captured["receipt"] = json.loads(
                (stage / "receipt.json").read_text())
            Path(argv[argv.index("-o") + 1]).write_bytes(b"synthetic iso")

        with tempfile.TemporaryDirectory() as name:
            output = Path(name) / "control.iso"
            prepare.build_durable_control_iso(
                output, dns_domain=DOMAIN, controller_fqdn=BOOTSTRAP,
                runner=runner)
            self.assertEqual(output.stat().st_mode & 0o777, 0o444)
            self.assertEqual(sorted(p.name for p in Path(name).iterdir()),
                             ["control.iso"])
        self.assertIn(f"$ControllerDomain = '{DOMAIN}'", captured["probe"])
        self.assertNotIn("ad.factory.test", captured["probe"])
        # The roster placeholders are rendered too, from the pinned roster.
        self.assertNotIn("{{", captured["probe"])
        self.assertIs(captured["receipt"]["contains_secrets"], False)


class RelabelTests(unittest.TestCase):
    def test_the_relabelled_reference_is_the_tracked_capture(self):
        tracked = load_identity_reference(
            prepare.REFERENCE_ROOT / f"{prepare.OPERATOR_SIGN_IN}.json")
        with tempfile.TemporaryDirectory() as name:
            manifest = prepare.relabel_operator_sign_in(
                Path(name) / "refs", kerberos_realm=REALM)
            relabelled = load_identity_reference(
                manifest, expected_guest=tracked.guest)
            self.assertEqual(manifest.stat().st_mode & 0o777, 0o600)
        self.assertEqual(relabelled.image, tracked.image)
        self.assertEqual(relabelled.crop, tracked.crop)
        self.assertEqual(relabelled.source_frame_sha256,
                         tracked.source_frame_sha256)
        self.assertTrue(relabelled.state.endswith(f"@{REALM}"))
        self.assertEqual(relabelled.state.rpartition("@")[0],
                         tracked.state.rpartition("@")[0])

    def test_gate_sixs_adapter_admits_it_and_refuses_the_tracked_one(self):
        daily = controller_principals.daily_administrator()
        admitted = windows_identity_adapter._domain_sign_in_states(
            f"{daily}@{REALM}")
        tracked = load_identity_reference(
            prepare.REFERENCE_ROOT / f"{prepare.OPERATOR_SIGN_IN}.json")
        # Why the relabel exists: the tracked state names the synthetic realm.
        self.assertNotIn(tracked.state, admitted)
        with tempfile.TemporaryDirectory() as name:
            manifest = prepare.relabel_operator_sign_in(
                Path(name) / "refs", kerberos_realm=REALM)
            self.assertIn(load_identity_reference(manifest).state, admitted)

    def test_a_realm_that_is_not_upper_case_dns_is_refused(self):
        for realm in ("durable.example.test", "NOREALM", "BAD REALM.TEST"):
            with self.subTest(realm=realm), tempfile.TemporaryDirectory() as n:
                with self.assertRaises(
                        prepare.DurableWindowsPrepareError) as caught:
                    prepare.relabel_operator_sign_in(
                        Path(n) / "refs", kerberos_realm=realm)
                self.assertNotIn(realm, str(caught.exception))


@unittest.skipUnless(shutil.which("qemu-img"), "qemu-img is required")
class PrepareTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.tmp = Path(temporary.name)
        self.state = write_kept_workstation(self.tmp / "workstations")
        self.workstation = wi.WorkstationInstance(self.state, name="w1")
        self.canonical = canonical_state(self.tmp)
        self.runs = self.tmp / "runs"

    def prepared(self, **options) -> Path:
        marker = self.workstation.read_marker()
        return prepare.prepare(
            self.workstation, marker, binding(),
            controller_state=self.canonical, run_root=self.runs,
            control_iso_builder=options.pop(
                "control_iso_builder", fake_control_iso), **options)

    def test_gate_sixs_boundary_validates_the_attempt_unchanged(self):
        before = snapshot(self.state)
        attempt = self.prepared()
        self.assertEqual(snapshot(self.state), before)
        self.assertEqual(attempt.parent, self.runs / "w1")
        self.assertEqual(attempt.stat().st_mode & 0o777, 0o700)
        boundary = NativeProcessBoundary(attempt, self.canonical)
        try:
            boundary._validate()
        finally:
            boundary.release_prestart_ownership()
        info = json.loads(subprocess.run(
            ["qemu-img", "info", "--output=json", str(attempt / "windows.qcow2")],
            check=True, capture_output=True, text=True).stdout)
        self.assertEqual(Path(info["full-backing-filename"]),
                         (self.state / wi.DISK_NAME).resolve())
        # The boot copy lacks only the boot-path cache; W's is untouched.
        self.assertEqual((attempt / "OVMF_VARS.fd").read_bytes(),
                         ovmf_vars.without_hddp(KEPT_VARS)[0])
        self.assertEqual((self.state / wi.VARS_NAME).read_bytes(), KEPT_VARS)

    def test_the_authorization_is_durable_and_carries_no_realm(self):
        attempt = self.prepared()
        text = (attempt / "authorization.json").read_text()
        authorization = json.loads(text)
        durable = authorization["durable"]
        head = self.workstation.read_marker()["ledger"][-1]
        self.assertEqual(durable["stage"], "windows-join")
        self.assertEqual(durable["workstation"], "w1")
        self.assertEqual(durable["bound_instance"], INSTANCE)
        self.assertEqual(durable["ledger_head"]["disk_sha256"],
                         head["disk_sha256"])
        # The copy's source is recorded as W holds it; the copy dropped HDDP.
        self.assertEqual(authorization["firmware_copy"]["source_sha256"],
                         head["vars_sha256"])
        self.assertEqual(authorization["firmware_copy"]["hddp_dropped"], 1)
        self.assertEqual(authorization["post_join_submit_focus_calibration"],
                         {"enabled": False, "tabs": 0})
        self.assertIs(authorization["external_access"], False)
        for value in PRIVATE_VALUES:
            self.assertNotIn(value, text)
        reference = attempt / durable["operator_sign_in_reference"]["path"]
        self.assertEqual(_digest(reference),
                         durable["operator_sign_in_reference"]["sha256"])

    def test_an_interrupted_fold_is_refused_naming_reconcile(self):
        marker = self.workstation.read_marker()
        marker["pending_fold"] = {"stage": "arch-join"}
        with self.assertRaisesRegex(
                prepare.DurableWindowsPrepareError, "reconcile"):
            prepare.prepare(
                self.workstation, marker, binding(),
                controller_state=self.canonical, run_root=self.runs,
                control_iso_builder=fake_control_iso)
        self.assertFalse(self.runs.exists())

    def test_a_disk_that_left_the_ledger_is_refused_and_nothing_remains(self):
        (self.state / wi.DISK_NAME).write_bytes(b"edited out of band")
        with self.assertRaisesRegex(
                prepare.DurableWindowsPrepareError, "ledger head"):
            self.prepared(image_info=lambda path: {"format": "qcow2"})
        self.assertFalse(self.runs.exists())

    def test_missing_firmware_variables_are_refused(self):
        (self.state / wi.VARS_NAME).unlink()
        with self.assertRaisesRegex(
                prepare.DurableWindowsPrepareError, "firmware variables"):
            self.prepared()

    def test_a_dirty_or_backed_disk_is_refused(self):
        for info in ({"format": "qcow2", "dirty-flag": True},
                     {"format": "qcow2", "backing-filename": "/x"},
                     {"format": "raw"}):
            with self.subTest(info=info):
                with self.assertRaisesRegex(
                        prepare.DurableWindowsPrepareError, "standalone"):
                    self.prepared(image_info=lambda path, info=info: info)

    def test_a_failure_mid_prepare_removes_the_attempt(self):
        def failing(output, **_options):
            raise RuntimeError("synthetic control disc fault")

        with self.assertRaisesRegex(RuntimeError, "synthetic"):
            self.prepared(control_iso_builder=failing)
        self.assertEqual(list((self.runs / "w1").iterdir()), [])


if __name__ == "__main__":
    unittest.main()
