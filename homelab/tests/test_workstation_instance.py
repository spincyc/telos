"""Safety tests for a kept (durable) workstation's state directory.

Every disk here is a small qcow2 made with ``qemu-img`` in a temporary
directory; no guest boots, nothing under ``build/``, ``homelab/var`` or
``homelab/instance`` is read, and every binding value is synthetic.
"""

import contextlib
import hashlib
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
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "vm"))

import workstation_instance as wi  # noqa: E402
from homelab.tests.identity_overlay_pin import (  # noqa: E402
    pinned_acceptance_state,
)
from homelab.tests.ovmf_store_fixture import store  # noqa: E402
from homelab.vm import arch_durable_install_run  # noqa: E402
from homelab.vm import arch_durable_join  # noqa: E402
from homelab.vm import ovmf_vars  # noqa: E402


def setUpModule():
    # HANDOFF section 5: no test stats the operator's build/ tree.  Every
    # persistent-instance separation check resolves the reserved acceptance
    # state, which defaults to the real build/homelab/vm/bootstrap-dc, so
    # every test here reserves private spellings of it instead.
    unittest.enterModuleContext(pinned_acceptance_state())


SECRET = b"SYNTHETIC-LOCAL-ADMIN-SECRET-7f3a"
BINDING = wi.Binding("synthetic-dc", "EXAMPLE.TEST", "S-1-5-21-11-22-33")
HOLDER = ["4242 (qemu-system-x86_64)"]
#: The gate-5 bundle's store: Windows booted it through its short-form entry,
#: so it carries the boot-path cache a kept workstation never keeps.
GATE5_VARS = store("Windows Boot Manager", hddp=True)


def _digest(path: Path) -> str:
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def _qemu_img(*argv: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["qemu-img", *argv], check=True, capture_output=True, text=True)


def _write(disk: Path, pattern: int, offset: str) -> None:
    subprocess.run(
        ["qemu-io", "-c", f"write -P {pattern} {offset} 64k", str(disk)],
        check=True, capture_output=True)


def _info(disk: Path) -> dict:
    return json.loads(_qemu_img("info", "--output=json", str(disk)).stdout)


def _identical(left: Path, right: Path) -> bool:
    return subprocess.run(
        ["qemu-img", "compare", "-q", str(left), str(right)],
        capture_output=True).returncode == 0


@unittest.skipUnless(
    shutil.which("qemu-img") and shutil.which("qemu-io"),
    "qemu-img and qemu-io are required")
class WorkstationTestCase(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.tmp = Path(self.temporary.name)
        self.proc = self.tmp / "proc"
        self.proc.mkdir()
        self.root = self.tmp / "workstations"
        self.bundle = self.make_bundle(self.tmp / "run-synthetic")

    def make_bundle(self, bundle: Path, *, backing: bool = True,
                    firmware: bool = True) -> Path:
        bundle.mkdir(mode=0o700)
        disk = bundle / "windows.qcow2"
        if backing:
            base = self.tmp / f"{bundle.name}-base.qcow2"
            _qemu_img("create", "-q", "-f", "qcow2", str(base), "64M")
            _write(base, 0xAB, "0")
            _qemu_img("create", "-q", "-f", "qcow2", "-b", str(base),
                      "-F", "qcow2", str(disk))
        else:
            _qemu_img("create", "-q", "-f", "qcow2", str(disk), "64M")
        _write(disk, 0xCD, "1M")
        disk.chmod(0o600)
        if firmware:
            (bundle / "OVMF_VARS.fd").write_bytes(GATE5_VARS)
            (bundle / "OVMF_VARS.fd").chmod(0o600)
        publication = bundle / "publication.iso"
        publication.write_bytes(b"ISO9660 " + SECRET + b"\n" * 4096)
        publication.chmod(0o600)
        evidence = bundle / "evidence"
        evidence.mkdir(mode=0o700)
        (evidence / "result.json").write_text(json.dumps({
            "schema": 1, "status": "observed",
            "phase": "native-windows-clean-shutdown",
            "private_publication_retained_for_identity": True,
        }))
        return bundle

    def target(self, name: str = "w1") -> wi.WorkstationInstance:
        return wi.WorkstationInstance(
            wi.workstation_state(self.root, name), name=name,
            proc_root=self.proc)

    def adopted(self, name: str = "w1") -> wi.WorkstationInstance:
        target = self.target(name)
        target.adopt(self.bundle, BINDING)
        return target

    def overlay(self, target: wi.WorkstationInstance, label: str,
                pattern: int = 0xEE) -> Path:
        overlay = self.tmp / f"{label}.qcow2"
        _qemu_img("create", "-q", "-f", "qcow2", "-b", str(target.disk),
                  "-F", "qcow2", str(overlay))
        _write(overlay, pattern, "2M")
        return overlay

    def snapshot(self, directory: Path) -> dict:
        """Content and mode of every file; the lock file's presence is not
        state (acquiring the lock creates it)."""
        return {
            path.name: (
                "directory" if path.is_dir() else _digest(path),
                stat.S_IMODE(path.lstat().st_mode))
            for path in sorted(directory.iterdir())
            if path.name != wi.LOCK_NAME}


class AdoptTests(WorkstationTestCase):
    def test_adopt_makes_a_standalone_disk_and_moves_the_publication(self):
        original = (self.bundle / "publication.iso").read_bytes()
        target = self.adopted()

        self.assertNotIn("backing-filename", _info(target.disk))
        self.assertTrue(_identical(self.bundle / "windows.qcow2", target.disk))
        source = self.bundle / "publication.iso"
        self.assertFalse(source.exists() or source.is_symlink())
        self.assertEqual(target.publication.read_bytes(), original)
        self.assertEqual(stat.S_IMODE(target.state.stat().st_mode), 0o700)
        for path in (target.disk, target.vars, target.publication,
                     target.marker):
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600, path)
        # Copied less the boot-path cache, and the bundle's own copy is kept.
        self.assertEqual(target.vars.read_bytes(),
                         ovmf_vars.without_hddp(GATE5_VARS)[0])
        self.assertEqual(ovmf_vars.hddp_states(target.vars.read_bytes()), [])
        self.assertEqual((self.bundle / "OVMF_VARS.fd").read_bytes(),
                         GATE5_VARS)
        marker = target.read_marker()
        self.assertEqual(marker["binding"], BINDING.record())
        self.assertEqual(marker["machine_accounts"], [])
        [entry] = marker["ledger"]
        self.assertEqual(entry["stage"], "adopt")
        self.assertEqual(entry["disk_sha256"], _digest(target.disk))
        self.assertEqual(entry["vars_sha256"], _digest(target.vars))
        self.assertEqual(entry["source"], str(self.bundle))
        self.assertNotIn(SECRET.decode(), target.marker.read_text())
        self.assertEqual(
            [path.name for path in self.root.iterdir()], ["w1"])

    def test_adopt_accepts_a_bundle_without_a_backing_file_or_firmware(self):
        bundle = self.make_bundle(
            self.tmp / "run-flat", backing=False, firmware=False)
        target = self.target("w2")
        marker = target.adopt(bundle, BINDING)
        self.assertNotIn("backing-filename", _info(target.disk))
        self.assertFalse(target.vars.exists())
        self.assertIsNone(marker["ledger"][0]["vars_sha256"])

    def assert_refused_untouched(self, pattern: str, error=wi.WorkstationInvalid):
        before = self.snapshot(self.bundle)
        with self.assertRaisesRegex(error, pattern):
            self.target().adopt(self.bundle, BINDING)
        self.assertFalse(self.root.exists() and any(self.root.iterdir()))
        self.assertEqual(self.snapshot(self.bundle), before)

    def test_adopt_refuses_a_symlinked_publication(self):
        elsewhere = self.tmp / "elsewhere.iso"
        (self.bundle / "publication.iso").rename(elsewhere)
        (self.bundle / "publication.iso").symlink_to(elsewhere)
        with self.assertRaisesRegex(wi.WorkstationInvalid, "non-symlink"):
            self.target().adopt(self.bundle, BINDING)
        self.assertTrue((self.bundle / "publication.iso").is_symlink())
        self.assertIn(SECRET, elsewhere.read_bytes())
        self.assertFalse(self.root.exists() and any(self.root.iterdir()))

    def test_adopt_refuses_a_missing_publication(self):
        (self.bundle / "publication.iso").unlink()
        self.assert_refused_untouched("no publication")

    def test_adopt_refuses_a_publication_that_is_not_a_regular_file(self):
        (self.bundle / "publication.iso").unlink()
        (self.bundle / "publication.iso").mkdir()
        with self.assertRaisesRegex(wi.WorkstationInvalid, "regular"):
            self.target().adopt(self.bundle, BINDING)

    def test_adopt_refuses_an_unfinished_install(self):
        (self.bundle / "evidence" / "result.json").write_text(json.dumps(
            {"schema": 1, "status": "fail", "phase": "starting"}))
        self.assert_refused_untouched("did not finish")

    def test_adopt_refuses_a_disk_a_process_holds_open(self):
        holders = lambda path, **_: HOLDER if path.name == "windows.qcow2" else []  # noqa: E731
        with mock.patch.object(wi, "canonical_disk_users", side_effect=holders):
            self.assert_refused_untouched("open by", wi.WorkstationInUse)

    def test_adopt_refuses_an_existing_workstation(self):
        self.adopted()
        second = self.make_bundle(self.tmp / "run-second")
        with self.assertRaisesRegex(wi.WorkstationInvalid, "already exists"):
            self.target().adopt(second, BINDING)
        self.assertTrue((second / "publication.iso").is_file())

    def test_adopt_refuses_an_invalid_binding(self):
        for binding in (
            wi.Binding("Bad_Name", "EXAMPLE.TEST", "S-1-5-21-11-22-33"),
            wi.Binding("synthetic-dc", "", "S-1-5-21-11-22-33"),
            wi.Binding("synthetic-dc", "EXAMPLE.TEST", "S-1-5-21-11-22"),
        ):
            with self.subTest(binding=binding), self.assertRaises(
                    wi.WorkstationInvalid):
                self.target().adopt(self.bundle, binding)
        self.assertTrue((self.bundle / "publication.iso").is_file())

    def test_a_failed_commit_returns_the_publication_to_the_bundle(self):
        original = (self.bundle / "publication.iso").read_bytes()
        real_rename = os.rename

        def rename(source, target):
            if Path(source).name.startswith(".w1."):
                raise OSError("simulated commit failure")
            return real_rename(source, target)

        with mock.patch.object(wi.os, "rename", side_effect=rename):
            with self.assertRaisesRegex(OSError, "simulated"):
                self.target().adopt(self.bundle, BINDING)
        self.assertEqual(
            (self.bundle / "publication.iso").read_bytes(), original)
        self.assertEqual(list(self.root.iterdir()), [])

    def test_an_interrupted_adoption_blocks_the_next_one(self):
        self.root.mkdir()
        (self.root / ".w1.abc123").mkdir()
        before = self.snapshot(self.bundle)
        with self.assertRaisesRegex(wi.WorkstationInvalid, "interrupted"):
            self.target().adopt(self.bundle, BINDING)
        self.assertEqual([path.name for path in self.root.iterdir()],
                         [".w1.abc123"])
        self.assertEqual(self.snapshot(self.bundle), before)

    def test_names_cannot_traverse_or_hide(self):
        for name in ("../w", "W1", "-w", "w-", "", "a" * 33, "w/x", ".w"):
            with self.subTest(name=name), self.assertRaises(
                    wi.WorkstationInvalid):
                wi.workstation_state(self.root, name)

    def test_the_bulk_cleaned_factory_tree_is_refused(self):
        repository = self.tmp / "repo"
        state = repository / "homelab" / "var" / "factory" / "kept" / "w1"
        with mock.patch.object(wi, "REPOSITORY", repository):
            with self.assertRaisesRegex(wi.WorkstationInvalid, "bulk-cleaned"):
                wi.WorkstationInstance(state, name="w1").assert_safe()

    def test_a_symlinked_workstation_root_is_refused(self):
        real = self.tmp / "real-root"
        real.mkdir()
        self.root.symlink_to(real)
        with self.assertRaisesRegex(wi.WorkstationInvalid, "symlink"):
            self.target().adopt(self.bundle, BINDING)
        self.assertTrue((self.bundle / "publication.iso").is_file())


class FoldTests(WorkstationTestCase):
    def setUp(self):
        super().setUp()
        self.w = self.adopted()

    def test_fold_flattens_the_overlay_and_appends_the_ledger(self):
        adopt_entry = self.w.read_marker()["ledger"][0]
        overlay = self.overlay(self.w, "arch-install")
        expected = self.tmp / "expected.qcow2"
        _qemu_img("convert", "-f", "qcow2", "-O", "qcow2",
                  str(overlay), str(expected))

        entry = self.w.fold(overlay, "arch-install", source="run-synthetic-2")

        self.assertNotIn("backing-filename", _info(self.w.disk))
        self.assertTrue(_identical(self.w.disk, expected))
        marker = self.w.read_marker()
        self.assertEqual(marker["ledger"], [adopt_entry, entry])
        self.assertEqual(entry["disk_sha256"], _digest(self.w.disk))
        self.assertEqual(entry["vars_sha256"], adopt_entry["vars_sha256"])
        self.assertEqual(entry["source"], "run-synthetic-2")
        self.assertNotIn("pending_fold", marker)
        self.assertEqual(stat.S_IMODE(self.w.disk.stat().st_mode), 0o600)
        self.assertEqual(sorted(path.name for path in self.w.state.iterdir()),
                         sorted([wi.DISK_NAME, wi.VARS_NAME, wi.MARKER_NAME,
                                 wi.PUBLICATION_NAME, wi.LOCK_NAME]))

    def test_fold_can_replace_the_firmware_variables(self):
        overlay = self.overlay(self.w, "arch-install")
        firmware = self.tmp / "stage-vars.fd"
        firmware.write_bytes(NEW_VARS)
        entry = self.w.fold(overlay, "arch-install", firmware_vars=firmware)
        self.assertEqual(self.w.vars.read_bytes(), NEW_VARS_KEPT)
        self.assertEqual(entry["vars_sha256"], _digest(self.w.vars))
        self.assertEqual(stat.S_IMODE(self.w.vars.stat().st_mode), 0o600)

    def test_fold_keeps_the_variables_without_the_boot_path_cache(self):
        overlay = self.overlay(self.w, "arch-install")
        firmware = self.tmp / "stage-vars.fd"
        firmware.write_bytes(NEW_VARS)
        self.assertEqual(len(ovmf_vars.hddp_states(NEW_VARS)), 1)
        entry = self.w.fold(overlay, "arch-install", firmware_vars=firmware)
        kept = self.w.vars.read_bytes()
        self.assertEqual(ovmf_vars.hddp_states(kept), [])
        # Only the cache's state byte differs, and every other variable reads
        # back unchanged.
        self.assertEqual(len(kept), len(NEW_VARS))
        self.assertEqual(
            [index for index in range(len(kept))
             if kept[index] != NEW_VARS[index]],
            ovmf_vars.hddp_states(NEW_VARS))
        live = ovmf_vars.firmware_variables(NEW_VARS)
        del live[(ovmf_vars.HDDP_VENDOR, ovmf_vars.HDDP_NAME)]
        self.assertEqual(ovmf_vars.firmware_variables(kept), live)
        # The ledger records what is kept; the run's own copy is not touched.
        self.assertEqual(entry["vars_sha256"], _digest(self.w.vars))
        self.assertEqual(self.w.read_marker()["ledger"][-1], entry)
        self.assertEqual(firmware.read_bytes(), NEW_VARS)

    def test_fold_refuses_variables_that_are_not_a_store(self):
        overlay = self.overlay(self.w, "arch-install")
        firmware = self.tmp / "stage-vars.fd"
        firmware.write_bytes(b"not an EDK2 variable store")
        before = self.snapshot(self.w.state)
        with self.assertRaisesRegex(wi.WorkstationInvalid,
                                    "not an EDK2 variable store"):
            self.w.fold(overlay, "arch-install", firmware_vars=firmware)
        self.assertEqual(self.snapshot(self.w.state), before)
        self.assertEqual(self.w._leftovers(), [])

    def test_fold_refuses_while_a_process_holds_the_disk(self):
        overlay = self.overlay(self.w, "arch-install")
        before = self.snapshot(self.w.state)
        holders = lambda path, **_: HOLDER if path == self.w.disk else []  # noqa: E731
        with mock.patch.object(wi, "canonical_disk_users", side_effect=holders):
            with self.assertRaisesRegex(wi.WorkstationInUse, "open by"):
                self.w.fold(overlay, "arch-install")
        self.assertEqual(self.snapshot(self.w.state), before)

    def test_fold_refuses_while_another_run_holds_the_lock(self):
        overlay = self.overlay(self.w, "arch-install")
        other = self.target()
        with other:
            with self.assertRaisesRegex(wi.WorkstationInUse, "locked"):
                self.w.fold(overlay, "arch-install")
        self.assertEqual(len(self.w.read_marker()["ledger"]), 1)

    def test_fold_refuses_an_overlay_not_backed_by_the_workstation(self):
        stranger = self.tmp / "stranger.qcow2"
        _qemu_img("create", "-q", "-f", "qcow2", str(stranger), "64M")
        standalone = self.tmp / "standalone.qcow2"
        _qemu_img("convert", "-f", "qcow2", "-O", "qcow2",
                  str(self.w.disk), str(standalone))
        foreign = self.tmp / "foreign.qcow2"
        _qemu_img("create", "-q", "-f", "qcow2", "-b", str(stranger),
                  "-F", "qcow2", str(foreign))
        for overlay in (standalone, foreign):
            with self.subTest(overlay=overlay.name), self.assertRaisesRegex(
                    wi.WorkstationInvalid, "not a qcow2 backed by"):
                self.w.fold(overlay, "arch-install")
        self.assertEqual(len(self.w.read_marker()["ledger"]), 1)

    def test_fold_takes_each_stage_once_and_in_flow_order(self):
        overlay = self.overlay(self.w, "arch-install")
        for stage in ("adopt", "arch-join", "windows-join", "keep-verify"):
            with self.subTest(stage=stage), self.assertRaisesRegex(
                    wi.WorkstationInvalid, "next stage"):
                self.w.fold(overlay, stage)
        self.w.fold(overlay, "arch-install")
        with self.assertRaisesRegex(wi.WorkstationInvalid, "next stage"):
            self.w.fold(overlay, "arch-install")

    def test_fold_refuses_a_disk_changed_outside_the_ledger(self):
        _write(self.w.disk, 0x11, "3M")
        overlay = self.overlay(self.w, "arch-install")
        with self.assertRaisesRegex(wi.WorkstationInvalid, "outside a fold"):
            self.w.fold(overlay, "arch-install")

    def test_an_interrupted_fold_after_the_rename_is_committed_next_time(self):
        overlay = self.overlay(self.w, "arch-install")
        real_replace = os.replace

        def replace(source, target):
            real_replace(source, target)
            if Path(target) == self.w.disk:
                raise KeyboardInterrupt("simulated kill after the disk rename")

        with mock.patch.object(wi.os, "replace", side_effect=replace):
            with self.assertRaises(KeyboardInterrupt):
                self.w.fold(overlay, "arch-install")
        pending = self.w.read_marker()["pending_fold"]
        self.assertEqual(pending["disk_sha256"], _digest(self.w.disk))
        self.assertEqual(self.w.summary()["pending_fold"], "arch-install")

        self.w.fold(self.overlay(self.w, "arch-join", 0x22), "arch-join")
        ledger = self.w.read_marker()["ledger"]
        self.assertEqual([entry["stage"] for entry in ledger],
                         ["adopt", "arch-install", "arch-join"])
        self.assertEqual(ledger[1], pending)

    def test_an_interrupted_fold_before_the_rename_is_rolled_back(self):
        overlay = self.overlay(self.w, "arch-install")
        head = _digest(self.w.disk)
        real_replace = os.replace

        def replace(source, target):
            if Path(target) == self.w.disk:
                raise KeyboardInterrupt("simulated kill before the disk rename")
            return real_replace(source, target)

        with mock.patch.object(wi.os, "replace", side_effect=replace):
            with self.assertRaises(KeyboardInterrupt):
                self.w.fold(overlay, "arch-install")
        self.assertEqual(_digest(self.w.disk), head)
        self.assertIn("pending_fold", self.w.read_marker())

        self.w.fold(overlay, "arch-install")
        marker = self.w.read_marker()
        self.assertEqual([entry["stage"] for entry in marker["ledger"]],
                         ["adopt", "arch-install"])
        self.assertNotIn("pending_fold", marker)
        self.assertFalse((self.w.state / wi.DISK_STAGING_NAME).exists())


class Killed(BaseException):
    """A SIGKILL stand-in: the fold stops dead and runs none of its cleanup."""


BOTH_STAGED = [wi.DISK_STAGING_NAME, wi.VARS_STAGING_NAME]
#: Every point a fold can die at, in the order it passes them, and what each
#: leaves: (a fold recorded pending, what the live disk and variables hold,
#: leftover staging files, the reconcile decision). The disk rename is the
#: commit point: before it the head is intact, after it the fold is.
INTERRUPTIONS = (
    ("staged-disk", False, "head", "head", [wi.DISK_STAGING_NAME],
     wi.RECOVERY_NONE),
    ("staged-vars", False, "head", "head", BOTH_STAGED, wi.RECOVERY_NONE),
    ("pending-recorded", True, "head", "head", BOTH_STAGED,
     wi.RECOVERY_ROLL_BACK),
    ("disk-renamed", True, "fold", "head", [wi.VARS_STAGING_NAME],
     wi.RECOVERY_COMPLETE),
    ("vars-renamed", True, "fold", "fold", [], wi.RECOVERY_COMPLETE),
    ("ledger-append", True, "fold", "fold", [], wi.RECOVERY_COMPLETE),
)
NEW_VARS = store("Linux Boot Manager", hddp=True)
NEW_VARS_KEPT = ovmf_vars.without_hddp(NEW_VARS)[0]


class InterruptedFoldTests(WorkstationTestCase):
    """Which of the two readings of an interrupted fold holds, point by point.

    ``fold``'s own ``_reconcile`` could finish or roll back an interruption,
    but every stage runner refuses a pending fold before it boots, so before
    ``reconcile`` existed nothing could ever reach that code: a pending fold
    stranded ``W``. These tests kill a fold at each point and prove that the
    runners keep refusing, naming the reconcile command, and that
    ``reconcile`` resolves every point from hashes alone.
    """

    def setUp(self):
        super().setUp()
        patcher = mock.patch.object(wi, "canonical_disk_users", return_value=[])
        patcher.start()
        self.addCleanup(patcher.stop)

    def fresh(self, name: str) -> wi.WorkstationInstance:
        target = self.target(name)
        target.adopt(self.make_bundle(self.tmp / f"run-{name}"), BINDING)
        return target

    @contextlib.contextmanager
    def killed_at(self, w: wi.WorkstationInstance, point: str):
        """Kill ``w``'s fold right after ``point``, like a SIGKILL would."""
        real_convert, real_copy = wi._convert_standalone, wi._copy_private
        real_replace = os.replace
        real_write = wi.WorkstationInstance._write_marker

        def convert(source, target):
            real_convert(source, target)
            if point == "staged-disk":
                raise Killed(point)

        def copy(source, target):
            real_copy(source, target)
            if point == "staged-vars":
                raise Killed(point)

        def write_marker(instance, marker):
            if point == "ledger-append" and "pending_fold" not in marker:
                # Died mid-write: the staged marker exists, the rename did not.
                (instance.state / wi.MARKER_STAGING_NAME).write_text(
                    json.dumps(marker))
                raise Killed(point)
            real_write(instance, marker)
            if point == "pending-recorded" and "pending_fold" in marker:
                raise Killed(point)

        def replace(source, target):
            real_replace(source, target)
            if (point, Path(target)) in (("disk-renamed", w.disk),
                                         ("vars-renamed", w.vars)):
                raise Killed(point)

        with mock.patch.object(wi, "_convert_standalone", new=convert), \
                mock.patch.object(wi, "_copy_private", new=copy), \
                mock.patch.object(wi.os, "replace", new=replace), \
                mock.patch.object(wi.WorkstationInstance, "_write_marker",
                                  new=write_marker), \
                mock.patch.object(wi.WorkstationInstance, "_discard_staging",
                                  new=lambda instance: None), \
                self.assertRaises(Killed):
            yield

    def interrupt(self, w: wi.WorkstationInstance, point: str) -> Path:
        """Kill a fold of arch-install with new variables; return the
        standalone copy an uninterrupted fold would have made."""
        overlay = self.overlay(w, f"{w.state.name}-arch-install")
        expected = self.tmp / f"{w.state.name}-expected.qcow2"
        _qemu_img("convert", "-f", "qcow2", "-O", "qcow2",
                  str(overlay), str(expected))
        firmware = self.tmp / f"{w.state.name}-vars.fd"
        firmware.write_bytes(NEW_VARS)
        with self.killed_at(w, point):
            w.fold(overlay, "arch-install", firmware_vars=firmware,
                   source="run-synthetic-2")
        return expected

    def cli(self, *argv: str) -> tuple[int, str, str]:
        stdout, stderr = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(stdout), \
                contextlib.redirect_stderr(stderr):
            code = wi.main(["--root", str(self.root), *argv])
        return code, stdout.getvalue(), stderr.getvalue()

    def assert_runners_refuse(self, w: wi.WorkstationInstance) -> None:
        for runner, error in (
            (arch_durable_install_run.require_arch_install_next,
             arch_durable_install_run.DurableInstallError),
            (arch_durable_join.require_arch_join_next,
             arch_durable_join.ArchDurableJoinError),
        ):
            with self.subTest(runner=runner.__module__), \
                    self.assertRaisesRegex(error, "interrupted fold") as caught:
                runner(w)
            self.assertIn(wi.reconcile_command(w.state.name), str(caught.exception))
            self.assertIn("APPLY=1", str(caught.exception))

    def test_every_interruption_point_is_refused_then_reconciled(self):
        for point, recorded, disk, firmware, leftovers, action in INTERRUPTIONS:
            with self.subTest(point=point):
                w = self.fresh(point)
                head = w.read_marker()["ledger"][-1]
                expected = self.interrupt(w, point)
                marker = w.read_marker()
                pending = marker.get("pending_fold")
                self.assertEqual(pending is not None, recorded)
                source = {"head": head, "fold": pending}
                self.assertEqual(_digest(w.disk),
                                 source[disk]["disk_sha256"])
                self.assertEqual(_digest(w.vars),
                                 source[firmware]["vars_sha256"])
                self.assertEqual(sorted(w._leftovers()), sorted(leftovers))

                # Status says so first; every stage runner refuses by name.
                code, output, _ = self.cli("status", "--workstation", point)
                self.assertEqual(code, 0)
                if recorded:
                    self.assertTrue(output.splitlines()[1].startswith(
                        "INTERRUPTED FOLD: stage arch-install"), output)
                    self.assertIn(wi.reconcile_command(point), output)
                    self.assert_runners_refuse(w)
                else:
                    self.assertNotIn("INTERRUPTED", output)
                    arch_durable_install_run.require_arch_install_next(w)

                # The dry run decides and changes nothing.
                before = self.snapshot(w.state)
                decision = w.reconcile()
                self.assertEqual(decision["action"], action)
                self.assertFalse(decision["applied"])
                code, output, _ = self.cli("reconcile", "--workstation", point)
                self.assertEqual(code, 0)
                self.assertIn(f"decision: {action}", output)
                self.assertIn("dry run: repeat with --apply", output)
                self.assertEqual(self.snapshot(w.state), before)

                code, output, error = self.cli(
                    "reconcile", "--workstation", point, "--apply")
                self.assertEqual(code, 0, error)
                self.assertIn(f"reconciled {point}", output)
                marker = w.read_marker()
                self.assertNotIn("pending_fold", marker)
                self.assertEqual(w._leftovers(), [])
                self.assertFalse(
                    (w.state / wi.MARKER_STAGING_NAME).exists())
                now = marker["ledger"][-1]
                self.assertEqual(
                    (_digest(w.disk), _digest(w.vars)),
                    (now["disk_sha256"], now["vars_sha256"]))
                if action == wi.RECOVERY_COMPLETE:
                    self.assertEqual(marker["ledger"][1:], [pending])
                    self.assertTrue(_identical(w.disk, expected))
                    self.assertEqual(w.vars.read_bytes(), NEW_VARS_KEPT)
                    arch_durable_join.require_arch_join_next(w)
                else:
                    self.assertEqual(marker["ledger"], [head])
                    arch_durable_install_run.require_arch_install_next(w)

                # Idempotent: a second apply has nothing left to do.
                settled = self.snapshot(w.state)
                self.assertEqual(w.reconcile(apply=True)["action"],
                                 wi.RECOVERY_NONE)
                self.assertEqual(self.snapshot(w.state), settled)

    def test_fold_resolves_every_point_the_same_way(self):
        """``fold``'s own reconcile shares the decision table."""
        for point, _recorded, _disk, _firmware, _left, action in INTERRUPTIONS:
            with self.subTest(point=point):
                w = self.fresh(f"f-{point}")
                self.interrupt(w, point)
                stage = ("arch-join" if action == wi.RECOVERY_COMPLETE
                         else "arch-install")
                w.fold(self.overlay(w, f"f-{point}-{stage}", 0x44), stage)
                marker = w.read_marker()
                self.assertEqual([entry["stage"] for entry in marker["ledger"]],
                                 ["adopt", "arch-install"] + (
                                     ["arch-join"] if stage == "arch-join"
                                     else []))
                self.assertNotIn("pending_fold", marker)
                self.assertEqual(w._leftovers(), [])

    def test_lost_variables_after_the_commit_point_are_refused(self):
        w = self.fresh("w1")
        self.interrupt(w, "disk-renamed")
        (w.state / wi.VARS_STAGING_NAME).unlink()
        before = self.snapshot(w.state)
        decision = w.reconcile()
        self.assertEqual(decision["action"], wi.RECOVERY_REFUSE)
        self.assertIn("neither finishing nor rolling back", decision["reason"])
        code, output, _ = self.cli("reconcile", "--workstation", "w1")
        self.assertEqual(code, 1)
        self.assertIn("decision: refuse", output)
        code, _, error = self.cli("reconcile", "--workstation", "w1", "--apply")
        self.assertEqual(code, 2)
        self.assertIn("Nothing was changed", error)
        with self.assertRaisesRegex(wi.WorkstationInvalid, "inspect"):
            w.reconcile(apply=True)
        self.assertEqual(self.snapshot(w.state), before)
        self.assert_runners_refuse(w)

    def test_files_changed_while_a_fold_is_pending_are_refused(self):
        changes = {
            "disk": lambda w: _write(w.disk, 0x11, "3M"),
            "vars": lambda w: w.vars.write_bytes(b"edited out of band"),
        }
        for label, change in changes.items():
            with self.subTest(changed=label):
                w = self.fresh(f"changed-{label}")
                self.interrupt(w, "pending-recorded")
                change(w)
                before = self.snapshot(w.state)
                with self.assertRaisesRegex(wi.WorkstationInvalid,
                                            "changed outside the ledger"):
                    w.reconcile(apply=True)
                self.assertEqual(self.snapshot(w.state), before)

    def test_a_disk_changed_with_no_fold_pending_is_refused(self):
        w = self.fresh("w1")
        _write(w.disk, 0x11, "3M")
        before = self.snapshot(w.state)
        self.assertEqual(w.reconcile()["action"], wi.RECOVERY_REFUSE)
        with self.assertRaisesRegex(wi.WorkstationInvalid, "outside a fold"):
            w.reconcile(apply=True)
        self.assertEqual(self.snapshot(w.state), before)

    def test_an_unchanged_disk_with_lost_variables_rolls_back(self):
        """The disk hashing to both head and fold is no proof of the fold."""
        w = self.fresh("w1")
        marker = w.read_marker()
        head = marker["ledger"][-1]
        marker["pending_fold"] = dict(
            head, stage="arch-install", vars_sha256="ab" * 32,
            source="synthetic")
        w._write_marker(marker)
        decision = w.reconcile(apply=True)
        self.assertEqual(decision["action"], wi.RECOVERY_ROLL_BACK)
        self.assertEqual(w.read_marker()["ledger"], [head])

    def test_an_interrupted_reconcile_reaches_the_same_end(self):
        w = self.fresh("w1")
        self.interrupt(w, "disk-renamed")
        pending = w.read_marker()["pending_fold"]
        with mock.patch.object(wi.WorkstationInstance, "_write_marker",
                               side_effect=Killed("after the vars rename")), \
                self.assertRaises(Killed):
            w.reconcile(apply=True)
        self.assertEqual(_digest(w.vars), pending["vars_sha256"])
        decision = w.reconcile(apply=True)
        self.assertEqual(decision["action"], wi.RECOVERY_COMPLETE)
        self.assertFalse(decision["rename_vars"])
        self.assertEqual(w.read_marker()["ledger"][-1], pending)

    def test_reconcile_holds_the_lock(self):
        w = self.fresh("w1")
        self.interrupt(w, "pending-recorded")
        before = self.snapshot(w.state)
        with self.target():
            for apply in (False, True):
                with self.subTest(apply=apply), self.assertRaisesRegex(
                        wi.WorkstationInUse, "locked"):
                    w.reconcile(apply=apply)
        self.assertEqual(self.snapshot(w.state), before)
        seen = []
        real = wi.WorkstationInstance.recovery

        def recovery(instance, marker=None):
            seen.append(self.target().locked())
            return real(instance, marker)

        with mock.patch.object(wi.WorkstationInstance, "recovery", new=recovery):
            w.reconcile(apply=True)
        self.assertEqual(seen, [True])
        self.assertFalse(self.target().locked())

    def test_reconcile_refuses_while_a_process_holds_the_disk(self):
        w = self.fresh("w1")
        self.interrupt(w, "disk-renamed")
        before = self.snapshot(w.state)
        holders = lambda path, **_: HOLDER if path == w.disk else []  # noqa: E731
        with mock.patch.object(wi, "canonical_disk_users", side_effect=holders):
            with self.assertRaisesRegex(wi.WorkstationInUse, "open by"):
                w.reconcile(apply=True)
        self.assertEqual(self.snapshot(w.state), before)

    def test_a_workstation_with_nothing_to_reconcile_says_so(self):
        self.fresh("w1")
        code, output, _ = self.cli("reconcile", "--workstation", "w1")
        self.assertEqual(code, 0)
        self.assertIn("no fold pending", output)
        self.assertNotIn("dry run", output)


class LedgerTests(WorkstationTestCase):
    def setUp(self):
        super().setUp()
        self.w = self.adopted()
        self.w.fold(self.overlay(self.w, "arch-install"), "arch-install")

    def test_the_ledger_and_identity_fields_cannot_be_rewritten(self):
        edits = {
            "rewritten hash": lambda m: m["ledger"][0].update(
                disk_sha256="0" * 64),
            "dropped entry": lambda m: m["ledger"].pop(),
            "rebound instance": lambda m: m["binding"].update(
                persistent_instance="other-dc"),
            "renamed": lambda m: m.update(created_utc="then"),
        }
        before = self.w.marker.read_bytes()
        for label, edit in edits.items():
            marker = self.w.read_marker()
            edit(marker)
            with self.subTest(label), self.assertRaises(wi.WorkstationInvalid):
                self.w._write_marker(marker)
        self.assertEqual(self.w.marker.read_bytes(), before)

    def test_machine_accounts_are_append_only(self):
        self.w.record_machine_account("TELOS-WIN-01")
        self.w.record_machine_account("TELOS-WIN-01")
        marker = self.w.read_marker()
        self.assertEqual(marker["machine_accounts"], ["TELOS-WIN-01"])
        marker["machine_accounts"] = []
        with self.assertRaisesRegex(wi.WorkstationInvalid, "append-only"):
            self.w._write_marker(marker)
        with self.assertRaises(wi.WorkstationInvalid):
            self.w.record_machine_account("not a name!")

    def test_a_marker_rewrite_is_atomic(self):
        before = self.w.marker.read_bytes()
        real_replace = os.replace

        def replace(source, target):
            if Path(target) == self.w.marker:
                raise OSError("simulated failure at the rename")
            return real_replace(source, target)

        with mock.patch.object(wi.os, "replace", side_effect=replace):
            with self.assertRaisesRegex(OSError, "simulated"):
                self.w.record_machine_account("TELOS-WIN-01")
        self.assertEqual(self.w.marker.read_bytes(), before)
        self.assertFalse((self.w.state / wi.MARKER_STAGING_NAME).exists())

    def test_a_marker_rewrite_refuses_a_planted_staging_symlink(self):
        victim = self.tmp / "victim"
        victim.write_text("untouched")
        (self.w.state / wi.MARKER_STAGING_NAME).symlink_to(victim)
        with self.assertRaises(OSError):
            self.w.record_machine_account("TELOS-WIN-01")
        self.assertEqual(victim.read_text(), "untouched")


class DestroyTests(WorkstationTestCase):
    def setUp(self):
        super().setUp()
        self.w = self.adopted()

    def test_destroy_requires_the_exact_phrase(self):
        before = self.snapshot(self.w.state)
        for phrase in (None, "", "DESTROY", "destroy w1", "DESTROY w2",
                       "DESTROY w1 ", "DESTROY  w1"):
            with self.subTest(phrase=phrase), self.assertRaisesRegex(
                    wi.WorkstationInvalid, "DESTROY w1"):
                self.w.destroy(phrase)
        self.assertEqual(self.snapshot(self.w.state), before)

    def test_destroy_shreds_the_publication_first_and_lists_accounts(self):
        self.w.record_machine_account("TELOS-WIN-01")
        self.w.record_machine_account("SYNTH-ARCH-01")
        witness = self.tmp / "publication-witness"
        os.link(self.w.publication, witness)
        removed = []
        real_unlink = Path.unlink

        def unlink(path, *args, **kwargs):
            removed.append(path.name)
            return real_unlink(path, *args, **kwargs)

        with mock.patch.object(Path, "unlink", autospec=True,
                               side_effect=unlink):
            result = self.w.destroy("DESTROY w1")

        self.assertEqual(removed[0], wi.PUBLICATION_NAME)
        self.assertNotIn(SECRET, witness.read_bytes())
        self.assertEqual(set(witness.read_bytes()), {0})
        self.assertEqual(result["machine_accounts"],
                         ["TELOS-WIN-01", "SYNTH-ARCH-01"])
        self.assertFalse(self.w.state.exists())

    def test_destroy_refuses_unexpected_entries_a_lock_and_a_holder(self):
        (self.w.state / "stray").write_text("x")
        with self.assertRaisesRegex(wi.WorkstationInvalid, "stray"):
            self.w.destroy("DESTROY w1")
        (self.w.state / "stray").unlink()
        with self.target():
            with self.assertRaisesRegex(wi.WorkstationInUse, "locked"):
                self.w.destroy("DESTROY w1")
        holders = lambda path, **_: HOLDER if path == self.w.disk else []  # noqa: E731
        with mock.patch.object(wi, "canonical_disk_users", side_effect=holders):
            with self.assertRaisesRegex(wi.WorkstationInUse, "open by"):
                self.w.destroy("DESTROY w1")
        self.assertIn(SECRET, self.w.publication.read_bytes())


class CustodyAndStatusTests(WorkstationTestCase):
    def setUp(self):
        super().setUp()
        self.w = self.adopted()

    def status_output(self) -> tuple[int, str]:
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            code = wi.main(["--root", str(self.root), "status",
                            "--workstation", "w1"])
        return code, stdout.getvalue()

    def test_status_reports_the_facts_and_no_secret(self):
        code, output = self.status_output()
        self.assertEqual(code, 0)
        self.assertIn("stage done: adopt", output)
        self.assertIn("next stage: arch-install", output)
        self.assertIn("publication custody: held", output)
        self.assertIn(f"bound instance: {BINDING.persistent_instance}", output)
        self.assertIn(f"disk: present, {self.w.disk.stat().st_size} bytes",
                      output)
        for private in (SECRET.decode(), "ISO9660", BINDING.realm,
                        BINDING.domain_sid):
            self.assertNotIn(private, output)

    def test_status_is_read_only(self):
        before = self.snapshot(self.w.state)
        self.status_output()
        self.assertEqual(self.snapshot(self.w.state), before)

    def test_status_of_an_absent_workstation_fails(self):
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            code = wi.main(["--root", str(self.root), "status",
                            "--workstation", "absent"])
        self.assertEqual(code, 1)
        self.assertIn("absent", stdout.getvalue())

    def test_a_vanished_publication_is_reported_not_hidden(self):
        self.w.publication.unlink()
        self.assertIn("MISSING", self.status_output()[1])

    def test_the_publication_is_retired_only_after_the_windows_join(self):
        with self.assertRaisesRegex(wi.WorkstationInvalid, "windows-join"):
            self.w.retire_publication()
        for number, stage in enumerate(wi.FLOW_STAGES[1:]):
            self.w.fold(self.overlay(self.w, stage, 0x30 + number), stage)
        self.w.retire_publication()
        self.assertFalse(self.w.publication.exists())
        self.assertIn("publication custody: retired", self.status_output()[1])
        self.assertIn("none; every stage folded", self.status_output()[1])


class CommandLineTests(WorkstationTestCase):
    def setUp(self):
        super().setUp()
        self.persistent_root = self.tmp / "persistent"
        self.persistent(converged=True)
        patcher = mock.patch.object(wi, "canonical_disk_users", return_value=[])
        patcher.start()
        self.addCleanup(patcher.stop)

    def persistent(self, *, converged: bool, name: str = "synthetic-dc"):
        state = self.persistent_root / name
        state.mkdir(parents=True, mode=0o700)
        for file in ("persistent-dc.qcow2", "OVMF_VARS.fd"):
            (state / file).write_bytes(b"synthetic")
        marker = {"schema": 1, "mode": "persistent", "instance": name,
                  "created_utc": "2026-01-01T00:00:00+00:00"}
        if converged:
            marker["converged"] = {
                "converged_utc": "2026-01-01T00:00:00+00:00",
                "realm": BINDING.realm, "domain_sid": BINDING.domain_sid}
        (state / "persistent-instance.json").write_text(json.dumps(marker))

    def run_cli(self, *argv: str) -> tuple[int, str, str]:
        stdout, stderr = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(stdout), \
                contextlib.redirect_stderr(stderr):
            code = wi.main(["--root", str(self.root), *argv])
        return code, stdout.getvalue(), stderr.getvalue()

    def adopt_argv(self, *extra: str, instance: str = "synthetic-dc"):
        return ("adopt", "--workstation", "w1",
                "--windows-run", str(self.bundle),
                "--persistent-dc", instance,
                "--persistent-root", str(self.persistent_root), *extra)

    def test_adopt_is_a_dry_run_without_apply(self):
        for argv in (self.adopt_argv(), ("plan", *self.adopt_argv()[1:])):
            code, output, _ = self.run_cli(*argv)
            self.assertEqual(code, 0)
            self.assertIn("dry run", output)
            self.assertIn("MOVED", output)
        self.assertFalse(self.root.exists())
        self.assertTrue((self.bundle / "publication.iso").is_file())

    def test_adopt_apply_binds_from_the_persistent_instance_marker(self):
        code, output, _ = self.run_cli(*self.adopt_argv("--apply"))
        self.assertEqual(code, 0, output)
        target = self.target()
        self.assertEqual(target.read_marker()["binding"], BINDING.record())
        self.assertFalse((self.bundle / "publication.iso").exists())
        code, output, _ = self.run_cli("plan", "--workstation", "w1")
        self.assertEqual(code, 0)
        self.assertIn("next stage: arch-install", output)

    def test_adopt_refuses_an_unconverged_instance(self):
        self.persistent(converged=False, name="bare-dc")
        code, _, error = self.run_cli(
            *self.adopt_argv("--apply", instance="bare-dc"))
        self.assertEqual(code, 2)
        self.assertIn("converge it", error)
        self.assertTrue((self.bundle / "publication.iso").is_file())

    def test_destroy_is_a_dry_run_and_then_needs_the_phrase(self):
        self.adopted().record_machine_account("TELOS-WIN-01")
        code, output, _ = self.run_cli("destroy", "--workstation", "w1")
        self.assertEqual(code, 0)
        self.assertIn("dry run", output)
        self.assertIn("TELOS-WIN-01", output)
        self.assertTrue(self.target().exists())
        code, _, error = self.run_cli(
            "destroy", "--workstation", "w1", "--apply",
            "--confirm", "DESTROY w2")
        self.assertEqual(code, 2)
        self.assertIn("DESTROY w1", error)
        self.assertTrue(self.target().exists())
        code, output, _ = self.run_cli(
            "destroy", "--workstation", "w1", "--apply",
            "--confirm", "DESTROY w1")
        self.assertEqual(code, 0)
        self.assertIn("samba-tool computer delete", output)
        self.assertIn("TELOS-WIN-01", output)
        self.assertFalse(self.target().state.exists())


if __name__ == "__main__":
    unittest.main()
