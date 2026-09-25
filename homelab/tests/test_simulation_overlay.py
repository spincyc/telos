"""Safety tests for disposable and persistent controller simulation state."""

import json
import subprocess
import sys
import tempfile
import unittest
import os
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "vm"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import fake_image_tools  # noqa: E402
import simulation_overlay  # noqa: E402


class TestControllerOverlay(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.state = self.root / "state"
        self.state.mkdir()
        self.disk = self.state / "bootstrap-dc.qcow2"
        self.disk.write_bytes(b"canonical disk")
        self.vars = self.state / "OVMF_VARS.fd"
        self.vars.write_bytes(b"canonical vars")
        self.run = self.root / "run"

    def prepared(self):
        overlay = simulation_overlay.ControllerOverlay(
            self.disk, self.vars, run_root=self.run, proc_root=self.root / "proc")

        def create(argv, **_kwargs):
            if argv[1] == "create":
                Path(argv[-1]).write_bytes(b"overlay")
            return subprocess.CompletedProcess(argv, 0)

        patch = mock.patch.object(simulation_overlay.subprocess, "run",
                                  side_effect=create)
        patch.start()
        self.addCleanup(patch.stop)
        (self.root / "proc").mkdir(exist_ok=True)
        return overlay.prepare()

    def test_qemu_img_uses_absolute_canonical_backing_file(self):
        with mock.patch.object(simulation_overlay.subprocess, "run") as run:
            overlay = simulation_overlay.ControllerOverlay(
                self.disk, self.vars, run_root=self.run,
                proc_root=self.root / "proc")
            (self.root / "proc").mkdir()
            overlay.prepare()
            argv = next(
                call.args[0] for call in run.call_args_list
                if call.args[0][1] == "create"
            )
            self.assertEqual(argv[argv.index("-b") + 1], str(self.disk.resolve()))
            self.assertEqual(argv[argv.index("-F") + 1], "qcow2")
            overlay.close()

    def test_qemu_drive_names_only_the_disposable_overlay(self):
        overlay = self.prepared()
        drive = overlay.qemu_disk_drive()
        self.assertIn(str(overlay.disk), drive)
        self.assertNotIn(str(self.disk), drive)
        overlay.close()

    def test_ovmf_variables_are_a_private_copy(self):
        overlay = self.prepared()
        overlay.vars.write_bytes(b"changed")
        self.assertEqual(self.vars.read_bytes(), b"canonical vars")
        drive = overlay.qemu_vars_drive()
        self.assertIn(str(overlay.vars), drive)
        self.assertNotIn(str(self.vars), drive)
        overlay.close()

    def test_second_run_cannot_acquire_the_same_lock(self):
        first = self.prepared()
        second = simulation_overlay.ControllerOverlay(
            self.disk, self.vars, run_root=self.root / "run-two",
            proc_root=self.root / "proc")
        with self.assertRaisesRegex(RuntimeError, "already running"):
            second.prepare()
        first.close()

    def test_changed_canonical_disk_fails_the_run(self):
        overlay = self.prepared()
        self.disk.write_bytes(b"tampered")
        with self.assertRaisesRegex(RuntimeError, "changed during simulation"):
            overlay.close()
        self.assertFalse(overlay.disk.exists())

    def test_changed_canonical_ovmf_variables_fail_the_run(self):
        overlay = self.prepared()
        self.vars.write_bytes(b"tampered")
        with self.assertRaisesRegex(
            RuntimeError, "canonical OVMF variables changed during simulation"
        ):
            overlay.close()
        self.assertFalse(overlay.vars.exists())

    def test_run_files_are_removed_on_clean_close(self):
        overlay = self.prepared()
        overlay.close()
        self.assertFalse(overlay.disk.exists())
        self.assertFalse(overlay.vars.exists())

    def test_symlinked_canonical_disk_is_rejected(self):
        real = self.root / "real.qcow2"
        real.write_bytes(b"disk")
        link = self.root / "link.qcow2"
        link.symlink_to(real)
        overlay = simulation_overlay.ControllerOverlay(
            link, self.vars, run_root=self.run, proc_root=self.root / "proc")
        with self.assertRaisesRegex(RuntimeError, "non-symlink"):
            overlay.prepare()

    def test_failed_overlay_creation_releases_lock(self):
        first = simulation_overlay.ControllerOverlay(
            self.disk, self.vars, run_root=self.run, proc_root=self.root / "proc")
        (self.root / "proc").mkdir()
        with mock.patch.object(
            simulation_overlay.subprocess, "run",
            side_effect=[
                subprocess.CompletedProcess(["qemu-img", "info"], 0),
                subprocess.CalledProcessError(1, "qemu-img"),
            ],
        ):
            with self.assertRaises(subprocess.CalledProcessError):
                first.prepare()
        second = self.prepared()
        second.close()

    def test_open_canonical_disk_is_rejected_before_overlay_creation(self):
        proc = self.root / "proc"
        fd = proc / "4312" / "fd"
        fd.mkdir(parents=True)
        (proc / "4312" / "comm").write_text("qemu-system-x86\n")
        (fd / "9").symlink_to(self.disk)
        overlay = simulation_overlay.ControllerOverlay(
            self.disk, self.vars, run_root=self.run, proc_root=proc)
        with self.assertRaisesRegex(
            simulation_overlay.CanonicalDiskInUse, r"4312 \(qemu-system-x86\)"
        ):
            overlay.prepare()
        self.assertFalse(overlay.disk.exists())

    def test_unreadable_or_missing_proc_fails_closed(self):
        overlay = simulation_overlay.ControllerOverlay(
            self.disk, self.vars, run_root=self.run,
            proc_root=self.root / "missing-proc")
        with self.assertRaisesRegex(RuntimeError, "cannot inspect"):
            overlay.prepare()

    def test_different_user_inaccessible_process_is_ignored(self):
        proc = self.root / "proc"
        pid = proc / "1"
        (pid / "fd").mkdir(parents=True)
        overlay = simulation_overlay.ControllerOverlay(
            self.disk, self.vars, run_root=self.run, proc_root=proc)
        real_stat = Path.stat

        def stat(path):
            result = real_stat(path)
            if Path(path) == pid:
                values = list(result)
                values[4] = os.geteuid() + 1
                return os.stat_result(values)
            return result

        real_iterdir = Path.iterdir

        def iterdir(path):
            if Path(path) == pid / "fd":
                raise PermissionError("different user")
            return real_iterdir(path)

        with mock.patch.object(Path, "stat", new=stat), \
             mock.patch.object(Path, "iterdir", new=iterdir), \
             mock.patch.object(simulation_overlay.subprocess, "run") as run:
            overlay.prepare()
        self.assertEqual(run.call_count, 2)
        overlay.close()

    def test_identified_same_user_non_qemu_inaccessible_process_is_ignored(self):
        proc = self.root / "proc"
        pid = proc / "2210"
        (pid / "fd").mkdir(parents=True)
        (pid / "comm").write_text("systemd\n")
        (pid / "cmdline").write_bytes(b"/usr/lib/systemd/systemd\0--user\0")
        overlay = simulation_overlay.ControllerOverlay(
            self.disk, self.vars, run_root=self.run, proc_root=proc)
        real_iterdir = Path.iterdir

        def iterdir(path):
            if Path(path) == pid / "fd":
                raise PermissionError("non-dumpable user process")
            return real_iterdir(path)

        with mock.patch.object(Path, "iterdir", new=iterdir), \
             mock.patch.object(simulation_overlay.subprocess, "run"):
            overlay.prepare()
        overlay.close()

    def test_same_user_unidentified_live_process_fails_closed(self):
        # A same-EUID process with no readable identity and inaccessible
        # descriptors cannot be cleared of holding the canonical disk. As long
        # as it stays live, the audit must fail closed even after the transient
        # re-check budget, or the security boundary would be weakened.
        proc = self.root / "proc"
        pid = proc / "5150"
        (pid / "fd").mkdir(parents=True)
        overlay = simulation_overlay.ControllerOverlay(
            self.disk, self.vars, run_root=self.run, proc_root=proc)
        real_iterdir = Path.iterdir

        def iterdir(path):
            if Path(path) == pid / "fd":
                raise PermissionError("non-dumpable, unidentified")
            return real_iterdir(path)

        with mock.patch.object(Path, "iterdir", new=iterdir), \
             mock.patch.object(simulation_overlay.time, "sleep"), \
             mock.patch.object(simulation_overlay.subprocess, "run"):
            with self.assertRaisesRegex(RuntimeError, "cannot inspect"):
                overlay.prepare()

    def test_same_user_qemu_zombie_is_skipped(self):
        # A zombie's descriptor table is already destroyed by the kernel, so it
        # cannot hold the canonical disk, yet its fd directory raises
        # PermissionError even for the owner and its comm stays readable. The
        # run's own just-killed QEMU sits in exactly this state during
        # teardown; the audit must skip it rather than fail closed.
        proc = self.root / "proc"
        pid = proc / "7350"
        (pid / "fd").mkdir(parents=True)
        (pid / "comm").write_text("qemu-system-x86\n")
        (pid / "cmdline").write_bytes(b"")
        (pid / "stat").write_text(
            "7350 (qemu-system-x86) Z 1 7350 7350 0 -1 4227340\n")
        overlay = simulation_overlay.ControllerOverlay(
            self.disk, self.vars, run_root=self.run, proc_root=proc)
        real_iterdir = Path.iterdir

        def iterdir(path):
            if Path(path) == pid / "fd":
                raise PermissionError("zombie fd table")
            return real_iterdir(path)

        with mock.patch.object(Path, "iterdir", new=iterdir), \
             mock.patch.object(simulation_overlay.subprocess, "run"):
            overlay.prepare()
        overlay.close()

    def test_same_user_live_qemu_with_unreadable_descriptors_fails_closed(self):
        # The zombie tolerance must not extend to a live QEMU: a running
        # same-EUID QEMU whose descriptors cannot be read stays a fail-closed
        # audit error, because it genuinely could hold the canonical disk.
        proc = self.root / "proc"
        pid = proc / "7351"
        (pid / "fd").mkdir(parents=True)
        (pid / "comm").write_text("qemu-system-x86\n")
        (pid / "cmdline").write_bytes(b"qemu-system-x86_64\0-m\0512\0")
        (pid / "stat").write_text(
            "7351 (qemu-system-x86) S 1 7351 7351 0 -1 4194560\n")
        overlay = simulation_overlay.ControllerOverlay(
            self.disk, self.vars, run_root=self.run, proc_root=proc)
        real_iterdir = Path.iterdir

        def iterdir(path):
            if Path(path) == pid / "fd":
                raise PermissionError("live but unreadable")
            return real_iterdir(path)

        with mock.patch.object(Path, "iterdir", new=iterdir), \
             mock.patch.object(simulation_overlay.time, "sleep"), \
             mock.patch.object(simulation_overlay.subprocess, "run"):
            with self.assertRaisesRegex(RuntimeError, "cannot inspect"):
                overlay.prepare()

    def test_transient_unidentified_process_that_exits_is_skipped(self):
        # A same-EUID unidentified process that is momentarily un-inspectable
        # but exits within the re-check window held no descriptors on the
        # canonical disk, so it is skipped rather than failing the audit.
        proc = self.root / "proc"
        pid = proc / "6270"
        (pid / "fd").mkdir(parents=True)
        overlay = simulation_overlay.ControllerOverlay(
            self.disk, self.vars, run_root=self.run, proc_root=proc)
        real_iterdir = Path.iterdir
        real_stat = Path.stat
        pid_stats = {"count": 0}

        def iterdir(path):
            if Path(path) == pid / "fd":
                raise PermissionError("un-inspectable while tearing down")
            return real_iterdir(path)

        # The ownership stat during inspection succeeds (the process is still
        # live), the descriptor read raises, and by the liveness re-check the
        # pid directory no longer stats: the process has exited, so the audit
        # treats it as gone rather than failing closed.
        def stat(path):
            if Path(path) == pid:
                pid_stats["count"] += 1
                if pid_stats["count"] > 1:
                    raise FileNotFoundError(path)
            return real_stat(path)

        with mock.patch.object(Path, "iterdir", new=iterdir), \
             mock.patch.object(Path, "stat", new=stat), \
             mock.patch.object(simulation_overlay.time, "sleep"), \
             mock.patch.object(simulation_overlay.subprocess, "run"):
            overlay.prepare()
        overlay.close()

    def test_group_writable_canonical_disk_is_rejected(self):
        self.disk.chmod(0o660)
        proc = self.root / "proc"
        proc.mkdir()
        overlay = simulation_overlay.ControllerOverlay(
            self.disk, self.vars, run_root=self.run, proc_root=proc)
        with self.assertRaisesRegex(RuntimeError, "group/world writable"):
            overlay.prepare()

    def test_group_writable_canonical_ovmf_variables_are_rejected(self):
        self.vars.chmod(0o660)
        proc = self.root / "proc"
        proc.mkdir()
        overlay = simulation_overlay.ControllerOverlay(
            self.disk, self.vars, run_root=self.run, proc_root=proc)
        with self.assertRaisesRegex(
            RuntimeError, "canonical OVMF variables must not be group/world writable"
        ):
            overlay.prepare()

    def test_close_preserves_state_and_lock_while_disk_is_open(self):
        proc = self.root / "proc"
        proc.mkdir()
        overlay = simulation_overlay.ControllerOverlay(
            self.disk, self.vars, run_root=self.run, proc_root=proc)

        def create(argv, **_kwargs):
            if argv[1] == "create":
                Path(argv[-1]).write_bytes(b"overlay")
            return subprocess.CompletedProcess(argv, 0)

        with mock.patch.object(
            simulation_overlay.subprocess, "run", side_effect=create
        ):
            overlay.prepare()
        fd = proc / "99" / "fd"
        fd.mkdir(parents=True)
        (fd / "3").symlink_to(self.disk)
        with self.assertRaises(simulation_overlay.CanonicalDiskInUse):
            overlay.close()
        self.assertTrue(overlay.disk.exists())
        second = simulation_overlay.ControllerOverlay(
            self.disk, self.vars, run_root=self.root / "run-two", proc_root=proc)
        with self.assertRaisesRegex(RuntimeError, "already running"):
            second.prepare()
        (fd / "3").unlink()
        overlay.close()
        self.assertFalse(overlay.disk.exists())

    def test_qemu_image_lock_probe_failure_is_rejected(self):
        proc = self.root / "proc"
        proc.mkdir()
        overlay = simulation_overlay.ControllerOverlay(
            self.disk, self.vars, run_root=self.run, proc_root=proc)
        with mock.patch.object(
            simulation_overlay.subprocess, "run",
            side_effect=subprocess.CalledProcessError(1, "qemu-img"),
        ):
            with self.assertRaisesRegex(
                simulation_overlay.CanonicalDiskInUse, "could not lock/read"
            ):
                overlay.prepare()

    def test_open_canonical_ovmf_variables_are_rejected(self):
        proc = self.root / "proc"
        fd = proc / "8841" / "fd"
        fd.mkdir(parents=True)
        (proc / "8841" / "comm").write_text("qemu-system-x86\n")
        (fd / "7").symlink_to(self.vars)
        overlay = simulation_overlay.ControllerOverlay(
            self.disk, self.vars, run_root=self.run, proc_root=proc)
        with self.assertRaisesRegex(
            simulation_overlay.CanonicalDiskInUse,
            r"canonical OVMF variables is open by: 8841 \(qemu-system-x86\)",
        ):
            overlay.prepare()
        self.assertFalse(overlay.vars.exists())


class TestPersistentControllerInstance(unittest.TestCase):
    """A controller whose directory survives shutdown, without weakening the
    disposable acceptance fence."""

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.canonical = self.root / "canonical"
        self.canonical.mkdir()
        self.disk = self.canonical / simulation_overlay.ACCEPTANCE_DISK_NAME
        # An installed canonical, because seeding from a never-installed one is
        # now refused. ``test_creation_refuses_a_canonical_that_was_never_installed``
        # covers the other side.
        fake_image_tools.installed_image(self.disk, b" canonical disk")
        self.vars = self.canonical / "OVMF_VARS.fd"
        self.vars.write_bytes(b"canonical vars")
        self.proc = self.root / "proc"
        self.proc.mkdir()
        self.instances = self.root / "instances"

    def _fake_qemu_img(self, argv, **kwargs):
        # ``create`` writes the guard overlay, ``convert`` writes the
        # instance's independent copy, ``info`` is the lock probe -- and
        # ``info``/``map``/``dd`` plus ``sfdisk`` are what the installed-image
        # gate reads. ``fake_image_tools`` answers all of them consistently
        # from the source file's content, so the gate runs for real here
        # instead of being patched out.
        return fake_image_tools.image_tool(argv, **kwargs)

    def _patch_qemu_img(self):
        patch = mock.patch.object(
            simulation_overlay.subprocess, "run",
            side_effect=self._fake_qemu_img)
        patch.start()
        self.addCleanup(patch.stop)

    def instance(self, name="lab-dc1", state=None):
        return simulation_overlay.PersistentControllerInstance(
            self.instances / name if state is None else state,
            instance=name, proc_root=self.proc)

    def seeded(self, name="lab-dc1"):
        self._patch_qemu_img()
        target = self.instance(name)
        target.create(self.disk, self.vars)
        return target

    # -- opt-in ----------------------------------------------------------
    def test_persistent_mode_is_never_inferred_from_state_on_disk(self):
        # A directory that merely holds a controller disk is not a persistent
        # instance: bring-up requires the instance's own marker, so persistence
        # can only be entered by explicitly creating one.
        state = self.instances / "lab-dc1"
        state.mkdir(parents=True)
        (state / simulation_overlay.PERSISTENT_DISK_NAME).write_bytes(b"disk")
        (state / "OVMF_VARS.fd").write_bytes(b"vars")
        target = self.instance()
        self.assertFalse(target.exists())
        with self.assertRaisesRegex(
            simulation_overlay.PersistentInstanceInvalid,
            "not a persistent controller instance",
        ):
            target.prepare()

    def test_marker_must_declare_the_schema_mode_and_matching_instance(self):
        target = self.seeded()
        for broken in (
            {"schema": 2, "mode": "persistent", "instance": "lab-dc1"},
            {"schema": 1, "mode": "disposable", "instance": "lab-dc1"},
            {"schema": 1, "mode": "persistent", "instance": "other"},
            {"schema": 1, "mode": "persistent", "instance": "../escape"},
            ["not", "an", "object"],
        ):
            with self.subTest(broken=broken):
                target.marker.write_text(json.dumps(broken), encoding="utf-8")
                with self.assertRaises(
                        simulation_overlay.PersistentInstanceInvalid):
                    target.prepare()
        target.marker.write_text("{not json", encoding="utf-8")
        with self.assertRaisesRegex(
            simulation_overlay.PersistentInstanceInvalid, "cannot read"
        ):
            target.prepare()

    def test_instance_names_cannot_traverse_or_hide(self):
        for bad in ("", "../escape", "Lab-DC1", "-lead", "trail-", "a" * 33,
                    "with/slash", None):
            with self.subTest(bad=bad):
                self.assertFalse(
                    simulation_overlay.PersistentControllerInstance
                    .valid_instance_name(bad))
        for good in ("a", "lab-dc1", "a" * 32):
            with self.subTest(good=good):
                self.assertTrue(
                    simulation_overlay.PersistentControllerInstance
                    .valid_instance_name(good))

    # -- the acceptance canonical is protected ---------------------------
    def test_persistent_run_against_the_acceptance_state_is_refused(self):
        # Every spelling of the reserved acceptance state, plus a canonical in a
        # non-default location, plus a directory that merely holds the
        # acceptance artefacts. Each must fail closed before anything is
        # created, locked, or booted.
        reserved = simulation_overlay.acceptance_state_candidates()
        self.assertTrue(reserved)
        for candidate in reserved:
            with self.subTest(candidate=candidate):
                with self.assertRaises(
                        simulation_overlay.AcceptanceStateProtected):
                    self.instance(state=candidate).assert_separate()
                with self.assertRaises(
                        simulation_overlay.AcceptanceStateProtected):
                    self.instance(state=candidate / "inside").assert_separate()
                with self.assertRaises(
                        simulation_overlay.AcceptanceStateProtected):
                    self.instance(state=candidate.parent).assert_separate()
        # The parent of whichever canonical disk this operation was handed.
        with self.assertRaises(simulation_overlay.AcceptanceStateProtected):
            self.instance(state=self.canonical).assert_separate(self.disk)
        # And any directory carrying the disposable acceptance artefacts, even
        # when its path is not on the reserved list at all.
        stray = self.root / "stray"
        stray.mkdir()
        (stray / simulation_overlay.ACCEPTANCE_DISK_NAME).write_bytes(b"disk")
        with self.assertRaisesRegex(
            simulation_overlay.AcceptanceStateProtected, "acceptance artefact"
        ):
            self.instance(state=stray).assert_separate()

    def test_create_and_destroy_refuse_the_acceptance_state(self):
        self._patch_qemu_img()
        canonical_state = simulation_overlay.acceptance_state_candidates()[0]
        with self.assertRaises(simulation_overlay.AcceptanceStateProtected):
            self.instance(state=canonical_state).create(self.disk, self.vars)
        with self.assertRaises(simulation_overlay.AcceptanceStateProtected):
            self.instance(state=canonical_state).destroy("DESTROY lab-dc1")
        with self.assertRaises(simulation_overlay.AcceptanceStateProtected):
            self.instance(state=self.canonical).create(self.disk, self.vars)
        self.assertEqual(
            self.disk.read_bytes(),
            fake_image_tools.INSTALLED + b" canonical disk")

    def test_symlinked_persistent_state_is_refused(self):
        self.instances.mkdir()
        real = self.root / "elsewhere"
        real.mkdir()
        link = self.instances / "lab-dc1"
        link.symlink_to(real)
        with self.assertRaisesRegex(
            simulation_overlay.PersistentInstanceInvalid, "symlink"
        ):
            self.instance().assert_separate()

    # -- creation is fenced, the canonical is not mutated ----------------
    def test_creation_copies_the_canonical_under_the_strict_fence(self):
        calls = []

        def record(argv, **kwargs):
            calls.append(list(argv))
            return self._fake_qemu_img(argv, **kwargs)

        with mock.patch.object(
                simulation_overlay.subprocess, "run", side_effect=record):
            target = self.instance()
            marker = target.create(self.disk, self.vars)
        convert = next(argv for argv in calls if argv[1] == "convert")
        # An independent qcow2, never a backing-file reference to the canonical.
        self.assertEqual(convert[convert.index("-O") + 1], "qcow2")
        self.assertNotIn("-b", convert)
        self.assertNotIn(str(self.disk), convert)
        # Written into a dot-prefixed staging directory and renamed into place,
        # so an interrupted creation cannot leave a half-seeded instance.
        self.assertEqual(
            Path(convert[-1]).name, simulation_overlay.PERSISTENT_DISK_NAME)
        self.assertNotEqual(Path(convert[-1]).parent, target.state)
        self.assertTrue(Path(convert[-1]).parent.name.startswith(".lab-dc1."))
        self.assertEqual(
            marker["seeded_from"]["disk_sha256"],
            simulation_overlay.sha256(self.disk))
        self.assertEqual(marker["mode"], "persistent")
        self.assertEqual(
            self.disk.read_bytes(),
            fake_image_tools.INSTALLED + b" canonical disk")
        self.assertEqual(self.vars.read_bytes(), b"canonical vars")
        self.assertEqual(target.state.stat().st_mode & 0o777, 0o700)
        for path in (target.disk, target.vars, target.marker):
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)

    def test_creation_fails_and_leaves_nothing_when_the_canonical_moves(self):
        def moving(argv, **kwargs):
            result = self._fake_qemu_img(argv, **kwargs)
            if argv[1] == "convert":
                self.disk.write_bytes(b"tampered mid-copy")
            return result

        with mock.patch.object(
                simulation_overlay.subprocess, "run", side_effect=moving):
            target = self.instance()
            with self.assertRaisesRegex(
                RuntimeError, "canonical controller disk changed"
            ):
                target.create(self.disk, self.vars)
        self.assertFalse(target.state.exists())
        # No dot-prefixed staging directory is left behind either.
        self.assertEqual(
            [entry.name for entry in self.instances.iterdir()], [])

    def test_creation_refuses_a_state_directory_that_already_has_content(self):
        self._patch_qemu_img()
        target = self.instance()
        target.state.mkdir(parents=True)
        (target.state / "unrelated").write_bytes(b"keep me")
        with self.assertRaisesRegex(
            simulation_overlay.PersistentInstanceInvalid, "already exists"
        ):
            target.create(self.disk, self.vars)
        self.assertEqual(
            (target.state / "unrelated").read_bytes(), b"keep me")

    def test_creation_requires_a_valid_instance_name(self):
        self._patch_qemu_img()
        target = simulation_overlay.PersistentControllerInstance(
            self.instances / "x", instance="../escape", proc_root=self.proc)
        with self.assertRaisesRegex(
            simulation_overlay.PersistentInstanceInvalid, "instance name"
        ):
            target.create(self.disk, self.vars)

    # -- the source image must actually hold an installation -------------
    def test_creation_refuses_a_canonical_that_was_never_installed(self):
        """A blank canonical used to seed a worthless 80 GiB instance.

        ``_regular_file`` was the only content gate, so creation succeeded,
        the marker recorded the hash of an empty image, and the failure did
        not surface until the guest booted to a UEFI dead end.
        """
        self._patch_qemu_img()
        fake_image_tools.blank_image(self.disk, b" never installed")
        target = self.instance()
        with self.assertRaises(
                simulation_overlay.PersistentInstanceInvalid) as raised:
            target.create(self.disk, self.vars)
        message = str(raised.exception)
        self.assertIn("not an installed Controller image", message)
        self.assertIn("entirely unallocated", message)
        # It names the way out rather than leaving the operator guessing.
        self.assertIn("homelab-bootstrap-vm-install", message)
        # Nothing was created, and the canonical was not touched.
        self.assertFalse(target.state.exists())
        self.assertFalse(self.instances.exists())

    def test_creation_refuses_a_canonical_that_cannot_be_inspected(self):
        """An unreadable image is refused exactly like a provably blank one."""
        def broken(argv, **kwargs):
            if argv[0] == "qemu-img" and argv[1] == "info":
                return subprocess.CompletedProcess(argv, 0, "not json", "")
            return self._fake_qemu_img(argv, **kwargs)

        with mock.patch.object(
                simulation_overlay.subprocess, "run", side_effect=broken):
            with self.assertRaises(
                    simulation_overlay.PersistentInstanceInvalid):
                self.instance().create(self.disk, self.vars)
        self.assertFalse(self.instances.exists())

    # -- the provisioning-attempt record ---------------------------------
    def test_an_instance_reports_no_provisioning_attempt_until_one_is_made(self):
        target = self.seeded()
        self.assertIsNone(target.provisioning_attempted())

    def test_a_provisioning_attempt_is_recorded_once_and_survives_a_reread(self):
        """The first attempt's timestamp is the one that matters.

        A later attempt must not make the record look fresher than the state
        it describes, and the record must outlive the run that wrote it --
        that is the whole point of writing it before the run can finish.
        """
        target = self.seeded()
        first = target.record_provisioning_attempt()
        recorded = first[simulation_overlay.PERSISTENT_PROVISIONING_KEY]
        again = target.record_provisioning_attempt()
        self.assertEqual(
            recorded,
            again[simulation_overlay.PERSISTENT_PROVISIONING_KEY])
        reread = self.instance().provisioning_attempted()
        self.assertEqual(recorded, reread)
        self.assertIn("attempted_utc", reread)
        # A provisioning attempt is not a convergence: an instance that only
        # got that far still reports no directory at all.
        self.assertIsNone(target.convergence())

    def test_a_malformed_provisioning_record_fails_closed(self):
        target = self.seeded()
        marker = target.read_marker()
        marker[simulation_overlay.PERSISTENT_PROVISIONING_KEY] = {"note": "x"}
        target._write_marker(marker)
        with self.assertRaises(
                simulation_overlay.PersistentInstanceInvalid):
            self.instance().provisioning_attempted()

    # -- the durable account roster --------------------------------------
    RECORD = {
        "staged_utc": "2026-08-17T10:00:00+00:00",
        "roster_fingerprint": "0123456789abcdef",
        "roster_source": "contract X patched by overlay Y",
        "accounts": [
            {"contract_role": "standard_user", "role": "standard",
             "uidNumber": 10000, "gidNumber": 10513},
            {"contract_role": "daily_administrator", "role": "standard",
             "uidNumber": 10001, "gidNumber": 10513},
            {"contract_role": "domain_administrator", "role": "administrator",
             "uidNumber": 10002, "gidNumber": 10513},
        ],
    }

    def test_an_instance_reports_no_staged_roster_until_one_is_proven(self):
        target = self.seeded()
        self.assertIsNone(target.directory_accounts())
        self.assertIsNone(target.directory_accounts_attempted())

    def test_a_proven_roster_is_recorded_and_survives_a_reread(self):
        target = self.seeded()
        target.record_directory_accounts(dict(self.RECORD))
        reread = self.instance().directory_accounts()
        self.assertEqual(self.RECORD, reread)
        # It is additive: recording a roster does not disturb the convergence
        # record or the instance identity.
        marker = self.instance().read_marker()
        self.assertEqual("lab-dc1", marker["instance"])

    def test_a_durable_account_record_may_never_carry_an_account_name(self):
        """Real names are instance data (ADR 0046) and stay in the overlay.

        The marker lives beside the disk under ``build/``; a reader identifies
        an account by its CONTRACT ROLE and proves the roster with the
        fingerprint, which is fixed-width and names nobody.
        """
        target = self.seeded()
        named = json.loads(json.dumps(self.RECORD))
        named["accounts"][0]["name"] = "person-a"
        with self.assertRaisesRegex(
                simulation_overlay.PersistentInstanceInvalid,
                "must not carry an account name"):
            target.record_directory_accounts(named)
        self.assertIsNone(self.instance().directory_accounts())

    def test_a_malformed_durable_account_record_fails_closed(self):
        target = self.seeded()
        for broken, expected in (
            ("not an object", "not an object"),
            ({"roster_fingerprint": "x", "accounts": [{"contract_role": "a"}]},
             "no staged_utc"),
            ({"staged_utc": "t", "accounts": [{"contract_role": "a"}]},
             "no roster fingerprint"),
            ({"staged_utc": "t", "roster_fingerprint": "x", "accounts": []},
             "names no contract roles"),
            ({"staged_utc": "t", "roster_fingerprint": "x",
              "accounts": [{"uidNumber": 10000}]},
             "no contract role"),
        ):
            with self.subTest(record=expected):
                with self.assertRaisesRegex(
                        simulation_overlay.PersistentInstanceInvalid,
                        expected):
                    target.record_directory_accounts(broken)
        # ...and a marker that already holds a bad record is refused on read,
        # rather than reported as a staged roster.
        marker = target.read_marker()
        marker[simulation_overlay.PERSISTENT_ACCOUNTS_KEY] = {"note": "x"}
        target._write_marker(marker)
        with self.assertRaises(
                simulation_overlay.PersistentInstanceInvalid):
            self.instance().directory_accounts()

    def test_the_first_staging_attempt_is_the_one_that_is_kept(self):
        target = self.seeded()
        first = target.record_directory_accounts_attempt()
        recorded = first[simulation_overlay.PERSISTENT_ACCOUNTS_ATTEMPT_KEY]
        again = target.record_directory_accounts_attempt()
        self.assertEqual(
            recorded,
            again[simulation_overlay.PERSISTENT_ACCOUNTS_ATTEMPT_KEY])
        reread = self.instance().directory_accounts_attempted()
        self.assertEqual(recorded, reread)
        self.assertIn("attempted_utc", reread)
        # An attempt is not a staged roster: an instance that only got that
        # far still reports none, which is what makes the next run refuse.
        self.assertIsNone(target.directory_accounts())

    def test_a_malformed_staging_attempt_record_fails_closed(self):
        target = self.seeded()
        marker = target.read_marker()
        marker[simulation_overlay.PERSISTENT_ACCOUNTS_ATTEMPT_KEY] = {"n": 1}
        target._write_marker(marker)
        with self.assertRaises(
                simulation_overlay.PersistentInstanceInvalid):
            self.instance().directory_accounts_attempted()

    # -- exclusivity -----------------------------------------------------
    def test_bring_up_takes_an_exclusive_lock_in_its_own_directory(self):
        target = self.seeded()
        target.prepare()
        self.assertEqual(
            target.lock_path,
            target.state / simulation_overlay.LOCK_NAME)
        self.assertTrue(target.lock_path.is_file())
        # A running instance holds its own lock only: it does not hold the
        # canonical acceptance lock, so it can neither block an acceptance run
        # nor be blocked by one.
        guard = simulation_overlay.ControllerOverlay(
            self.disk, self.vars, run_root=self.root / "guard",
            proc_root=self.proc)
        guard.prepare()
        guard.close()
        second = self.instance()
        with self.assertRaisesRegex(
            simulation_overlay.PersistentInstanceInUse, "already running"
        ):
            second.prepare()
        target.close()
        # After close the same instance can be brought up again.
        target.prepare()
        target.close()

    def test_bring_up_refuses_a_disk_another_process_holds_open(self):
        target = self.seeded()
        descriptors = self.proc / "5312" / "fd"
        descriptors.mkdir(parents=True)
        (self.proc / "5312" / "comm").write_text("qemu-system-x86\n")
        (descriptors / "4").symlink_to(target.disk)
        with self.assertRaisesRegex(
            simulation_overlay.PersistentInstanceInUse,
            r"5312 \(qemu-system-x86\)",
        ):
            target.prepare()
        # The lock was released again, so a later legitimate run is not wedged.
        (descriptors / "4").unlink()
        target.prepare()
        target.close()

    def test_close_keeps_the_lock_while_the_disk_is_still_open(self):
        target = self.seeded()
        target.prepare()
        descriptors = self.proc / "77" / "fd"
        descriptors.mkdir(parents=True)
        (descriptors / "3").symlink_to(target.disk)
        with self.assertRaises(simulation_overlay.PersistentInstanceInUse):
            target.close()
        self.assertTrue(target.disk.is_file())
        (descriptors / "3").unlink()
        target.close()

    def test_bring_up_requires_private_owner_only_state(self):
        target = self.seeded()
        target.disk.chmod(0o644)
        with self.assertRaisesRegex(
            simulation_overlay.PersistentInstanceInvalid,
            "must not be group/world accessible",
        ):
            target.prepare()

    # -- deliberately no hash fence, and nothing is deleted --------------
    def test_the_instance_disk_may_change_and_is_never_removed(self):
        target = self.seeded()
        target.prepare()
        target.disk.write_bytes(b"a domain was provisioned here")
        target.vars.write_bytes(b"firmware variables moved too")
        target.close()
        self.assertEqual(
            target.disk.read_bytes(), b"a domain was provisioned here")
        self.assertTrue(target.marker.is_file())
        # ... and the next bring-up accepts the changed disk without complaint.
        target.prepare()
        target.close()

    def test_verify_canonical_is_a_tripwire_not_a_silent_pass(self):
        # Acceptance runners call verify_canonical before writing a pass
        # receipt. If a persistent instance were ever wired into one of those
        # paths it must stop loudly rather than record a fence it never had.
        target = self.seeded()
        with self.assertRaisesRegex(
            simulation_overlay.PersistentInstanceInvalid, "no canonical hash fence"
        ):
            target.verify_canonical()

    # -- the convergence record ------------------------------------------
    def test_a_seeded_instance_reports_no_directory_until_it_is_converged(self):
        # Seeding copies an installed Controller, which has no domain at all.
        # Nothing may read that as a directory server.
        target = self.seeded()
        self.assertIsNone(target.convergence())
        self.assertNotIn(
            simulation_overlay.PERSISTENT_CONVERGENCE_KEY,
            target.read_marker())

    def test_a_recorded_convergence_reports_the_durable_domain_sid(self):
        target = self.seeded()
        record = {
            "converged_utc": "2026-08-14T20:00:00+00:00",
            "realm": "AD.FACTORY.TEST",
            "domain_sid": "S-1-5-21-11-22-33",
        }
        target.record_convergence(record)
        # Readable by a fresh object, so the claim lives in durable state and
        # not in this process.
        again = self.instance()
        self.assertEqual(again.convergence()["domain_sid"], "S-1-5-21-11-22-33")
        # The rest of the marker is untouched: still the same instance, still
        # unfenced, still seeded from the same canonical digest.
        marker = again.read_marker()
        self.assertEqual(marker["instance"], "lab-dc1")
        self.assertEqual(
            marker["seeded_from"]["disk_sha256"],
            simulation_overlay.sha256(self.disk))

    def test_a_convergence_record_without_a_canonical_sid_is_refused(self):
        target = self.seeded()
        for bad in (
            {},
            {"converged_utc": ""},
            {"converged_utc": "now", "domain_sid": "S-1-5-32-544"},
            {"converged_utc": "now", "domain_sid": "not a sid"},
            {"converged_utc": "now", "domain_sid": 1234},
            "converged",
        ):
            with self.subTest(bad=bad):
                with self.assertRaises(
                        simulation_overlay.PersistentInstanceInvalid):
                    target.record_convergence(bad)
                self.assertIsNone(target.convergence())
        # A missing SID is allowed and explicit: convergence happened, the SID
        # could not be read. It must never be silently invented.
        target.record_convergence(
            {"converged_utc": "now", "domain_sid": None})
        self.assertIsNone(target.convergence()["domain_sid"])

    def test_an_interrupted_record_leaves_the_instance_unconverged(self):
        # The failure that matters: a kill between staging the new marker and
        # renaming it. The instance must keep reporting no directory rather
        # than a half-written one, and must stay usable.
        target = self.seeded()
        record = {"converged_utc": "2026-08-14T20:00:00+00:00",
                  "domain_sid": "S-1-5-21-1-2-3"}
        before = target.marker.read_text(encoding="utf-8")
        with mock.patch.object(
                simulation_overlay.os, "replace",
                side_effect=OSError("interrupted")):
            with self.assertRaises(OSError):
                target.record_convergence(record)
        self.assertEqual(target.marker.read_text(encoding="utf-8"), before)
        self.assertIsNone(target.convergence())
        self.assertFalse(
            (target.state
             / simulation_overlay.PERSISTENT_MARKER_STAGING_NAME).exists())
        # Still a valid instance afterwards, and the next attempt succeeds.
        target.record_convergence(record)
        self.assertEqual(
            target.convergence()["domain_sid"], "S-1-5-21-1-2-3")

    def test_a_stranded_staging_file_neither_converges_nor_blocks_destroy(self):
        # A staging file left by a killed rewrite is truncated by the next one
        # and swept by destroy, so it can never look like a convergence and can
        # never make an instance permanently un-erasable.
        target = self.seeded()
        staging = (target.state
                   / simulation_overlay.PERSISTENT_MARKER_STAGING_NAME)
        staging.write_text('{"schema": 1, "mode": "persist', encoding="utf-8")
        self.assertIsNone(target.convergence())
        target.record_convergence(
            {"converged_utc": "now", "domain_sid": "S-1-5-21-9-9-9"})
        self.assertFalse(staging.exists())
        staging.write_text("half", encoding="utf-8")
        target.destroy("DESTROY lab-dc1")
        self.assertFalse(target.state.exists())

    def test_a_marker_rewrite_is_private_and_refuses_a_planted_symlink(self):
        target = self.seeded()
        staging = (target.state
                   / simulation_overlay.PERSISTENT_MARKER_STAGING_NAME)
        elsewhere = self.root / "elsewhere"
        staging.symlink_to(elsewhere)
        with self.assertRaises(OSError):
            target.record_convergence(
                {"converged_utc": "now", "domain_sid": "S-1-5-21-1-1-1"})
        self.assertFalse(elsewhere.exists())
        self.assertIsNone(target.convergence())
        staging.unlink()
        target.record_convergence(
            {"converged_utc": "now", "domain_sid": "S-1-5-21-1-1-1"})
        self.assertEqual(target.marker.stat().st_mode & 0o777, 0o600)

    # -- teardown --------------------------------------------------------
    def test_destroy_requires_the_exact_instance_named_confirmation(self):
        target = self.seeded()
        for wrong in (None, "", "DESTROY", "destroy lab-dc1",
                      "DESTROY other", "lab-dc1"):
            with self.subTest(wrong=wrong):
                with self.assertRaisesRegex(
                    simulation_overlay.PersistentInstanceInvalid,
                    "DESTROY lab-dc1",
                ):
                    target.destroy(wrong)
                self.assertTrue(target.disk.is_file())
        self.assertEqual(target.destroy("DESTROY lab-dc1"), str(target.state))
        self.assertFalse(target.state.exists())

    def test_destroy_refuses_unexpected_files_and_a_running_instance(self):
        target = self.seeded()
        stray = target.state / "operator-notes"
        stray.write_bytes(b"not ours")
        with self.assertRaisesRegex(
            simulation_overlay.PersistentInstanceInvalid, "unexpected files"
        ):
            target.destroy("DESTROY lab-dc1")
        self.assertTrue(target.disk.is_file())
        stray.unlink()
        holder = self.instance()
        holder.prepare()
        with self.assertRaisesRegex(
            simulation_overlay.PersistentInstanceInUse, "already running"
        ):
            target.destroy("DESTROY lab-dc1")
        self.assertTrue(target.disk.is_file())
        holder.close()
        target.destroy("DESTROY lab-dc1")
        self.assertFalse(target.state.exists())

    # -- the disposable path is unchanged --------------------------------
    def test_disposable_overlay_still_fences_and_deletes_its_state(self):
        # The persistent relaxation is scoped to the persistent class: the
        # disposable guard keeps hashing the canonical and removing its run
        # state, and it never learns the persistent filenames.
        self._patch_qemu_img()
        overlay = simulation_overlay.ControllerOverlay(
            self.disk, self.vars, run_root=self.root / "run",
            proc_root=self.proc)
        overlay.prepare()
        self.assertEqual(
            overlay.canonical_disk_sha256,
            simulation_overlay.sha256(self.disk))
        self.assertNotIn(
            simulation_overlay.PERSISTENT_DISK_NAME, str(overlay.disk))
        self.disk.write_bytes(b"tampered")
        with self.assertRaisesRegex(RuntimeError, "changed during simulation"):
            overlay.close()
        self.assertFalse(overlay.disk.exists())
        self.assertFalse(overlay.vars.exists())

    def test_persistent_and_acceptance_filenames_are_disjoint(self):
        self.assertNotEqual(
            simulation_overlay.PERSISTENT_DISK_NAME,
            simulation_overlay.ACCEPTANCE_DISK_NAME)
        self.assertNotEqual(
            simulation_overlay.PERSISTENT_MARKER_NAME,
            simulation_overlay.ACCEPTANCE_MANIFEST_NAME)


if __name__ == "__main__":
    unittest.main()
