"""Safety tests for disposable controller simulation state."""

import subprocess
import sys
import tempfile
import unittest
import os
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "vm"))

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


if __name__ == "__main__":
    unittest.main()
