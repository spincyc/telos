"""Contracts for the bounded private Arch-second installation lifecycle."""

import hashlib
import json
import os
from pathlib import Path
import re
import tempfile
import threading
import time
import unittest
from unittest import mock

from homelab.vm import arch_install_run
from homelab.vm.arch_install_prepare import (
    DISK_BYTES, INSTALLER_NAME, OVERLAY_NAME, VARS_NAME, VERIFY_NAME)


CONST = "c" * 64

# The runner echoes ``printf '\nTELOS_ARCH_SHELL_READY_<token>=%s\n' ready`` to
# prove the shell is live; the fake guest greps this command out of its stdin,
# reconstructs the token, and prints the resolved ``...=ready`` sentinel back.
_READY_PROBE = re.compile(rb"TELOS_ARCH_SHELL_READY_([0-9a-f]+)=%s")


def _kernel_noise(stamp: str) -> bytes:
    """A kernel audit/printk line like the ones that share archiso's ttyS0."""
    return (
        f"[  {stamp}.807034] audit: type=1131 "
        f"audit(1700000000.{stamp}:{stamp}): pid=1 uid=0 "
        f"msg='unit=telos comm=\"systemd\" exe=\"/usr/lib/systemd/systemd\"'\n"
    ).encode("ascii")


def _await_ready_probe(stdin: "_Recorder", spins: int = 5000) -> bytes | None:
    """Spin until the runner has echoed its readiness probe; return the token."""
    for _ in range(spins):
        match = _READY_PROBE.search(stdin.data)
        if match:
            return match.group(1)
        time.sleep(0.001)
    return None


class _FakeQmp:
    """Record QMP execute() calls; optionally fail closed like the real client."""

    def __init__(self, *, fail: bool = False) -> None:
        self.calls: list[tuple] = []
        self.fail = fail
        self.closed = False

    def execute(self, command, arguments=None, *, timeout=None):
        self.calls.append((command, arguments, timeout))
        if self.fail:
            raise arch_install_run.WindowsGuiError("device_add refused")
        return {}

    def close(self):
        self.closed = True


class _Recorder:
    """A stdin sink that timestamps writes so ordering can be asserted."""

    def __init__(self, events: list) -> None:
        self.events = events
        self.data = bytearray()

    def write(self, payload: bytes) -> None:
        self.events.append(("write", bytes(payload)))
        self.data.extend(payload)

    def flush(self) -> None:
        pass


class _Fd:
    def __init__(self, fd: int) -> None:
        self._fd = fd

    def fileno(self) -> int:
        return self._fd


class _FakeProcess:
    def __init__(self, read_fd: int, stdin: _Recorder) -> None:
        self.stdout = _Fd(read_fd)
        self.stdin = stdin
        self.returncode = None

    def poll(self):
        return self.returncode


def _digest(command):
    return hashlib.sha256(
        json.dumps(command, separators=(",", ":")).encode()).hexdigest()


GOOD_SERIAL = "\n".join((
    'BdsDxe: loading Boot0005 "UEFI PXEv4 (MAC:525400311212)"',
    'BdsDxe: starting Boot0005 "UEFI PXEv4 (MAC:525400311212)"',
    "TELOS IPXE PRE-BOOT: selected Arch kernel and initramfs loaded",
    "Welcome to Arch Linux",
    "[root@archiso ~]# echo TELOS ARCH INSTALL BEGIN",
    "TELOS ARCH INSTALL BEGIN",
    "TELOS ARCH DISK ATTACHED serial=TELOS-WIN-0001",
    "PASS: Windows-first GPT matches the approved Arch install contract",
    "Arch installed; Windows partitions and filesystems were not modified.",
    "TELOS ARCH INSTALL COMPLETE",
    "Boot0000* Windows Boot Manager",
    "Boot0001* Linux Boot Manager",
    "/mnt/boot/loader/loader.conf:default auto-windows",
))


class ArchInstallRunTests(unittest.TestCase):
    def bundle(self, root: Path) -> Path:
        root.mkdir(mode=0o700)
        (root / OVERLAY_NAME).write_bytes(b"overlay")
        (root / VARS_NAME).write_bytes(b"vars")
        (root / VERIFY_NAME).write_text("verify")
        (root / INSTALLER_NAME).write_text("installer")
        backing = root / "windows-base.qcow2"
        backing.write_bytes(b"base")
        overlay = root / OVERLAY_NAME
        command = [
            "qemu",
            "-qmp", "unix:/tmp/telos-arch-abc/arch.qmp,server=on,wait=off",
            "-boot", "order=n,menu=off",
            "-drive",
            f"if=none,id=osdisk,format=qcow2,cache=none,file={overlay.resolve()}",
            "-netdev", "socket,id=factory,connect=127.0.0.1:31415",
            "-device", "e1000e,netdev=factory,mac=52:54:00:31:12:12",
        ]
        authorization = {
            "schema": 1,
            "authorization": {
                "release_version": "20260727.005",
                "release_manifest_sha256": "a" * 64,
                "disk_serial": "TELOS-WIN-0001",
                "guest_disk": "/dev/nvme0n1",
                "hostname": "telos-workstation",
                "overlay": {
                    "path": str(overlay.resolve()), "format": "qcow2",
                    "backing": str(backing.resolve()), "sha256": CONST,
                },
                "backing_windows_disk": {
                    "path": str(backing.resolve()), "sha256": CONST,
                    "virtual_size": DISK_BYTES,
                },
                "expected_sizes_mib": [1024, 16, 186098, 72956, 2048],
                "qemu_argv_sha256": _digest(command),
                "layout": {},
            },
            "guest_inputs": [
                {"name": INSTALLER_NAME, "sha256": CONST},
                {"name": VERIFY_NAME, "sha256": CONST},
            ],
        }
        (root / "authorization.json").write_text(json.dumps(authorization))
        (root / "qemu-command.json").write_text(
            json.dumps({"schema": 1, "argv": command}))
        return root

    def _overlay(self, backing: Path):
        return {
            "path": "unused", "format": "qcow2",
            "backing": str(backing.resolve()), "sha256": CONST,
        }

    def test_default_is_dry_run(self):
        with tempfile.TemporaryDirectory() as temporary:
            bundle = self.bundle(Path(temporary) / "bundle")
            backing = bundle / "windows-base.qcow2"
            with mock.patch.object(
                    arch_install_run, "inspect_overlay",
                    return_value=self._overlay(backing)), \
                    mock.patch.object(
                        arch_install_run, "sha256", return_value=CONST), \
                    mock.patch.object(
                        arch_install_run, "audit_arch_boot_boundary"):
                self.assertEqual(arch_install_run.run(
                    bundle, controller_state=Path("/state"),
                    releases=Path("/pxe"), seed_iso=Path("/seed.iso"),
                    duration=60, apply=False), 0)
            self.assertFalse((bundle / "evidence").exists())

    def test_duration_bounds_are_enforced(self):
        with tempfile.TemporaryDirectory() as temporary:
            bundle = self.bundle(Path(temporary) / "bundle")
            with self.assertRaisesRegex(RuntimeError, "duration"):
                arch_install_run.run(
                    bundle, controller_state=Path("/state"),
                    releases=Path("/pxe"), seed_iso=Path("/seed.iso"),
                    duration=5, apply=True)

    def test_qmp_socket_path_is_recovered_from_the_authorized_argv(self):
        path = arch_install_run._qmp_socket_path([
            "qemu", "-qmp", "unix:/tmp/telos-arch-abc/arch.qmp,"
            "server=on,wait=off",
        ])
        self.assertEqual(Path("/tmp/telos-arch-abc/arch.qmp"), path)
        for argv in (
            ["qemu"],
            ["qemu", "-qmp"],
            ["qemu", "-qmp", "tcp:127.0.0.1:4444,server=on"],
            ["qemu", "-qmp", "unix:/tmp/x.qmp"],
            ["qemu", "-qmp", "unix:relative.qmp,server=on"],
            ["qemu", "-qmp", "unix:/" + "a" * 120 + ",server=on"],
        ):
            with self.subTest(argv=argv):
                with self.assertRaises(RuntimeError):
                    arch_install_run._qmp_socket_path(argv)

    def test_switch_port_is_recovered_from_the_authorized_argv(self):
        self.assertEqual(31415, arch_install_run._switch_port([
            "qemu", "-netdev", "socket,id=factory,connect=127.0.0.1:31415",
        ]))
        with self.assertRaises(RuntimeError):
            arch_install_run._switch_port(["qemu", "-netdev", "user,id=n0"])

    def test_lifecycle_accepts_a_windows_preserving_transcript(self):
        arch_install_run._validate_lifecycle(GOOD_SERIAL)

    def test_lifecycle_rejects_more_than_one_pxe_boot(self):
        doubled = GOOD_SERIAL + (
            '\nBdsDxe: starting Boot0006 "UEFI PXEv4 (MAC:525400311212)"')
        with self.assertRaisesRegex(RuntimeError, "exactly one PXE"):
            arch_install_run._validate_lifecycle(doubled)

    def test_lifecycle_rejects_windows_partition_loss(self):
        transcript = "\n".join((
            'BdsDxe: starting Boot0005 "UEFI PXEv4 (MAC:525400311212)"',
            "Welcome to Arch Linux",
            "TELOS ARCH INSTALL BEGIN",
            "partition 3 (windows) filesystem mismatch: "
            "expected ntfs, found unformatted",
            "InstallContractError",
            "TELOS ARCH INSTALL FAIL rc=1",
        ))
        with self.assertRaisesRegex(RuntimeError, "failure"):
            arch_install_run._validate_lifecycle(transcript)

    def test_lifecycle_rejects_missing_preservation_marker(self):
        transcript = GOOD_SERIAL.replace(
            "Arch installed; Windows partitions and filesystems "
            "were not modified.", "")
        with self.assertRaisesRegex(RuntimeError, "markers missing"):
            arch_install_run._validate_lifecycle(transcript)

    def test_bundle_rejects_group_or_world_access(self):
        with tempfile.TemporaryDirectory() as temporary:
            bundle = self.bundle(Path(temporary) / "bundle")
            bundle.chmod(0o755)
            backing = bundle / "windows-base.qcow2"
            with mock.patch.object(
                    arch_install_run, "inspect_overlay",
                    return_value=self._overlay(backing)), \
                    mock.patch.object(
                        arch_install_run, "sha256", return_value=CONST), \
                    mock.patch.object(
                        arch_install_run, "audit_arch_boot_boundary"):
                with self.assertRaisesRegex(RuntimeError, "private"):
                    arch_install_run._bundle(bundle)

    def test_bundle_rejects_symlink(self):
        with tempfile.TemporaryDirectory() as temporary:
            temporary = Path(temporary)
            target = self.bundle(temporary / "target")
            link = temporary / "bundle"
            link.symlink_to(target, target_is_directory=True)
            with self.assertRaisesRegex(RuntimeError, "non-symlink"):
                arch_install_run._bundle(link)

    def test_bundle_rejects_changed_command_digest(self):
        with tempfile.TemporaryDirectory() as temporary:
            bundle = self.bundle(Path(temporary) / "bundle")
            authorization = json.loads(
                (bundle / "authorization.json").read_text())
            authorization["authorization"]["qemu_argv_sha256"] = "0" * 64
            (bundle / "authorization.json").write_text(
                json.dumps(authorization))
            backing = bundle / "windows-base.qcow2"
            with mock.patch.object(
                    arch_install_run, "inspect_overlay",
                    return_value=self._overlay(backing)), \
                    mock.patch.object(
                        arch_install_run, "sha256", return_value=CONST), \
                    mock.patch.object(
                        arch_install_run, "audit_arch_boot_boundary"):
                with self.assertRaisesRegex(RuntimeError, "command differs"):
                    arch_install_run._bundle(bundle)

    def test_bundle_rejects_backing_disk_swap(self):
        with tempfile.TemporaryDirectory() as temporary:
            bundle = self.bundle(Path(temporary) / "bundle")
            other = Path(temporary) / "other.qcow2"
            other.write_bytes(b"other")
            with mock.patch.object(
                    arch_install_run, "inspect_overlay",
                    return_value=self._overlay(other)), \
                    mock.patch.object(
                        arch_install_run, "sha256", return_value=CONST), \
                    mock.patch.object(
                        arch_install_run, "audit_arch_boot_boundary"):
                with self.assertRaisesRegex(RuntimeError, "different disk"):
                    arch_install_run._bundle(bundle)

    def test_bundle_rejects_altered_persistent_windows_disk(self):
        with tempfile.TemporaryDirectory() as temporary:
            bundle = self.bundle(Path(temporary) / "bundle")
            backing = bundle / "windows-base.qcow2"

            def by_path(path):
                return "z" * 64 if Path(path) == backing else CONST

            with mock.patch.object(
                    arch_install_run, "inspect_overlay",
                    return_value=self._overlay(backing)), \
                    mock.patch.object(
                        arch_install_run, "sha256", side_effect=by_path), \
                    mock.patch.object(
                        arch_install_run, "audit_arch_boot_boundary"):
                with self.assertRaisesRegex(
                        RuntimeError, "persistent Windows disk differs"):
                    arch_install_run._bundle(bundle)

    def test_lifecycle_requires_the_post_attach_disk_marker(self):
        transcript = GOOD_SERIAL.replace(
            "TELOS ARCH DISK ATTACHED serial=TELOS-WIN-0001", "")
        with self.assertRaisesRegex(RuntimeError, "markers missing"):
            arch_install_run._validate_lifecycle(transcript)

    def test_lifecycle_rejects_attach_before_archiso_is_live(self):
        # A disk-serial detection that precedes the live environment implies a
        # cold-plugged target rather than a post-boot hot-attach.
        transcript = "\n".join((
            'BdsDxe: starting Boot0005 "UEFI PXEv4 (MAC:525400311212)"',
            "TELOS ARCH DISK ATTACHED serial=TELOS-WIN-0001",
            "Welcome to Arch Linux",
            "TELOS ARCH INSTALL BEGIN",
            "PASS: Windows-first GPT matches the approved Arch install contract",
            "Arch installed; Windows partitions and filesystems "
            "were not modified.",
            "TELOS ARCH INSTALL COMPLETE",
            "Boot0000* Windows Boot Manager",
            "Boot0001* Linux Boot Manager",
            "/mnt/boot/loader/loader.conf:default auto-windows",
        ))
        with self.assertRaisesRegex(RuntimeError, "before archiso was live"):
            arch_install_run._validate_lifecycle(transcript)

    def test_hot_attach_adds_nvme_with_the_authorized_serial(self):
        qmp = _FakeQmp()
        arch_install_run.hot_attach_disk(qmp, "TELOS-WIN-0001")
        self.assertEqual(len(qmp.calls), 1)
        command, arguments, timeout = qmp.calls[0]
        self.assertEqual(command, "device_add")
        self.assertEqual(arguments["driver"], "nvme")
        self.assertEqual(arguments["drive"], "osdisk")
        self.assertEqual(arguments["serial"], "TELOS-WIN-0001")
        self.assertEqual(arguments["id"], "osdisk-nvme")
        self.assertIsNotNone(timeout)
        self.assertGreater(timeout, 0)

    def test_hot_attach_fails_closed_when_qmp_refuses(self):
        qmp = _FakeQmp(fail=True)
        with self.assertRaisesRegex(RuntimeError, "hot-attach failed"):
            arch_install_run.hot_attach_disk(qmp, "TELOS-WIN-0001")

    def test_drive_installer_hot_attaches_before_running_the_installer(self):
        read_fd, write_fd = os.pipe()
        events: list = []
        stdin = _Recorder(events)
        process = _FakeProcess(read_fd, stdin)
        attach_calls: list = []

        def attach() -> None:
            events.append(("attach", None))
            attach_calls.append(1)

        # archiso reaches its root prompt first; the installer only runs after
        # the readiness sentinel is proven despite interleaved kernel spam.
        os.write(write_fd, b"[root@archiso ~]# ")

        def feeder() -> None:
            token = _await_ready_probe(stdin)
            # The prompt is buried under kernel audit lines, then the resolved
            # sentinel arrives, then more spam: an end-anchored matcher fails.
            os.write(write_fd, _kernel_noise("900"))
            os.write(write_fd, b"TELOS_ARCH_SHELL_READY_" + token + b"=ready\n")
            os.write(write_fd, _kernel_noise("901"))
            for _ in range(5000):
                if attach_calls and b"bash /root/arch-install.sh" in stdin.data:
                    break
                time.sleep(0.001)
            os.write(write_fd, _kernel_noise("902"))
            os.write(write_fd, b"\nTELOS ARCH INSTALL COMPLETE\n")
            os.close(write_fd)

        worker = threading.Thread(target=feeder)
        worker.start()
        try:
            with tempfile.TemporaryDirectory() as temporary:
                capture = Path(temporary) / "serial.log"
                transcript = arch_install_run.drive_installer(
                    process, capture, verify_script="verify",
                    installer_script="installer", serial="TELOS-WIN-0001",
                    attach=attach, timeout=10)
        finally:
            worker.join()
            os.close(read_fd)
        self.assertEqual(attach_calls, [1])
        # The readiness probe is echoed before the hot-attach, and the attach
        # precedes every installer byte written to the guest shell.
        probe_index = next(
            index for index, (kind, payload) in enumerate(events)
            if kind == "write" and b"TELOS_ARCH_SHELL_READY_" in payload)
        attach_index = events.index(("attach", None))
        installer_index = next(
            index for index, (kind, payload) in enumerate(events)
            if kind == "write" and b"bash /root/arch-install.sh" in payload)
        self.assertLess(probe_index, attach_index)
        self.assertLess(attach_index, installer_index)
        self.assertIn(b"bash /root/arch-install.sh", stdin.data)
        self.assertIn(b"lsblk -dno SERIAL", stdin.data)
        self.assertIn("TELOS ARCH INSTALL COMPLETE", transcript)

    def test_drive_installer_answers_the_getty_login_then_hot_attaches(self):
        read_fd, write_fd = os.pipe()
        events: list = []
        stdin = _Recorder(events)
        process = _FakeProcess(read_fd, stdin)
        attach_calls: list = []

        def attach() -> None:
            events.append(("attach", None))
            attach_calls.append(1)

        # The PXE archiso stops at a getty login prompt, not a root shell.
        os.write(
            write_fd, b"Arch Linux 7.0.14-arch1-1 (ttyS0)\n\narchiso login: ")

        def feeder() -> None:
            # Once the runner answers the login with `root`, the getty echoes it
            # and drops to the passwordless root shell; the runner then echoes a
            # readiness probe, which the shell answers with the sentinel.
            for _ in range(5000):
                if b"root\n" in stdin.data:
                    break
                time.sleep(0.001)
            os.write(write_fd, b"root\n[root@archiso ~]# ")
            token = _await_ready_probe(stdin)
            os.write(write_fd, _kernel_noise("900"))
            os.write(write_fd, b"TELOS_ARCH_SHELL_READY_" + token + b"=ready\n")
            os.write(write_fd, _kernel_noise("901"))
            for _ in range(5000):
                if attach_calls and b"bash /root/arch-install.sh" in stdin.data:
                    break
                time.sleep(0.001)
            os.write(write_fd, b"\nTELOS ARCH INSTALL COMPLETE\n")
            os.close(write_fd)

        worker = threading.Thread(target=feeder)
        worker.start()
        try:
            with tempfile.TemporaryDirectory() as temporary:
                capture = Path(temporary) / "serial.log"
                transcript = arch_install_run.drive_installer(
                    process, capture, verify_script="verify",
                    installer_script="installer", serial="TELOS-WIN-0001",
                    attach=attach, timeout=10)
        finally:
            worker.join()
            os.close(read_fd)
        self.assertEqual(attach_calls, [1])
        # The very first byte sent to the guest is the login answer.
        writes = [payload for kind, payload in events if kind == "write"]
        self.assertEqual(writes[0], b"root\n")
        # Ordering: login `root` -> hot-attach -> installer bytes.
        login_index = next(
            index for index, (kind, payload) in enumerate(events)
            if kind == "write" and payload == b"root\n")
        probe_index = next(
            index for index, (kind, payload) in enumerate(events)
            if kind == "write" and b"TELOS_ARCH_SHELL_READY_" in payload)
        attach_index = events.index(("attach", None))
        installer_index = next(
            index for index, (kind, payload) in enumerate(events)
            if kind == "write" and b"bash /root/arch-install.sh" in payload)
        # Ordering: login `root` -> readiness probe -> hot-attach -> installer.
        self.assertLess(login_index, probe_index)
        self.assertLess(probe_index, attach_index)
        self.assertLess(attach_index, installer_index)
        self.assertIn(b"lsblk -dno SERIAL", stdin.data)
        self.assertIn("TELOS ARCH INSTALL COMPLETE", transcript)

    def test_drive_installer_fails_closed_when_login_never_yields_a_shell(self):
        read_fd, write_fd = os.pipe()
        events: list = []
        stdin = _Recorder(events)
        process = _FakeProcess(read_fd, stdin)

        def attach() -> None:
            events.append(("attach", None))

        # A getty login that is answered but never produces a root shell.
        os.write(write_fd, b"archiso login: ")
        try:
            with tempfile.TemporaryDirectory() as temporary:
                capture = Path(temporary) / "serial.log"
                with self.assertRaisesRegex(
                        RuntimeError, "root shell was never reached"):
                    arch_install_run.drive_installer(
                        process, capture, verify_script="verify",
                        installer_script="installer", serial="TELOS-WIN-0001",
                        attach=attach, timeout=1)
        finally:
            os.close(write_fd)
            os.close(read_fd)
        # `root` was sent to answer the login, but no destructive step ran: no
        # hot-attach and no installer bytes reached the guest.
        self.assertIn(("write", b"root\n"), events)
        self.assertNotIn(("attach", None), events)
        self.assertNotIn(b"bash /root/arch-install.sh", stdin.data)

    def test_drive_installer_propagates_a_hot_attach_failure(self):
        read_fd, write_fd = os.pipe()
        stdin = _Recorder([])
        process = _FakeProcess(read_fd, stdin)

        def attach() -> None:
            raise RuntimeError("install-target NVMe hot-attach failed")

        os.write(write_fd, b"[root@archiso ~]# ")

        def feeder() -> None:
            # The sentinel confirms readiness, so the runner reaches the attach
            # step whose failure must propagate for fail-closed teardown.
            token = _await_ready_probe(stdin)
            if token is not None:
                os.write(
                    write_fd, b"TELOS_ARCH_SHELL_READY_" + token + b"=ready\n")

        worker = threading.Thread(target=feeder)
        worker.start()
        try:
            with tempfile.TemporaryDirectory() as temporary:
                capture = Path(temporary) / "serial.log"
                with self.assertRaisesRegex(RuntimeError, "hot-attach failed"):
                    arch_install_run.drive_installer(
                        process, capture, verify_script="verify",
                        installer_script="installer", serial="TELOS-WIN-0001",
                        attach=attach, timeout=10)
        finally:
            worker.join()
            os.close(write_fd)
            os.close(read_fd)

    def test_drive_installer_reaches_readiness_when_the_prompt_is_buried(self):
        # The core regression: the root prompt is never the last bytes because
        # kernel audit lines keep printing to the shared ttyS0. An end-anchored
        # matcher would never fire, but the sentinel handshake still proceeds.
        read_fd, write_fd = os.pipe()
        events: list = []
        stdin = _Recorder(events)
        process = _FakeProcess(read_fd, stdin)
        attach_calls: list = []

        def attach() -> None:
            events.append(("attach", None))
            attach_calls.append(1)

        os.write(write_fd, b"archiso login: ")

        def feeder() -> None:
            for _ in range(5000):
                if b"root\n" in stdin.data:
                    break
                time.sleep(0.001)
            # A root prompt that is immediately and continuously buried under
            # kernel spam: it is never the tail of the transcript.
            os.write(write_fd, b"root\n[root@archiso ~]# ")
            os.write(write_fd, _kernel_noise("900"))
            os.write(write_fd, _kernel_noise("901"))
            token = _await_ready_probe(stdin)
            os.write(write_fd, _kernel_noise("902"))
            os.write(write_fd, b"TELOS_ARCH_SHELL_READY_" + token + b"=ready\n")
            os.write(write_fd, _kernel_noise("903"))
            for _ in range(5000):
                if attach_calls and b"bash /root/arch-install.sh" in stdin.data:
                    break
                time.sleep(0.001)
            os.write(write_fd, _kernel_noise("904"))
            os.write(write_fd, b"\nTELOS ARCH INSTALL COMPLETE\n")
            os.close(write_fd)

        worker = threading.Thread(target=feeder)
        worker.start()
        try:
            with tempfile.TemporaryDirectory() as temporary:
                capture = Path(temporary) / "serial.log"
                transcript = arch_install_run.drive_installer(
                    process, capture, verify_script="verify",
                    installer_script="installer", serial="TELOS-WIN-0001",
                    attach=attach, timeout=10)
        finally:
            worker.join()
            os.close(read_fd)
        self.assertEqual(attach_calls, [1])
        # The prompt really is followed by kernel audit spam in the transcript,
        # so an end-of-transcript matcher could not have detected readiness.
        self.assertLess(
            transcript.index("[root@archiso ~]#"), transcript.index("audit:"))
        self.assertIn(b"bash /root/arch-install.sh", stdin.data)
        self.assertIn("TELOS ARCH INSTALL COMPLETE", transcript)

    def test_drive_installer_fails_closed_when_the_sentinel_never_appears(self):
        # A root prompt is reached and the probe is echoed, but the guest only
        # ever emits kernel spam and never the sentinel: the run fails closed.
        read_fd, write_fd = os.pipe()
        events: list = []
        stdin = _Recorder(events)
        process = _FakeProcess(read_fd, stdin)

        def attach() -> None:
            events.append(("attach", None))

        # The root prompt is reached (so the runner echoes its probe), but the
        # guest only ever emits kernel spam afterwards, never the sentinel.
        os.write(write_fd, b"[root@archiso ~]# ")

        def feeder() -> None:
            token = _await_ready_probe(stdin)
            os.write(write_fd, _kernel_noise("900"))
            os.write(write_fd, _kernel_noise("901"))

        worker = threading.Thread(target=feeder)
        worker.start()
        try:
            with tempfile.TemporaryDirectory() as temporary:
                capture = Path(temporary) / "serial.log"
                with self.assertRaisesRegex(
                        RuntimeError, "root shell was never reached"):
                    arch_install_run.drive_installer(
                        process, capture, verify_script="verify",
                        installer_script="installer", serial="TELOS-WIN-0001",
                        attach=attach, timeout=1)
        finally:
            worker.join()
            os.close(write_fd)
            os.close(read_fd)
        # The readiness probe was echoed, but no destructive step ran: the
        # sentinel never surfaced, so there was no hot-attach and no installer.
        self.assertTrue(any(
            kind == "write" and b"TELOS_ARCH_SHELL_READY_" in payload
            for kind, payload in events))
        self.assertNotIn(("attach", None), events)
        self.assertNotIn(b"bash /root/arch-install.sh", stdin.data)

    def test_sanitize_log_redacts_and_bounds(self):
        with tempfile.TemporaryDirectory() as temporary:
            log = Path(temporary) / "serial.log"
            log.write_bytes(b"x" * 100 + b"\npassword: should-not-survive\n")
            arch_install_run._sanitize_log(log, maximum=40)
            self.assertLessEqual(log.stat().st_size, 40)
            self.assertNotIn(b"should-not-survive", log.read_bytes())
            self.assertEqual(log.stat().st_mode & 0o777, 0o600)

    def test_runtime_publication_destroyed_without_following_symlinks(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            publication = root / "publication.iso"
            publication.write_bytes(b"published arch release")
            self.assertIsNone(
                arch_install_run._destroy_runtime_publication(publication))
            self.assertFalse(publication.exists())
            target = root / "target"
            target.write_bytes(b"preserve")
            publication.symlink_to(target)
            self.assertIn(
                "symlink",
                arch_install_run._destroy_runtime_publication(publication))
            self.assertTrue(target.exists())


if __name__ == "__main__":
    unittest.main()
