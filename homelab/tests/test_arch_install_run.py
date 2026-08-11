"""Contracts for the bounded private Arch-second installation lifecycle."""

import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import threading
import time
import unittest
from unittest import mock

from homelab.vm import arch_install_run
from homelab.vm.arch_install_prepare import (
    DISK_BYTES, INSTALLER_NAME, JOIN_PORT_ID, OVERLAY_NAME, VARS_NAME,
    VERIFY_NAME)
from homelab.vm.controller_join_material import (
    ControllerJoinResult, OneUseDomainJoinMaterial)


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
    "TELOS ARCH JOIN MEDIA CONSUMED",
    "TELOS ARCH JOIN VERIFIED",
    "Arch installed; Windows partitions and filesystems were not modified.",
    "TELOS ARCH INSTALL COMPLETE",
    "TELOS ARCH BOOTLOADER LINUX PRESENT",
    "TELOS ARCH BOOTLOADER WINDOWS PRESERVED",
    "TELOS ARCH DEFAULT auto-windows",
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
                "hostname": "telos-ws1",
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
            "TELOS ARCH JOIN MEDIA CONSUMED",
            "TELOS ARCH JOIN VERIFIED",
            "Arch installed; Windows partitions and filesystems "
            "were not modified.",
            "TELOS ARCH INSTALL COMPLETE",
            "TELOS ARCH BOOTLOADER LINUX PRESENT",
            "TELOS ARCH BOOTLOADER WINDOWS PRESERVED",
            "TELOS ARCH DEFAULT auto-windows",
        ))
        with self.assertRaisesRegex(RuntimeError, "before archiso was live"):
            arch_install_run._validate_lifecycle(transcript)

    def test_hot_attach_adds_virtio_blk_with_the_authorized_serial(self):
        qmp = _FakeQmp()
        arch_install_run.hot_attach_disk(qmp, "TELOS-WIN-0001")
        self.assertEqual(len(qmp.calls), 1)
        command, arguments, timeout = qmp.calls[0]
        self.assertEqual(command, "device_add")
        # virtio-blk, not NVMe: QEMU's NVMe namespace identifiers are bogus to
        # the kernel and namespace revalidation tears down the enumerated GPT.
        self.assertEqual(arguments["driver"], "virtio-blk-pci")
        self.assertEqual(arguments["drive"], "osdisk")
        self.assertEqual(arguments["serial"], "TELOS-WIN-0001")
        self.assertEqual(arguments["id"], "osdisk-blk")
        # The disk must land in the cold-plugged hotplug root port, not the
        # q35 root complex pcie.0, which does not support PCIe hotplug.
        self.assertEqual(arguments["bus"], arch_install_run.DISK_PORT_ID)
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
        # The disk confirmation gates the ATTACHED marker on visible
        # partitions, not on the serial alone, so an attach whose GPT never
        # surfaces fails before a single installer byte runs. No NVMe rescan
        # remains: the attach is virtio-blk and forced namespace rescans were
        # what tore the enumerated partitions back down.
        # The marker is emitted quote-split so the command's own tty echo can
        # never contain the contiguous marker text the host watches for.
        self.assertIn(
            b"grep -qw part && echo 'TELOS ARCH DISK' 'ATTACHED'",
            stdin.data)
        self.assertNotIn(b"echo TELOS ARCH DISK ATTACHED", stdin.data)
        self.assertNotIn(b"echo TELOS ARCH INSTALL FAIL", stdin.data)
        self.assertNotIn(b"rescan_controller", stdin.data)
        self.assertNotIn(b"nvme ns-rescan", stdin.data)
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

    def test_lifecycle_requires_the_join_media_consumed_marker(self):
        transcript = GOOD_SERIAL.replace("TELOS ARCH JOIN MEDIA CONSUMED", "")
        with self.assertRaisesRegex(RuntimeError, "markers missing"):
            arch_install_run._validate_lifecycle(transcript)

    def test_lifecycle_requires_the_join_verified_marker(self):
        transcript = GOOD_SERIAL.replace("TELOS ARCH JOIN VERIFIED", "")
        with self.assertRaisesRegex(RuntimeError, "markers missing"):
            arch_install_run._validate_lifecycle(transcript)

    def test_lifecycle_requires_join_markers_between_attach_and_complete(self):
        lines = GOOD_SERIAL.splitlines()
        consumed = lines.index("TELOS ARCH JOIN MEDIA CONSUMED")
        verified = lines.index("TELOS ARCH JOIN VERIFIED")
        attached = lines.index("TELOS ARCH DISK ATTACHED serial=TELOS-WIN-0001")
        complete = lines.index("TELOS ARCH INSTALL COMPLETE")
        reorderings = (
            # Media consumed before the disk attach: credential media exposed
            # to a pre-live environment.
            [lines[consumed]] + lines[:consumed] + lines[consumed + 1:],
            # Verified before consumed: the join cannot precede the media.
            (lines[:consumed] + [lines[verified], lines[consumed]]
             + lines[verified + 1:]),
            # Verified only after completion: the installer finished without
            # a proven join.
            (lines[:verified] + lines[verified + 1:complete + 1]
             + [lines[verified]] + lines[complete + 1:]),
        )
        # The attach index anchors the window; sanity-check the fixture.
        self.assertLess(attached, consumed)
        for transcript in reorderings:
            with self.subTest(transcript=transcript[:6]):
                with self.assertRaisesRegex(RuntimeError, "out of order"):
                    arch_install_run._validate_lifecycle(
                        "\n".join(transcript))

    def test_drive_installer_destroys_join_media_on_the_consumed_marker(self):
        read_fd, write_fd = os.pipe()
        events: list = []
        stdin = _Recorder(events)
        process = _FakeProcess(read_fd, stdin)
        consumed_calls: list = []

        def attach() -> None:
            events.append(("attach", None))

        def consume_media() -> None:
            events.append(("consume-media", None))
            consumed_calls.append(1)

        os.write(write_fd, b"[root@archiso ~]# ")

        def feeder() -> None:
            token = _await_ready_probe(stdin)
            os.write(write_fd, b"TELOS_ARCH_SHELL_READY_" + token + b"=ready\n")
            for _ in range(5000):
                if b"bash /root/arch-install.sh" in stdin.data:
                    break
                time.sleep(0.001)
            # The guest unmounts the media and prints the consumed marker;
            # only after the host destroys the media does the guest join.
            os.write(write_fd, b"\nTELOS ARCH JOIN MEDIA CONSUMED\n")
            for _ in range(5000):
                if consumed_calls:
                    break
                time.sleep(0.001)
            os.write(write_fd, b"TELOS ARCH JOIN VERIFIED\n")
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
                    attach=attach, consume_media=consume_media, timeout=10)
        finally:
            worker.join()
            os.close(read_fd)
        # Exactly one destruction, after the attach and before completion.
        self.assertEqual(consumed_calls, [1])
        attach_index = events.index(("attach", None))
        consume_index = events.index(("consume-media", None))
        self.assertLess(attach_index, consume_index)
        self.assertIn("TELOS ARCH JOIN MEDIA CONSUMED", transcript)
        self.assertIn("TELOS ARCH INSTALL COMPLETE", transcript)

    def test_drive_installer_propagates_a_media_destruction_failure(self):
        read_fd, write_fd = os.pipe()
        stdin = _Recorder([])
        process = _FakeProcess(read_fd, stdin)

        def consume_media() -> None:
            raise RuntimeError("join media hot-remove failed: refused")

        os.write(write_fd, b"[root@archiso ~]# ")

        def feeder() -> None:
            token = _await_ready_probe(stdin)
            os.write(write_fd, b"TELOS_ARCH_SHELL_READY_" + token + b"=ready\n")
            for _ in range(5000):
                if b"bash /root/arch-install.sh" in stdin.data:
                    break
                time.sleep(0.001)
            os.write(write_fd, b"\nTELOS ARCH JOIN MEDIA CONSUMED\n")

        worker = threading.Thread(target=feeder)
        worker.start()
        try:
            with tempfile.TemporaryDirectory() as temporary:
                capture = Path(temporary) / "serial.log"
                with self.assertRaisesRegex(
                        RuntimeError, "hot-remove failed"):
                    arch_install_run.drive_installer(
                        process, capture, verify_script="verify",
                        installer_script="installer", serial="TELOS-WIN-0001",
                        attach=lambda: None, consume_media=consume_media,
                        timeout=10)
        finally:
            worker.join()
            os.close(write_fd)
            os.close(read_fd)

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


class _FakeMediaQmp:
    """Track blockdev/device lifecycle and prove inode ownership like QEMU."""

    def __init__(self, *, fail_on=()) -> None:
        self.calls: list[tuple] = []
        self.fail_on = set(fail_on)
        self.held: set[tuple[int, int]] = set()
        self.deleted: list[str] = []

    def execute(self, command, arguments=None, *, timeout=None):
        self.calls.append((command, arguments))
        if command in self.fail_on:
            raise arch_install_run.WindowsGuiError(f"{command} refused")
        if command == "blockdev-add":
            info = Path(arguments["file"]["filename"]).stat()
            self.held.add((info.st_dev, info.st_ino))
        if command == "blockdev-del":
            self.held.clear()
        return {}

    def holds_inode(self, device, inode):
        return (device, inode) in self.held

    def await_device_deleted(self, device_id, *, timeout=None):
        self.deleted.append(device_id)
        return {"event": "DEVICE_DELETED", "data": {"device": device_id}}


def _private_parent(root: Path) -> Path:
    parent = root / "evidence"
    parent.mkdir(mode=0o700)
    return parent


def _iso_runner(argv, **_kwargs):
    """Stand in for xorriso: create the -o target without reading secrets."""
    Path(argv[argv.index("-o") + 1]).write_bytes(b"iso-image")
    return subprocess.CompletedProcess(argv, 0)


JOIN_MATERIAL = {
    "username": "tj-" + "0" * 16 + "@AD.FACTORY.TEST",
    "password": "Synthetic-Join-secret-47!",
}


class ArchJoinMediaTests(unittest.TestCase):
    def build(self, parent: Path, runner=_iso_runner) -> Path:
        return arch_install_run.build_arch_join_iso(
            parent / "join.iso", JOIN_MATERIAL, runner=runner)

    def test_join_iso_is_private_and_secret_free_in_argv(self):
        with tempfile.TemporaryDirectory() as temporary:
            parent = _private_parent(Path(temporary))
            argvs: list[list[str]] = []

            def runner(argv, **kwargs):
                argvs.append(list(argv))
                return _iso_runner(argv, **kwargs)

            iso = self.build(parent, runner)
            self.assertEqual(iso.stat().st_mode & 0o777, 0o600)
            # The credential never crosses the process boundary and no
            # plaintext staging survives next to the ISO.
            self.assertEqual(len(argvs), 1)
            self.assertNotIn(
                JOIN_MATERIAL["password"], " ".join(argvs[0]))
            self.assertEqual(list(parent.iterdir()), [iso])
            # The staged tree fed to xorriso carried join.json read-only.
            staging = Path(argvs[0][-1])
            self.assertEqual(staging.name, "payload")

    def test_join_iso_builder_fails_closed(self):
        with tempfile.TemporaryDirectory() as temporary:
            parent = _private_parent(Path(temporary))
            occupied = parent / "join.iso"
            occupied.write_bytes(b"stale")
            with self.assertRaisesRegex(RuntimeError, "absent"):
                self.build(parent)
            occupied.unlink()
            parent.chmod(0o755)
            with self.assertRaisesRegex(RuntimeError, "mode-0700"):
                self.build(parent)
            parent.chmod(0o700)
            for material in (
                {"username": "operator@AD.FACTORY.TEST",
                 "password": "Synthetic-47!"},
                {"username": JOIN_MATERIAL["username"],
                 "password": "line\nbreak"},
                {"username": JOIN_MATERIAL["username"], "password": ""},
                {"username": JOIN_MATERIAL["username"]},
            ):
                with self.subTest(material=material):
                    with self.assertRaises(RuntimeError):
                        arch_install_run.build_arch_join_iso(
                            parent / "join.iso", material,
                            runner=_iso_runner)
            self.assertEqual(list(parent.iterdir()), [])

    def test_media_attach_is_read_only_into_the_join_port(self):
        with tempfile.TemporaryDirectory() as temporary:
            parent = _private_parent(Path(temporary))
            iso = self.build(parent)
            qmp = _FakeMediaQmp()
            media = arch_install_run.ArchJoinMedia(qmp, iso, qemu_pid=4321)
            media.attach()
            commands = [command for command, _ in qmp.calls]
            self.assertEqual(commands, ["blockdev-add", "device_add"])
            node = qmp.calls[0][1]
            self.assertIs(node["read-only"], True)
            self.assertEqual(node["node-name"], "joinmedia")
            self.assertEqual(node["file"]["filename"], str(iso.resolve()))
            device = qmp.calls[1][1]
            self.assertEqual(device["driver"], "virtio-blk-pci")
            self.assertEqual(device["bus"], JOIN_PORT_ID)
            self.assertEqual(device["drive"], "joinmedia")
            self.assertEqual(device["id"], "joinmedia-blk")
            self.assertFalse(media.destroyed)
            self.assertTrue(iso.is_file())

    def test_media_destroy_hot_removes_then_unlinks_the_exact_inode(self):
        with tempfile.TemporaryDirectory() as temporary:
            parent = _private_parent(Path(temporary))
            iso = self.build(parent)
            qmp = _FakeMediaQmp()
            media = arch_install_run.ArchJoinMedia(qmp, iso, qemu_pid=4321)
            media.attach()
            media.destroy()
            commands = [command for command, _ in qmp.calls]
            self.assertEqual(commands, [
                "blockdev-add", "device_add", "device_del", "blockdev-del"])
            self.assertEqual(qmp.deleted, ["joinmedia-blk"])
            self.assertTrue(media.destroyed)
            self.assertFalse(iso.exists())

    def test_media_destroy_refuses_an_impostor_file(self):
        with tempfile.TemporaryDirectory() as temporary:
            parent = _private_parent(Path(temporary))
            iso = self.build(parent)
            qmp = _FakeMediaQmp()
            media = arch_install_run.ArchJoinMedia(qmp, iso, qemu_pid=4321)
            media.attach()
            # The name is replaced by a different inode after attach: exact
            # inode destruction must refuse to unlink the impostor.
            iso.unlink()
            iso.write_bytes(b"impostor")
            with self.assertRaisesRegex(RuntimeError, "uniquely owned"):
                media.destroy()
            self.assertTrue(iso.is_file())
            self.assertEqual(iso.read_bytes(), b"impostor")

    def test_media_attach_failure_fails_closed_and_cleanup_destroys(self):
        with tempfile.TemporaryDirectory() as temporary:
            parent = _private_parent(Path(temporary))
            iso = self.build(parent)
            qmp = _FakeMediaQmp(fail_on={"device_add"})
            media = arch_install_run.ArchJoinMedia(qmp, iso, qemu_pid=4321)
            with self.assertRaisesRegex(RuntimeError, "attach failed"):
                media.attach()
            self.assertEqual(media.cleanup(), [])
            self.assertTrue(media.destroyed)
            self.assertFalse(iso.exists())

    def test_join_account_media_install_sequencing(self):
        # The proven order: per-run DC account staged, then ISO built, then
        # media attached, then consumed/destroyed, then the DC account
        # destroyed — with the credential absent from every recorded fact.
        events: list[str] = []
        principal = "tj-" + "a" * 16

        def stage(credential):
            self.assertIsInstance(credential, str)
            events.append("stage-principal")
            return ControllerJoinResult(
                operation="stage", principal=principal,
                destruction_proved=False, events=())

        def destroy():
            events.append("destroy-principal")
            return ControllerJoinResult(
                operation="destroy", principal=principal,
                destruction_proved=True, events=())

        owner = OneUseDomainJoinMaterial(
            "ad.factory.test", stage=stage, destroy=destroy)
        with tempfile.TemporaryDirectory() as temporary:
            parent = _private_parent(Path(temporary))
            iso = parent / "join.iso"
            qmp = _FakeMediaQmp()
            materials: list[dict] = []

            def consume(material):
                materials.append(dict(material))

                def drive(attach_media, consume_media):
                    events.append("guest-boot")
                    attach_media()
                    events.append("media-attached")
                    consume_media()
                    events.append("media-destroyed")
                    return "transcript"

                original_build = arch_install_run.build_arch_join_iso

                def build(output, material, **kwargs):
                    events.append("iso-built")
                    self.assertNotIn("credential", material)
                    return original_build(
                        output, material, runner=_iso_runner)

                with mock.patch.object(
                        arch_install_run, "build_arch_join_iso",
                        side_effect=build):
                    return arch_install_run.run_join_install(
                        material=material, iso=iso, qmp=qmp,
                        qemu_pid=4321, drive=drive)

            (transcript, facts), proof = owner.use(consume)
        self.assertEqual(transcript, "transcript")
        self.assertEqual(events, [
            "stage-principal", "iso-built", "guest-boot", "media-attached",
            "media-destroyed", "destroy-principal"])
        # Facts are secret-free lifecycle booleans only.
        self.assertEqual(facts, {
            "built": True, "attached": True,
            "consumed": True, "destroyed": True})
        self.assertTrue(proof.destruction_proved)
        self.assertFalse(iso.exists())
        # The staged one-use credential reached the ISO builder, not the
        # facts, the transcript, or the events.
        self.assertEqual(
            materials[0]["principal"], principal)
        self.assertNotIn(materials[0]["credential"], json.dumps(facts))

    def test_run_join_install_fails_closed_without_consumption(self):
        with tempfile.TemporaryDirectory() as temporary:
            parent = _private_parent(Path(temporary))
            iso = parent / "join.iso"
            qmp = _FakeMediaQmp()

            def drive(attach_media, consume_media):
                attach_media()
                return "transcript"  # COMPLETE without the consumed marker.

            facts: dict = {}
            with mock.patch.object(
                    arch_install_run, "build_arch_join_iso",
                    side_effect=lambda output, material, **kwargs:
                    _build_stub(output)):
                with self.assertRaisesRegex(
                        RuntimeError, "not consumed and destroyed"):
                    arch_install_run.run_join_install(
                        material={
                            "principal": "tj-" + "b" * 16,
                            "realm": "AD.FACTORY.TEST",
                            "credential": "Synthetic-47!",
                        },
                        iso=iso, qmp=qmp, qemu_pid=4321, drive=drive,
                        facts=facts)
            # The failure still tore the attached media down by exact inode.
            self.assertTrue(facts["attached"])
            self.assertFalse(facts["consumed"])
            self.assertFalse(iso.exists())

    def test_run_join_install_lets_a_guest_failure_surface_unmasked(self):
        # An installer that fails before consuming the media must surface as
        # the guest's honest FAIL marker (via lifecycle validation), not as a
        # masking media error — while the media is still torn down.
        with tempfile.TemporaryDirectory() as temporary:
            parent = _private_parent(Path(temporary))
            iso = parent / "join.iso"
            qmp = _FakeMediaQmp()

            def drive(attach_media, consume_media):
                attach_media()
                return "TELOS ARCH INSTALL FAIL rc=1"

            facts: dict = {}
            with mock.patch.object(
                    arch_install_run, "build_arch_join_iso",
                    side_effect=lambda output, material, **kwargs:
                    _build_stub(output)):
                transcript, returned = arch_install_run.run_join_install(
                    material={
                        "principal": "tj-" + "d" * 16,
                        "realm": "AD.FACTORY.TEST",
                        "credential": "Synthetic-47!",
                    },
                    iso=iso, qmp=qmp, qemu_pid=4321, drive=drive,
                    facts=facts)
            self.assertIn("TELOS ARCH INSTALL FAIL", transcript)
            self.assertFalse(facts["consumed"])
            # cleanup destroyed the attached media by exact inode anyway.
            self.assertTrue(facts["destroyed"])
            self.assertFalse(iso.exists())
            with self.assertRaisesRegex(RuntimeError, "reported failure"):
                arch_install_run._validate_lifecycle(transcript)

    def test_run_join_install_cleans_up_when_the_drive_fails(self):
        with tempfile.TemporaryDirectory() as temporary:
            parent = _private_parent(Path(temporary))
            iso = parent / "join.iso"
            qmp = _FakeMediaQmp()

            def drive(attach_media, consume_media):
                attach_media()
                raise RuntimeError("installer failed")

            facts: dict = {}
            with mock.patch.object(
                    arch_install_run, "build_arch_join_iso",
                    side_effect=lambda output, material, **kwargs:
                    _build_stub(output)):
                with self.assertRaisesRegex(RuntimeError, "installer failed"):
                    arch_install_run.run_join_install(
                        material={
                            "principal": "tj-" + "c" * 16,
                            "realm": "AD.FACTORY.TEST",
                            "credential": "Synthetic-47!",
                        },
                        iso=iso, qmp=qmp, qemu_pid=4321, drive=drive,
                        facts=facts)
            self.assertTrue(facts["built"])
            self.assertTrue(facts["attached"])
            self.assertFalse(facts["consumed"])
            # Cleanup still destroyed the attached media by exact inode, and
            # the facts record that honestly.
            self.assertTrue(facts["destroyed"])
            self.assertFalse(iso.exists())

    def test_leftover_join_iso_destroyed_without_following_symlinks(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            iso = root / "join.iso"
            iso.write_bytes(b"leftover")
            self.assertIsNone(
                arch_install_run._destroy_leftover_join_iso(iso))
            self.assertFalse(iso.exists())
            target = root / "target"
            target.write_bytes(b"preserve")
            iso.symlink_to(target)
            self.assertIn(
                "symlink",
                arch_install_run._destroy_leftover_join_iso(iso))
            self.assertTrue(target.exists())


def _build_stub(output: Path) -> Path:
    output.write_bytes(b"iso-image")
    output.chmod(0o600)
    return output


class _ConsoleProcess:
    def __init__(self, read_fd: int, stdin: _Recorder) -> None:
        self.stdout = os.fdopen(read_fd, "rb", buffering=0)
        self.stdin = stdin


class _FakeControllerQmp:
    """Record controller QMP media lifecycle like the identity lane's QEMU."""

    def __init__(self) -> None:
        self.calls: list[tuple] = []
        self.deleted: list[str] = []

    def execute(self, command, arguments=None, *, timeout=None):
        self.calls.append((command, arguments))
        return {}

    def await_device_deleted(self, device_id, *, timeout=None):
        self.deleted.append(device_id)
        return {"event": "DEVICE_DELETED", "data": {"device": device_id}}


class _FakeConsole:
    """Record the proven SerialAutomation convergence entry points."""

    def __init__(self) -> None:
        self.password = b"Synthetic-Controller-test-47!"
        self.events: list = []

    def install_offline_controller_dependencies(self, **kwargs):
        self.events.append(("seed-install", None))

    def converge_disposable_controller(self, guest_command, **kwargs):
        self.events.append(("converge", guest_command))


class ControllerDomainTests(unittest.TestCase):
    def test_prepare_controller_domain_orders_the_proven_steps(self):
        events: list[str] = []
        facts: dict = {}
        with mock.patch.object(
                arch_install_run, "install_controller_seed",
                side_effect=lambda *a, **k: events.append("seed")), \
                mock.patch.object(
                    arch_install_run, "_controller_sudo",
                    side_effect=lambda console, command, label:
                    events.append(label)), \
                mock.patch.object(
                    arch_install_run, "converge_controller",
                    side_effect=lambda *a, **k: events.append("converge")):
            returned = arch_install_run.prepare_controller_domain(
                qmp=object(), console=object(), seed_iso=Path("/seed.iso"),
                media_root=Path("/media"), facts=facts)
        # Publication stays (it ran in the init shell); then: seed install,
        # stop the publication nginx the convergence would collide with,
        # converge (which requires PASS and live AD), restore the published
        # PXE bootstrap the convergence overwrote.
        self.assertEqual(events, [
            "seed", "arch-publication-http-stop", "converge",
            "arch-pxe-bootstrap-restore"])
        self.assertEqual(returned, {
            "seed_installed": True, "converged": True,
            "pxe_bootstrap_restored": True})
        self.assertIs(returned, facts)

    def test_prepare_controller_domain_fails_closed_mid_sequence(self):
        facts: dict = {}
        with mock.patch.object(
                arch_install_run, "install_controller_seed"), \
                mock.patch.object(arch_install_run, "_controller_sudo"), \
                mock.patch.object(
                    arch_install_run, "converge_controller",
                    side_effect=RuntimeError("convergence failed")):
            with self.assertRaisesRegex(RuntimeError, "convergence failed"):
                arch_install_run.prepare_controller_domain(
                    qmp=object(), console=object(),
                    seed_iso=Path("/seed.iso"),
                    media_root=Path("/media"), facts=facts)
        # The evidence facts honestly record how far provisioning got.
        self.assertEqual(facts, {
            "seed_installed": True, "converged": False,
            "pxe_bootstrap_restored": False})

    def test_seed_install_attaches_verifies_and_releases_media(self):
        with tempfile.TemporaryDirectory() as temporary:
            seed = Path(temporary) / "seed.iso"
            seed.write_bytes(b"seed")
            seed.chmod(0o644)
            qmp = _FakeControllerQmp()
            console = _FakeConsole()
            arch_install_run.install_controller_seed(qmp, console, seed)
            self.assertEqual(
                [command for command, _ in qmp.calls],
                ["blockdev-add", "blockdev-add", "device_add",
                 "device_del", "blockdev-del", "blockdev-del"])
            device = qmp.calls[2][1]
            self.assertEqual(device["driver"], "scsi-cd")
            self.assertEqual(device["bus"], "archfactorybus.0")
            node = qmp.calls[1][1]
            self.assertIs(node["read-only"], True)
            # The in-guest verify/install ran between attach and release.
            self.assertEqual(console.events, [("seed-install", None)])
            self.assertEqual(qmp.deleted, ["archseedcd"])

    def test_seed_install_refuses_unsafe_media(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            world_writable = root / "seed.iso"
            world_writable.write_bytes(b"seed")
            world_writable.chmod(0o666)
            link = root / "link.iso"
            link.symlink_to(world_writable)
            for unsafe in (world_writable, link, root / "absent.iso"):
                with self.subTest(seed=unsafe):
                    with self.assertRaisesRegex(RuntimeError, "unsafe"):
                        arch_install_run.install_controller_seed(
                            _FakeControllerQmp(), _FakeConsole(), unsafe)

    def test_convergence_attaches_media_and_destroys_the_secret(self):
        with tempfile.TemporaryDirectory() as temporary:
            media_root = Path(temporary) / "controller-media"
            bundles: list = []

            class _StubBundle:
                def __init__(self, repo, output, *, authorization_nonce):
                    self.output = Path(output)
                    self.nonce = authorization_nonce
                    self.password = "Synthetic-secret-47!"
                    bundles.append(self)

                def build(self):
                    self.output.write_bytes(b"convergence")
                    self.output.chmod(0o600)
                    return self.output

                @staticmethod
                def guest_command(nonce):
                    return f"converge --nonce {nonce}"

            qmp = _FakeControllerQmp()
            console = _FakeConsole()
            with mock.patch.object(
                    arch_install_run, "FactoryBundle", _StubBundle):
                arch_install_run.converge_controller(
                    qmp, console, media_root, repo_root=Path(temporary))
            bundle = bundles[0]
            # The console ran the exact nonce-bound convergence command.
            self.assertEqual(
                console.events,
                [("converge", f"converge --nonce {bundle.nonce}")])
            self.assertEqual(
                [command for command, _ in qmp.calls],
                ["blockdev-add", "blockdev-add", "device_add",
                 "device_del", "blockdev-del", "blockdev-del"])
            self.assertEqual(qmp.calls[2][1]["bus"], "archfactorybus.0")
            self.assertEqual(qmp.deleted, ["archfactorycd"])
            # The secret-bearing media and in-memory password are destroyed.
            self.assertEqual(bundle.password, "")
            self.assertFalse(bundle.output.exists())
            self.assertFalse(media_root.exists())

    def test_convergence_drops_the_secret_even_on_failure(self):
        with tempfile.TemporaryDirectory() as temporary:
            media_root = Path(temporary) / "controller-media"
            bundles: list = []

            class _StubBundle:
                def __init__(self, repo, output, *, authorization_nonce):
                    self.output = Path(output)
                    self.password = "Synthetic-secret-47!"
                    bundles.append(self)

                def build(self):
                    self.output.write_bytes(b"convergence")
                    return self.output

                @staticmethod
                def guest_command(nonce):
                    return "converge"

            class _FailingConsole(_FakeConsole):
                def converge_disposable_controller(self, guest_command,
                                                   **kwargs):
                    raise RuntimeError("convergence guest failure")

            with mock.patch.object(
                    arch_install_run, "FactoryBundle", _StubBundle):
                with self.assertRaisesRegex(RuntimeError, "guest failure"):
                    arch_install_run.converge_controller(
                        _FakeControllerQmp(), _FailingConsole(), media_root,
                        repo_root=Path(temporary))
            self.assertEqual(bundles[0].password, "")
            self.assertFalse(bundles[0].output.exists())

    def test_controller_sudo_runs_one_bounded_root_command(self):
        read_fd, write_fd = os.pipe()
        events: list = []
        stdin = _Recorder(events)
        console = arch_install_run.SerialAutomation(
            os.fdopen(read_fd, "rb", buffering=0), stdin,
            b"Synthetic-Controller-test-47!", timeout=10)

        def feeder() -> None:
            os.write(write_fd, b"\n[local-rescue@bootstrap-dc ~]$ ")
            prompt = None
            for _ in range(5000):
                match = re.search(
                    rb"__TELOS_ARCH_SUDO_[0-9a-f]{32}__", stdin.data)
                if match:
                    prompt = match.group(0)
                    break
                time.sleep(0.001)
            os.write(write_fd, b"\n" + prompt)
            for _ in range(5000):
                if b"Synthetic-Controller-test-47!" in stdin.data:
                    break
                time.sleep(0.001)
            marker = re.search(
                rb"__TELOS_ARCH_RC_[0-9a-f]{32}=", stdin.data).group(0)
            os.write(write_fd, b"\n" + marker + b"0\n")

        worker = threading.Thread(target=feeder)
        worker.start()
        try:
            arch_install_run._controller_sudo(
                console, "systemctl stop telos-factory-http.service",
                "arch-publication-http-stop")
        finally:
            worker.join()
            os.close(write_fd)
            console.reader.close()
        self.assertIn(
            b"systemctl stop telos-factory-http.service", stdin.data)
        self.assertIn(b"sudo -k -S", stdin.data)

    def test_controller_sudo_fails_closed_on_nonzero_return(self):
        read_fd, write_fd = os.pipe()
        stdin = _Recorder([])
        console = arch_install_run.SerialAutomation(
            os.fdopen(read_fd, "rb", buffering=0), stdin,
            b"Synthetic-Controller-test-47!", timeout=10)

        def feeder() -> None:
            os.write(write_fd, b"\n[local-rescue@bootstrap-dc ~]$ ")
            prompt = None
            for _ in range(5000):
                match = re.search(
                    rb"__TELOS_ARCH_SUDO_[0-9a-f]{32}__", stdin.data)
                if match:
                    prompt = match.group(0)
                    break
                time.sleep(0.001)
            os.write(write_fd, b"\n" + prompt)
            for _ in range(5000):
                if b"Synthetic-Controller-test-47!" in stdin.data:
                    break
                time.sleep(0.001)
            marker = re.search(
                rb"__TELOS_ARCH_RC_[0-9a-f]{32}=", stdin.data).group(0)
            os.write(write_fd, b"\n" + marker + b"1\n")

        worker = threading.Thread(target=feeder)
        worker.start()
        try:
            with self.assertRaisesRegex(RuntimeError, "command failed"):
                arch_install_run._controller_sudo(
                    console, "false", "arch-pxe-bootstrap-restore")
        finally:
            worker.join()
            os.close(write_fd)
            console.reader.close()

    def test_gateway_argv_requires_the_pxe_identity_seam(self):
        # Until the simulated_gateway/factory_runner pxe_identity_mode seam
        # lands, the run must fail closed naming the exact gap: the archiso
        # live client's plain DHCP lease needs Controller DNS and the
        # ad.factory.test suffix while PXE options 66/67 stay served.
        def old_signature(port, *, controller_mac=None, identity_mode=False):
            raise AssertionError("must not be reached")

        def rejecting(port, **kwargs):
            raise TypeError(
                "gateway_command() got an unexpected keyword argument "
                "'pxe_identity_mode'")

        with mock.patch.object(
                arch_install_run, "gateway_command", side_effect=rejecting):
            with self.assertRaisesRegex(RuntimeError, "pxe_identity_mode"):
                arch_install_run._gateway_argv(31415)

        def composed(port, *, pxe_identity_mode=False):
            self.assertTrue(pxe_identity_mode)
            return ["gateway", "--port", str(port), "--pxe-identity-mode"]

        with mock.patch.object(
                arch_install_run, "gateway_command", side_effect=composed):
            self.assertEqual(
                arch_install_run._gateway_argv(31415),
                ["gateway", "--port", "31415", "--pxe-identity-mode"])


class EstablishPublicationConsoleTests(unittest.TestCase):
    """The Controller console must publish and stay owned for join staging."""

    def test_publication_then_authenticated_console_is_returned(self):
        read_fd, write_fd = os.pipe()
        events: list = []
        stdin = _Recorder(events)
        process = _ConsoleProcess(read_fd, stdin)
        password = b"Synthetic-Controller-test-47!"

        def feeder() -> None:
            os.write(write_fd, b"\n[root@bootstrap-dc /]# ")
            for _ in range(5000):
                if b"/run/telos-pxe-release/publish" in stdin.data:
                    break
                time.sleep(0.001)
            os.write(
                write_fd,
                b"\npublishing verified release\n"
                b"TELOS PXE PUBLICATION PASS\n")
            # Systemd services print readiness on the same console after the
            # (mocked) session establishment execs systemd and logs in.
            os.write(write_fd, b"TELOS PXE SERVICES READY\n")

        worker = threading.Thread(target=feeder)
        worker.start()
        try:
            with mock.patch.object(
                    arch_install_run.SerialAutomation,
                    "establish_disposable_controller_session") as establish:
                console = arch_install_run.establish_publication_console(
                    process, password=password, timeout=10)
        finally:
            worker.join()
            os.close(write_fd)
            process.stdout.close()
        establish.assert_called_once()
        # The publish command was sent from the disposable init shell, and
        # the returned console still owns the channel and the credential the
        # join-material protocol needs for sudo.
        sent = bytes(stdin.data)
        self.assertIn(b"/usr/bin/mount -L TELOS_PXE_RELEASE", sent)
        self.assertIn(b"/run/telos-pxe-release/publish", sent)
        self.assertIsInstance(console, arch_install_run.SerialAutomation)
        self.assertEqual(console.password, password)
        self.assertIn(b"TELOS PXE SERVICES READY", console.transcript)

    def test_publication_failure_fails_closed(self):
        read_fd, write_fd = os.pipe()
        stdin = _Recorder([])
        process = _ConsoleProcess(read_fd, stdin)

        def feeder() -> None:
            os.write(write_fd, b"\n[root@bootstrap-dc /]# ")
            for _ in range(5000):
                if b"/run/telos-pxe-release/publish" in stdin.data:
                    break
                time.sleep(0.001)
            # The publish script fails: no PASS marker ever arrives and the
            # console closes, so the run must fail closed.
            os.write(write_fd, b"\nTELOS PXE PUBLICATION FAIL\n")
            os.close(write_fd)

        worker = threading.Thread(target=feeder)
        worker.start()
        try:
            with mock.patch.object(
                    arch_install_run.SerialAutomation,
                    "establish_disposable_controller_session") as establish:
                with self.assertRaisesRegex(
                        RuntimeError, "publication console failed"):
                    arch_install_run.establish_publication_console(
                        process, password=b"Synthetic-Controller-test-47!",
                        timeout=5)
        finally:
            worker.join()
            process.stdout.close()
        establish.assert_not_called()


if __name__ == "__main__":
    unittest.main()
