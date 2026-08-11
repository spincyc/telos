"""Contracts for the bounded gate-10 dual-boot acceptance lifecycle.

Pure unit tests: QEMU, QMP, and qemu-img are always mocked; no guest boots.
"""

import hashlib
import json
import os
from pathlib import Path
import secrets
import struct
import tempfile
import threading
import time
import unittest
from unittest import mock
import zlib

from homelab.vm import dualboot_acceptance as da
from homelab.workstations import dualboot_acceptance as judge_mod
from homelab.workstations.arch_second import (
    EXPECTED, MENU_ARCH_TITLE, MENU_WINDOWS_TITLE, NVRAM_LINUX_LABEL)
from homelab.workstations.layout import GIB, MIB


ROOT = Path(__file__).resolve().parents[1]
LAYOUT = ROOT / "workstations/profiles/default-layout.json"
WORKSTATION = ROOT / "workstations/profiles/phase1-windows-primary.json"
CONST = "c" * 64
SIZES = [1024, 16, 186098, 72956, 2048]
CONTRACT = judge_mod.load_json(judge_mod.CONTRACT)


def _guid_bytes(text: str) -> bytes:
    parts = text.split("-")
    return (
        struct.pack(
            "<IHH", int(parts[0], 16), int(parts[1], 16), int(parts[2], 16))
        + bytes.fromhex(parts[3]) + bytes.fromhex(parts[4])
    )


def make_gpt(sizes_mib, type_guids=None) -> bytes:
    """Build a deterministic, CRC-valid primary GPT head region."""
    guids = type_guids or [guid for _role, guid in EXPECTED]
    count, entry_size = 128, 128
    array = bytearray(count * entry_size)
    first = 2048
    for index, (size_mib, guid) in enumerate(zip(sizes_mib, guids)):
        last = first + size_mib * (MIB // da.SECTOR) - 1
        offset = index * entry_size
        array[offset:offset + 16] = _guid_bytes(guid)
        array[offset + 16:offset + 32] = bytes([index + 1]) * 16
        struct.pack_into("<QQ", array, offset + 32, first, last)
        name = f"part{index + 1}".encode("utf-16-le")
        array[offset + 56:offset + 56 + len(name)] = name
        first = last + 1
    header = bytearray(da.SECTOR)
    header[:8] = b"EFI PART"
    struct.pack_into("<I", header, 8, 0x00010000)
    struct.pack_into("<I", header, 12, 92)
    struct.pack_into("<QQ", header, 24, 1, 2**30)
    struct.pack_into("<QQ", header, 40, 34, 2**30 - 34)
    header[56:72] = bytes(16)
    struct.pack_into("<Q", header, 72, 2)
    struct.pack_into("<III", header, 80, count, entry_size, zlib.crc32(array))
    struct.pack_into("<I", header, 16, zlib.crc32(bytes(header[:92])))
    raw = bytearray(da.GPT_REGION_BYTES)
    raw[da.SECTOR:2 * da.SECTOR] = header
    raw[2 * da.SECTOR:2 * da.SECTOR + len(array)] = array
    return bytes(raw)


def happy_boot1() -> da.BootObservation:
    return da.BootObservation(
        transcript="menu", menu_first=100.0, last_output=105.2,
        entries=[da.MENU_ARCH_ENTRY, da.MENU_WINDOWS_ENTRY,
                 da.MENU_FIRMWARE_ENTRY],
        firmware_entry=NVRAM_LINUX_LABEL,
        guest_running=True, frames=2)


def happy_boot2() -> da.BootObservation:
    return da.BootObservation(
        transcript="menu2", menu_first=10.0, last_output=30.0,
        entries=[da.MENU_ARCH_ENTRY, da.MENU_WINDOWS_ENTRY,
                 da.MENU_FIRMWARE_ENTRY],
        selection="1", selection_at=12.0, kernel_handoff_at=13.0,
        login_prompt_at=20.0, firmware_entry=NVRAM_LINUX_LABEL,
        guest_running=True, frames=1)


def happy_events(**overrides):
    gpt = da.parse_gpt(make_gpt(SIZES))
    keywords = dict(
        boot1=happy_boot1(), boot2=happy_boot2(), gpt_baseline=gpt,
        gpt_after=gpt, expected_sizes_mib=SIZES,
        vars_source=da.VARS_SOURCE_GATE7,
        windows_clean_shutdown=True, arch_clean_shutdown=True)
    keywords.update(overrides)
    return da.build_events(**keywords)


class _FakeQmp:
    """Record QMP calls; screenshot writes a stub frame like QEMU would.

    ``status`` is mutable so a test can prove WHEN liveness was sampled:
    a feeder that flips it to ``shutdown`` mid-run distinguishes a sample
    taken while awaiting the handoff from one taken after the window.
    """

    def __init__(self, status: str = "running") -> None:
        self.calls: list = []
        self.status = status
        self.closed = False

    def execute(self, command, arguments=None, *, timeout=None):
        self.calls.append((command, arguments, timeout))
        if command == "query-status":
            # QmpClient.execute returns the UNWRAPPED ``return`` payload, so
            # query-status yields {"status": ...} directly — not nested under
            # another "return" key.  The fake must mirror that exactly, or a
            # double-unwrap bug in the runner passes here and fails live.
            return {"status": self.status, "running": self.status == "running"}
        return {}

    def screenshot(self, path: Path) -> None:
        self.calls.append(("screendump", str(path)))
        Path(path).write_bytes(b"P6 4 4 255 " + b"\x00" * 48)

    def close(self):
        self.closed = True


class _Recorder:
    def __init__(self) -> None:
        self.data = bytearray()

    def write(self, payload: bytes) -> None:
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


def _menu_cell(row: int, title: str, *, selected: bool) -> bytes:
    """One positioned, attribute-run, space-padded menu cell (live shape)."""
    attributes = (
        b"\x1b[1m\x1b[30m\x1b[47m\x1b[0m\x1b[30m\x1b[47m" if selected
        else b"\x1b[1m\x1b[37m\x1b[40m\x1b[0m\x1b[37m\x1b[40m")
    return b"\x1b[%03d;103H" % row + attributes + f"{title:^36}".encode()


# One systemd-boot menu render modeled on the REAL gate-10 boot-1 serial
# transcript of 2026-08-11 (cursor-positioned rows at column 103 with
# attribute runs and space padding, the Windows default highlighted, a
# countdown line below): its shape is copied, not its bytes.
MENU = (
    b"\x1b[2J\x1b[001;001H"
    + _menu_cell(27, da.MENU_ARCH_ENTRY, selected=False)
    + _menu_cell(28, da.MENU_WINDOWS_ENTRY, selected=True)
    + _menu_cell(29, da.MENU_FIRMWARE_ENTRY, selected=False)
    + _menu_cell(31, "Boot in 5s.", selected=False)
)

# OVMF's firmware handoff lines: entry labels appear only as plain quoted
# log text, never as rendered menu cells.  BDS_LINUX models the fixed boot-1
# shape once the installer-authored NVRAM is first; BDS_WINDOWS_DIRECT
# models the observed menuless boot-2 regression (Windows self-promoted).
_BDS_DEVICE = (
    b'HD(1,GPT,CA2548AC-278B-4457-ADFB-0ED0703C3197,0x800,0x200000)')
BDS_LINUX = (
    b'BdsDxe: loading Boot0003 "Linux Boot Manager" from ' + _BDS_DEVICE
    + b'/\\EFI\\systemd\\systemd-bootx64.efi\r\n'
    b'BdsDxe: starting Boot0003 "Linux Boot Manager" from ' + _BDS_DEVICE
    + b'/\\EFI\\systemd\\systemd-bootx64.efi\r\n'
)
BDS_WINDOWS_DIRECT = (
    b'BdsDxe: loading Boot0004 "Windows Boot Manager" from ' + _BDS_DEVICE
    + b'/\\EFI\\Microsoft\\Boot\\bootmgfw.efi\r\n'
    b'BdsDxe: starting Boot0004 "Windows Boot Manager" from ' + _BDS_DEVICE
    + b'/\\EFI\\Microsoft\\Boot\\bootmgfw.efi\r\n'
)

_MENU_ROWS = (da.MENU_ARCH_ENTRY, da.MENU_WINDOWS_ENTRY, da.MENU_FIRMWARE_ENTRY)


def _render_menu(highlight: int) -> bytes:
    """A full systemd-boot menu render with *highlight* row inverse-video."""
    cells = b"\x1b[2J\x1b[001;001H"
    for index, title in enumerate(_MENU_ROWS):
        cells += _menu_cell(20 + index, title, selected=(index == highlight))
    return cells


def systemd_boot_feeder(
    *, handoff: bytes = b"EFI stub: Booting the kernel\r\n",
    login: bytes | None = None, default: int = 1, arch: int = 0,
    hold: float = 0.6,
):
    """A fake systemd-boot menu that only boots the Arch row on Enter.

    Models the live boot-2 systemd-boot: the menu renders with the Windows
    row highlighted (the ``default auto-windows`` policy), cursor keys move
    the highlight (non-wrapping, as sd-boot does at the ends), a DIGIT key
    does nothing (systemd-boot treats it as a title type-ahead, never a row
    selector), and only Enter on the Arch row boots and emits the handoff.
    """
    def feeder(write_fd, stdin):
        highlight = default
        os.write(write_fd, BDS_LINUX + _render_menu(highlight))
        consumed = 0
        booted = False
        deadline = time.monotonic() + 8.0
        while time.monotonic() < deadline and not booted:
            data = bytes(stdin.data)
            chunk = data[consumed:]
            index = 0
            while index < len(chunk):
                if chunk[index:index + 3] == da.MENU_UP_KEY:
                    highlight = max(0, highlight - 1)
                    os.write(write_fd, _render_menu(highlight))
                    index += 3
                elif chunk[index:index + 3] == da.MENU_DOWN_KEY:
                    highlight = min(len(_MENU_ROWS) - 1, highlight + 1)
                    os.write(write_fd, _render_menu(highlight))
                    index += 3
                elif chunk[index:index + 1] == da.MENU_ENTER_KEY:
                    if highlight == arch:
                        os.write(write_fd, handoff)
                        if login is not None:
                            os.write(write_fd, login)
                        booted = True
                    index += 1
                else:
                    # A stray digit (type-ahead) selects and boots nothing.
                    index += 1
            consumed = len(data)
            time.sleep(0.01)
        time.sleep(0.1)
        os.close(write_fd)
    return feeder


class GptTests(unittest.TestCase):
    def test_round_trip_parses_the_approved_roles_and_sizes(self):
        parsed = da.parse_gpt(make_gpt(SIZES))
        self.assertEqual(5, len(parsed["partitions"]))
        da.compare_gpt_layout(parsed, SIZES)
        ordered = sorted(
            parsed["partitions"], key=lambda item: item["first_lba"])
        self.assertEqual(
            [guid for _role, guid in EXPECTED],
            [item["type_guid"] for item in ordered])
        self.assertEqual(
            [size * MIB for size in SIZES],
            [item["size_bytes"] for item in ordered])

    def test_gpt_digest_is_deterministic_and_tamper_evident(self):
        first = da.parse_gpt(make_gpt(SIZES))["entries_sha256"]
        second = da.parse_gpt(make_gpt(SIZES))["entries_sha256"]
        self.assertEqual(first, second)
        moved = da.parse_gpt(
            make_gpt([1024, 16, 186098, 72955, 2048]))["entries_sha256"]
        self.assertNotEqual(first, moved)

    def test_missing_signature_is_rejected(self):
        raw = bytearray(make_gpt(SIZES))
        raw[da.SECTOR] = 0
        with self.assertRaisesRegex(RuntimeError, "signature"):
            da.parse_gpt(bytes(raw))

    def test_corrupted_entry_array_fails_its_crc(self):
        raw = bytearray(make_gpt(SIZES))
        raw[2 * da.SECTOR + 40] ^= 0xFF
        with self.assertRaisesRegex(RuntimeError, "CRC"):
            da.parse_gpt(bytes(raw))

    def test_corrupted_header_fails_its_crc(self):
        raw = bytearray(make_gpt(SIZES))
        raw[da.SECTOR + 24] ^= 0xFF
        with self.assertRaisesRegex(RuntimeError, "header CRC"):
            da.parse_gpt(bytes(raw))

    def test_layout_comparison_rejects_wrong_sizes_and_roles(self):
        parsed = da.parse_gpt(make_gpt(SIZES))
        with self.assertRaisesRegex(RuntimeError, "size differs"):
            da.compare_gpt_layout(parsed, [1024, 16, 186098, 72957, 2048])
        swapped = [guid for _role, guid in EXPECTED]
        swapped[2], swapped[3] = swapped[3], swapped[2]
        parsed = da.parse_gpt(make_gpt(SIZES, swapped))
        with self.assertRaisesRegex(RuntimeError, "role"):
            da.compare_gpt_layout(parsed, SIZES)


class AuditTests(unittest.TestCase):
    def command(self, overlay: Path) -> list:
        return [
            "qemu-system-x86_64", "-nodefaults", "-display", "none",
            "-serial", "stdio",
            "-drive", "if=pflash,format=raw,readonly=on,file=/f/CODE.fd",
            "-drive", "if=pflash,format=raw,file=/f/VARS.fd",
            "-boot", "order=c,menu=off",
            "-monitor", "none",
            "-qmp", "unix:/tmp/telos-db/db.qmp,server=on,wait=off",
            "-device", "VGA",
            "-drive",
            f"if=none,id=osdisk,format=qcow2,cache=none,file={overlay}",
            "-device", "nvme,drive=osdisk,serial=TELOS-WIN-0001",
        ]

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.overlay = Path(self.temporary.name) / "dualboot.qcow2"
        self.overlay.write_bytes(b"overlay")

    def test_disk_only_cold_boot_is_accepted(self):
        da.audit_dualboot_boot_boundary(
            self.command(self.overlay.resolve()), disk=self.overlay,
            serial="TELOS-WIN-0001")

    def test_any_network_device_is_rejected(self):
        for extra in (
            ["-netdev", "socket,id=factory,connect=127.0.0.1:31415"],
            ["-nic", "user"],
            ["-device", "e1000e,netdev=factory"],
        ):
            command = self.command(self.overlay.resolve()) + extra
            with self.subTest(extra=extra), self.assertRaisesRegex(
                    RuntimeError, "forbidden"):
                da.audit_dualboot_boot_boundary(
                    command, disk=self.overlay, serial="TELOS-WIN-0001")

    def test_installation_media_is_rejected(self):
        command = self.command(self.overlay.resolve()) + [
            "-drive", "if=none,id=media,media=cdrom,readonly=on,file=/x.iso"]
        with self.assertRaisesRegex(RuntimeError, "media=cdrom"):
            da.audit_dualboot_boot_boundary(
                command, disk=self.overlay, serial="TELOS-WIN-0001")

    def test_the_nvme_must_be_cold_plugged_with_the_authorized_serial(self):
        command = self.command(self.overlay.resolve())
        del command[-2:]
        with self.assertRaisesRegex(RuntimeError, "one cold-plugged NVMe"):
            da.audit_dualboot_boot_boundary(
                command, disk=self.overlay, serial="TELOS-WIN-0001")
        wrong = self.command(self.overlay.resolve())
        wrong[-1] = "nvme,drive=osdisk,serial=OTHER-0002"
        with self.assertRaisesRegex(RuntimeError, "authorized overlay and"):
            da.audit_dualboot_boot_boundary(
                wrong, disk=self.overlay, serial="TELOS-WIN-0001")

    def test_the_display_device_is_required_and_bounded(self):
        # screendump needs a display device (with -nodefaults there is none
        # and the live runs retained zero frames); the audit requires
        # exactly one VGA and refuses any further device.
        command = self.command(self.overlay.resolve())
        missing = [item for item in command if item != "VGA"]
        missing.remove("-device")
        with self.assertRaisesRegex(RuntimeError, "one VGA display"):
            da.audit_dualboot_boot_boundary(
                missing, disk=self.overlay, serial="TELOS-WIN-0001")
        doubled = self.command(self.overlay.resolve()) + ["-device", "VGA"]
        with self.assertRaisesRegex(RuntimeError, "one VGA display"):
            da.audit_dualboot_boot_boundary(
                doubled, disk=self.overlay, serial="TELOS-WIN-0001")

    def test_boot_order_must_pin_the_disk(self):
        command = [
            "order=n,menu=off" if item == "order=c,menu=off" else item
            for item in self.command(self.overlay.resolve())
        ]
        with self.assertRaisesRegex(RuntimeError, "order=c"):
            da.audit_dualboot_boot_boundary(
                command, disk=self.overlay, serial="TELOS-WIN-0001")

    def test_a_second_writable_disk_is_rejected(self):
        command = self.command(self.overlay.resolve()) + [
            "-drive", "if=none,id=extra,format=qcow2,file=/x.qcow2"]
        with self.assertRaisesRegex(RuntimeError, "exactly one writable"):
            da.audit_dualboot_boot_boundary(
                command, disk=self.overlay, serial="TELOS-WIN-0001")

    def test_bootindex_and_missing_nodefaults_are_rejected(self):
        command = self.command(self.overlay.resolve())
        command[-1] += ",bootindex=1"
        with self.assertRaisesRegex(RuntimeError, "bootindex"):
            da.audit_dualboot_boot_boundary(
                command, disk=self.overlay, serial="TELOS-WIN-0001")
        command = [
            item for item in self.command(self.overlay.resolve())
            if item != "-nodefaults"
        ]
        with self.assertRaisesRegex(RuntimeError, "defaults"):
            da.audit_dualboot_boot_boundary(
                command, disk=self.overlay, serial="TELOS-WIN-0001")

    def test_generated_command_passes_its_own_audit(self):
        variables = Path(self.temporary.name) / "OVMF_VARS.fd"
        variables.write_bytes(b"vars")
        command = da.qemu_dualboot_command(
            disk=self.overlay, variables=variables,
            qmp_socket=Path("/tmp/telos-db-test/db.qmp"),
            serial="TELOS-WIN-0001")
        self.assertNotIn("-netdev", command)
        self.assertEqual(
            Path("/tmp/telos-db-test/db.qmp"),
            da._qmp_socket_path(command))


class PrepareTests(unittest.TestCase):
    def gate7(self, root: Path) -> Path:
        bundle = root / "gate7"
        bundle.mkdir(mode=0o700)
        (bundle / "arch.qcow2").write_bytes(b"gate7-disk")
        # The post-install OVMF variables carrying the installer-authored
        # NVRAM; the default prepare must consume exactly these.
        (bundle / "OVMF_VARS.fd").write_bytes(b"gate7-installed-vars")
        (bundle / "evidence").mkdir(mode=0o700)
        (bundle / "evidence" / "result.json").write_text(json.dumps({
            "schema": 1, "status": "observed",
            "phase": "arch-installed-windows-preserved",
        }))
        (root / "windows.qcow2").write_bytes(b"windows-base")
        return bundle

    def fake_qemu_img(self, root: Path):
        def run(command, **_kwargs):
            if command[:2] == ["qemu-img", "info"]:
                return mock.Mock(stdout=json.dumps({
                    "format": "qcow2",
                    "virtual-size": 256 * GIB,
                    "backing-filename": str(root / "windows.qcow2"),
                    "full-backing-filename": str(root / "windows.qcow2"),
                }))
            if command[:2] == ["qemu-img", "create"]:
                Path(command[-1]).write_bytes(b"overlay")
                return mock.Mock(stdout="")
            raise AssertionError(f"unexpected subprocess: {command}")
        return run

    def arguments(self, root: Path, bundle: Path, *extra: str):
        return da.parser().parse_args([
            "prepare", "--gate7-bundle", str(bundle),
            "--layout", str(LAYOUT),
            "--workstation-profile", str(WORKSTATION),
            "--run-root", str(root / "runs"), "--apply",
            *extra,
        ])

    def pristine_arguments(self, root: Path, bundle: Path):
        variables = root / "template-vars.fd"
        variables.write_bytes(b"pristine-vars")
        return self.arguments(
            root, bundle, "--pristine-vars", "--ovmf-vars", str(variables))

    def test_gate7_refusals(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with self.assertRaisesRegex(RuntimeError, "directory"):
                da.inspect_gate7_bundle(root / "missing")
            bundle = self.gate7(root)
            (bundle / "evidence" / "result.json").unlink()
            with self.assertRaisesRegex(RuntimeError, "result.json"):
                da.inspect_gate7_bundle(bundle)
            (bundle / "evidence" / "result.json").write_text(json.dumps({
                "schema": 1, "status": "fail", "phase": "starting"}))
            with self.assertRaisesRegex(RuntimeError, "did not prove"):
                da.inspect_gate7_bundle(bundle)
            (bundle / "evidence" / "result.json").write_text(json.dumps({
                "schema": 1, "status": "observed",
                "phase": "arch-installed-windows-preserved"}))
            (bundle / "OVMF_VARS.fd").unlink()
            with self.assertRaisesRegex(
                    RuntimeError, "post-install OVMF variables"):
                da.inspect_gate7_bundle(bundle)
            (bundle / "OVMF_VARS.fd").write_bytes(b"gate7-installed-vars")
            (bundle / "arch.qcow2").unlink()
            with self.assertRaisesRegex(RuntimeError, "missing its installed"):
                da.inspect_gate7_bundle(bundle)

    def test_gate7_disk_must_overlay_the_retained_windows_disk(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            bundle = self.gate7(root)

            def run(command, **_kwargs):
                return mock.Mock(stdout=json.dumps({
                    "format": "qcow2", "virtual-size": 256 * GIB}))

            with mock.patch.object(da.subprocess, "run", side_effect=run):
                with self.assertRaisesRegex(RuntimeError, "overlay the"):
                    da.inspect_gate7_bundle(bundle)

    def test_prepare_writes_a_bounded_prepared_authorization(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            bundle = self.gate7(root)
            arguments = self.arguments(root, bundle)
            with mock.patch.object(
                    da.subprocess, "run",
                    side_effect=self.fake_qemu_img(root)) as spawn, \
                    mock.patch.object(
                        da, "read_gpt_region",
                        return_value=make_gpt(SIZES)), \
                    mock.patch.object(
                        da, "inspect_overlay",
                        side_effect=lambda path: {
                            "path": str(Path(path).resolve()),
                            "format": "qcow2",
                            "backing": str(
                                (bundle / "arch.qcow2").resolve()),
                            "sha256": CONST,
                        }):
                run_dir = da.prepare(arguments)
            self.assertTrue((run_dir / "dualboot.qcow2").is_file())
            self.assertTrue((run_dir / "OVMF_VARS.fd").is_file())
            # The default vars are the gate-7 installed NVRAM, byte for
            # byte, and the authorization records their provenance.
            self.assertEqual(
                b"gate7-installed-vars",
                (run_dir / "OVMF_VARS.fd").read_bytes())
            creates = [
                call.args[0] for call in spawn.call_args_list
                if call.args[0][:2] == ["qemu-img", "create"]
            ]
            self.assertEqual(1, len(creates))
            self.assertIn("-b", creates[0])
            self.assertEqual(
                str((bundle / "arch.qcow2").resolve()),
                creates[0][creates[0].index("-b") + 1])
            authorization = json.loads(
                (run_dir / "authorization.json").read_text())
            self.assertEqual("prepared", authorization["status"])
            self.assertIs(False, authorization["external_access"])
            self.assertIs(False, authorization["pxe"])
            self.assertIs(False, authorization["media"])
            self.assertIs(False, authorization["pristine_vars"])
            authorized = authorization["authorization"]
            self.assertEqual(
                da.VARS_SOURCE_GATE7, authorized["vars_source"])
            self.assertEqual(
                hashlib.sha256(b"gate7-installed-vars").hexdigest(),
                authorized["vars_sha256"])
            self.assertEqual(
                authorized["gate7"]["vars_sha256"],
                authorized["vars_sha256"])
            command = json.loads(
                (run_dir / "qemu-command.json").read_text())["argv"]
            self.assertEqual(
                _digest(command), authorized["qemu_argv_sha256"])
            self.assertEqual(SIZES, authorized["expected_sizes_mib"])
            self.assertEqual(
                5, len(authorized["gpt_baseline"]["partitions"]))
            self.assertEqual("TELOS-WIN-0001", authorized["disk_serial"])
            self.assertEqual(
                CONTRACT["boot_policy"], authorized["boot_policy"])
            da.audit_dualboot_boot_boundary(
                command, disk=run_dir / "dualboot.qcow2",
                serial=authorized["disk_serial"])
            serialized = json.dumps(authorization)
            self.assertNotIn("password", serialized.lower())

    def test_pristine_vars_escape_hatch_is_flagged_in_authorization(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            bundle = self.gate7(root)
            arguments = self.pristine_arguments(root, bundle)
            with mock.patch.object(
                    da.subprocess, "run",
                    side_effect=self.fake_qemu_img(root)), \
                    mock.patch.object(
                        da, "read_gpt_region",
                        return_value=make_gpt(SIZES)), \
                    mock.patch.object(
                        da, "inspect_overlay",
                        side_effect=lambda path: {
                            "path": str(Path(path).resolve()),
                            "format": "qcow2",
                            "backing": str(
                                (bundle / "arch.qcow2").resolve()),
                            "sha256": CONST,
                        }):
                run_dir = da.prepare(arguments)
            self.assertEqual(
                b"pristine-vars", (run_dir / "OVMF_VARS.fd").read_bytes())
            authorization = json.loads(
                (run_dir / "authorization.json").read_text())
            self.assertIs(True, authorization["pristine_vars"])
            self.assertEqual(
                "pristine",
                authorization["authorization"]["vars_source"])

    def test_ovmf_vars_override_requires_the_pristine_flag(self):
        # Without --pristine-vars an --ovmf-vars override would silently
        # bypass the gate-7 installed NVRAM; prepare refuses it instead.
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            bundle = self.gate7(root)
            variables = root / "template-vars.fd"
            variables.write_bytes(b"pristine-vars")
            arguments = self.arguments(
                root, bundle, "--ovmf-vars", str(variables))
            with mock.patch.object(
                    da.subprocess, "run",
                    side_effect=self.fake_qemu_img(root)):
                with self.assertRaisesRegex(
                        RuntimeError, "requires\\s+--pristine-vars"):
                    da.prepare(arguments)
            self.assertEqual([], list((root / "runs").iterdir()))

    def test_prepare_removes_its_run_directory_on_failure(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            bundle = self.gate7(root)
            arguments = self.arguments(root, bundle)
            wrong = make_gpt([1024, 16, 186098, 72955, 2048])
            with mock.patch.object(
                    da.subprocess, "run",
                    side_effect=self.fake_qemu_img(root)), \
                    mock.patch.object(
                        da, "read_gpt_region", return_value=wrong):
                with self.assertRaisesRegex(RuntimeError, "size differs"):
                    da.prepare(arguments)
            self.assertEqual([], list((root / "runs").iterdir()))


class ObserveBootTests(unittest.TestCase):
    def _observe(self, mode, feeder, *, timeout=10.0, frames=False,
                 qmp=None, **overrides):
        read_fd, write_fd = os.pipe()
        stdin = _Recorder()
        process = _FakeProcess(read_fd, stdin)
        if qmp is None:
            qmp = _FakeQmp()
        worker = threading.Thread(target=feeder, args=(write_fd, stdin))
        worker.start()
        try:
            with tempfile.TemporaryDirectory() as temporary:
                frames_dir = None
                if frames:
                    frames_dir = Path(temporary) / "frames"
                    frames_dir.mkdir()
                observation = da.observe_boot(
                    process, Path(temporary) / "serial.log", mode=mode,
                    qmp=qmp, frames_dir=frames_dir, timeout=timeout,
                    quiesce=overrides.pop("quiesce", 0.3),
                    confirm=overrides.pop("confirm", 0.2),
                    login_wait=overrides.pop("login_wait", 0.3),
                    frame_interval=overrides.pop("frame_interval", 0.05),
                    nav_interval=overrides.pop("nav_interval", 0.05),
                    **overrides)
        finally:
            worker.join()
            os.close(read_fd)
        return observation, stdin, qmp

    def test_windows_default_boot_is_observed_without_any_input(self):
        def feeder(write_fd, _stdin):
            os.write(write_fd, BDS_LINUX)
            for _ in range(3):
                os.write(write_fd, MENU)
                time.sleep(0.05)
            # Silence: the default entry hands off to Windows, which prints
            # nothing to serial.  The pipe stays open like a live guest.
            time.sleep(0.8)
            os.close(write_fd)

        observation, stdin, _qmp = self._observe(
            "windows-default", feeder, frames=True)
        self.assertIsNotNone(observation.menu_first)
        self.assertEqual(
            [da.MENU_ARCH_ENTRY, da.MENU_WINDOWS_ENTRY,
             da.MENU_FIRMWARE_ENTRY],
            observation.entries)
        self.assertEqual(NVRAM_LINUX_LABEL, observation.firmware_entry)
        self.assertIsNone(observation.selection)
        self.assertIsNone(observation.kernel_handoff_at)
        self.assertIsNone(observation.login_prompt_at)
        self.assertTrue(observation.guest_running)
        self.assertGreaterEqual(observation.frames, 1)
        self.assertEqual(b"", bytes(stdin.data))
        self.assertIsNotNone(observation.measured_menu_seconds)

    def test_firmware_log_text_never_counts_as_a_rendered_menu(self):
        # The live boot-2 regression shape: Windows self-promoted and booted
        # directly, so the only occurrence of a boot-entry label is inside
        # OVMF's BdsDxe log line.  That text must not count as a menu.
        def feeder(write_fd, _stdin):
            os.write(write_fd, BDS_WINDOWS_DIRECT)
            time.sleep(0.4)
            os.close(write_fd)

        observation, stdin, _qmp = self._observe(
            "windows-default", feeder, timeout=1.0)
        self.assertEqual([], observation.entries)
        self.assertIsNone(observation.menu_first)
        self.assertEqual("Windows Boot Manager", observation.firmware_entry)
        self.assertEqual(b"", bytes(stdin.data))

    def test_guest_running_is_sampled_while_awaiting_the_handoff(self):
        # The first live run sampled liveness after the clean shutdown and
        # recorded a false negative.  The feeder flips the guest status to
        # ``shutdown`` after the handoff instant but well before the confirm
        # window closes: only a sample taken while awaiting the handoff can
        # still observe ``running``.
        qmp = _FakeQmp()

        def feeder(write_fd, _stdin):
            os.write(write_fd, BDS_LINUX)
            os.write(write_fd, MENU)
            time.sleep(1.5)
            qmp.status = "shutdown"
            time.sleep(1.5)
            os.close(write_fd)

        observation, _stdin, qmp = self._observe(
            "windows-default", feeder, qmp=qmp,
            quiesce=0.4, confirm=2.5)
        self.assertTrue(observation.guest_running)
        self.assertIn(
            "query-status", [call[0] for call in qmp.calls])

    def test_query_running_reads_the_unwrapped_qmp_return_shape(self):
        # QmpClient.execute returns the unwrapped ``return`` payload, so
        # query-status yields {"status": "running"} directly.  The runner
        # must read status at the top level; the earlier double-unwrap
        # reported every live guest as not running (the live boot-1 false
        # negative).  A process fallback covers a QMP error.
        running = _FakeQmp("running")
        stopped = _FakeQmp("shutdown")
        alive = mock.Mock()
        alive.poll.return_value = None
        self.assertTrue(da._query_running(running, alive))
        self.assertFalse(da._query_running(stopped, alive))

        class _Boom:
            def execute(self, *a, **k):
                raise da.WindowsGuiError("gone")
        self.assertTrue(da._query_running(_Boom(), alive))
        dead = mock.Mock()
        dead.poll.return_value = 0
        self.assertFalse(da._query_running(_Boom(), dead))

    def test_a_linux_handoff_on_the_default_boot_is_recorded(self):
        def feeder(write_fd, _stdin):
            os.write(write_fd, MENU)
            os.write(
                write_fd,
                b"EFI stub: Loaded initrd from LINUX_EFI_INITRD_MEDIA_GUID"
                b" device path\r\n")
            time.sleep(0.8)
            os.close(write_fd)

        observation, stdin, _qmp = self._observe("windows-default", feeder)
        self.assertIsNotNone(observation.kernel_handoff_at)
        self.assertEqual(b"", bytes(stdin.data))

    def test_arch_selection_navigates_to_arch_and_enters(self):
        # Models the live boot-2 systemd-boot: the default highlight is
        # Windows, the runner pauses the countdown and drives the highlight
        # to Arch, then Enter boots it and the EFI-stub handoff appears.
        feeder = systemd_boot_feeder(
            handoff=(
                b"EFI stub: Loaded initrd from LINUX_EFI_INITRD_MEDIA_GUID"
                b" device path\r\n"),
            login=b"\r\ntelos-workstation login: ")
        observation, stdin, _qmp = self._observe("arch-select", feeder)
        keys = bytes(stdin.data)
        # A digit key is never sent — it would only trigger a title
        # type-ahead in systemd-boot and boot nothing.
        self.assertNotIn(b"1", keys)
        # Up moves Windows->Arch, then Enter boots the highlighted Arch row.
        self.assertIn(da.MENU_UP_KEY, keys)
        self.assertIn(da.MENU_ENTER_KEY, keys)
        # Enter is the last key sent — it is what actually boots the entry.
        self.assertTrue(keys.endswith(da.MENU_ENTER_KEY))
        self.assertEqual("1", observation.selection)
        self.assertIsNotNone(observation.selection_at)
        self.assertIsNotNone(observation.kernel_handoff_at)
        self.assertIsNotNone(observation.login_prompt_at)

    def test_arch_selection_only_enters_once_arch_is_highlighted(self):
        # Enter must never be sent while a non-Arch row is highlighted, or
        # it would boot Windows.  With Arch two rows above the default the
        # runner must step up twice and Enter only after Arch is inverse.
        enter_on_wrong: list = []

        base = systemd_boot_feeder(
            handoff=b"Linux version 6.12.0-arch1\r\n", default=2, arch=0)

        def feeder(write_fd, stdin):
            # Wrap the base feeder to assert no Enter arrives on rows 1/2.
            highlight = 2
            os.write(write_fd, BDS_LINUX + _render_menu(highlight))
            consumed = 0
            booted = False
            deadline = time.monotonic() + 8.0
            while time.monotonic() < deadline and not booted:
                data = bytes(stdin.data)
                chunk = data[consumed:]
                index = 0
                while index < len(chunk):
                    if chunk[index:index + 3] == da.MENU_UP_KEY:
                        highlight = max(0, highlight - 1)
                        os.write(write_fd, _render_menu(highlight))
                        index += 3
                    elif chunk[index:index + 3] == da.MENU_DOWN_KEY:
                        highlight = min(2, highlight + 1)
                        os.write(write_fd, _render_menu(highlight))
                        index += 3
                    elif chunk[index:index + 1] == da.MENU_ENTER_KEY:
                        if highlight != 0:
                            enter_on_wrong.append(highlight)
                        else:
                            os.write(
                                write_fd, b"Linux version 6.12.0-arch1\r\n")
                            booted = True
                        index += 1
                    else:
                        index += 1
                consumed = len(data)
                time.sleep(0.01)
            time.sleep(0.1)
            os.close(write_fd)

        observation, stdin, _qmp = self._observe("arch-select", feeder)
        self.assertEqual([], enter_on_wrong)
        self.assertEqual(bytes(stdin.data).count(da.MENU_ENTER_KEY), 1)
        self.assertEqual("1", observation.selection)
        self.assertIsNotNone(observation.kernel_handoff_at)

    def test_arch_selection_without_a_getty_records_the_absence(self):
        feeder = systemd_boot_feeder(
            handoff=b"EFI stub: Booting the kernel\r\n", login=None)
        observation, _stdin, _qmp = self._observe("arch-select", feeder)
        self.assertEqual("1", observation.selection)
        self.assertIsNotNone(observation.kernel_handoff_at)
        self.assertIsNone(observation.login_prompt_at)

    def test_a_digit_keypress_never_boots_and_fails_closed(self):
        # Regression for the live boot-2: if the runner had kept sending a
        # digit, systemd-boot would type-ahead and boot nothing, so no
        # handoff is ever observed and the check honestly fails.  This feeder
        # ignores Enter entirely (as if the runner only sent digits) and the
        # observation must carry no kernel handoff.
        def feeder(write_fd, stdin):
            highlight = 1
            os.write(write_fd, BDS_LINUX + _render_menu(highlight))
            consumed = 0
            deadline = time.monotonic() + 1.0
            while time.monotonic() < deadline:
                data = bytes(stdin.data)
                chunk = data[consumed:]
                index = 0
                while index < len(chunk):
                    if chunk[index:index + 3] in (
                            da.MENU_UP_KEY, da.MENU_DOWN_KEY):
                        highlight = max(0, min(2, highlight + (
                            -1 if chunk[index:index + 3] == da.MENU_UP_KEY
                            else 1)))
                        os.write(write_fd, _render_menu(highlight))
                        index += 3
                    else:
                        # Enter and digits alike boot nothing here.
                        index += 1
                consumed = len(data)
                time.sleep(0.01)
            os.close(write_fd)

        observation, _stdin, _qmp = self._observe(
            "arch-select", feeder, timeout=1.5, login_wait=0.3)
        self.assertIsNone(observation.kernel_handoff_at)

    def test_a_menu_that_never_appears_is_bounded_and_honest(self):
        def feeder(write_fd, _stdin):
            os.write(write_fd, b"BdsDxe: failed to load Boot0001\r\n")
            time.sleep(0.4)
            os.close(write_fd)

        observation, stdin, _qmp = self._observe(
            "windows-default", feeder, timeout=1.0)
        self.assertIsNone(observation.menu_first)
        self.assertIsNone(observation.measured_menu_seconds)
        self.assertEqual(b"", bytes(stdin.data))


class BuildEventsTests(unittest.TestCase):
    def test_happy_observations_pass_the_real_judge(self):
        events = happy_events()
        self.assertEqual(
            list(judge_mod.REQUIRED_CHECKS),
            [event["check"] for event in events])
        self.assertTrue(
            all(event["result"] == "pass" for event in events))
        verdict = judge_mod.judge(CONTRACT, events)
        self.assertEqual("pass", verdict["result"])
        self.assertEqual(8, verdict["checks"])
        self.assertIs(False, verdict["windows_login_proven"])

    def test_menu_titles_come_from_the_arch_second_exports(self):
        # Runner and installer share one source of truth for the rendered
        # titles the acceptance keys on (calibrated against the live boot-1
        # serial), so a title change cannot silently split them.
        self.assertEqual(MENU_ARCH_TITLE, da.MENU_ARCH_ENTRY)
        self.assertEqual(MENU_WINDOWS_TITLE, da.MENU_WINDOWS_ENTRY)
        self.assertEqual(NVRAM_LINUX_LABEL, judge_mod.NVRAM_LINUX_LABEL)
        self.assertEqual(
            da.VARS_SOURCE_GATE7, judge_mod.VARS_SOURCE_GATE7)

    def test_selection_method_is_the_arrow_enter_method(self):
        # The emitted arch-menu-selectable evidence names the proven cursor
        # method (not the type-ahead digit), and the judge validates against
        # the same single source of truth.
        self.assertEqual("menu-arrow-enter", judge_mod.SELECTION_METHOD)
        events = happy_events()
        selectable = next(
            event for event in events
            if event["check"] == "arch-menu-selectable")
        self.assertEqual(
            judge_mod.SELECTION_METHOD, selectable["selection_method"])
        judge_mod.judge(CONTRACT, events)
        # A stale "menu-digit" method is refused by the judge.
        selectable["selection_method"] = "menu-digit"
        with self.assertRaisesRegex(ValueError, "selection method"):
            judge_mod.judge(CONTRACT, events)

    def test_pristine_vars_fail_the_nvram_check(self):
        events = happy_events(vars_source="pristine")
        nvram = next(
            event for event in events
            if event["check"] == "nvram-linux-first")
        self.assertEqual("fail", nvram["result"])
        self.assertEqual("pristine", nvram["vars_source"])
        with self.assertRaisesRegex(ValueError, "did not pass"):
            judge_mod.judge(CONTRACT, events)

    def test_a_missing_vars_source_fails_closed(self):
        events = happy_events(vars_source=None)
        nvram = next(
            event for event in events
            if event["check"] == "nvram-linux-first")
        self.assertEqual("fail", nvram["result"])

    def test_a_wrong_firmware_entry_fails_the_nvram_check(self):
        # The pristine-vars regression shape: OVMF auto-created its own NVMe
        # entry instead of starting the authored Linux Boot Manager.
        boot1 = happy_boot1()
        boot1.firmware_entry = "UEFI QEMU NVMe Ctrl TELOS-WIN-0001 1"
        events = happy_events(boot1=boot1)
        nvram = next(
            event for event in events
            if event["check"] == "nvram-linux-first")
        self.assertEqual("fail", nvram["result"])
        self.assertEqual(
            "UEFI QEMU NVMe Ctrl TELOS-WIN-0001 1", nvram["firmware_entry"])

    def test_an_unrendered_windows_title_fails_the_default_boot_check(self):
        # windows_menu_listed comes only from rendered menu parsing now; an
        # entries list without the Windows title (as in the menuless live
        # boot 2) must fail even when everything else held.
        boot1 = happy_boot1()
        boot1.entries = [da.MENU_ARCH_ENTRY, da.MENU_FIRMWARE_ENTRY]
        events = happy_events(boot1=boot1)
        default = next(
            event for event in events
            if event["check"] == "windows-default-boot")
        self.assertEqual("fail", default["result"])
        self.assertIs(False, default["windows_menu_listed"])

    def test_zero_retained_frames_fail_closed(self):
        # A screendump failure (the live zero-frame runs) must fail the
        # default-boot check and be refused by the judge, never silently
        # pass with frames_retained=0.
        boot1 = happy_boot1()
        boot1.frames = 0
        events = happy_events(boot1=boot1)
        default = next(
            event for event in events
            if event["check"] == "windows-default-boot")
        self.assertEqual("fail", default["result"])
        self.assertEqual(0, default["frames_retained"])
        with self.assertRaisesRegex(ValueError, "did not pass"):
            judge_mod.judge(CONTRACT, events)

    def test_windows_login_is_never_claimed(self):
        events = happy_events()
        default = next(
            event for event in events
            if event["check"] == "windows-default-boot")
        self.assertEqual("boot-observed", default["observation"])
        self.assertIs(False, default["login_proven"])

    def test_a_linux_handoff_fails_the_windows_default_check(self):
        boot1 = happy_boot1()
        boot1.kernel_handoff_at = 104.0
        gpt = da.parse_gpt(make_gpt(SIZES))
        events = da.build_events(
            boot1=boot1, boot2=happy_boot2(), gpt_baseline=gpt,
            gpt_after=gpt, expected_sizes_mib=SIZES,
            vars_source=da.VARS_SOURCE_GATE7)
        default = next(
            event for event in events
            if event["check"] == "windows-default-boot")
        self.assertEqual("fail", default["result"])
        with self.assertRaisesRegex(ValueError, "did not pass"):
            judge_mod.judge(CONTRACT, events)

    def test_a_handoff_outside_the_policy_window_fails(self):
        for last_output in (100.5, 130.0):
            boot1 = happy_boot1()
            boot1.last_output = last_output
            gpt = da.parse_gpt(make_gpt(SIZES))
            events = da.build_events(
                boot1=boot1, boot2=happy_boot2(), gpt_baseline=gpt,
                gpt_after=gpt, expected_sizes_mib=SIZES,
                vars_source=da.VARS_SOURCE_GATE7)
            policy = next(
                event for event in events
                if event["check"] == "five-second-policy")
            with self.subTest(last_output=last_output):
                self.assertEqual("fail", policy["result"])

    def test_an_absent_login_surface_fails_with_its_honest_reason(self):
        boot2 = happy_boot2()
        boot2.login_prompt_at = None
        gpt = da.parse_gpt(make_gpt(SIZES))
        events = da.build_events(
            boot1=happy_boot1(), boot2=boot2, gpt_baseline=gpt,
            gpt_after=gpt, expected_sizes_mib=SIZES,
            vars_source=da.VARS_SOURCE_GATE7)
        surface = next(
            event for event in events
            if event["check"] == "arch-console-login-surface")
        self.assertEqual("fail", surface["result"])
        self.assertIn("ttyS0", surface["reason"])

    def test_stages_that_never_ran_render_not_run(self):
        gpt = da.parse_gpt(make_gpt(SIZES))
        events = da.build_events(
            boot1=happy_boot1(), boot2=None, gpt_baseline=gpt,
            gpt_after=None, expected_sizes_mib=SIZES,
            vars_source=da.VARS_SOURCE_GATE7)
        by_check = {event["check"]: event for event in events}
        self.assertEqual("not-run", by_check["arch-menu-selectable"]["result"])
        self.assertEqual(
            "not-run", by_check["arch-console-login-surface"]["result"])
        self.assertEqual("not-run", by_check["partitions-unchanged"]["result"])
        self.assertEqual("fail", by_check["evidence-complete"]["result"])

    def test_a_changed_partition_table_fails_the_no_damage_check(self):
        baseline = da.parse_gpt(make_gpt(SIZES))
        moved = da.parse_gpt(make_gpt([1024, 16, 186098, 72955, 2048]))
        events = da.build_events(
            boot1=happy_boot1(), boot2=happy_boot2(), gpt_baseline=baseline,
            gpt_after=moved, expected_sizes_mib=SIZES,
            vars_source=da.VARS_SOURCE_GATE7)
        unchanged = next(
            event for event in events
            if event["check"] == "partitions-unchanged")
        self.assertEqual("fail", unchanged["result"])
        self.assertIs(False, unchanged["byte_identical"])
        self.assertIs(False, unchanged["roles_verified"])


class JudgeTests(unittest.TestCase):
    def test_shipped_contract_is_valid(self):
        self.assertEqual([], judge_mod.validate_contract(CONTRACT))

    def test_contract_must_defer_the_unprovable_logins(self):
        contract = json.loads(json.dumps(CONTRACT))
        contract["deferred_checks"] = []
        errors = judge_mod.validate_contract(contract)
        self.assertTrue(
            any("windows-login-driven" in error for error in errors))
        self.assertTrue(
            any("arch-authenticated-login" in error for error in errors))

    def test_out_of_order_evidence_is_rejected(self):
        events = happy_events()
        events[0], events[1] = events[1], events[0]
        with self.assertRaisesRegex(ValueError, "out of order"):
            judge_mod.judge(CONTRACT, events)

    def test_duplicate_and_missing_evidence_are_rejected(self):
        events = happy_events()
        with self.assertRaisesRegex(ValueError, "duplicate"):
            judge_mod.judge(CONTRACT, events + [events[0]])
        with self.assertRaisesRegex(ValueError, "missing evidence"):
            judge_mod.judge(CONTRACT, events[:-1])

    def test_external_access_must_be_proven_false(self):
        events = happy_events()
        events[3]["external_access"] = True
        with self.assertRaisesRegex(ValueError, "external_access"):
            judge_mod.judge(CONTRACT, events)

    def test_a_pass_with_contaminated_measurement_is_rejected(self):
        events = happy_events()
        policy = next(
            event for event in events
            if event["check"] == "five-second-policy")
        policy["measured_seconds"] = 60.0
        with self.assertRaisesRegex(ValueError, "policy bounds"):
            judge_mod.judge(CONTRACT, events)

    def test_login_proven_cannot_contradict_the_observation_level(self):
        events = happy_events()
        default = next(
            event for event in events
            if event["check"] == "windows-default-boot")
        default["login_proven"] = True
        with self.assertRaisesRegex(ValueError, "contradicts"):
            judge_mod.judge(CONTRACT, events)

    def test_mismatched_partition_digests_are_rejected_even_if_passed(self):
        events = happy_events()
        unchanged = next(
            event for event in events
            if event["check"] == "partitions-unchanged")
        unchanged["post_sha256"] = "d" * 64
        with self.assertRaisesRegex(ValueError, "changed across"):
            judge_mod.judge(CONTRACT, events)

    def test_runner_and_judge_agree_on_the_required_checks(self):
        self.assertEqual(
            tuple(CONTRACT["required_checks"]), da.REQUIRED_CHECKS)
        self.assertEqual(
            tuple(CONTRACT["required_checks"]), judge_mod.REQUIRED_CHECKS)
        self.assertEqual("nvram-linux-first", judge_mod.REQUIRED_CHECKS[0])

    def test_nvram_evidence_fields_are_each_fail_closed(self):
        for field, value, message in (
                ("vars_source", "pristine", "gate-7 installed"),
                ("vars_source", None, "gate-7 installed"),
                ("firmware_entry",
                 "UEFI QEMU NVMe Ctrl TELOS-WIN-0001 1",
                 "Linux Boot Manager"),
                ("menu_rendered", False, "render its menu"),
                ("menu_rendered", None, "render its menu"),
        ):
            events = happy_events()
            nvram = next(
                event for event in events
                if event["check"] == "nvram-linux-first")
            nvram[field] = value
            with self.subTest(field=field, value=value):
                with self.assertRaisesRegex(ValueError, message):
                    judge_mod.judge(CONTRACT, events)


class RunTests(unittest.TestCase):
    def bundle(self, root: Path) -> Path:
        root.mkdir(mode=0o700)
        overlay = root / "dualboot.qcow2"
        overlay.write_bytes(b"overlay")
        (root / "OVMF_VARS.fd").write_bytes(b"vars")
        gate7 = root / "arch.qcow2"
        gate7.write_bytes(b"gate7-disk")
        windows = root / "windows.qcow2"
        windows.write_bytes(b"windows-base")
        self.qmp_parent = (
            Path(tempfile.gettempdir())
            / f"telos-dbtest-{secrets.token_hex(4)}")
        command = [
            "qemu-system-x86_64", "-nodefaults", "-display", "none",
            "-serial", "stdio",
            "-drive", "if=pflash,format=raw,readonly=on,file=/f/CODE.fd",
            "-drive", f"if=pflash,format=raw,file={root / 'OVMF_VARS.fd'}",
            "-boot", "order=c,menu=off",
            "-monitor", "none",
            "-qmp", f"unix:{self.qmp_parent}/db.qmp,server=on,wait=off",
            "-device", "VGA",
            "-drive",
            (
                "if=none,id=osdisk,format=qcow2,cache=none,"
                f"file={overlay.resolve()}"
            ),
            "-device", "nvme,drive=osdisk,serial=TELOS-WIN-0001",
        ]
        gpt_baseline = da.parse_gpt(make_gpt(SIZES))
        authorization = {
            "schema": 1,
            "status": "prepared",
            "external_access": False,
            "pxe": False,
            "media": False,
            "authorization": {
                "disk_serial": "TELOS-WIN-0001",
                "overlay": {
                    "path": str(overlay.resolve()), "format": "qcow2",
                    "backing": str(gate7.resolve()), "sha256": CONST,
                },
                "gate7": {
                    "bundle": str(root), "path": str(gate7.resolve()),
                    "sha256": CONST, "virtual_size": 256 * GIB,
                    "backing": str(windows.resolve()),
                    "backing_sha256": CONST,
                    "result_status": "observed",
                    "result_phase": "arch-installed-windows-preserved",
                },
                "expected_sizes_mib": SIZES,
                "gpt_baseline": gpt_baseline,
                "qemu_argv_sha256": _digest(command),
                "layout": {},
                "boot_policy": CONTRACT["boot_policy"],
                "vars_source": da.VARS_SOURCE_GATE7,
                "vars_sha256": CONST,
            },
        }
        (root / "authorization.json").write_text(json.dumps(authorization))
        (root / "qemu-command.json").write_text(
            json.dumps({"schema": 1, "argv": command}))
        return root

    def _overlay(self, root: Path):
        return {
            "path": str((root / "dualboot.qcow2").resolve()),
            "format": "qcow2",
            "backing": str((root / "arch.qcow2").resolve()),
            "sha256": CONST,
        }

    def _mocks(self, root: Path, **extra):
        patches = [
            mock.patch.object(
                da, "inspect_overlay", return_value=self._overlay(root)),
            mock.patch.object(da, "sha256", return_value=CONST),
        ]
        patches.extend(
            mock.patch.object(da, name, **kwargs)
            for name, kwargs in extra.items())
        return patches

    def test_default_is_dry_run(self):
        with tempfile.TemporaryDirectory() as temporary:
            bundle = self.bundle(Path(temporary) / "bundle")
            patches = self._mocks(bundle)
            with patches[0], patches[1]:
                self.assertEqual(
                    0, da.run(bundle, duration=120, apply=False))
            self.assertFalse((bundle / "evidence").exists())

    def test_duration_bounds_are_enforced(self):
        with tempfile.TemporaryDirectory() as temporary:
            bundle = self.bundle(Path(temporary) / "bundle")
            for duration in (5, 20000):
                with self.subTest(duration=duration):
                    with self.assertRaisesRegex(RuntimeError, "duration"):
                        da.run(bundle, duration=duration, apply=True)

    def test_bundle_rejects_group_or_world_access(self):
        with tempfile.TemporaryDirectory() as temporary:
            bundle = self.bundle(Path(temporary) / "bundle")
            bundle.chmod(0o755)
            with self.assertRaisesRegex(RuntimeError, "private"):
                da._bundle(bundle)

    def test_bundle_rejects_changed_command_digest(self):
        with tempfile.TemporaryDirectory() as temporary:
            bundle = self.bundle(Path(temporary) / "bundle")
            authorization = json.loads(
                (bundle / "authorization.json").read_text())
            authorization["authorization"]["qemu_argv_sha256"] = "0" * 64
            (bundle / "authorization.json").write_text(
                json.dumps(authorization))
            patches = self._mocks(bundle)
            with patches[0], patches[1]:
                with self.assertRaisesRegex(RuntimeError, "differs from"):
                    da._bundle(bundle)

    def test_bundle_rejects_a_weakened_authorization(self):
        for key, value in (
                ("status", "run"), ("pxe", True), ("media", True),
                ("external_access", True)):
            with tempfile.TemporaryDirectory() as temporary:
                bundle = self.bundle(Path(temporary) / "bundle")
                authorization = json.loads(
                    (bundle / "authorization.json").read_text())
                authorization[key] = value
                (bundle / "authorization.json").write_text(
                    json.dumps(authorization))
                with self.subTest(key=key), self.assertRaisesRegex(
                        RuntimeError, "prepared|pin"):
                    da._bundle(bundle)

    def test_bundle_rejects_swapped_ovmf_variables(self):
        # A vars swap after prepare (pristine for gate-7-installed) would
        # falsify the judged vars_source claim; the run refuses to boot it.
        with tempfile.TemporaryDirectory() as temporary:
            bundle = self.bundle(Path(temporary) / "bundle")
            target = (bundle / "OVMF_VARS.fd").resolve()

            def by_path(path, target=target):
                return "z" * 64 if Path(path).resolve() == target else CONST

            patches = self._mocks(bundle)
            with patches[0], mock.patch.object(
                    da, "sha256", side_effect=by_path):
                with self.assertRaisesRegex(
                        RuntimeError, "OVMF variables differ"):
                    da._bundle(bundle)

    def test_bundle_rejects_altered_gate7_inputs(self):
        for altered in ("arch.qcow2", "windows.qcow2"):
            with tempfile.TemporaryDirectory() as temporary:
                bundle = self.bundle(Path(temporary) / "bundle")
                target = (bundle / altered).resolve()

                def by_path(path, target=target):
                    return "z" * 64 if Path(path).resolve() == target else CONST

                patches = self._mocks(bundle)
                with patches[0], mock.patch.object(
                        da, "sha256", side_effect=by_path):
                    with self.subTest(altered=altered):
                        with self.assertRaisesRegex(
                                RuntimeError, "differs from authorization"):
                            da._bundle(bundle)

    def test_run_completes_and_self_judges_honest_observations(self):
        with tempfile.TemporaryDirectory() as temporary:
            bundle = self.bundle(Path(temporary) / "bundle")

            def fake_boot(command, *, processes, label, evidence,
                          qmp_socket, mode, timeout):
                self.assertLessEqual(timeout, 120)
                (evidence / f"{label}-serial.log").write_bytes(b"transcript")
                if label == "boot1":
                    self.assertEqual("windows-default", mode)
                    return happy_boot1(), True
                self.assertEqual("arch-select", mode)
                return happy_boot2(), True

            patches = self._mocks(
                bundle,
                _boot_once={"side_effect": fake_boot},
                read_gpt_region={"return_value": make_gpt(SIZES)})
            with patches[0], patches[1], patches[2], patches[3]:
                self.assertEqual(0, da.run(bundle, duration=240, apply=True))
            evidence = bundle / "evidence"
            result = json.loads((evidence / "result.json").read_text())
            self.assertEqual("observed", result["status"])
            self.assertEqual("dualboot-accepted", result["phase"])
            self.assertIs(False, result["windows_login_proven"])
            events = [
                json.loads(line)
                for line in (evidence / da.EVENTS_NAME).read_text().splitlines()
                if line.strip()
            ]
            self.assertEqual(8, len(events))
            judge_mod.judge(CONTRACT, events)
            self.assertFalse(self.qmp_parent.exists())

    def test_an_unproven_check_fails_the_run_but_keeps_the_evidence(self):
        with tempfile.TemporaryDirectory() as temporary:
            bundle = self.bundle(Path(temporary) / "bundle")
            silent = happy_boot2()
            silent.login_prompt_at = None

            def fake_boot(command, *, processes, label, evidence,
                          qmp_socket, mode, timeout):
                (evidence / f"{label}-serial.log").write_bytes(b"transcript")
                return (happy_boot1(), True) if label == "boot1" \
                    else (silent, True)

            patches = self._mocks(
                bundle,
                _boot_once={"side_effect": fake_boot},
                read_gpt_region={"return_value": make_gpt(SIZES)})
            with patches[0], patches[1], patches[2], patches[3]:
                with self.assertRaisesRegex(ValueError, "did not pass"):
                    da.run(bundle, duration=240, apply=True)
            evidence = bundle / "evidence"
            result = json.loads((evidence / "result.json").read_text())
            self.assertEqual("fail", result["status"])
            self.assertEqual("judging", result["phase"])
            events = [
                json.loads(line)
                for line in (evidence / da.EVENTS_NAME).read_text().splitlines()
                if line.strip()
            ]
            surface = next(
                event for event in events
                if event["check"] == "arch-console-login-surface")
            self.assertEqual("fail", surface["result"])

    def test_result_json_is_written_even_when_a_boot_explodes(self):
        with tempfile.TemporaryDirectory() as temporary:
            bundle = self.bundle(Path(temporary) / "bundle")
            patches = self._mocks(
                bundle,
                _boot_once={"side_effect": RuntimeError("qemu exploded")})
            with patches[0], patches[1], patches[2]:
                with self.assertRaisesRegex(RuntimeError, "qemu exploded"):
                    da.run(bundle, duration=240, apply=True)
            result = json.loads(
                (bundle / "evidence" / "result.json").read_text())
            self.assertEqual("fail", result["status"])
            self.assertEqual("boot-windows-default", result["phase"])
            self.assertEqual("RuntimeError", result["error_type"])
            self.assertFalse(self.qmp_parent.exists())

    def test_a_second_run_refuses_existing_evidence(self):
        with tempfile.TemporaryDirectory() as temporary:
            bundle = self.bundle(Path(temporary) / "bundle")
            (bundle / "evidence").mkdir(mode=0o700)
            patches = self._mocks(bundle)
            with patches[0], patches[1]:
                with self.assertRaisesRegex(RuntimeError, "already has"):
                    da.run(bundle, duration=240, apply=True)

    def test_shutdown_guest_is_bounded_and_honest(self):
        qmp = _FakeQmp()
        process = mock.Mock()
        process.poll.side_effect = [None, None, 0]
        self.assertTrue(da.shutdown_guest(qmp, process, timeout=5))
        self.assertIn(
            "system_powerdown", [call[0] for call in qmp.calls])
        stubborn = mock.Mock()
        stubborn.poll.return_value = None
        self.assertFalse(da.shutdown_guest(_FakeQmp(), stubborn, timeout=0.3))

    def test_sanitize_log_redacts_and_bounds(self):
        with tempfile.TemporaryDirectory() as temporary:
            log = Path(temporary) / "serial.log"
            log.write_bytes(b"x" * 100 + b"\npassword: should-not-survive\n")
            da._sanitize_log(log, maximum=40)
            self.assertLessEqual(log.stat().st_size, 40)
            self.assertNotIn(b"should-not-survive", log.read_bytes())


if __name__ == "__main__":
    unittest.main()
