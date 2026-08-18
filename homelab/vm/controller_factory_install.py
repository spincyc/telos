#!/usr/bin/env python3
"""Unattended serial protocol for a disposable Controller installation."""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import tempfile
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO, Callable

try:
    from .controller_factory import FactoryBundle
    from .serial_automation import SerialAutomation, SerialAutomationError
except ImportError:
    from controller_factory import FactoryBundle
    from serial_automation import SerialAutomation, SerialAutomationError

DISK_SERIAL = "TELOS-BOOTSTRAP-DC1"


def arch_volume_label(iso: Path) -> str:
    """The Arch ISO's volume identifier, which ``archisolabel=`` must carry.

    Module-level because two callers need it: the disposable acceptance
    controller below, and ``bootstrap_install``, which boots the same kernel
    and initramfs against the *canonical* image. One reader, one refusal.
    """
    volume = subprocess.run(
        ["xorriso", "-indev", str(iso), "-pvd_info"],
        check=True, capture_output=True, text=True)
    match = re.search(r"^\s*Volume id\s*:\s*'([A-Z0-9_]{1,32})'\s*$",
                      volume.stdout + volume.stderr, re.MULTILINE)
    if not match:
        raise RuntimeError("Arch ISO has no safe volume identifier")
    return match.group(1)


def extract_arch_boot_files(
    iso: Path, kernel: Path, initramfs: Path,
) -> None:
    """Copy the ISO's kernel and initramfs out so QEMU can boot them directly.

    Direct kernel boot is what removes the manual ``e`` edit at the boot menu:
    ``console=ttyS0,115200n8`` goes on the command line here instead of being
    typed by a person at a graphical prompt they cannot see.
    """
    for source, destination in (
        ("/arch/boot/x86_64/vmlinuz-linux", kernel),
        ("/arch/boot/x86_64/initramfs-linux.img", initramfs),
    ):
        subprocess.run(
            ["xorriso", "-osirrox", "on", "-indev", str(iso),
             "-extract", source, str(destination)],
            check=True, capture_output=True)


def isolated_qemu_prefix(code: Path, vars_: Path, *, name: str) -> list[str]:
    """The shared, network-free QEMU preamble for an offline guest."""
    return [
        "qemu-system-x86_64", "-nodefaults",
        "-name", name,
        "-machine", "q35,accel=kvm", "-cpu", "host",
        "-smp", "4", "-m", "8192",
        "-display", "none", "-monitor", "none", "-serial", "stdio",
        "-drive",
        f"if=pflash,format=raw,readonly=on,file={code}",
        "-drive", f"if=pflash,format=raw,file={vars_}",
    ]


def direct_kernel_install_command(
    prefix: list[str],
    *,
    disk: Path,
    disk_format: str,
    kernel: Path,
    initramfs: Path,
    arch_label: str,
    arch_iso: Path,
    seed_iso: Path,
    disk_serial: str = DISK_SERIAL,
) -> list[str]:
    """One argv shape for both installation targets.

    The disposable acceptance controller writes a temporary raw disk and the
    canonical driver writes ``bootstrap-dc.qcow2``; nothing else about the
    boot differs, so ``disk`` and ``disk_format`` are the only seam. Keeping
    one shape is the point: an acceptance run that passes proves the argv the
    operator's real installation uses.
    """
    command = prefix + [
        "-nic", "none",
        "-kernel", str(kernel),
        "-initrd", str(initramfs),
        "-append",
        "archisobasedir=arch "
        f"archisolabel={arch_label} console=ttyS0,115200n8",
        "-drive",
        f"if=none,id=osdisk,format={disk_format},cache=none,file={disk}",
        "-device",
        f"virtio-blk-pci,drive=osdisk,serial={disk_serial},bootindex=2",
        "-device", "virtio-scsi-pci,id=mediabus",
    ]
    for identifier, media, index in (
        ("installmedia", arch_iso, 1),
        ("seedmedia", seed_iso, 3),
    ):
        command += [
            "-drive",
            f"if=none,id={identifier},media=cdrom,readonly=on,file={media}",
            "-device",
            f"scsi-cd,bus=mediabus.0,drive={identifier},bootindex={index}",
        ]
    return command


class DisposableFactoryController:
    """Fresh disk and firmware used only for one local factory cycle."""

    def __init__(
        self,
        arch_iso: Path,
        seed_iso: Path,
        *,
        run_root: Path | None = None,
    ) -> None:
        self.arch_iso = Path(arch_iso).resolve()
        self.seed_iso = Path(seed_iso).resolve()
        self._temporary = run_root is None
        self.root = (
            Path(tempfile.mkdtemp(prefix="telos-factory-controller-"))
            if run_root is None else Path(run_root).resolve())
        self.disk = self.root / "controller.raw"
        self.vars = self.root / "OVMF_VARS.fd"
        self.kernel = self.root / "vmlinuz-linux"
        self.initramfs = self.root / "initramfs-linux.img"
        self.arch_label = ""
        self.code = Path("/usr/share/edk2/x64/OVMF_CODE.4m.fd")
        self.prepared = False

    def prepare(self) -> "DisposableFactoryController":
        for media in (self.arch_iso, self.seed_iso):
            if not media.is_file() or media.is_symlink():
                raise ValueError(f"factory media is not a regular file: {media}")
        candidates = (
            (Path("/usr/share/edk2/x64/OVMF_CODE.4m.fd"),
             Path("/usr/share/edk2/x64/OVMF_VARS.4m.fd")),
            (Path("/usr/share/edk2-ovmf/x64/OVMF_CODE.fd"),
             Path("/usr/share/edk2-ovmf/x64/OVMF_VARS.fd")),
        )
        pair = next(
            ((code, vars_) for code, vars_ in candidates
             if code.is_file() and vars_.is_file()), None)
        if pair is None:
            raise RuntimeError("OVMF firmware was not found")
        if not shutil.which("qemu-img"):
            raise RuntimeError("qemu-img was not found")
        self.code, template = pair
        self.root.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.root.chmod(0o700)
        subprocess.run(
            ["qemu-img", "create", "-f", "raw", str(self.disk), "80G"],
            check=True, capture_output=True)
        shutil.copy2(template, self.vars)
        self.arch_label = arch_volume_label(self.arch_iso)
        extract_arch_boot_files(self.arch_iso, self.kernel, self.initramfs)
        os.chmod(self.disk, 0o600)
        os.chmod(self.vars, 0o600)
        os.chmod(self.kernel, 0o600)
        os.chmod(self.initramfs, 0o600)
        self.prepared = True
        return self

    def _base(self) -> list[str]:
        if not self.prepared:
            raise RuntimeError("factory controller state is not prepared")
        return isolated_qemu_prefix(
            self.code.resolve(), self.vars.resolve(),
            name="telos-factory-controller")

    def install_command(self) -> list[str]:
        return direct_kernel_install_command(
            self._base(),
            disk=self.disk.resolve(), disk_format="raw",
            kernel=self.kernel.resolve(),
            initramfs=self.initramfs.resolve(),
            arch_label=self.arch_label,
            arch_iso=self.arch_iso, seed_iso=self.seed_iso)

    @staticmethod
    def _factory_media(path: Path) -> Path:
        media = Path(path).resolve()
        if not media.is_file() or media.is_symlink():
            raise ValueError("factory bundle is not a regular file")
        return media

    def convergence_command(
        self, factory_iso: Path, port: int,
    ) -> list[str]:
        factory_iso = self._factory_media(factory_iso)
        if port < 1 or port > 65535:
            raise ValueError("invalid simulation gateway port")
        return self._base() + [
            "-drive",
            f"if=virtio,format=raw,cache=none,file={self.disk.resolve()}",
            "-device", "virtio-scsi-pci,id=mediabus",
            "-drive",
            "if=none,id=factorymedia,media=cdrom,readonly=on,"
            f"file={factory_iso}",
            "-device", "scsi-cd,bus=mediabus.0,drive=factorymedia",
            "-netdev", f"socket,id=simnet,connect=127.0.0.1:{port}",
            "-device",
            "virtio-net-pci,netdev=simnet,mac=52:54:00:11:11:12",
        ]

    def close(self) -> None:
        for path in (self.disk, self.vars, self.kernel, self.initramfs):
            path.unlink(missing_ok=True)
        if self._temporary and self.root.is_dir():
            self.root.rmdir()
        self.prepared = False

    def __enter__(self) -> "DisposableFactoryController":
        return self.prepare()

    def __exit__(self, *_exc: object) -> None:
        self.close()


class RedactedSerialCapture:
    """Bounded diagnostic reader that never writes unredacted bytes."""

    def __init__(
        self,
        source: BinaryIO,
        path: Path,
        secrets_: tuple[bytes, ...],
        *,
        limit: int = 1024 * 1024,
    ) -> None:
        self.source = source
        self.path = Path(path)
        self.secrets = tuple(value for value in secrets_ if value)
        if not self.secrets or any(b"\n" in value for value in self.secrets):
            raise ValueError("diagnostic redaction requires non-line secrets")
        if limit < max(map(len, self.secrets)) * 2:
            raise ValueError("diagnostic limit is too small for safe redaction")
        if self.path.is_symlink():
            raise ValueError("diagnostic path must not be a symlink")
        self.limit = limit
        self.raw = b""
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.path.parent.chmod(0o700)
        self._write()

    def _write(self) -> None:
        safe = self.raw
        for value in self.secrets:
            safe = safe.replace(value, b"[REDACTED]")
        safe = safe[-self.limit:]
        with self.path.open("wb") as stream:
            os.fchmod(stream.fileno(), 0o600)
            stream.write(safe)

    def read1(self, size: int = -1) -> bytes:
        read = getattr(self.source, "read1", self.source.read)
        chunk = read(size)
        if chunk:
            # Keep enough history to redact a value split across reads.  The
            # raw bytes exist only in memory and are never written.
            self.raw = (self.raw + chunk)[-(self.limit + max(
                map(len, self.secrets))):]
            self._write()
        return chunk

    def read(self, size: int = -1) -> bytes:
        return self.read1(size)

    def fileno(self) -> int:
        return self.source.fileno()


@dataclass(frozen=True)
class FactoryInstallResult:
    installed: bool
    powered_off: bool
    events: tuple[str, ...]


@dataclass(frozen=True)
class FactoryConvergenceResult:
    converged: bool
    powered_off: bool
    events: tuple[str, ...]


class FactoryConvergenceSerial:
    """Log into the fresh guest and execute the read-only factory payload."""

    def __init__(
        self,
        reader: BinaryIO,
        writer: BinaryIO,
        password: bytes,
        authorization_nonce: str,
        *,
        timeout: float = 1800,
        clock: Callable[[], float] = time.monotonic,
        progress: Callable[[str], None] | None = None,
    ) -> None:
        if not password or b"\n" in password or b"\r" in password:
            raise ValueError("factory password must be one non-empty line")
        if not re.fullmatch(r"[0-9a-f]{64}", authorization_nonce):
            raise ValueError("authorization nonce must be 64 lowercase hex digits")
        self.password = password
        self.authorization_nonce = authorization_nonce
        self.progress = progress or (lambda _stage: None)
        self.console = SerialAutomation(
            reader, writer, None, timeout=timeout, clock=clock)

    def run(self) -> FactoryConvergenceResult:
        console = self.console
        token = uuid.uuid4().hex.encode()
        console._wait(
            rb"(?:^|\n)bootstrap-dc login:\s*$", "login-prompt")
        console._send(b"local-rescue", "username-sent")
        console._wait(rb"(?:^|\n)Password:\s*$", "login-password-prompt")
        console._send(self.password, "login-password-sent")
        console._wait(rb"(?:^|\n)[^\n]*\$\s*$", "shell-prompt")
        prompt = b"__TELOS_FACTORY_SUDO_" + token + b"__"
        result = b"__TELOS_FACTORY_RC_" + token + b"="
        payload = FactoryBundle.guest_command(
            self.authorization_nonce).encode()
        command = (
            b"sudo -S -p '" + prompt + b"' /usr/bin/bash -c '"
            + payload + b"'; rc=$?; printf '\\n" + result
            + b"%s\\n' \"$rc\"")
        console._send(command, "factory-command-sent")
        # The serial TTY echoes the command, including the value supplied to
        # sudo -p.  Match only the standalone prompt at the end of a line so
        # the credential cannot be sent early and consumed by the login shell.
        console._wait(
            rb"(?:^|\n)" + re.escape(prompt) + rb"\s*$",
            "sudo-password-prompt")
        console._send(self.password, "sudo-password-sent")
        while True:
            outcome = console._wait(
                rb"(?:^|\n)(?:TELOS FACTORY STEP ([a-z-]+)|"
                rb"TELOS FACTORY CONTROLLER PASS|"
                + re.escape(result) + rb"([0-9]+))\s*\n",
                "factory-progress-observed")
            if outcome.group(1) is None:
                break
            stage = outcome.group(1).decode()
            console.events.append("factory-step-" + stage)
            self.progress(stage)
        if outcome.group(2) is not None:
            raise RuntimeError(
                f"factory convergence returned {int(outcome.group(2))}")
        console.events.append("factory-pass-observed")
        match = console._wait(
            rb"(?:^|\n)" + re.escape(result) + rb"([0-9]+)\s*(?:\n|$)",
            "factory-return-code-observed")
        if int(match.group(1)) != 0:
            raise RuntimeError("factory printed PASS but returned nonzero")
        console._wait(rb"(?:^|\n)[^\n]*\$\s*$", "post-factory-shell")
        console._send(
            b"sudo -n systemctl poweroff", "poweroff-command-sent")
        console._wait(
            rb"(?:Reached target System Power Off|reboot: Power down)",
            "poweroff-observed")
        return FactoryConvergenceResult(
            True, True, tuple(console.events))


class FactoryInstallSerial:
    """Drive the stock Arch ISO and offline seed without recording secrets."""

    def __init__(
        self,
        reader: BinaryIO,
        writer: BinaryIO,
        password: bytes,
        *,
        confirmation: bytes | None = None,
        timeout: float = 1200,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        if not password or b"\n" in password or b"\r" in password:
            raise ValueError("factory password must be one non-empty line")
        if confirmation is not None and (
                not confirmation
                or b"\n" in confirmation or b"\r" in confirmation):
            raise ValueError(
                "the erasure confirmation must be one non-empty line")
        self.password = password
        # ADR 0058: the acceptance matrix answers the confirmation itself,
        # "the way a person would". That is what the default is for, and it is
        # only ever reached by the disposable, temporary-disk path.
        # ``bootstrap_install`` targets the *canonical* image and always
        # supplies this, so the phrase that erases the real Controller disk
        # exists nowhere but in what the operator typed.
        self.confirmation = (
            f"ERASE {DISK_SERIAL}".encode()
            if confirmation is None else confirmation)
        self.console = SerialAutomation(
            reader, writer, None, timeout=timeout, clock=clock)

    def run(self) -> FactoryInstallResult:
        console = self.console
        token = ("__TELOS_SEED_" + uuid.uuid4().hex + "__").encode()
        console._wait(
            rb"(?:^|\n)archiso login:\s*$", "archiso-login-prompt")
        console._send(b"root", "archiso-root-username-sent")
        console._wait(
            rb"(?:^|\n)[^\n]*@archiso[^\n]*#\s*$", "archiso-root-ready")
        console._send(
            b"mkdir -p /run/telos-seed; "
            b"mount -L TELOS_SEED /run/telos-seed; "
            b"/run/telos-seed/verify-seed /run/telos-seed && "
            b"printf '\\n" + token + b"\\n'",
            "seed-verify-command-sent",
        )
        console._wait(
            rb"(?:^|\n)seed receipt verified\s*(?:\n|$)",
            "seed-receipt-verified",
        )
        console._wait(
            rb"(?:^|\n)" + re.escape(token) + rb"\s*(?:\n|$)",
            "seed-token-observed",
        )
        console._wait(rb"(?:^|\n)[^\n]*#\s*$", "post-seed-root-ready")
        console._send(
            b"/run/telos-seed/install-controller /run/telos-seed",
            "installer-command-sent",
        )
        console._wait(
            rb"Type ERASE " + re.escape(DISK_SERIAL.encode())
            + rb" to continue:\s*$",
            "disk-erasure-prompt",
        )
        console._send(self.confirmation, "disk-erasure-authorized")
        # A relayed confirmation can be wrong -- the operator typed it -- and
        # the installer answers a mismatch with one ``install-controller:``
        # line and exit 2. Waiting only for the password prompt would turn a
        # typo into a full timeout, so the refusal is matched too and named.
        answered = console._wait(
            rb"New password:\s*$"
            rb"|(?:^|\n)install-controller: (?P<refused>[^\n]*)\n",
            "console-password-prompt",
        )
        if answered.group("refused") is not None:
            raise SerialAutomationError(
                "the installer refused before setting a password: "
                + answered.group("refused").decode("utf-8", "replace"))
        console._send(self.password, "console-password-sent")
        console._wait(
            rb"Retype new password:\s*$", "console-password-confirm-prompt")
        console._send(self.password, "console-password-confirm-sent")
        console._wait(
            rb"(?:^|\n)passwd: password updated successfully\s*(?:\n|$)",
            "console-password-updated",
        )
        console._wait(
            rb"(?:^|\n)Controller installation complete\. "
            rb"Remove both ISOs and reboot\.\s*(?:\n|$)",
            "installation-complete",
        )
        console._wait(rb"(?:^|\n)[^\n]*#\s*$", "post-install-root-ready")
        console._send(b"systemctl poweroff", "poweroff-command-sent")
        console._wait(
            rb"(?:Reached target System Power Off|reboot: Power down)",
            "poweroff-observed",
        )
        return FactoryInstallResult(
            True, True, tuple(console.events))


def _run_qemu(
    command: list[str],
    protocol: FactoryInstallSerial | FactoryConvergenceSerial,
    *,
    timeout: float,
    diagnostic_path: Path | None = None,
    diagnostic_secrets: tuple[bytes, ...] = (),
) -> FactoryInstallResult | FactoryConvergenceResult:
    process = subprocess.Popen(
        command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT, bufsize=0)
    try:
        if process.stdin is None or process.stdout is None:
            raise RuntimeError("QEMU serial pipes were not created")
        reader: BinaryIO = process.stdout
        if diagnostic_path is not None:
            reader = RedactedSerialCapture(
                process.stdout, diagnostic_path, diagnostic_secrets)
        protocol.reader = reader
        protocol.writer = process.stdin
        protocol.console.reader = reader
        protocol.console.writer = process.stdin
        result = protocol.run()
        returncode = process.wait(timeout=timeout)
        if returncode != 0:
            raise RuntimeError(f"QEMU exited with status {returncode}")
        return result
    finally:
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=10)


def run_install(
    state: DisposableFactoryController,
    password: bytes,
    *,
    confirmation: bytes | None = None,
    timeout: float = 1800,
) -> FactoryInstallResult:
    protocol = FactoryInstallSerial(
        # Replaced with QEMU pipes before the protocol starts.
        subprocess.DEVNULL, subprocess.DEVNULL, password,  # type: ignore[arg-type]
        confirmation=confirmation, timeout=timeout)
    result = _run_qemu(
        state.install_command(), protocol, timeout=timeout)
    assert isinstance(result, FactoryInstallResult)
    return result


def run_convergence(
    state: DisposableFactoryController,
    factory_iso: Path,
    gateway_port: int,
    password: bytes,
    authorization_nonce: str,
    *,
    timeout: float = 2400,
    progress: Callable[[str], None] | None = None,
    diagnostic_path: Path | None = None,
    diagnostic_redactions: tuple[bytes, ...] = (),
) -> FactoryConvergenceResult:
    protocol = FactoryConvergenceSerial(
        subprocess.DEVNULL, subprocess.DEVNULL, password,
        authorization_nonce, timeout=timeout,
        progress=progress)  # type: ignore[arg-type]
    result = _run_qemu(
        state.convergence_command(factory_iso, gateway_port),
        protocol, timeout=timeout, diagnostic_path=diagnostic_path,
        diagnostic_secrets=(
            password, authorization_nonce.encode(), *diagnostic_redactions))
    assert isinstance(result, FactoryConvergenceResult)
    return result
