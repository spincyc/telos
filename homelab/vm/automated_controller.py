#!/usr/bin/env python3
"""Rootless, disposable controller boot and serial verification helpers."""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import tempfile
import time
import uuid
from pathlib import Path
from typing import BinaryIO, Callable

try:
    from .serial_automation import SerialAutomation, SerialAutomationError, SerialResult
    from .simulation_overlay import CanonicalDiskInUse, ControllerOverlay
except ImportError:
    from serial_automation import SerialAutomation, SerialAutomationError, SerialResult
    from simulation_overlay import CanonicalDiskInUse, ControllerOverlay


EFI_SYSTEM_GUID = "c12a7328-f81f-11d2-ba4b-00a0c93ec93b"


class DisposableBootDisk:
    """Make a sparse raw copy and select a one-run init shell on its ESP."""

    def __init__(
        self,
        canonical_disk: Path,
        canonical_vars: Path,
        *,
        run_root: Path | None = None,
    ) -> None:
        self._temporary = run_root is None
        self.root = (
            Path(tempfile.mkdtemp(prefix="homelab-controller-auto-"))
            if run_root is None else Path(run_root).resolve()
        )
        self.overlay = ControllerOverlay(
            canonical_disk, canonical_vars, run_root=self.root / "guard")
        self.disk = self.root / "controller.raw"
        self.vars = self.root / "OVMF_VARS.fd"
        self._prepared = False

    def prepare(self) -> "DisposableBootDisk":
        if self._prepared:
            raise RuntimeError("automated controller disk is already prepared")
        self.root.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.root.chmod(0o700)
        try:
            self.overlay.prepare()
            subprocess.run(
                [
                    "qemu-img", "convert", "-f", "qcow2", "-O", "raw",
                    "-S", "4096", str(self.overlay.disk), str(self.disk),
                ],
                check=True, capture_output=True,
            )
            os.chmod(self.disk, 0o600)
            shutil.copy2(self.overlay.vars, self.vars)
            os.chmod(self.vars, 0o600)
            self._inject_entry()
            self._prepared = True
        except BaseException:
            self.close()
            raise
        return self

    def _partition_table(self) -> dict:
        result = subprocess.run(
            ["sfdisk", "--json", str(self.disk)],
            check=True, capture_output=True, text=True,
        )
        return json.loads(result.stdout)["partitiontable"]

    def _esp_offset(self) -> int:
        table = self._partition_table()
        sector_size = int(table.get("sectorsize", 512))
        matches = [
            part for part in table["partitions"]
            if str(part.get("type", "")).lower() == EFI_SYSTEM_GUID
        ]
        if len(matches) != 1:
            raise RuntimeError(
                f"expected exactly one EFI system partition; found {len(matches)}")
        start = int(matches[0]["start"])
        size = int(matches[0].get("size", 0))
        disk_size = self.disk.stat().st_size
        if (sector_size <= 0 or start <= 0 or size <= 0
                or start * sector_size >= disk_size
                or (start + size) * sector_size > disk_size):
            raise RuntimeError("invalid EFI system partition geometry")
        return start * sector_size

    def _mcopy_out(self, image: str, destination: Path) -> None:
        subprocess.run(
            ["mcopy", "-n", "-i", image, "::" + image, str(destination)],
            check=True, capture_output=True,
        )

    @staticmethod
    def _default_entry(loader: str) -> str:
        matches = re.findall(
            r"(?im)^\s*default\s+([^\s#]+)\s*(?:#.*)?$", loader)
        if len(matches) != 1:
            raise RuntimeError("loader.conf must contain exactly one default entry")
        name = matches[0]
        if any(part in name for part in ("/", "\\", "..", "*", "?")):
            raise RuntimeError("loader.conf default entry is not a literal filename")
        return name if name.endswith(".conf") else name + ".conf"

    @staticmethod
    def _with_init_shell(entry: str) -> str:
        options = re.findall(r"(?m)^\s*options\s+.*$", entry)
        if len(options) != 1:
            raise RuntimeError(
                "default boot entry must have exactly one options line")
        if re.search(r"(?:^|\s)init=", options[0]):
            raise RuntimeError("default boot entry already overrides init")
        return re.sub(
            r"(?m)^(\s*options\s+.*)$", r"\1 init=/bin/bash", entry,
            count=1)

    def _inject_entry(self) -> None:
        offset = self._esp_offset()
        image = f"{self.disk}@@{offset}"
        with tempfile.TemporaryDirectory(
                prefix="telos-esp-", dir=self.root) as temp_name:
            temp = Path(temp_name)
            loader_path = temp / "loader.conf"
            subprocess.run(
                ["mcopy", "-n", "-i", image, "::loader/loader.conf",
                 str(loader_path)],
                check=True, capture_output=True,
            )
            loader = loader_path.read_text(encoding="utf-8")
            entry_name = self._default_entry(loader)
            entry_path = temp / entry_name
            subprocess.run(
                ["mcopy", "-n", "-i", image,
                 f"::loader/entries/{entry_name}", str(entry_path)],
                check=True, capture_output=True,
            )
            entry = entry_path.read_text(encoding="utf-8")
            injected = self._with_init_shell(entry)
            simulation_name = "telos-automated-once.conf"
            simulation_path = temp / simulation_name
            simulation_path.write_text(injected, encoding="utf-8")
            selected = re.sub(
                r"(?im)^(\s*default\s+)[^\s#]+",
                rf"\g<1>{simulation_name}", loader, count=1)
            loader_path.write_text(selected, encoding="utf-8")
            subprocess.run(
                ["mcopy", "-o", "-i", image, str(simulation_path),
                 f"::loader/entries/{simulation_name}"],
                check=True, capture_output=True,
            )
            subprocess.run(
                ["mcopy", "-o", "-i", image, str(loader_path),
                 "::loader/loader.conf"],
                check=True, capture_output=True,
            )

    def qemu_disk_drive(self) -> str:
        if not self._prepared:
            raise RuntimeError("automated controller disk is not prepared")
        return f"if=virtio,format=raw,cache=none,file={self.disk}"

    def close(self) -> None:
        failure: BaseException | None = None
        try:
            if self.overlay._lock_stream is not None:
                for attempt in range(6):
                    try:
                        self.overlay.close()
                        break
                    except CanonicalDiskInUse:
                        if attempt == 5:
                            raise
                        time.sleep(0.1)
        except BaseException as error:
            failure = error
        for path in (self.disk, self.vars):
            path.unlink(missing_ok=True)
        if self._temporary:
            shutil.rmtree(self.root, ignore_errors=True)
        self._prepared = False
        if failure is not None:
            raise failure

    def __enter__(self) -> "DisposableBootDisk":
        return self.prepare()

    def __exit__(self, *_exc: object) -> None:
        self.close()


class AutomatedSerial:
    """Set a disposable password through passwd, then run the normal gate."""

    def __init__(
        self,
        reader: BinaryIO,
        writer: BinaryIO,
        password: bytes,
        *,
        timeout: float = 90.0,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        if not password or b"\n" in password or b"\r" in password:
            raise ValueError("simulation password must be one non-empty line")
        self.reader = reader
        self.writer = writer
        self.password = password
        self.timeout = timeout
        self.clock = clock

    def run(self) -> SerialResult:
        bootstrap = SerialAutomation(
            self.reader, self.writer, None,
            timeout=self.timeout, clock=self.clock)
        token = ("__TELOS_INIT_" + uuid.uuid4().hex + "__").encode()
        split = len(token) // 2
        bootstrap._wait(rb"(?:^|\n)[^\n]*#\s*$", "disposable-init-shell")
        bootstrap._send(
            b"/usr/bin/mount -o remount,rw /; "
            b"/usr/bin/findmnt -no OPTIONS / | /usr/bin/grep -qw rw && "
            b"/usr/bin/printf '%s%s\\n' '"
            + token[:split] + b"' '" + token[split:] + b"'",
            "root-remount-command-sent",
        )
        bootstrap._wait(
            re.escape(token) + rb"\s*$",
            "root-remount-confirmed",
        )
        bootstrap._wait(rb"(?:^|\n)[^\n]*#\s*$", "init-shell-ready")
        bootstrap._send(
            b"/usr/bin/passwd local-rescue", "passwd-command-sent")
        bootstrap._wait(rb"New password:\s*$", "new-password-prompt")
        bootstrap._send(self.password, "new-password-sent")
        bootstrap._wait(
            rb"Retype new password:\s*$", "password-confirm-prompt")
        bootstrap._send(self.password, "password-confirm-sent")
        bootstrap._wait(
            rb"(?:^|\n)passwd: password updated successfully\s*(?:\n|$)",
            "password-updated",
        )
        bootstrap._wait(rb"(?:^|\n)[^\n]*#\s*$", "post-passwd-init-shell")
        bootstrap._send(
            b"exec /usr/lib/systemd/systemd", "systemd-exec-sent")
        verified = SerialAutomation(
            self.reader, self.writer, self.password,
            timeout=self.timeout, clock=self.clock,
        ).run()
        return SerialResult(
            verified.helper_passed,
            verified.helper_returncode,
            verified.powered_off,
            tuple(bootstrap.events) + verified.events,
        )
