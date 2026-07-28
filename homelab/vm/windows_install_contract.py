"""Fail-closed contract for a disposable Windows-first QEMU installation."""

from __future__ import annotations

from contextlib import AbstractContextManager
from dataclasses import asdict, dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import subprocess
from typing import Any

from homelab.workstations.layout import GIB, build_record


MIN_DISK_BYTES = 256 * GIB
SAFE_SERIAL = re.compile(r"[A-Z0-9][A-Z0-9._-]{7,31}")
RUN_ROOT = Path("homelab/var/factory/windows-runs")


class WindowsInstallContractError(RuntimeError):
    """The proposed run cannot prove a narrow disposable-disk boundary."""


def sha256(path: Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(block)
    return value.hexdigest()


def inspect_qcow2(path: Path) -> dict[str, Any]:
    path = Path(path)
    if path.is_symlink() or not path.is_file():
        raise WindowsInstallContractError(
            "workstation disk must be a regular non-symlink file")
    result = subprocess.run(
        ["qemu-img", "info", "--output=json", str(path)],
        check=True, capture_output=True, text=True)
    try:
        info = json.loads(result.stdout)
    except json.JSONDecodeError as error:
        raise WindowsInstallContractError(
            "qemu-img returned invalid disk metadata") from error
    if info.get("format") != "qcow2" or info.get("backing-filename"):
        raise WindowsInstallContractError(
            "workstation disk must be standalone qcow2")
    virtual_size = info.get("virtual-size")
    if not isinstance(virtual_size, int) or virtual_size < MIN_DISK_BYTES:
        raise WindowsInstallContractError(
            "workstation disk is below the 256 GiB disposable minimum")
    return {
        "path": str(path.resolve()),
        "virtual_size": virtual_size,
        "format": "qcow2",
        "sha256": sha256(path),
    }


def audit_qemu_disk_boundary(
    command: list[str], *, disk: Path, serial: str,
) -> None:
    if not SAFE_SERIAL.fullmatch(serial):
        raise WindowsInstallContractError(
            "synthetic disk serial is not safely representable")
    expected = str(Path(disk).resolve())
    writable = []
    joined = " ".join(command)
    for index, argument in enumerate(command):
        if argument != "-drive" or index + 1 >= len(command):
            continue
        drive = command[index + 1]
        fields = dict(
            item.split("=", 1) for item in drive.split(",") if "=" in item)
        if (
            fields.get("media") == "cdrom"
            or fields.get("readonly") == "on"
            or fields.get("if") == "pflash"
        ):
            continue
        writable.append(fields)
    if len(writable) != 1:
        raise WindowsInstallContractError(
            "QEMU must expose exactly one writable disk")
    exposed = writable[0].get("file")
    if exposed is None or str(Path(exposed).resolve()) != expected:
        raise WindowsInstallContractError(
            "QEMU writable disk differs from the authorized disk")
    if f"serial={serial}" not in joined:
        raise WindowsInstallContractError(
            "QEMU disk does not expose the authorized synthetic serial")


@dataclass(frozen=True)
class Authorization:
    schema: int
    release_version: str
    release_manifest_sha256: str
    disk: dict[str, Any]
    disk_serial: str
    layout: dict[str, Any]
    qemu_argv_sha256: str


def authorize(
    *,
    disk: Path,
    serial: str,
    command: list[str],
    release_version: str,
    release_manifest_sha256: str,
    layout_profile: Path,
    workstation_profile: Path,
) -> Authorization:
    if not re.fullmatch(r"\d{8}\.\d{3}", release_version):
        raise WindowsInstallContractError("release version is invalid")
    if not re.fullmatch(r"[0-9a-f]{64}", release_manifest_sha256):
        raise WindowsInstallContractError("release manifest digest is invalid")
    disk_record = inspect_qcow2(disk)
    audit_qemu_disk_boundary(command, disk=disk, serial=serial)
    layout = build_record(
        disk_record["virtual_size"], layout_profile, workstation_profile)
    argv_digest = hashlib.sha256(
        json.dumps(command, separators=(",", ":")).encode()).hexdigest()
    return Authorization(
        schema=1,
        release_version=release_version,
        release_manifest_sha256=release_manifest_sha256,
        disk=disk_record,
        disk_serial=serial,
        layout=layout,
        qemu_argv_sha256=argv_digest,
    )


class PrivateRun(AbstractContextManager["PrivateRun"]):
    """Own generated secret inputs and guarantee their recursive teardown."""

    def __init__(self, root: Path = RUN_ROOT) -> None:
        self.root = Path(root)
        self.path: Path | None = None
        self.known_secrets: tuple[str, ...] = ()

    def __enter__(self) -> "PrivateRun":
        if self.root.is_symlink():
            raise WindowsInstallContractError("private run root is a symlink")
        self.root.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.root.chmod(0o700)
        self.path = self.root / ("run-" + secrets.token_hex(12))
        self.path.mkdir(mode=0o700)
        return self

    def write_secret(self, name: str, content: str) -> Path:
        if self.path is None or not re.fullmatch(r"[A-Za-z0-9_.-]+", name):
            raise WindowsInstallContractError("invalid private run filename")
        output = self.path / name
        descriptor = os.open(
            output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as stream:
            stream.write(content)
        return output

    def remember_secrets(self, *values: str) -> None:
        if any(not value for value in values):
            raise WindowsInstallContractError("known secrets must be nonempty")
        self.known_secrets += tuple(values)

    def public_receipt(
        self, authorization: Authorization, generated: list[Path],
    ) -> dict[str, Any]:
        if self.path is None:
            raise WindowsInstallContractError("private run is not active")
        return {
            "schema": 1,
            "authorization": asdict(authorization),
            "generated_inputs": [
                {"name": path.name, "sha256": sha256(path)}
                for path in generated
            ],
        }

    def assert_secret_free(self, evidence: Path) -> None:
        raw = Path(evidence).read_bytes()
        for value in self.known_secrets:
            if value.encode() in raw:
                raise WindowsInstallContractError(
                    "retained evidence contains a known secret")

    def __exit__(self, exc_type, exc_value, traceback) -> None:
        if self.path is not None:
            shutil.rmtree(self.path)
            self.path = None
