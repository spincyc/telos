#!/usr/bin/env python3
"""One-use private medium carrying the Windows COM1 progress reporter.

Windows needs no image rebuild to report progress: `TelosJoin.ps1` already
proves that an ISO-delivered script can `Register-ScheduledTask`, so the
reporter rides the same kind of one-use medium and registers its own boot
task.  The medium carries the per-attempt channel material; when it is absent
the guest script exits 0 in silence.

The material includes a MAC key, but this channel is diagnostic by
construction: it is one-way, it is shared with human-readable console output,
and its events bind to a producer no authoritative receiver accepts.  The key
binds a channel; it does not make a report into evidence.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import tempfile
from typing import Mapping

from .guest_progress_com1 import (
    COM1_PHASES,
    COM1_PRODUCER,
    MARKER,
    MAX_LINE_BYTES,
)


class WindowsProgressIsoError(RuntimeError):
    """The progress medium is not safe to attach to a factory guest."""


ASSET_ROOT = Path(__file__).with_name("windows_progress_control")
SCRIPT = ASSET_ROOT / "TelosProgress.ps1"
MANIFEST = ASSET_ROOT / "manifest.json"
EXPECTED_FILES = frozenset({SCRIPT.name, MANIFEST.name})

VOLUME_LABEL = "TELOS_PROGRESS"
TASK_NAME = "TelosProgress"
MATERIAL_NAME = "progress.json"
REPORTED_PHASE = "windows-firstboot"

_TOKEN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_KEY_HEX = re.compile(r"(?:[0-9a-f]{2}){32,}\Z")

# The reporter is an observation interface. It must not mutate the guest, must
# not touch credentials, and must never read COM1 -- a read would be the first
# half of an acknowledgment, and an acknowledged channel invites being treated
# as authoritative.
FORBIDDEN_POWERSHELL = (
    "readline",
    "readexisting",
    ".readtimeout",
    "readchar",
    "readbyte",
    "add-computer",
    "set-localuser",
    "net user",
    "convertto-securestring",
    "pscredential",
    "invoke-expression",
    "downloadstring",
    "start-process",
)

_TRANSPORT = {
    "kind": "serial-line",
    "port": "COM1",
    "baud": 115200,
    "direction": "guest-to-host",
    "marker": MARKER,
    "encoding": "base64url-canonical-json",
    "authoritative": False,
    "acknowledged": False,
}


def progress_task_argument() -> str:
    """Return the exact scheduled-task argument the guest must register.

    The volume is resolved by label at run time, so no drive letter is baked
    into the task and a destroyed medium simply makes the task a no-op.
    """

    argument = (
        "-NoProfile -NonInteractive -ExecutionPolicy Bypass -Command "
        "\"& ((Get-Volume -FileSystemLabel '" + VOLUME_LABEL + "')"
        ".DriveLetter + ':\\TelosProgress.ps1')\""
    )
    if len(argument) > MAX_LINE_BYTES or any(
        ord(character) < 0x20 for character in argument
    ):
        raise WindowsProgressIsoError("progress task argument is not bounded")
    return argument


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def audit_payload(asset_root: Path = ASSET_ROOT) -> dict[str, object]:
    """Validate the tracked reporter payload without evaluating PowerShell."""

    root = Path(asset_root)
    if root.is_symlink() or not root.is_dir():
        raise WindowsProgressIsoError(
            "progress payload must be a regular directory")
    entries = list(root.iterdir())
    files = {item.name for item in entries if item.is_file()}
    if files != EXPECTED_FILES or any(item.is_symlink() for item in entries):
        raise WindowsProgressIsoError(
            "progress payload must contain only the declared regular files")
    try:
        manifest = json.loads(
            (root / MANIFEST.name).read_text(encoding="utf-8"))
        script = (root / SCRIPT.name).read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise WindowsProgressIsoError(
            "progress payload is unreadable") from error
    if manifest.get("schema_version") != 1:
        raise WindowsProgressIsoError("progress manifest schema is invalid")
    if manifest.get("entrypoint") != SCRIPT.name:
        raise WindowsProgressIsoError("progress entrypoint is invalid")
    if manifest.get("producer") != COM1_PRODUCER:
        raise WindowsProgressIsoError("progress producer is invalid")
    if manifest.get("task_name") != TASK_NAME:
        raise WindowsProgressIsoError("progress task name is invalid")
    if manifest.get("volume_label") != VOLUME_LABEL:
        raise WindowsProgressIsoError("progress volume label is invalid")
    phases = manifest.get("phases")
    if phases != [REPORTED_PHASE] or REPORTED_PHASE not in COM1_PHASES:
        raise WindowsProgressIsoError("progress phase registry is invalid")
    if manifest.get("transport") != _TRANSPORT:
        raise WindowsProgressIsoError("progress transport is invalid")

    folded = script.casefold()
    forbidden = [token for token in FORBIDDEN_POWERSHELL if token in folded]
    if forbidden:
        raise WindowsProgressIsoError(
            "progress script contains a mutating, reading, or "
            "secret-capable primitive")
    # One-way and single-shape: exactly the framed emitter writes to COM1.
    if script.count(".WriteLine(") != script.count(
            "$serial.WriteLine((New-TelosProgressLine"):
        raise WindowsProgressIsoError(
            "progress script writes to COM1 outside the framed emitter")
    if progress_task_argument() not in script:
        raise WindowsProgressIsoError(
            "progress script does not register the exact bounded task")
    for required in (MARKER, COM1_PRODUCER, REPORTED_PHASE, TASK_NAME,
                     VOLUME_LABEL, MATERIAL_NAME):
        if required not in script:
            raise WindowsProgressIsoError(
                "progress script omits a declared protocol constant")
    return manifest


def _private_parent(path: Path) -> Path:
    parent = path.resolve()
    if (path.is_symlink() or not parent.is_dir()
            or stat.S_IMODE(parent.stat().st_mode) != 0o700):
        raise WindowsProgressIsoError(
            "progress ISO parent must be a private mode-0700 directory")
    return parent


def validate_material(material: Mapping[str, str]) -> dict[str, str]:
    """Accept exactly one bounded per-attempt COM1 channel material set."""

    if set(material) != {"attempt", "nonce", "key_hex"}:
        raise WindowsProgressIsoError("progress material fields are invalid")
    values = {name: material[name] for name in ("attempt", "nonce", "key_hex")}
    for name in ("attempt", "nonce"):
        if (type(values[name]) is not str
                or _TOKEN.fullmatch(values[name]) is None):
            raise WindowsProgressIsoError(
                f"progress {name} is not a bounded public token")
    if (type(values["key_hex"]) is not str
            or _KEY_HEX.fullmatch(values["key_hex"]) is None):
        raise WindowsProgressIsoError(
            "progress key must be at least 32 bytes of lowercase hex")
    return values


def build_progress_iso(
    output: Path,
    material: Mapping[str, str],
    *,
    asset_root: Path = ASSET_ROOT,
    runner=subprocess.run,
) -> Path:
    """Build the one-use progress medium without putting material in argv."""

    output = Path(output)
    if output.exists() or output.is_symlink():
        raise WindowsProgressIsoError(
            "progress ISO destination must be absent")
    parent = _private_parent(output.parent)
    values = validate_material(material)
    manifest = audit_payload(asset_root)
    with tempfile.TemporaryDirectory(
            prefix=".windows-progress-", dir=parent) as temporary:
        root = Path(temporary)
        root.chmod(0o700)
        stage = root / "payload"
        stage.mkdir(mode=0o700)
        target_script = stage / SCRIPT.name
        shutil.copyfile(Path(asset_root) / SCRIPT.name, target_script)
        target_script.chmod(0o400)
        document = stage / MATERIAL_NAME
        descriptor = os.open(
            document, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
            0o400)
        try:
            with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
                json.dump(
                    {
                        "schema_version": 1,
                        "attempt": values["attempt"],
                        "nonce": values["nonce"],
                        "key_hex": values["key_hex"],
                        "producer": COM1_PRODUCER,
                        "phase": REPORTED_PHASE,
                        # Restated in the material the guest reads, so the
                        # boundary is visible at both ends of the channel.
                        "authoritative": False,
                    },
                    stream, separators=(",", ":"), sort_keys=True)
                stream.write("\n")
        except BaseException:
            try:
                os.close(descriptor)
            except OSError:
                pass
            raise
        receipt = stage / "receipt.json"
        receipt.write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "payload": "telos-windows-progress-reporter",
                    "entrypoint": manifest["entrypoint"],
                    "task_name": TASK_NAME,
                    "producer": COM1_PRODUCER,
                    "transport": _TRANSPORT,
                    "contains_per_attempt_channel_key": True,
                    "authoritative": False,
                    "files": {SCRIPT.name: _sha256(target_script)},
                },
                indent=2, sort_keys=True) + "\n",
            encoding="utf-8")
        receipt.chmod(0o400)
        partial = root / "progress.iso"
        runner([
            "xorriso", "-as", "mkisofs", "-quiet",
            "-V", VOLUME_LABEL, "-J", "-r",
            "-o", str(partial), str(stage),
        ], check=True)
        if partial.is_symlink() or not partial.is_file():
            raise WindowsProgressIsoError(
                "xorriso did not create the progress ISO")
        partial.chmod(0o600)
        partial.replace(output)
    output.chmod(0o600)
    return output


def register_launch_command() -> str:
    """Return the fixed, secret-free one-shot task-registration command."""

    command = (
        "powershell.exe -NoP -NonI -EP Bypass -C \"&((Get-Volume "
        f"-FileSystemLabel {VOLUME_LABEL}).DriveLetter+"
        "':\\TelosProgress.ps1') -Register\""
    )
    if len(command) > 240 or any(ord(item) < 0x20 for item in command):
        raise WindowsProgressIsoError(
            "progress registration command is not QMP-safe")
    return command
