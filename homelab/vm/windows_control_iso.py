#!/usr/bin/env python3
"""Build the static, secret-free Windows identity probe control disc."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import tempfile


class WindowsControlIsoError(RuntimeError):
    """The control payload is not safe to attach to an acceptance guest."""


ASSET_ROOT = Path(__file__).with_name("windows_control")
SCRIPT = ASSET_ROOT / "Invoke-TelosIdentityProbe.ps1"
MANIFEST = ASSET_ROOT / "manifest.json"
EXPECTED_FILES = frozenset({SCRIPT.name, MANIFEST.name})
MAX_PROBE_LAUNCH_CHARS = 240

# The control disc is an observation interface, not a provisioning channel.
# Keep this deliberately small and case-insensitive.
FORBIDDEN_POWERSHELL = (
    "add-computer",
    "new-aduser",
    "remove-aduser",
    "set-adaccountpassword",
    "set-localuser",
    "net user",
    "convertto-securestring",
    "pscredential",
    "invoke-expression",
    "downloadstring",
)


def probe_launch_command(
    action: str,
    *,
    asset_root: Path = ASSET_ROOT,
) -> str:
    """Return bounded, secret-free PowerShell for QMP keyboard injection."""
    manifest = audit_payload(asset_root)
    if action not in manifest["actions"]:
        raise WindowsControlIsoError("control action is not allowlisted")
    # Resolve by ISO volume label because Windows drive letters are not stable.
    # Action is an exact manifest member, not caller-provided shell text.
    command = (
        "powershell.exe -NoP -NonI -EP Bypass -C \""
        "$v=(Get-Volume -FileSystemLabel 'TELOS_CONTROL'|"
        "Select-Object -First 1).DriveLetter;"
        f"&($v+':\\Invoke-TelosIdentityProbe.ps1') -Action '{action}'\""
    )
    if (
        len(command) > MAX_PROBE_LAUNCH_CHARS
        or any(ord(character) < 0x20 for character in command)
    ):
        raise WindowsControlIsoError("control launch command is not QMP-safe")
    return command


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def audit_payload(asset_root: Path = ASSET_ROOT) -> dict[str, object]:
    """Validate the tracked payload without evaluating PowerShell."""
    root = Path(asset_root)
    if root.is_symlink() or not root.is_dir():
        raise WindowsControlIsoError(
            "control payload must be a regular directory")
    files = {item.name for item in root.iterdir() if item.is_file()}
    if files != EXPECTED_FILES or any(item.is_symlink() for item in root.iterdir()):
        raise WindowsControlIsoError(
            "control payload must contain only the declared regular files")
    try:
        manifest = json.loads((root / MANIFEST.name).read_text(
            encoding="utf-8"))
        script = (root / SCRIPT.name).read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise WindowsControlIsoError("control payload is unreadable") from error
    if manifest.get("schema_version") != 1:
        raise WindowsControlIsoError("control manifest schema is invalid")
    if manifest.get("entrypoint") != SCRIPT.name:
        raise WindowsControlIsoError("control entrypoint is invalid")
    actions = manifest.get("actions")
    if (not isinstance(actions, list) or not actions
            or any(not isinstance(action, str) or not action
                   for action in actions)
            or len(actions) != len(set(actions))):
        raise WindowsControlIsoError("control actions are invalid")
    if manifest.get("transport") != {
            "kind": "serial-jsonl", "default_port": "COM1",
            "baud": 115200}:
        raise WindowsControlIsoError("control transport is invalid")
    folded = script.casefold()
    forbidden = [token for token in FORBIDDEN_POWERSHELL if token in folded]
    if forbidden:
        raise WindowsControlIsoError(
            "control script contains a mutating or secret-capable primitive")
    for action in actions:
        if f"'{action.casefold()}'" not in folded:
            raise WindowsControlIsoError(
                f"control script does not implement action {action}")
    return manifest


def build_control_iso(
    output: Path,
    *,
    asset_root: Path = ASSET_ROOT,
    runner=subprocess.run,
) -> Path:
    """Build an ISO 9660 disc containing only the audited static payload."""
    output = Path(output)
    if output.exists() or output.is_symlink():
        raise WindowsControlIsoError("control ISO destination must be absent")
    parent = output.parent.resolve()
    if not parent.is_dir() or parent.is_symlink():
        raise WindowsControlIsoError(
            "control ISO parent must be a regular directory")
    manifest = audit_payload(asset_root)
    with tempfile.TemporaryDirectory(
            prefix=".windows-control-", dir=parent) as temporary:
        temporary_root = Path(temporary)
        stage = temporary_root / "payload"
        stage.mkdir(mode=0o700)
        for name in sorted(EXPECTED_FILES):
            shutil.copyfile(Path(asset_root) / name, stage / name)
            (stage / name).chmod(0o444)
        receipt = {
            "schema_version": 1,
            "payload": "telos-windows-identity-probes",
            "entrypoint": manifest["entrypoint"],
            "actions": manifest["actions"],
            "files": {
                name: _sha256(stage / name) for name in sorted(EXPECTED_FILES)
            },
            "contains_secrets": False,
            "read_only_actions": True,
        }
        receipt_path = stage / "receipt.json"
        receipt_path.write_text(
            json.dumps(receipt, indent=2, sort_keys=True) + "\n",
            encoding="utf-8")
        receipt_path.chmod(0o444)
        partial = temporary_root / "control.iso"
        runner([
            "xorriso", "-as", "mkisofs", "-quiet",
            "-V", "TELOS_CONTROL", "-J", "-r",
            "-o", str(partial), str(stage),
        ], check=True)
        if partial.is_symlink() or not partial.is_file():
            raise WindowsControlIsoError("xorriso did not create the control ISO")
        partial.replace(output)
    output.chmod(0o444)
    return output
