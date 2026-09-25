#!/usr/bin/env python3
"""Build the static, secret-free Windows identity probe control disc."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
from typing import Mapping

from .windows_guest_principals import (
    GUEST_ROLES,
    WindowsGuestPrincipalError,
    audit_guest_script,
    guest_roster,
    render_guest_script,
)


class WindowsControlIsoError(RuntimeError):
    """The control payload is not safe to attach to an acceptance guest."""


ASSET_ROOT = Path(__file__).with_name("windows_control")
SCRIPT = ASSET_ROOT / "Invoke-TelosIdentityProbe.ps1"
MANIFEST = ASSET_ROOT / "manifest.json"
EXPECTED_FILES = frozenset({SCRIPT.name, MANIFEST.name})
MAX_PROBE_LAUNCH_CHARS = 240
_LAUNCH_MARKERS = {
    action: index
    for index, action in enumerate((
        "current-principal",
        "current-session-state",
        "controller-readiness",
        "domain-state",
        "managed-identity-state",
        "cached-logon-policy",
        "gateway-reachability",
        "dependency-reachability",
        "service-reachability",
        "update-policy",
        "interactive-operator",
    ), start=1)
}

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

# The probe resolves the directory principals by NAME, but it rides a static
# disc with no per-run document to carry them, and its launch line is typed
# through the Run dialog within MAX_PROBE_LAUNCH_CHARS -- too tight for three
# names.  So the tracked script names each principal by a ``{{role}}``
# placeholder and build_control_iso renders the host-derived roster into the
# STAGED copy only.  With no private overlay the rendered script is
# byte-for-byte the script gate 6 proved; with one, only those string
# literals differ.  The host judges the same resolved names
# (windows_identity_orchestrator), so the two cannot drift.


def probe_launch_command(
    action: str,
    *,
    asset_root: Path = ASSET_ROOT,
) -> str:
    """Return bounded, secret-free PowerShell for QMP keyboard injection."""
    manifest = audit_payload(asset_root)
    if action not in manifest["actions"]:
        raise WindowsControlIsoError("control action is not allowlisted")
    marker = probe_launch_marker(action)
    # Open COM1 and emit the fixed action marker before touching optical media.
    # Pass that same port to the script so no reopen race can erase the boundary.
    command = (
        "powershell.exe -NoP -NonI -EP Bypass -C \""
        "$p=[IO.Ports.SerialPort]::new('COM1',115200);"
        f"$p.Open();$p.WriteLine({marker});"
        "&((Get-Volume -FileSystemLabel TELOS_CONTROL).DriveLetter+"
        f"':\\Invoke-TelosIdentityProbe.ps1') -A '{action}' -S $p\""
    )
    if (
        len(command) > MAX_PROBE_LAUNCH_CHARS
        or any(ord(character) < 0x20 for character in command)
    ):
        raise WindowsControlIsoError("control launch command is not QMP-safe")
    return command


def probe_launch_marker(action: str) -> int:
    """Return the exact JSON-number launcher marker for one action."""
    try:
        return _LAUNCH_MARKERS[action]
    except (KeyError, TypeError) as error:
        raise WindowsControlIsoError(
            "control action is not allowlisted") from error


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
    try:
        roles = audit_guest_script(
            script, label=SCRIPT.name, placeholders=True)
    except WindowsGuestPrincipalError as error:
        raise WindowsControlIsoError(str(error)) from error
    if roles != frozenset(GUEST_ROLES):
        raise WindowsControlIsoError(
            "control script must name every directory principal through "
            "its roster placeholder")
    return manifest


def render_probe_script(
    asset_root: Path = ASSET_ROOT,
    roster: Mapping[str, str] | None = None,
) -> bytes:
    """Return the probe exactly as it ships: the host roster rendered in."""
    try:
        source = (Path(asset_root) / SCRIPT.name).read_bytes().decode(
            "ascii")
        rendered = render_guest_script(
            source, guest_roster() if roster is None else roster)
    except (OSError, UnicodeDecodeError,
            WindowsGuestPrincipalError) as error:
        raise WindowsControlIsoError(
            f"control script cannot be rendered: {error}") from error
    folded = rendered.casefold()
    if any(token in folded for token in FORBIDDEN_POWERSHELL):
        raise WindowsControlIsoError(
            "control script contains a mutating or secret-capable primitive")
    return rendered.encode("ascii")


def build_control_iso(
    output: Path,
    *,
    asset_root: Path = ASSET_ROOT,
    runner=subprocess.run,
    roster: Mapping[str, str] | None = None,
) -> Path:
    """Build an ISO 9660 disc containing only the audited static payload.

    *roster* is ``{role: name}`` for the directory roles and defaults to the
    host-derived roster; the probe is the one staged file that differs from
    its tracked source, and only by those names.
    """
    output = Path(output)
    if output.exists() or output.is_symlink():
        raise WindowsControlIsoError("control ISO destination must be absent")
    parent = output.parent.resolve()
    if not parent.is_dir() or parent.is_symlink():
        raise WindowsControlIsoError(
            "control ISO parent must be a regular directory")
    manifest = audit_payload(asset_root)
    probe = render_probe_script(asset_root, roster)
    with tempfile.TemporaryDirectory(
            prefix=".windows-control-", dir=parent) as temporary:
        temporary_root = Path(temporary)
        stage = temporary_root / "payload"
        stage.mkdir(mode=0o700)
        for name in sorted(EXPECTED_FILES):
            if name == SCRIPT.name:
                (stage / name).write_bytes(probe)
            else:
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
