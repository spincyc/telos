"""Shared validation for a staged Windows WinPE release."""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path

RELEASE_RE = re.compile(r"^[A-Za-z0-9._-]+$")
PAYLOADS = ("wimboot", "bootmgr", "boot/BCD", "boot/boot.sdi", "sources/boot.wim")
FORBIDDEN = {
    "autounattend.xml",
    "unattend.xml",
    "credentials.json",
    "secrets.json",
}


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def validate_release_name(release: str) -> None:
    if not RELEASE_RE.fullmatch(release) or release in {".", ".."}:
        raise ValueError("release must use only letters, digits, dot, underscore, or hyphen")


def load_manifest(release_dir: Path) -> dict:
    manifest_path = release_dir / "release.json"
    return json.loads(manifest_path.read_text(encoding="utf-8"))


def verify_release(release_dir: Path, expected_release: str | None = None) -> list[str]:
    errors: list[str] = []
    try:
        manifest = load_manifest(release_dir)
    except (OSError, json.JSONDecodeError) as exc:
        return [f"manifest unreadable: {exc}"]

    if manifest.get("schema") != 1:
        errors.append("manifest schema is not 1")
    if manifest.get("version") != (expected_release or release_dir.name):
        errors.append("manifest release does not match directory")
    if manifest.get("target") != "windows":
        errors.append("unexpected target")
    if manifest.get("redistributable") is not False:
        errors.append("Microsoft payload must be marked non-redistributable")
    provenance = manifest.get("wimboot_provenance")
    if not isinstance(provenance, dict):
        errors.append("wimboot provenance is missing")
    else:
        if provenance.get("project") != "https://github.com/ipxe/wimboot":
            errors.append("wimboot provenance is not official")
        if provenance.get("sha256") != manifest.get("wimboot_sha256"):
            errors.append("wimboot provenance digest differs")
        if not re.fullmatch(r"[0-9a-f]{64}", str(provenance.get("sha256", ""))):
            errors.append("wimboot provenance digest is malformed")

    records = manifest.get("artifacts")
    if not isinstance(records, dict):
        return errors + ["manifest artifacts is not an object"]
    by_name = records
    required = set(PAYLOADS) | {"boot.ipxe"}
    if set(by_name) != required:
        errors.append("manifest file set differs from required payload")

    for relative in sorted(required):
        path = release_dir / relative
        if not path.is_file():
            errors.append(f"missing {relative}")
            continue
        record = by_name.get(relative, {})
        if record.get("size") != path.stat().st_size:
            errors.append(f"size mismatch: {relative}")
        if record.get("sha256") != sha256(path):
            errors.append(f"digest mismatch: {relative}")
    if isinstance(provenance, dict):
        record = by_name.get("wimboot", {})
        if provenance.get("sha256") != record.get("sha256"):
            errors.append("wimboot artifact differs from provenance")
        if provenance.get("size") != record.get("size"):
            errors.append("wimboot size differs from provenance")

    for path in release_dir.rglob("*"):
        if path.is_file() and path.name.casefold() in FORBIDDEN:
            errors.append(f"forbidden secret-bearing filename: {path.relative_to(release_dir)}")
    return errors
