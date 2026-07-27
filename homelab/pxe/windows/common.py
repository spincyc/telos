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
    manifest_path = release_dir / "manifest.json"
    return json.loads(manifest_path.read_text(encoding="utf-8"))


def verify_release(release_dir: Path, expected_release: str | None = None) -> list[str]:
    errors: list[str] = []
    try:
        manifest = load_manifest(release_dir)
    except (OSError, json.JSONDecodeError) as exc:
        return [f"manifest unreadable: {exc}"]

    if manifest.get("schema") != 1:
        errors.append("manifest schema is not 1")
    if manifest.get("release") != (expected_release or release_dir.name):
        errors.append("manifest release does not match directory")
    if manifest.get("target") != "windows-11-pro-winpe":
        errors.append("unexpected target")
    if manifest.get("redistributable") is not False:
        errors.append("Microsoft payload must be marked non-redistributable")

    records = manifest.get("files")
    if not isinstance(records, list):
        return errors + ["manifest files is not a list"]
    by_name = {record.get("path"): record for record in records if isinstance(record, dict)}
    required = set(PAYLOADS) | {"boot.ipxe"}
    if set(by_name) != required:
        errors.append("manifest file set differs from required payload")

    for relative in sorted(required):
        path = release_dir / relative
        if not path.is_file():
            errors.append(f"missing {relative}")
            continue
        record = by_name.get(relative, {})
        if record.get("bytes") != path.stat().st_size:
            errors.append(f"size mismatch: {relative}")
        if record.get("sha256") != sha256(path):
            errors.append(f"digest mismatch: {relative}")

    for path in release_dir.rglob("*"):
        if path.is_file() and path.name.casefold() in FORBIDDEN:
            errors.append(f"forbidden secret-bearing filename: {path.relative_to(release_dir)}")
    return errors
