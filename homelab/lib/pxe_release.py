"""Immutable local staging for PXE targets.

Target builders place only redistributable instructions and generated metadata
in Git. Operators supply installation media locally. This module copies a
completed target into a versioned staging tree and records every byte before a
separate publisher is allowed to see it.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import tempfile
from pathlib import Path

SCHEMA = 1
VERSION_PATTERN = re.compile(r"^[0-9]{8}\.[0-9]{3}$")
TARGET_PATTERN = re.compile(r"^[a-z][a-z0-9-]*$")
DESCRIPTOR = "target.json"
MANIFEST = "release.json"


class ReleaseError(ValueError):
    """The source or staged release violates the PXE contract."""


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_descriptor(source: Path) -> dict:
    descriptor_path = Path(source) / DESCRIPTOR
    try:
        descriptor = json.loads(descriptor_path.read_text())
    except FileNotFoundError as error:
        raise ReleaseError(f"missing {descriptor_path}") from error
    except json.JSONDecodeError as error:
        raise ReleaseError(f"invalid JSON in {descriptor_path}: {error}") from error

    target_id = descriptor.get("id")
    if descriptor.get("schema") != SCHEMA:
        raise ReleaseError(f"{descriptor_path}: schema must be {SCHEMA}")
    if not isinstance(target_id, str) or not TARGET_PATTERN.fullmatch(target_id):
        raise ReleaseError(f"{descriptor_path}: invalid target id")
    if Path(source).name != target_id:
        raise ReleaseError(
            f"{descriptor_path}: id {target_id!r} must match directory name")
    entrypoints = descriptor.get("entrypoints")
    if not isinstance(entrypoints, list) or not entrypoints:
        raise ReleaseError(f"{descriptor_path}: entrypoints must be a non-empty list")
    for name in entrypoints:
        if not isinstance(name, str) or name.startswith("/") or ".." in Path(name).parts:
            raise ReleaseError(f"{descriptor_path}: unsafe entrypoint {name!r}")
        if not (Path(source) / name).is_file():
            raise ReleaseError(f"{descriptor_path}: missing entrypoint {name}")
    return descriptor


def source_files(source: Path) -> list[Path]:
    source = Path(source)
    files = []
    for path in sorted(source.rglob("*")):
        if path.is_symlink():
            raise ReleaseError(f"symlinks are not allowed: {path}")
        if path.is_file():
            files.append(path)
    return files


def build_manifest(source: Path, *, version: str) -> dict:
    if not VERSION_PATTERN.fullmatch(version):
        raise ReleaseError("version must have form YYYYMMDD.NNN")
    descriptor = load_descriptor(source)
    entries = {}
    for path in source_files(source):
        relative = path.relative_to(source).as_posix()
        if relative == MANIFEST:
            raise ReleaseError(f"source must not contain generated {MANIFEST}")
        entries[relative] = {
            "sha256": sha256(path),
            "size": path.stat().st_size,
        }
    return {
        "schema": SCHEMA,
        "version": version,
        "target": descriptor["id"],
        "artifacts": entries,
    }


def stage(source: Path, releases: Path, *, version: str) -> Path:
    """Atomically stage one immutable target version.

    The caller supplies a target directory, not a downloaded ISO. Existing
    releases are never replaced.
    """
    source = Path(source).resolve()
    releases = Path(releases).resolve()
    manifest = build_manifest(source, version=version)
    destination = releases / manifest["target"] / version
    if destination.exists():
        raise ReleaseError(f"release already exists: {destination}")
    destination.parent.mkdir(parents=True, exist_ok=True)

    temporary = Path(tempfile.mkdtemp(
        prefix=f".{version}.", dir=destination.parent))
    try:
        for path in source_files(source):
            relative = path.relative_to(source)
            output = temporary / relative
            output.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(path, output)
        (temporary / MANIFEST).write_text(
            json.dumps(manifest, indent=2, sort_keys=True) + "\n")
        os.rename(temporary, destination)
    except Exception:
        shutil.rmtree(temporary, ignore_errors=True)
        raise
    return destination


def verify(release: Path) -> list[str]:
    release = Path(release)
    manifest_path = release / MANIFEST
    try:
        manifest = json.loads(manifest_path.read_text())
    except (FileNotFoundError, json.JSONDecodeError) as error:
        return [f"cannot read {manifest_path}: {error}"]

    problems = []
    if manifest.get("schema") != SCHEMA:
        problems.append(f"manifest schema must be {SCHEMA}")
    if manifest.get("version") != release.name:
        problems.append("manifest version does not match release directory")
    if manifest.get("target") != release.parent.name:
        problems.append("manifest target does not match target directory")

    expected = manifest.get("artifacts")
    if not isinstance(expected, dict):
        return problems + ["manifest artifacts must be an object"]
    actual_names = {
        path.relative_to(release).as_posix()
        for path in source_files(release)
        if path.name != MANIFEST
    }
    expected_names = set(expected)
    for name in sorted(expected_names - actual_names):
        problems.append(f"{name}: missing")
    for name in sorted(actual_names - expected_names):
        problems.append(f"{name}: unlisted")
    for name in sorted(actual_names & expected_names):
        path = release / name
        record = expected[name]
        if not isinstance(record, dict):
            problems.append(f"{name}: invalid manifest record")
            continue
        if record.get("size") != path.stat().st_size:
            problems.append(f"{name}: size mismatch")
        if record.get("sha256") != sha256(path):
            problems.append(f"{name}: checksum mismatch")
    return problems
