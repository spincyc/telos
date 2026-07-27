"""Transactional immutable PXE release sets.

A set becomes selectable only after all three target releases and the aggregate
manifest verify.  Large, non-redistributable Windows installation files remain
in the ignored media cache; the set binds their sealed receipt and describes
the publication contract instead of copying them.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import tempfile
from pathlib import Path
from typing import Callable

try:
    from . import pxe_release
except ImportError:
    import pxe_release

SCHEMA = 1
TARGETS = ("controller", "arch-workstation", "windows")
VERSION = re.compile(r"^\d{8}\.\d{3}$")
MANIFEST = "release-set.json"
SELECTED = "selected-release-set.json"


class ReleaseSetError(RuntimeError):
    """The release set cannot be built, verified, or selected safely."""


def _json(path: Path) -> dict:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ReleaseSetError(f"cannot read {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise ReleaseSetError(f"{path} must contain a JSON object")
    return value


def _digest(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _seal_install_source(seal: dict, version: str) -> dict:
    content = seal.get("content")
    if not isinstance(content, list):
        raise ReleaseSetError("media seal content must be a list")
    records = {
        item.get("name"): item for item in content if isinstance(item, dict)
    }
    required = {"arch-iso", "windows-iso", "wimboot", "windows-install-source"}
    if not required.issubset(records):
        raise ReleaseSetError("media seal is missing required factory content")
    install = records["windows-install-source"]
    windows = records["windows-iso"]
    if install.get("source_iso_sha256") != windows.get("sha256"):
        raise ReleaseSetError("Windows install source is not bound to the sealed ISO")
    if not re.fullmatch(r"[0-9a-f]{64}", str(install.get("receipt_sha256", ""))):
        raise ReleaseSetError("Windows install-source receipt digest is invalid")
    if (
        not isinstance(install.get("bytes"), int)
        or install["bytes"] <= 0
        or not isinstance(install.get("file_count"), int)
        or install["file_count"] <= 0
    ):
        raise ReleaseSetError("Windows install-source size inventory is invalid")
    return {
        "source_iso_sha256": install["source_iso_sha256"],
        "receipt_sha256": install["receipt_sha256"],
        "bytes": install.get("bytes"),
        "file_count": install.get("file_count"),
        "edition": "Windows 11 Pro",
        "redistributable": False,
        "copied_into_release_set": False,
        "publication": {
            "transport": "smb",
            "share_name": f"windows-{version}",
            "read_only": True,
            "verify_receipt_before_serving": True,
        },
    }


def _aggregate(root: Path, version: str, seal: dict, seal_digest: str) -> dict:
    targets = {}
    for target in TARGETS:
        manifest = root / "targets" / target / version / "release.json"
        targets[target] = {
            "manifest": f"targets/{target}/{version}/release.json",
            "manifest_sha256": _digest(manifest),
        }
    targets["windows"]["install_source"] = _seal_install_source(seal, version)
    return {
        "schema": SCHEMA,
        "version": version,
        "media_seal_sha256": seal_digest,
        "targets": targets,
    }


def verify(
    root: Path,
    *,
    expected_version: str | None = None,
    expected_media_seal_sha256: str | None = None,
) -> list[str]:
    root = Path(root)
    problems: list[str] = []
    if not root.is_dir():
        return [f"release set is missing: {root}"]
    version = expected_version or root.name
    if not VERSION.fullmatch(version):
        problems.append("release-set directory must have form YYYYMMDD.NNN")
    try:
        manifest = _json(root / MANIFEST)
    except ReleaseSetError as exc:
        return problems + [str(exc)]
    if set(manifest) != {"schema", "version", "media_seal_sha256", "targets"}:
        problems.append("aggregate manifest has missing or unlisted fields")
    if manifest.get("schema") != SCHEMA:
        problems.append(f"aggregate manifest schema must be {SCHEMA}")
    if manifest.get("version") != version:
        problems.append("aggregate version does not match release-set directory")
    if not re.fullmatch(r"[0-9a-f]{64}", str(manifest.get("media_seal_sha256", ""))):
        problems.append("aggregate media-seal digest is invalid")
    if (
        expected_media_seal_sha256 is not None
        and manifest.get("media_seal_sha256") != expected_media_seal_sha256
    ):
        problems.append("aggregate does not match the expected media seal")
    targets = manifest.get("targets")
    if not isinstance(targets, dict) or set(targets) != set(TARGETS):
        return problems + ["aggregate targets must name exactly all factory targets"]
    for target in TARGETS:
        release = root / "targets" / target / version
        try:
            leaf_problems = pxe_release.verify(release)
        except pxe_release.ReleaseError as exc:
            leaf_problems = [str(exc)]
        problems.extend(f"{target}: {item}" for item in leaf_problems)
        record = targets.get(target)
        if not isinstance(record, dict):
            problems.append(f"{target}: aggregate record must be an object")
            continue
        allowed = {"manifest", "manifest_sha256"}
        if target == "windows":
            allowed.add("install_source")
        if set(record) != allowed:
            problems.append(f"{target}: aggregate record has missing or unlisted fields")
        expected_path = f"targets/{target}/{version}/release.json"
        if record.get("manifest") != expected_path:
            problems.append(f"{target}: aggregate manifest path is invalid")
        leaf_manifest = root / expected_path
        if leaf_manifest.is_file() and record.get("manifest_sha256") != _digest(leaf_manifest):
            problems.append(f"{target}: aggregate manifest digest mismatch")
    windows = targets.get("windows", {})
    install = windows.get("install_source") if isinstance(windows, dict) else None
    if not isinstance(install, dict):
        problems.append("windows: install-source contract is missing")
    else:
        expected_keys = {
            "source_iso_sha256", "receipt_sha256", "bytes", "file_count",
            "edition", "redistributable", "copied_into_release_set", "publication",
        }
        if set(install) != expected_keys:
            problems.append("windows: install-source contract has missing or unlisted fields")
        if install.get("edition") != "Windows 11 Pro":
            problems.append("windows: install source is not Windows 11 Pro")
        if install.get("redistributable") is not False:
            problems.append("windows: install source must be non-redistributable")
        if install.get("copied_into_release_set") is not False:
            problems.append("windows: install source must not be copied into the release set")
        publication = install.get("publication")
        if publication != {
            "transport": "smb",
            "share_name": f"windows-{version}",
            "read_only": True,
            "verify_receipt_before_serving": True,
        }:
            problems.append("windows: install-source publication contract is invalid")
    return problems


def _write_selected(releases: Path, version: str, manifest_digest: str) -> None:
    selected = releases / SELECTED
    temporary = selected.with_name(f".{selected.name}.{os.getpid()}")
    with temporary.open("w", encoding="utf-8") as stream:
        json.dump({
            "schema": SCHEMA,
            "version": version,
            "manifest_sha256": manifest_digest,
        }, stream, indent=2, sort_keys=True)
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())
    try:
        os.replace(temporary, selected)
        descriptor = os.open(releases, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    finally:
        temporary.unlink(missing_ok=True)


def build(
    releases: Path,
    version: str,
    seal_path: Path,
    verified_seal: dict,
    stage_leaves: Callable[[Path], dict[str, Path]],
    *,
    select: bool = True,
) -> Path:
    """Build and optionally select one complete release set.

    ``verified_seal`` must be the freshly inventoried value already compared
    with ``seal_path`` by ``media_seal.verify``.
    """
    if not VERSION.fullmatch(version):
        raise ReleaseSetError("version must have form YYYYMMDD.NNN")
    releases = Path(releases).resolve()
    destination = releases / "release-sets" / version
    if destination.exists():
        raise ReleaseSetError(f"release set already exists: {destination}")
    releases.mkdir(parents=True, exist_ok=True)
    seal_path = Path(seal_path).resolve(strict=True)
    seal_digest = _digest(seal_path)
    if _json(seal_path) != verified_seal:
        raise ReleaseSetError("media seal changed after offline verification")
    _seal_install_source(verified_seal, version)

    staging_parent = releases / ".release-set-staging"
    staging_parent.mkdir(exist_ok=True)
    temporary = Path(tempfile.mkdtemp(prefix=f".{version}.", dir=staging_parent))
    try:
        leaves = stage_leaves(temporary / "leaf-build")
        if set(leaves) != set(TARGETS):
            raise ReleaseSetError("leaf builder did not return exactly all factory targets")
        target_root = temporary / "set" / "targets"
        target_root.mkdir(parents=True)
        for target in TARGETS:
            leaf = Path(leaves[target])
            errors = pxe_release.verify(leaf)
            if errors:
                raise ReleaseSetError(
                    f"{target} release failed verification: {'; '.join(errors)}")
            destination_parent = target_root / target
            destination_parent.mkdir()
            leaf.rename(destination_parent / version)
        staged_set = temporary / "set"
        aggregate = _aggregate(staged_set, version, verified_seal, seal_digest)
        (staged_set / MANIFEST).write_text(
            json.dumps(aggregate, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        errors = verify(staged_set, expected_version=version)
        if errors:
            raise ReleaseSetError(
                "aggregate release set failed verification: " + "; ".join(errors))
        destination.parent.mkdir(parents=True, exist_ok=True)
        staged_set.rename(destination)
        final_errors = verify(destination)
        if final_errors:
            shutil.rmtree(destination, ignore_errors=True)
            raise ReleaseSetError(
                "published release set failed verification: " + "; ".join(final_errors))
        if select:
            _write_selected(releases, version, _digest(destination / MANIFEST))
        return destination
    finally:
        shutil.rmtree(temporary, ignore_errors=True)
        try:
            staging_parent.rmdir()
        except OSError:
            pass


def select(releases: Path, version: str) -> Path:
    releases = Path(releases).resolve()
    release_set = releases / "release-sets" / version
    problems = verify(release_set)
    if problems:
        raise ReleaseSetError("cannot select invalid release set: " + "; ".join(problems))
    _write_selected(releases, version, _digest(release_set / MANIFEST))
    return release_set
