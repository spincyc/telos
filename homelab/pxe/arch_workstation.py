"""Build a versioned Arch workstation PXE target from local Arch media.

This module never downloads media and never publishes a release.  It copies a
locally mounted or extracted Arch ISO tree into a complete staging directory,
writes the iPXE entrypoint, and records every byte in a SHA-256 manifest.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Callable


TARGET_ID = "arch-workstation"
VERSION = re.compile(r"^\d{8}\.\d{3}$")
REQUIRED_MEDIA = (
    Path("arch/version"),
    Path("arch/boot/x86_64/vmlinuz-linux"),
    Path("arch/boot/x86_64/initramfs-linux.img"),
    Path("arch/x86_64/airootfs.sfs"),
)


class TargetError(ValueError):
    """The supplied media or staged target is not safe to use."""


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _files(root: Path, *, omit_manifest: bool = False):
    for path in sorted(root.rglob("*")):
        if path.is_file() and not (omit_manifest and path.name == "release.json"):
            yield path


def _refuse_links(root: Path) -> None:
    links = sorted(
        path.relative_to(root).as_posix()
        for path in root.rglob("*")
        if path.is_symlink()
    )
    if links:
        raise TargetError("symlinks are not valid PXE payloads: " + ", ".join(links))


def _refuse_special_files(root: Path) -> None:
    special = sorted(
        path.relative_to(root).as_posix()
        for path in root.rglob("*")
        if not path.is_symlink() and not path.is_dir() and not path.is_file()
    )
    if special:
        raise TargetError(
            "special files are not valid PXE payloads: " + ", ".join(special)
        )


def validate_source(source: Path) -> None:
    source = Path(source)
    if not source.is_dir():
        raise TargetError(f"Arch media root is not a directory: {source}")
    _refuse_links(source)
    _refuse_special_files(source)
    missing = [str(name) for name in REQUIRED_MEDIA if not (source / name).is_file()]
    if missing:
        raise TargetError("Arch media is incomplete; missing: " + ", ".join(missing))


def _extraction_receipt(root: Path, image_digest: str) -> dict:
    return {
        "schema": 1,
        "image_sha256": image_digest,
        "files": {
            path.relative_to(root).as_posix(): {
                "sha256": sha256(path),
                "size": path.stat().st_size,
            }
            for path in _files(root)
        },
    }


def _valid_extraction(directory: Path, image_digest: str) -> bool:
    root = directory / "root"
    receipt_path = directory / "receipt.json"
    if not root.is_dir() or not receipt_path.is_file():
        return False
    try:
        validate_source(root)
        receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    except (TargetError, json.JSONDecodeError, OSError, UnicodeDecodeError):
        return False
    return receipt == _extraction_receipt(root, image_digest)


def extract_iso(
    image: Path,
    cache: Path,
    *,
    expected_sha256: str | None = None,
    runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
) -> Path:
    """Extract an Arch ISO without mounting it, caching only verified output."""
    image = Path(image)
    if not image.is_file():
        raise TargetError(f"Arch ISO is not a regular file: {image}")
    image_digest = sha256(image)
    if expected_sha256 is not None and image_digest != expected_sha256:
        raise TargetError("Arch ISO does not match the sealed media digest")
    destination = Path(cache) / image_digest
    if _valid_extraction(destination, image_digest):
        return destination / "root"

    Path(cache).mkdir(parents=True, exist_ok=True)
    temporary = Path(tempfile.mkdtemp(prefix=f".{image_digest}.", dir=cache))
    root = temporary / "root"
    root.mkdir()
    try:
        try:
            runner(
                (
                    "xorriso",
                    "-osirrox", "on",
                    "-indev", str(image.resolve()),
                    "-extract", "/", str(root.resolve()),
                ),
                check=True,
                text=True,
                capture_output=True,
            )
        except FileNotFoundError as error:
            raise TargetError(
                "xorriso is required for mount-free Arch ISO extraction"
            ) from error
        except subprocess.CalledProcessError as error:
            detail = (error.stderr or "").strip()
            suffix = f": {detail}" if detail else ""
            raise TargetError(f"xorriso could not extract {image.name}{suffix}") from error
        # Rock Ridge media commonly records directories as 0555.  The cache is
        # disposable caller-owned state, so restore owner write permission on
        # directories to make atomic cleanup and replacement reliable.  File
        # bytes and their receipt remain unchanged.
        for directory in (root, *(path for path in root.rglob("*") if path.is_dir())):
            os.chmod(directory, directory.stat().st_mode | 0o700)
        validate_source(root)
        (temporary / "receipt.json").write_text(
            json.dumps(
                _extraction_receipt(root, image_digest), indent=2, sort_keys=True
            ) + "\n",
            encoding="utf-8",
        )
        if destination.exists():
            if _valid_extraction(destination, image_digest):
                return destination / "root"
            raise TargetError(f"invalid Arch extraction cache entry: {destination}")
        temporary.rename(destination)
        return destination / "root"
    finally:
        if temporary.exists():
            shutil.rmtree(temporary)


def render_ipxe(*, release_url: str) -> str:
    if not release_url.startswith(("http://", "https://")):
        raise TargetError("release URL must use http:// or https://")
    base = release_url.rstrip("/") + "/payload"
    return f"""#!ipxe
# Arch workstation installer --- generated; do not edit.
set base {base}

kernel ${{base}}/arch/boot/x86_64/vmlinuz-linux \\
    archisobasedir=arch \\
    archiso_http_srv=${{base}}/ \\
    ip=dhcp \\
    copytoram=n \\
    console=ttyS0,115200 console=tty0 \\
    initrd=initramfs-linux.img
initrd ${{base}}/arch/boot/x86_64/initramfs-linux.img
boot || goto failed

:failed
echo Arch workstation boot failed.
echo Verify this release and confirm that ${{base}} is reachable.
shell
"""


def build_manifest(root: Path, version: str) -> dict:
    entries = {}
    for path in _files(root, omit_manifest=True):
        relative = path.relative_to(root).as_posix()
        entries[relative] = {"sha256": sha256(path), "size": path.stat().st_size}
    return {
        "schema": 1,
        "version": version,
        "target": TARGET_ID,
        "artifacts": entries,
    }


def verify(root: Path, *, expected_version: str | None = None) -> list[str]:
    root = Path(root)
    if not root.is_dir():
        return [f"release is missing: {root}"]
    problems = []
    try:
        _refuse_links(root)
    except TargetError as error:
        problems.append(str(error))
    manifest_path = root / "release.json"
    if not manifest_path.is_file():
        return problems + ["release.json: missing"]
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError) as error:
        return problems + [f"release.json: invalid JSON: {error}"]
    if manifest.get("schema") != 1:
        problems.append("release.json: unsupported schema")
    if manifest.get("version") != (expected_version or root.name):
        problems.append("release.json: version must match release directory")
    if manifest.get("target") != TARGET_ID:
        problems.append(f"release.json: target must be {TARGET_ID}")
    listed = manifest.get("artifacts")
    if not isinstance(listed, dict):
        return problems + ["release.json: artifacts must be an object"]

    actual_names = {
        path.relative_to(root).as_posix()
        for path in _files(root, omit_manifest=True)
    }
    listed_names = set(listed)
    for name in sorted(listed_names - actual_names):
        problems.append(f"{name}: listed but missing")
    for name in sorted(actual_names - listed_names):
        problems.append(f"{name}: present but not listed")
    for name in sorted(actual_names & listed_names):
        record = listed[name]
        if not isinstance(record, dict):
            problems.append(f"{name}: manifest record must be an object")
            continue
        path = root / name
        if record.get("size") != path.stat().st_size:
            problems.append(f"{name}: size mismatch")
        if record.get("sha256") != sha256(path):
            problems.append(f"{name}: checksum mismatch")

    descriptor = root / "target.json"
    if descriptor.is_file():
        try:
            target = json.loads(descriptor.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError) as error:
            problems.append(f"target.json: invalid JSON: {error}")
        else:
            expected = {
                "schema": 1,
                "id": TARGET_ID,
                "kind": "archiso-netboot",
                "version": expected_version or root.name,
                "entrypoints": ["boot.ipxe"],
                "source": target.get("source"),
            }
            if target != expected:
                problems.append("target.json: target contract mismatch")
    return problems


def stage(*, source: Path, releases: Path, version: str, base_url: str) -> Path:
    """Create ``releases/arch-workstation/<version>`` without partial output."""
    if not VERSION.fullmatch(version):
        raise TargetError("version must match YYYYMMDD.NNN")
    validate_source(source)
    destination = Path(releases) / TARGET_ID / version
    if destination.exists():
        raise TargetError(f"release already exists: {destination}")
    destination.parent.mkdir(parents=True, exist_ok=True)

    temporary = Path(tempfile.mkdtemp(
        prefix=f".{version}.", dir=destination.parent))
    try:
        payload = temporary / "payload"
        shutil.copytree(Path(source) / "arch", payload / "arch")
        (temporary / "boot.ipxe").write_text(
            render_ipxe(
                release_url=f"{base_url.rstrip('/')}/{TARGET_ID}/{version}"),
            encoding="utf-8")
        media_info = (Path(source) / "arch/version").read_text(
            encoding="utf-8", errors="replace").strip()
        descriptor = {
            "schema": 1,
            "id": TARGET_ID,
            "kind": "archiso-netboot",
            "version": version,
            "entrypoints": ["boot.ipxe"],
            "source": {"media_info": media_info},
        }
        (temporary / "target.json").write_text(
            json.dumps(descriptor, indent=2, sort_keys=True) + "\n",
            encoding="utf-8")
        (temporary / "release.json").write_text(
            json.dumps(build_manifest(temporary, version), indent=2, sort_keys=True) + "\n",
            encoding="utf-8")
        problems = verify(temporary, expected_version=version)
        if problems:
            raise TargetError("staged release failed verification: " + "; ".join(problems))
        temporary.rename(destination)
    except Exception:
        shutil.rmtree(temporary, ignore_errors=True)
        raise
    return destination
