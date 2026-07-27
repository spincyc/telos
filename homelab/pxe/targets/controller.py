#!/usr/bin/env python3
"""Stage and verify the Controller Archiso PXE target.

This tool never downloads or publishes anything. It turns a completed local
mkarchiso netboot output into one immutable, versioned release directory.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import shutil
import sys
import tempfile
from pathlib import Path

SCHEMA = 1
TARGET_ID = "controller"
KIND = "archiso-netboot"
VERSION_PATTERN = re.compile(r"^\d{8}\.\d{3}$")
MANIFEST_NAME = "release.json"
REQUIRED_PAYLOADS = (
    "arch/boot/x86_64/vmlinuz-linux",
    "arch/boot/x86_64/initramfs-linux.img",
)
ROOT_IMAGES = (
    "arch/x86_64/airootfs.sfs",
    "arch/x86_64/airootfs.erofs",
)
ROOT_CHECKSUM = "arch/x86_64/airootfs.sha512"


class TargetError(RuntimeError):
    pass


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def sha512(path: Path) -> str:
    digest = hashlib.sha512()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _files(root: Path) -> list[Path]:
    return sorted(
        path for path in root.rglob("*")
        if path.is_file() and path.name != MANIFEST_NAME
    )


def _validate_tree(root: Path) -> None:
    links = sorted(path.relative_to(root).as_posix()
                   for path in root.rglob("*") if path.is_symlink())
    if links:
        raise TargetError("symlinks are not valid PXE payloads: "
                          + ", ".join(links))
    special = sorted(
        path.relative_to(root).as_posix()
        for path in root.rglob("*")
        if not path.is_symlink() and not path.is_dir() and not path.is_file()
    )
    if special:
        raise TargetError("special files are not valid PXE payloads: "
                          + ", ".join(special))


def _inventory(root: Path) -> dict[str, dict[str, object]]:
    return {
        path.relative_to(root).as_posix(): {
            "sha256": sha256(path),
            "size": path.stat().st_size,
        }
        for path in _files(root)
    }


def _arch_inventory(root: Path) -> dict[str, dict[str, object]]:
    """Inventory the ``arch/`` subtree using mkarchiso-relative names."""
    return {
        f"arch/{name}": record
        for name, record in _inventory(Path(root) / "arch").items()
    }


def validate_source(source: Path) -> dict[str, dict[str, object]]:
    """Validate and inventory one completed mkarchiso netboot output."""
    source = Path(source)
    if not source.is_dir() or source.is_symlink():
        raise TargetError(f"mkarchiso netboot output is missing: {source}")
    _validate_tree(source)
    for relative in REQUIRED_PAYLOADS:
        payload = source / relative
        if not payload.is_file() or payload.is_symlink():
            raise TargetError(f"required netboot payload is missing: {relative}")
        if payload.stat().st_size == 0:
            raise TargetError(f"required netboot payload is empty: {relative}")
    root_images = [
        relative for relative in ROOT_IMAGES
        if (source / relative).is_file() and not (source / relative).is_symlink()
    ]
    if len(root_images) != 1:
        raise TargetError(
            "mkarchiso output must contain exactly one supported root image "
            "(airootfs.sfs or airootfs.erofs)")
    root_image = source / root_images[0]
    if root_image.stat().st_size == 0:
        raise TargetError(f"required netboot payload is empty: {root_images[0]}")
    checksum_path = source / ROOT_CHECKSUM
    if not checksum_path.is_file() or checksum_path.is_symlink():
        raise TargetError(f"required netboot payload is missing: {ROOT_CHECKSUM}")
    try:
        checksum_parts = checksum_path.read_text(encoding="ascii").strip().split()
    except UnicodeDecodeError as error:
        raise TargetError("root image SHA-512 receipt is not ASCII") from error
    expected_name = root_image.name
    if (
        len(checksum_parts) != 2
        or not re.fullmatch(r"[0-9a-fA-F]{128}", checksum_parts[0])
        or checksum_parts[1].lstrip("*") != expected_name
    ):
        raise TargetError("root image SHA-512 receipt is malformed")
    digest = sha512(root_image)
    if checksum_parts[0].lower() != digest:
        raise TargetError("root image does not match its SHA-512 receipt")
    return _arch_inventory(source)


def render_ipxe(base_url: str) -> str:
    base = base_url.rstrip("/")
    if not base.startswith(("http://", "https://")):
        raise TargetError("base URL must use http:// or https://")
    return f"""#!ipxe
# Controller installer --- GENERATED, do not edit.
set base {base}

echo Loading versioned Controller installer from ${{base}}
kernel ${{base}}/payload/arch/boot/x86_64/vmlinuz-linux \\
    archisobasedir=arch \\
    archiso_http_srv=${{base}}/payload/ \\
    checksum=y \\
    console=ttyS0,115200 console=tty0 \\
    initrd=initramfs-linux.img
initrd ${{base}}/payload/arch/boot/x86_64/initramfs-linux.img
boot || goto failed

:failed
echo Controller installer boot failed; no disk has been selected or written.
shell
"""


def _manifest(release: Path, version: str) -> dict:
    return {
        "schema": SCHEMA,
        "version": version,
        "target": TARGET_ID,
        "artifacts": {
            path.relative_to(release).as_posix(): {
                "sha256": sha256(path),
                "size": path.stat().st_size,
            }
            for path in _files(release)
        },
    }


def stage(source: Path, releases: Path, version: str, base_url: str) -> Path:
    source = Path(source)
    if source.is_symlink():
        raise TargetError("mkarchiso netboot output must not be a symlink")
    source = source.resolve()
    releases = releases.resolve()
    if not VERSION_PATTERN.fullmatch(version):
        raise TargetError("version must have form YYYYMMDD.NNN")
    source_inventory = validate_source(source)

    destination = releases / TARGET_ID / version
    if destination.exists():
        raise TargetError(f"release already exists: {destination}")
    destination.parent.mkdir(parents=True, exist_ok=True)

    temporary = Path(tempfile.mkdtemp(
        prefix=f".{version}.", dir=destination.parent))
    try:
        shutil.copytree(source / "arch", temporary / "payload/arch")
        (temporary / "boot.ipxe").write_text(
            render_ipxe(base_url), encoding="utf-8")
        metadata = {
            "schema": SCHEMA,
            "id": TARGET_ID,
            "kind": KIND,
            "version": version,
            "entrypoints": ["boot.ipxe"],
            "source": {
                "kind": "mkarchiso-netboot",
                "artifacts": source_inventory,
            },
        }
        (temporary / "target.json").write_text(
            json.dumps(metadata, indent=2, sort_keys=True) + "\n",
            encoding="utf-8")
        (temporary / MANIFEST_NAME).write_text(
            json.dumps(_manifest(temporary, version), indent=2, sort_keys=True) + "\n",
            encoding="utf-8")
        problems = verify(temporary, expected_version=version)
        if problems:
            raise TargetError("staged release failed verification:\n  "
                              + "\n  ".join(problems))
        temporary.rename(destination)
    except BaseException:
        shutil.rmtree(temporary, ignore_errors=True)
        raise
    return destination


def verify(release: Path, *, expected_version: str | None = None) -> list[str]:
    release = Path(release)
    problems: list[str] = []
    if not release.is_dir():
        return [f"release is missing: {release}"]
    try:
        _validate_tree(release)
    except TargetError as error:
        problems.append(str(error))

    metadata_path = release / "target.json"
    manifest_path = release / MANIFEST_NAME
    try:
        metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        problems.append(f"target.json cannot be read: {error}")
        metadata = {}
    directory_version = expected_version or release.name
    expected_metadata = {
        "schema": SCHEMA,
        "id": TARGET_ID,
        "kind": KIND,
        "version": directory_version,
        "entrypoints": ["boot.ipxe"],
        "source": {
            "kind": "mkarchiso-netboot",
            "artifacts": _arch_inventory(release / "payload"),
        },
    }
    if metadata != expected_metadata:
        problems.append("target.json does not match the Controller target contract")
    if not VERSION_PATTERN.fullmatch(directory_version):
        problems.append("release directory is not named YYYYMMDD.NNN")

    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        problems.append(f"{MANIFEST_NAME} cannot be read: {error}")
        return problems
    if (
        manifest.get("schema") != SCHEMA
        or manifest.get("version") != directory_version
        or manifest.get("target") != TARGET_ID
    ):
        problems.append("manifest identity is invalid")
    listed = manifest.get("artifacts")
    if not isinstance(listed, dict):
        problems.append("manifest artifacts must be an object")
        return problems
    actual_names = {path.relative_to(release).as_posix()
                    for path in _files(release)}
    if set(listed) != actual_names:
        missing = sorted(set(listed) - actual_names)
        extra = sorted(actual_names - set(listed))
        if missing:
            problems.append("listed files missing: " + ", ".join(missing))
        if extra:
            problems.append("unlisted files present: " + ", ".join(extra))
    for name in sorted(set(listed) & actual_names):
        entry = listed[name]
        path = release / name
        if not isinstance(entry, dict):
            problems.append(f"{name}: invalid manifest entry")
            continue
        if entry.get("sha256") != sha256(path):
            problems.append(f"{name}: checksum mismatch")
        if entry.get("size") != path.stat().st_size:
            problems.append(f"{name}: size mismatch")
    try:
        validate_source(release / "payload")
    except TargetError as error:
        problems.append(str(error))
    return problems


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    commands = parser.add_subparsers(dest="command", required=True)
    build = commands.add_parser("build")
    build.add_argument("--source", type=Path, required=True)
    build.add_argument("--releases", type=Path, required=True)
    build.add_argument("--version", required=True)
    build.add_argument("--base-url", required=True)
    check = commands.add_parser("verify")
    check.add_argument("release", type=Path)
    arguments = parser.parse_args(argv)
    try:
        if arguments.command == "build":
            release = stage(arguments.source, arguments.releases,
                            arguments.version, arguments.base_url)
            print(f"staged and verified {release}")
            return 0
        problems = verify(arguments.release)
        if problems:
            for problem in problems:
                print(problem, file=sys.stderr)
            return 1
        print(f"verified {arguments.release}")
        return 0
    except TargetError as error:
        print(f"controller target: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
