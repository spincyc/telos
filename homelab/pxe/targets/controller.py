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
MANIFEST_NAME = "manifest.json"
REQUIRED_PAYLOADS = (
    "arch/boot/x86_64/vmlinuz-linux",
    "arch/boot/x86_64/initramfs-linux.img",
    "arch/x86_64/airootfs.sfs",
)


class TargetError(RuntimeError):
    pass


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _files(root: Path) -> list[Path]:
    return sorted(
        path for path in root.rglob("*")
        if path.is_file() and path.name != MANIFEST_NAME
    )


def _refuse_links(root: Path) -> None:
    links = sorted(path.relative_to(root).as_posix()
                   for path in root.rglob("*") if path.is_symlink())
    if links:
        raise TargetError("symlinks are not valid PXE payloads: "
                          + ", ".join(links))


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
    cms_verify=y \\
    console=ttyS0,115200 console=tty0 \\
    initrd=initramfs-linux.img
initrd ${{base}}/payload/arch/boot/x86_64/initramfs-linux.img
boot || goto failed

:failed
echo Controller installer boot failed; no disk has been selected or written.
shell
"""


def _manifest(release: Path) -> dict:
    return {
        "schema": SCHEMA,
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
    source = source.resolve()
    releases = releases.resolve()
    if not VERSION_PATTERN.fullmatch(version):
        raise TargetError("version must have form YYYYMMDD.NNN")
    if not source.is_dir():
        raise TargetError(f"mkarchiso netboot output is missing: {source}")
    _refuse_links(source)
    for relative in REQUIRED_PAYLOADS:
        if not (source / relative).is_file():
            raise TargetError(f"required netboot payload is missing: {relative}")

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
        }
        (temporary / "target.json").write_text(
            json.dumps(metadata, indent=2, sort_keys=True) + "\n",
            encoding="utf-8")
        (temporary / MANIFEST_NAME).write_text(
            json.dumps(_manifest(temporary), indent=2, sort_keys=True) + "\n",
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
        _refuse_links(release)
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
    }
    if metadata != expected_metadata:
        problems.append("target.json does not match the Controller target contract")
    if not VERSION_PATTERN.fullmatch(directory_version):
        problems.append("release directory is not named YYYYMMDD.NNN")

    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        problems.append(f"manifest.json cannot be read: {error}")
        return problems
    if manifest.get("schema") != SCHEMA or manifest.get("target") != TARGET_ID:
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
    for relative in REQUIRED_PAYLOADS:
        if not (release / "payload" / relative).is_file():
            problems.append(f"required payload missing: payload/{relative}")
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
