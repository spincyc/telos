#!/usr/bin/env python3
"""Stage immutable Windows 11 Pro WinPE inputs from operator-supplied media."""

from __future__ import annotations

import argparse
import json
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

from common import PAYLOADS, sha256, validate_release_name, verify_release

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "lib"))
import windows_install_source  # noqa: E402

DEFAULT_WIMBOOT_METADATA = (
    Path(__file__).resolve().parents[2] / "media" / "wimboot.json"
)


def run(command: list[str]) -> str:
    result = subprocess.run(command, check=True, text=True, capture_output=True)
    return result.stdout


def locate_casefold(root: Path, relative: str) -> Path:
    current = root
    for component in Path(relative).parts:
        matches = [item for item in current.iterdir() if item.name.casefold() == component.casefold()]
        if len(matches) != 1:
            raise RuntimeError(f"ISO must contain exactly one {relative}")
        current = matches[0]
    return current


def assert_windows_11_pro(extracted: Path) -> str:
    sources = locate_casefold(extracted, "sources")
    images = [path for path in sources.iterdir() if path.name.casefold() in {"install.wim", "install.esd"}]
    if len(images) != 1:
        raise RuntimeError("ISO must contain exactly one sources/install.wim or install.esd")
    info = run(["wimlib-imagex", "info", str(images[0])])
    folded = info.casefold()
    if "windows 11 pro" not in folded:
        raise RuntimeError("installation image does not advertise Windows 11 Pro")
    return images[0].name


def write_ipxe(path: Path, release: str, base_url: str) -> None:
    root = f"{base_url.rstrip('/')}/{release}"
    path.write_text(
        "\n".join(
            [
                "#!ipxe",
                f"set release-root {root}",
                "kernel ${release-root}/wimboot",
                "initrd ${release-root}/bootmgr bootmgr",
                "initrd ${release-root}/boot/BCD BCD",
                "initrd ${release-root}/boot/boot.sdi boot.sdi",
                "initrd ${release-root}/sources/boot.wim boot.wim",
                "boot",
                "",
            ]
        ),
        encoding="utf-8",
    )


def wimboot_provenance(binary: Path, metadata_path: Path) -> dict:
    metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
    required = {"schema", "name", "version", "source", "release", "url", "size", "sha256"}
    if set(metadata) != required or metadata["schema"] != 1:
        raise RuntimeError("invalid wimboot provenance metadata")
    if metadata["source"] != "https://github.com/ipxe/wimboot":
        raise RuntimeError("wimboot provenance is not the official iPXE project")
    expected_url = (
        "https://github.com/ipxe/wimboot/releases/download/"
        f"v{metadata['version']}/wimboot"
    )
    if metadata["url"] != expected_url:
        raise RuntimeError("wimboot provenance does not name the official release asset")
    if (
        not isinstance(metadata["size"], int)
        or metadata["size"] <= 0
        or not isinstance(metadata["sha256"], str)
        or not re.fullmatch(r"[0-9a-f]{64}", metadata["sha256"])
    ):
        raise RuntimeError("wimboot provenance checksum metadata is malformed")
    actual_size = binary.stat().st_size
    actual_digest = sha256(binary)
    if actual_size != metadata["size"] or actual_digest != metadata["sha256"]:
        raise RuntimeError("wimboot does not match pinned provenance")
    return {
        "project": metadata["source"],
        "release": metadata["release"],
        "version": metadata["version"],
        "url": metadata["url"],
        "size": metadata["size"],
        "sha256": metadata["sha256"],
    }


def stage_tree(
    *,
    extracted: Path,
    install_image: str,
    source_iso_sha256: str,
    wimboot: Path,
    provenance: dict,
    output: Path,
    release: str,
    base_url: str,
) -> Path:
    """Stage only WinPE boot files from an already verified source tree."""
    output = output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    final = output / release
    if final.exists():
        raise RuntimeError(f"release already exists: {final}")
    with tempfile.TemporaryDirectory(prefix=".windows-stage-", dir=output) as stage_name:
        staged = Path(stage_name)
        sources = {
            "wimboot": wimboot,
            "bootmgr": locate_casefold(extracted, "bootmgr"),
            "boot/BCD": locate_casefold(extracted, "boot/BCD"),
            "boot/boot.sdi": locate_casefold(extracted, "boot/boot.sdi"),
            "sources/boot.wim": locate_casefold(extracted, "sources/boot.wim"),
        }
        for relative, source in sources.items():
            if source.is_symlink() or not source.is_file():
                raise RuntimeError(f"unsafe or missing Windows boot input: {relative}")
            destination = staged / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, destination)
        write_ipxe(staged / "boot.ipxe", release, base_url)

        records = {}
        for relative in (*PAYLOADS, "boot.ipxe"):
            path = staged / relative
            records[relative] = {
                "size": path.stat().st_size,
                "sha256": sha256(path),
            }
        manifest = {
            "schema": 1,
            "version": release,
            "target": "windows",
            "architecture": "x86_64-uefi",
            "edition_verified": "Windows 11 Pro",
            "install_image_source": Path(install_image).name,
            "redistributable": False,
            "source_iso_sha256": source_iso_sha256,
            "wimboot_sha256": sha256(wimboot),
            "wimboot_provenance": provenance,
            "artifacts": records,
        }
        (staged / "release.json").write_text(
            json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        errors = verify_release(staged, release)
        if errors:
            raise RuntimeError("; ".join(errors))
        staged.rename(final)
    return final


def stage_from_install_source(args: argparse.Namespace) -> Path:
    """Stage from the sealed, complete extracted source without host extractors."""
    validate_release_name(args.release)
    wimboot = args.wimboot.resolve(strict=True)
    if not wimboot.is_file():
        raise RuntimeError("wimboot input must be a regular file")
    provenance = wimboot_provenance(
        wimboot, args.wimboot_metadata.resolve(strict=True))
    receipt = windows_install_source.verify_cache(
        args.install_source, args.source_iso_sha256)
    return stage_tree(
        extracted=args.install_source,
        install_image=receipt["install_image"],
        source_iso_sha256=receipt["source_iso_sha256"],
        wimboot=wimboot,
        provenance=provenance,
        output=args.output,
        release=args.release,
        base_url=args.base_url,
    )


def stage(args: argparse.Namespace) -> Path:
    validate_release_name(args.release)
    iso = args.iso.resolve(strict=True)
    wimboot = args.wimboot.resolve(strict=True)
    if not iso.is_file() or not wimboot.is_file():
        raise RuntimeError("ISO and wimboot inputs must be regular files")
    provenance = wimboot_provenance(
        wimboot, args.wimboot_metadata.resolve(strict=True))
    missing = [name for name in ("7z", "wimlib-imagex") if shutil.which(name) is None]
    if missing:
        raise RuntimeError(
            "missing Windows media dependencies: "
            + ", ".join(missing)
            + " (run make homelab-bootstrap-deps)"
        )

    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix=".windows-extract-", dir=output) as extract_name:
        extracted = Path(extract_name)
        run(["7z", "x", "-tUdf", "-y", f"-o{extracted}", str(iso)])
        install_image = assert_windows_11_pro(extracted)
        return stage_tree(
            extracted=extracted,
            install_image=install_image,
            source_iso_sha256=sha256(iso),
            wimboot=wimboot,
            provenance=provenance,
            output=args.output,
            release=args.release,
            base_url=args.base_url,
        )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--iso", type=Path)
    source.add_argument("--install-source", type=Path)
    parser.add_argument("--source-iso-sha256")
    parser.add_argument("--wimboot", type=Path, required=True)
    parser.add_argument(
        "--wimboot-metadata", type=Path, default=DEFAULT_WIMBOOT_METADATA)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--release", required=True)
    parser.add_argument("--base-url", default="http://boot.example.test/windows")
    return parser.parse_args()


if __name__ == "__main__":
    try:
        arguments = parse_args()
        if arguments.install_source:
            if not arguments.source_iso_sha256:
                raise ValueError(
                    "--source-iso-sha256 is required with --install-source")
            print(stage_from_install_source(arguments))
        else:
            print(stage(arguments))
    except (OSError, RuntimeError, ValueError, subprocess.CalledProcessError) as exc:
        raise SystemExit(f"error: {exc}")
