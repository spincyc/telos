#!/usr/bin/env python3
"""Stage immutable Windows 11 Pro WinPE inputs from operator-supplied media."""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import tempfile
from pathlib import Path

from common import PAYLOADS, sha256, validate_release_name, verify_release


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


def stage(args: argparse.Namespace) -> Path:
    validate_release_name(args.release)
    iso = args.iso.resolve(strict=True)
    wimboot = args.wimboot.resolve(strict=True)
    if not iso.is_file() or not wimboot.is_file():
        raise RuntimeError("ISO and wimboot inputs must be regular files")

    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    final = output / args.release
    if final.exists():
        raise RuntimeError(f"release already exists: {final}")

    with tempfile.TemporaryDirectory(prefix=".windows-extract-", dir=output) as extract_name:
        extracted = Path(extract_name)
        run(["xorriso", "-osirrox", "on", "-indev", str(iso), "-extract", "/", str(extracted)])
        install_image = assert_windows_11_pro(extracted)
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
                destination = staged / relative
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(source, destination)
            write_ipxe(staged / "boot.ipxe", args.release, args.base_url)

            records = []
            for relative in (*PAYLOADS, "boot.ipxe"):
                path = staged / relative
                records.append(
                    {"path": relative, "bytes": path.stat().st_size, "sha256": sha256(path)}
                )
            manifest = {
                "schema": 1,
                "release": args.release,
                "target": "windows-11-pro-winpe",
                "architecture": "x86_64-uefi",
                "edition_verified": "Windows 11 Pro",
                "install_image_source": install_image,
                "redistributable": False,
                "source_iso_sha256": sha256(iso),
                "wimboot_sha256": sha256(wimboot),
                "files": records,
            }
            (staged / "manifest.json").write_text(
                json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
            )
            errors = verify_release(staged, args.release)
            if errors:
                raise RuntimeError("; ".join(errors))
            staged.rename(final)
    return final


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--iso", type=Path, required=True)
    parser.add_argument("--wimboot", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--release", required=True)
    parser.add_argument("--base-url", default="http://boot.ad.home.arpa/windows")
    return parser.parse_args()


if __name__ == "__main__":
    try:
        print(stage(parse_args()))
    except (OSError, RuntimeError, ValueError, subprocess.CalledProcessError) as exc:
        raise SystemExit(f"error: {exc}")
