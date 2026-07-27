"""Verify the identity and useful contents of a local Windows installation ISO."""

from __future__ import annotations

import hashlib
import re
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Callable

SHA256_RE = re.compile(r"^[0-9a-fA-F]{64}$")
PRO_NAME_RE = re.compile(r"(?im)^\s*Name\s*:\s*Windows 11 Pro\s*$")

# Files needed to enter Windows Setup natively through UEFI and to enter its
# WinPE image through wimboot.  Checking both catches incomplete/repacked media
# before it becomes a workstation-factory input.
BOOT_CHAIN = (
    "/bootmgr",
    "/boot/bcd",
    "/boot/boot.sdi",
    "/efi/boot/bootx64.efi",
    "/efi/microsoft/boot/cdboot.efi",
    "/sources/boot.wim",
)
INSTALL_IMAGES = ("/sources/install.wim", "/sources/install.esd")


class VerificationError(RuntimeError):
    """The supplied file is not the expected usable Windows installation ISO."""


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _run(command: list[str]) -> str:
    result = subprocess.run(command, check=True, text=True, capture_output=True)
    return result.stdout


def _require_tools() -> None:
    missing = [
        name for name in ("7z", "wimlib-imagex") if shutil.which(name) is None
    ]
    if missing:
        raise VerificationError(
            "missing Windows media dependencies: "
            + ", ".join(missing)
            + " (run make homelab-bootstrap-deps)"
        )


def _iso_files(iso: Path, run: Callable[[list[str]], str]) -> dict[str, str]:
    # Microsoft's current consumer image uses UDF. xorriso and libarchive see
    # only its tiny ISO-9660 compatibility tree, while 7-Zip reads the UDF tree.
    output = run(["7z", "l", "-tUdf", "-slt", str(iso)])
    files: dict[str, str] = {}
    duplicates: set[str] = set()
    for line in output.splitlines():
        if not line.casefold().startswith("path = "):
            continue
        reported = line.split("=", 1)[1].strip()
        if reported in {str(iso), iso.name}:
            continue
        path = "/" + reported.lstrip("/")
        folded = path.casefold()
        if folded in files:
            duplicates.add(folded)
        else:
            files[folded] = path
    if duplicates:
        names = ", ".join(sorted(duplicates))
        raise VerificationError(f"ISO contains case-insensitive duplicate paths: {names}")
    return files


def verify(
    iso: Path,
    expected_sha256: str,
    *,
    run: Callable[[list[str]], str] = _run,
) -> dict[str, object]:
    """Verify *iso* and return a small receipt suitable for build output."""
    iso = iso.resolve()
    if not iso.is_file():
        raise VerificationError(f"Windows ISO not found: {iso}")
    expected = expected_sha256.strip().lower()
    if not SHA256_RE.fullmatch(expected):
        raise VerificationError("expected SHA-256 must be exactly 64 hexadecimal digits")
    actual = sha256(iso)
    if actual != expected:
        raise VerificationError(
            f"Windows ISO SHA-256 mismatch: expected {expected}, got {actual}"
        )

    if run is _run:
        _require_tools()
    files = _iso_files(iso, run)
    missing = [path for path in BOOT_CHAIN if path.casefold() not in files]
    if missing:
        raise VerificationError(
            "Windows ISO is missing boot-chain files: " + ", ".join(missing)
        )
    images = [files[path.casefold()] for path in INSTALL_IMAGES if path.casefold() in files]
    if len(images) != 1:
        raise VerificationError(
            "Windows ISO must contain exactly one of "
            "sources/install.wim or sources/install.esd"
        )

    with tempfile.TemporaryDirectory(prefix="telos-windows-iso-") as name:
        image = Path(name) / Path(images[0]).name
        run(
            [
                "7z",
                "e",
                "-tUdf",
                "-y",
                f"-o{name}",
                str(iso),
                images[0].lstrip("/"),
            ]
        )
        info = run(["wimlib-imagex", "info", str(image)])
    if not PRO_NAME_RE.search(info):
        raise VerificationError(
            "installation image does not contain the exact edition Windows 11 Pro"
        )

    return {
        "iso": str(iso),
        "sha256": actual,
        "edition": "Windows 11 Pro",
        "install_image": images[0],
        "boot_chain": list(BOOT_CHAIN),
    }
