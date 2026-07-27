"""Verify the identity and useful contents of a local Windows installation ISO."""

from __future__ import annotations

import hashlib
import re
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
    "/efi/microsoft/boot/bootmgfw.efi",
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


def _iso_files(iso: Path, run: Callable[[list[str]], str]) -> dict[str, str]:
    # With no explicit action, xorriso's -find prints each matching path.
    output = run(["xorriso", "-indev", str(iso), "-find", "/", "-type", "f"])
    files: dict[str, str] = {}
    duplicates: set[str] = set()
    for line in output.splitlines():
        # xorriso shell-quotes reported paths. The boot-chain names contain no
        # quote characters, so removing the surrounding pair is unambiguous.
        path = line.strip()
        if len(path) >= 2 and path[0] == path[-1] == "'":
            path = path[1:-1]
        if not path.startswith("/"):
            continue
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
                "xorriso",
                "-osirrox",
                "on",
                "-indev",
                str(iso),
                "-extract",
                images[0],
                str(image),
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
