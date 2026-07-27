"""Acquire operator-downloaded Windows media without inventing a download API."""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import tempfile
import fcntl
from pathlib import Path
from typing import Callable

DOWNLOAD_PAGE = "https://www.microsoft.com/software-download/windows11"
MINIMUM_ISO_BYTES = 1024 * 1024
ISO9660_MAGIC_OFFSET = 16 * 2048 + 1
ISO9660_MAGIC = b"CD001"
SHA256_RE = re.compile(r"[0-9a-fA-F]{64}\Z")


class MediaError(RuntimeError):
    """A Windows media input is missing or plainly invalid."""


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def validate_source(path: Path) -> None:
    if not path.is_file():
        raise MediaError(f"Windows ISO not found: {path}")
    if path.suffix.lower() != ".iso":
        raise MediaError(f"Windows media must have an .iso suffix: {path}")
    if path.stat().st_size < MINIMUM_ISO_BYTES:
        raise MediaError(f"Windows ISO is implausibly small: {path}")
    with path.open("rb") as stream:
        stream.seek(ISO9660_MAGIC_OFFSET)
        if stream.read(len(ISO9660_MAGIC)) != ISO9660_MAGIC:
            raise MediaError(f"Windows media lacks an ISO-9660 volume descriptor: {path}")


def _reject_symlink(path: Path, label: str) -> None:
    if path.is_symlink():
        raise MediaError(f"{label} must not be a symbolic link: {path}")


def _atomic_json(path: Path, value: dict) -> None:
    _reject_symlink(path, "provenance receipt")
    with tempfile.NamedTemporaryFile(
        mode="w",
        encoding="utf-8",
        dir=path.parent,
        prefix=f".{path.name}.",
        delete=False,
    ) as stream:
        temporary = Path(stream.name)
        json.dump(value, stream, indent=2, sort_keys=True)
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())
    try:
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def import_iso(
    source: Path,
    output: Path,
    expected_sha256: str,
    *,
    content_verifier: Callable[[Path, str], dict] | None = None,
) -> dict:
    """Atomically copy operator-acquired media and record its provenance."""
    source = source.resolve()
    output = output.absolute()
    if not SHA256_RE.fullmatch(expected_sha256):
        raise MediaError("expected SHA-256 must be exactly 64 hexadecimal characters")
    expected = expected_sha256.lower()
    validate_source(source)
    if source == output:
        raise MediaError("source and output must be different files")

    output.parent.mkdir(parents=True, exist_ok=True)
    _reject_symlink(output, "output")
    record_path = output.with_suffix(output.suffix + ".provenance.json")
    verification_path = output.with_suffix(output.suffix + ".verification.json")
    lock_path = output.with_suffix(output.suffix + ".lock")
    _reject_symlink(record_path, "provenance receipt")
    _reject_symlink(verification_path, "verification receipt")
    _reject_symlink(lock_path, "cache lock")
    lock_fd = os.open(lock_path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(lock_fd, "w") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            _reject_symlink(output, "output")
            _reject_symlink(record_path, "provenance receipt")
            _reject_symlink(verification_path, "verification receipt")
            actual = sha256(source)
            if actual != expected:
                raise MediaError(
                    f"Windows ISO SHA-256 mismatch: expected {expected}, got {actual}"
                )
            with tempfile.NamedTemporaryFile(
                dir=output.parent, prefix=f".{output.name}.", delete=False
            ) as stream:
                temporary = Path(stream.name)
            try:
                shutil.copyfile(source, temporary)
                if sha256(temporary) != expected:
                    raise MediaError("Windows ISO changed while it was copied")
                verification = (
                    content_verifier(temporary, expected)
                    if content_verifier is not None
                    else None
                )
                os.replace(temporary, output)
            finally:
                temporary.unlink(missing_ok=True)

            record = {
                "schema": 2,
                "source": "Microsoft Software Download",
                "download_page": DOWNLOAD_PAGE,
                "filename": output.name,
                "bytes": output.stat().st_size,
                "sha256": expected,
                "expected_sha256": expected,
                "digest_authority": "operator-supplied Microsoft-published SHA-256",
            }
            _atomic_json(record_path, record)
            if verification is not None:
                verification = dict(verification)
                verification["iso"] = output.name
                verification["schema"] = 1
                _atomic_json(
                    verification_path,
                    verification,
                )
    finally:
        # fdopen owns lock_fd after it succeeds; close only an early open failure.
        try:
            os.close(lock_fd)
        except OSError:
            pass
    return record


def continuation(output: Path) -> str:
    return f"""Windows 11 media needs one manual Microsoft step.

Microsoft does not publish a supported, stable URL for unattended Windows 11
Pro ISO downloads. The generated links expire, so this build will not scrape
the download page or use an unofficial mirror.

1. Open {DOWNLOAD_PAGE}
2. Under "Download Windows 11 Disk Image (ISO) for x64 devices", select
   Windows 11, confirm the product language, and choose the 64-bit download.
3. Continue this build with:

   homelab/bin/homelab-fetch-windows \\
     --source /path/to/downloaded.iso \\
     --expected-sha256 <SHA-256-published-by-Microsoft> \\
     --output {output}

Copy Microsoft's published SHA-256 from the download page. The helper refuses
media that does not match it, copies under a cache lock, and atomically records
the verification receipt. The later PXE staging check verifies that the media
advertises Windows 11 Pro before it is used.
"""
