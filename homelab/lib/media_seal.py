"""Create and verify the deterministic, offline factory-media seal."""

from __future__ import annotations

import hashlib
import json
import os
import platform
import stat
import tempfile
from pathlib import Path

import windows_install_source

CONTRACT_VERSION = 1


class SealError(RuntimeError):
    """A media input or seal receipt does not satisfy the factory contract."""


def _sha256_descriptor(descriptor: int) -> str:
    digest = hashlib.sha256()
    os.lseek(descriptor, 0, os.SEEK_SET)
    for chunk in iter(lambda: os.read(descriptor, 1024 * 1024), b""):
        digest.update(chunk)
    return digest.hexdigest()


def _snapshot(descriptor: int) -> tuple[int, int, int, int, int]:
    status = os.fstat(descriptor)
    if not stat.S_ISREG(status.st_mode) or status.st_nlink != 1:
        raise SealError("sealed inputs must be regular, single-link files")
    return (
        status.st_dev,
        status.st_ino,
        status.st_size,
        status.st_mtime_ns,
        status.st_ctime_ns,
    )


def _open_regular(path: Path, label: str) -> int:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise SealError(
            f"{label} must be a regular file, not a symbolic link: {path}"
        ) from exc
    try:
        _snapshot(descriptor)
    except Exception:
        os.close(descriptor)
        raise
    return descriptor


def _json(path: Path, label: str) -> dict:
    descriptor = _open_regular(path, label)
    try:
        before = _snapshot(descriptor)
        raw = b""
        os.lseek(descriptor, 0, os.SEEK_SET)
        for chunk in iter(lambda: os.read(descriptor, 1024 * 1024), b""):
            raw += chunk
        after = _snapshot(descriptor)
    finally:
        os.close(descriptor)
    if before != after:
        raise SealError(f"{label} changed while it was read")
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SealError(f"{label} is unreadable: {exc}") from exc
    if not isinstance(value, dict):
        raise SealError(f"{label} must contain a JSON object")
    return value


def _record(name: str, path: Path) -> dict:
    descriptor = _open_regular(path, name)
    try:
        before = _snapshot(descriptor)
        digest = _sha256_descriptor(descriptor)
        after = _snapshot(descriptor)
    finally:
        os.close(descriptor)
    if before != after:
        raise SealError(f"{name} changed while it was hashed")
    return {"name": name, "bytes": before[2], "sha256": digest}


def _arch_record(path: Path, receipt_filename: object) -> dict:
    """Accept a regular ISO or the fetcher's narrowly bound atomic selector."""
    if not path.is_symlink():
        return _record("arch-iso", path)
    target = Path(os.readlink(path))
    if (
        not isinstance(receipt_filename, str)
        or target.is_absolute()
        or len(target.parts) != 1
        or target.name in {"", ".", ".."}
        or target.name != receipt_filename
    ):
        raise SealError("Arch ISO selector is not bound to its receipt filename")
    selected = path.parent / target
    if selected.is_symlink() or not selected.is_file():
        raise SealError("Arch ISO selector target must be a regular non-symlink file")
    return _record("arch-iso", selected)


def inventory(
    *,
    arch_iso: Path,
    arch_receipt: Path,
    windows_iso: Path,
    windows_provenance: Path,
    windows_verification: Path,
    windows_install_source_path: Path,
    wimboot: Path,
    wimboot_metadata: Path,
) -> dict:
    """Verify every declared cache input and return its canonical seal."""
    arch = _json(arch_receipt, "Arch receipt")
    if set(arch) != {"filename", "sha256", "source", "signing_fingerprint"}:
        raise SealError("Arch receipt has unlisted or missing fields")
    if Path(str(arch["filename"])).name != arch["filename"]:
        raise SealError("Arch receipt filename is unsafe")
    arch_record = _arch_record(arch_iso, arch["filename"])
    if arch_record["sha256"] != arch["sha256"]:
        raise SealError("Arch ISO differs from its receipt")

    provenance = _json(windows_provenance, "Windows provenance receipt")
    verification = _json(windows_verification, "Windows verification receipt")
    expected_provenance = {
        "schema", "source", "download_page", "filename", "bytes", "sha256",
        "expected_sha256", "digest_authority",
    }
    expected_verification = {
        "schema", "iso", "sha256", "edition", "install_image", "boot_chain",
    }
    if set(provenance) != expected_provenance:
        raise SealError("Windows provenance receipt has unlisted or missing fields")
    if set(verification) != expected_verification:
        raise SealError("Windows verification receipt has unlisted or missing fields")
    windows_record = _record("windows-iso", windows_iso)
    digest = windows_record["sha256"]
    if (
        provenance["sha256"] != digest
        or provenance["expected_sha256"] != digest
        or provenance["bytes"] != windows_record["bytes"]
        or verification["sha256"] != digest
    ):
        raise SealError("Windows ISO differs from its verification/provenance receipts")
    if verification["edition"] != "Windows 11 Pro":
        raise SealError("Windows installation image is not Windows 11 Pro")

    metadata = _json(wimboot_metadata, "wimboot metadata")
    if set(metadata) != {
        "schema", "name", "version", "source", "release", "url", "size", "sha256"
    }:
        raise SealError("wimboot metadata has unlisted or missing fields")
    wimboot_record = _record("wimboot", wimboot)
    if (
        metadata["schema"] != 1
        or metadata["name"] != "wimboot"
        or metadata["source"] != "https://github.com/ipxe/wimboot"
        or metadata["size"] != wimboot_record["bytes"]
        or metadata["sha256"] != wimboot_record["sha256"]
    ):
        raise SealError("wimboot differs from pinned official metadata")

    try:
        install = windows_install_source.verify_cache(
            windows_install_source_path, digest
        )
    except windows_install_source.InstallSourceError as exc:
        raise SealError(str(exc)) from exc
    if install["edition"] != "Windows 11 Pro":
        raise SealError("install-source edition is not Windows 11 Pro")

    content = [
        arch_record,
        windows_record,
        wimboot_record,
        {
            "name": "windows-install-source",
            "bytes": install["bytes"],
            "file_count": install["file_count"],
            "receipt_sha256": _record(
                "windows-install-source-receipt",
                windows_install_source_path / "receipt.json",
            )["sha256"],
            "source_iso_sha256": install["source_iso_sha256"],
        },
    ]
    provenance_records = [
        _record("arch-receipt", arch_receipt),
        _record("windows-provenance", windows_provenance),
        _record("windows-verification", windows_verification),
        _record("wimboot-metadata", wimboot_metadata),
    ]
    return {
        "schema": 1,
        "content": content,
        "tool_versions": {
            "python": platform.python_version(),
            "media_seal_contract": CONTRACT_VERSION,
            "windows_install_source_receipt_schema":
                windows_install_source.RECEIPT_SCHEMA,
        },
        "provenance": {
            "records": provenance_records,
            "assertions": {
                "arch_signing_fingerprint": arch["signing_fingerprint"],
                "windows_edition": "Windows 11 Pro",
                "windows_install_image": verification["install_image"],
                "wimboot_version": metadata["version"],
            },
        },
        # Tool versions are deliberately not content identity. Reproduction on
        # another host is equivalent when these validators produce this seal.
        "environment_equivalence": {
            "policy": "verified-content-and-provenance-v1",
            "validators": [
                "arch-signed-receipt",
                "windows-verification-receipt",
                "windows-install-source.verify_cache",
                "wimboot-pinned-metadata",
            ],
        },
    }


def write(path: Path, receipt: dict) -> None:
    path = path.absolute()
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.is_symlink():
        raise SealError(f"seal receipt must not be a symbolic link: {path}")
    with tempfile.NamedTemporaryFile(
        mode="w", encoding="utf-8", dir=path.parent,
        prefix=f".{path.name}.", delete=False,
    ) as stream:
        temporary = Path(stream.name)
        json.dump(receipt, stream, indent=2, sort_keys=True)
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())
    try:
        os.replace(temporary, path)
        descriptor = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    finally:
        temporary.unlink(missing_ok=True)


def verify(path: Path, expected: dict) -> dict:
    actual = _json(path, "media seal")
    if actual != expected:
        raise SealError("media seal differs from the verified cache inventory")
    return actual
