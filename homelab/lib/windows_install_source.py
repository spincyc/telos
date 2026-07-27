"""Atomically stage a verified, read-only Windows installation source tree."""

from __future__ import annotations

import fcntl
import hashlib
import json
import os
import shutil
import stat
import tempfile
from pathlib import Path
from pathlib import PurePosixPath
from typing import Callable

import windows_iso

REQUIRED = (
    "setup.exe",
    "bootmgr",
    "efi/boot/bootx64.efi",
    "sources/boot.wim",
)
INSTALL_IMAGES = ("sources/install.wim", "sources/install.esd")
RECEIPT_SCHEMA = 1
FORBIDDEN_NAMES = {
    "autounattend.xml",
    "unattend.xml",
    "credentials.json",
    "secrets.json",
}


class InstallSourceError(RuntimeError):
    """The install source cannot be safely staged or reused."""


RECEIPT_KEYS = {
    "schema",
    "source_iso",
    "source_iso_sha256",
    "edition",
    "install_image",
    "bytes",
    "file_count",
    "files",
}
FILE_KEYS = {"path", "bytes", "sha256"}


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _locate(root: Path, relative: str) -> Path:
    current = root
    for component in Path(relative).parts:
        matches = [
            entry for entry in current.iterdir()
            if entry.name.casefold() == component.casefold()
        ]
        if len(matches) != 1:
            raise InstallSourceError(
                f"extracted ISO must contain exactly one {relative}"
            )
        current = matches[0]
    return current


def _inventory(root: Path) -> tuple[list[dict[str, object]], int]:
    records: list[dict[str, object]] = []
    total = 0
    seen: set[str] = set()
    for path in sorted(root.rglob("*")):
        relative = path.relative_to(root).as_posix()
        folded = relative.casefold()
        if folded in seen:
            raise InstallSourceError(
                f"case-insensitive duplicate path in extracted ISO: {relative}"
            )
        seen.add(folded)
        if path.is_symlink() or not (path.is_dir() or path.is_file()):
            raise InstallSourceError(f"unsafe extracted file type: {relative}")
        if path.is_file():
            if path.stat().st_nlink != 1:
                raise InstallSourceError(f"hard-linked extracted file: {relative}")
            if path.name.casefold() in FORBIDDEN_NAMES:
                raise InstallSourceError(
                    f"secret-bearing answer file is forbidden: {relative}"
                )
            size = path.stat().st_size
            total += size
            records.append(
                {"path": relative, "bytes": size, "sha256": _sha256(path)}
            )
    return records, total


def _check_required(root: Path) -> str:
    for relative in REQUIRED:
        if not _locate(root, relative).is_file():
            raise InstallSourceError(f"required install file is not regular: {relative}")
    images = []
    for relative in INSTALL_IMAGES:
        try:
            candidate = _locate(root, relative)
        except InstallSourceError:
            continue
        if candidate.is_file():
            images.append(relative)
    if len(images) != 1:
        raise InstallSourceError(
            "extracted ISO must contain exactly one sources/install.wim or install.esd"
        )
    return images[0]


def _make_read_only(root: Path, *, root_mode: int = 0o555) -> None:
    for path in sorted(root.rglob("*"), reverse=True):
        os.chmod(path, 0o555 if path.is_dir() else 0o444)
    os.chmod(root, root_mode)


def _fsync_tree(root: Path) -> None:
    """Persist file contents and directory entries without following links."""
    files = [path for path in root.rglob("*") if path.is_file()]
    directories = [path for path in root.rglob("*") if path.is_dir()]
    for path in files:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    for path in sorted(directories, key=lambda item: len(item.parts), reverse=True):
        descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    descriptor = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _validate_receipt(receipt: object, expected_sha256: str) -> list[dict[str, object]]:
    if not isinstance(receipt, dict) or set(receipt) != RECEIPT_KEYS:
        raise InstallSourceError("install-source receipt fields are invalid")
    if receipt["schema"] != RECEIPT_SCHEMA:
        raise InstallSourceError(
            f"install-source receipt schema is not {RECEIPT_SCHEMA}"
        )
    digest = receipt["source_iso_sha256"]
    if (
        not isinstance(digest, str)
        or not windows_iso.SHA256_RE.fullmatch(digest)
        or digest != expected_sha256.lower()
    ):
        raise InstallSourceError("install-source receipt has the wrong source digest")
    source_name = receipt["source_iso"]
    if (
        not isinstance(source_name, str)
        or not source_name
        or Path(source_name).name != source_name
    ):
        raise InstallSourceError("install-source receipt source filename is invalid")
    if receipt["edition"] != "Windows 11 Pro":
        raise InstallSourceError("install-source receipt edition is not Windows 11 Pro")
    if receipt["install_image"] not in INSTALL_IMAGES:
        raise InstallSourceError("install-source receipt install image is invalid")
    if type(receipt["bytes"]) is not int or receipt["bytes"] < 0:
        raise InstallSourceError("install-source receipt byte count is invalid")
    if type(receipt["file_count"]) is not int or receipt["file_count"] < 1:
        raise InstallSourceError("install-source receipt file count is invalid")
    files = receipt["files"]
    if not isinstance(files, list) or receipt["file_count"] != len(files):
        raise InstallSourceError("install-source receipt file list is invalid")
    seen: set[str] = set()
    for record in files:
        if not isinstance(record, dict) or set(record) != FILE_KEYS:
            raise InstallSourceError("install-source receipt file record is invalid")
        relative = record["path"]
        if not isinstance(relative, str) or not relative:
            raise InstallSourceError("install-source receipt path is invalid")
        parsed = PurePosixPath(relative)
        if parsed.is_absolute() or any(part in {"", ".", ".."} for part in parsed.parts):
            raise InstallSourceError("install-source receipt path is unsafe")
        if relative.casefold() in seen:
            raise InstallSourceError("install-source receipt paths are not unique")
        seen.add(relative.casefold())
        if type(record["bytes"]) is not int or record["bytes"] < 0:
            raise InstallSourceError("install-source receipt file size is invalid")
        file_digest = record["sha256"]
        if (
            not isinstance(file_digest, str)
            or not windows_iso.SHA256_RE.fullmatch(file_digest)
            or file_digest != file_digest.lower()
        ):
            raise InstallSourceError("install-source receipt file digest is invalid")
    return files


def verify_cache(output: Path, expected_sha256: str) -> dict:
    if output.is_symlink() or not output.is_dir():
        raise InstallSourceError(f"install-source cache is not a directory: {output}")
    receipt_path = output / "receipt.json"
    try:
        receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise InstallSourceError(f"install-source receipt is unreadable: {exc}") from exc
    expected = _validate_receipt(receipt, expected_sha256)
    actual, total = _inventory(output)
    actual = [record for record in actual if record["path"] != "receipt.json"]
    if actual != expected or total - receipt_path.stat().st_size != receipt.get("bytes"):
        raise InstallSourceError("install-source cache differs from its receipt")
    for path in output.rglob("*"):
        wanted = 0o555 if path.is_dir() else 0o444
        if stat.S_IMODE(path.stat().st_mode) != wanted:
            raise InstallSourceError(f"install-source mode changed: {path}")
    if stat.S_IMODE(output.stat().st_mode) != 0o555:
        raise InstallSourceError("install-source root is not read-only")
    if _check_required(output) != receipt["install_image"]:
        raise InstallSourceError("install-source receipt install image does not match")
    return receipt


def stage(
    iso: Path,
    output: Path,
    expected_sha256: str,
    *,
    run: Callable[[list[str]], str] = windows_iso._run,
    verify_iso: Callable[..., dict] = windows_iso.verify,
) -> dict:
    """Verify *iso*, extract its UDF tree, and atomically promote *output*."""
    iso = iso.resolve(strict=True)
    output = output.absolute()
    for component in (output.parent, *output.parent.parents):
        if component.is_symlink():
            raise InstallSourceError(
                f"output path contains a symbolic link: {component}"
            )
    output.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    if output.is_symlink():
        raise InstallSourceError(f"output must not be a symbolic link: {output}")
    lock_path = output.with_name(output.name + ".lock")
    if lock_path.is_symlink():
        raise InstallSourceError(f"lock must not be a symbolic link: {lock_path}")
    lock_fd = os.open(lock_path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    with os.fdopen(lock_fd, "w") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        if output.exists():
            return verify_cache(output, expected_sha256)
        with tempfile.TemporaryDirectory(
            prefix=f".{output.name}.", dir=output.parent
        ) as work_name:
            work = Path(work_name)
            private_iso = work / "verified-media.iso"
            temporary = work / "source"
            temporary.mkdir(mode=0o700)
            shutil.copyfile(iso, private_iso)
            os.chmod(private_iso, 0o400)
            descriptor = os.open(private_iso, os.O_RDONLY | os.O_NOFOLLOW)
            try:
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
            verification = verify_iso(private_iso, expected_sha256, run=run)
            run(
                [
                    "7z",
                    "x",
                    "-tUdf",
                    "-y",
                    f"-o{temporary}",
                    str(private_iso),
                ]
            )
            install_image = _check_required(temporary)
            records, total = _inventory(temporary)
            receipt = {
                "schema": RECEIPT_SCHEMA,
                "source_iso": iso.name,
                "source_iso_sha256": expected_sha256.lower(),
                "edition": verification.get("edition"),
                "install_image": install_image,
                "bytes": total,
                "file_count": len(records),
                "files": records,
            }
            _validate_receipt(receipt, expected_sha256)
            receipt_path = temporary / "receipt.json"
            with receipt_path.open("w", encoding="utf-8") as stream:
                stream.write(json.dumps(receipt, indent=2, sort_keys=True) + "\n")
                stream.flush()
                os.fsync(stream.fileno())
            # The source directory itself must remain writable until rename:
            # moving a directory updates its internal ".." entry on Linux.
            # All payloads and descendant directories are already read-only.
            _make_read_only(temporary, root_mode=0o700)
            _fsync_tree(temporary)
            temporary.rename(output)
            os.chmod(output, 0o555)
            _fsync_tree(output)
            parent_fd = os.open(
                output.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
            )
            try:
                os.fsync(parent_fd)
            finally:
                os.close(parent_fd)
        return verify_cache(output, expected_sha256)
