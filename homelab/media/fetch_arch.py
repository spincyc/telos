#!/usr/bin/env python3
"""Fetch and verify the current official Arch Linux installation image."""

from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import tempfile
import urllib.request
from contextlib import contextmanager
from pathlib import Path
from typing import Callable, Sequence
from urllib.parse import urlsplit

DEFAULT_BASE_URL = "https://geo.mirror.pkgbuild.com/iso/latest"
OFFICIAL_DOWNLOAD_HOSTS = frozenset({"geo.mirror.pkgbuild.com"})
RELEASE_EMAIL = "pierre@archlinux.org"
RELEASE_FINGERPRINT = "3E80CA1A8B89F69CBA57D98A76A5EF9054449A5C"
RELEASE_SIGNING_FINGERPRINT = RELEASE_FINGERPRINT
ISO_PATTERN = re.compile(r"^([0-9a-f]{64})  (archlinux-\d{4}\.\d{2}\.\d{2}-x86_64\.iso)$")


class FetchError(RuntimeError):
    """A media fetch or verification failed."""


def _require_official_url(url: str) -> None:
    parsed = urlsplit(url)
    if (
        parsed.scheme != "https"
        or parsed.hostname not in OFFICIAL_DOWNLOAD_HOSTS
        or parsed.username is not None
        or parsed.password is not None
        or parsed.port not in (None, 443)
    ):
        raise FetchError(f"refusing non-official Arch download URL: {url}")


def _require_safe_file(path: Path, *, allow_missing: bool = True) -> None:
    try:
        status = path.lstat()
    except FileNotFoundError:
        if allow_missing:
            return
        raise
    if (
        not stat.S_ISREG(status.st_mode)
        or status.st_uid != os.geteuid()
        or status.st_nlink != 1
    ):
        raise FetchError(f"refusing unsafe cache entry: {path}")


def _secure_directory(path: Path) -> None:
    if path.is_symlink():
        raise FetchError(f"refusing symlink cache directory: {path}")
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    if not path.is_dir() or path.is_symlink():
        raise FetchError(f"cache path is not a safe directory: {path}")
    path.chmod(0o700)


@contextmanager
def cache_lock(cache_dir: Path):
    """Serialize fetches that publish into the same cache."""
    lock_path = cache_dir / ".fetch.lock"
    _require_safe_file(lock_path)
    descriptor = os.open(lock_path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        os.fchmod(descriptor, 0o600)
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        yield
    finally:
        fcntl.flock(descriptor, fcntl.LOCK_UN)
        os.close(descriptor)


def download(url: str, destination: Path) -> None:
    """Download *url* atomically, leaving no partial artifact on failure."""
    _require_official_url(url)
    _secure_directory(destination.parent)
    _require_safe_file(destination)
    handle, temporary_name = tempfile.mkstemp(
        prefix=f".{destination.name}.", suffix=".part", dir=destination.parent
    )
    os.fchmod(handle, 0o600)
    os.close(handle)
    temporary = Path(temporary_name)
    try:
        request = urllib.request.Request(url, headers={"User-Agent": "telos-media-fetch/1"})
        with urllib.request.urlopen(request, timeout=60) as source, temporary.open("wb") as target:
            _require_official_url(source.geturl())
            shutil.copyfileobj(source, target, length=1024 * 1024)
            target.flush()
            os.fsync(target.fileno())
        temporary.chmod(0o600)
        temporary.replace(destination)
    except Exception:
        temporary.unlink(missing_ok=True)
        raise


def release_from_sums(text: str) -> tuple[str, str]:
    candidates = [match.groups() for line in text.splitlines() if (match := ISO_PATTERN.match(line))]
    if len(candidates) != 1:
        raise FetchError("official checksum file did not name exactly one versioned Arch ISO")
    checksum, filename = candidates[0]
    return filename, checksum


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def verify_checksum(path: Path, expected: str) -> None:
    actual = sha256(path)
    if actual != expected:
        raise FetchError(f"SHA-256 mismatch for {path.name}: expected {expected}, got {actual}")


def _run(command: Sequence[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, check=True, text=True, capture_output=True)


def ensure_release_key(
    keyring: Path,
    runner: Callable[[Sequence[str]], subprocess.CompletedProcess[str]] = _run,
) -> None:
    keyring.mkdir(parents=True, exist_ok=True)
    common = ("gpg", "--batch", "--homedir", str(keyring))
    try:
        result = runner((*common, "--with-colons", "--fingerprint", RELEASE_FINGERPRINT))
    except (subprocess.CalledProcessError, FileNotFoundError):
        result = None
    if result is None or RELEASE_FINGERPRINT not in result.stdout.replace(":", ""):
        try:
            runner(
                (
                    *common,
                    "--auto-key-locate",
                    "clear,wkd",
                    "--locate-external-key",
                    RELEASE_EMAIL,
                )
            )
        except FileNotFoundError as error:
            raise FetchError("gpg is required to authenticate the Arch ISO") from error
        except subprocess.CalledProcessError as error:
            raise FetchError("could not retrieve the Arch release key from its official WKD") from error

    result = runner((*common, "--with-colons", "--fingerprint", RELEASE_FINGERPRINT))
    fingerprints = {
        fields[9]
        for line in result.stdout.splitlines()
        if (fields := line.split(":"))[0] == "fpr" and len(fields) > 9
    }
    if RELEASE_FINGERPRINT not in fingerprints:
        raise FetchError("retrieved release key did not match the pinned Arch developer fingerprint")


def verify_signature(
    image: Path,
    signature: Path,
    keyring: Path,
    runner: Callable[[Sequence[str]], subprocess.CompletedProcess[str]] = _run,
) -> None:
    try:
        result = runner(
            (
                "gpg",
                "--batch",
                "--homedir",
                str(keyring),
                "--status-fd",
                "1",
                "--verify",
                str(signature),
                str(image),
            )
        )
    except subprocess.CalledProcessError as error:
        raise FetchError(f"OpenPGP signature verification failed for {image.name}") from error
    valid = []
    for line in result.stdout.splitlines():
        marker = "[GNUPG:] VALIDSIG "
        if line.startswith(marker):
            fields = line[len(marker) :].split()
            if fields:
                valid.append(fields[0])
    if valid != [RELEASE_SIGNING_FINGERPRINT]:
        raise FetchError(
            "OpenPGP signature was not made by the pinned Arch release-signing key"
        )


def _atomic_json(path: Path, payload: dict[str, str]) -> None:
    _require_safe_file(path)
    handle, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".part", dir=path.parent
    )
    try:
        os.fchmod(handle, 0o600)
        with os.fdopen(handle, "w", encoding="utf-8") as stream:
            json.dump(payload, stream, sort_keys=True)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary_name, path)
    except Exception:
        Path(temporary_name).unlink(missing_ok=True)
        raise


def _atomic_symlink(path: Path, target: str) -> None:
    if path.exists() and not path.is_symlink():
        raise FetchError(f"refusing to replace non-symlink publication path: {path}")
    temporary = path.with_name(f".{path.name}.{os.getpid()}.link")
    if temporary.exists() or temporary.is_symlink():
        temporary.unlink()
    try:
        temporary.symlink_to(target)
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def fetch(
    cache_dir: Path,
    base_url: str = DEFAULT_BASE_URL,
    downloader: Callable[[str, Path], None] = download,
    runner: Callable[[Sequence[str]], subprocess.CompletedProcess[str]] = _run,
) -> dict[str, str]:
    _secure_directory(cache_dir)
    if downloader is download:
        _require_official_url(base_url)
    with cache_lock(cache_dir):
        metadata = cache_dir / "metadata"
        _secure_directory(metadata)
        sums = metadata / "sha256sums.txt"

        # Metadata is deliberately refreshed on every invocation. The large image is
        # reused only when its locally calculated digest matches the current release.
        downloader(f"{base_url.rstrip('/')}/sha256sums.txt", sums)
        _require_safe_file(sums, allow_missing=False)
        sums.chmod(0o600)
        filename, expected = release_from_sums(sums.read_text(encoding="utf-8"))
        image = cache_dir / filename
        signature = cache_dir / f"{filename}.sig"
        _require_safe_file(image)
        _require_safe_file(signature)

        cached = image.is_file() and sha256(image) == expected
        if not cached:
            image.unlink(missing_ok=True)
            downloader(f"{base_url.rstrip('/')}/{filename}", image)
            _require_safe_file(image, allow_missing=False)
        verify_checksum(image, expected)
        image.chmod(0o600)

        downloader(f"{base_url.rstrip('/')}/{filename}.sig", signature)
        _require_safe_file(signature, allow_missing=False)
        signature.chmod(0o600)
        keyring = cache_dir / "keyring"
        _secure_directory(keyring)
        ensure_release_key(keyring, runner)
        verify_signature(image, signature, keyring, runner)

        source = f"{base_url.rstrip('/')}/{filename}"
        receipt = cache_dir / f"{filename}.receipt.json"
        receipt_payload = {
            "filename": filename,
            "sha256": expected,
            "source": source,
            "signing_fingerprint": RELEASE_SIGNING_FINGERPRINT,
        }
        _atomic_json(receipt, receipt_payload)
        current = cache_dir / "archlinux-x86_64.iso"
        _atomic_symlink(current, image.name)
        current_receipt = cache_dir / "archlinux-x86_64.iso.receipt.json"
        _atomic_json(current_receipt, receipt_payload)
        return {
            "image": str(image.resolve()),
            "current": str(current.resolve()),
            "receipt": str(current_receipt.resolve()),
            "sha256": expected,
            "source": source,
            "cached": str(cached).lower(),
        }


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Fetch the latest Arch ISO and verify its SHA-256 and OpenPGP signature."
    )
    parser.add_argument(
        "--cache-dir",
        type=Path,
        default=Path("homelab/var/media/arch"),
        help="persistent download cache (default: homelab/var/media/arch)",
    )
    parser.add_argument(
        "--base-url",
        default=DEFAULT_BASE_URL,
        help="official Arch mirror release directory",
    )
    parser.add_argument("--json", action="store_true", help="emit machine-readable results")
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    arguments = parse_args(argv)
    try:
        result = fetch(arguments.cache_dir, arguments.base_url)
    except (FetchError, OSError) as error:
        raise SystemExit(f"error: {error}") from error
    if arguments.json:
        print(json.dumps(result, sort_keys=True))
    else:
        print(f"verified Arch installation image: {result['image']}")
        print(f"SHA-256: {result['sha256']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
