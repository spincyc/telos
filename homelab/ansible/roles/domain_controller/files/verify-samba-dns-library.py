#!/usr/bin/env python3
"""Refuse a stale or unsafe Samba DNS library override before service startup.

The receipt binds this narrow override to the exact official split-package
build.  This checks provenance and filesystem safety, not ELF behavior; the
build's serializer tests and the live DNS wire check establish that separately.
All failures printed by the CLI are fixed categories, without paths, package
output, receipt contents or exception text.
"""

from __future__ import annotations

import argparse
from collections.abc import Callable, Mapping
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys


SONAME = "libndr-nbt.so.0"
BASE_FILENAME = "libndr-nbt.so.0.0.1"
BASE_VERSION = "2:4.24.5-1"
BASE_SHA256 = "478a4a6e623001d7f98e40859308e258b9c2074f4682ca75eefdef2de7c6c4a2"
PACKAGES = ("samba", "smbclient")
MAX_RECEIPT_BYTES = 64 * 1024
SHA256 = re.compile(r"[0-9a-f]{64}\Z")
FAILURES = frozenset({
    "arguments", "unsafe-directory", "unsafe-file", "receipt-format",
    "receipt-binding", "patched-digest", "base-soname", "base-digest",
    "package-query", "package-version", "internal-error",
})


class GuardError(ValueError):
    """A fixed, safe-to-print failure category."""


def trusted_directory(path: Path, *, owner: int, trust_root: Path) -> None:
    """Check every ancestor, rejecting symlink or writable directory paths."""
    path, trust_root = Path(os.path.abspath(path)), Path(os.path.abspath(trust_root))
    try:
        relative = path.relative_to(trust_root)
        current = trust_root
        for part in (None, *relative.parts):
            if part is not None:
                current /= part
            info = current.lstat()
            if (not stat.S_ISDIR(info.st_mode) or info.st_uid != owner
                    or info.st_mode & 0o022):
                raise GuardError("unsafe-directory")
    except (OSError, ValueError) as error:
        raise GuardError("unsafe-directory") from error


def open_regular(path: Path, *, owner: int):
    """Check the opened inode; NOFOLLOW and NONBLOCK also reject links/FIFOs."""
    descriptor = None
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        info = os.fstat(descriptor)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != owner
                or info.st_mode & 0o022):
            raise GuardError("unsafe-file")
        stream = os.fdopen(descriptor, "rb")
        descriptor = None
        return stream
    except OSError as error:
        raise GuardError("unsafe-file") from error
    finally:
        if descriptor is not None:
            os.close(descriptor)


def file_digest(path: Path, *, owner: int) -> str:
    with open_regular(path, owner=owner) as stream:
        digest = hashlib.sha256()
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def unique_object(pairs: list[tuple[str, object]]) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            raise GuardError("receipt-format")
        result[key] = value
    return result


def read_receipt(path: Path, *, owner: int, base_sha256: str) -> dict:
    with open_regular(path, owner=owner) as stream:
        raw = stream.read(MAX_RECEIPT_BYTES + 1)
    if len(raw) > MAX_RECEIPT_BYTES:
        raise GuardError("receipt-format")
    try:
        receipt = json.loads(raw, object_pairs_hook=unique_object)
    except (ValueError, UnicodeError, RecursionError) as error:
        raise GuardError("receipt-format") from error
    if not isinstance(receipt, dict):
        raise GuardError("receipt-format")
    for field in ("library_sha256", "base_library_sha256"):
        value = receipt.get(field)
        if not isinstance(value, str) or not SHA256.fullmatch(value):
            raise GuardError("receipt-format")
    if (type(receipt.get("schema")) is not int or receipt["schema"] != 1
            or receipt.get("base_package") != "smbclient"
            or receipt.get("base_package_version") != BASE_VERSION
            or receipt.get("soname") != SONAME
            or receipt["base_library_sha256"] != base_sha256
            or receipt["library_sha256"] == base_sha256):
        raise GuardError("receipt-binding")
    return receipt


def installed_packages(*, run: Callable = subprocess.run) -> dict[str, str]:
    """Query the official package database without the service's loader env."""
    try:
        result = run(
            ["/usr/bin/pacman", "-Q", *PACKAGES],
            stdin=subprocess.DEVNULL, capture_output=True, text=True,
            encoding="ascii", errors="strict", timeout=10, check=False,
            env={"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"})
        if result.returncode != 0:
            raise GuardError("package-query")
        packages = {}
        for line in result.stdout.splitlines():
            fields = line.split()
            if len(fields) != 2 or fields[0] not in PACKAGES or fields[0] in packages:
                raise GuardError("package-query")
            packages[fields[0]] = fields[1]
        if set(packages) != set(PACKAGES):
            raise GuardError("package-query")
        return packages
    except (OSError, subprocess.SubprocessError, UnicodeError) as error:
        raise GuardError("package-query") from error


def verify(
    directory: Path, *, base_directory: Path = Path("/usr/lib"),
    owner: int = 0, trust_root: Path = Path("/"),
    base_sha256: str = BASE_SHA256,
    package_query: Callable[[], Mapping[str, str]] = installed_packages,
) -> None:
    """Validate an override; injectable boundaries keep tests off live state.

    Only ``directory`` is selectable at the CLI. The ownership, base path,
    package/version pins and expected official digest are not runtime options.
    """
    directory, base_directory = Path(directory), Path(base_directory)
    trusted_directory(directory, owner=owner, trust_root=trust_root)
    trusted_directory(base_directory, owner=owner, trust_root=trust_root)
    receipt = read_receipt(directory / "receipt.json", owner=owner,
                           base_sha256=base_sha256)
    if file_digest(directory / SONAME, owner=owner) != receipt["library_sha256"]:
        raise GuardError("patched-digest")
    base = base_directory / BASE_FILENAME
    try:
        link = base_directory / SONAME
        info = link.lstat()
        if (not stat.S_ISLNK(info.st_mode) or info.st_uid != owner
                or os.readlink(link) not in (BASE_FILENAME, str(base.absolute()))
                or link.resolve(strict=True) != base.absolute()):
            raise GuardError("base-soname")
    except (OSError, RuntimeError) as error:
        raise GuardError("base-soname") from error
    if file_digest(base, owner=owner) != base_sha256:
        raise GuardError("base-digest")
    packages = package_query()
    if (set(packages) != set(PACKAGES)
            or any(packages[name] != BASE_VERSION for name in PACKAGES)):
        raise GuardError("package-version")


class Parser(argparse.ArgumentParser):
    def error(self, _message):
        self.exit(2, "samba-dns-library-guard: arguments\n")


def main(argv: list[str] | None = None, *, verifier: Callable = verify) -> int:
    parser = Parser(description=__doc__)
    parser.add_argument("--directory", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        verifier(args.directory)
    except Exception as error:
        category = (str(error) if isinstance(error, GuardError)
                    and str(error) in FAILURES else "internal-error")
        print(f"samba-dns-library-guard: {category}", file=sys.stderr)
        return 1
    print("samba-dns-library-guard: pass")
    return 0


if __name__ == "__main__":
    sys.exit(main())
