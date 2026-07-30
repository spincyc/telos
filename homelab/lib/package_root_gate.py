"""Read-only package identity and binary ownership evidence for an Arch root."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import os
from pathlib import Path, PurePosixPath
import stat

from .package_contract import MergedPackageContract, PACKAGE_RE


class PackageRootGateError(RuntimeError):
    """The candidate root cannot supply confined, exact package evidence."""


@dataclass(frozen=True, order=True)
class InstalledPackage:
    name: str
    version: str


@dataclass(frozen=True, order=True)
class OwnedBinary:
    path: str
    owner: str
    resolved_path: str


@dataclass(frozen=True)
class PackageRootEvidence:
    root: str
    installed_packages: tuple[InstalledPackage, ...]
    required_packages: tuple[str, ...]
    binaries: tuple[OwnedBinary, ...]


def _fail(message: str) -> PackageRootGateError:
    return PackageRootGateError(message)


def _open_directory_chain(path: Path) -> int:
    if not isinstance(path, Path) or not path.is_absolute() or str(path) == "/":
        raise _fail("package root must be a non-root absolute Path")
    if ".." in path.parts or any(ord(char) < 32 or ord(char) == 127
                                 for char in str(path)):
        raise _fail("package root is not normalized")
    descriptor = os.open("/", os.O_RDONLY | os.O_DIRECTORY)
    try:
        for component in path.parts[1:]:
            following = os.open(
                component,
                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                dir_fd=descriptor,
            )
            os.close(descriptor)
            descriptor = following
    except (OSError, ValueError) as error:
        os.close(descriptor)
        raise _fail("package root is absent or has a symlinked ancestor") from error
    return descriptor


def _open_child_directory(parent: int, name: str) -> int:
    try:
        return os.open(
            name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
    except OSError as error:
        raise _fail(f"required package database directory is unsafe: {name}") from error


def _read_regular(parent: int, name: str, *, limit: int = 1024 * 1024) -> str:
    try:
        descriptor = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=parent)
        try:
            metadata = os.fstat(descriptor)
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > limit:
                raise _fail(f"package database file is unsafe: {name}")
            content = os.read(descriptor, limit + 1)
            if len(content) != metadata.st_size:
                raise _fail(f"package database file changed while read: {name}")
        finally:
            os.close(descriptor)
        return content.decode("utf-8")
    except (OSError, UnicodeError) as error:
        raise _fail(f"cannot read package database file: {name}") from error


def _sections(content: str, source: str) -> dict[str, tuple[str, ...]]:
    lines = content.splitlines()
    result: dict[str, tuple[str, ...]] = {}
    index = 0
    while index < len(lines):
        marker = lines[index]
        if not (marker.startswith("%") and marker.endswith("%")
                and len(marker) > 2):
            raise _fail(f"malformed package database record: {source}")
        name = marker[1:-1]
        if name in result:
            raise _fail(f"duplicate package database section: {source}:{name}")
        index += 1
        start = index
        while index < len(lines) and lines[index] != "":
            index += 1
        result[name] = tuple(lines[start:index])
        index += 1
    return result


def _single(sections: dict[str, tuple[str, ...]], name: str, source: str) -> str:
    values = sections.get(name, ())
    if len(values) != 1 or not values[0]:
        raise _fail(f"package database record lacks exact {name}: {source}")
    return values[0]


def _package_database(
    root_fd: int,
) -> tuple[tuple[InstalledPackage, ...], dict[str, str]]:
    descriptors = [os.dup(root_fd)]
    try:
        for component in ("var", "lib", "pacman", "local"):
            descriptors.append(_open_child_directory(descriptors[-1], component))
        local_fd = descriptors[-1]
        packages: dict[str, InstalledPackage] = {}
        owners: dict[str, str] = {}
        for entry in sorted(os.listdir(local_fd)):
            if entry == "ALPM_DB_VERSION":
                continue
            entry_fd = _open_child_directory(local_fd, entry)
            try:
                desc = _sections(_read_regular(entry_fd, "desc"), f"{entry}/desc")
                files = _sections(_read_regular(entry_fd, "files"), f"{entry}/files")
            finally:
                os.close(entry_fd)
            name = _single(desc, "NAME", entry)
            version = _single(desc, "VERSION", entry)
            if not PACKAGE_RE.fullmatch(name):
                raise _fail(f"package database has invalid package name: {entry}")
            if any(character.isspace() or ord(character) < 32
                   or ord(character) == 127 for character in version):
                raise _fail(f"package database has invalid version: {entry}")
            if entry != f"{name}-{version}":
                raise _fail(f"package database directory identity differs: {entry}")
            if name in packages:
                raise _fail(f"duplicate installed package identity: {name}")
            packages[name] = InstalledPackage(name, version)
            for item in files.get("FILES", ()):
                is_directory = item.endswith("/")
                candidate = item[:-1] if is_directory else item
                path = PurePosixPath(candidate)
                if (path.is_absolute() or ".." in path.parts
                        or candidate == "." or str(path) != candidate
                        or not candidate
                        or any(ord(character) < 32 or ord(character) == 127
                               for character in candidate)):
                    raise _fail(f"unsafe package file path: {name}")
                if is_directory:
                    continue
                guest_path = "/" + item
                if guest_path in owners:
                    raise _fail(f"duplicate package file ownership: {guest_path}")
                owners[guest_path] = name
        return tuple(sorted(packages.values())), owners
    finally:
        for descriptor in reversed(descriptors):
            os.close(descriptor)


def _database_fingerprint(root_fd: int) -> tuple[tuple[str, str, str], ...]:
    descriptors = [os.dup(root_fd)]
    try:
        for component in ("var", "lib", "pacman", "local"):
            descriptors.append(_open_child_directory(descriptors[-1], component))
        local_fd = descriptors[-1]
        fingerprint: list[tuple[str, str, str]] = []
        for entry in sorted(os.listdir(local_fd)):
            if entry == "ALPM_DB_VERSION":
                version = _read_regular(local_fd, entry, limit=64)
                if not version.endswith("\n") or not version[:-1].isdigit():
                    raise _fail("invalid ALPM database version marker")
                fingerprint.append((
                    entry, "", hashlib.sha256(version.encode()).hexdigest()))
                continue
            entry_fd = _open_child_directory(local_fd, entry)
            try:
                for name in ("desc", "files"):
                    content = _read_regular(entry_fd, name)
                    fingerprint.append((
                        entry, name,
                        hashlib.sha256(content.encode()).hexdigest(),
                    ))
            finally:
                os.close(entry_fd)
        return tuple(fingerprint)
    finally:
        for descriptor in reversed(descriptors):
            os.close(descriptor)


def _confined_executable(root_fd: int, guest_path: str) -> tuple[str, int]:
    pending = list(PurePosixPath(guest_path).parts[1:])
    resolved: list[str] = []
    links = 0
    while pending:
        parent = os.dup(root_fd)
        try:
            for component in resolved:
                following = os.open(
                    component,
                    os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                    dir_fd=parent,
                )
                os.close(parent)
                parent = following
            component = pending.pop(0)
            metadata = os.stat(component, dir_fd=parent, follow_symlinks=False)
            if stat.S_ISLNK(metadata.st_mode):
                links += 1
                if links > 40:
                    raise _fail(f"binary symlink chain is too deep: {guest_path}")
                target = os.readlink(component, dir_fd=parent)
                target_path = PurePosixPath(target)
                candidate = (
                    list(target_path.parts[1:]) if target_path.is_absolute()
                    else resolved + list(target_path.parts)
                )
                normalized: list[str] = []
                for part in candidate:
                    if part in ("", "."):
                        continue
                    if part == "..":
                        if not normalized:
                            raise _fail(f"binary symlink escapes root: {guest_path}")
                        normalized.pop()
                    else:
                        normalized.append(part)
                resolved = []
                pending = normalized + pending
            elif pending:
                if not stat.S_ISDIR(metadata.st_mode):
                    raise _fail(f"binary ancestor is not a directory: {guest_path}")
                resolved.append(component)
            else:
                executable_fd = os.open(
                    component,
                    os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW,
                    dir_fd=parent,
                )
                opened = os.fstat(executable_fd)
                if (not stat.S_ISREG(opened.st_mode)
                        or opened.st_mode & 0o111 == 0
                        or (opened.st_dev, opened.st_ino)
                        != (metadata.st_dev, metadata.st_ino)):
                    os.close(executable_fd)
                    raise _fail(f"binary is not a regular executable: {guest_path}")
                resolved.append(component)
        except OSError as error:
            raise _fail(f"cannot inspect required binary: {guest_path}") from error
        finally:
            os.close(parent)
    return "/" + "/".join(resolved), executable_fd


def audit_package_root(
    root: Path,
    contract: MergedPackageContract,
) -> PackageRootEvidence:
    """Prove installed identities and required binary owners inside one root."""
    if type(contract) is not MergedPackageContract:
        raise _fail("contract must be a merged package contract")
    root_fd = _open_directory_chain(root)
    executable_fds: list[int] = []
    try:
        database_before = _database_fingerprint(root_fd)
        installed, owners = _package_database(root_fd)
        installed_names = {package.name for package in installed}
        missing = sorted(set(contract.packages) - installed_names)
        if missing:
            raise _fail(f"required package is not installed: {missing[0]}")
        binaries: list[OwnedBinary] = []
        for binary in contract.binaries:
            if owners.get(binary.path) != binary.owner:
                raise _fail(f"package database has wrong owner: {binary.path}")
            resolved_path, executable_fd = _confined_executable(
                root_fd, binary.path)
            executable_fds.append(executable_fd)
            if owners.get(resolved_path) != binary.owner:
                raise _fail(
                    f"package database has wrong resolved owner: {binary.path}")
            binaries.append(OwnedBinary(
                binary.path,
                binary.owner,
                resolved_path,
            ))
        evidence = PackageRootEvidence(
            root=str(root),
            installed_packages=installed,
            required_packages=contract.packages,
            binaries=tuple(binaries),
        )
        if _database_fingerprint(root_fd) != database_before:
            raise _fail("package database changed during audit")
        return evidence
    finally:
        for descriptor in executable_fds:
            os.close(descriptor)
        os.close(root_fd)
