#!/usr/bin/env python3
"""Derive closed Windows diagnostic-sanitization facts from exact sources."""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from dataclasses import dataclass
import json
import os
from pathlib import Path, PurePosixPath
import stat

from .windows_identity_evidence import _encoded_secret


class WindowsIdentityDiagnosticError(RuntimeError):
    """The production diagnostic sources could not be scanned exactly."""


@dataclass(frozen=True)
class RetainedInventory:
    """Exhaustive regular-file inventory beneath one authoritative root."""

    root: Path
    tracked_artifacts: tuple[PurePosixPath, ...]
    logs: tuple[PurePosixPath, ...]

    def __init__(
        self,
        root: Path,
        *,
        tracked_artifacts: Iterable[str | PurePosixPath],
        logs: Iterable[str | PurePosixPath],
    ) -> None:
        object.__setattr__(self, "root", Path(root).absolute())
        object.__setattr__(
            self, "tracked_artifacts",
            tuple(_relative_path(path) for path in tracked_artifacts),
        )
        object.__setattr__(
            self, "logs", tuple(_relative_path(path) for path in logs),
        )
        declared = self.tracked_artifacts + self.logs
        if not declared or len(set(declared)) != len(declared):
            raise WindowsIdentityDiagnosticError(
                "retained inventory paths must be non-empty and unique")


@dataclass(frozen=True)
class CredentialOwnershipState:
    """Live credential ownership at the diagnostic observation boundary.

    Credentials needed by the running acceptance remain in the intended
    in-memory scope. A credential is "retained" only if it exists outside
    that scope or if the recovery publication still exists.
    """

    acceptance_scope_active: bool
    scoped_credentials: int
    credentials_outside_scope: int
    recovery_publication_exists: bool


def _relative_path(value: str | PurePosixPath) -> PurePosixPath:
    path = PurePosixPath(value)
    if (
        path.is_absolute()
        or not path.parts
        or any(part in {"", ".", ".."} for part in path.parts)
    ):
        raise WindowsIdentityDiagnosticError(
            "retained inventory paths must be normalized and relative")
    return path


def _secret_encodings(secret: str | bytes) -> tuple[bytes, ...]:
    encoded = _encoded_secret(secret)
    if not encoded:
        raise WindowsIdentityDiagnosticError(
            "empty values cannot be used as known secrets")
    variants = {encoded}
    if isinstance(secret, str):
        variants.update((secret.encode("utf-16-le"), secret.encode("utf-16-be")))
    return tuple(sorted(variants, key=len, reverse=True))


def _inventory_files(
    inventory: RetainedInventory,
) -> tuple[tuple[Path, ...], tuple[Path, ...]]:
    root = inventory.root
    for ancestor in (root, *root.parents):
        try:
            ancestor_mode = ancestor.lstat().st_mode
        except OSError as error:
            raise WindowsIdentityDiagnosticError(
                f"retained root ancestry is unavailable: {ancestor}"
            ) from error
        if stat.S_ISLNK(ancestor_mode):
            raise WindowsIdentityDiagnosticError(
                f"retained root ancestry contains a symlink: {ancestor}")
    try:
        metadata = root.lstat()
    except OSError as error:
        raise WindowsIdentityDiagnosticError(
            f"retained root is unavailable: {root}") from error
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
        raise WindowsIdentityDiagnosticError(
            f"retained root is not a real directory: {root}")
    declared = set(inventory.tracked_artifacts + inventory.logs)
    declared_directories = {
        parent
        for path in declared
        for parent in path.parents
        if parent != PurePosixPath(".")
    }
    observed: set[PurePosixPath] = set()
    observed_directories: set[PurePosixPath] = set()

    def walk_error(error: OSError) -> None:
        raise WindowsIdentityDiagnosticError(
            "retained inventory could not be enumerated") from error

    for current, directories, files in os.walk(
            root, followlinks=False, onerror=walk_error):
        current_path = Path(current)
        for name in tuple(directories):
            entry = current_path / name
            if entry.is_symlink():
                raise WindowsIdentityDiagnosticError(
                    f"retained inventory contains a symlink: {entry}")
            observed_directories.add(PurePosixPath(
                entry.relative_to(root).as_posix()))
        for name in files:
            entry = current_path / name
            relative = PurePosixPath(entry.relative_to(root).as_posix())
            try:
                item = entry.lstat()
            except OSError as error:
                raise WindowsIdentityDiagnosticError(
                    f"retained inventory changed while enumerated: {entry}"
                ) from error
            if stat.S_ISLNK(item.st_mode) or not stat.S_ISREG(item.st_mode):
                raise WindowsIdentityDiagnosticError(
                    f"retained inventory contains a nonregular file: {entry}")
            observed.add(relative)
    if observed != declared or observed_directories != declared_directories:
        raise WindowsIdentityDiagnosticError(
            "retained root does not exactly match its exhaustive inventory")
    artifacts = tuple(root / Path(*path.parts)
                      for path in inventory.tracked_artifacts)
    logs = tuple(root / Path(*path.parts) for path in inventory.logs)
    return artifacts, logs


def _scan_regular_file(path: Path, needles: tuple[bytes, ...]) -> int:
    """Count known-secret encodings in one unchanged, non-symlink file."""
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise WindowsIdentityDiagnosticError(
            f"diagnostic source is unavailable: {path}") from error
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise WindowsIdentityDiagnosticError(
                f"diagnostic source is not a regular file: {path}")
        tails = [b""] * len(needles)
        found = 0
        while block := os.read(descriptor, 1024 * 1024):
            for index, needle in enumerate(needles):
                window = tails[index] + block
                found += window.count(needle)
                overlap = len(needle) - 1
                tails[index] = window[-overlap:] if overlap else b""
        after = os.fstat(descriptor)
        identity = lambda item: (  # noqa: E731
            item.st_dev, item.st_ino, item.st_size, item.st_mtime_ns,
            item.st_ctime_ns,
        )
        if identity(before) != identity(after):
            raise WindowsIdentityDiagnosticError(
                f"diagnostic source changed while scanned: {path}")
        return found
    finally:
        os.close(descriptor)


@dataclass(frozen=True)
class ProductionSecretScanner:
    """Scan exact QEMU arguments and exhaustive retained-root inventories."""

    retained: tuple[RetainedInventory, ...]
    qemu_arguments: tuple[str, ...]
    credential_ownership: CredentialOwnershipState

    def __init__(
        self,
        *,
        retained: Iterable[RetainedInventory],
        qemu_arguments: Sequence[str],
        credential_ownership: CredentialOwnershipState,
    ) -> None:
        inventories = tuple(retained)
        arguments = tuple(qemu_arguments)
        if not inventories or any(
                not isinstance(item, RetainedInventory)
                for item in inventories):
            raise WindowsIdentityDiagnosticError(
                "at least one retained inventory is required")
        roots = tuple(item.root for item in inventories)
        if len(set(roots)) != len(roots):
            raise WindowsIdentityDiagnosticError(
                "retained inventory roots must be unique")
        if (
            not arguments
            or any(not isinstance(value, str) or not value for value in arguments)
        ):
            raise WindowsIdentityDiagnosticError(
                "exact QEMU arguments must be non-empty strings")
        if not isinstance(credential_ownership, CredentialOwnershipState):
            raise WindowsIdentityDiagnosticError(
                "structured credential ownership state is required")
        object.__setattr__(self, "retained", inventories)
        object.__setattr__(self, "qemu_arguments", arguments)
        object.__setattr__(self, "credential_ownership", credential_ownership)

    def __call__(self, known_secrets: tuple[str, ...]) -> dict[str, object]:
        """Return the exact ``windows-diagnostics-sanitized`` field set."""
        if not isinstance(known_secrets, tuple) or not known_secrets:
            raise WindowsIdentityDiagnosticError(
                "known secrets must be a non-empty tuple")
        needles = tuple({
            encoding
            for secret in known_secrets
            for encoding in _secret_encodings(secret)
        })
        artifacts: list[Path] = []
        logs: list[Path] = []
        for inventory in self.retained:
            found_artifacts, found_logs = _inventory_files(inventory)
            artifacts.extend(found_artifacts)
            logs.extend(found_logs)
        artifact_hits = sum(
            _scan_regular_file(path, needles) for path in artifacts)
        log_hits = sum(_scan_regular_file(path, needles) for path in logs)
        qemu_payload = json.dumps(
            self.qemu_arguments,
            ensure_ascii=False,
            separators=(",", ":"),
        ).encode("utf-8")
        qemu_hits = sum(qemu_payload.count(needle) for needle in needles)
        ownership = self.credential_ownership
        if (
            type(ownership.acceptance_scope_active) is not bool
            or type(ownership.scoped_credentials) is not int
            or ownership.scoped_credentials < 0
            or type(ownership.credentials_outside_scope) is not int
            or ownership.credentials_outside_scope < 0
            or type(ownership.recovery_publication_exists) is not bool
        ):
            raise WindowsIdentityDiagnosticError(
                "credential ownership state is invalid")
        if (
            not ownership.acceptance_scope_active
            or ownership.scoped_credentials != len(known_secrets)
        ):
            raise WindowsIdentityDiagnosticError(
                "known secrets are not exactly owned by the active scope")
        retained = (
            ownership.credentials_outside_scope > 0
            or ownership.recovery_publication_exists
        )
        return {
            "secrets_found": artifact_hits + log_hits + qemu_hits,
            "reusable_credentials_retained": retained,
            "qemu_arguments_secret_free": qemu_hits == 0,
            "tracked_artifacts_secret_free": artifact_hits == 0,
            "logs_secret_free": log_hits == 0,
        }
