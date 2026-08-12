#!/usr/bin/env python3
"""Derive closed Windows diagnostic-sanitization facts from exact sources."""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from dataclasses import dataclass
import json
import os
from pathlib import Path, PurePosixPath
import stat
from typing import NamedTuple

from .secret_scan import count_secret_occurrences, secret_needles


class WindowsIdentityDiagnosticError(RuntimeError):
    """The production diagnostic sources could not be scanned exactly."""


@dataclass(frozen=True)
class RetainedInventory:
    """Exhaustive regular-file inventory beneath one authoritative root.

    A *frozen* inventory (``live_logs`` empty) describes a sealed, quiescent
    tree: its walk must match the declared file set exactly and every entry
    must be byte- and metadata-stable across the scan.

    A *live* inventory (``live_logs`` non-empty) describes the running
    acceptance attempt directory, scanned mid-run while the guest QEMU and the
    simulated switch still own it.  The named ``live_logs`` are the fixed
    append-only runtime logs (e.g. ``runtime/switch.jsonl`` and
    ``runtime/windows-qemu.log``); they may grow by append during the scan.
    Beyond that, new evidence files may appear between the caller's snapshot
    and this walk, so a live inventory tolerates *extra* files and directories
    (they are scanned as found) instead of demanding an exact match.  Every
    other guarantee is preserved: no symlink or nonregular entry, every
    declared path still present, and no scanned file mutated in a
    stale-making way.
    """

    root: Path
    tracked_artifacts: tuple[PurePosixPath, ...]
    logs: tuple[PurePosixPath, ...]
    directories: tuple[PurePosixPath, ...]
    active_media: tuple[PurePosixPath, ...]
    live_logs: tuple[PurePosixPath, ...]

    def __init__(
        self,
        root: Path,
        *,
        tracked_artifacts: Iterable[str | PurePosixPath],
        logs: Iterable[str | PurePosixPath],
        directories: Iterable[str | PurePosixPath] = (),
        active_media: Iterable[str | PurePosixPath] = (),
        live_logs: Iterable[str | PurePosixPath] = (),
    ) -> None:
        object.__setattr__(self, "root", Path(root).absolute())
        object.__setattr__(
            self, "tracked_artifacts",
            tuple(_relative_path(path) for path in tracked_artifacts),
        )
        object.__setattr__(
            self, "logs", tuple(_relative_path(path) for path in logs),
        )
        object.__setattr__(
            self, "directories",
            tuple(_relative_path(path) for path in directories),
        )
        object.__setattr__(
            self, "active_media",
            tuple(_relative_path(path) for path in active_media),
        )
        object.__setattr__(
            self, "live_logs",
            tuple(_relative_path(path) for path in live_logs),
        )
        declared = self.tracked_artifacts + self.logs + self.active_media
        if (
            not declared
            or len(set(declared)) != len(declared)
            or len(set(self.directories)) != len(self.directories)
        ):
            raise WindowsIdentityDiagnosticError(
                "retained inventory paths must be non-empty and unique")
        if (
            len(set(self.live_logs)) != len(self.live_logs)
            or not set(self.live_logs).issubset(self.logs)
        ):
            raise WindowsIdentityDiagnosticError(
                "live logs must be unique declared logs")
        inferred_directories = {
            parent
            for path in declared
            for parent in path.parents
            if parent != PurePosixPath(".")
        }
        if (
            any(path in inferred_directories for path in self.directories)
            or any(path in declared for path in self.directories)
        ):
            raise WindowsIdentityDiagnosticError(
                "explicit retained directories must be empty and unique")


@dataclass(frozen=True)
class CredentialOwnershipState:
    """Live credential ownership at the diagnostic observation boundary.

    Credentials needed by the running acceptance remain in the intended
    in-memory scope. A credential is "retained" only if it exists outside
    that scope, or if the recovery publication still contains a credential
    that the proved rotation did not invalidate.
    """

    acceptance_scope_active: bool
    scoped_credentials: int
    credentials_outside_scope: int
    recovery_publication_exists: bool
    recovered_credential_invalidated: bool


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
    try:
        return secret_needles((secret,))
    except ValueError:
        raise WindowsIdentityDiagnosticError(
            "empty values cannot be used as known secrets") from None


class ScanTarget(NamedTuple):
    """One regular file to read for secrets, with its walk-time identity."""

    path: Path
    relative: PurePosixPath
    kind: str  # "artifact" or "log"
    append_ok: bool  # tolerate append-only growth while scanning


_LOG_SUFFIXES = {".log", ".jsonl"}


def _inventory_files(
    inventory: RetainedInventory,
) -> tuple[
    tuple[ScanTarget, ...],
    dict[PurePosixPath, tuple[int, int, int, int, int]],
]:
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
    active_media = set(inventory.active_media)
    live_logs = set(inventory.live_logs)
    declared_artifacts = set(inventory.tracked_artifacts)
    declared_logs = set(inventory.logs)
    declared = declared_artifacts | declared_logs | active_media
    declared_directories = {
        parent
        for path in declared
        for parent in path.parents
        if parent != PurePosixPath(".")
    }
    declared_directories.update(inventory.directories)
    declared_directories.update(
        parent
        for path in inventory.directories
        for parent in path.parents
        if parent != PurePosixPath(".")
    )
    observed: set[PurePosixPath] = set()
    observed_directories: set[PurePosixPath] = set()
    identities = {PurePosixPath("."): _metadata_identity(metadata)}

    def walk_error(error: OSError) -> None:
        raise WindowsIdentityDiagnosticError(
            "retained inventory could not be enumerated") from error

    for current, directories, files in os.walk(
            root, followlinks=False, onerror=walk_error):
        current_path = Path(current)
        for name in tuple(directories):
            entry = current_path / name
            try:
                item = entry.lstat()
            except OSError as error:
                raise WindowsIdentityDiagnosticError(
                    f"retained inventory changed while enumerated: {entry}"
                ) from error
            if stat.S_ISLNK(item.st_mode) or not stat.S_ISDIR(item.st_mode):
                raise WindowsIdentityDiagnosticError(
                    f"retained inventory contains a non-directory: {entry}")
            relative = PurePosixPath(entry.relative_to(root).as_posix())
            observed_directories.add(relative)
            identities[relative] = _metadata_identity(item)
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
            identities[relative] = _metadata_identity(item)
    if live_logs:
        # A live tree tolerates extra files/directories appearing between the
        # caller's snapshot and this walk, but every declared surface must
        # still be present (a scanned file must not vanish to hide content).
        if not declared.issubset(observed) or not (
                declared_directories.issubset(observed_directories)):
            raise WindowsIdentityDiagnosticError(
                "retained root is missing a declared inventory entry")
    elif observed != declared or observed_directories != declared_directories:
        raise WindowsIdentityDiagnosticError(
            "retained root does not exactly match its exhaustive inventory")
    if live_logs:
        # Scan every regular file actually present now except the active VM
        # media (huge live disk images, intentionally unscanned). New evidence
        # files are scanned as found.
        scan_relatives = observed - active_media
    else:
        scan_relatives = declared_artifacts | declared_logs

    def _kind(relative: PurePosixPath) -> str:
        # Declared files keep the caller's exact artifact/log split; a file
        # that appeared after the caller's snapshot is classified by suffix,
        # the same rule the caller uses to build the declared split.
        if relative in declared_logs:
            return "log"
        if relative in declared_artifacts:
            return "artifact"
        return "log" if relative.suffix in _LOG_SUFFIXES else "artifact"

    targets = tuple(
        ScanTarget(
            path=root / Path(*relative.parts),
            relative=relative,
            kind=_kind(relative),
            append_ok=relative in live_logs,
        )
        for relative in sorted(scan_relatives)
    )
    return targets, identities


def _metadata_identity(item: os.stat_result) -> tuple[int, int, int, int, int]:
    return (
        item.st_dev, item.st_ino, item.st_size, item.st_mtime_ns,
        item.st_ctime_ns,
    )


def _scan_regular_file(
    path: Path, needles: tuple[bytes, ...], *, append_ok: bool = False,
) -> int:
    """Count known-secret encodings in one non-symlink regular file.

    The file's whole current content is read and every declared secret
    encoding counted.  A mutation that would make the read stale fails closed:
    for a normal file the open descriptor's identity must be byte-for-byte
    stable across the read; for an ``append_ok`` live log only monotonic
    append is tolerated -- the inode is unchanged and neither size nor mtime
    moves backwards, so the bytes read remain a valid prefix of the file and
    an in-place rewrite or truncate-and-replace is still rejected.
    """
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
        def blocks() -> Iterable[bytes]:
            while block := os.read(descriptor, 1024 * 1024):
                yield block

        found = count_secret_occurrences(blocks(), needles)
        after = os.fstat(descriptor)
        if append_ok:
            appended_only = (
                before.st_dev == after.st_dev
                and before.st_ino == after.st_ino
                and after.st_size >= before.st_size
                and after.st_mtime_ns >= before.st_mtime_ns
            )
            if not appended_only:
                raise WindowsIdentityDiagnosticError(
                    f"live diagnostic log was rewritten while scanned: {path}")
        elif _metadata_identity(before) != _metadata_identity(after):
            raise WindowsIdentityDiagnosticError(
                f"diagnostic source changed while scanned: {path}")
        return found
    finally:
        os.close(descriptor)


def _verify_scan_stability(
    inventory: RetainedInventory,
    targets: tuple[ScanTarget, ...],
    before: dict[PurePosixPath, tuple[int, int, int, int, int]],
    after: dict[PurePosixPath, tuple[int, int, int, int, int]],
) -> None:
    """Fail closed if a scanned file mutated in a stale-making way.

    A frozen inventory must be identical between the pre-scan and post-scan
    walks -- any change at all is rejected.  A live inventory tolerates the
    benign mid-run motion its structure guarantees (append-only log growth,
    directory mtime churn as evidence lands, new files appearing) and instead
    re-verifies only the files it actually read: an append-only log must have
    grown by append (same inode, non-decreasing size and mtime) and every
    other scanned file must be byte- and metadata-identical to when it was
    read, so a frame or breadcrumb rewritten after its scan is still caught.
    """
    if not inventory.live_logs:
        if before != after:
            raise WindowsIdentityDiagnosticError(
                "retained inventory changed while scanned")
        return
    for target in targets:
        prior = before[target.relative]
        current = after.get(target.relative)
        if current is None:
            # A declared file cannot vanish -- the post-scan walk already
            # rejects that -- so this is a transient new file we scanned; its
            # scan stands regardless of its later disappearance.
            continue
        if target.append_ok:
            appended_only = (
                prior[0] == current[0]
                and prior[1] == current[1]
                and current[2] >= prior[2]
                and current[3] >= prior[3]
            )
            if not appended_only:
                raise WindowsIdentityDiagnosticError(
                    "retained inventory changed while scanned")
        elif prior != current:
            raise WindowsIdentityDiagnosticError(
                "retained inventory changed while scanned")


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
        plans = []
        for inventory in self.retained:
            targets, before = _inventory_files(inventory)
            plans.append((inventory, targets, before))
        artifact_hits = 0
        log_hits = 0
        for _inventory, targets, _before in plans:
            for target in targets:
                hits = _scan_regular_file(
                    target.path, needles, append_ok=target.append_ok)
                if target.kind == "log":
                    log_hits += hits
                else:
                    artifact_hits += hits
        for inventory, targets, before in plans:
            _, after = _inventory_files(inventory)
            _verify_scan_stability(inventory, targets, before, after)
        qemu_payload = json.dumps(
            self.qemu_arguments,
            ensure_ascii=False,
            separators=(",", ":"),
        ).encode("utf-8")
        qemu_hits = count_secret_occurrences((qemu_payload,), needles)
        ownership = self.credential_ownership
        if (
            type(ownership.acceptance_scope_active) is not bool
            or type(ownership.scoped_credentials) is not int
            or ownership.scoped_credentials < 0
            or type(ownership.credentials_outside_scope) is not int
            or ownership.credentials_outside_scope < 0
            or type(ownership.recovery_publication_exists) is not bool
            or type(ownership.recovered_credential_invalidated) is not bool
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
            or (
                ownership.recovery_publication_exists
                and not ownership.recovered_credential_invalidated
            )
        )
        return {
            "secrets_found": artifact_hits + log_hits + qemu_hits,
            "reusable_credentials_retained": retained,
            "qemu_arguments_secret_free": qemu_hits == 0,
            "tracked_artifacts_secret_free": artifact_hits == 0,
            "logs_secret_free": log_hits == 0,
        }
