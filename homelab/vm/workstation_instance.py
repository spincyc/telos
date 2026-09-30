#!/usr/bin/env python3
"""A kept workstation disk bound to one persistent Controller instance.

The durable workstation flow (``homelab/DURABLE-WORKSTATION-FLOW.md``, step 4)
mints a Windows-and-Arch disk that is meant to be kept. Every disposable run
directory under ``homelab/var/factory`` is bulk-cleaned, so a kept workstation
``W`` lives in its own state directory, ``build/homelab/vm/workstations/<name>``,
beside ``persistent-dc/``. It is modelled on ``PersistentControllerInstance``
(``simulation_overlay``): a marker it must carry to be recognised at all, an
exclusive lock, private files, and an erase that needs the exact
``DESTROY <name>`` phrase.

What ``W`` holds:

``workstation.qcow2``
    A standalone qcow2 with no backing file. It changes only by ``fold``: every
    stage boots an overlay backed by it, and on success that overlay is
    flattened into a new standalone copy that is renamed over it. ``W`` is
    never booted in place, so its SHA-256 always equals the head of the ledger,
    and ``fold`` refuses a disk that no longer does.
``OVMF_VARS.fd``
    The firmware variables that belong to the disk (boot entries live there),
    copied from the gate-5 bundle and optionally replaced by a fold.
``publication.iso``
    The gate-5 bundle's one-use publication. It carries the Windows local
    administrator credential, so it is MOVED, never copied: after adoption the
    only copy is here, mode 0600, and ``W`` has custody until
    ``retire_publication`` or ``destroy`` shreds it.
``workstation-instance.json``
    The marker: the bound persistent instance, realm and domain SID (values
    handed in, never read from the private identity overlay here), the machine
    accounts the workstation has left in that directory, and an append-only
    stage ledger of ``{stage, utc, disk_sha256, vars_sha256, source}``. Every
    rewrite stages into one fixed name, fsyncs and renames, and refuses to
    change history.

A fold is a two-phase commit: once the staged disk (and variables) are fsynced
and hashed, the new ledger entry is recorded as ``pending_fold``; then the disk
is renamed into place, then the variables, then the entry moves onto the
ledger. The disk rename is the commit point. No stage runner boots ``W`` while
a fold is pending (``pending_fold_refusal``); ``reconcile``
(``make homelab-durable-workstation-reconcile``, a dry run without
``APPLY=1``) resolves it from the files' own hashes under the lock, and never
guesses (``recovery``):

=====================================  ============  ======================
live disk / firmware variables         action        how
=====================================  ============  ======================
fold's disk; fold's vars in place      complete      append the entry
fold's disk; fold's vars still staged  complete      rename them, append
ledger head's disk and vars intact     roll back     drop the entry
anything else                          refuse        change nothing
=====================================  ============  ======================

Every applied action ends by discarding leftover staging files, which also
clears a staging copy that was interrupted before any fold was recorded.
``fold`` applies the same decision before it folds.
"""

from __future__ import annotations

import argparse
import contextlib
import errno
import fcntl
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

try:
    from . import credential_custody as _custody
    from .simulation_overlay import (
        DESTROY_CONFIRMATION_PREFIX,
        DOMAIN_SID,
        LOCK_NAME,
        PERSISTENT_INSTANCE_NAME,
        PersistentControllerInstance,
        canonical_disk_users,
        sha256,
    )
except ImportError:  # Direct execution from homelab/vm.
    import credential_custody as _custody
    from simulation_overlay import (
        DESTROY_CONFIRMATION_PREFIX,
        DOMAIN_SID,
        LOCK_NAME,
        PERSISTENT_INSTANCE_NAME,
        PersistentControllerInstance,
        canonical_disk_users,
        sha256,
    )


REPOSITORY = Path(__file__).resolve().parents[2]
DEFAULT_ROOT = Path("build/homelab/vm/workstations")
#: Bulk-cleaned by the factory tooling; a kept workstation must never live here.
BULK_CLEANED_RELATIVE = Path("homelab/var/factory")

DISK_NAME = "workstation.qcow2"
VARS_NAME = "OVMF_VARS.fd"
PUBLICATION_NAME = "publication.iso"
MARKER_NAME = "workstation-instance.json"
#: Fixed staging names, never random ones: an interrupted write leaves exactly
#: one predictable leftover that the next write truncates and ``destroy`` knows.
MARKER_STAGING_NAME = "." + MARKER_NAME + ".new"
DISK_STAGING_NAME = "." + DISK_NAME + ".new"
VARS_STAGING_NAME = "." + VARS_NAME + ".new"
MARKER_SCHEMA = 1
MARKER_KIND = "durable-workstation"

#: The gate-5 bundle's own names (``windows_install_prepare``).
BUNDLE_DISK_NAME = "windows.qcow2"
BUNDLE_VARS_NAME = "OVMF_VARS.fd"
BUNDLE_PUBLICATION_NAME = "publication.iso"
BUNDLE_RESULT = Path("evidence/result.json")
BUNDLE_PASS_PHASE = "native-windows-clean-shutdown"

#: The disk-changing stages of the approved flow, in order. ``adopt`` opens the
#: ledger; each later stage folds exactly once, in this order. Keep-verify
#: re-proves the joins on an overlay and folds nothing.
FLOW_STAGES = ("adopt", "arch-install", "arch-join", "windows-join")
#: The publication carries the Windows local administrator credential the
#: durable Windows join rotates, so it is kept until that stage has FOLDED: a
#: failed join then needs a retry, not a 70-minute reinstall.
PUBLICATION_NEEDED_UNTIL = "windows-join"
#: Head room kept free beyond qemu-img's own estimate of a standalone copy.
SPACE_MARGIN_BYTES = 256 * 1024 * 1024
#: The Make target an operator runs to resolve an interrupted fold.
RECONCILE_TARGET = "homelab-durable-workstation-reconcile"
#: ``recovery`` actions.
RECOVERY_NONE = "none"
RECOVERY_COMPLETE = "complete"
RECOVERY_ROLL_BACK = "roll-back"
RECOVERY_REFUSE = "refuse"

_SHA256 = re.compile(r"[0-9a-f]{64}")
_REALM = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?")
#: A computer account: a NetBIOS name of at most 15 characters, optionally in
#: its ``sAMAccountName`` form with the trailing ``$``.
_MACHINE_ACCOUNT = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,14})\$?")
_IMMUTABLE_KEYS = ("schema", "kind", "workstation", "created_utc", "binding")


class WorkstationInvalid(RuntimeError):
    """The named state is not a usable kept workstation, or the request is."""


class WorkstationInUse(RuntimeError):
    """The workstation's lock or one of its files is held elsewhere."""


def _now() -> str:
    return datetime.now(UTC).isoformat()


def _regular_file(path: Path) -> bool:
    return path.is_file() and not path.is_symlink()


def _path_has_symlink(path: Path) -> bool:
    candidate = Path(path).absolute()
    return any(
        component.is_symlink()
        for component in (candidate, *candidate.parents)
        if component.exists())


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _fsync_file(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _write_private_json(directory: Path, name: str, staging_name: str,
                        payload: dict) -> None:
    """Stage, fsync and rename one 0600 JSON file into ``directory``."""
    staging = directory / staging_name
    # O_NOFOLLOW so a planted symlink cannot redirect the write; O_TRUNC so an
    # interrupted rewrite's leftover is replaced rather than appended to.
    descriptor = os.open(
        staging, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            stream.write(json.dumps(payload, indent=2) + "\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(staging, 0o600)
        os.replace(staging, directory / name)
        _fsync_directory(directory)
    except BaseException:
        staging.unlink(missing_ok=True)
        raise


def _image_info(path: Path) -> dict:
    """``qemu-img info``; it takes qemu's read lock, so a live writer fails it."""
    try:
        completed = subprocess.run(
            ["qemu-img", "info", "--output=json", str(path)],
            check=True, capture_output=True, text=True)
    except subprocess.CalledProcessError as error:
        raise WorkstationInUse(
            f"qemu-img could not lock/read {path}; is a guest still using "
            "it?") from error
    return json.loads(completed.stdout)


def _required_bytes(path: Path) -> int:
    """qemu-img's own estimate of a flattened qcow2 copy of ``path``."""
    completed = subprocess.run(
        ["qemu-img", "measure", "--output=json", "-O", "qcow2", str(path)],
        check=True, capture_output=True, text=True)
    return int(json.loads(completed.stdout)["required"])


def _existing_ancestor(path: Path) -> Path:
    for candidate in (path, *path.parents):
        if candidate.is_dir():
            return candidate
    return Path("/")


def _assert_space(source: Path, directory: Path) -> tuple[int, int]:
    required = _required_bytes(source)
    free = shutil.disk_usage(_existing_ancestor(directory)).free
    if free < required + SPACE_MARGIN_BYTES:
        raise WorkstationInvalid(
            f"not enough free space in {directory} for a standalone copy of "
            f"{source}: {required} bytes needed plus "
            f"{SPACE_MARGIN_BYTES} head room, {free} free")
    return required, free


def _convert_standalone(source: Path, target: Path) -> None:
    """Flatten ``source`` (and any backing chain) into a standalone qcow2."""
    if target.is_symlink():
        raise WorkstationInvalid(f"refusing a symlinked staging file: {target}")
    target.unlink(missing_ok=True)
    subprocess.run(
        ["qemu-img", "convert", "-f", "qcow2", "-O", "qcow2",
         str(source), str(target)],
        check=True, capture_output=True)
    os.chmod(target, 0o600)
    _fsync_file(target)
    info = _image_info(target)
    if info.get("format") != "qcow2" or any(
            key in info for key in ("backing-filename", "full-backing-filename")):
        raise WorkstationInvalid(
            f"the converted disk is not a standalone qcow2: {target}")


def _copy_private(source: Path, target: Path) -> None:
    if target.is_symlink():
        raise WorkstationInvalid(f"refusing a symlinked staging file: {target}")
    target.unlink(missing_ok=True)
    shutil.copyfile(source, target)
    os.chmod(target, 0o600)
    _fsync_file(target)


def _shred(path: Path) -> None:
    """Overwrite a regular file in place, fsync it, then unlink it.

    Best effort by nature: a copy-on-write filesystem or an SSD's remapping can
    keep old blocks. It still guarantees that no other name for the same inode
    (a stray hard link, an open descriptor) keeps readable content.
    """
    descriptor = os.open(path, os.O_WRONLY | os.O_NOFOLLOW)
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode):
            raise WorkstationInvalid(f"refusing to shred a non-regular file: {path}")
        block = b"\0" * (1024 * 1024)
        remaining = info.st_size
        while remaining:
            remaining -= os.write(descriptor, block[:min(remaining, len(block))])
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    path.unlink()
    _fsync_directory(path.parent)


@dataclass(frozen=True)
class Binding:
    """The persistent Controller instance a workstation is joined to."""

    persistent_instance: str
    realm: str
    domain_sid: str

    def validated(self) -> "Binding":
        if not PERSISTENT_INSTANCE_NAME.fullmatch(str(self.persistent_instance)):
            raise WorkstationInvalid(
                f"invalid persistent instance name: {self.persistent_instance!r}")
        if not isinstance(self.realm, str) or not _REALM.fullmatch(self.realm):
            raise WorkstationInvalid(f"invalid realm: {self.realm!r}")
        if not isinstance(self.domain_sid, str) or not DOMAIN_SID.fullmatch(
                self.domain_sid):
            raise WorkstationInvalid(
                f"invalid domain SID: {self.domain_sid!r}")
        return self

    def record(self) -> dict:
        return {
            "persistent_instance": self.persistent_instance,
            "realm": self.realm,
            "domain_sid": self.domain_sid,
        }

    @classmethod
    def from_record(cls, record: object) -> "Binding":
        if not isinstance(record, dict) or set(record) != {
                "persistent_instance", "realm", "domain_sid"}:
            raise WorkstationInvalid("workstation binding record is malformed")
        return cls(**record).validated()


def _validated_entry(entry: object) -> dict:
    if not isinstance(entry, dict):
        raise WorkstationInvalid("ledger entry is not an object")
    if entry.get("stage") not in FLOW_STAGES:
        raise WorkstationInvalid(f"ledger entry names an unknown stage: "
                                 f"{entry.get('stage')!r}")
    if not isinstance(entry.get("utc"), str) or not entry["utc"]:
        raise WorkstationInvalid("ledger entry has no utc time")
    if not isinstance(entry.get("disk_sha256"), str) or not _SHA256.fullmatch(
            entry["disk_sha256"]):
        raise WorkstationInvalid("ledger entry has no disk SHA-256")
    vars_hash = entry.get("vars_sha256")
    if vars_hash is not None and (
            not isinstance(vars_hash, str) or not _SHA256.fullmatch(vars_hash)):
        raise WorkstationInvalid("ledger entry has a malformed vars SHA-256")
    if not isinstance(entry.get("source"), str) or not entry["source"]:
        raise WorkstationInvalid("ledger entry has no source")
    return entry


def valid_machine_account(account: object) -> bool:
    return isinstance(account, str) and bool(_MACHINE_ACCOUNT.fullmatch(account))


def bulk_cleaned_roots() -> tuple[Path, ...]:
    """Every spelling of the bulk-cleaned factory tree; textual, no I/O."""
    roots = []
    for base in (REPOSITORY, Path.cwd()):
        candidate = Path(os.path.normpath(base.absolute() / BULK_CLEANED_RELATIVE))
        if candidate not in roots:
            roots.append(candidate)
    return tuple(roots)


def workstation_state(root: Path, name: str) -> Path:
    """Resolve one workstation directory, refusing a name that could traverse."""
    if not WorkstationInstance.valid_name(name):
        raise WorkstationInvalid(
            "workstation name must be 1-32 lowercase letters, digits, or "
            "hyphens and must not start or end with a hyphen")
    return Path(root) / name


def reconcile_command(name: str, *, apply: bool = False) -> str:
    """The operator command that resolves ``name``'s interrupted fold."""
    return (f"make {RECONCILE_TARGET} WORKSTATION={name}"
            + (" APPLY=1" if apply else ""))


def _matches(value: str | None, head: str | None, fold: str | None) -> str:
    if value == head == fold:
        return "both the ledger head and the interrupted fold"
    if value == head:
        return "the ledger head"
    if value == fold:
        return "the interrupted fold"
    return "neither the ledger head nor the interrupted fold"


class WorkstationInstance:
    """One kept workstation directory. Nothing here boots a guest."""

    def __init__(
        self,
        state: Path,
        *,
        name: str | None = None,
        proc_root: Path = Path("/proc"),
    ) -> None:
        self.state = Path(state).absolute()
        self.name = name
        self._proc_root = Path(proc_root)
        self.disk = self.state / DISK_NAME
        self.vars = self.state / VARS_NAME
        self.publication = self.state / PUBLICATION_NAME
        self.marker = self.state / MARKER_NAME
        self.lock_path = self.state / LOCK_NAME
        self._lock_stream = None

    # -- guards ----------------------------------------------------------
    @staticmethod
    def valid_name(name: object) -> bool:
        return isinstance(name, str) and bool(
            PERSISTENT_INSTANCE_NAME.fullmatch(name))

    def assert_safe(self) -> None:
        """Refuse a symlinked state path and one inside the bulk-cleaned tree."""
        if _path_has_symlink(self.state):
            raise WorkstationInvalid(
                f"workstation state path includes a symlink: {self.state}")
        spellings = {Path(os.path.normpath(self.state)), self.state.resolve()}
        for root in bulk_cleaned_roots():
            if any(spelling.is_relative_to(root) for spelling in spellings):
                raise WorkstationInvalid(
                    f"refusing a kept workstation at {self.state}: {root} is "
                    "bulk-cleaned")

    def exists(self) -> bool:
        return _regular_file(self.marker) and _regular_file(self.disk)

    # -- marker ----------------------------------------------------------
    def _validated(self, raw: object) -> dict:
        if not isinstance(raw, dict):
            raise WorkstationInvalid(f"workstation marker is not an object: "
                                     f"{self.marker}")
        if raw.get("schema") != MARKER_SCHEMA or raw.get("kind") != MARKER_KIND:
            raise WorkstationInvalid(
                f"workstation marker must declare schema {MARKER_SCHEMA} and "
                f"kind {MARKER_KIND}: {self.marker}")
        name = raw.get("workstation")
        if not self.valid_name(name):
            raise WorkstationInvalid(
                f"workstation marker has no valid name: {self.marker}")
        if self.name is not None and name != self.name:
            raise WorkstationInvalid(
                f"workstation marker names {name}, not {self.name}: "
                f"{self.marker}")
        Binding.from_record(raw.get("binding"))
        ledger = raw.get("ledger")
        if not isinstance(ledger, list) or not ledger:
            raise WorkstationInvalid("workstation marker has no stage ledger")
        for entry in ledger:
            _validated_entry(entry)
        if [entry["stage"] for entry in ledger] != list(FLOW_STAGES[:len(ledger)]):
            raise WorkstationInvalid(
                "workstation ledger is out of the flow order: "
                + ", ".join(entry["stage"] for entry in ledger))
        pending = raw.get("pending_fold")
        if pending is not None:
            _validated_entry(pending)
            if len(ledger) >= len(FLOW_STAGES) or (
                    pending["stage"] != FLOW_STAGES[len(ledger)]):
                raise WorkstationInvalid(
                    "workstation marker records an out-of-order pending fold")
        accounts = raw.get("machine_accounts")
        if not isinstance(accounts, list) or not all(
                valid_machine_account(account) for account in accounts):
            raise WorkstationInvalid(
                "workstation marker has a malformed machine-account list")
        if not isinstance(raw.get("publication"), dict):
            raise WorkstationInvalid(
                "workstation marker has no publication custody record")
        return raw

    def read_marker(self) -> dict:
        """Return the validated marker, or fail closed."""
        self.assert_safe()
        if not _regular_file(self.marker):
            raise WorkstationInvalid(
                f"not a kept workstation (no {MARKER_NAME}): {self.state}")
        try:
            raw = json.loads(self.marker.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as error:
            raise WorkstationInvalid(
                f"cannot read workstation marker: {self.marker}") from error
        return self._validated(raw)

    def _write_marker(self, marker: dict) -> None:
        """Rewrite the marker atomically; history may only grow."""
        marker = self._validated(marker)
        current = self.read_marker()
        for key in _IMMUTABLE_KEYS:
            if marker.get(key) != current.get(key):
                raise WorkstationInvalid(
                    f"workstation marker field {key} is immutable")
        for key in ("ledger", "machine_accounts"):
            if marker[key][:len(current[key])] != current[key]:
                raise WorkstationInvalid(
                    f"workstation {key.replace('_', ' ')} is append-only")
        _write_private_json(self.state, MARKER_NAME, MARKER_STAGING_NAME, marker)

    # -- lock ------------------------------------------------------------
    def acquire(self) -> "WorkstationInstance":
        """Take the workstation's exclusive lock, or fail at once."""
        if self._lock_stream is not None:
            raise RuntimeError("workstation lock is already held by this object")
        self.read_marker()
        stream = self.lock_path.open("a+b")
        try:
            fcntl.flock(stream.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            stream.close()
            raise WorkstationInUse(
                f"kept workstation {self.state.name} is locked by another "
                "run") from error
        os.chmod(self.lock_path, 0o600)
        self._lock_stream = stream
        return self

    def release(self) -> None:
        if self._lock_stream is not None:
            fcntl.flock(self._lock_stream.fileno(), fcntl.LOCK_UN)
            self._lock_stream.close()
            self._lock_stream = None

    @contextlib.contextmanager
    def _held(self):
        """Hold the lock for one operation; reuse it when a caller holds it."""
        if self._lock_stream is not None:
            yield
            return
        self.acquire()
        try:
            yield
        finally:
            self.release()

    def __enter__(self) -> "WorkstationInstance":
        return self.acquire()

    def __exit__(self, *_exc) -> None:
        self.release()

    def locked(self) -> bool | None:
        """Whether another holder has the lock; ``None`` when unprobeable."""
        if self._lock_stream is not None:
            return True
        if not _regular_file(self.lock_path):
            return False
        try:
            with self.lock_path.open("rb") as stream:
                try:
                    fcntl.flock(stream.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                except BlockingIOError:
                    return True
                fcntl.flock(stream.fileno(), fcntl.LOCK_UN)
        except OSError:
            return None
        return False

    def _assert_not_open(self, *paths: Path) -> None:
        for path in paths:
            users = canonical_disk_users(path, proc_root=self._proc_root)
            if users:
                raise WorkstationInUse(
                    f"{path} is open by: " + ", ".join(users))

    # -- adoption --------------------------------------------------------
    def adoption_plan(self, bundle: Path) -> dict:
        """Check a gate-5 bundle can be adopted here; change nothing."""
        if not self.valid_name(self.name):
            raise WorkstationInvalid("a workstation name is required to adopt")
        self.assert_safe()
        if self.state.exists() and (
                not self.state.is_dir() or any(self.state.iterdir())):
            raise WorkstationInvalid(
                f"workstation state already exists at {self.state}")
        leftovers = sorted(
            str(path) for path in self.state.parent.glob(f".{self.state.name}.*")
        ) if self.state.parent.is_dir() else []
        if leftovers:
            raise WorkstationInvalid(
                "an earlier adoption was interrupted; inspect and remove "
                + ", ".join(leftovers) + " first (a publication.iso inside "
                "one is the bundle's credential: move it back to the bundle)")
        bundle = Path(bundle).absolute()
        if bundle.is_symlink() or not bundle.is_dir():
            raise WorkstationInvalid(
                f"gate-5 bundle must be a non-symlink directory: {bundle}")
        if bundle.stat().st_mode & 0o077:
            raise WorkstationInvalid(f"gate-5 bundle must be private: {bundle}")
        disk = bundle / BUNDLE_DISK_NAME
        if not _regular_file(disk):
            raise WorkstationInvalid(f"gate-5 bundle has no disk: {disk}")
        result = bundle / BUNDLE_RESULT
        try:
            outcome = json.loads(result.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as error:
            raise WorkstationInvalid(
                f"gate-5 bundle has no readable install result: {result}"
            ) from error
        if result.is_symlink() or not isinstance(outcome, dict) or (
                outcome.get("status"), outcome.get("phase"),
                outcome.get("private_publication_retained_for_identity"),
        ) != ("observed", BUNDLE_PASS_PHASE, True):
            raise WorkstationInvalid(
                "gate-5 bundle did not finish a native Windows install with "
                f"its publication retained: {result}")
        publication = self._bundle_publication(bundle)
        firmware = bundle / BUNDLE_VARS_NAME
        if firmware.exists() or firmware.is_symlink():
            if not _regular_file(firmware):
                raise WorkstationInvalid(
                    f"gate-5 firmware variables must be a regular file: "
                    f"{firmware}")
        else:
            firmware = None
        in_use = [disk, publication] + ([firmware] if firmware else [])
        self._assert_not_open(*in_use)
        info = _image_info(disk)
        if info.get("format") != "qcow2":
            raise WorkstationInvalid(f"gate-5 disk is not qcow2: {disk}")
        required, free = _assert_space(disk, self.state.parent)
        return {
            "workstation": self.name, "state": str(self.state),
            "bundle": str(bundle), "disk": str(disk),
            "disk_backing": info.get("full-backing-filename"),
            "firmware_vars": None if firmware is None else str(firmware),
            "publication": str(publication),
            "required_bytes": required, "free_bytes": free,
        }

    @staticmethod
    def _bundle_publication(bundle: Path) -> Path:
        publication = bundle / BUNDLE_PUBLICATION_NAME
        try:
            info = publication.lstat()
        except FileNotFoundError as error:
            raise WorkstationInvalid(
                f"gate-5 bundle has no publication to take custody of: "
                f"{publication}") from error
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
            raise WorkstationInvalid(
                f"gate-5 publication must be a regular, non-symlink file: "
                f"{publication}")
        if info.st_uid != os.geteuid():
            raise WorkstationInvalid(
                f"gate-5 publication must be owned by the current user: "
                f"{publication}")
        return publication

    def adopt(self, bundle: Path, binding: Binding) -> dict:
        """Make a gate-5 bundle's disk into this kept workstation.

        Everything is assembled in a dot-prefixed 0700 staging directory beside
        the target and becomes ``W`` in one rename, so an interruption never
        leaves a half-adopted workstation. The publication is the last thing
        moved in; if the directory cannot be committed it is moved back to the
        bundle, and if even that fails the staging directory is kept (never
        swept) and named, because it then holds the only copy.
        """
        binding = binding.validated()
        plan = self.adoption_plan(bundle)
        bundle = Path(plan["bundle"])
        self.state.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        staging = Path(tempfile.mkdtemp(
            prefix=f".{self.state.name}.", dir=self.state.parent))
        moved: Path | None = None
        try:
            staging.chmod(0o700)
            _convert_standalone(bundle / BUNDLE_DISK_NAME, staging / DISK_NAME)
            vars_hash = None
            if plan["firmware_vars"] is not None:
                _copy_private(Path(plan["firmware_vars"]), staging / VARS_NAME)
                vars_hash = sha256(staging / VARS_NAME)
            received = _now()
            marker = {
                "schema": MARKER_SCHEMA,
                "kind": MARKER_KIND,
                "workstation": self.name,
                "created_utc": received,
                "binding": binding.record(),
                "disk": {"format": "qcow2", "name": DISK_NAME,
                         "standalone": True},
                "publication": {
                    "name": PUBLICATION_NAME,
                    "received_utc": received,
                    "from_bundle": str(bundle),
                    "note": ("the gate-5 one-use publication; it carries the "
                             "Windows local administrator credential and "
                             "exists only here"),
                },
                "machine_accounts": [],
                "ledger": [{
                    "stage": "adopt", "utc": received,
                    "disk_sha256": sha256(staging / DISK_NAME),
                    "vars_sha256": vars_hash,
                    "source": str(bundle),
                }],
            }
            self._validated(marker)
            _write_private_json(
                staging, MARKER_NAME, MARKER_STAGING_NAME, marker)
            moved = self._take_publication(
                self._bundle_publication(bundle), staging / PUBLICATION_NAME)
            _fsync_directory(bundle)
            os.rename(staging, self.state)
        except BaseException:
            if moved is not None:
                try:
                    os.rename(moved, bundle / BUNDLE_PUBLICATION_NAME)
                    _fsync_directory(bundle)
                except OSError as error:
                    raise WorkstationInvalid(
                        f"adoption failed after taking the publication and "
                        f"could not return it; it is at {moved}; move it back "
                        f"to {bundle / BUNDLE_PUBLICATION_NAME}") from error
            shutil.rmtree(staging, ignore_errors=True)
            raise
        _fsync_directory(self.state.parent)
        return marker

    @staticmethod
    def _take_publication(source: Path, target: Path) -> Path:
        """Move, never copy, the credential; refuse a cross-device move."""
        before = source.lstat()
        try:
            os.rename(source, target)
        except OSError as error:
            if error.errno == errno.EXDEV:
                raise WorkstationInvalid(
                    "the gate-5 bundle and the workstation root are on "
                    "different filesystems; the publication must be moved by "
                    "one rename, never copied") from error
            raise
        after = target.lstat()
        if (not stat.S_ISREG(after.st_mode)
                or (after.st_dev, after.st_ino) != (before.st_dev, before.st_ino)):
            os.rename(target, source)
            raise WorkstationInvalid(
                "gate-5 publication changed identity while it was moved")
        os.chmod(target, 0o600)
        return target

    # -- folding ---------------------------------------------------------
    def _hashes(self) -> tuple[str, str | None]:
        if not _regular_file(self.disk):
            raise WorkstationInvalid(f"workstation disk is missing: {self.disk}")
        return (sha256(self.disk),
                sha256(self.vars) if _regular_file(self.vars) else None)

    def _leftovers(self) -> list[str]:
        return [name for name in (DISK_STAGING_NAME, VARS_STAGING_NAME)
                if (self.state / name).is_symlink()
                or (self.state / name).exists()]

    def _discard_staging(self) -> None:
        for name in self._leftovers():
            (self.state / name).unlink()

    @staticmethod
    def pending_fold_refusal(marker: dict) -> str | None:
        """Why no stage may boot ``W`` while ``marker`` records a pending fold.

        Every stage runner raises this before anything boots, rather than
        spending a stage on a disk whose ledger is unresolved; ``None`` when
        no fold is pending.
        """
        pending = marker.get("pending_fold")
        if pending is None:
            return None
        name = marker["workstation"]
        return (
            f"kept workstation {name} records an interrupted fold of stage "
            f"{pending['stage']}; no stage runs until it is reconciled. "
            f"`{reconcile_command(name)}` reports whether it can be finished "
            f"or rolled back, and `{reconcile_command(name, apply=True)}` "
            "does it")

    def recovery(self, marker: dict | None = None) -> dict:
        """Decide how an interrupted fold is resolved; change nothing.

        The disk rename is the fold's commit point. Once the fold's disk is in
        place it is finished, provided its firmware variables are in place or
        still staged with the recorded hash; while the ledger head's disk and
        variables are both intact it is rolled back; anything else is refused
        (``fold`` renames the disk before the variables, so it leaves no
        other state). With no fold pending, the files must match the ledger
        head. Only hashes decide; nothing is guessed.
        """
        marker = self.read_marker() if marker is None else marker
        head = marker["ledger"][-1]
        pending = marker.get("pending_fold")
        disk_hash, vars_hash = self._hashes()
        old = (head["disk_sha256"], head.get("vars_sha256"))
        decision = {
            "workstation": marker["workstation"],
            "head": head["stage"],
            "pending_fold": None if pending is None else pending["stage"],
            "leftovers": self._leftovers(),
            "rename_vars": False,
            "hashes": (disk_hash, vars_hash),
        }
        if pending is None:
            if (disk_hash, vars_hash) == old:
                decision.update(
                    action=RECOVERY_NONE,
                    reason="no fold is pending and the disk and firmware "
                           "variables match the ledger head")
            else:
                decision.update(
                    action=RECOVERY_REFUSE,
                    reason="no fold is pending, but the disk or firmware "
                           "variables no longer match the ledger head; they "
                           "changed outside a fold, which reconcile cannot "
                           "undo")
            return decision
        new = (pending["disk_sha256"], pending.get("vars_sha256"))
        decision["disk"] = _matches(disk_hash, old[0], new[0])
        decision["vars"] = _matches(vars_hash, old[1], new[1])
        staged_vars = self.state / VARS_STAGING_NAME
        if disk_hash == new[0]:
            if vars_hash == new[1]:
                decision.update(
                    action=RECOVERY_COMPLETE, hashes=new,
                    reason="the fold's disk and firmware variables are both "
                           "in place")
                return decision
            if _regular_file(staged_vars) and sha256(staged_vars) == new[1]:
                decision.update(
                    action=RECOVERY_COMPLETE, hashes=new, rename_vars=True,
                    reason="the fold's disk is in place and its staged "
                           "firmware variables still hash to the fold's")
                decision["vars"] += "; the staged copy matches the fold"
                return decision
        if (disk_hash, vars_hash) == old:
            decision.update(
                action=RECOVERY_ROLL_BACK,
                reason="the fold never committed its disk, and the ledger "
                       "head's disk and firmware variables are intact")
        elif disk_hash == new[0]:
            decision.update(
                action=RECOVERY_REFUSE,
                reason="the fold's disk is in place but its firmware "
                       "variables are neither in place nor staged, and the "
                       "ledger head's disk is gone, so neither finishing nor "
                       "rolling back can be proven")
        else:
            decision.update(
                action=RECOVERY_REFUSE,
                reason="the disk and firmware variables match neither the "
                       "ledger head nor the interrupted fold; they changed "
                       "outside the ledger")
        return decision

    def _apply_recovery(self, decision: dict) -> tuple[str, str | None]:
        """Carry out a ``recovery`` decision; the caller holds the lock.

        Returns the disk and variables hashes the ledger head now records.
        Each step is idempotent: interrupted anywhere, the next ``recovery``
        reaches the same end.
        """
        if decision["action"] == RECOVERY_REFUSE:
            detail = "".join(
                f"; the {label} matches {decision[key]}"
                for key, label in (("disk", "disk"),
                                   ("vars", "firmware variables"))
                if key in decision)
            raise WorkstationInvalid(
                f"refusing to reconcile kept workstation "
                f"{decision['workstation']}: {decision['reason']}{detail}. "
                f"Nothing was changed; inspect {self.state} by hand")
        marker = self.read_marker()
        if decision["action"] == RECOVERY_COMPLETE:
            if decision["rename_vars"]:
                os.replace(self.state / VARS_STAGING_NAME, self.vars)
                _fsync_directory(self.state)
            marker["ledger"].append(marker.pop("pending_fold"))
            self._write_marker(marker)
        elif decision["action"] == RECOVERY_ROLL_BACK:
            del marker["pending_fold"]
            self._write_marker(marker)
        self._discard_staging()
        return decision["hashes"]

    def reconcile(self, *, apply: bool = False) -> dict:
        """Resolve an interrupted fold under the lock; a dry run by default.

        Returns the ``recovery`` decision. With ``apply`` it is carried out
        (a refusal raises ``WorkstationInvalid`` and changes nothing), and any
        leftover staging file is discarded.
        """
        with self._held():
            decision = self.recovery()
            if apply:
                self._assert_not_open(*[
                    path for path in (
                        self.disk, self.vars,
                        *(self.state / name for name in decision["leftovers"]))
                    if _regular_file(path)])
                self._apply_recovery(decision)
            decision["applied"] = apply
            return decision

    def _reconcile(self) -> tuple[str, str | None]:
        """Finish or roll back an interrupted fold; return the current hashes."""
        marker = self.read_marker()
        if marker.get("pending_fold") is None:
            # Unreferenced: a staging copy interrupted before any fold was
            # recorded. The head check that follows is ``fold``'s own.
            self._discard_staging()
            return self._hashes()
        return self._apply_recovery(self.recovery(marker))

    def next_stage(self, marker: dict | None = None) -> str | None:
        ledger = (marker or self.read_marker())["ledger"]
        return FLOW_STAGES[len(ledger)] if len(ledger) < len(FLOW_STAGES) else None

    def fold(
        self,
        overlay: Path,
        stage: str,
        *,
        firmware_vars: Path | None = None,
        source: str | None = None,
    ) -> dict:
        """Fold one successful stage's overlay into the workstation disk.

        ``overlay`` must be a qcow2 whose backing file is this workstation's
        disk. It is flattened into a standalone staging copy, fsynced, and
        renamed over the disk; ``firmware_vars``, when given, replaces the
        workstation's variables the same way. Refused while any process holds
        either side open, and refused unless the disk still hashes to the
        ledger head (it was not booted in place or edited out of band).
        """
        overlay = Path(overlay).absolute()
        if firmware_vars is not None:
            firmware_vars = Path(firmware_vars).absolute()
        with self._held():
            marker = self.read_marker()
            if marker.get("pending_fold") is None and (
                    stage != self.next_stage(marker)):
                raise WorkstationInvalid(
                    f"refusing to fold {stage!r}: the next stage for "
                    f"{marker['workstation']} is {self.next_stage(marker)!r}")
            if not _regular_file(overlay) or overlay.stat().st_uid != os.geteuid():
                raise WorkstationInvalid(
                    f"overlay must be a regular, non-symlink file owned by the "
                    f"current user: {overlay}")
            if firmware_vars is not None and not _regular_file(firmware_vars):
                raise WorkstationInvalid(
                    f"firmware variables must be a regular, non-symlink file: "
                    f"{firmware_vars}")
            if not _regular_file(self.disk):
                raise WorkstationInvalid(
                    f"workstation disk is missing: {self.disk}")
            self._assert_not_open(self.disk, overlay, *[
                path for path in (self.vars, firmware_vars)
                if path is not None and _regular_file(path)])
            disk_hash, vars_hash = self._reconcile()
            marker = self.read_marker()
            expected = self.next_stage(marker)
            if stage != expected:
                raise WorkstationInvalid(
                    f"refusing to fold {stage!r}: the next stage for "
                    f"{marker['workstation']} is {expected!r}")
            head = marker["ledger"][-1]
            if (disk_hash, vars_hash) != (head["disk_sha256"],
                                          head.get("vars_sha256")):
                raise WorkstationInvalid(
                    "workstation disk or firmware variables no longer match "
                    "the ledger head; they changed outside a fold")
            info = _image_info(overlay)
            backing = info.get("full-backing-filename")
            if info.get("format") != "qcow2" or not backing or not _same_file(
                    Path(backing), self.disk):
                raise WorkstationInvalid(
                    f"overlay {overlay} is not a qcow2 backed by {self.disk}")
            _assert_space(overlay, self.state)
            staged_disk = self.state / DISK_STAGING_NAME
            staged_vars = self.state / VARS_STAGING_NAME
            try:
                _convert_standalone(overlay, staged_disk)
                entry = {
                    "stage": stage, "utc": _now(),
                    "disk_sha256": sha256(staged_disk),
                    "vars_sha256": vars_hash,
                    "source": source or str(overlay),
                }
                if firmware_vars is not None:
                    _copy_private(firmware_vars, staged_vars)
                    entry["vars_sha256"] = sha256(staged_vars)
                marker["pending_fold"] = entry
                self._write_marker(marker)
            except BaseException:
                self._discard_staging()
                raise
            # From here the pending record is the authority: every stage runner
            # refuses to boot until ``reconcile`` finishes or rolls it back.
            # The disk rename below is the commit point (``recovery``).
            os.replace(staged_disk, self.disk)
            if firmware_vars is not None:
                os.replace(staged_vars, self.vars)
            _fsync_directory(self.state)
            marker = self.read_marker()
            marker["ledger"].append(marker.pop("pending_fold"))
            self._write_marker(marker)
            return entry

    # -- directory side effects and custody -------------------------------
    def record_machine_account(self, account: str) -> dict:
        """Remember a computer account BEFORE the join that may create it."""
        if not valid_machine_account(account):
            raise WorkstationInvalid(f"invalid machine account name: {account!r}")
        with self._held():
            marker = self.read_marker()
            if account not in marker["machine_accounts"]:
                marker["machine_accounts"].append(account)
                self._write_marker(marker)
            return marker

    def retire_publication(self) -> dict:
        """Shred the custody publication once the stage that needed it folded."""
        with self._held():
            marker = self.read_marker()
            if PUBLICATION_NEEDED_UNTIL not in [
                    entry["stage"] for entry in marker["ledger"]]:
                raise WorkstationInvalid(
                    f"refusing to retire the publication before the "
                    f"{PUBLICATION_NEEDED_UNTIL} stage has folded; a failed "
                    "join would then need a fresh gate-5 install")
            if self.publication.is_symlink():
                raise WorkstationInvalid(
                    f"custody publication became a symlink: {self.publication}")
            if not self.publication.exists():
                raise WorkstationInvalid(
                    f"custody publication is already gone: {self.publication}")
            self._assert_not_open(self.publication)
            _shred(self.publication)
            marker["publication"]["retired_utc"] = _now()
            self._write_marker(marker)
            return marker

    # -- reporting -------------------------------------------------------
    def summary(self) -> dict:
        """Read-only facts for status; never opens the publication."""
        result: dict = {"workstation": self.state.name, "state": str(self.state)}
        try:
            self.assert_safe()
        except WorkstationInvalid as error:
            result["error"] = str(error)
            return result
        result["present"] = self.state.is_dir()
        if not result["present"]:
            return result
        try:
            marker = self.read_marker()
        except WorkstationInvalid as error:
            result["marker"] = f"invalid: {error}"
            marker = None
        if marker is not None:
            result["marker"] = "valid"
            result["binding"] = marker["binding"]
            result["created_utc"] = marker["created_utc"]
            result["stages"] = [
                {"stage": entry["stage"], "utc": entry["utc"],
                 "disk_sha256": entry["disk_sha256"]}
                for entry in marker["ledger"]]
            result["next_stage"] = self.next_stage(marker)
            pending = marker.get("pending_fold")
            result["pending_fold"] = None if pending is None else pending["stage"]
            if pending is not None:
                result["reconcile"] = reconcile_command(marker["workstation"])
            result["machine_accounts"] = list(marker["machine_accounts"])
            retired = marker["publication"].get("retired_utc")
        else:
            retired = None
        result["disk_bytes"] = (
            self.disk.stat().st_size if _regular_file(self.disk) else None)
        result["firmware_vars"] = _regular_file(self.vars)
        result["staging_leftovers"] = self._leftovers()
        if self.publication.is_symlink():
            result["publication"] = "UNSAFE: a symlink"
        elif _regular_file(self.publication):
            result["publication"] = "held"
        elif retired:
            result["publication"] = f"retired {retired}"
        else:
            result["publication"] = "MISSING: not retired, not present"
        result["locked"] = self.locked()
        return result

    # -- credential custody (TASK-40) ----------------------------------------
    def custody_store(self, marker: dict | None = None):
        """This workstation's custody store (break-glass passwords).

        It exists only for a workstation bound to an agent-custody instance,
        whose custody it inherits; the runner creates it on first use.
        """
        name = (marker or {}).get("workstation") or self.name or self.state.name
        return _custody.workstation_store(self.state, name)

    # -- teardown --------------------------------------------------------
    def destroy(self, confirm: str | None) -> dict:
        """Erase this workstation after the exact ``DESTROY <name>`` phrase."""
        marker = self.read_marker()
        expected = f"{DESTROY_CONFIRMATION_PREFIX} {marker['workstation']}"
        if confirm != expected:
            raise WorkstationInvalid(
                f"refusing to erase a kept workstation; pass the exact "
                f"confirmation: {expected}")
        self.acquire()
        try:
            self._assert_not_open(*[
                path for path in (self.disk, self.vars, self.publication)
                if _regular_file(path)])
            keep = {
                DISK_NAME, VARS_NAME, PUBLICATION_NAME, MARKER_NAME,
                MARKER_STAGING_NAME, DISK_STAGING_NAME, VARS_STAGING_NAME,
                LOCK_NAME,
            }
            unexpected = sorted(
                entry.name for entry in self.state.iterdir()
                if not (entry.name == _custody.CUSTODY_DIR_NAME
                        and entry.is_dir() and not entry.is_symlink())
                and (entry.name not in keep or entry.is_symlink()
                     or not (entry.is_file())))
            if unexpected:
                raise WorkstationInvalid(
                    "refusing: workstation state holds unexpected entries: "
                    + ", ".join(unexpected))
            # The credentials go first, so an interruption at any later point
            # leaves a disk without them, never them without the disk's
            # marker: an agent-custody store of break-glass passwords
            # (TASK-40), then the publication.
            try:
                self.custody_store(marker).shred()
            except _custody.CustodyError as error:
                raise WorkstationInvalid(str(error)) from error
            if self.publication.exists():
                _shred(self.publication)
            for name in (
                DISK_STAGING_NAME, VARS_STAGING_NAME, DISK_NAME, VARS_NAME,
                MARKER_STAGING_NAME, MARKER_NAME,
            ):
                (self.state / name).unlink(missing_ok=True)
        finally:
            self.release()
        self.lock_path.unlink(missing_ok=True)
        self.state.rmdir()
        return {
            "state": str(self.state),
            "binding": marker["binding"],
            "machine_accounts": list(marker["machine_accounts"]),
        }


def _same_file(left: Path, right: Path) -> bool:
    try:
        a, b = left.stat(), right.stat()
    except OSError:
        return False
    return (a.st_dev, a.st_ino) == (b.st_dev, b.st_ino)


# -- command line --------------------------------------------------------------
def _default_persistent_root() -> Path:
    try:
        from .bootstrap_dc import DEFAULT_PERSISTENT_ROOT
    except ImportError:
        from bootstrap_dc import DEFAULT_PERSISTENT_ROOT
    return DEFAULT_PERSISTENT_ROOT


def persistent_binding(root: Path | None, instance: str) -> Binding:
    """Read the binding from a converged persistent instance's own marker."""
    if not PersistentControllerInstance.valid_instance_name(instance):
        raise WorkstationInvalid(f"invalid persistent instance name: {instance!r}")
    root = _default_persistent_root() if root is None else Path(root)
    target = PersistentControllerInstance(root / instance, instance=instance)
    if not target.exists():
        raise WorkstationInvalid(
            f"persistent controller instance {instance} is absent or "
            f"incomplete under {root}")
    record = target.convergence()
    if record is None or not record.get("realm") or not record.get("domain_sid"):
        raise WorkstationInvalid(
            f"persistent controller instance {instance} records no converged "
            "realm and domain SID; converge it before binding a workstation")
    return Binding(instance, record["realm"], record["domain_sid"]).validated()


def _print_plan(plan: dict, binding: Binding) -> None:
    print(f"workstation {plan['workstation']}: would adopt into {plan['state']}")
    backing = plan["disk_backing"]
    print(f"disk: {plan['disk']} -> {DISK_NAME}, standalone ("
          + (f"flattening backing {backing}" if backing else "no backing file")
          + ")")
    print(f"space: {plan['required_bytes']} bytes needed, "
          f"{plan['free_bytes']} free")
    firmware = plan["firmware_vars"]
    print("firmware variables: "
          + (f"copied from {firmware}" if firmware else "none in the bundle"))
    print(f"publication: MOVED from {plan['publication']}; the workstation "
          "takes custody and the bundle keeps no copy")
    # The realm and SID are recorded in the private marker, not echoed: like
    # ``durable_workstation.DurableBinding``'s repr, output names the instance.
    print(f"bound to persistent instance {binding.persistent_instance} "
          "(its converged realm and domain SID are recorded in the marker)")
    print("stages after adoption: " + ", ".join(FLOW_STAGES[1:]))


def _print_summary(summary: dict) -> None:
    print(f"kept workstation {summary['workstation']}: "
          f"{'present' if summary.get('present') else 'absent'}")
    pending = summary.get("pending_fold")
    if pending:
        # Right under the name, so it cannot scroll past: every stage runner
        # refuses W until it is resolved.
        print(f"INTERRUPTED FOLD: stage {pending} is pending; no stage runs "
              f"until `{summary['reconcile']}` finishes or rolls it back "
              "(a dry run without APPLY=1)")
    print(f"state: {summary['state']}")
    if "error" in summary:
        print(f"error: {summary['error']}")
        return
    if not summary.get("present"):
        return
    print(f"marker: {summary['marker']}")
    binding = summary.get("binding")
    if binding:
        print(f"bound instance: {binding['persistent_instance']}")
    for entry in summary.get("stages", []):
        print(f"stage done: {entry['stage']} {entry['utc']} "
              f"disk {entry['disk_sha256']}")
    if "next_stage" in summary:
        print("next stage: "
              + (summary["next_stage"] or "none; every stage folded")
              + (" (blocked by the interrupted fold)" if pending else ""))
    size = summary["disk_bytes"]
    print("disk: " + ("absent" if size is None else f"present, {size} bytes"))
    print("firmware variables: "
          + ("present" if summary["firmware_vars"] else "absent"))
    if summary.get("staging_leftovers"):
        print("staging leftovers: " + ", ".join(summary["staging_leftovers"])
              + " (left by a fold that is running or was interrupted; "
              f"{RECONCILE_TARGET} resolves them)")
    print(f"publication custody: {summary['publication']}")
    if "machine_accounts" in summary:
        accounts = summary["machine_accounts"]
        print("machine accounts left in the directory: "
              + (", ".join(accounts) if accounts else "none recorded"))
    print("locked: "
          + {True: "yes", False: "no", None: "unknown"}[summary["locked"]])


def cli_plan(root: Path, name: str, bundle: Path | None,
             instance: str | None, persistent_root: Path | None,
             *, adopting: bool = False, apply: bool = False) -> int:
    """``plan`` reports an existing workstation or an adoption preflight;
    ``adopt`` always runs the preflight and acts only with ``apply``."""
    target = WorkstationInstance(workstation_state(root, name), name=name)
    if not adopting and target.state.exists():
        summary = target.summary()
        _print_summary(summary)
        return 0 if summary.get("marker") == "valid" else 1
    if bundle is None or instance is None:
        print("error: adopting needs --windows-run <gate-5 bundle> and "
              "--persistent-dc <instance>", file=sys.stderr)
        return 2
    binding = persistent_binding(persistent_root, instance)
    plan = target.adoption_plan(bundle)
    _print_plan(plan, binding)
    if not apply:
        print("dry run: repeat with --apply to adopt")
        return 0
    marker = target.adopt(bundle, binding)
    print(f"adopted {name} at {target.state}; ledger head "
          f"{marker['ledger'][-1]['disk_sha256']}")
    return 0


def cli_status(root: Path, name: str) -> int:
    target = WorkstationInstance(workstation_state(root, name), name=name)
    summary = target.summary()
    _print_summary(summary)
    return 0 if summary.get("marker") == "valid" else 1


def _print_recovery(decision: dict) -> None:
    name = decision["workstation"]
    pending = decision["pending_fold"]
    print(f"kept workstation {name}: "
          + (f"interrupted fold of stage {pending}" if pending
             else "no fold pending")
          + f" (ledger head: {decision['head']})")
    if "disk" in decision:
        print(f"disk: matches {decision['disk']}")
        print(f"firmware variables: match {decision['vars']}")
    if decision["leftovers"]:
        print("staging leftovers: " + ", ".join(decision["leftovers"])
              + " (an apply that is not refused uses or discards them)")
    action = decision["action"]
    print(f"decision: {action}: {decision['reason']}")
    if action == RECOVERY_REFUSE:
        print("nothing is changed by this command; inspect the workstation "
              "by hand")


def cli_reconcile(root: Path, name: str, apply: bool) -> int:
    """Finish or roll back an interrupted fold; a dry run without ``apply``."""
    target = WorkstationInstance(workstation_state(root, name), name=name)
    decision = target.reconcile(apply=apply)
    _print_recovery(decision)
    action = decision["action"]
    if action == RECOVERY_REFUSE:
        return 1
    if not apply:
        if action != RECOVERY_NONE or decision["leftovers"]:
            print("dry run: repeat with --apply")
        return 0
    done = {RECOVERY_COMPLETE: f"completed the fold of {decision['pending_fold']}",
            RECOVERY_ROLL_BACK: f"rolled back the fold of "
                                f"{decision['pending_fold']}",
            RECOVERY_NONE: "nothing pending"}[action]
    head = target.read_marker()["ledger"][-1]
    print(f"reconciled {name}: {done}; ledger head {head['stage']} disk "
          f"{head['disk_sha256']}")
    return 0


def cli_destroy(root: Path, name: str, confirm: str | None, apply: bool) -> int:
    target = WorkstationInstance(workstation_state(root, name), name=name)
    target.assert_safe()
    if not target.state.exists():
        print(f"kept workstation {name}: already absent")
        return 0
    marker = target.read_marker()
    expected = f"{DESTROY_CONFIRMATION_PREFIX} {marker['workstation']}"
    accounts = marker["machine_accounts"]
    binding = marker["binding"]
    if not apply:
        if target.custody_store(marker).exists():
            print(f"dry run: would shred the credential custody store "
                  f"({_custody.CUSTODY_DIR_NAME}/) first")
        print(f"dry run: would shred {PUBLICATION_NAME} first, then erase "
              f"{target.state}")
        print(f"repeat with --apply --confirm '{expected}'")
    elif confirm != expected:
        print(f"error: refusing to erase a kept workstation; pass the exact "
              f"confirmation: {expected}", file=sys.stderr)
        return 2
    else:
        target.destroy(confirm)
        print(f"destroyed kept workstation {name} at {target.state}")
    if accounts:
        print(f"machine accounts this workstation left in the directory of "
              f"{binding['persistent_instance']}; remove them there, e.g. "
              "`samba-tool computer delete <name>`: " + ", ".join(accounts))
    else:
        print("machine accounts left in the directory: none recorded")
    return 0


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(
        description="Keep one durable workstation bound to a persistent "
                    "Controller instance")
    result.add_argument(
        "--root", type=Path, default=DEFAULT_ROOT,
        help="root holding kept workstations; never homelab/var/factory")
    commands = result.add_subparsers(dest="command", required=True)
    for name in ("plan", "status", "adopt", "reconcile", "destroy"):
        sub = commands.add_parser(name)
        sub.add_argument("--workstation", required=True,
                         help="stable workstation name")
        if name in ("plan", "adopt"):
            sub.add_argument("--windows-run", type=Path,
                             help="the finished gate-5 Windows install bundle")
            sub.add_argument("--persistent-dc",
                             help="the persistent Controller instance to bind")
            sub.add_argument("--persistent-root", type=Path, default=None,
                             help="root holding persistent instances")
        if name in ("adopt", "reconcile", "destroy"):
            sub.add_argument("--apply", action="store_true")
        if name == "destroy":
            sub.add_argument("--confirm",
                             help="required exact acknowledgement: "
                                  "'DESTROY <workstation>'")
    return result


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        if args.command == "status":
            return cli_status(args.root, args.workstation)
        if args.command == "reconcile":
            return cli_reconcile(args.root, args.workstation, args.apply)
        if args.command == "destroy":
            return cli_destroy(
                args.root, args.workstation, args.confirm, args.apply)
        adopting = args.command == "adopt"
        return cli_plan(
            args.root, args.workstation, args.windows_run,
            args.persistent_dc, args.persistent_root,
            adopting=adopting, apply=adopting and args.apply)
    except (RuntimeError, OSError, subprocess.CalledProcessError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
