"""Fail-closed controller simulation state, disposable and persistent.

Two state models live here, and keeping them apart is the point of the module:

``ControllerOverlay``
    The disposable acceptance model. It locks the canonical controller disk,
    hands QEMU nothing but throwaway copies, and fails the run if either
    canonical digest moved. Every acceptance gate depends on that fence.

``PersistentControllerInstance``
    The opposite model, added for a directory server that must survive being
    shut down and brought up again. The disk it hands QEMU *is* the durable
    Active Directory state, so it is deliberately not hash-fenced. It is never
    the default, never inferred, always lives in its own state directory, and
    refuses the acceptance canonical outright.
"""

from __future__ import annotations

import contextlib
import fcntl
import hashlib
import json
import os
import re
import shutil
import subprocess
import tempfile
import time
from datetime import UTC, datetime
from pathlib import Path

#: Exclusivity lock beside a controller state directory's disk. One name for
#: both models: a disposable run locks the canonical state directory and a
#: persistent instance locks its own, so neither can ever be run twice at once.
LOCK_NAME = ".simulation.lock"

REPOSITORY = Path(__file__).resolve().parents[2]

#: The disposable acceptance canonical, relative to the repository root. Gates
#: 3, 8 and 12 all assume this state is freshly provisioned and byte-stable, so
#: no persistent instance may ever be aimed at it. See
#: ``assert_persistent_state_separate``.
ACCEPTANCE_STATE_RELATIVE = Path("build/homelab/vm/bootstrap-dc")
ACCEPTANCE_DISK_NAME = "bootstrap-dc.qcow2"
ACCEPTANCE_MANIFEST_NAME = "manifest.json"

#: A persistent instance's own filenames. Deliberately disjoint from the
#: acceptance names above, in both directions: acceptance tooling looks for
#: ``bootstrap-dc.qcow2``/``manifest.json`` and can never mistake a persistent
#: instance for a canonical state, and persistent tooling requires
#: ``persistent-instance.json`` and can never mistake the canonical state for an
#: instance. The disjointness is structural, not a naming convention.
PERSISTENT_DISK_NAME = "persistent-dc.qcow2"
PERSISTENT_VARS_NAME = "OVMF_VARS.fd"
PERSISTENT_MARKER_NAME = "persistent-instance.json"
PERSISTENT_MARKER_SCHEMA = 1
PERSISTENT_MODE = "persistent"
#: Instance names become a single path component under the persistent root, so
#: they are restricted to a shape that cannot traverse, glob, or hide.
PERSISTENT_INSTANCE_NAME = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,30}[a-z0-9])?$")
#: Erasing a persistent instance erases a real directory server, so it needs the
#: instance's own stable name inside the confirmation value.
DESTROY_CONFIRMATION_PREFIX = "DESTROY"

# A same-EUID process that is momentarily un-inspectable (mid-exec, or a
# short-lived process the kernel is tearing down) is re-checked over this small
# budget before the audit fails closed. A process that exits within the window
# holds no descriptors on the canonical disk, so skipping it is sound; a process
# that stays live and un-inspectable still fails closed, so the boundary is
# unchanged. The budget is tiny so a real un-inspectable process is not masked.
_PROCESS_INSPECT_ATTEMPTS = 6
_PROCESS_INSPECT_BACKOFF_SECONDS = 0.05


class CanonicalDiskInUse(RuntimeError):
    """The canonical controller disk is open outside this safety guard."""


class AcceptanceStateProtected(RuntimeError):
    """A persistent operation was aimed at the disposable acceptance state.

    The single most important safety property of the persistent mode. An
    accidental persistent bring-up against ``build/homelab/vm/bootstrap-dc``
    would boot the acceptance canonical read-write, provision a domain into it
    and leave it changed — silently destroying the hermeticity gate 3 ("from a
    fresh offline-installed disposable controller"), gate 8 (a freshly
    provisioned domain each run, which is why it re-joins the workstation
    in-run) and gate 12 (destroy disposable state and repeat) all depend on.
    """


class PersistentInstanceInvalid(RuntimeError):
    """The named state directory is not a usable persistent instance."""


class PersistentInstanceInUse(RuntimeError):
    """A persistent instance's own disk is open outside this guard."""


def _process_identity(process: Path) -> tuple[bool, bool]:
    """Return (identified, is_qemu) without trusting a single process name."""
    values = []
    try:
        values.append((process / "comm").read_text(errors="replace").strip())
    except OSError:
        pass
    try:
        values.append(
            (process / "cmdline").read_bytes().replace(b"\0", b" ").decode(
                errors="replace"
            )
        )
    except OSError:
        pass
    names = ("qemu-system", "qemu-kvm", "qemu-storage")
    return bool(values), any(name in value for value in values for name in names)


def _process_is_live(process: Path) -> bool:
    """True while ``/proc/<pid>`` still resolves to an existing process."""
    try:
        process.stat()
    except OSError:
        return False
    return True


def _process_is_zombie(process: Path) -> bool:
    """True when ``/proc/<pid>`` is an exited process awaiting reaping.

    A zombie's file-descriptor table is already destroyed by the kernel, so it
    cannot hold the canonical disk open, yet reading its ``fd`` directory
    raises ``PermissionError`` even for the owner. Teardown routinely audits
    while this run's own just-killed QEMU sits in that state, so the audit must
    recognise it rather than fail closed on a process that provably holds
    nothing.
    """
    try:
        status = (process / "stat").read_text()
    except OSError:
        return False
    # /proc/<pid>/stat: pid (comm) state ... — comm may contain spaces and
    # parentheses, so parse the state as the first field after the LAST ')'.
    _, _, tail = status.rpartition(")")
    fields = tail.split()
    return bool(fields) and fields[0] == "Z"


def _disk_user_label(process: Path, wanted: os.stat_result) -> str | None:
    """Return a label if ``process`` holds ``wanted`` open, else ``None``.

    Raises ``RuntimeError`` when a same-EUID, possibly-QEMU process is
    un-inspectable and so cannot be cleared of holding the canonical disk. A
    positively identified non-QEMU same-EUID process may have inaccessible
    descriptors (for example, a non-dumpable user systemd); those are ignored so
    the check works without sudo.
    """
    try:
        process_uid = process.stat().st_uid
    except FileNotFoundError:
        return None
    except OSError as error:
        raise RuntimeError(
            f"cannot inspect process {process.name} ownership"
        ) from error
    identified, is_qemu = _process_identity(process)
    # A different EUID cannot open our disk under our permissions, and a
    # positively identified non-QEMU process is not a storage backend; both may
    # be ignored when un-inspectable. Everything else must be inspected.
    tolerant = process_uid != os.geteuid() or (identified and not is_qemu)
    descriptors = process / "fd"
    try:
        open_files = list(descriptors.iterdir())
    except FileNotFoundError:
        return None
    except OSError as error:
        if tolerant or _process_is_zombie(process):
            return None
        raise RuntimeError(
            f"cannot inspect process {process.name} file descriptors"
        ) from error
    for descriptor in open_files:
        try:
            opened = descriptor.stat()
        except FileNotFoundError:
            continue
        except OSError as error:
            if tolerant:
                continue
            raise RuntimeError(
                f"cannot inspect process {process.name} descriptor {descriptor.name}"
            ) from error
        if (opened.st_dev, opened.st_ino) != (wanted.st_dev, wanted.st_ino):
            continue
        label = process.name
        try:
            command = (process / "comm").read_text().strip()
            if command:
                label = f"{process.name} ({command})"
        except OSError:
            pass
        return label
    return None


def canonical_disk_users(path: Path, *, proc_root: Path = Path("/proc")) -> list[str]:
    """Best-effort guard against normal and QEMU opens of a user-mode VM disk.

    The canonical disk must be owned by the effective user and must not be
    group/world writable.  Unreadable QEMU or unidentified same-EUID process
    state fails closed.  A positively identified non-QEMU same-EUID process
    may have inaccessible descriptors (for example, a non-dumpable user
    systemd); those descriptors are ignored so the check works without sudo.
    This is not a defense against a malicious same-user or privileged process.

    A same-EUID process that is only *momentarily* un-inspectable — a
    short-lived process the kernel is tearing down, common on a busy host — is
    re-checked over a small budget. If it exits within the window it held no
    descriptors on the canonical disk and is skipped; if it stays live and
    un-inspectable the audit still fails closed, so the boundary is unchanged.
    """
    try:
        wanted = path.stat()
        processes = list(proc_root.iterdir())
    except (OSError, PermissionError) as error:
        raise RuntimeError(f"cannot inspect process file descriptors via {proc_root}") from error

    users = []
    for process in processes:
        if not process.name.isdigit():
            continue
        for attempt in range(_PROCESS_INSPECT_ATTEMPTS):
            try:
                label = _disk_user_label(process, wanted)
            except RuntimeError:
                # A process that has since exited holds nothing on the canonical
                # disk. Only a process that stays live through the whole budget
                # and remains un-inspectable fails the audit closed.
                if not _process_is_live(process):
                    label = None
                    break
                if attempt + 1 == _PROCESS_INSPECT_ATTEMPTS:
                    raise
                time.sleep(_PROCESS_INSPECT_BACKOFF_SECONDS)
                continue
            break
        if label is not None:
            users.append(label)
    return users


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _regular_file(path: Path) -> bool:
    return path.is_file() and not path.is_symlink()


def _qemu_image_info(path: Path) -> None:
    """Ask qemu-img to acquire its normal read lock without modifying data."""
    subprocess.run(
        ["qemu-img", "info", "--output=json", str(path)],
        check=True,
        capture_output=True,
    )


def _path_has_symlink(path: Path) -> bool:
    """True when any existing component of ``path`` is a symlink."""
    candidate = Path(path).absolute()
    return any(
        component.is_symlink()
        for component in (candidate, *candidate.parents)
        if component.exists()
    )


def _same_path(left: Path, right: Path) -> bool:
    """True when two resolved paths name the same directory entry.

    Textual equality is not enough on its own: a bind mount, or two spellings
    that ``resolve`` cannot reconcile because a component does not exist yet,
    can still land on one inode. Identity is the authoritative comparison when
    both paths exist; the textual one covers the not-yet-created case.
    """
    if left == right:
        return True
    try:
        left_state, right_state = left.stat(), right.stat()
    except OSError:
        return False
    return ((left_state.st_dev, left_state.st_ino)
            == (right_state.st_dev, right_state.st_ino))


def acceptance_state_candidates() -> tuple[Path, ...]:
    """Every spelling of the disposable acceptance state on this host.

    The acceptance state is named by a *relative* default
    (``bootstrap_dc.DEFAULT_STATE``) that runners resolve against the working
    directory, so both the repository-relative and the cwd-relative reading are
    reserved. Neither may become a persistent instance.
    """
    candidates = []
    for root in (REPOSITORY, Path.cwd()):
        candidate = (root / ACCEPTANCE_STATE_RELATIVE).absolute()
        if candidate not in candidates:
            candidates.append(candidate)
    return tuple(candidates)


def assert_persistent_state_separate(
    state: Path, *, canonical_disk: Path | None = None
) -> None:
    """Fail closed unless ``state`` is disjoint from any acceptance state.

    Four independent refusals, because one bad persistent run against the
    acceptance canonical is unrecoverable — it would leave a provisioned domain
    on the disk every gate assumes is freshly installed, and the damage would
    only surface as a later gate mysteriously passing for the wrong reason:

    1. path identity with a reserved acceptance state, by inode where both
       exist and textually otherwise;
    2. containment either way, so an instance cannot sit inside the acceptance
       state nor enclose it (a destroy would sweep it);
    3. identity with the parent of whichever canonical disk this operation was
       actually given, which protects a canonical in a non-default location
       that the reserved list cannot know about;
    4. presence of the acceptance artefacts themselves, which holds even if a
       caller reaches the directory by a spelling checks 1-3 cannot see.

    Bring-up adds a fifth, positive requirement on top of these: a persistent
    instance must carry its own marker file (see ``read_marker``), which the
    acceptance state does not and must never have.
    """
    resolved = Path(state).absolute().resolve()
    reserved = [candidate.resolve() for candidate in acceptance_state_candidates()]
    if canonical_disk is not None:
        reserved.append(Path(canonical_disk).absolute().resolve().parent)
    for candidate in reserved:
        if (_same_path(resolved, candidate)
                or resolved.is_relative_to(candidate)
                or candidate.is_relative_to(resolved)):
            raise AcceptanceStateProtected(
                "refusing a persistent controller instance at "
                f"{state}: it is not separate from the disposable acceptance "
                f"state {candidate}"
            )
    for name in (ACCEPTANCE_DISK_NAME, ACCEPTANCE_MANIFEST_NAME):
        if (resolved / name).exists():
            raise AcceptanceStateProtected(
                "refusing a persistent controller instance at "
                f"{state}: it holds the disposable acceptance artefact {name}"
            )


class ControllerOverlay:
    """Lock a canonical VM and expose only disposable writable state.

    The lock remains held until ``close`` has checked that the canonical disk
    did not change. Callers must give QEMU ``disk`` and ``vars`` from this
    object, never the canonical paths.
    """

    def __init__(
        self,
        canonical_disk: Path,
        canonical_vars: Path,
        *,
        run_root: Path | None = None,
        proc_root: Path = Path("/proc"),
    ) -> None:
        self.canonical_disk = Path(canonical_disk).absolute()
        self.canonical_vars = Path(canonical_vars).absolute()
        self._temporary = run_root is None
        self._proc_root = Path(proc_root)
        self.root = (
            Path(tempfile.mkdtemp(prefix="homelab-controller-sim-"))
            if run_root is None
            else Path(run_root).resolve()
        )
        self.disk = self.root / "controller-overlay.qcow2"
        self.vars = self.root / "OVMF_VARS.fd"
        self._lock_stream = None
        self._disk_hash = ""
        self._vars_hash = ""
        self._closed = False

    def prepare(self) -> "ControllerOverlay":
        if self._lock_stream is not None:
            raise RuntimeError("controller simulation state is already prepared")
        for path, label in (
            (self.canonical_disk, "canonical controller disk"),
            (self.canonical_vars, "canonical OVMF variables"),
        ):
            if not path.is_file() or path.is_symlink():
                raise RuntimeError(f"{label} must be a regular, non-symlink file: {path}")
        for path, label in (
            (self.canonical_disk, "canonical controller disk"),
            (self.canonical_vars, "canonical OVMF variables"),
        ):
            state = path.stat()
            if state.st_uid != os.geteuid():
                raise RuntimeError(f"{label} must be owned by the current user")
            if state.st_mode & 0o022:
                raise RuntimeError(f"{label} must not be group/world writable")

        self.root.mkdir(parents=True, exist_ok=True)
        lock_path = self.canonical_disk.parent / LOCK_NAME
        self._lock_stream = lock_path.open("a+b")
        try:
            fcntl.flock(self._lock_stream.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            self._lock_stream.close()
            self._lock_stream = None
            raise RuntimeError("another controller simulation is already running") from error

        try:
            self._assert_canonical_not_open()
            self._probe_qemu_image_lock()
            self._disk_hash = sha256(self.canonical_disk)
            self._vars_hash = sha256(self.canonical_vars)
            subprocess.run(
                [
                    "qemu-img", "create", "-f", "qcow2",
                    "-F", "qcow2", "-b", str(self.canonical_disk), str(self.disk),
                ],
                check=True,
                capture_output=True,
            )
            shutil.copy2(self.canonical_vars, self.vars)
            os.chmod(self.vars, 0o600)
        except BaseException:
            self._unlock()
            self._remove_run_state()
            raise
        return self

    @property
    def canonical_disk_sha256(self) -> str:
        """The canonical disk digest captured at ``prepare``, or ``""``."""
        return self._disk_hash

    @property
    def canonical_vars_sha256(self) -> str:
        """The canonical variables digest captured at ``prepare``, or ``""``."""
        return self._vars_hash

    def qemu_disk_drive(self, drive_id: str = "osdisk") -> str:
        """Return a writable drive argument that cannot name the canonical disk."""
        if self._lock_stream is None or not self.disk.is_file():
            raise RuntimeError("controller simulation state is not prepared")
        return f"file={self.disk},if=none,id={drive_id},format=qcow2,cache=none"

    def qemu_vars_drive(self) -> str:
        """Return the writable pflash argument for the private variable copy."""
        if self._lock_stream is None or not self.vars.is_file():
            raise RuntimeError("controller simulation state is not prepared")
        return f"if=pflash,format=raw,unit=1,file={self.vars}"

    def verify_canonical(self) -> None:
        if not self._disk_hash or not self._vars_hash:
            raise RuntimeError("controller simulation state is not prepared")
        if sha256(self.canonical_disk) != self._disk_hash:
            raise RuntimeError("canonical controller disk changed during simulation")
        if sha256(self.canonical_vars) != self._vars_hash:
            raise RuntimeError("canonical OVMF variables changed during simulation")

    def close(self) -> None:
        if self._closed:
            return
        # Preserve the overlay and lock when QEMU (or anything else) still has
        # the backing disk open.  The caller can stop it and retry close.
        self._assert_canonical_not_open()
        failure = None
        try:
            self.verify_canonical()
        except BaseException as error:
            failure = error
        finally:
            self._remove_run_state()
            self._unlock()
            self._closed = True
        if failure:
            raise failure

    def _assert_canonical_not_open(self) -> None:
        for path, label in (
            (self.canonical_disk, "canonical controller disk"),
            (self.canonical_vars, "canonical OVMF variables"),
        ):
            users = canonical_disk_users(path, proc_root=self._proc_root)
            if users:
                raise CanonicalDiskInUse(f"{label} is open by: " + ", ".join(users))

    def _probe_qemu_image_lock(self) -> None:
        """Ask qemu-img to acquire its normal read lock without modifying data."""
        try:
            _qemu_image_info(self.canonical_disk)
        except subprocess.CalledProcessError as error:
            raise CanonicalDiskInUse(
                "qemu-img could not lock/read the canonical controller disk"
            ) from error

    def _remove_run_state(self) -> None:
        if self._temporary:
            shutil.rmtree(self.root, ignore_errors=True)
        else:
            for path in (self.disk, self.vars):
                path.unlink(missing_ok=True)

    def _unlock(self) -> None:
        if self._lock_stream is not None:
            fcntl.flock(self._lock_stream.fileno(), fcntl.LOCK_UN)
            self._lock_stream.close()
            self._lock_stream = None

    def __enter__(self) -> "ControllerOverlay":
        return self.prepare()

    def __exit__(self, *_exc) -> None:
        self.close()


class PersistentControllerInstance:
    """A named controller whose directory server survives being shut down.

    Opt-in only. Nothing constructs this class from a default; a caller has to
    name a persistent root and an instance, and every entry point refuses the
    acceptance canonical (``assert_persistent_state_separate``). The disposable
    path is untouched by this class existing: it neither imports from nor
    changes ``ControllerOverlay``'s behaviour, and it never opens the canonical
    disk except read-only, once, while creating an instance.

    **Why the instance boots its own disk in place** rather than booting an
    overlay and committing it back at shutdown:

    * *Crash safety.* Booting the qcow2 in place means a killed run leaves the
      disk exactly as a power cut leaves a physical disk: crash-consistent,
      recovered by the guest filesystem journal and Samba's own ldb/tdb
      recovery on the next boot — the same failure mode a real domain
      controller has. Commit-at-shutdown instead turns every abrupt kill into
      the total loss of that session's accounts, and a kill *during*
      ``qemu-img commit`` leaves the base image partially rewritten: a torn
      directory, across the whole disk, that no journal can recover.
    * *``qemu-img`` safety.* ``convert``/``commit`` against a disk that is live
      state is a data race; qemu-img's own locking refuses the image while QEMU
      holds it, and a crashed run is by definition not a quiesced window.
      Booting in place needs no ``qemu-img`` operation after creation at all.
    * *Bootstrapping.* First bring-up therefore copies the canonical image once,
      under ``ControllerOverlay``'s strict fence, into an independent qcow2 with
      no backing file. A backing-file reference to the canonical would have made
      every later session depend on the canonical staying byte-identical for
      ever, and would have put persistent writes one link away from the disk the
      acceptance gates fence.
    """

    def __init__(
        self,
        state: Path,
        *,
        instance: str | None = None,
        proc_root: Path = Path("/proc"),
    ) -> None:
        self.state = Path(state).absolute()
        self.instance = instance
        self._proc_root = Path(proc_root)
        self.disk = self.state / PERSISTENT_DISK_NAME
        self.vars = self.state / PERSISTENT_VARS_NAME
        self.marker = self.state / PERSISTENT_MARKER_NAME
        self.lock_path = self.state / LOCK_NAME
        self._lock_stream = None
        self._closed = False

    # -- guards ----------------------------------------------------------
    def assert_separate(self, canonical_disk: Path | None = None) -> None:
        """Refuse the acceptance state, and refuse a symlinked state path."""
        assert_persistent_state_separate(
            self.state, canonical_disk=canonical_disk)
        if _path_has_symlink(self.state):
            raise PersistentInstanceInvalid(
                f"persistent state path includes a symlink: {self.state}")

    @staticmethod
    def valid_instance_name(instance: str | None) -> bool:
        return isinstance(instance, str) and bool(
            PERSISTENT_INSTANCE_NAME.fullmatch(instance))

    def read_marker(self) -> dict:
        """Return the validated instance marker, or fail closed.

        The positive half of the safety property: a directory is only a
        persistent instance if it says so in its own marker. The acceptance
        canonical has no marker and must never be given one, so no spelling of
        its path can reach bring-up or teardown through here.
        """
        self.assert_separate()
        if not _regular_file(self.marker):
            raise PersistentInstanceInvalid(
                f"not a persistent controller instance (no "
                f"{PERSISTENT_MARKER_NAME}): {self.state}")
        try:
            raw = json.loads(self.marker.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as error:
            raise PersistentInstanceInvalid(
                f"cannot read persistent instance marker: {self.marker}"
            ) from error
        if not isinstance(raw, dict):
            raise PersistentInstanceInvalid(
                f"persistent instance marker is not an object: {self.marker}")
        if raw.get("schema") != PERSISTENT_MARKER_SCHEMA:
            raise PersistentInstanceInvalid(
                "persistent instance marker must declare schema "
                f"{PERSISTENT_MARKER_SCHEMA}: {self.marker}")
        if raw.get("mode") != PERSISTENT_MODE:
            raise PersistentInstanceInvalid(
                f"persistent instance marker must declare mode "
                f"{PERSISTENT_MODE}: {self.marker}")
        name = raw.get("instance")
        if not self.valid_instance_name(name):
            raise PersistentInstanceInvalid(
                f"persistent instance marker has no valid instance name: "
                f"{self.marker}")
        if self.instance is not None and name != self.instance:
            raise PersistentInstanceInvalid(
                f"persistent instance marker names {name}, not "
                f"{self.instance}: {self.marker}")
        return raw

    def exists(self) -> bool:
        return all(
            _regular_file(path)
            for path in (self.disk, self.vars, self.marker))

    # -- creation --------------------------------------------------------
    def create(self, canonical_disk: Path, canonical_vars: Path) -> dict:
        """Seed a new instance from the canonical image without mutating it.

        The copy is taken through ``ControllerOverlay``, so creation runs under
        the *strict* fence: the canonical disk is locked, audited for open
        descriptors, and re-hashed afterwards. Creation is the only moment a
        persistent instance touches the canonical at all, and it may not change
        it — the relaxed fence applies solely to the instance's own disk.
        """
        if not self.valid_instance_name(self.instance):
            raise PersistentInstanceInvalid(
                "persistent instance name must be 1-32 lowercase letters, "
                "digits, or hyphens and must not start or end with a hyphen")
        canonical_disk = Path(canonical_disk).absolute()
        canonical_vars = Path(canonical_vars).absolute()
        self.assert_separate(canonical_disk)
        if self.state.exists() and any(self.state.iterdir()):
            raise PersistentInstanceInvalid(
                f"persistent state already exists at {self.state}")
        for path, label in (
            (canonical_disk, "canonical controller disk"),
            (canonical_vars, "canonical OVMF variables"),
        ):
            if not _regular_file(path):
                raise PersistentInstanceInvalid(
                    f"{label} must be a regular, non-symlink file: {path}")

        self.state.parent.mkdir(parents=True, exist_ok=True)
        staging = Path(tempfile.mkdtemp(
            prefix=f".{self.state.name}.", dir=self.state.parent))
        try:
            staging.chmod(0o700)
            staged_disk = staging / PERSISTENT_DISK_NAME
            staged_vars = staging / PERSISTENT_VARS_NAME
            with tempfile.TemporaryDirectory(
                    prefix="homelab-persistent-seed-") as guard_root:
                guard = ControllerOverlay(
                    canonical_disk, canonical_vars,
                    run_root=Path(guard_root) / "guard",
                    proc_root=self._proc_root)
                guard.prepare()
                try:
                    # An independent qcow2, not an overlay: after this the
                    # instance has no dependency on the canonical image, so
                    # rebuilding the canonical can never corrupt a directory.
                    subprocess.run(
                        [
                            "qemu-img", "convert", "-f", "qcow2",
                            "-O", "qcow2", str(guard.disk), str(staged_disk),
                        ],
                        check=True, capture_output=True,
                    )
                    shutil.copy2(guard.vars, staged_vars)
                    seeded = {
                        "disk": str(canonical_disk),
                        "disk_sha256": guard.canonical_disk_sha256,
                        "vars_sha256": guard.canonical_vars_sha256,
                    }
                except BaseException:
                    # Report the real failure, not a teardown error raised on
                    # top of it; the guard still releases its lock either way.
                    with contextlib.suppress(BaseException):
                        guard.close()
                    raise
                guard.close()
            marker = {
                "schema": PERSISTENT_MARKER_SCHEMA,
                "mode": PERSISTENT_MODE,
                "instance": self.instance,
                "created_utc": datetime.now(UTC).isoformat(),
                "disk": {"format": "qcow2", "name": PERSISTENT_DISK_NAME},
                "seeded_from": seeded,
                "hash_fence": (
                    "none: this disk is the durable directory state and is "
                    "expected to change; the acceptance canonical keeps its "
                    "strict fence"
                ),
            }
            (staging / PERSISTENT_MARKER_NAME).write_text(
                json.dumps(marker, indent=2) + "\n", encoding="utf-8")
            for name in (
                PERSISTENT_DISK_NAME, PERSISTENT_VARS_NAME,
                PERSISTENT_MARKER_NAME,
            ):
                (staging / name).chmod(0o600)
            # Rename last: an interrupted creation leaves a dot-prefixed
            # staging directory, never a half-seeded instance that bring-up
            # would treat as a directory server.
            staging.rename(self.state)
        except BaseException:
            shutil.rmtree(staging, ignore_errors=True)
            raise
        return marker

    # -- bring-up --------------------------------------------------------
    def prepare(self) -> "PersistentControllerInstance":
        """Take the instance's exclusive lock and check nothing else has it."""
        if self._lock_stream is not None:
            raise RuntimeError(
                "persistent controller instance is already prepared")
        marker = self.read_marker()
        self.instance = marker["instance"]
        for path, label in (
            (self.disk, "persistent controller disk"),
            (self.vars, "persistent OVMF variables"),
        ):
            if not _regular_file(path):
                raise PersistentInstanceInvalid(
                    f"{label} must be a regular, non-symlink file: {path}")
            state = path.stat()
            if state.st_uid != os.geteuid():
                raise PersistentInstanceInvalid(
                    f"{label} must be owned by the current user")
            # A live directory holds the domain's own secrets (krbtgt, machine
            # account keys), so nothing beyond the owner may read it either.
            if state.st_mode & 0o077:
                raise PersistentInstanceInvalid(
                    f"{label} must not be group/world accessible")
        self._closed = False
        self._lock_stream = self.lock_path.open("a+b")
        try:
            fcntl.flock(self._lock_stream.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            self._lock_stream.close()
            self._lock_stream = None
            raise PersistentInstanceInUse(
                f"persistent controller instance {self.instance} is already "
                "running"
            ) from error
        try:
            self._assert_disk_not_open()
            try:
                _qemu_image_info(self.disk)
            except subprocess.CalledProcessError as error:
                raise PersistentInstanceInUse(
                    "qemu-img could not lock/read the persistent controller "
                    "disk"
                ) from error
        except BaseException:
            self._unlock()
            raise
        return self

    def qemu_disk_drive(self, drive_id: str = "osdisk") -> str:
        """Return the writable in-place drive argument for the durable disk."""
        if self._lock_stream is None or not self.disk.is_file():
            raise RuntimeError(
                "persistent controller instance is not prepared")
        return f"file={self.disk},if=none,id={drive_id},format=qcow2,cache=none"

    def qemu_vars_drive(self) -> str:
        """Return the writable pflash argument for the instance's variables."""
        if self._lock_stream is None or not self.vars.is_file():
            raise RuntimeError(
                "persistent controller instance is not prepared")
        return f"if=pflash,format=raw,unit=1,file={self.vars}"

    def verify_canonical(self) -> None:
        """Always fail: a persistent instance has no hash fence, by design.

        A tripwire, not an oversight. ``ControllerOverlay`` exposes this method
        and acceptance runners call it before writing a pass receipt; if a
        persistent instance were ever wired into one of those paths, the run
        must stop loudly here rather than silently record a fence it never had.
        """
        raise PersistentInstanceInvalid(
            "a persistent controller instance has no canonical hash fence: "
            "its disk is the durable directory state and is expected to change")

    def close(self) -> None:
        """Release the lock. The disk is deliberately left exactly as it is.

        There is nothing to delete and nothing to re-hash: the disk *is* the
        state. The open-descriptor audit still runs first, so a lock is never
        released while QEMU is still writing the directory — the caller can stop
        the guest and retry, exactly as the disposable path does.
        """
        if self._closed:
            return
        self._assert_disk_not_open()
        self._unlock()
        self._closed = True

    # -- teardown --------------------------------------------------------
    def destroy(self, confirm: str | None) -> str:
        """Erase one instance after an exact, instance-named confirmation."""
        marker = self.read_marker()
        expected = f"{DESTROY_CONFIRMATION_PREFIX} {marker['instance']}"
        if confirm != expected:
            raise PersistentInstanceInvalid(
                f"refusing to erase a directory server; pass the exact "
                f"confirmation: {expected}")
        # Lock and audit before unlinking: erasing the disk under a running
        # QEMU would corrupt a live directory instead of retiring it.
        self.prepare()
        try:
            keep = {
                PERSISTENT_DISK_NAME, PERSISTENT_VARS_NAME,
                PERSISTENT_MARKER_NAME, LOCK_NAME,
            }
            unexpected = sorted(
                entry.name for entry in self.state.iterdir()
                if entry.name not in keep or entry.is_symlink())
            if unexpected:
                raise PersistentInstanceInvalid(
                    "refusing: persistent state holds unexpected files: "
                    + ", ".join(unexpected))
            for name in (
                PERSISTENT_DISK_NAME, PERSISTENT_VARS_NAME,
                PERSISTENT_MARKER_NAME,
            ):
                (self.state / name).unlink(missing_ok=True)
        finally:
            # Release directly rather than through ``close``: the audit there
            # stats a disk this method has just removed.
            self._unlock()
            self._closed = True
        self.lock_path.unlink(missing_ok=True)
        self.state.rmdir()
        return str(self.state)

    # -- internals -------------------------------------------------------
    def _assert_disk_not_open(self) -> None:
        for path, label in (
            (self.disk, "persistent controller disk"),
            (self.vars, "persistent OVMF variables"),
        ):
            users = canonical_disk_users(path, proc_root=self._proc_root)
            if users:
                raise PersistentInstanceInUse(
                    f"{label} is open by: " + ", ".join(users))

    def _unlock(self) -> None:
        if self._lock_stream is not None:
            fcntl.flock(self._lock_stream.fileno(), fcntl.LOCK_UN)
            self._lock_stream.close()
            self._lock_stream = None

    def __enter__(self) -> "PersistentControllerInstance":
        return self.prepare()

    def __exit__(self, *_exc) -> None:
        self.close()
