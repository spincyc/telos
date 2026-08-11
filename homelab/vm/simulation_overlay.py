"""Disposable, fail-closed state for controller network simulations."""

from __future__ import annotations

import fcntl
import hashlib
import os
import shutil
import subprocess
import tempfile
import time
from pathlib import Path

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
        lock_path = self.canonical_disk.parent / ".simulation.lock"
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
            subprocess.run(
                ["qemu-img", "info", "--output=json", str(self.canonical_disk)],
                check=True,
                capture_output=True,
            )
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
