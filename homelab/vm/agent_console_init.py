"""Give a new agent-custody instance a generated ``local-rescue`` password.

TASK-40.  The canonical Controller image's ``local-rescue`` password is the
owner's (typed during its offline install); root is locked, there is no key
and no init shell, and nothing in this repository can open the image without
that password.  A THROWAWAY instance created with ``CUSTODY=agent`` needs a
console credential the harness holds instead, so ``persistent-up`` sets one,
once, while the instance is being created:

1. ``PersistentControllerInstance.create`` has copied the canonical image
   (under its strict fence) into a private staging directory; the instance
   does not exist under its own name yet.  Nothing here touches the
   canonical image, an owner-custody instance or an existing instance.
2. A value is generated and written to the staging copy's custody store
   BEFORE any guest can take it.
3. The staged qcow2 is converted to a sparse raw copy and the disposable
   path's proven one-run init-shell entry is selected on ITS ESP
   (``automated_controller.DisposableBootDisk._inject_entry``, reused, not
   rewritten), after keeping the original ``loader/loader.conf`` bytes.
4. The raw copy boots with no network device at all (``-nic none``) to the
   init shell: remount rw, ``passwd local-rescue`` (the sequence
   ``AutomatedSerial`` proved), then ``exec`` systemd.  The console then
   logs in as ``local-rescue`` with the new value and powers off through
   ``sudo -k -S`` -- which proves the stored value opens both the console
   and sudo before anything depends on it -- and QEMU must exit 0.
5. Host-side, the original ``loader.conf`` bytes are written back, the
   one-run entry is deleted, and both are proved: the loader reads back
   byte-identical and the entry cannot be read.  Only then is the raw copy
   converted back to a standalone qcow2 over the staged disk.

Any failure raises; ``create`` then shreds the staged store and removes the
staging directory, so no instance, no half-initialized disk and no stray
credential remain.  The value never reaches argv, the environment, stdout or
the marker; only event names are printed.
"""

from __future__ import annotations

import contextlib
import os
import re
import shutil
import subprocess
import tempfile
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Callable

from .automated_controller import DisposableBootDisk
from .bootstrap_dc import (
    CONSOLE_ACCOUNT, DISK_SERIAL, MEMORY_MIB, NAME, PERSISTENT_CONSOLE_TIMEOUT,
    VCPUS, _AnnouncedEvents, _console_poweroff, ovmf_pair,
    persistent_console_login)
from .credential_custody import (
    SCOPE_INSTANCE, CustodyStore, generate_password)
from .serial_automation import SerialAutomation, SerialAutomationError


#: ``DisposableBootDisk._inject_entry``'s own one-run entry name; a drift test
#: holds it to that method's source.
ONE_RUN_ENTRY = "telos-automated-once.conf"
#: Everything an agent-custody creation runs on the host.
REQUIRED_TOOLS = ("qemu-system-x86_64", "qemu-img", "sfdisk", "mcopy", "mdel")
RAW_NAME = ".custody-init.raw"
QCOW2_NAME = ".custody-init.qcow2"
WORK_NAME = ".custody-init"
#: After the poweroff is observed QEMU exits on its own; this bounds it.
EXIT_TIMEOUT = 120.0
TERMINATE_TIMEOUT = 20.0
#: The only options the init boot may carry, each with its arity.
_ALLOWED_OPTIONS = {
    "-name": 1, "-machine": 1, "-cpu": 1, "-smp": 1, "-m": 1, "-display": 1,
    "-serial": 1, "-boot": 1, "-drive": 1, "-device": 1, "-nic": 1,
}


class AgentConsoleInitError(RuntimeError):
    """The generated console credential could not be set and proven."""


def _say(message: str) -> None:
    print(f"agent custody: {message}", flush=True)


class StagedEsp(DisposableBootDisk):
    """``DisposableBootDisk``'s ESP edit, aimed at one raw copy this run owns.

    Deliberately no ``DisposableBootDisk.__init__``: there is no canonical
    and no overlay here, only the staged raw disk and a private work
    directory.  ``_partition_table``, ``_esp_offset`` and ``_inject_entry``
    are inherited unchanged; they read nothing but ``disk`` and ``root``.
    """

    def __init__(self, disk: Path, root: Path) -> None:  # noqa: D107
        self.disk = Path(disk)
        self.root = Path(root)
        self._prepared = False
        self._temporary = False

    def prepare(self):  # pragma: no cover - a tripwire
        raise AgentConsoleInitError("a staged ESP is never prepared from a canonical")

    def close(self) -> None:
        """Nothing to release: the caller owns the raw copy's lifetime."""

    def _image(self) -> str:
        return f"{self.disk}@@{self._esp_offset()}"

    def loader_bytes(self) -> bytes:
        with tempfile.TemporaryDirectory(prefix="telos-esp-", dir=self.root) as temp:
            target = Path(temp) / "loader.conf"
            subprocess.run(
                ["mcopy", "-n", "-i", self._image(), "::loader/loader.conf",
                 str(target)], check=True, capture_output=True)
            return target.read_bytes()

    def entry_present(self, name: str = ONE_RUN_ENTRY) -> bool:
        with tempfile.TemporaryDirectory(prefix="telos-esp-", dir=self.root) as temp:
            target = Path(temp) / name
            completed = subprocess.run(
                ["mcopy", "-n", "-i", self._image(),
                 f"::loader/entries/{name}", str(target)],
                check=False, capture_output=True)
            return completed.returncode == 0 or target.exists()

    def select_init_shell(self) -> bytes:
        """Select the one-run entry; return the loader bytes it replaced."""
        original = self.loader_bytes()
        if self.entry_present():
            raise AgentConsoleInitError(
                "the staged copy already carries a one-run entry; refusing")
        self._inject_entry()
        if self.loader_bytes() == original or not self.entry_present():
            raise AgentConsoleInitError(
                "the one-run init-shell entry was not selected")
        return original

    def restore(self, original: bytes) -> None:
        """Write the original loader back and delete the one-run entry."""
        with tempfile.TemporaryDirectory(prefix="telos-esp-", dir=self.root) as temp:
            source = Path(temp) / "loader.conf"
            source.write_bytes(original)
            subprocess.run(
                ["mcopy", "-o", "-i", self._image(), str(source),
                 "::loader/loader.conf"], check=True, capture_output=True)
        subprocess.run(
            ["mdel", "-i", self._image(), f"::loader/entries/{ONE_RUN_ENTRY}"],
            check=True, capture_output=True)

    def prove_restored(self, original: bytes) -> None:
        if self.loader_bytes() != original:
            raise AgentConsoleInitError(
                "the staged copy's loader.conf is not the original after the "
                "one-run entry was removed")
        if self.entry_present():
            raise AgentConsoleInitError(
                "the one-run init-shell entry is still on the staged copy's "
                "ESP")


def init_command(raw: Path, vars_file: Path, *, instance: str) -> list[str]:
    """The init boot: the persistent shape, the raw copy, and NO network."""
    pair = ovmf_pair()
    code = pair[0] if pair else Path("/usr/share/edk2/x64/OVMF_CODE.4m.fd")
    return [
        "qemu-system-x86_64",
        "-name", f"persistent-dc-{instance}-custody-init",
        "-machine", "q35,accel=kvm",
        "-cpu", "host",
        "-smp", str(VCPUS),
        "-m", str(MEMORY_MIB),
        "-display", "none",
        "-serial", "mon:stdio",
        "-boot", "strict=on,menu=off",
        "-drive", f"if=pflash,format=raw,readonly=on,file={code}",
        "-drive", f"if=pflash,format=raw,file={Path(vars_file).absolute()}",
        "-drive", (f"if=none,id=osdisk,format=raw,cache=none,"
                   f"file={Path(raw).absolute()}"),
        "-device", (f"virtio-blk-pci,drive=osdisk,serial={DISK_SERIAL},"
                    "bootindex=1"),
        # Without this QEMU adds a default user-mode NIC with NAT to the host.
        "-nic", "none",
    ]


def audit_init_command(argv: list[str], *, raw: Path, vars_file: Path,
                       forbidden: tuple[Path, ...] = ()) -> None:
    """Fail closed unless *argv* boots the staged raw copy with no network."""
    if not argv or Path(argv[0]).name != "qemu-system-x86_64":
        raise AgentConsoleInitError("init boot: unapproved QEMU executable")
    index = 1
    options: list[tuple[str, str]] = []
    while index < len(argv):
        option = argv[index]
        if _ALLOWED_OPTIONS.get(option) != 1 or index + 1 >= len(argv):
            raise AgentConsoleInitError(
                f"init boot: option {option!r} is not allowed")
        options.append((option, argv[index + 1]))
        index += 2
    if [value for option, value in options if option == "-nic"] != ["none"]:
        raise AgentConsoleInitError("init boot must carry exactly -nic none")
    files = [re.search(r"(?:^|,)file=([^,]+)", value).group(1)
             for option, value in options
             if option == "-drive" and "file=" in value]
    disks = [value for option, value in options
             if option == "-drive" and "id=osdisk" in value]
    if (len(disks) != 1 or f"file={Path(raw).absolute()}" not in disks[0]
            or "format=raw" not in disks[0] or "media=cdrom" in " ".join(
                value for _option, value in options)):
        raise AgentConsoleInitError(
            "init boot must attach exactly the staged raw copy and no medium")
    if str(Path(vars_file).absolute()) not in files:
        raise AgentConsoleInitError(
            "init boot must use the staged copy's own firmware variables")
    joined = " ".join(argv)
    for path in forbidden:
        if str(Path(path).absolute()) in joined:
            raise AgentConsoleInitError(
                f"init boot names a forbidden path: {path}")


def drive_console_init(
    reader, writer, password: bytes, *, timeout: float,
    events: list | None = None,
) -> tuple[str, ...]:
    """The init-shell ``passwd``, then a real login and a sudo poweroff.

    The first half is ``AutomatedSerial.run``'s sequence byte for byte (a
    drift test holds the literals to it); the second is the persistent
    instance's own login and poweroff, so the value is proved to open the
    console and sudo exactly as every later stage will use it.
    """
    if not password or b"\n" in password or b"\r" in password:
        raise AgentConsoleInitError("the console credential must be one line")
    bootstrap = SerialAutomation(reader, writer, None, timeout=timeout)
    if events is not None:
        bootstrap.events = events
    token = ("__TELOS_INIT_" + uuid.uuid4().hex + "__").encode()
    split = len(token) // 2
    bootstrap._wait(rb"(?:^|\n)[^\n]*#\s*$", "disposable-init-shell")
    bootstrap._send(
        b"/usr/bin/mount -o remount,rw /; "
        b"/usr/bin/findmnt -no OPTIONS / | /usr/bin/grep -qw rw && "
        b"/usr/bin/printf '%s%s\\n' '"
        + token[:split] + b"' '" + token[split:] + b"'",
        "root-remount-command-sent",
    )
    bootstrap._wait(re.escape(token) + rb"\s*$", "root-remount-confirmed")
    bootstrap._wait(rb"(?:^|\n)[^\n]*#\s*$", "init-shell-ready")
    bootstrap._send(b"/usr/bin/passwd local-rescue", "passwd-command-sent")
    bootstrap._wait(rb"New password:\s*$", "new-password-prompt")
    bootstrap._send(password, "new-password-sent")
    bootstrap._wait(rb"Retype new password:\s*$", "password-confirm-prompt")
    bootstrap._send(password, "password-confirm-sent")
    bootstrap._wait(
        rb"(?:^|\n)passwd: password updated successfully\s*(?:\n|$)",
        "password-updated",
    )
    bootstrap._wait(rb"(?:^|\n)[^\n]*#\s*$", "post-passwd-init-shell")
    bootstrap._send(b"exec /usr/lib/systemd/systemd", "systemd-exec-sent")
    console = SerialAutomation(reader, writer, password, timeout=timeout)
    console.events = bootstrap.events
    persistent_console_login(console, "agent-custody")
    _console_poweroff(console, password, "agent-custody-poweroff")
    return tuple(str(event) for event in console.events)


def _spawn(argv: list[str]) -> subprocess.Popen[bytes]:
    # Its own session, as the persistent session's guest: an operator's
    # Ctrl-C reaches this process, never the guest's QEMU.
    return subprocess.Popen(
        argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT, bufsize=0, start_new_session=True)


def _stop(process: subprocess.Popen[bytes]) -> int | None:
    with contextlib.suppress(subprocess.TimeoutExpired):
        return process.wait(timeout=EXIT_TIMEOUT)
    process.terminate()
    try:
        process.wait(timeout=TERMINATE_TIMEOUT)
    except subprocess.TimeoutExpired:
        process.kill()
        with contextlib.suppress(subprocess.TimeoutExpired):
            process.wait(timeout=10)
    return None


def initializer(
    instance: str, *,
    forbidden: tuple[Path, ...] = (),
    spawn: Callable[[list[str]], subprocess.Popen[bytes]] | None = None,
    drive: Callable[..., tuple[str, ...]] | None = None,
    timeout: float = PERSISTENT_CONSOLE_TIMEOUT,
) -> Callable[..., dict]:
    """The ``initialize`` callable ``PersistentControllerInstance.create`` takes.

    *forbidden* are the canonical image's paths, which the init boot's argv
    may never name.  *spawn* and *drive* are test seams.
    """
    spawn = spawn or _spawn
    drive = drive or drive_console_init

    def initialize(*, disk: Path, vars_file: Path, staging: Path) -> dict:
        disk, vars_file, staging = (
            Path(disk).absolute(), Path(vars_file).absolute(),
            Path(staging).absolute())
        store = CustodyStore(staging, scope=SCOPE_INSTANCE, name=instance)
        value = generate_password()
        # Stored BEFORE the guest can take it, in the staging copy that
        # becomes the instance; ``create`` shreds it if anything below fails.
        store.create({"console": value})
        password = value.encode("ascii")
        value = ""
        raw = staging / RAW_NAME
        converted = staging / QCOW2_NAME
        work = staging / WORK_NAME
        process: subprocess.Popen[bytes] | None = None
        try:
            work.mkdir(mode=0o700)
            _say("copying the staged disk to a sparse raw image")
            subprocess.run(
                ["qemu-img", "convert", "-f", "qcow2", "-O", "raw", "-S",
                 "4096", str(disk), str(raw)], check=True, capture_output=True)
            os.chmod(raw, 0o600)
            esp = StagedEsp(raw, work)
            original = esp.select_init_shell()
            _say("one-run init-shell entry selected on the staged copy's ESP")
            argv = init_command(raw, vars_file, instance=instance)
            audit_init_command(
                argv, raw=raw, vars_file=vars_file, forbidden=forbidden)
            _say(f"booting the staged copy with no network; each console "
                 f"wait is bounded at {timeout:g}s")
            process = spawn(argv)
            if process.stdout is None or process.stdin is None:
                raise AgentConsoleInitError("the init boot has no console pipes")
            events = drive(process.stdout, process.stdin, password,
                           timeout=timeout, events=_AnnouncedEvents())
            returncode = _stop(process)
            if returncode != 0:
                raise AgentConsoleInitError(
                    f"the init boot did not power off cleanly (QEMU status "
                    f"{returncode})")
            process = None
            esp.restore(original)
            esp.prove_restored(original)
            _say("the one-run entry is removed and the loader is the original")
            subprocess.run(
                ["qemu-img", "convert", "-f", "raw", "-O", "qcow2", str(raw),
                 str(converted)], check=True, capture_output=True)
            os.chmod(converted, 0o600)
            os.replace(converted, disk)
        except (SerialAutomationError, subprocess.CalledProcessError,
                OSError) as error:
            raise AgentConsoleInitError(
                f"setting the agent-custody console credential failed: "
                f"{type(error).__name__}: {error}") from error
        finally:
            password = b""
            if process is not None and process.poll() is None:
                process.terminate()
                with contextlib.suppress(subprocess.TimeoutExpired):
                    process.wait(timeout=TERMINATE_TIMEOUT)
                if process.poll() is None:
                    process.kill()
            for leftover in (raw, converted):
                leftover.unlink(missing_ok=True)
            shutil.rmtree(work, ignore_errors=True)
        return {
            "utc": datetime.now(UTC).isoformat(),
            "console_account": CONSOLE_ACCOUNT,
            "method": (
                "generated by the harness; set once on the staged copy "
                "through the disposable path's one-run init-shell entry, "
                "which was removed and proved absent; the value opened the "
                f"{NAME} console and sudo before the instance existed"),
            "one_run_entry_removed": True,
            "boot_events": len(events),
            "store": "custody/" + store.path.name,
        }

    return initialize
