"""Host-side arming and reconnect-aware collection for the progress channel.

Two host-side jobs live here, shared by every harness:

* **Arming.**  ``attach_planned_progress_port`` adds the virtserialport
  triple to a QEMU argv whose socket directory does not exist yet (a bundle
  pinned at prepare time) or which already carries another, separately
  audited character device.  It renders byte-identical argv to
  ``guest_progress_host.attach_progress_port`` and is proved so by test; the
  strict launch-time filesystem checks that function performs are then run
  by ``prepare_socket_directory`` immediately before the guest starts.
* **Collection.**  ``GuestProgressCollector`` connects opportunistically to
  the QEMU-owned socket and survives guest restarts: the shipped reporter
  unit is ``Restart=on-failure`` with ``StartLimitBurst=3``, so one run can
  legitimately produce several transport boots.  Each reconnection restores
  the authenticated checkpoint of the previous one and retires its boot id,
  so replay resistance and accepted-event history carry across, and the
  **host deadline is the one supplied at construction, forever**: a restored
  receiver is built against that same immutable value.

Nothing here is authoritative.  Progress never extends a deadline, never
authorizes the next destructive step, and an absent stream is recorded as
absent.  Every wait is bounded: the connect attempt, the collection (by the
receiver deadline), the thread join, and the number of reconnections.
"""

from __future__ import annotations

import shutil
import socket
import threading
import time
from pathlib import Path

try:
    from .guest_progress_credentials import (
        ProgressCredential, destroy_credential_document,
        stage_credential_document)
    from .guest_progress_host import (
        PROGRESS_BUS_ID, PROGRESS_CHARDEV_ID, PROGRESS_PORT_NAME,
        GuestProgressHostError, classify, progress_record)
    from .guest_progress_protocol import (
        DeadlineError, GuestProgressError, ReceiverState, ReplayError)
    from .guest_progress_transport import GuestProgressTransport
except ImportError:  # Direct execution from homelab/vm.
    # The guest-progress modules import siblings only relatively, so a
    # direct-script run reaches them through the repository root package,
    # exactly as factory_runner does.
    import sys

    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
    from homelab.vm.guest_progress_credentials import (
        ProgressCredential, destroy_credential_document,
        stage_credential_document)
    from homelab.vm.guest_progress_host import (
        PROGRESS_BUS_ID, PROGRESS_CHARDEV_ID, PROGRESS_PORT_NAME,
        GuestProgressHostError, classify, progress_record)
    from homelab.vm.guest_progress_protocol import (
        DeadlineError, GuestProgressError, ReceiverState, ReplayError)
    from homelab.vm.guest_progress_transport import GuestProgressTransport


#: The socket file every harness creates inside its own private root.
PROGRESS_SOCKET_NAME = "progress.sock"
#: One bounded connect attempt per poll; a missing socket is not an error.
CONNECT_TIMEOUT = 0.05
#: Bound on transport boots per run.  The shipped unit restarts at most
#: three times, so this leaves headroom without becoming unbounded.
MAX_SESSIONS = 8
#: Linux sockaddr_un.sun_path is 108 bytes including the trailing NUL.
SUN_PATH_LIMIT = 108


def progress_port_arguments(socket_path) -> tuple[list[str], str]:
    """Return the progress argv fragment and its exact chardev value.

    Path-shape validation only: the socket's directory need not exist yet,
    so a bundle prepared long before its run can pin this argv.  The
    filesystem invariants (private real parent, absent socket) are proved at
    launch by ``prepare_socket_directory``.
    """
    if isinstance(socket_path, (bytes, bytearray)):
        raise GuestProgressHostError("progress socket path must be text")
    path = Path(socket_path)
    if not path.is_absolute():
        raise GuestProgressHostError("progress socket path must be absolute")
    encoded = str(path).encode()
    if b"," in encoded or any(byte < 0x20 for byte in encoded):
        raise GuestProgressHostError("progress socket path is not QEMU-safe")
    if len(encoded) >= SUN_PATH_LIMIT:
        raise GuestProgressHostError("progress socket path is too long")
    chardev = f"socket,id={PROGRESS_CHARDEV_ID},path={path},server=on,wait=off"
    return [
        "-chardev", chardev,
        "-device", f"virtio-serial-pci,id={PROGRESS_BUS_ID}",
        "-device",
        f"virtserialport,bus={PROGRESS_BUS_ID}.0,"
        f"chardev={PROGRESS_CHARDEV_ID},name={PROGRESS_PORT_NAME}",
    ], chardev


def attach_planned_progress_port(
    command: list[str] | tuple[str, ...], socket_path,
) -> tuple[list[str], str]:
    """Return argv plus the progress port, tolerating other audited chardevs.

    ``guest_progress_host.attach_progress_port`` refuses any command that
    already declares a character device, which is right for a command built
    from nothing.  Some harnesses attach one separately audited chardev of
    their own (the Windows identity console), so this variant refuses only a
    second *progress* channel.  Nothing secret enters argv either way.
    """
    if type(command) not in (list, tuple):
        raise GuestProgressHostError("QEMU command must be a list or tuple")
    items = list(command)
    if not items or any(type(item) is not str for item in items):
        raise GuestProgressHostError("QEMU command must be exact strings")
    # PROGRESS_BUS_ID contains PROGRESS_CHARDEV_ID, so one check covers both.
    if any(PROGRESS_CHARDEV_ID in item for item in items):
        raise GuestProgressHostError(
            "QEMU command already uses the progress channel identifier")
    fragment, chardev = progress_port_arguments(socket_path)
    return items + fragment, chardev


def audit_progress_port(command) -> tuple[str, ...]:
    """Prove how (or whether) an argv arms the progress port, fail-closed.

    Returns the armed chardev values -- ``()`` when the port is not armed --
    for the caller to hand straight to its own closed chardev allowlist.  A
    partial, duplicated, or hand-edited arming raises instead of being
    silently tolerated, so no harness can grow a channel that the boundary
    audits never saw.
    """
    if type(command) not in (list, tuple) or any(
            type(item) is not str for item in command):
        raise GuestProgressHostError("QEMU command must be exact strings")
    items = list(command)
    chardevs = [
        items[index + 1] for index, item in enumerate(items[:-1])
        if item == "-chardev"
        and items[index + 1].startswith(f"socket,id={PROGRESS_CHARDEV_ID},")
    ]
    mentions = [
        item for item in items
        if PROGRESS_CHARDEV_ID in item or PROGRESS_PORT_NAME in item
    ]
    if not chardevs:
        if mentions:
            raise GuestProgressHostError(
                "QEMU command names the progress channel without arming it")
        return ()
    if len(chardevs) != 1:
        raise GuestProgressHostError(
            "QEMU command arms the progress channel more than once")
    fields = dict(
        field.split("=", 1) for field in chardevs[0].split(",")
        if "=" in field)
    fragment, chardev = progress_port_arguments(fields.get("path", ""))
    if chardev != chardevs[0]:
        raise GuestProgressHostError(
            "progress chardev differs from the canonical channel")
    for index in range(len(items) - len(fragment) + 1):
        if items[index:index + len(fragment)] == fragment:
            break
    else:
        raise GuestProgressHostError(
            "progress port is not armed as the canonical device triple")
    if any(items.count(value) != 1 for value in fragment[1::2]):
        raise GuestProgressHostError(
            "progress port devices are declared more than once")
    return (chardev,)


def prepare_socket_directory(root, *, name: str = PROGRESS_SOCKET_NAME) -> Path:
    """Create the private socket root and prove the socket path is free.

    Mirrors the launch-time invariants ``attach_progress_port`` enforces:
    a real, private, non-symlinked parent directory and an absent socket.
    """
    directory = Path(root)
    # Created private, and never relaxed *or* silently tightened: a directory
    # that already exists with loose permissions is a fail-closed error, not
    # something to repair underneath the caller.
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    if directory.is_symlink() or not directory.is_dir():
        raise GuestProgressHostError(
            "progress socket parent must be a private real directory")
    if directory.stat().st_mode & 0o077:
        raise GuestProgressHostError(
            "progress socket parent must be a private real directory")
    path = directory / name
    if path.exists() or path.is_symlink():
        raise GuestProgressHostError("progress socket path must be absent")
    # Re-run the exact shape checks the argv fragment applied.
    progress_port_arguments(path)
    return path


def remove_socket_root(root) -> list[str]:
    """Remove one per-run progress socket root and prove its absence."""
    target = Path(root)
    failures: list[str] = []
    try:
        shutil.rmtree(target)
    except FileNotFoundError:
        pass
    except OSError as error:
        failures.append(f"progress socket root removal failed: {error}")
    if target.is_symlink() or target.exists():
        failures.append(f"progress socket root was not removed: {target}")
    return failures


class GuestProgressCollector:
    """Opportunistic, reconnect-aware collector for one progress socket.

    Never load-bearing: an absent peer, a transport fault, or a protocol
    error only shapes the retained progress block.  Verdicts, gates, and
    deadlines are untouched, and nothing secret leaves this object.
    """

    def __init__(
        self,
        socket_path,
        *,
        deadline: float,
        credential: ProgressCredential,
        producer: str,
        phases: tuple[str, ...],
        statuses: tuple[str, ...],
        connect_timeout: float = CONNECT_TIMEOUT,
        max_sessions: int = MAX_SESSIONS,
        clock=time.monotonic,
        **options,
    ) -> None:
        if type(credential) is not ProgressCredential:
            raise GuestProgressHostError(
                "collector requires an exact ProgressCredential")
        if type(max_sessions) is not int or not 1 <= max_sessions <= 64:
            raise GuestProgressHostError(
                "reconnection bound must be a small positive integer")
        self.socket_path = Path(socket_path)
        # Immutable for the collector's whole life: every restored receiver
        # is rebuilt against this same value, so a reconnection can never
        # extend the host timeline.
        self.deadline = float(deadline)
        self._credential = credential
        self._config = credential.protocol_config(
            producer=producer, phases=tuple(phases), statuses=tuple(statuses),
            **options)
        self._key = bytes(credential.key)
        self._connect_timeout = float(connect_timeout)
        self._max_sessions = max_sessions
        self._clock = clock

        self._receiver: ReceiverState | None = None
        self._checkpoint: bytes | None = None
        self._connection: socket.socket | None = None
        self._thread: threading.Thread | None = None
        self._result = None
        self._error: BaseException | None = None
        self._stopping = False
        self._staged: list[Path] = []
        #: Host-monotonic instant of the newest accepted event, across all
        #: transport boots.  Liveness is measured from it, so a reconnection
        #: that has not spoken yet does not erase what the previous one said.
        self._last_event_at: float | None = None
        #: A boot-change rejection held in suspense: cleared once the resumed
        #: session accepts an event (proving a restart), reported as the
        #: classification if it never does (leaving the doubt on the record).
        self._deferred_error: BaseException | None = None
        #: Guest restarts resumed in place, for the harness's diagnostics.
        self.restarts = 0
        #: Public, secret-free counters for the harness's own diagnostics.
        self.sessions = 0
        self.boots: tuple[str, ...] = ()
        self.events_accepted = 0
        self.last_phase: str | None = None
        self.last_sequence: int | None = None
        #: The liveness the newest settled session reported.  The evidence
        #: block uses the cross-boot aggregate below, not this.
        self.session_liveness: str | None = None

    # -- delivery seam ------------------------------------------------------

    def stage_credential(self, directory, **options) -> Path:
        """Write this channel's credential document for a delivery channel.

        The collector owns the credential, so whichever channel the owner
        chooses asks the collector for the document rather than re-deriving
        it.  Every staged document is destroyed by ``close``.
        """
        path = stage_credential_document(
            self._credential, directory, **options)
        self._staged.append(path)
        return path

    def credential_document_bytes(self) -> bytes:
        """The byte-shaped half of the same seam; nothing touches disk."""
        return self._credential.document_bytes()

    # -- collection ---------------------------------------------------------

    def poll(self) -> None:
        """Advance collection by at most one bounded, non-blocking step.

        Reaps a finished session, restores the receiver for the next one,
        and tries one bounded connect.  A missing or refusing socket is
        tolerated for the whole run; a successful connect hands the stream
        to a background collector so the caller's cadence never blocks.
        """
        if self._stopping:
            return
        if self._thread is not None:
            if self._thread.is_alive():
                return
            self._reap()
            if self._thread is not None:
                # The reap could not finish (the collector thread outlived
                # its join bound); never open a second session beside it.
                return
        if self.sessions >= self._max_sessions:
            return
        if self._clock() >= self.deadline:
            return
        if self._receiver is None and not self._open_receiver():
            return
        # A restart the guest performed behind an unbroken host connection
        # (the shipped unit is Restart=on-failure) leaves the socket usable;
        # only a broken or finished stream needs a fresh connect.
        connection = self._connection
        if connection is None:
            connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            connection.settimeout(self._connect_timeout)
            try:
                connection.connect(str(self.socket_path))
            except OSError:
                connection.close()
                return
            self._connection = connection
        assert self._receiver is not None
        transport = GuestProgressTransport(connection, self._receiver)
        self.sessions += 1
        self._thread = threading.Thread(
            target=self._collect, args=(transport,),
            name="guest-progress", daemon=True)
        self._thread.start()

    def _open_receiver(self) -> bool:
        """Build the receiver for the next session under the same deadline."""
        try:
            if self._checkpoint is None:
                self._receiver = ReceiverState(
                    self._config, self._key, deadline=self.deadline)
            else:
                receiver = ReceiverState.restore(
                    self._checkpoint, self._config, self._key,
                    deadline=self.deadline)
                # Retire the previous transport boot: a restarted guest
                # reports a new boot_id, and its old one may never return.
                receiver.reconnect()
                self._receiver = receiver
        except GuestProgressError as error:
            self._error = error
            self._receiver = None
            return False
        return True

    def _collect(self, transport: GuestProgressTransport) -> None:
        try:
            self._result = transport.collect()
        except BaseException as error:
            # A deliberate stop tears the socket down under the reader; that
            # fault is not a guest observation.
            if not self._stopping:
                self._error = error

    def _reap(self) -> None:
        """Fold one finished session into the aggregate observation."""
        thread, self._thread = self._thread, None
        if thread is not None:
            thread.join(timeout=5)
            if thread.is_alive():
                # Leave the session owned by the live thread rather than
                # racing it; the next poll retries the reap.
                self._thread = thread
                return
        # A rejected boot change is the one fault worth resuming in place:
        # the guest restarted, its stop-and-wait sender still holds the
        # unacknowledged frame, and the socket underneath is untouched.  Any
        # other fault closes the connection and starts a clean session.
        resumable = (
            self._result is None
            and isinstance(self._error, ReplayError)
            and not self._stopping)
        if resumable:
            self.restarts += 1
            self._deferred_error, self._error = self._error, None
        else:
            connection, self._connection = self._connection, None
            if connection is not None:
                try:
                    connection.close()
                except OSError:
                    pass
        result, self._result = self._result, None
        receiver, self._receiver = self._receiver, None
        if result is not None:
            for event in result.events:
                self.events_accepted += 1
                self.last_sequence = event.envelope["sequence"]
                if event.envelope["phase"] is not None:
                    self.last_phase = event.envelope["phase"]
                boot = event.envelope["boot_id"]
                if boot not in self.boots:
                    self.boots += (boot,)
            if result.events:
                self._last_event_at = self._clock()
                # The resumed stream delivered: the rejection that preceded
                # it was a guest restart, not a replay.
                self._deferred_error = None
            self.session_liveness = result.liveness
            # The transport drained and closed the receiver; its
            # authenticated checkpoint is what the next boot restores from.
            self._checkpoint = result.checkpoint
            return
        # No settled result: harvest what the receiver itself accepted
        # before the fault, then checkpoint it if that is still possible.
        if receiver is not None:
            try:
                self._checkpoint = receiver.checkpoint()
            except GuestProgressError:
                pass
            try:
                self.session_liveness = receiver.liveness(now=self._clock())
            except GuestProgressError:
                pass
            last = receiver.last_sequence
            if last is not None:
                accepted = last + 1
                if accepted > self.events_accepted:
                    self.events_accepted = accepted
                self.last_sequence = last
                self.last_phase = receiver.active_phase or self.last_phase
                self._last_event_at = receiver.last_receive
                if receiver.boot_id and receiver.boot_id not in self.boots:
                    self.boots += (receiver.boot_id,)
            try:
                receiver.close()
            except Exception:
                pass

    def stop(self) -> None:
        """Stop collecting; idempotent and bounded."""
        self._stopping = True
        if self._connection is not None:
            try:
                self._connection.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
        if self._thread is not None:
            self._thread.join(timeout=5)
            if not self._thread.is_alive():
                self._reap()

    # -- evidence -----------------------------------------------------------

    def record(self) -> dict:
        """Compose the secret-free evidence block; never raises."""
        self.stop()
        try:
            return self._compose()
        except Exception:
            # Composition can never mask a run verdict; fall back to the
            # weakest honest observation.
            return progress_record(
                liveness="absent", classification="unavailable")

    def _compose(self) -> dict:
        if self.sessions == 0:
            # No peer ever connected: the device was unavailable and the
            # stream is absent.
            return progress_record(
                liveness="absent", classification="unavailable")
        liveness = self._aggregate_liveness()
        error = self._error or self._deferred_error
        if error is None:
            classification = None
        elif isinstance(error, DeadlineError) and not self.events_accepted:
            # An empty stream at the deadline is absence, not a stall.
            classification = "absent"
        else:
            classification = classify(error)
        if not self.events_accepted:
            # A peer connected and no authenticated event ever landed: the
            # stream is absent, whatever the socket did.
            return progress_record(
                liveness="absent", classification=classification or "absent")
        return progress_record(
            liveness=liveness,
            classification=classification,
            last_phase=self.last_phase,
            last_sequence=self.last_sequence,
            events_accepted=self.events_accepted,
        )

    def _aggregate_liveness(self) -> str:
        """Classify the stream across boots, exactly as one receiver would.

        Silence is measured from the newest accepted event of any boot, with
        the same tightened bound ``ReceiverState.liveness`` applies while a
        phase is active.  A reconnection that has not spoken yet therefore
        reads as a stall of one stream rather than as an absent one.
        """
        if self._last_event_at is None or not self.events_accepted:
            return "absent"
        limit = self._config.silence_limit
        if self.last_phase is not None:
            limit = min(limit, 2 * self._config.heartbeat_interval)
        return (
            "stalled" if self._clock() - self._last_event_at > limit
            else "live")

    def close(self) -> list[str]:
        """Stop collection, destroy key and credential state, report failures."""
        failures: list[str] = []
        self.stop()
        if self._thread is not None and self._thread.is_alive():
            failures.append("progress collector thread did not stop")
        if self._connection is not None:
            try:
                self._connection.close()
            except OSError as error:
                failures.append(f"progress connection close failed: {error}")
            self._connection = None
        if self._receiver is not None:
            try:
                self._receiver.close()
            except Exception as error:
                failures.append(f"progress receiver close failed: {error}")
            self._receiver = None
        for path in self._staged:
            failures += destroy_credential_document(path)
        self._staged = []
        self._checkpoint = None
        self._key = b""
        # Python cannot zeroize the immutable key bytes; dropping the only
        # reference this object holds is the whole of what it can promise.
        self._credential = None
        return failures
