"""Host-side wiring and classification for the guest progress channel.

The channel is diagnostic only: nothing here turns a guest report into
acceptance evidence.  Socket-path rules mirror the fail-closed
`windows_control_serial` precedent, and the chardev value is returned
verbatim so callers can allowlist it in the QEMU argv audits.
"""

from __future__ import annotations

import re
from pathlib import Path

from .guest_progress_protocol import (
    JSON_SAFE_INTEGER_MAX,
    AuthenticationError,
    DeadlineError,
    FrameError,
    ReplayError,
    SchemaError,
    TransitionError,
)
from .guest_progress_transport import TransportError


# Public protocol constant; sized well under the shortest supported
# platform/device-name limit (30 bytes).
PROGRESS_PORT_NAME = "org.telos.progress.0"
PROGRESS_CHARDEV_ID = "telosprogress"
PROGRESS_BUS_ID = "telosprogressbus"

LIVENESS_STATES = ("absent", "live", "stalled")
# Closed receiver-state registry from GUEST-PROGRESS-REPORTING.md.
CLASSIFICATIONS = (
    "absent", "unavailable", "malformed", "unauthenticated", "replayed",
    "stalled", "contradictory", "cleanup-unproved",
)
_TOKEN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_CLASSIFY_ORDER = (
    ((FrameError, SchemaError), "malformed"),
    (AuthenticationError, "unauthenticated"),
    (ReplayError, "replayed"),
    (TransitionError, "contradictory"),
    (TransportError, "unavailable"),
    (DeadlineError, "stalled"),
)


class GuestProgressHostError(ValueError):
    """Fail-closed host wiring error for the progress channel."""


def _validate_socket_path(path) -> Path:
    """Mirror windows_control_serial: QEMU-safe, absent, private real parent."""
    if isinstance(path, (bytes, bytearray)):
        raise GuestProgressHostError("progress socket path must be text")
    path = Path(path).absolute()
    encoded = str(path).encode()
    if b"," in encoded or any(byte < 0x20 for byte in encoded):
        raise GuestProgressHostError("progress socket path is not QEMU-safe")
    parent = path.parent
    if (parent.is_symlink() or not parent.is_dir()
            or parent.stat().st_mode & 0o077):
        raise GuestProgressHostError(
            "progress socket parent must be a private real directory")
    if path.exists() or path.is_symlink():
        raise GuestProgressHostError("progress socket path must be absent")
    # Linux sockaddr_un.sun_path has 108 bytes including the trailing NUL.
    if len(encoded) >= 108:
        raise GuestProgressHostError("progress socket path is too long")
    return path


def attach_progress_port(
    command: list[str] | tuple[str, ...], socket_path
) -> tuple[list[str] | tuple[str, ...], str]:
    """Return argv plus the progress virtserialport and the exact chardev value.

    The socket is a QEMU server on a fresh private path.  Nothing secret
    enters argv, and the original command object is left untouched.
    """
    if type(command) not in (list, tuple):
        raise GuestProgressHostError("QEMU command must be a list or tuple")
    items = list(command)
    if not items or any(type(item) is not str for item in items):
        raise GuestProgressHostError("QEMU command must be exact strings")
    if "-chardev" in items:
        raise GuestProgressHostError(
            "QEMU command already declares a character device")
    # PROGRESS_BUS_ID contains PROGRESS_CHARDEV_ID, so one check covers both.
    if any(PROGRESS_CHARDEV_ID in item for item in items):
        raise GuestProgressHostError(
            "QEMU command already uses the progress channel identifier")
    path = _validate_socket_path(socket_path)
    chardev = f"socket,id={PROGRESS_CHARDEV_ID},path={path},server=on,wait=off"
    result = items + [
        "-chardev", chardev,
        "-device", f"virtio-serial-pci,id={PROGRESS_BUS_ID}",
        "-device",
        f"virtserialport,bus={PROGRESS_BUS_ID}.0,"
        f"chardev={PROGRESS_CHARDEV_ID},name={PROGRESS_PORT_NAME}",
    ]
    if type(command) is tuple:
        return tuple(result), chardev
    return result, chardev


def classify(error) -> str:
    """Map a failure to the diagnostic receiver taxonomy; never to success."""
    for kinds, label in _CLASSIFY_ORDER:
        if isinstance(error, kinds):
            return label
    return "unavailable"


def classify_liveness(liveness) -> str:
    """Validate and pass through a ReceiverState.liveness() coordinate."""
    if type(liveness) is not str or liveness not in LIVENESS_STATES:
        raise GuestProgressHostError("unknown liveness state")
    return liveness


def progress_record(
    *,
    liveness,
    classification=None,
    last_phase=None,
    last_sequence=None,
    events_accepted=0,
) -> dict:
    """Render one secret-free, JSON-able progress observation block.

    Keys, nonces, checkpoints, and other secret material are never
    accepted; every field is a bounded public coordinate.
    """
    state = classify_liveness(liveness)
    if classification is not None and (
        type(classification) is not str
        or classification not in CLASSIFICATIONS
    ):
        raise GuestProgressHostError("unknown progress classification")
    if last_phase is not None and (
        type(last_phase) is not str or _TOKEN.fullmatch(last_phase) is None
    ):
        raise GuestProgressHostError(
            "last phase is not a bounded public token")
    if last_sequence is not None and (
        type(last_sequence) is not int
        or not 0 <= last_sequence <= JSON_SAFE_INTEGER_MAX
    ):
        raise GuestProgressHostError(
            "last sequence must be a nonnegative JSON-safe integer")
    if (type(events_accepted) is not int
            or not 0 <= events_accepted <= JSON_SAFE_INTEGER_MAX):
        raise GuestProgressHostError(
            "accepted event count must be a nonnegative JSON-safe integer")
    if state == "absent" and (
        last_phase is not None
        or last_sequence is not None
        or events_accepted != 0
    ):
        raise GuestProgressHostError("absent stream cannot carry progress")
    if last_sequence is not None and events_accepted == 0:
        raise GuestProgressHostError(
            "a last sequence requires at least one accepted event")
    return {
        "channel": "virtserialport",
        "port": PROGRESS_PORT_NAME,
        "authoritative": False,
        "liveness": state,
        "classification": classification,
        "last_phase": last_phase,
        "last_sequence": last_sequence,
        "events_accepted": events_accepted,
    }
