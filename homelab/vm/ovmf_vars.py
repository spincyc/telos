#!/usr/bin/env python3
"""OVMF variable stores: read them, and drop the boot-path cache to carry one.

EDK2's variable store (``MdeModulePkg/Include/Guid/VariableFormat.h``) lives
in the NV firmware volume OVMF keeps in ``OVMF_VARS.fd``.
``firmware_variables`` reads it on the host and never writes it.

``without_hddp`` exists because a store carried from one boot into another is
not topology-neutral.  ``UefiBootManagerLib`` (``BmExpandPartitionDevicePath``)
caches the full device path it expanded a short-form ``HD()`` boot option to
in the variable ``HDDP`` (vendor ``fab7e9e1-39dd-4f2b-8408-e20e906cb6de``,
as observed in the retained workstation stores), and tries that cached path
first on the next boot.  The Arch install stages hot-attach the NVMe disk
behind a ``pcie-root-port``; every other boot of the same disk cold-plugs it
on the root complex.  A cache written in one topology poisons a boot in the
other: on 2026-10-01 kept workstation ``rehearsal-auto-ws2`` failed its
durable Windows join twice with OVMF crashing right after its logo (``KVM
internal error ... emulation failure``), its disk booted with another store,
and its OWN store booted once ``HDDP`` alone was marked deleted.  The gate-8
"firmware boot stall" (3 of 16 runs) wedged right after ``HDDP`` was written,
very likely the same mechanism.

Deleting the cache is EDK2's own operation (the state byte is ANDed with
``VAR_DELETED``, exactly as the firmware deletes a variable in place), and
the firmware re-expands the path by scanning on the next boot.  Every
other byte of the store is left as it was.  A file that is not an EDK2
variable store this module understands is refused, never guessed at.
"""

from __future__ import annotations

import os
import struct
import uuid
from pathlib import Path

FV_SIGNATURE = b"_FVH"
#: ``EFI_FIRMWARE_VOLUME_HEADER.Signature`` and ``.HeaderLength``.
FV_SIGNATURE_OFFSET = 40
FV_HEADER_LENGTH_OFFSET = 48
AUTHENTICATED_STORE = uuid.UUID("aaf32c78-947b-439a-a180-2e144ec37792")
PLAIN_STORE = uuid.UUID("ddcf3616-3275-4164-98b6-fe85707ffe7d")
STORE_HEADER_SIZE = 28
STORE_FORMATTED = 0x5A
VARIABLE_START_ID = 0x55AA
#: Header sizes: the authenticated one carries a monotonic count, a
#: timestamp and a public-key index before the name and data sizes.
AUTHENTICATED_HEADER = 60
PLAIN_HEADER = 32
#: ``VAR_ADDED``, and ``VAR_ADDED & VAR_IN_DELETED_TRANSITION`` -- a copy
#: that stays live only while no fully added copy exists.
VAR_ADDED = 0x3F
VAR_ADDED_IN_TRANSITION = 0x3E
#: ``VAR_DELETED``: a state byte ANDed with it no longer names a live copy.
VAR_DELETED = 0xFD
LIVE_STATES = (VAR_ADDED, VAR_ADDED_IN_TRANSITION)
EFI_GLOBAL_VARIABLE = uuid.UUID("8be4df61-93ca-11d2-aa0d-00e098032b8c")
#: ``mBmHardDriveBootVariableGuid``: the vendor of UefiBootManagerLib's
#: expanded hard-drive device-path cache.
HDDP_VENDOR = uuid.UUID("fab7e9e1-39dd-4f2b-8408-e20e906cb6de")
HDDP_NAME = "HDDP"
LOAD_OPTION_ACTIVE = 0x1


class FirmwareVariablesError(ValueError):
    """The file is not an EDK2 variable store this parser understands."""


def _align4(value: int) -> int:
    return (value + 3) & ~3


def _records(data: bytes):
    """``(state at, state, vendor at, name at, value at, value size)``.

    One tuple per stored copy, live or not, located by offsets into *data*.

    Walks the store the way EDK2 does: from the first 4-byte-aligned header
    after the store header to the first header without the start id.
    """
    if (len(data) < 64
            or data[FV_SIGNATURE_OFFSET:FV_SIGNATURE_OFFSET + 4]
            != FV_SIGNATURE):
        raise FirmwareVariablesError("not a firmware volume")
    store = struct.unpack_from("<H", data, FV_HEADER_LENGTH_OFFSET)[0]
    if store + STORE_HEADER_SIZE > len(data):
        raise FirmwareVariablesError("the variable store header is missing")
    vendor = uuid.UUID(bytes_le=data[store:store + 16])
    if vendor == AUTHENTICATED_STORE:
        header = AUTHENTICATED_HEADER
    elif vendor == PLAIN_STORE:
        header = PLAIN_HEADER
    else:
        raise FirmwareVariablesError("not an EDK2 variable store")
    size, format_ = struct.unpack_from("<IB", data, store + 16)
    if format_ != STORE_FORMATTED:
        raise FirmwareVariablesError("the variable store is not formatted")
    end = min(store + size, len(data))
    offset = _align4(store + STORE_HEADER_SIZE)
    while offset + header <= end:
        start_id, state = struct.unpack_from("<HB", data, offset)
        if start_id != VARIABLE_START_ID:
            break
        if header == AUTHENTICATED_HEADER:
            name_size, data_size = struct.unpack_from("<II", data, offset + 36)
            guid_at = offset + 44
        else:
            name_size, data_size = struct.unpack_from("<II", data, offset + 8)
            guid_at = offset + 16
        name_at = offset + header
        value_at = name_at + name_size
        if value_at + data_size > end:
            raise FirmwareVariablesError("a variable runs past the store")
        yield offset + 2, state, guid_at, name_at, value_at, data_size
        offset = _align4(value_at + data_size)


def _decoded(data: bytes, guid_at: int, name_at: int,
             value_at: int) -> tuple[uuid.UUID, str]:
    try:
        name = data[name_at:value_at].decode("utf-16-le").rstrip("\0")
    except UnicodeDecodeError as error:
        raise FirmwareVariablesError(
            "a variable name is not UTF-16") from error
    return uuid.UUID(bytes_le=data[guid_at:guid_at + 16]), name


def firmware_variables(data: bytes) -> dict[tuple[uuid.UUID, str], bytes]:
    """Every live variable in an OVMF variable store, by (vendor, name).

    Only the fully added copy of a variable counts; a copy caught in a
    deletion transition counts only when no fully added one exists, which is
    EDK2's own rule after an interrupted update.
    """
    added: dict[tuple[uuid.UUID, str], bytes] = {}
    transition: dict[tuple[uuid.UUID, str], bytes] = {}
    for _, state, guid_at, name_at, value_at, size in _records(data):
        if state not in LIVE_STATES:
            continue
        key = _decoded(data, guid_at, name_at, value_at)
        target = added if state == VAR_ADDED else transition
        target[key] = data[value_at:value_at + size]
    return {**transition, **added}


def load_option(data: bytes) -> tuple[bool, str]:
    """``(active, description)`` of one ``EFI_LOAD_OPTION``."""
    if len(data) < 8:
        raise FirmwareVariablesError("a boot option is truncated")
    attributes = struct.unpack_from("<I", data, 0)[0]
    end = 6
    while end + 1 < len(data) and data[end:end + 2] != b"\0\0":
        end += 2
    try:
        description = data[6:end].decode("utf-16-le")
    except UnicodeDecodeError as error:
        raise FirmwareVariablesError(
            "a boot option description is not UTF-16") from error
    return bool(attributes & LOAD_OPTION_ACTIVE), description


def hddp_states(data: bytes) -> list[int]:
    """The state-byte offsets of every live ``HDDP`` copy in a store."""
    return [
        state_at
        for state_at, state, guid_at, name_at, value_at, _ in _records(data)
        if state in LIVE_STATES
        and _decoded(data, guid_at, name_at, value_at)
        == (HDDP_VENDOR, HDDP_NAME)]


def without_hddp(data: bytes) -> tuple[bytes, int]:
    """A copy of *data* with every live ``HDDP`` copy deleted, and how many.

    Only those state bytes change, each ANDed with ``VAR_DELETED``; a store
    without the cache comes back byte-identical, so this is idempotent.
    Raises ``FirmwareVariablesError`` for anything that is not a store.
    """
    states = hddp_states(data)
    cleaned = bytearray(data)
    for state_at in states:
        cleaned[state_at] &= VAR_DELETED
    return bytes(cleaned), len(states)


def copy_without_hddp(source: Path, target: Path) -> int:
    """Write *source*'s store to *target* (mode 0600) without ``HDDP``.

    For a store carried into a boot: *source* is only read, so a retained
    input keeps its recorded hash.  The store is checked before *target* is
    touched, and a symlinked *target* is refused.  Returns how many cached
    copies were deleted.
    """
    cleaned, dropped = without_hddp(Path(source).read_bytes())
    descriptor = os.open(
        target, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, "wb") as stream:
        os.fchmod(stream.fileno(), 0o600)
        stream.write(cleaned)
    return dropped
