#!/usr/bin/env python3
"""Read-only proof that a Controller image actually holds an installation.

Nothing in this repository could tell a *created* Controller image from an
*installed* one.  ``bootstrap_dc.status`` called a freshly created,
never-installed 197,888-byte qcow2 ``ready``; ``manifest.json`` records only
creation metadata; and ``ControllerOverlay.prepare`` proves the canonical was
not *mutated*, which is an immutability proof and not an installed-OS proof.
The first thing that actually noticed was ``DisposableBootDisk.prepare`` in
``automated_controller.py``, where ``sfdisk --json`` on an unpartitioned image
exits 1 and surfaces as a ``CalledProcessError`` three layers from the cause.

The probe here is the cheapest honest one, and it looks for exactly what
``automated_controller`` already looks for: a GPT carrying exactly one EFI
system partition, because that is what ``homelab/seed/install-controller``
writes.  It costs one ``qemu-img info``, one ``qemu-img map`` and -- only when
something has actually been written -- a 1 MiB extraction of the image's head.
It never opens the image for writing, never needs root, and never mounts
anything, so it is safe to run from ``status`` and safe to run against the
acceptance canonical while its immutability fence still applies.
"""

from __future__ import annotations

import json
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path

#: The GPT type GUID of an EFI system partition. Same constant as
#: ``automated_controller.EFI_SYSTEM_GUID``; repeated rather than imported
#: because ``automated_controller`` imports ``simulation_overlay``, which
#: imports this module, and a shared constant is not worth an import cycle.
EFI_SYSTEM_GUID = "c12a7328-f81f-11d2-ba4b-00a0c93ec93b"

#: How much of the image head to extract. The protective MBR, the primary GPT
#: header and its entry array all live in the first 34 sectors; 1 MiB is the
#: first partition's start on every layout this repository writes and keeps the
#: read to a single allocated cluster run.
PROBE_BYTES = 1 << 20


class ControllerImageError(RuntimeError):
    """The image could not be inspected, or it is not an installed Controller."""


@dataclass(frozen=True)
class ControllerImageState:
    """What a read-only look at a Controller image can honestly say."""

    installed: bool
    reason: str
    virtual_bytes: int
    allocated_bytes: int
    partitions: int
    esp_partitions: int

    def summary(self) -> str:
        state = "installed" if self.installed else "not installed"
        return f"{state}: {self.reason}"

    def record(self) -> dict[str, object]:
        """The receipt-shaped form: facts only, no paths and no secrets."""
        return {
            "installed": self.installed,
            "reason": self.reason,
            "virtual_bytes": self.virtual_bytes,
            "allocated_bytes": self.allocated_bytes,
            "partitions": self.partitions,
            "esp_partitions": self.esp_partitions,
        }


def _tool(argv: list[str], *, check: bool = True) -> subprocess.CompletedProcess:
    try:
        return subprocess.run(argv, check=check, capture_output=True, text=True)
    except FileNotFoundError as error:
        raise ControllerImageError(
            f"{argv[0]} is required to inspect a Controller image") from error
    except subprocess.CalledProcessError as error:
        raise ControllerImageError(
            f"{argv[0]} could not read the image: "
            f"{(error.stderr or '').strip() or error}") from error


def _json(result: subprocess.CompletedProcess, tool: str) -> object:
    try:
        return json.loads(result.stdout or "")
    except (TypeError, json.JSONDecodeError) as error:
        raise ControllerImageError(
            f"{tool} did not return readable JSON") from error


def image_info(disk: Path, image_format: str = "qcow2") -> dict:
    """``qemu-img info`` as a mapping, with the format pinned by the caller."""
    result = _tool(
        ["qemu-img", "info", "--output=json", "-f", image_format, str(disk)])
    info = _json(result, "qemu-img info")
    if not isinstance(info, dict):
        raise ControllerImageError("qemu-img info did not return an object")
    return info


def allocated_bytes(disk: Path, image_format: str = "qcow2") -> int:
    """Bytes the image has actually written, from ``qemu-img map``.

    A never-installed image maps as one unallocated, all-zero extent, so this
    is zero, and that alone settles the question without extracting anything.
    """
    result = _tool(
        ["qemu-img", "map", "--output=json", "-f", image_format, str(disk)])
    extents = _json(result, "qemu-img map")
    if not isinstance(extents, list):
        raise ControllerImageError("qemu-img map did not return a list")
    total = 0
    for extent in extents:
        if isinstance(extent, dict) and extent.get("data"):
            try:
                total += int(extent.get("length", 0))
            except (TypeError, ValueError) as error:
                raise ControllerImageError(
                    "qemu-img map reported an unreadable extent") from error
    return total


def partition_table(
    disk: Path, image_format: str, virtual_bytes: int,
) -> dict | None:
    """The image's partition table, read without writing to the image.

    ``sfdisk`` needs a raw view, and a *truncated* raw view is worse than
    none: a 1 MiB file makes the GPT header's last-usable-LBA exceed the
    device, ``sfdisk`` falls back to the protective MBR, and an installed
    image reports a single DOS partition of type ``ee``. Restoring the sparse
    tail costs no blocks and makes the primary GPT validate normally. The
    backup GPT is genuinely absent from this view, which ``sfdisk`` reports on
    stderr and recovers from by using the primary -- exactly the right
    behaviour here, where the copy is a throwaway and is never written back.
    """
    with tempfile.TemporaryDirectory(prefix="telos-image-probe-") as name:
        head = Path(name) / "head.raw"
        _tool([
            "qemu-img", "dd", "-f", image_format, "-O", "raw",
            f"bs={PROBE_BYTES}", "count=1",
            f"if={disk}", f"of={head}",
        ])
        if not head.is_file():
            raise ControllerImageError(
                "qemu-img dd produced no image head to inspect")
        if virtual_bytes > head.stat().st_size:
            with head.open("r+b") as stream:
                stream.truncate(virtual_bytes)
        result = _tool(["sfdisk", "--json", str(head)], check=False)
        if result.returncode != 0:
            return None
        table = _json(result, "sfdisk --json")
        if not isinstance(table, dict):
            raise ControllerImageError("sfdisk did not return an object")
        found = table.get("partitiontable")
        return found if isinstance(found, dict) else None


def _esp_geometry_is_sane(partition: dict, sector: int, virtual: int) -> bool:
    """The geometry check ``automated_controller._esp_offset`` makes."""
    try:
        start = int(partition["start"])
        size = int(partition.get("size", 0))
    except (KeyError, TypeError, ValueError):
        return False
    return (
        sector > 0 and start > 0 and size > 0
        and start * sector < virtual
        and (start + size) * sector <= virtual
    )


def probe(disk: Path, *, image_format: str = "qcow2") -> ControllerImageState:
    """Say whether this image holds a Controller installation, and why."""
    disk = Path(disk)
    if not disk.is_file() or disk.is_symlink():
        raise ControllerImageError(
            f"a Controller image must be a regular, non-symlink file: {disk}")
    info = image_info(disk, image_format)
    reported = str(info.get("format", image_format))
    if reported != image_format:
        raise ControllerImageError(
            f"{disk} is a {reported} image, not {image_format}")
    try:
        virtual = int(info["virtual-size"])
    except (KeyError, TypeError, ValueError) as error:
        raise ControllerImageError(
            "qemu-img info did not report a virtual size") from error
    written = allocated_bytes(disk, image_format)
    if written == 0:
        return ControllerImageState(
            False,
            "the image is entirely unallocated; nothing has ever been "
            "written to it",
            virtual, 0, 0, 0)
    table = partition_table(disk, image_format, virtual)
    if table is None:
        return ControllerImageState(
            False,
            "the image holds data but carries no readable partition table",
            virtual, written, 0, 0)
    label = str(table.get("label", "")).lower()
    partitions = [
        entry for entry in (table.get("partitions") or [])
        if isinstance(entry, dict)
    ]
    esps = [
        entry for entry in partitions
        if str(entry.get("type", "")).lower() == EFI_SYSTEM_GUID
    ]
    if label != "gpt":
        return ControllerImageState(
            False,
            f"the image carries a {label or 'unknown'} partition table, not "
            "the GPT the installer writes",
            virtual, written, len(partitions), len(esps))
    if len(esps) != 1:
        return ControllerImageState(
            False,
            f"the GPT holds {len(esps)} EFI system partitions; an installed "
            "Controller has exactly one",
            virtual, written, len(partitions), len(esps))
    try:
        sector = int(table.get("sectorsize", 512))
    except (TypeError, ValueError):
        sector = 0
    if not _esp_geometry_is_sane(esps[0], sector, virtual):
        return ControllerImageState(
            False,
            "the EFI system partition's geometry does not fit the image",
            virtual, written, len(partitions), 1)
    return ControllerImageState(
        True,
        f"GPT with one EFI system partition and {written} bytes written",
        virtual, written, len(partitions), 1)


def assert_installed(
    disk: Path, *, subject: str, remedy: str, image_format: str = "qcow2",
) -> ControllerImageState:
    """Refuse to proceed unless ``disk`` really holds an installed Controller.

    Fail-closed on purpose, and on every path: an image that cannot be
    inspected is refused exactly like one that is provably blank, because the
    caller is about to spend an operator's time -- or an operator's typed
    credential -- on a guest that cannot boot.
    """
    state = probe(disk, image_format=image_format)
    if not state.installed:
        raise ControllerImageError(
            f"{subject} is not an installed Controller image: {state.reason}. "
            f"{remedy}")
    return state
