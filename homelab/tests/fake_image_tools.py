"""A fake ``qemu-img``/``sfdisk`` pair that models the real image probe.

``controller_image`` asks four questions of two real tools: what an image's
format and virtual size are (``qemu-img info``), how much of it has been
written (``qemu-img map``), what its first megabyte contains (``qemu-img dd``)
and what partition table that megabyte holds (``sfdisk --json``). Tests that
patched ``subprocess.run`` with a stub returning ``CompletedProcess(argv, 0)``
and no stdout could not answer any of them.

This models the tools instead of patching the probe out. A "disk" here is an
ordinary file whose leading bytes say whether it is an installed Controller,
and every tool answers consistently from that one fact -- so a test that seeds
an instance really does exercise the production code path that inspects the
source image, and a regression in that path fails a test rather than passing
through a stubbed seam.
"""

from __future__ import annotations

import json
import re
import subprocess
from pathlib import Path

#: Leading bytes that make a fake image read as an installed Controller.
INSTALLED = b"TELOS-FAKE-INSTALLED-CONTROLLER-IMAGE"
#: Leading bytes of a created-but-never-installed image.
BLANK = b"TELOS-FAKE-BLANK-CONTROLLER-IMAGE"

#: The declared 80 GiB virtual size the real canonical carries.
VIRTUAL_BYTES = 85899345920
#: How much an installed image reports as written. Any nonzero value takes the
#: probe past its cheap "entirely unallocated" answer and on to the GPT read.
WRITTEN_BYTES = 131072

EFI_SYSTEM_GUID = "C12A7328-F81F-11D2-BA4B-00A0C93EC93B"


def installed_image(path: Path, note: bytes = b"") -> Path:
    """Write a file that every fake tool reports as an installed Controller."""
    path = Path(path)
    path.write_bytes(INSTALLED + note)
    return path


def blank_image(path: Path, note: bytes = b"") -> Path:
    """Write a file that reads as created-but-never-installed."""
    path = Path(path)
    path.write_bytes(BLANK + note)
    return path


def _looks_installed(path: Path) -> bool:
    try:
        with Path(path).open("rb") as stream:
            return stream.read(len(INSTALLED)) == INSTALLED
    except OSError:
        return False


def _value(argv: list[str], prefix: str) -> str | None:
    for part in argv:
        if part.startswith(prefix):
            return part[len(prefix):]
    return None


def _done(argv, stdout: str = "", returncode: int = 0):
    return subprocess.CompletedProcess(argv, returncode, stdout, "")


def image_tool(argv, **_kwargs) -> subprocess.CompletedProcess:
    """Answer as the real ``qemu-img``/``sfdisk`` would for these images."""
    argv = [str(part) for part in argv]
    tool = Path(argv[0]).name
    if tool == "sfdisk" and "--json" in argv:
        head = Path(argv[-1])
        if not _looks_installed(head):
            return _done(argv, "", 1)
        return _done(argv, json.dumps({"partitiontable": {
            "label": "gpt",
            "device": str(head),
            "unit": "sectors",
            "sectorsize": 512,
            "partitions": [
                {"node": f"{head}1", "start": 2048, "size": 2097152,
                 "type": EFI_SYSTEM_GUID, "name": "EFI System"},
                {"node": f"{head}2", "start": 2099200, "size": 165670912,
                 "type": "0FC63DAF-8483-4772-8E79-3D69D8477DE4",
                 "name": "Arch Linux"},
            ],
        }}))
    if tool != "qemu-img":
        return _done(argv)
    verb = argv[1] if len(argv) > 1 else ""
    if verb == "info":
        target = Path(argv[-1])
        size = target.stat().st_size if target.is_file() else 0
        return _done(argv, json.dumps({
            "format": "qcow2",
            "virtual-size": VIRTUAL_BYTES,
            "actual-size": size,
            "filename": str(target),
        }))
    if verb == "map":
        target = Path(argv[-1])
        if not _looks_installed(target):
            return _done(argv, json.dumps([{
                "start": 0, "length": VIRTUAL_BYTES, "depth": 0,
                "present": False, "zero": True, "data": False,
                "compressed": False,
            }]))
        return _done(argv, json.dumps([
            {"start": 0, "length": WRITTEN_BYTES, "depth": 0, "present": True,
             "zero": False, "data": True, "compressed": False, "offset": 0},
            {"start": WRITTEN_BYTES, "length": VIRTUAL_BYTES - WRITTEN_BYTES,
             "depth": 0, "present": False, "zero": True, "data": False,
             "compressed": False},
        ]))
    if verb == "dd":
        source = _value(argv, "if=")
        destination = _value(argv, "of=")
        if source is None or destination is None:
            return _done(argv, "", 1)
        content = (
            Path(source).read_bytes() if Path(source).is_file() else b"")
        Path(destination).write_bytes(content)
        return _done(argv)
    if verb in {"create", "convert"}:
        # ``create -f qcow2 FILE SIZE`` puts the size last; ``create -b BACKING
        # OVERLAY`` and ``convert SRC DST`` put the destination there.
        tail = argv[-1]
        destination = Path(
            argv[-2] if re.fullmatch(r"[0-9]+[KMGTPkmgtp]?", tail)
            else tail)
        # ``create -b BACKING`` and ``convert SRC DST`` both produce an image
        # whose *content* is the source's, which is what makes a seeded
        # instance inherit the source's installed-ness the way a real one does.
        backing = None
        if "-b" in argv:
            backing = Path(argv[argv.index("-b") + 1])
        elif verb == "convert" and len(argv) >= 2:
            candidate = Path(argv[-2])
            if candidate.is_file():
                backing = candidate
        if backing is not None and backing.is_file():
            destination.write_bytes(backing.read_bytes())
        else:
            destination.write_bytes(BLANK)
        return _done(argv)
    return _done(argv)
