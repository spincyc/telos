"""Hardware facts, behind a seam the tests can substitute.

The installer needs to know what disks exist, what network interfaces exist, and
what mode the firmware is in. None of that is available to a unit test, and none
of it should be discovered by code that also decides what to erase.

So collection is separated from judgement. `SystemCollector` reads the real
machine; `FixtureCollector` replays output captured from real machines. The
logic in preflight.py sees only the dataclasses below and never knows which it
is talking to.

The fixtures are captured, not invented. An invented fixture encodes what I
assumed lsblk prints, and then the tests confirm my assumption rather than the
behaviour.
"""

from __future__ import annotations

import json
import subprocess
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Protocol

GIB = 1024 ** 3


@dataclass(frozen=True)
class Disk:
    path: str
    model: str
    serial: str
    size_bytes: int
    removable: bool
    rotational: bool
    transport: str

    @property
    def size_gib(self) -> float:
        return self.size_bytes / GIB

    def describe(self) -> str:
        """One line an operator can check against the label on the drive."""
        serial = self.serial or "(no serial reported)"
        return f"{self.path}  {self.size_gib:,.0f} GiB  {self.model or 'unknown model'}  serial {serial}"


@dataclass(frozen=True)
class Interface:
    name: str
    mac: str
    carrier: bool
    speed_mbps: int | None
    wireless: bool

    def describe(self) -> str:
        link = "link up" if self.carrier else "no link"
        speed = f"{self.speed_mbps} Mb/s" if self.speed_mbps and self.speed_mbps > 0 else "speed unknown"
        return f"{self.name}  {self.mac}  {link}, {speed}"


@dataclass(frozen=True)
class Firmware:
    uefi: bool
    secure_boot: str | None
    tpm2: bool

    def describe(self) -> str:
        mode = "UEFI" if self.uefi else "legacy BIOS / CSM"
        secure = self.secure_boot or "unknown"
        return f"{mode}; Secure Boot {secure}; TPM 2.0 {'present' if self.tpm2 else 'absent'}"


class Collector(Protocol):
    def disks(self) -> list[Disk]: ...
    def interfaces(self) -> list[Interface]: ...
    def firmware(self) -> Firmware: ...


# --------------------------------------------------------------------------
# Parsing, shared by both collectors so a fixture exercises the real parser
# --------------------------------------------------------------------------


def parse_lsblk(payload: dict) -> list[Disk]:
    """Turn `lsblk --json --bytes` output into Disk records.

    Only whole disks. Partitions, loop devices and device-mapper nodes are not
    installation targets and offering one would be a bug with permanent
    consequences.
    """
    disks: list[Disk] = []
    for entry in payload.get("blockdevices", []):
        if entry.get("type") != "disk":
            continue
        disks.append(Disk(
            path=entry.get("path") or f"/dev/{entry.get('name', '')}",
            model=(entry.get("model") or "").strip(),
            serial=(entry.get("serial") or "").strip(),
            size_bytes=int(entry.get("size") or 0),
            removable=bool(entry.get("rm")),
            rotational=bool(entry.get("rota")),
            transport=(entry.get("tran") or "").strip(),
        ))
    return disks


def parse_interfaces(entries: list[dict]) -> list[Interface]:
    result: list[Interface] = []
    for entry in entries:
        speed = entry.get("speed")
        try:
            speed = int(speed)
        except (TypeError, ValueError):
            speed = None
        result.append(Interface(
            name=entry["name"],
            mac=(entry.get("mac") or "").strip().lower(),
            carrier=bool(entry.get("carrier")),
            speed_mbps=speed if speed and speed > 0 else None,
            wireless=bool(entry.get("wireless")),
        ))
    return result


# --------------------------------------------------------------------------
# The real machine
# --------------------------------------------------------------------------


class SystemCollector:
    """Reads the running machine. Never used by a unit test."""

    def __init__(self, sysfs: Path = Path("/sys")) -> None:
        self.sysfs = sysfs

    def disks(self) -> list[Disk]:
        output = subprocess.run(
            ["lsblk", "--json", "--bytes", "-o",
             "NAME,PATH,TYPE,SIZE,MODEL,SERIAL,ROTA,RM,TRAN"],
            capture_output=True, text=True, check=True,
        ).stdout
        return parse_lsblk(json.loads(output))

    def interfaces(self) -> list[Interface]:
        entries = []
        net = self.sysfs / "class/net"
        for path in sorted(net.iterdir()) if net.is_dir() else []:
            name = path.name
            if name == "lo":
                continue
            entries.append({
                "name": name,
                # The permanent address, not the current one: a bonded or
                # spoofed interface reports a different `address`, and ADR 0050
                # pins the identity to the hardware.
                "mac": _read(path / "address"),
                "carrier": _read(path / "carrier") == "1",
                "speed": _read(path / "speed"),
                "wireless": (path / "wireless").exists() or (path / "phy80211").exists(),
            })
        return parse_interfaces(entries)

    def firmware(self) -> Firmware:
        uefi = (self.sysfs / "firmware/efi").is_dir()
        secure_boot = None
        if uefi:
            # The SecureBoot EFI variable's last byte is 1 when enabled.
            for candidate in (self.sysfs / "firmware/efi/efivars").glob("SecureBoot-*"):
                try:
                    secure_boot = "enabled" if candidate.read_bytes()[-1] else "disabled"
                except OSError:
                    secure_boot = None
                break
        tpm2 = any((self.sysfs / "class/tpm").glob("tpm*")) if (self.sysfs / "class/tpm").is_dir() else False
        return Firmware(uefi=uefi, secure_boot=secure_boot, tpm2=tpm2)


def _read(path: Path) -> str:
    try:
        return path.read_text().strip()
    except OSError:
        return ""


# --------------------------------------------------------------------------
# Captured machines, for tests
# --------------------------------------------------------------------------


class FixtureCollector:
    """Replays a captured machine. The parsers above are the real ones."""

    def __init__(self, payload: dict) -> None:
        self.payload = payload

    @classmethod
    def from_file(cls, path: Path) -> "FixtureCollector":
        return cls(json.loads(Path(path).read_text()))

    def disks(self) -> list[Disk]:
        return parse_lsblk(self.payload["lsblk"])

    def interfaces(self) -> list[Interface]:
        return parse_interfaces(self.payload["interfaces"])

    def firmware(self) -> Firmware:
        return Firmware(**self.payload["firmware"])


def capture(collector: Collector) -> dict:
    """Serialise a live machine into a fixture. Used to record new fixtures."""
    return {
        "lsblk": {"blockdevices": [
            {"path": d.path, "type": "disk", "model": d.model, "serial": d.serial,
             "size": d.size_bytes, "rm": d.removable, "rota": d.rotational,
             "tran": d.transport}
            for d in collector.disks()]},
        "interfaces": [
            {"name": i.name, "mac": i.mac, "carrier": i.carrier,
             "speed": i.speed_mbps, "wireless": i.wireless}
            for i in collector.interfaces()],
        "firmware": asdict(collector.firmware()),
    }
