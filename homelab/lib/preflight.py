"""Preflight: what the machine is, what may be offered, what stops the install.

ADR 0004 makes the preflight summary the authorization boundary. Everything
here runs before a single byte is written, and its job is to narrow an operator's
choices to the ones that are safe and then state, plainly, what is about to be
destroyed.

Two kinds of finding:

  * A **refusal** stops the installation. The machine cannot host this profile
    and no confirmation makes it possible.
  * An **exclusion** removes one candidate from a list, with a reason the
    operator can read, so they can see that a disk was considered and rejected
    rather than silently missing.

Nothing here touches a disk. It reads facts from a collector and returns
records.
"""

from __future__ import annotations

from dataclasses import dataclass

from hardware import Collector, Disk, Firmware, Interface, GIB

# ADR 0051: the Controller layout is a 2 GiB ESP plus the LUKS2 container.
# 64 GiB is not a computed minimum; it is a floor below which the machine is
# not a plausible Controller and the operator has almost certainly selected the
# wrong device.
MINIMUM_DISK_GIB = 64


@dataclass(frozen=True)
class Candidate:
    """Something the operator may choose, or may not, with the reason why."""
    item: object
    eligible: bool
    reason: str = ""


@dataclass(frozen=True)
class Preflight:
    firmware: Firmware
    disks: list[Candidate]
    interfaces: list[Candidate]
    refusals: list[str]

    @property
    def eligible_disks(self) -> list[Disk]:
        return [c.item for c in self.disks if c.eligible]

    @property
    def eligible_interfaces(self) -> list[Interface]:
        return [c.item for c in self.interfaces if c.eligible]

    @property
    def may_proceed(self) -> bool:
        return not self.refusals and bool(self.eligible_disks)


def assess_disk(disk: Disk) -> Candidate:
    """Decide whether a disk may be offered as an installation target."""
    # The installer is booted from removable media. Offering the stick it is
    # running from is the single most destructive mistake available here, and no
    # amount of confirmation text makes it acceptable to list it.
    if disk.removable or disk.transport == "usb":
        return Candidate(disk, False, "removable device --- this may be the installer's own boot medium")

    # ADR 0058 confirms the wipe by having the operator type the disk's serial.
    # A disk whose serial cannot be read therefore cannot be confirmed, so it
    # must not be offered. The two decisions interlock.
    if not disk.serial:
        return Candidate(disk, False, "no serial reported --- it could not be confirmed at the authorization prompt")

    if disk.size_gib < MINIMUM_DISK_GIB:
        return Candidate(disk, False, f"{disk.size_gib:,.0f} GiB is below the {MINIMUM_DISK_GIB} GiB minimum")

    return Candidate(disk, True)


def assess_interface(interface: Interface) -> Candidate:
    """Decide whether an interface may be offered as the managed interface."""
    # ADR 0050 and the bootstrap assumption: bare-metal network installation is
    # wired. A Controller serving DHCP over wireless is not a supported design.
    if interface.wireless:
        return Candidate(interface, False, "wireless --- the managed network is wired only")
    if not interface.mac:
        return Candidate(interface, False, "no permanent MAC address --- it cannot be pinned to a stable name")
    # No carrier is not disqualifying. The Controller is frequently provisioned
    # on one network and relocated to another while powered off (ADR 0010), so
    # the managed interface may legitimately be unplugged right now. First-boot
    # activation checks carrier; preflight only notes it.
    return Candidate(interface, True, "" if interface.carrier else "no link detected at present")


def assess(collector: Collector, profile: str) -> Preflight:
    """Collect the machine's facts and judge them against the profile."""
    firmware = collector.firmware()
    refusals: list[str] = []

    # ADR 0019: the Controller profile is UEFI only. Refuse before offering any
    # destructive action, not after collecting a full set of answers.
    if not firmware.uefi:
        refusals.append(
            "This machine booted in legacy BIOS / CSM mode. The Controller profile "
            "requires UEFI (ADR 0019). Change the firmware boot mode and start again."
        )

    disks = [assess_disk(disk) for disk in collector.disks()]
    interfaces = [assess_interface(nic) for nic in collector.interfaces()]

    if not any(candidate.eligible for candidate in disks):
        refusals.append(
            "No disk on this machine may be used as an installation target. "
            "Each disk found is listed above with the reason it was excluded."
        )
    if profile == "controller" and not any(c.eligible for c in interfaces):
        refusals.append(
            "No wired network interface with a permanent MAC address was found. "
            "A Controller needs one to serve DHCP and DNS (ADR 0050)."
        )

    return Preflight(firmware=firmware, disks=disks, interfaces=interfaces, refusals=refusals)


# --------------------------------------------------------------------------
# The summary that ADR 0004 makes the authorization boundary
# --------------------------------------------------------------------------


def summary_lines(
    *,
    preflight: Preflight,
    profile: str,
    hostname: str,
    target: Disk,
    interface: Interface | None,
    network_rows: list[tuple[str, str]] | None,
    development_proof: bool,
) -> list[str]:
    """The complete text shown immediately before the confirmation prompt.

    Everything the operator needs to decide is here, and the destructive fact is
    stated in its own block rather than buried in a list of settings.
    """
    lines: list[str] = []
    rule = "=" * 72

    lines.append(rule)
    lines.append("PREFLIGHT SUMMARY --- read this before authorizing anything")
    lines.append(rule)
    lines.append("")
    lines.append(f"  Profile          {profile}")
    lines.append(f"  Hostname         {hostname}  ({hostname}.home.arpa)")
    lines.append(f"  Firmware         {preflight.firmware.describe()}")
    if interface is not None:
        lines.append(f"  Managed NIC      {interface.describe()}")
        lines.append(f"                   will be pinned to the stable name lan0")
    lines.append("")

    if network_rows:
        lines.append("  Managed network")
        for label, value in network_rows:
            lines.append(f"    {label:<22} {value}")
        lines.append("")

    lines.append(rule)
    lines.append("THE FOLLOWING DISK WILL BE COMPLETELY ERASED")
    lines.append(rule)
    lines.append("")
    lines.append(f"    Device   {target.path}")
    lines.append(f"    Model    {target.model or 'unknown'}")
    lines.append(f"    Serial   {target.serial}")
    lines.append(f"    Size     {target.size_gib:,.0f} GiB")
    lines.append("")
    lines.append("    Check that serial against the label on the drive itself.")
    lines.append("    Everything on this disk will be destroyed and is not recoverable.")
    lines.append("")

    if development_proof:
        lines.append(rule)
        lines.append("DEVELOPMENT-PROOF MODE --- NOT A PRODUCTION INSTALLATION")
        lines.append(rule)
        lines.append("")
        lines.append("    Authenticated boot is NOT being tested (ADR 0043).")
        lines.append("    LUKS2 must be unlocked by hand at every boot.")
        lines.append("    This installation is disposable. Put no real data on it.")
        lines.append("")

    return lines


def excluded_lines(candidates: list[Candidate], heading: str) -> list[str]:
    """Show what was considered and rejected, so nothing is silently absent."""
    rejected = [c for c in candidates if not c.eligible]
    if not rejected:
        return []
    lines = [f"  {heading} not offered:"]
    for candidate in rejected:
        lines.append(f"    {candidate.item.describe()}")
        lines.append(f"        excluded: {candidate.reason}")
    return lines
