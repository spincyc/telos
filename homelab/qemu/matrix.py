"""The acceptance matrix (ADR 0056).

Stages, each of which either passes, fails, or says exactly what it is waiting
for. A stage that cannot run yet is reported as *pending* rather than skipped
quietly, because a matrix that silently shrinks is a matrix that reports green
while testing nothing.

    stage 1  firmware      UEFI comes up, finds no boot disk, tries PXE
    stage 2  boot-chain    the Controller serves the chain and the guest loads it
    stage 3  install       the real installer is driven to completion
    stage 4  activation    first boot fails closed, then starts DHCP
    stage 5  converge      Ansible converges, and a second run changes nothing

Stage 1 needs nothing but QEMU and OVMF and runs today. The rest need boot
artifacts that do not exist until the Archiso image is built, which needs root,
so they are pending by construction rather than by omission.

Everything here drives the guest through a pseudo-terminal. The installer's
serial console *is* the QEMU process's stdio, so the same driver that runs it as
a subprocess runs it in a virtual machine, and it cannot tell the difference.
That is what makes ADR 0058 hold in the lab as well as on metal.
"""

from __future__ import annotations

import os
import pty
import select
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path

import lab

# How long to let firmware run before deciding it is not going to say anything.
# OVMF reaches the PXE attempt in a second or two; this is generous so a loaded
# machine does not produce a spurious failure.
FIRMWARE_SECONDS = 25.0


@dataclass
class Outcome:
    stage: str
    state: str                       # "passed" | "failed" | "pending"
    detail: str = ""
    evidence: list[str] = field(default_factory=list)
    waiting_for: str = ""

    @property
    def ok(self) -> bool:
        return self.state != "failed"


def boot_and_listen(argv: list[str], seconds: float) -> str:
    """Boot a guest and return whatever it wrote to its serial console.

    A pseudo-terminal, not a pipe. Firmware and the installer both behave
    differently when their console is not a terminal -- OVMF writes nothing at
    all down a closed pipe -- so a pipe would test something other than what
    runs for real.
    """
    primary, secondary = pty.openpty()
    process = subprocess.Popen(argv, stdin=secondary, stdout=secondary,
                               stderr=subprocess.PIPE)
    os.close(secondary)

    collected = bytearray()
    deadline = time.time() + seconds
    try:
        while time.time() < deadline:
            ready, _, _ = select.select([primary], [], [], 0.5)
            if not ready:
                continue
            try:
                chunk = os.read(primary, 4096)
            except OSError:
                break
            if not chunk:
                break
            collected += chunk
    finally:
        process.kill()
        process.wait()
        os.close(primary)

    return collected.decode("utf8", "replace")


def strip_escapes(text: str) -> str:
    """Firmware draws with ANSI sequences; the assertions are about words."""
    out, index = [], 0
    while index < len(text):
        if text[index] == "\x1b":
            index += 1
            while index < len(text) and text[index] not in "ABCDHJKfhlmst":
                index += 1
            index += 1
            continue
        out.append(text[index])
        index += 1
    return "".join(out)


# --------------------------------------------------------------------------
# Stage 1: firmware
# --------------------------------------------------------------------------


def stage_firmware() -> Outcome:
    """The guest boots UEFI, finds nothing on its disk, and tries the network.

    This is the whole boot chain's first link, and it is worth its own stage:
    it proves the firmware is UEFI and not BIOS (ADR 0019), that the virtio
    disk is present and empty, and that the NIC is on the lab segment and the
    firmware will PXE from it. If this fails, nothing further can work, and
    every later failure would be misleading.
    """
    if not lab.available():
        return Outcome("firmware", "pending",
                       waiting_for="; ".join(lab.missing_requirements()))

    with lab.Lab() as bench:
        machine = bench.add(lab.Machine("firmware", disk_gib=8, listens=True))
        text = strip_escapes(boot_and_listen(bench.argv(machine), FIRMWARE_SECONDS))

    evidence = [line.strip() for line in text.splitlines() if line.strip()]

    if not evidence:
        return Outcome("firmware", "failed",
                       "the firmware wrote nothing to the serial console",
                       waiting_for="check that OVMF_CODE is a UEFI build and "
                                   "that -serial stdio is present")

    problems = []
    if "Start PXE over IPv4" not in text:
        problems.append("the firmware did not attempt PXE over IPv4, so either "
                        "the NIC is absent or network boot is disabled")
    if "failed to load Boot" not in text and "Not Found" not in text:
        problems.append("the firmware did not report an empty boot disk, which "
                        "it should on a freshly created image")

    if problems:
        return Outcome("firmware", "failed", "; ".join(problems), evidence[-8:])

    return Outcome("firmware", "passed",
                   "UEFI booted, found no boot disk, and attempted PXE over IPv4",
                   evidence[-4:])


# --------------------------------------------------------------------------
# Stages 2 to 5: pending until the boot artifacts exist
# --------------------------------------------------------------------------


# Where `bin/homelab-image` leaves a build. Overridable so a build kept
# somewhere else can be tested without moving it.
ARTIFACT_ROOT = Path(os.environ.get("HOMELAB_ARTIFACT_ROOT", "/tmp/homelab-image/out"))

# The netboot build mode produces these, not an ISO. Looking for the kernel by
# name rather than for "some file" means a half-finished build reads as absent
# instead of as ready.
REQUIRED_ARTIFACTS = ("vmlinuz-linux", "initramfs-linux.img")


def missing_artifacts(root: Path = ARTIFACT_ROOT) -> list[str]:
    if not root.is_dir():
        return list(REQUIRED_ARTIFACTS)
    present = {path.name for path in root.rglob("*") if path.is_file()}
    return [name for name in REQUIRED_ARTIFACTS if name not in present]


def _pending(stage: str, detail: str) -> Outcome:
    missing = missing_artifacts()
    if missing:
        return Outcome(stage, "pending", detail,
                       waiting_for=f"a built image ({', '.join(missing)} not under "
                                   f"{ARTIFACT_ROOT}). Stage it with "
                                   f"bin/homelab-image, then build it: mkarchiso "
                                   f"needs root, so nothing here escalates for you")
    return Outcome(stage, "pending", detail,
                   waiting_for="this stage is not implemented yet")


def stage_boot_chain() -> Outcome:
    return _pending(
        "boot-chain",
        "a Controller on the segment answers DHCP, serves iPXE over TFTP, and "
        "the guest chainloads the installer environment over HTTP")


def stage_install() -> Outcome:
    return _pending(
        "install",
        "the genuine installer is driven over the guest's serial console, "
        "including typing the target disk's serial to authorize the erase")


def stage_activation() -> Outcome:
    return _pending(
        "activation",
        "first boot on a segment with another DHCP server refuses to start, "
        "and on a clear segment starts dnsmasq and nginx together")


def stage_converge() -> Outcome:
    return _pending(
        "converge",
        "Ansible converges the installed Controller, and a second run reports "
        "no changes")


STAGES = (stage_firmware, stage_boot_chain, stage_install, stage_activation,
          stage_converge)


# --------------------------------------------------------------------------


def run(stages=STAGES) -> list[Outcome]:
    return [stage() for stage in stages]


def report(outcomes: list[Outcome]) -> list[str]:
    rule = "=" * 72
    lines = [rule, "HOMELAB ACCEPTANCE MATRIX", rule, ""]

    for outcome in outcomes:
        mark = {"passed": "ok  ", "failed": "FAIL", "pending": "wait"}[outcome.state]
        lines.append(f"  [{mark}] {outcome.stage:<12} {outcome.detail}")
        for line in outcome.evidence:
            lines.append(f"           | {line}")
        if outcome.waiting_for:
            lines.append(f"           needs {outcome.waiting_for}")
        lines.append("")

    passed = sum(1 for outcome in outcomes if outcome.state == "passed")
    failed = sum(1 for outcome in outcomes if outcome.state == "failed")
    pending = sum(1 for outcome in outcomes if outcome.state == "pending")
    lines.append(f"  {passed} passed, {failed} failed, {pending} pending "
                 f"of {len(outcomes)} stages")
    if pending:
        lines.append("  Pending stages are reported, not skipped: the matrix is "
                     "not green until they run.")
    lines.append(rule)
    return lines


def main(argv=None) -> int:
    import argparse
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--stage", action="append",
                        help="run only the named stage; repeatable")
    arguments = parser.parse_args(argv)

    stages = STAGES
    if arguments.stage:
        wanted = set(arguments.stage)
        stages = tuple(stage for stage in STAGES
                       if stage.__name__.removeprefix("stage_").replace("_", "-")
                       in wanted)
        if not stages:
            print(f"no such stage: {', '.join(sorted(wanted))}")
            return 2

    outcomes = run(stages)
    print("\n".join(report(outcomes)))
    return 0 if all(outcome.ok for outcome in outcomes) else 1


if __name__ == "__main__":
    raise SystemExit(main())
