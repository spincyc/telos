#!/usr/bin/env python3
"""Gate-12 repeat driver: run the sealed-input lifecycle twice and compare.

Gate 12 (``homelab/WORKSTATION-FACTORY-STATE.md``) requires running the
complete sealed-input lifecycle at least twice from destroyed disposable state
and comparing the receipts.  The comparator already existed
(:mod:`factory_verify`); the aggregate driver that produces two comparable
receipts did not, and that is what this module is.

Why an aggregate driver is needed at all
----------------------------------------
No phase bundle can ever render all sixteen acceptance checks, and this is a
property of the phases rather than a defect in any of them.  Measured against
real retained evidence, the newest live phase bundle renders
``NOT-RUN {'pass': 8, 'fail': 0, 'not_run': 8}``: one phase installs one
operating system, so it can honestly claim neither an install ORDER across both
nor BOTH systems' logins, and three further measurements
(``host_network_changes``, ``optional_storage_absence_nonblocking``,
``artifact_scan``) belong to no phase runner at all.  A phase also records the
narrower ``"observed"`` pass vocabulary, which ``factory_verify`` renders as
``run_status.scope: "phase"``.

So this driver assembles ONE aggregate evidence directory per iteration out of
the phase bundles the lifecycle produced:

* it CONCATENATES ``install_order`` across the Windows and Arch phases into a
  single list, which is the only way check 11 ("Windows was installed before
  Arch") can render anything but NOT-RUN;
* it draws the four measurements no phase records from three sibling producer
  modules through a deliberately thin adapter seam (:func:`bind_producers`);
* it composes the union through ``factory_runner.measurement_block``, which
  refuses an unknown key, so the assembled block can never widen past the ten
  pinned ``MEASUREMENT_KEYS``; and
* it records ``status: "pass"`` -- the aggregate vocabulary -- only when that
  union is genuinely complete and every phase passed.  An incomplete union
  stays ``"observed"``, so an absent measurement stays NOT-RUN in the receipt
  and is never promoted.

Nothing here relaxes ``factory_verify.ALLOWED_EVIDENCE``
------------------------------------------------------
That whitelist is a fail-closed security surface, and loosening it is the
riskier change: it is the only thing standing between "a file appeared in the
evidence directory" and "the receipt passed anyway".  Measured today, the
dual-boot, identity and recovery bundles all FAIL check 2 because
``boot1-serial.log``, ``boot2-serial.log``, ``dualboot-events.jsonl`` and
``recovery-evidence.jsonl`` are not in it.

This driver therefore RE-RETAINS instead of widening.  Phase artifacts whose
names ``ALLOWED_EVIDENCE`` already accepts are merged into the aggregate
evidence root (redacted and size-bounded exactly as ``factory_runner``
retains); every other phase artifact is re-retained under
``phases/<phase>/<name>``, a working subdirectory that ``verify_run`` accepts
structurally and NAMES in the receipt.  That does not make the re-retention
side permissive: this module keeps its OWN fail-closed table
(:func:`evidence_disposition`), and an artifact name it does not recognise
raises :class:`RepeatError` rather than being copied anywhere.  A name has to
be understood by one of the two tables to survive; nothing is silently
accepted by either.

Live evidence and test boundary
-------------------------------
On 2026-10-01 the live driver completed two six-phase lifecycles in
``20261001T153726Z-2517176-repeat``.  Their receipts agreed, with no retries,
but failed the artifact scan and release-set checks.  Subsequent fixes
corrected the dotted-netmask scan and release-root resolution; rejudging the
old evidence cannot prove the later WinPE IKE suppression or firmware fix.
Both old iterations also failed gate 4 on an unapproved UDP 500 flow.

Gate 12 therefore requires a passing embedded gate-4 audit in every
iteration, separately from the verifier's sixteen-check API.  Agreement on
the same failing or unproven prerequisite can never close the repeat gate.
The fixture tests cover assembly, retention, verification, comparison and
this prerequisite, but only a new live twice-through can prove changed
lifecycle behavior.  :func:`controller_image_problem` still probes the real
canonical disk and refuses a blank or uninspectable image.

The live driver pins the selected set, current media seal and verified Samba
repair library/receipt pair before any phase. Each payload checks the expected
pair while staging; each iteration retains it in the compared evidence. A
coherent cache replacement or reseal during the repeat is a hard failure.

``--reuse-iteration`` revalidates one complete accepted aggregate and runs
the remaining cycles fresh under exactly its input pin. It never rewrites
the original repeat or upgrades a failed cycle. Raw host-network snapshots
are bounded private diagnostics beside each new aggregate, outside the
publishable evidence allowlist.

The seam keeps the live process layer thin:
:meth:`LifecycleDriver.run_phase` returns a bundle path and
:meth:`LifecycleDriver.destroy` removes disposable state, and everything else
in :func:`run_iteration` and :func:`repeat` is driver-agnostic and tested with
a fake.
"""

from __future__ import annotations

import argparse
import ctypes
import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Iterable, Sequence

try:
    from . import (
        factory_runner, factory_verify, simulation_evidence,
        windows_install_run)
except ImportError:  # Direct execution from homelab/vm.
    import factory_runner  # type: ignore[no-redef]
    import factory_verify  # type: ignore[no-redef]
    import simulation_evidence  # type: ignore[no-redef]
    import windows_install_run  # type: ignore[no-redef]


SCHEMA = 1
REPOSITORY = Path(__file__).resolve().parents[2]

#: Gate 12's own words: "at least twice".  One iteration proves nothing about
#: repeatability, so the driver refuses to call a single run a repeat.
MINIMUM_ITERATIONS = 2
DEFAULT_ITERATIONS = 2
DEFAULT_DURATION = 3600.0

DEFAULT_EVIDENCE_ROOT = Path("homelab/var/factory/repeat")
DEFAULT_WORK_ROOT = Path("homelab/var/factory/repeat-work")
DEFAULT_RELEASES = Path("homelab/var/pxe")
DEFAULT_MEDIA_SEAL = Path("homelab/var/media/factory-media-seal.json")
NETWORK_SNAPSHOT_LIMIT = 2 << 20
REUSE_EVIDENCE_LIMIT = 64 << 20
REUSE_ENTRY_LIMIT = 1024

#: The canonical Controller disk every live phase boots or copies.
CANONICAL_CONTROLLER_DISK = Path("build/homelab/vm/bootstrap-dc/bootstrap-dc.qcow2")
#: A never-installed 80 GiB qcow2 holds only its own header and L1 table --
#: measured at 197,888 bytes on this host.  An installed Controller (Arch plus
#: Samba AD, Kerberos, DNS and the PXE tree) is gigabytes.  Anything under this
#: floor cannot possibly contain an installation, so the precondition reads the
#: real file rather than trusting a manifest that an empty disk also carries.
#: Fallback floor, used only when :mod:`controller_image` cannot be imported.
#: It is deliberately weak -- a partially written gigabyte passes it -- so the
#: real check is the partition-table probe in ``controller_image_problem``.
INSTALLED_DISK_MINIMUM_BYTES = 1 << 30

try:  # pragma: no cover - exercised by the import-failure test
    from . import controller_image
except ImportError:  # pragma: no cover
    try:
        import controller_image  # type: ignore[no-redef]
    except ImportError:
        controller_image = None  # type: ignore[assignment]

#: Phase artifacts whose names ``factory_verify.ALLOWED_EVIDENCE`` already
#: accepts at an evidence root, and which therefore MERGE across phases into
#: one aggregate artifact.  ``switch.jsonl`` concatenates as JSONL; the two
#: logs concatenate as text.
MERGED_EVIDENCE = ("controller-publication.log", "workstation-serial.log",
                   "switch.jsonl")

#: Every other phase artifact this driver knows how to re-retain, verbatim,
#: under ``phases/<phase>/``.  Measured from the retained bundles under
#: ``homelab/var/factory``: a name absent here is refused, never copied.
PHASE_LOCAL_EVIDENCE = frozenset({
    factory_verify.RESULT,
    factory_verify.PXE_AUTHORITY_AUDIT,
    "dualboot-events.jsonl",
    "recovery-evidence.jsonl",
    "identity-lifecycle.jsonl",
    "workstation-boot.json",
    "workstation-firmware.log",
    "workstation-switch.jsonl",
})

#: The same, for the artifact families whose names carry a run-scoped counter
#: or timestamp.  Anchored whole-name patterns only: a prefix match would let
#: an arbitrary suffix through.
PHASE_LOCAL_PATTERNS = (
    re.compile(r"\Aboot\d+-serial\.log\Z"),
    re.compile(r"\Aworkstation-stall-\d+\.png\Z"),
    re.compile(r"\A\d{8}T\d{6}Z-controller\.json\Z"),
    re.compile(r"\A\d{8}T\d{6}Z-serial-redacted\.log\Z"),
)

MERGE = "merge"
RETAIN = "retain"

#: Where re-retained phase artifacts live inside the aggregate evidence
#: directory.  One working subdirectory, named in the receipt by
#: ``verify_run``'s ``evidence_subdirectories``.
PHASE_TREE = "phases"

#: The measurements no phase runner records, each drawn from a sibling module
#: through :func:`bind_producers`.  The module and attribute of each are named
#: once, here, so the adapter seam and the availability report cannot drift.
PRODUCER_ENTRY_POINTS: dict[str, tuple[str, str]] = {
    "host_network_changes": ("host_network_evidence", "change_counters"),
    "login": ("factory_measurements", "login_measurement"),
    "optional_storage_absence_nonblocking":
        ("factory_measurements", "optional_storage_measurement"),
    "artifact_scan": ("artifact_scan", "scan_paths"),
}
PRODUCED_KEYS = tuple(PRODUCER_ENTRY_POINTS)

#: The persistent disk inside a Windows install bundle
#: (``windows_install_prepare``; ``windows_identity_prepare.DISK_NAME``).
#: ``homelab-arch-install-prepare`` forwards ``WINDOWS_RUN`` as
#: ``--windows-disk``, which must name this regular file, not the bundle.
WINDOWS_INSTALL_DISK = "windows.qcow2"

#: Where each identity phase leaves the judged acceptance stream the login
#: measurements are derived from.  The Windows name is the documented gate-6
#: output (``<attempt>/acceptance-evidence.jsonl``); the Arch one is measured
#: from the retained gate-8 bundles under ``homelab/var/factory/arch-identity``.
WINDOWS_IDENTITY_EVIDENCE = "acceptance-evidence.jsonl"
ARCH_IDENTITY_EVIDENCE = "evidence/identity-lifecycle.jsonl"

#: Measurements that legitimately accumulate across phases rather than having
#: one value.  ``install_order`` is the whole point of the aggregate; the guest
#: disk inventory is a union because every phase exposes its own disks and the
#: check requires all of them to be disposable and run-scoped.
CONCATENATED_KEYS = ("install_order", "guest_disks")

AGGREGATE_STATUS = factory_verify.AGGREGATE_PASS_STATUS   # "pass"
PARTIAL_STATUS = factory_verify.PHASE_PASS_STATUS         # "observed"
FAIL_STATUS = factory_verify.RUN_FAIL_STATUS              # "fail"


class RepeatError(RuntimeError):
    """The lifecycle, its evidence, or its preconditions are not repeatable."""


class PhaseFailed(RepeatError):
    """A prepared phase bundle's run step failed; ``bundle`` names it.

    Raised by a driver's :meth:`LifecycleDriver.run_phase` so the failed
    bundle's own ``result.json`` can be read for a retryable
    ``failure_category`` (:data:`RETRYABLE_FAILURES`).
    """

    def __init__(self, phase: str, bundle: Path, detail: str) -> None:
        super().__init__(f"phase {phase} failed in {bundle}: {detail}")
        self.phase = phase
        self.bundle = Path(bundle)


#: The only failures a phase is retried for, by phase: the Windows install's
#: PXE->WinPE->reboot->PXE loop, a nondeterministic flake a fresh bundle clears
#: (4 of 5 live installs on 2026-10-01 were healthy), which
#: ``windows_install_run`` detects live and records as its
#: ``failure_category``.  At most ONE retry per phase per iteration; any other
#: phase or category, or a second loop, fails the iteration as before.  Every
#: retry is recorded in the iteration's ``result.json`` and the repeat receipt.
RETRYABLE_FAILURES: dict[str, frozenset[str]] = {
    "windows-install": frozenset({windows_install_run.PXE_LOOP}),
}


# --------------------------------------------------------------------------
# No new privileges
# --------------------------------------------------------------------------

#: ``linux/prctl.h``.
PR_SET_NO_NEW_PRIVS = 38
PR_GET_NO_NEW_PRIVS = 39


def set_no_new_privileges() -> None:
    """Irreversibly forbid this process and every descendant any new privilege.

    Sets ``PR_SET_NO_NEW_PRIVS`` on the calling process through libc's
    ``prctl``.  The flag survives fork and execve and can never be cleared, so
    from here on no descendant gains privilege through a setuid/setgid binary
    (``sudo`` refuses) or file capabilities.  That is the first fact of the
    ``forwarding`` counter's privilege basis
    (``host_network_evidence.classify``): with an unreadable nft ruleset, the
    counter is proven only when every snapshot of the run records
    ``NoNewPrivs: 1`` and no CAP_NET_ADMIN/CAP_SYS_ADMIN, so a run that skips
    this can only lose that proof, never fake it.  The read-back is checked so
    a silently ignored call fails here rather than hours later.
    """
    libc = ctypes.CDLL(None, use_errno=True)
    prctl = libc.prctl
    prctl.restype = ctypes.c_int
    prctl.argtypes = (ctypes.c_int, ctypes.c_ulong, ctypes.c_ulong,
                      ctypes.c_ulong, ctypes.c_ulong)
    if prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0:
        raise RepeatError(
            "prctl(PR_SET_NO_NEW_PRIVS) failed: "
            f"{os.strerror(ctypes.get_errno())}")
    if prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) != 1:
        raise RepeatError("prctl(PR_SET_NO_NEW_PRIVS) did not take effect")


# --------------------------------------------------------------------------
# The lifecycle phase table
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class SourceRef:
    """A Make variable a phase's prepare step needs from an earlier phase."""

    variable: str
    phase: str
    #: Appended to the earlier phase's bundle path when the variable names a
    #: file inside it rather than the bundle itself.
    suffix: str = ""


@dataclass(frozen=True)
class Phase:
    """One step of the sealed-input lifecycle, as an operator drives it.

    The driver goes through the Make targets rather than the runners' Python
    entry points because the Makefile is the operator surface and already
    encodes each runner's required variables; a repeat that only a bespoke
    Python path can perform would not be the lifecycle an operator repeats.
    """

    name: str
    run_target: str
    #: The Make variable naming the bundle the run step consumes.
    variable: str
    #: ``None`` for a phase whose bundle the driver mints itself.
    prepare_target: str | None = None
    sources: tuple[SourceRef, ...] = ()
    #: The bundle-relative evidence directory: ``"evidence"`` for most phases,
    #: ``""`` when the bundle root IS the evidence, and ``None`` for a phase
    #: that retains no ``verify_run``-shaped directory at all (the Windows
    #: identity attempt keeps disk images and frame captures beside its
    #: acceptance JSONL, so it contributes through the producers instead).
    evidence: str | None = "evidence"
    #: Whether that evidence directory carries a ``result.json`` whose status
    #: must be a recognised pass.  The identity phases retain a judged
    #: acceptance stream instead of a result, and their verdict reaches the
    #: aggregate through the login measurement (whose producer calls the real
    #: judges), not through a status this driver could read.
    result: bool = True


PHASES: tuple[Phase, ...] = (
    Phase(name="windows-install",
          prepare_target="homelab-windows-install-prepare",
          run_target="homelab-windows-install-run",
          variable="WINDOWS_RUN"),
    Phase(name="windows-identity",
          prepare_target="homelab-windows-identity-prepare",
          run_target="homelab-windows-identity-run",
          variable="WINDOWS_IDENTITY_ATTEMPT",
          sources=(SourceRef("WINDOWS_RUN", "windows-install"),),
          evidence=None),
    Phase(name="arch-install",
          prepare_target="homelab-arch-install-prepare",
          run_target="homelab-arch-install-run",
          variable="ARCH_RUN",
          sources=(SourceRef("WINDOWS_RUN", "windows-install",
                             WINDOWS_INSTALL_DISK),)),
    Phase(name="arch-identity",
          prepare_target="homelab-arch-identity-prepare",
          run_target="homelab-arch-identity-run",
          variable="ARCH_IDENTITY_BUNDLE",
          sources=(SourceRef("ARCH_RUN", "arch-install"),
                   SourceRef("WINDOWS_IDENTITY_EVIDENCE", "windows-identity",
                             WINDOWS_IDENTITY_EVIDENCE)),
          result=False),
    Phase(name="dualboot-acceptance",
          prepare_target="homelab-dualboot-acceptance-prepare",
          run_target="homelab-dualboot-acceptance-run",
          variable="DUALBOOT_RUN",
          sources=(SourceRef("GATE7_RUN", "arch-install"),)),
    Phase(name="lifecycle-recovery",
          run_target="homelab-factory-recover",
          variable="RECOVERY_RUN",
          evidence=""),
)


def phase_evidence(phase: Phase, bundle: Path) -> Path | None:
    """The ``verify_run``-shaped directory a finished phase bundle exposes."""
    if phase.evidence is None:
        return None
    return Path(bundle) if phase.evidence == "" else Path(bundle) / phase.evidence


def _source_path(reference: SourceRef, bundles: dict[str, Path]) -> Path:
    try:
        bundle = bundles[reference.phase]
    except KeyError:
        raise RepeatError(
            f"phase {reference.phase} has not run yet, so "
            f"{reference.variable} cannot be resolved") from None
    return Path(bundle) / reference.suffix if reference.suffix else Path(bundle)


def prepare_command(phase: Phase, bundles: dict[str, Path]) -> list[str] | None:
    """The argv that prepares one phase bundle, or ``None`` when it mints one."""
    if phase.prepare_target is None:
        return None
    return [
        "make", "--no-print-directory", phase.prepare_target, "APPLY=1",
        *(f"{reference.variable}={_source_path(reference, bundles)}"
          for reference in phase.sources),
    ]


def run_command(phase: Phase, bundle: Path, *, duration: float) -> list[str]:
    """The argv that executes one prepared phase bundle."""
    return [
        "make", "--no-print-directory", phase.run_target, "APPLY=1",
        f"{phase.variable}={Path(bundle)}",
        f"FACTORY_DURATION={duration:g}",
    ]


# --------------------------------------------------------------------------
# The producer adapter seam
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class Producers:
    """Zero-argument producers for the measurements no phase runner records.

    Each is already bound to its arguments, so this module never learns a
    sibling's parameter list and a test can inject a plain ``lambda``.  A
    ``None`` producer means "not available": the field then stays absent, which
    renders NOT-RUN in the receipt.  It is never defaulted to a passing value.
    """

    host_network_changes: Callable[[], object] | None = None
    login: Callable[[], object] | None = None
    optional_storage_absence_nonblocking: Callable[[], object] | None = None
    artifact_scan: Callable[[], object] | None = None

    def fields(self) -> list[tuple[str, Callable[[], object] | None]]:
        return [(name, getattr(self, name)) for name in PRODUCED_KEYS]

    def available(self) -> list[str]:
        return [name for name, producer in self.fields() if producer is not None]


def _optional_module(name: str):
    """Import a sibling producer module, or ``None`` when it does not exist.

    The three producer modules are written by other lanes.  This module must
    import, and its tests must pass, whether or not they are present yet.

    Only a genuinely absent sibling yields ``None``: a ``ModuleNotFoundError``
    raised from INSIDE a sibling that is present but broken names a different
    module and is re-raised, so a broken producer is never mistaken for an
    absent one and silently downgraded to NOT-RUN.
    """
    if name in sys.modules:
        return sys.modules[name]
    for candidate in (f"homelab.vm.{name}", name):
        try:
            return __import__(candidate, fromlist=[name])
        except ModuleNotFoundError as error:
            if error.name is not None and not candidate.startswith(error.name):
                raise
    return None


def _entry_point(key: str):
    module_name, attribute = PRODUCER_ENTRY_POINTS[key]
    module = _optional_module(module_name)
    return module, getattr(module, attribute, None)


def producer_availability() -> dict[str, bool]:
    """Which sibling producer entry points exist in this checkout."""
    return {key: _entry_point(key)[1] is not None for key in PRODUCED_KEYS}


def _producer(key: str, call: Callable[[Callable], object], *,
              tolerate: str | None = None) -> Callable[[], object] | None:
    """Wrap one sibling entry point as a zero-argument producer.

    ``tolerate`` names an exception class on the same module that means "this
    measurement is not proven".  Catching it yields ``None``, which omits the
    field and leaves the check NOT-RUN -- the only honest outcome, since
    neither a zero nor a false may be invented for an unproven measurement.
    """
    module, function = _entry_point(key)
    if function is None:
        return None
    unproven = getattr(module, tolerate, None) if tolerate else None
    ignored: tuple = (
        (unproven,) if isinstance(unproven, type)
        and issubclass(unproven, BaseException) else ())

    def produce() -> object:
        try:
            return call(function)
        except ignored:
            return None

    return produce


def host_network_measurement(module, before, after) -> dict | None:
    """The ``host_network_changes`` field, honouring ADR 0080's waiver.

    ``change_counters`` returns seven proven integers and the ``basis`` of the
    forwarding proof, or raises ``UnprovenCategory``.  When the ONLY unproven
    counter is one ``factory_verify.HOST_NETWORK_WAIVER`` covers (``unifi``,
    which no snapshot pair can prove), the other six were proven, so the field
    is emitted from ``classify`` with that slot holding the unproven sentinel:
    ``factory_verify`` then grades the six and renders check 9 ``WAIVED`` --
    or ``FAIL`` if any of them counted a change.  Any other unproven counter
    omits the field, which keeps the check NOT-RUN exactly as before: the
    waiver never widens past the one counter it names, and no zero is ever
    invented for a slot nothing observed.
    """
    change_counters = getattr(module, "change_counters", None)
    if change_counters is None:
        return None
    classify = getattr(module, "classify", None)
    unproven_error = getattr(module, "UnprovenCategory", None)
    tolerated: tuple = (
        (unproven_error,) if isinstance(unproven_error, type)
        and issubclass(unproven_error, BaseException) else ())
    waivable = set(factory_verify.HOST_NETWORK_WAIVER["covers"])
    try:
        return change_counters(before, after)
    except tolerated as error:
        if set(getattr(error, "reasons", {}) or {}) != waivable:
            return None
    if classify is None:
        return None
    report = classify(before, after)
    counters = report.get("counters") if isinstance(report, dict) else None
    if (not isinstance(counters, dict)
            or set(report.get("unproven") or ()) != waivable
            or any(counters.get(name) != factory_verify.UNPROVEN_COUNTER
                   for name in waivable)):
        return None
    measurement = dict(counters)
    # The basis travels with the counters, so the receipt can say whether
    # forwarding was proven by a ruleset snapshot or only by privilege.
    basis = report.get("basis")
    if isinstance(basis, dict):
        measurement["basis"] = dict(basis)
    return measurement


def _host_network_producer(before, after) -> Callable[[], object] | None:
    """Bind :func:`host_network_measurement` to the sibling, if it exists."""
    module, change_counters = _entry_point("host_network_changes")
    if change_counters is None:
        return None
    return lambda: host_network_measurement(module, before, after)


def scan_retained_evidence(scan_paths: Callable,
                           evidence_dirs: Sequence[Path]) -> dict | None:
    """The ``artifact_scan`` counters over the evidence an iteration retains.

    Check 15's tree is the run's retained evidence, which is what
    ``artifact_scan`` is calibrated for: its size limit is the evidence limit
    and its credential rule was tuned on retained evidence.  So each finished
    phase's evidence directory is scanned file by file, exactly as
    :func:`enumerate_bundle` lists it.  The working subdirectories beside
    those files hold disks and frame captures and are named in the aggregate
    but never copied, so they are not scanned; nor are the phase bundle roots
    or the checkout.  The aggregate directory and the repeat receipt are
    written after this measurement and only from these files, so scanning
    them would be circular.

    ``None`` -- the field omitted, check 15 NOT-RUN -- when no evidence
    directory exists or any one is missing or unreadable: an unscanned tree
    is never clean.
    """
    if not evidence_dirs:
        return None
    listed = []
    for evidence in evidence_dirs:
        try:
            listed.append((Path(evidence), enumerate_bundle(evidence)[0]))
        except (RepeatError, OSError):
            return None
    totals: dict = {}
    for evidence, files in listed:
        for category, count in scan_paths(evidence, files).counters.items():
            totals[category] = totals.get(category, 0) + count
    return totals


def bind_producers(*, windows_evidence: Path | None = None,
                   arch_evidence: Path | None = None,
                   evidence_dirs: Sequence[Path] = (),
                   network_before=None, network_after=None) -> Producers:
    """Bind the four sibling-owned measurements, tolerating absent siblings.

    This is the ENTIRE coupling to the three producer modules: one line each.
    When a sibling's final signature differs from the call below, exactly one
    lambda changes and nothing else in this module or its tests moves.

    The two identity measurements are bound only when BOTH judged streams are
    present.  The producers themselves return an all-false block for a missing
    stream, and an all-false ``login`` asserts a login that FAILED, which is a
    different claim from "this run observed no login".  Leaving them unbound
    keeps the absent case at NOT-RUN.
    """
    identity = (windows_evidence is not None and arch_evidence is not None
                and Path(windows_evidence).is_file()
                and Path(arch_evidence).is_file())
    return Producers(
        host_network_changes=_host_network_producer(
            network_before, network_after)
        if network_before is not None and network_after is not None else None,
        login=_producer(
            "login",
            lambda f: f(windows_evidence, arch_evidence)) if identity else None,
        optional_storage_absence_nonblocking=_producer(
            "optional_storage_absence_nonblocking",
            lambda f: f(windows_evidence, arch_evidence)) if identity else None,
        artifact_scan=_producer(
            "artifact_scan",
            lambda f: scan_retained_evidence(f, evidence_dirs)),
    )


def default_producer_binding(bundles: dict[str, Path], *,
                             phases: Sequence[Phase] = PHASES,
                             network_before=None,
                             network_after=None) -> Producers:
    """Bind the producers to one finished iteration's phase bundles."""
    windows = bundles.get("windows-identity")
    arch = bundles.get("arch-identity")
    return bind_producers(
        windows_evidence=(
            None if windows is None
            else Path(windows) / WINDOWS_IDENTITY_EVIDENCE),
        arch_evidence=(
            None if arch is None else Path(arch) / ARCH_IDENTITY_EVIDENCE),
        evidence_dirs=[
            phase_evidence(phase, bundles[phase.name]) for phase in phases
            if phase.name in bundles and phase.evidence is not None],
        network_before=network_before, network_after=network_after)


# --------------------------------------------------------------------------
# Measurement assembly
# --------------------------------------------------------------------------


def merge_phase_measurements(
    blocks: Sequence[tuple[str, dict]],
) -> dict:
    """Merge each phase's honest measurement subset into one union.

    ``install_order`` and ``guest_disks`` concatenate in phase order and are
    never de-duplicated -- a repeated entry is a fact about the run, and
    collapsing it would hide a second install.  Every other key must agree
    wherever two phases both recorded it: a disagreement is a contradiction
    between two runs of the same lifecycle, which is exactly the kind of thing
    gate 12 exists to surface, so it fails closed instead of picking a winner.
    """
    merged: dict = {}
    origin: dict[str, str] = {}
    for phase, block in blocks:
        if not isinstance(block, dict):
            raise RepeatError(f"phase {phase} recorded a malformed measurement block")
        for key in sorted(block):
            value = block[key]
            if key not in factory_runner.MEASUREMENT_KEYS:
                raise RepeatError(
                    f"phase {phase} recorded an unknown acceptance measurement: {key}")
            if key in CONCATENATED_KEYS:
                if not isinstance(value, list):
                    raise RepeatError(
                        f"phase {phase} recorded a malformed {key}")
                merged.setdefault(key, []).extend(value)
                origin.setdefault(key, phase)
                continue
            if key in merged and merged[key] != value:
                raise RepeatError(
                    f"phases {origin[key]} and {phase} disagree about {key}")
            merged[key] = value
            origin.setdefault(key, phase)
    return merged


def assemble_measurements(blocks: Sequence[tuple[str, dict]], *,
                          producers: Producers) -> dict:
    """The union of the phase measurements and the four produced ones.

    Composed through ``factory_runner.measurement_block``, so the result can
    never carry a key outside the ten pinned ``MEASUREMENT_KEYS`` and a
    producer that drifts is a hard error rather than dead evidence.
    """
    merged = merge_phase_measurements(blocks)
    for key, produce in producers.fields():
        value = produce() if produce is not None else None
        if value is None:
            continue
        if key in merged and merged[key] != value:
            raise RepeatError(
                f"a phase and the {key} producer disagree about {key}")
        merged[key] = value
    return factory_runner.measurement_block(**merged)


def missing_measurements(measurements: dict) -> list[str]:
    """The acceptance measurements the assembled union still lacks."""
    return sorted(factory_runner.MEASUREMENT_KEYS - set(measurements))


# --------------------------------------------------------------------------
# Evidence re-retention (fail-closed; ALLOWED_EVIDENCE is never widened)
# --------------------------------------------------------------------------


def evidence_disposition(name: str) -> str:
    """``MERGE``, ``RETAIN``, or a refusal for an artifact this driver cannot place.

    Fail-closed by construction: the only two ways out of this function are the
    two known dispositions, and an unrecognised name raises.  Nothing reaches
    the aggregate evidence directory without passing through here.
    """
    if name in MERGED_EVIDENCE:
        return MERGE
    if name in PHASE_LOCAL_EVIDENCE:
        return RETAIN
    if any(pattern.match(name) for pattern in PHASE_LOCAL_PATTERNS):
        return RETAIN
    raise RepeatError(
        f"unrecognised phase evidence artifact: {name!r}; add it to "
        "PHASE_LOCAL_EVIDENCE (or PHASE_LOCAL_PATTERNS) with a reason, or "
        "remove it from the phase bundle -- it is never copied unrecognised")


def enumerate_bundle(evidence_dir: Path) -> tuple[list[str], list[str]]:
    """Retained files and working subdirectories of one phase evidence dir.

    Mirrors ``factory_verify._list_evidence``'s refusals: a symlink, socket,
    FIFO or device node has no place in evidence and is refused rather than
    skipped.
    """
    evidence_dir = Path(evidence_dir)
    if evidence_dir.is_symlink() or not evidence_dir.is_dir():
        raise RepeatError(f"phase evidence is missing or not a directory: {evidence_dir}")
    files: list[str] = []
    subdirectories: list[str] = []
    with os.scandir(evidence_dir) as scan:
        for entry in scan:
            if entry.is_symlink():
                raise RepeatError(f"unexpected phase evidence entry: {entry.name}")
            if entry.is_dir(follow_symlinks=False):
                subdirectories.append(entry.name)
            elif entry.is_file(follow_symlinks=False):
                files.append(entry.name)
            else:
                raise RepeatError(f"unexpected phase evidence entry: {entry.name}")
    return sorted(files), sorted(subdirectories)


@dataclass(frozen=True)
class RetentionPlan:
    """Where every phase artifact goes, decided before anything is written."""

    #: aggregate artifact name -> the phases contributing to it, in order
    merged: dict[str, list[str]] = field(default_factory=dict)
    #: phase -> the artifacts re-retained under ``phases/<phase>/``
    retained: dict[str, list[str]] = field(default_factory=dict)
    #: phase -> the working subdirectories named but not copied
    subdirectories: dict[str, list[str]] = field(default_factory=dict)


def plan_retention(
    contents: Sequence[tuple[str, list[str], list[str]]],
) -> RetentionPlan:
    """Decide the disposition of every phase artifact, or refuse the run.

    Pure: it takes the enumerations, not the directories, so the whole
    fail-closed decision is testable without a filesystem.
    """
    plan = RetentionPlan()
    for phase, files, subdirectories in contents:
        for name in files:
            if evidence_disposition(name) == MERGE:
                plan.merged.setdefault(name, []).append(phase)
            else:
                plan.retained.setdefault(phase, []).append(name)
        if subdirectories:
            plan.subdirectories[phase] = list(subdirectories)
    return plan


def _merged_bytes(chunks: Iterable[bytes], *, name: str) -> bytes:
    """Concatenate, redact, and bound one merged artifact.

    The same treatment ``factory_runner.retain_evidence`` gives what it
    retains: redacted, then truncated to the last ``EVIDENCE_LIMIT`` bytes so
    the aggregate cannot fail its own size check by merging several phases.
    A head-truncated JSONL would begin mid-record, so the partial first line is
    dropped rather than retained as an unparseable fragment.
    """
    data = simulation_evidence.redact(b"".join(chunks))
    if len(data) <= factory_verify.EVIDENCE_LIMIT:
        return data
    data = data[-factory_verify.EVIDENCE_LIMIT:]
    if name.endswith(".jsonl"):
        newline = data.find(b"\n")
        data = b"" if newline < 0 else data[newline + 1:]
    return data


def _read_regular(path: Path, *, limit: int | None = None,
                  single_link: bool = False) -> bytes:
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise RepeatError(f"{path} is not a regular file")
        if single_link and metadata.st_nlink != 1:
            raise RepeatError("reused evidence file must have exactly one link")
        chunks = []
        size = 0
        while True:
            chunk = os.read(descriptor, 1 << 20)
            if not chunk:
                break
            size += len(chunk)
            if limit is not None and size > limit:
                raise RepeatError("evidence exceeds its read size limit")
            chunks.append(chunk)
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def _private_write(path: Path, data: bytes) -> None:
    simulation_evidence.private_file(path, data)


def retain_aggregate_evidence(destination: Path,
                              bundles: Sequence[tuple[str, Path]], *,
                              result: dict) -> Path:
    """Build one aggregate evidence directory ``verify_run`` can read.

    ``bundles`` pairs a phase name with its evidence directory.  The result is
    a directory holding only names ``ALLOWED_EVIDENCE`` accepts, plus the one
    ``phases/`` working tree, plus the aggregate ``result.json``.
    """
    destination = Path(destination)
    if destination.exists():
        raise RepeatError(f"aggregate evidence already exists: {destination}")
    contents = [(phase, *enumerate_bundle(evidence))
                for phase, evidence in bundles]
    plan = plan_retention(contents)

    simulation_evidence.private_directory(destination)
    sources = dict(bundles)
    for name in MERGED_EVIDENCE:
        phases = plan.merged.get(name)
        if not phases:
            continue
        chunks = [_read_regular(Path(sources[phase]) / name) for phase in phases]
        _private_write(destination / name, _merged_bytes(chunks, name=name))
    for phase, names in sorted(plan.retained.items()):
        # Created explicitly, because a directory made only as a by-product of
        # ``mkdir(parents=True)`` keeps the process umask instead of 0700.
        simulation_evidence.private_directory(destination / PHASE_TREE)
        simulation_evidence.private_directory(destination / PHASE_TREE / phase)
        for name in names:
            _private_write(destination / PHASE_TREE / phase / name,
                           _read_regular(Path(sources[phase]) / name))

    document = dict(result)
    document["retained"] = sorted(plan.merged)
    document["phase_evidence"] = {
        "merged": {name: list(phases) for name, phases in sorted(plan.merged.items())},
        "retained": {phase: list(names) for phase, names in sorted(plan.retained.items())},
        # Named, never copied: a phase working tree holds disk images and frame
        # captures whose bytes belong in the phase bundle, not in an aggregate.
        "uncopied_working_trees": {
            phase: list(names)
            for phase, names in sorted(plan.subdirectories.items())},
    }
    _private_write(destination / factory_verify.RESULT,
                   (json.dumps(document, indent=2, sort_keys=True) + "\n").encode())
    return destination


# --------------------------------------------------------------------------
# Aggregation
# --------------------------------------------------------------------------


def read_phase_result(evidence_dir: Path) -> dict:
    """One phase's ``result.json``, or ``{}`` when it retained none."""
    path = Path(evidence_dir) / factory_verify.RESULT
    try:
        value = json.loads(_read_regular(path))
    except (OSError, RepeatError, json.JSONDecodeError, UnicodeDecodeError):
        return {}
    return value if isinstance(value, dict) else {}


def aggregate_status(observations: Sequence[dict], measurements: dict) -> str:
    """The honest pass vocabulary for an assembled iteration.

    ``"pass"`` -- the aggregate whole-factory claim ``factory_verify`` renders
    as ``run_status.scope: "aggregate"`` -- requires BOTH that every phase
    that retains a result recorded a recognised pass status AND that the
    measurement union is complete.  An incomplete union is still an honest run,
    just a narrower one, so it records the phase vocabulary and leaves the
    unmeasured checks NOT-RUN.  Nothing here can turn an absent measurement
    into a pass.  Complete means PRESENT: a value's content -- including the
    unproven ``unifi`` slot ADR 0080 waives -- is graded by ``factory_verify``,
    whose verdict (``PASS-WITH-WAIVER``, never ``PASS``) is what the gate reads.

    A phase marked ``result=False`` retains a judged acceptance stream rather
    than a status; its verdict reaches this function through the completeness
    of the measurement union, since the login producer calls that phase's own
    judge.  Skipping it here is therefore not a gap -- an unjudged identity
    phase yields no login measurement, and the union is then incomplete.
    """
    for observation in observations:
        if not observation.get("status_required"):
            continue
        if observation.get("status") not in factory_verify.PASS_STATUS_SCOPES:
            return FAIL_STATUS
    return AGGREGATE_STATUS if not missing_measurements(measurements) else PARTIAL_STATUS


def aggregate_result(*, iteration: int, observations: Sequence[dict],
                     measurements: dict,
                     retries: Sequence[dict] = ()) -> dict:
    """The aggregate ``result.json`` body for one iteration.

    ``retries`` is always present, empty when no phase was retried, so the
    nondeterminism a retry absorbed is disclosed rather than hidden.
    """
    status = aggregate_status(observations, measurements)
    return {
        "schema": SCHEMA,
        "kind": "factory-repeat-iteration",
        "status": status,
        "iteration": iteration,
        "phases": [dict(observation) for observation in observations],
        "measurements": measurements,
        "measurements_missing": missing_measurements(measurements),
        "retries": [dict(retry) for retry in retries],
    }


def repeat_prerequisites(receipts: Sequence[dict]) -> list[dict]:
    """Require gate 4 in each run without widening the phase verifier API.

    Missing or incomplete evidence needs a live proof.  A failed audit or
    malformed/unknown verdict fails closed.  The receipt names each blocked
    iteration even when two identical failures compare as equivalent.
    """
    prerequisites = []
    for index, receipt in enumerate(receipts, 1):
        audit = receipt.get("pxe_authority_audit")
        verdict = audit.get("verdict") if isinstance(audit, dict) else None
        if isinstance(audit, dict) and audit.get("gate") != "workstation-factory-gate-4":
            status = factory_verify.FAIL
            detail = "the retained PXE authority audit does not identify gate 4"
        elif verdict == factory_verify.PASS:
            status = factory_verify.PASS
            detail = "the retained gate-4 PXE authority audit passed"
        elif audit is None or verdict in (factory_verify.NOT_RUN, "NOT-PROVABLE"):
            status = factory_verify.NOT_RUN
            detail = "gate 4 needs complete live switch evidence and a passing audit"
        else:
            status = factory_verify.FAIL
            detail = ("the retained gate-4 PXE authority audit failed"
                      if verdict == factory_verify.FAIL else
                      "the retained gate-4 PXE authority audit has an invalid verdict")
        prerequisites.append({
            "iteration": index,
            "gate": "workstation-factory-gate-4",
            "status": status,
            "detail": detail,
        })
    return prerequisites


def repeat_verdict(receipts: Sequence[dict], comparisons: Sequence[dict]) -> str:
    """The gate-12 verdict: every run must pass AND every pair must agree.

    A divergence, failing run or failing prerequisite fails; any NOT-RUN run
    or prerequisite holds the verdict at NOT-RUN.  A waived run makes the repeat
    ``PASS-WITH-WAIVER``, never ``PASS``.  A verdict outside
    ``factory_verify.VERDICTS`` fails closed rather than reading as a pass.
    Agreement on a waiver is the comparator's job: a waived check embeds its
    decision record, so two runs agree only when both waived it identically.
    """
    if any(comparison["divergent_count"] for comparison in comparisons):
        return factory_verify.FAIL
    verdicts = {receipt["verdict"] for receipt in receipts}
    verdicts.update(item["status"] for item in repeat_prerequisites(receipts))
    if factory_verify.FAIL in verdicts or not verdicts <= factory_verify.VERDICTS:
        return factory_verify.FAIL
    if factory_verify.NOT_RUN in verdicts:
        return factory_verify.NOT_RUN
    if factory_verify.PASS_WITH_WAIVER in verdicts:
        return factory_verify.PASS_WITH_WAIVER
    return factory_verify.PASS


def repeat_waivers(receipts: Sequence[dict]) -> list[dict]:
    """Every distinct waiver any run recorded, each once, by check and ADR."""
    distinct: list[dict] = []
    for receipt in receipts:
        for waiver in receipt.get("waivers") or ():
            if waiver not in distinct:
                distinct.append(waiver)
    return sorted(distinct, key=lambda waiver: (
        str(waiver.get("check")), str(waiver.get("adr")),
        str(waiver.get("reason"))))


#: The repeat verdicts that close gate 12.  ADR 0080 closes it with the one
#: waived check, so ``PASS-WITH-WAIVER`` exits 0 like ``PASS`` -- the receipt
#: and the stderr verdict line, not the exit status, carry the distinction.
ACCEPTED_VERDICTS = frozenset(
    {factory_verify.PASS, factory_verify.PASS_WITH_WAIVER})


def repeat_receipt(receipts: Sequence[dict],
                   comparisons: Sequence[dict], *,
                   retries: Sequence[dict] = ()) -> dict:
    """The whole-gate receipt: N run receipts plus their pairwise comparisons.

    ``retries`` lists every bounded phase retry any iteration made
    (:data:`RETRYABLE_FAILURES`).  It discloses nondeterminism; it never
    changes the verdict, which is still graded on the runs that completed.
    """
    if len(receipts) < MINIMUM_ITERATIONS:
        raise RepeatError(
            f"gate 12 needs at least {MINIMUM_ITERATIONS} iterations; "
            f"{len(receipts)} were verified")
    prerequisites = repeat_prerequisites(receipts)
    return {
        "schema": SCHEMA,
        "kind": "factory-repeat",
        "iterations": len(receipts),
        "verdict": repeat_verdict(receipts, comparisons),
        "equivalent": all(comparison["equivalent"] for comparison in comparisons),
        "runs": list(receipts),
        "comparisons": list(comparisons),
        "prerequisites": prerequisites,
        "needs_live_gate": sorted(
            {name for receipt in receipts for name in receipt["needs_live_gate"]}
            | {item["gate"] for item in prerequisites
               if item["status"] != factory_verify.PASS}),
        "waivers": repeat_waivers(receipts),
        "retries": [dict(retry) for retry in retries],
    }


def compare_iterations(receipts: Sequence[dict]) -> list[dict]:
    """Compare the first run against each later one, naming both sides."""
    first, *rest = receipts
    comparisons = []
    for other in rest:
        comparison = dict(factory_verify.compare_runs(first, other))
        comparison["a"] = first["evidence"]
        comparison["b"] = other["evidence"]
        comparisons.append(comparison)
    return comparisons


def _input_identity(value: object) -> dict:
    """Require the complete live input pin, never a partially matching subset."""
    try:
        if (not isinstance(value, dict)
                or set(value) != {"release_set", "media_seal_sha256", "samba_dns"}
                or set(value["release_set"]) != {"version", "manifest_sha256"}
                or set(value["samba_dns"]) != {"library_sha256", "receipt_sha256"}
                or not re.fullmatch(r"\d{8}\.\d{3}", value["release_set"]["version"])
                or any(not re.fullmatch(r"[0-9a-f]{64}", digest) for digest in (
                    value["release_set"]["manifest_sha256"], value["media_seal_sha256"],
                    *value["samba_dns"].values()))):
            raise ValueError("incomplete identity")
    except (KeyError, TypeError, ValueError):
        raise RepeatError("reused iteration has invalid factory_inputs") from None
    return value


def _evidence_snapshot(root: Path) -> dict[str, bytes | None]:
    """Bounded regular-file snapshot, including all retained phase artifacts.

    Verification runs on these exact bytes in a private temporary tree, so
    a concurrent edit cannot separate the verifier's input from its digest.
    """
    root = Path(root)
    if root.is_symlink() or not root.is_dir():
        raise RepeatError("reused iteration must be an existing regular evidence directory")
    result: dict[str, bytes | None] = {}
    pending = [root]
    total = 0
    while pending:
        for entry in sorted(pending.pop().iterdir()):
            mode = entry.lstat().st_mode
            name = entry.relative_to(root).as_posix()
            if stat.S_ISDIR(mode):
                result[name] = None
                pending.append(entry)
            elif stat.S_ISREG(mode):
                if entry.stat().st_size > factory_verify.EVIDENCE_LIMIT:
                    raise RepeatError("reused evidence exceeds the per-file size limit")
                payload = _read_regular(
                    entry, limit=factory_verify.EVIDENCE_LIMIT, single_link=True)
                total += len(payload)
                if len(payload) > factory_verify.EVIDENCE_LIMIT or total > REUSE_EVIDENCE_LIMIT:
                    raise RepeatError("reused evidence exceeds the size limit")
                result[name] = payload
            else:
                raise RepeatError("reused evidence contains a symlink or non-regular entry")
            if len(result) > REUSE_ENTRY_LIMIT:
                raise RepeatError("reused evidence exceeds the entry limit")
    return result


def _snapshot_digest(snapshot: dict[str, bytes | None]) -> str:
    inventory = {name: None if payload is None else hashlib.sha256(payload).hexdigest()
                 for name, payload in sorted(snapshot.items())}
    return hashlib.sha256(json.dumps(inventory, sort_keys=True).encode()).hexdigest()


def _complete_iteration(evidence: Path, result: dict) -> None:
    """A reused aggregate must retain the complete six-phase contract."""
    observations = result.get("phases")
    if (result.get("schema") != SCHEMA or result.get("kind") != "factory-repeat-iteration"
            or result.get("status") != "pass"
            or type(result.get("iteration")) is not int or result["iteration"] < 1
            or not isinstance(observations, list) or len(observations) != len(PHASES)):
        raise RepeatError("reused evidence is not a complete passing aggregate iteration")
    retries = result.get("retries")
    if result.get("measurements_missing") != [] or not isinstance(retries, list):
        raise RepeatError("reused iteration has incomplete measurements or retry metadata")
    for retry in retries:
        if (not isinstance(retry, dict)
                or set(retry) != {"iteration", "phase", "failed_bundle", "category", "retry_bundle"}
                or retry["iteration"] != result["iteration"]
                or not isinstance(retry["phase"], str)
                or retry["category"] not in RETRYABLE_FAILURES.get(retry["phase"], ())
                or any(not isinstance(retry[key], str) or not retry[key]
                       for key in ("failed_bundle", "retry_bundle"))):
            raise RepeatError("reused iteration has invalid retry metadata")
    retained = result.get("phase_evidence", {}).get("retained", {})
    if not isinstance(retained, dict):
        raise RepeatError("reused iteration has invalid retained phase metadata")
    expected_trees = {phase.name for phase in PHASES if phase.evidence is not None}
    _files, trees = enumerate_bundle(evidence / PHASE_TREE)
    if _files or set(trees) != expected_trees or set(retained) != expected_trees:
        raise RepeatError("reused iteration lacks the complete retained phase tree")
    for phase, observation in zip(PHASES, observations):
        required = phase.result and phase.evidence is not None
        if (not isinstance(observation, dict)
                or set(observation) != {"phase", "status", "status_required", "evidence"}
                or observation["phase"] != phase.name
                or observation["status_required"] is not required
                or (phase.evidence is None and observation["evidence"] is not None)
                or (phase.evidence is not None and (
                    not isinstance(observation["evidence"], str) or not observation["evidence"]))
                or (required and observation["status"] not in {"pass", "observed"})
                or (not required and observation["status"] is not None)):
            raise RepeatError(f"reused iteration has invalid phase metadata: {phase.name}")
        if phase.evidence is None:
            continue
        phase_root = evidence / PHASE_TREE / phase.name
        files, directories = enumerate_bundle(phase_root)
        if directories or sorted(files) != retained[phase.name]:
            raise RepeatError(f"reused iteration retained phase inventory differs: {phase.name}")
        for name in files:
            if evidence_disposition(name) != RETAIN:
                raise RepeatError("reused phase tree has an unexpected artifact")
        if required and read_phase_result(phase_root).get("status") != observation["status"]:
            raise RepeatError(f"reused iteration phase status differs: {phase.name}")


def checked_reused_iteration(evidence: Path, *, releases: Path | None) -> tuple[dict, str, list]:
    """Return the verified receipt, digest and retries from the same snapshot."""
    evidence = Path(evidence).absolute()
    try:
        snapshot = _evidence_snapshot(evidence)
        fingerprint = _snapshot_digest(snapshot)
        with tempfile.TemporaryDirectory(prefix="telos-repeat-reuse-") as temporary:
            copied = Path(temporary) / evidence.name
            simulation_evidence.private_directory(copied)
            for name, payload in sorted(snapshot.items()):
                if payload is None:
                    simulation_evidence.private_directory(copied / name)
                else:
                    _private_write(copied / name, payload)
            result = read_phase_result(copied)
            _complete_iteration(copied, result)
            inputs = _input_identity(result.get("factory_inputs"))
            verified = factory_verify.verify_run(copied, releases=releases)
            if (verified["verdict"] not in ACCEPTED_VERDICTS
                    or repeat_prerequisites([verified])[0]["status"] != factory_verify.PASS):
                raise RepeatError("reused iteration must pass verification and gate 4")
            if verified.get("release_set") != {
                    **inputs["release_set"], "media_seal_sha256": inputs["media_seal_sha256"]}:
                raise RepeatError("reused iteration factory_inputs differ from the verified release")
            verified["factory_inputs"] = inputs
            verified["evidence"] = str(evidence)
        if _snapshot_digest(_evidence_snapshot(evidence)) != fingerprint:
            raise RepeatError("reused iteration changed while being verified")
        return verified, fingerprint, result["retries"]
    except (OSError, ValueError, TypeError, KeyError, AttributeError) as error:
        raise RepeatError(f"cannot reuse iteration: {error}") from error


def _retain_network_snapshot(snapshot: object, destination: Path) -> None:
    payload = (json.dumps(snapshot, indent=2, sort_keys=True) + "\n").encode()
    if len(payload) > NETWORK_SNAPSHOT_LIMIT:
        raise RepeatError("host network diagnostic snapshot exceeds its size limit")
    if destination.exists():
        raise RepeatError("host network diagnostic snapshot already exists")
    _private_write(destination, payload)


# --------------------------------------------------------------------------
# Preconditions
# --------------------------------------------------------------------------


def controller_image_problem(
    disk: Path = CANONICAL_CONTROLLER_DISK,
) -> str | None:
    """Why the canonical Controller image cannot back a live run, if it cannot.

    Every phase boots or copies this disk, so a repeat against an empty one
    would burn hours to produce two identically worthless receipts.  This reads
    the actual file: absent, not a regular file, or too small to hold an
    installation are all refusals.
    """
    path = Path(disk)
    try:
        info = path.lstat()
    except OSError as error:
        return f"canonical Controller image cannot be read: {path} ({error})"
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        return f"canonical Controller image is not a regular file: {path}"
    if controller_image is not None:
        # The size floor below is a weak proxy -- a partially written gigabyte
        # passes it.  ``controller_image.probe`` reads the actual partition
        # table, so prefer it and let it speak for itself; it is fail-closed,
        # so an image it cannot inspect is refused exactly like a blank one.
        try:
            state = controller_image.probe(path)
        except controller_image.ControllerImageError as error:
            return (
                f"canonical Controller image {path} could not be inspected: "
                f"{error}. Run `make homelab-bootstrap-vm-install` if it has "
                "never been installed")
        if not state.installed:
            return (
                f"canonical Controller image {path} is not an installed "
                f"Controller: {state.reason}. No live lifecycle can run "
                "against it; run `make homelab-bootstrap-vm-install` first")
        return None
    if info.st_size < INSTALLED_DISK_MINIMUM_BYTES:
        return (
            f"canonical Controller image {path} holds {info.st_size} bytes, far "
            f"below the {INSTALLED_DISK_MINIMUM_BYTES}-byte floor an installed "
            "system must exceed: it is an empty, never-installed disk, so no "
            "live lifecycle can run against it")
    return None


def preflight(*, iterations: int = DEFAULT_ITERATIONS,
              controller_disk: Path = CANONICAL_CONTROLLER_DISK,
              releases: Path | None = None) -> list[str]:
    """Every reason a live repeat must refuse to start, gathered at once."""
    problems: list[str] = []
    if iterations < MINIMUM_ITERATIONS:
        problems.append(
            f"gate 12 requires at least {MINIMUM_ITERATIONS} iterations; "
            f"{iterations} was requested")
    problem = controller_image_problem(controller_disk)
    if problem is not None:
        problems.append(problem)
    if releases is not None and not Path(releases).is_dir():
        problems.append(f"release set root is missing: {releases}")
    elif releases is not None:
        # Cheap (one descriptor, one manifest digest) and decided before hours
        # of lifecycle: a root whose selection names no set can only FAIL
        # check 16.  The full leaf verification runs into every receipt.
        try:
            factory_verify.pxe_release_set.selected_release_set(Path(releases))
        except factory_verify.pxe_release_set.ReleaseSetError as error:
            problems.append(
                f"release root {releases} selects no verifiable release set: "
                f"{error}")
    return problems


# --------------------------------------------------------------------------
# Orchestration -- the thin live process layer
# --------------------------------------------------------------------------


class LifecycleDriver:
    """The seam between the tested aggregation and the live lifecycle.

    Two methods, deliberately: everything else an iteration does is
    driver-agnostic and unit tested.  A test injects a fake here and never
    boots, spawns, or deletes anything.
    """

    def destroy(self, workdir: Path) -> None:
        """Destroy the disposable state an iteration will rebuild from."""
        raise NotImplementedError

    def run_phase(self, phase: Phase, *, workdir: Path,
                  bundles: dict[str, Path], duration: float) -> Path:
        """Prepare and execute one phase; return its bundle directory.

        Each call prepares a FRESH bundle.  When the run step fails after a
        bundle was prepared, raise :class:`PhaseFailed` naming it, so the
        iteration can read that bundle's ``failure_category``.
        """
        raise NotImplementedError

    def capture_host_network(self):
        """Host networking state, or ``None`` when it cannot be captured.

        Read-only, but it shells out, so it sits behind the seam with the rest
        of the live layer.  ``None`` on either side of an iteration leaves
        ``host_network_changes`` unbound and therefore NOT-RUN.
        """
        return None

    def confine(self) -> None:
        """Drop the ability to gain privilege before anything is spawned.

        :func:`repeat` calls this once, under ``--apply`` only, after the
        preconditions pass and before the first capture or phase.  The base
        does nothing, so a test driver never changes the test process; the
        real driver sets ``PR_SET_NO_NEW_PRIVS``.  A driver that does not
        confine leaves ``NoNewPrivs: 0`` in every host-network snapshot, which
        keeps the forwarding counter unproven rather than faking it.
        """

    def bind_inputs(self, *, releases: Path | None, media_seal: Path) -> None:
        """Pin the live inputs; fixture drivers have no external inputs."""

    def check_inputs(self) -> dict | None:
        """Current input identity, or no external inputs for a fixture driver."""
        return None


class SubprocessLifecycle(LifecycleDriver):
    """Drive the real Make targets; completed twice-through on 2026-10-01.

    This class is the live process boundary of gate 12's driver: the
    ``rmtree`` below and the two ``subprocess.run`` calls per phase.  Its argv
    construction lives in :func:`prepare_command` / :func:`run_command`, which
    are pure and tested, and the bundle a prepare step produces is read from
    the last non-empty line of its standard output, which is how every
    ``*-prepare`` runner reports it (``print(prepare(args))``).

    The ``PHASES`` table has been confirmed against the live lifecycle.
    No phase target or runner invokes a host privilege helper (reviewed
    2026-09-30: no host ``sudo``, ``pkexec``, ``fusermount`` or bridge helper;
    the ``sudo`` strings in the
    runners are typed into guests); the completed live repeat exercised
    :meth:`confine` before its captures and phase commands.
    """

    def __init__(self, *, repository: Path = REPOSITORY,
                 stream=sys.stdout) -> None:
        self.repository = Path(repository)
        self.stream = stream
        # Injectable so unit tests never read the lab's lock or see a live
        # guest on the host.
        self.simulation_lock = (
            self.repository / CANONICAL_CONTROLLER_DISK.parent
            / ".simulation.lock")
        self.qemu_running = lambda: subprocess.run(
            ["pgrep", "-u", str(os.geteuid()), "-f", "^qemu-system-"],
            capture_output=True).returncode == 0
        self._expected_inputs: dict | None = None
        self._input_paths: tuple[Path, Path, Path] | None = None

    def bind_inputs(self, *, releases: Path | None, media_seal: Path) -> None:
        # Install prepare targets currently route only their default PXE root.
        # Refuse a verifier-only override instead of grading a different set.
        served = (self.repository / DEFAULT_RELEASES).resolve()
        requested = None if releases is None else Path(releases).resolve()
        if requested != served:
            raise RepeatError("live repeat serves only the default PXE root "
                              f"{served}; --releases cannot select a different served root")
        cache = Path(os.environ.get("TELOS_SAMBA_DNS_CACHE", str(
            self.repository / "homelab/var/media/samba-dns"))).resolve()
        self._input_paths = (served, Path(media_seal).resolve(), cache)
        selected = factory_verify.pxe_release_set.selected_release_set(served)
        problems = factory_verify.pxe_release_set.verify(selected)
        if problems:
            raise RepeatError("selected release does not verify: " + "; ".join(problems))
        self._expected_inputs = self._current_inputs()

    def _current_inputs(self) -> dict:
        if self._input_paths is None:
            raise RepeatError("live repeat inputs were not pinned")
        try:
            from .controller_factory import dns_repair_identity
            from ..lib import samba_dns
        except ImportError:
            from controller_factory import dns_repair_identity
            sys.path.insert(0, str(self.repository / "homelab/lib"))
            import samba_dns
        releases, seal_path, cache = self._input_paths
        try:
            selected = factory_verify.pxe_release_set.selected_release_set(releases)
            aggregate = json.loads(_read_regular(selected / "release-set.json"))
            seal_raw = _read_regular(seal_path)
            seal = json.loads(seal_raw)
            seal_digest = hashlib.sha256(seal_raw).hexdigest()
            if aggregate.get("media_seal_sha256") != seal_digest:
                raise RepeatError("selected release is not bound to the current media seal")
            repair = samba_dns.verify(cache)
            identity = dns_repair_identity(cache)
            if repair.get("library_sha256") != identity["library_sha256"]:
                raise RepeatError("DNS repair changed after verification")
            if json.loads(_read_regular(cache / "receipt.json")) != repair:
                raise RepeatError("DNS repair receipt changed after verification")
            provenance = seal.get("provenance", {})
            records = seal.get("content", []) + provenance.get("records", [])
            for name, key in (("samba-dns-library", "library_sha256"),
                              ("samba-dns-receipt", "receipt_sha256")):
                matches = [record for record in records if record.get("name") == name]
                if len(matches) != 1 or matches[0].get("sha256") != identity[key]:
                    raise RepeatError(f"{name} differs from the selected release's media seal")
            if provenance.get("assertions", {}).get("samba_dns") != repair:
                raise RepeatError("DNS repair provenance differs from the media seal")
            return {
                "release_set": {"version": aggregate["version"],
                    "manifest_sha256": hashlib.sha256(_read_regular(selected / "release-set.json")).hexdigest()},
                "media_seal_sha256": seal_digest,
                "samba_dns": identity,
            }
        except (OSError, ValueError, TypeError, KeyError, AttributeError, RuntimeError) as exc:
            raise RepeatError(f"live factory inputs do not verify: {exc}") from exc

    def check_inputs(self) -> dict:
        if self._expected_inputs is None:
            raise RepeatError("live repeat inputs were not pinned")
        current = self._current_inputs()
        if current != self._expected_inputs:
            raise RepeatError("live factory inputs changed during the repeat")
        return current

    def destroy(self, workdir: Path) -> None:
        workdir = Path(workdir)
        if workdir.is_symlink():
            raise RepeatError(f"disposable work root must not be a symlink: {workdir}")
        shutil.rmtree(workdir, ignore_errors=True)
        simulation_evidence.private_directory(workdir)

    #: How long a step waits for the previous step's guests and Controller
    #: lock to be released before it starts anyway (and fails honestly).
    QUIESCE_SECONDS = 120.0

    def _await_quiescent(self) -> None:
        """Wait until no QEMU guest runs and the simulation lock is free.

        Consecutive phases start within seconds of each other; on 2026-10-01
        an arch-install step failed 20 s after the identity phase ended, and
        the same step passed when rerun on an idle lab. Bounded: after
        ``QUIESCE_SECONDS`` the step runs and reports its own refusal.
        """
        import fcntl

        lock = Path(self.simulation_lock)
        deadline = time.monotonic() + self.QUIESCE_SECONDS
        while time.monotonic() < deadline:
            busy = self.qemu_running()
            free = True
            if lock.exists():
                with lock.open("a+b") as stream:
                    try:
                        fcntl.flock(stream.fileno(),
                                    fcntl.LOCK_EX | fcntl.LOCK_NB)
                        fcntl.flock(stream.fileno(), fcntl.LOCK_UN)
                    except BlockingIOError:
                        free = False
            if not busy and free:
                return
            time.sleep(2.0)
        print("warning: the lab did not quiesce before the next step",
              file=self.stream)

    def _run(self, command: list[str], log: Path | None = None) -> str:
        self._await_quiescent()
        print(f"$ {' '.join(command)}", file=self.stream)
        completed = subprocess.run(
            command, cwd=self.repository, capture_output=True, text=True,
            env=self._phase_environment())
        kept = b""
        if log is not None:
            # Every step's own output, redacted then bounded, beside its
            # bundle: a 2026-10-01 run failed with only "lifecycle step failed
            # (2)" because the captured output was discarded.
            combined = (completed.stdout + completed.stderr).encode(
                "utf-8", "replace")
            kept, _sizes = simulation_evidence.redact_and_bound(combined)
            simulation_evidence.private_file(Path(log), kept)
        if completed.returncode != 0:
            tail = "\n".join(
                kept.decode("utf-8", "replace").splitlines()[-15:])
            raise RepeatError(
                f"lifecycle step failed ({completed.returncode}): "
                f"{' '.join(command)}"
                + (f"\nstep output: {log}\n{tail}" if log is not None
                   else ""))
        return completed.stdout

    def _phase_environment(self) -> dict[str, str]:
        environment = dict(os.environ)
        if self._expected_inputs is not None:
            try:
                from .controller_factory import DNS_REPAIR_EXPECTED_ENV
                from .factory_publication import RELEASE_EXPECTED_ENV
            except ImportError:
                from controller_factory import DNS_REPAIR_EXPECTED_ENV
                from factory_publication import RELEASE_EXPECTED_ENV
            environment[DNS_REPAIR_EXPECTED_ENV] = json.dumps(
                self._expected_inputs["samba_dns"], sort_keys=True)
            environment[RELEASE_EXPECTED_ENV] = json.dumps({
                **self._expected_inputs["release_set"],
                "media_seal_sha256": self._expected_inputs["media_seal_sha256"],
            }, sort_keys=True)
            assert self._input_paths is not None
            # The inner Makefile derives TELOS_SAMBA_DNS_CACHE from this
            # variable; carry the same cache the driver actually inspected.
            environment["SAMBA_DNS_CACHE"] = str(self._input_paths[2])
            environment["TELOS_SAMBA_DNS_CACHE"] = str(self._input_paths[2])
        return environment

    def run_phase(self, phase: Phase, *, workdir: Path,
                  bundles: dict[str, Path], duration: float) -> Path:
        command = prepare_command(phase, bundles)
        if command is None:
            bundle = Path(workdir) / phase.name
            simulation_evidence.private_directory(bundle.parent)
        else:
            lines = [line.strip() for line in self._run(
                command, Path(workdir) / f"{phase.name}-prepare.log").splitlines()]
            reported = [line for line in lines if line]
            if not reported:
                raise RepeatError(f"{phase.prepare_target} reported no bundle path")
            bundle = Path(reported[-1])
        try:
            self._run(run_command(phase, bundle, duration=duration),
                      Path(workdir) / f"{phase.name}-run.log")
        except RepeatError as error:
            raise PhaseFailed(phase.name, bundle, str(error)) from error
        return bundle

    def capture_host_network(self):
        module = _optional_module("host_network_evidence")
        capture = getattr(module, "capture", None)
        return None if capture is None else capture()

    def confine(self) -> None:
        set_no_new_privileges()


def failure_category(phase: Phase, bundle: Path) -> str | None:
    """The machine-readable ``failure_category`` a failed bundle recorded."""
    evidence = phase_evidence(phase, bundle)
    if evidence is None:
        return None
    category = read_phase_result(evidence).get("failure_category")
    return category if isinstance(category, str) else None


def run_phase_bounded(driver: LifecycleDriver, phase: Phase, *,
                      iteration: int, workdir: Path,
                      bundles: dict[str, Path], duration: float,
                      retries: list[dict]) -> Path:
    """Run one phase, retrying it at most ONCE on a retryable failure.

    Only a :class:`PhaseFailed` whose bundle recorded a category
    :data:`RETRYABLE_FAILURES` lists for this phase is retried, with a fresh
    bundle; anything else propagates exactly as before.  A retry that fails
    again fails the iteration -- there is never a second retry.  A successful
    retry is appended to ``retries``.
    """
    try:
        return Path(driver.run_phase(
            phase, workdir=workdir, bundles=bundles, duration=duration))
    except PhaseFailed as failure:
        category = failure_category(phase, failure.bundle)
        if category not in RETRYABLE_FAILURES.get(phase.name, ()):
            raise
        record = {"iteration": iteration, "phase": phase.name,
                  "failed_bundle": str(failure.bundle), "category": category}
    print(f"retry: iteration {iteration} {phase.name} hit {category} in "
          f"{record['failed_bundle']}; preparing a fresh bundle for its one "
          "retry", file=sys.stderr)
    try:
        bundle = Path(driver.run_phase(
            phase, workdir=workdir, bundles=bundles, duration=duration))
    except PhaseFailed as again:
        raise RepeatError(
            f"phase {phase.name} failed again after its one {category} retry "
            f"in iteration {iteration} (first {record['failed_bundle']}, "
            f"retry {again.bundle}): {again}") from again
    retries.append(dict(record, retry_bundle=str(bundle)))
    return bundle


def run_iteration(index: int, *, driver: LifecycleDriver, workdir: Path,
                  destination: Path, bind: Callable[..., Producers] = None,
                  phases: Sequence[Phase] = PHASES,
                  duration: float = DEFAULT_DURATION,
                  diagnostics: Path | None = None) -> Path:
    """Run one whole lifecycle from destroyed state into one aggregate bundle.

    Driver-agnostic and unit tested with a fake driver: the destroy call, the
    phase order, the measurement assembly, the aggregate status and the
    re-retention all happen here, and only the driver itself is live.

    ``bind`` receives the finished bundles, the phase table and the two
    host-network captures and returns the :class:`Producers` for THIS
    iteration, because the identity evidence a login measurement reads and
    the evidence the artifact scan reads only exist once the phases have run.
    """
    bind = default_producer_binding if bind is None else bind
    inputs = driver.check_inputs()
    before = driver.capture_host_network()
    if diagnostics is not None:
        _retain_network_snapshot(before, Path(diagnostics) / "before.json")
    driver.destroy(workdir)
    bundles: dict[str, Path] = {}
    observations: list[dict] = []
    blocks: list[tuple[str, dict]] = []
    evidence_pairs: list[tuple[str, Path]] = []
    retries: list[dict] = []
    for phase in phases:
        if driver.check_inputs() != inputs:
            raise RepeatError("factory inputs changed before a lifecycle phase")
        bundle = run_phase_bounded(
            driver, phase, iteration=index, workdir=workdir, bundles=bundles,
            duration=duration, retries=retries)
        if driver.check_inputs() != inputs:
            raise RepeatError("factory inputs changed during a lifecycle phase")
        bundles[phase.name] = bundle
        evidence = phase_evidence(phase, bundle)
        observation = {"phase": phase.name, "status": None,
                       "status_required": phase.result and evidence is not None,
                       "evidence": None if evidence is None else str(evidence)}
        if evidence is not None:
            result = read_phase_result(evidence)
            observation["status"] = result.get("status")
            measurements = result.get("measurements")
            if isinstance(measurements, dict):
                blocks.append((phase.name, measurements))
            evidence_pairs.append((phase.name, evidence))
        observations.append(observation)
    after = driver.capture_host_network()
    if diagnostics is not None:
        _retain_network_snapshot(after, Path(diagnostics) / "after.json")
    producers = bind(bundles, phases=phases, network_before=before,
                     network_after=after)
    measurements = assemble_measurements(blocks, producers=producers)
    result = aggregate_result(
        iteration=index, observations=observations, measurements=measurements,
        retries=retries)
    if inputs is not None:
        result["factory_inputs"] = inputs
    return retain_aggregate_evidence(destination, evidence_pairs, result=result)


def _plan(stream, *, iterations: int, evidence_root: Path, work_root: Path,
          releases: Path | None, receipt: Path | None, phases: Sequence[Phase],
          availability: dict[str, bool], problems: Sequence[str]) -> None:
    print("Boundary: loopback-only; no host, UniFi, or physical change",
          file=stream)
    print(f"Iterations: {iterations} (gate 12 requires at least "
          f"{MINIMUM_ITERATIONS})", file=stream)
    print(f"Aggregate evidence root: {evidence_root}", file=stream)
    print(f"Disposable work root (destroyed before each iteration): {work_root}",
          file=stream)
    print(f"Release root: {releases} (each receipt verifies the set its "
          "selected-release-set.json names)", file=stream)
    if receipt is not None:
        print(f"Receipt: {receipt} (mode 0600)", file=stream)
    print("Lifecycle phases, in order:", file=stream)
    for phase in phases:
        print(f"  - {phase.name} ({phase.run_target})", file=stream)
    available = [name for name in PRODUCED_KEYS if availability.get(name)]
    print("Producer measurements available: "
          + (", ".join(available) if available else "none"), file=stream)
    for name in PRODUCED_KEYS:
        if not availability.get(name):
            module, attribute = PRODUCER_ENTRY_POINTS[name]
            print(f"  ! {name} has no producer ({module}.{attribute}); "
                  "it will stay NOT-RUN", file=stream)
    print("Privilege: --apply sets no_new_privs before the first capture or "
          "phase; with an unreadable nft ruleset, forwarding is proven only by "
          "privilege (the run could not change it), never as 'nothing changed'",
          file=stream)
    waiver = factory_verify.HOST_NETWORK_WAIVER
    print(f"Waiver: {waiver['adr']} covers only the host_network_changes "
          f"{', '.join(waiver['covers'])} counter; every other counter must be "
          "a proven zero, and a waived run renders PASS-WITH-WAIVER, never PASS",
          file=stream)
    for problem in problems:
        print(f"  ! refuses to apply: {problem}", file=stream)


def repeat(*, evidence_root: Path = DEFAULT_EVIDENCE_ROOT,
           work_root: Path = DEFAULT_WORK_ROOT,
           releases: Path | None = DEFAULT_RELEASES,
           media_seal: Path = DEFAULT_MEDIA_SEAL,
           iterations: int = DEFAULT_ITERATIONS,
           duration: float = DEFAULT_DURATION,
           apply: bool = False,
           receipt: Path | None = None,
           reuse_iteration: Path | None = None,
           controller_disk: Path = CANONICAL_CONTROLLER_DISK,
           driver: LifecycleDriver | None = None,
           bind: Callable[..., Producers] | None = None,
           phases: Sequence[Phase] = PHASES,
           stream=None) -> int:
    """Plan or perform the gate-12 repeat.  Dry run unless ``apply``."""
    stream = sys.stdout if stream is None else stream
    bind = default_producer_binding if bind is None else bind
    evidence_root = Path(evidence_root)
    work_root = Path(work_root)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    run_root = evidence_root / f"{stamp}-{os.getpid()}-repeat"
    problems = preflight(iterations=iterations, controller_disk=controller_disk,
                         releases=releases)
    if (evidence_root.resolve().is_relative_to(work_root.resolve())
            or work_root.resolve().is_relative_to(evidence_root.resolve())):
        problems.append("aggregate evidence and disposable work roots must not overlap")
    if receipt is not None:
        output = Path(receipt).resolve()
        if (output.is_relative_to(work_root.resolve())
                or any(output.is_relative_to((run_root / f"iteration-{index}").resolve())
                       for index in range(1, iterations + 1))):
            problems.append("receipt must be outside disposable work and generated aggregates")
    reused = None
    if reuse_iteration is not None:
        prior = Path(reuse_iteration).absolute()
        try:
            if (tuple(phases) != PHASES
                    or prior.resolve().is_relative_to(Path(work_root).resolve())
                    or Path(work_root).resolve().is_relative_to(prior.resolve())
                    or evidence_root.resolve().is_relative_to(prior.resolve())):
                raise RepeatError("reuse requires all six phases and disjoint prior/new work and evidence")
            if receipt is not None and (Path(receipt).exists() or Path(receipt).is_symlink()
                    or Path(receipt).resolve().is_relative_to(prior.resolve())):
                raise RepeatError("recovery receipt must be a new path outside reused evidence")
            verified, fingerprint, prior_retries = checked_reused_iteration(prior, releases=releases)
            reused = (prior, verified, fingerprint, prior_retries)
        except RepeatError as error:
            problems.append(str(error))
    # A dry run's whole output IS the plan, so it belongs on standard output.
    # An apply's standard output is the receipt document and nothing else --
    # the same split ``factory_verify`` uses -- so the plan narrates on stderr.
    _plan(stream if not apply else sys.stderr,
          iterations=iterations, evidence_root=evidence_root,
          work_root=work_root, releases=releases, receipt=receipt,
          phases=phases, availability=producer_availability(),
          problems=problems)
    if reuse_iteration is not None:
        print(f"Reuse candidate: {reuse_iteration}; run {iterations - 1} new lifecycle(s)",
              file=stream if not apply else sys.stderr)
    if not apply:
        print("dry run; repeat with --apply to run the lifecycle "
              f"{iterations - (reuse_iteration is not None)} times and compare the receipts", file=stream)
        return 0
    if problems:
        for problem in problems:
            print(f"refusing to run the lifecycle: {problem}", file=sys.stderr)
        return 2

    if driver is None:
        driver = SubprocessLifecycle(stream=stream)
    # Before anything is spawned -- the first host-network capture shells out
    # too -- so every process of the run inherits it and the forwarding
    # proof's start-of-run facts are read after it holds.
    driver.confine()
    driver.bind_inputs(releases=releases, media_seal=media_seal)
    if reused is not None and driver.check_inputs() != reused[1]["factory_inputs"]:
        raise RepeatError("live factory_inputs differ from the reused iteration")
    simulation_evidence.private_directory(run_root)
    receipts = [] if reused is None else [reused[1]]
    retries: list[dict] = [] if reused is None else list(reused[3])
    sources = [] if reused is None else [{
        "kind": "reused", "evidence": str(reused[0]), "sha256": reused[2]}]
    for index in range(len(receipts) + 1, iterations + 1):
        destination = run_iteration(
            index, driver=driver, workdir=work_root / f"iteration-{index}",
            destination=run_root / f"iteration-{index}", bind=bind,
            phases=phases, duration=duration,
            diagnostics=run_root / "diagnostics" / f"iteration-{index}")
        # Read back from the retained evidence, so the receipt discloses
        # exactly the retries the iteration's own result.json records.
        retries.extend(read_phase_result(destination).get("retries") or ())
        # ``releases`` is the PXE release ROOT, so the verifier resolves the
        # set its selection descriptor names; handing the root over as the set
        # failed check 16 in both iterations of the 2026-10-01 live repeat.
        verified = factory_verify.verify_run(destination, releases=releases)
        # Keep the actual consumed inputs in both retained iteration evidence
        # and the compared receipt. Historical verifier behavior is unchanged.
        inputs = read_phase_result(destination).get("factory_inputs")
        if inputs is not None:
            verified["factory_inputs"] = inputs
        if reused is not None and inputs != reused[1]["factory_inputs"]:
            raise RepeatError("new iteration factory_inputs differ from the reused iteration")
        driver.check_inputs()
        receipts.append(verified)
        if reused is not None:
            sources.append({"kind": "new", "evidence": str(destination.absolute()),
                            "sha256": _snapshot_digest(_evidence_snapshot(destination))})
    if reused is not None:
        checked, fingerprint, prior_retries = checked_reused_iteration(reused[0], releases=releases)
        if checked != reused[1] or fingerprint != reused[2] or prior_retries != reused[3]:
            raise RepeatError("reused iteration changed before the recovery receipt")
        if driver.check_inputs() != reused[1]["factory_inputs"]:
            raise RepeatError("live factory_inputs changed before the recovery receipt")
        if receipt is not None and (Path(receipt).exists() or Path(receipt).is_symlink()):
            raise RepeatError("recovery receipt already exists; original evidence is preserved")
    comparisons = compare_iterations(receipts)
    document = repeat_receipt(receipts, comparisons, retries=retries)
    if reused is not None:
        document["sources"] = sources
    print(factory_verify.render_receipt(document), end="", file=stream)
    if receipt is not None:
        factory_verify.write_receipt(document, receipt)
        print(f"receipt written: {receipt}", file=sys.stderr)
    for retry in document["retries"]:
        print(f"retried: iteration {retry['iteration']} {retry['phase']} "
              f"after {retry['category']} (failed bundle "
              f"{retry['failed_bundle']}, retry bundle "
              f"{retry['retry_bundle']})", file=sys.stderr)
    print(f"{document['verdict']}: factory-repeat iterations="
          f"{document['iterations']} equivalent={document['equivalent']} "
          f"retries={len(document['retries'])}"
          f"{factory_verify.waiver_note(document['waivers'])}",
          file=sys.stderr)
    for prerequisite in document["prerequisites"]:
        if prerequisite["status"] != factory_verify.PASS:
            print(f"blocked: iteration {prerequisite['iteration']} "
                  f"{prerequisite['gate']}: {prerequisite['detail']}",
                  file=sys.stderr)
    return 0 if document["verdict"] in ACCEPTED_VERDICTS else 1


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    result.add_argument("--evidence-root", type=Path,
                        default=DEFAULT_EVIDENCE_ROOT,
                        help="root for the aggregate per-iteration evidence")
    result.add_argument("--work-root", type=Path, default=DEFAULT_WORK_ROOT,
                        help="disposable state, destroyed before each iteration")
    result.add_argument("--releases", type=Path, default=DEFAULT_RELEASES,
                        help="PXE release root; live runs currently require "
                             "the default root served by the prepare targets")
    result.add_argument("--iterations", type=int, default=DEFAULT_ITERATIONS,
                        help=f"total lifecycles, including reuse (at least {MINIMUM_ITERATIONS})")
    result.add_argument("--reuse-iteration", type=Path, default=None,
                        help="reverify one complete retained iteration and run the remaining cycles fresh")
    result.add_argument("--media-seal", type=Path, default=DEFAULT_MEDIA_SEAL,
                        help="current media seal the selected set and repair must match")
    result.add_argument("--duration", type=float, default=DEFAULT_DURATION,
                        help="per-phase runtime budget in seconds")
    result.add_argument("--controller-disk", type=Path,
                        default=CANONICAL_CONTROLLER_DISK,
                        help="canonical Controller image the preconditions read")
    result.add_argument("--receipt", type=Path, default=None,
                        help="persist the repeat receipt here, mode 0600")
    result.add_argument("--apply", action="store_true",
                        help="actually run the lifecycle; refuses while a "
                             "precondition fails")
    return result


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    return repeat(
        evidence_root=args.evidence_root, work_root=args.work_root,
        releases=args.releases, iterations=args.iterations,
        media_seal=args.media_seal,
        duration=args.duration, apply=args.apply, receipt=args.receipt,
        reuse_iteration=args.reuse_iteration,
        controller_disk=args.controller_disk)


if __name__ == "__main__":
    raise SystemExit(main())
