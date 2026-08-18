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

What has never run
------------------
The honest boundary.  Everything above -- assembly, merging, retention
planning, aggregation, verification and comparison -- is exercised by
``homelab/tests/test_factory_repeat.py`` against fabricated bundles and the
real :func:`factory_verify.verify_run`.  What has NEVER run is:

* :class:`SubprocessLifecycle` -- the eleven ``subprocess.run`` calls that
  actually drive the Make targets, and the ``rmtree`` that destroys disposable
  state between iterations.  Its argv construction is pure and tested
  (:func:`prepare_command`, :func:`run_command`); only the process spawning is
  not, and the ``PHASES`` argv table has never been confirmed against a live
  lifecycle.
* Consequently, gate 12 itself.  Two live lifecycles are the only thing that
  can prove repeatability, and they cannot run today: the canonical Controller
  image ``build/homelab/vm/bootstrap-dc/bootstrap-dc.qcow2`` is an empty,
  never-installed disk.  ``--apply`` refuses on that precondition
  (:func:`controller_image_problem`), which is a real check against the file
  rather than a comment.

The seam is arranged so the untested layer is as thin as it can be:
:meth:`LifecycleDriver.run_phase` returns a bundle path and
:meth:`LifecycleDriver.destroy` removes disposable state, and everything else
in :func:`run_iteration` and :func:`repeat` is driver-agnostic and tested with
a fake.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import stat
import subprocess
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Iterable, Sequence

try:
    from . import factory_runner, factory_verify, simulation_evidence
except ImportError:  # Direct execution from homelab/vm.
    import factory_runner  # type: ignore[no-redef]
    import factory_verify  # type: ignore[no-redef]
    import simulation_evidence  # type: ignore[no-redef]


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

#: The canonical Controller disk every live phase boots or copies.
CANONICAL_CONTROLLER_DISK = Path("build/homelab/vm/bootstrap-dc/bootstrap-dc.qcow2")
#: A never-installed 80 GiB qcow2 holds only its own header and L1 table --
#: measured at 197,888 bytes on this host.  An installed Controller (Arch plus
#: Samba AD, Kerberos, DNS and the PXE tree) is gigabytes.  Anything under this
#: floor cannot possibly contain an installation, so the precondition reads the
#: real file rather than trusting a manifest that an empty disk also carries.
INSTALLED_DISK_MINIMUM_BYTES = 1 << 30

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
    re.compile(r"\Aworkstation-stall-\d+\.ppm\Z"),
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
    "artifact_scan": ("artifact_scan", "scan_artifacts"),
}
PRODUCED_KEYS = tuple(PRODUCER_ENTRY_POINTS)

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
          sources=(SourceRef("WINDOWS_RUN", "windows-install"),)),
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


def bind_producers(*, windows_evidence: Path | None = None,
                   arch_evidence: Path | None = None,
                   repository: Path = REPOSITORY,
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
        host_network_changes=_producer(
            "host_network_changes",
            lambda f: f(network_before, network_after),
            tolerate="UnprovenCategory")
        if network_before is not None and network_after is not None else None,
        login=_producer(
            "login",
            lambda f: f(windows_evidence, arch_evidence)) if identity else None,
        optional_storage_absence_nonblocking=_producer(
            "optional_storage_absence_nonblocking",
            lambda f: f(windows_evidence, arch_evidence)) if identity else None,
        artifact_scan=_producer(
            "artifact_scan",
            lambda f: f(repository)),
    )


def default_producer_binding(bundles: dict[str, Path], *,
                             network_before=None, network_after=None,
                             repository: Path = REPOSITORY) -> Producers:
    """Bind the producers to one finished iteration's phase bundles."""
    windows = bundles.get("windows-identity")
    arch = bundles.get("arch-identity")
    return bind_producers(
        windows_evidence=(
            None if windows is None
            else Path(windows) / WINDOWS_IDENTITY_EVIDENCE),
        arch_evidence=(
            None if arch is None else Path(arch) / ARCH_IDENTITY_EVIDENCE),
        repository=repository,
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


def _read_regular(path: Path) -> bytes:
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            raise RepeatError(f"{path} is not a regular file")
        chunks = []
        while True:
            chunk = os.read(descriptor, 1 << 20)
            if not chunk:
                break
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
    into a pass.

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
                     measurements: dict) -> dict:
    """The aggregate ``result.json`` body for one iteration."""
    status = aggregate_status(observations, measurements)
    return {
        "schema": SCHEMA,
        "kind": "factory-repeat-iteration",
        "status": status,
        "iteration": iteration,
        "phases": [dict(observation) for observation in observations],
        "measurements": measurements,
        "measurements_missing": missing_measurements(measurements),
    }


def repeat_verdict(receipts: Sequence[dict], comparisons: Sequence[dict]) -> str:
    """The gate-12 verdict: every run must pass AND every pair must agree."""
    if any(comparison["divergent_count"] for comparison in comparisons):
        return factory_verify.FAIL
    verdicts = {receipt["verdict"] for receipt in receipts}
    if factory_verify.FAIL in verdicts:
        return factory_verify.FAIL
    if factory_verify.NOT_RUN in verdicts:
        return factory_verify.NOT_RUN
    return factory_verify.PASS


def repeat_receipt(receipts: Sequence[dict],
                   comparisons: Sequence[dict]) -> dict:
    """The whole-gate receipt: N run receipts plus their pairwise comparisons."""
    if len(receipts) < MINIMUM_ITERATIONS:
        raise RepeatError(
            f"gate 12 needs at least {MINIMUM_ITERATIONS} iterations; "
            f"{len(receipts)} were verified")
    return {
        "schema": SCHEMA,
        "kind": "factory-repeat",
        "iterations": len(receipts),
        "verdict": repeat_verdict(receipts, comparisons),
        "equivalent": all(comparison["equivalent"] for comparison in comparisons),
        "runs": list(receipts),
        "comparisons": list(comparisons),
        "needs_live_gate": sorted(
            {name for receipt in receipts for name in receipt["needs_live_gate"]}),
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
    return problems


# --------------------------------------------------------------------------
# Orchestration -- the thin, never-executed layer
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
        """Prepare and execute one phase; return its bundle directory."""
        raise NotImplementedError

    def capture_host_network(self):
        """Host networking state, or ``None`` when it cannot be captured.

        Read-only, but it shells out, so it sits behind the seam with the rest
        of the live layer.  ``None`` on either side of an iteration leaves
        ``host_network_changes`` unbound and therefore NOT-RUN.
        """
        return None


class SubprocessLifecycle(LifecycleDriver):
    """HAS NEVER RUN.  Drives the real Make targets in a real repository.

    This class is the entire untested surface of gate 12's driver: the
    ``rmtree`` below and the two ``subprocess.run`` calls per phase.  Its argv
    construction lives in :func:`prepare_command` / :func:`run_command`, which
    are pure and tested, and the bundle a prepare step produces is read from
    the last non-empty line of its standard output, which is how every
    ``*-prepare`` runner reports it (``print(prepare(args))``).

    The ``PHASES`` table it walks has been read off the Makefile but never
    confirmed against a live lifecycle; when the first real repeat runs, that
    table and this class are where the corrections land.
    """

    def __init__(self, *, repository: Path = REPOSITORY,
                 stream=sys.stdout) -> None:
        self.repository = Path(repository)
        self.stream = stream

    def destroy(self, workdir: Path) -> None:
        workdir = Path(workdir)
        if workdir.is_symlink():
            raise RepeatError(f"disposable work root must not be a symlink: {workdir}")
        shutil.rmtree(workdir, ignore_errors=True)
        simulation_evidence.private_directory(workdir)

    def _run(self, command: list[str]) -> str:
        print(f"$ {' '.join(command)}", file=self.stream)
        completed = subprocess.run(
            command, cwd=self.repository, capture_output=True, text=True)
        if completed.returncode != 0:
            raise RepeatError(
                f"lifecycle step failed ({completed.returncode}): "
                f"{' '.join(command)}")
        return completed.stdout

    def run_phase(self, phase: Phase, *, workdir: Path,
                  bundles: dict[str, Path], duration: float) -> Path:
        command = prepare_command(phase, bundles)
        if command is None:
            bundle = Path(workdir) / phase.name
            simulation_evidence.private_directory(bundle.parent)
        else:
            lines = [line.strip() for line in self._run(command).splitlines()]
            reported = [line for line in lines if line]
            if not reported:
                raise RepeatError(f"{phase.prepare_target} reported no bundle path")
            bundle = Path(reported[-1])
        self._run(run_command(phase, bundle, duration=duration))
        return bundle

    def capture_host_network(self):
        module = _optional_module("host_network_evidence")
        capture = getattr(module, "capture", None)
        return None if capture is None else capture()


def run_iteration(index: int, *, driver: LifecycleDriver, workdir: Path,
                  destination: Path, bind: Callable[..., Producers] = None,
                  phases: Sequence[Phase] = PHASES,
                  duration: float = DEFAULT_DURATION) -> Path:
    """Run one whole lifecycle from destroyed state into one aggregate bundle.

    Driver-agnostic and unit tested with a fake driver: the destroy call, the
    phase order, the measurement assembly, the aggregate status and the
    re-retention all happen here, and only the driver itself is live.

    ``bind`` receives the finished bundles and the two host-network captures
    and returns the :class:`Producers` for THIS iteration, because the identity
    evidence a login measurement reads only exists once the phases have run.
    """
    bind = default_producer_binding if bind is None else bind
    before = driver.capture_host_network()
    driver.destroy(workdir)
    bundles: dict[str, Path] = {}
    observations: list[dict] = []
    blocks: list[tuple[str, dict]] = []
    evidence_pairs: list[tuple[str, Path]] = []
    for phase in phases:
        bundle = Path(driver.run_phase(
            phase, workdir=workdir, bundles=bundles, duration=duration))
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
    producers = bind(bundles, network_before=before,
                     network_after=driver.capture_host_network())
    measurements = assemble_measurements(blocks, producers=producers)
    result = aggregate_result(
        iteration=index, observations=observations, measurements=measurements)
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
    print(f"Release set: {releases}", file=stream)
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
    for problem in problems:
        print(f"  ! refuses to apply: {problem}", file=stream)


def repeat(*, evidence_root: Path = DEFAULT_EVIDENCE_ROOT,
           work_root: Path = DEFAULT_WORK_ROOT,
           releases: Path | None = DEFAULT_RELEASES,
           iterations: int = DEFAULT_ITERATIONS,
           duration: float = DEFAULT_DURATION,
           apply: bool = False,
           receipt: Path | None = None,
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
    problems = preflight(iterations=iterations, controller_disk=controller_disk,
                         releases=releases)
    # A dry run's whole output IS the plan, so it belongs on standard output.
    # An apply's standard output is the receipt document and nothing else --
    # the same split ``factory_verify`` uses -- so the plan narrates on stderr.
    _plan(stream if not apply else sys.stderr,
          iterations=iterations, evidence_root=evidence_root,
          work_root=work_root, releases=releases, receipt=receipt,
          phases=phases, availability=producer_availability(),
          problems=problems)
    if not apply:
        print("dry run; repeat with --apply to run the lifecycle "
              f"{iterations} times and compare the receipts", file=stream)
        return 0
    if problems:
        for problem in problems:
            print(f"refusing to run the lifecycle: {problem}", file=sys.stderr)
        return 2

    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    run_root = evidence_root / f"{stamp}-{os.getpid()}-repeat"
    simulation_evidence.private_directory(run_root)
    receipts = []
    if driver is None:
        driver = SubprocessLifecycle(stream=stream)
    for index in range(1, iterations + 1):
        destination = run_iteration(
            index, driver=driver, workdir=work_root / f"iteration-{index}",
            destination=run_root / f"iteration-{index}", bind=bind,
            phases=phases, duration=duration)
        receipts.append(factory_verify.verify_run(
            destination, release_set=releases))
    comparisons = compare_iterations(receipts)
    document = repeat_receipt(receipts, comparisons)
    print(factory_verify.render_receipt(document), end="", file=stream)
    if receipt is not None:
        factory_verify.write_receipt(document, receipt)
        print(f"receipt written: {receipt}", file=sys.stderr)
    print(f"{document['verdict']}: factory-repeat iterations="
          f"{document['iterations']} equivalent={document['equivalent']}",
          file=sys.stderr)
    return 0 if document["verdict"] == factory_verify.PASS else 1


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    result.add_argument("--evidence-root", type=Path,
                        default=DEFAULT_EVIDENCE_ROOT,
                        help="root for the aggregate per-iteration evidence")
    result.add_argument("--work-root", type=Path, default=DEFAULT_WORK_ROOT,
                        help="disposable state, destroyed before each iteration")
    result.add_argument("--releases", type=Path, default=DEFAULT_RELEASES,
                        help="release-set root verified into every receipt")
    result.add_argument("--iterations", type=int, default=DEFAULT_ITERATIONS,
                        help=f"lifecycles to run (at least {MINIMUM_ITERATIONS})")
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
        duration=args.duration, apply=args.apply, receipt=args.receipt,
        controller_disk=args.controller_disk)


if __name__ == "__main__":
    raise SystemExit(main())
