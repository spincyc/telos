#!/usr/bin/env python3
"""Gate-12 acceptance verifier and two-run receipt comparator.

This module is pure, deterministic, and unprivileged.  It never boots a guest,
opens a socket, performs an installation, or modifies the evidence it reads;
the only files it ever writes are the two artifacts an operator explicitly
names OUTSIDE that evidence -- the standalone gate-4 audit JSON
(``--audit-json``) and the receipt itself (``--receipt``), both created mode
0600 and refusing to follow a symlink.
It reads one retained factory run's evidence (as produced by
``factory_runner.retain_evidence``) and produces a machine-readable receipt
that classifies every acceptance measurement it can check from evidence alone
as ``PASS``, ``FAIL``, or ``NOT-RUN``.  A measurement that was never recorded
stays ``NOT-RUN``; it is never promoted to ``PASS``.  Anything unreadable,
oversized, unexpected, or ambiguous fails closed to ``FAIL``.  One check has a
fourth state, ``WAIVED``, under ADR 0080 (see :data:`HOST_NETWORK_WAIVER`),
and a run whose only non-``PASS`` check is waived renders the distinct verdict
``PASS-WITH-WAIVER``, never ``PASS``.  The retained
*artifacts* are the files; the working trees a real run bundle keeps beside
them are accepted structurally and named in the receipt rather than inspected.

``compare_runs`` diffs two runs' receipts (including any embedded release-set
aggregate identity) and classifies every differing byte as either
content-equivalent expected nondeterminism or a genuine divergence, which is
the "explain any nondeterministic bytes" output the repeat gate requires.

Release-set integrity is delegated to :func:`pxe_release_set.verify`; it is
never reimplemented here.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import sys
from pathlib import Path

try:
    from homelab.lib import pxe_release_set
except ModuleNotFoundError as error:
    if error.name != "homelab":
        raise
    sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "lib"))
    import pxe_release_set  # type: ignore[no-redef]


SCHEMA = 1
# Mirrors factory_runner.EVIDENCE_LIMIT: no retained artifact may exceed it.
EVIDENCE_LIMIT = 1024 * 1024

PASS = "PASS"
FAIL = "FAIL"
NOT_RUN = "NOT-RUN"
#: A check state, never a verdict: the check could not be proven and an
#: accepted decision record waives exactly that gap.  It is distinct from
#: ``PASS`` (nothing was proven) and from ``NOT-RUN`` (the measurement exists).
WAIVED = "WAIVED"
#: The run verdict when every check passes except ones that are ``WAIVED``.
#: Distinct from ``PASS`` so a receipt can never be misread as full acceptance;
#: the receipt's ``waivers`` block names the decision record behind it.
PASS_WITH_WAIVER = "PASS-WITH-WAIVER"
VERDICTS = frozenset({PASS, PASS_WITH_WAIVER, FAIL, NOT_RUN})

# ``host_network_changes`` counters, all seven required by check 9.
HOST_NETWORK_CATEGORIES = (
    "tap", "bridge", "route", "vlan", "forwarding", "listener", "unifi")
#: Mirrors ``host_network_evidence.UNPROVEN`` (a test pins the equality): the
#: sentinel a producer puts in a counter slot no observation stands behind.
UNPROVEN_COUNTER = "unproven"

#: ADR 0080 (accepted 2026-09-30): the ``unifi`` contact counter cannot be
#: proven by any snapshot pair -- a connection can open and close between two
#: snapshots -- and only a run-window host egress ledger could prove it, which
#: nothing produces.  The owner waived it for the loopback factory, whose
#: runner conditions (ADR 0077) already confine every guest NIC to an audited
#: host-loopback hub.  The waiver covers exactly that one counter: every other
#: counter must still be a proven zero, an absent measurement stays NOT-RUN,
#: and the waiver lapses at gate 14, where a factory attached to a real network
#: must prove its egress directly.
HOST_NETWORK_WAIVER = {
    "adr": "ADR 0080",
    "covers": ["unifi"],
    "reason": (
        "the unifi contact counter is unprovable without a run-window host "
        "egress ledger; waived for the loopback factory until gate 14"),
}

#: How a ``host_network_changes`` producer may state a counter was proven
#: (``host_network_evidence.BASIS_SNAPSHOT``/``BASIS_PRIVILEGE``; a test pins
#: the equality).  ``snapshot`` compares observations of host state and proves
#: "nothing changed"; ``privilege`` proves only "the run could not change it",
#: and the owner accepted it on 2026-09-30 for ``forwarding`` alone, for a run
#: whose nft ruleset is unreadable.  A measurement without ``basis`` is read as
#: a snapshot proof, which is all any producer emitted before.  Any other
#: basis fails the check rather than being ignored.
HOST_NETWORK_BASES = {"forwarding": ("snapshot", "privilege")}
PRIVILEGE_BASIS = "privilege"

RESULT = "result.json"
# The read-only gate-4 audit receipt (homelab/vm/pxe_authority_audit.py) is a
# permitted finalization artifact when a run embeds it beside its evidence.
PXE_AUTHORITY_AUDIT = "pxe-authority-audit.json"
ALLOWED_EVIDENCE = frozenset(
    {RESULT, "controller-publication.log", "workstation-serial.log",
     "switch.jsonl", PXE_AUTHORITY_AUDIT}
)
LOG_FILES = ("controller-publication.log", "workstation-serial.log")

# Two honest pass vocabularies reach retained evidence, and the receipt names
# which one it read rather than flattening them:
#
#   "pass"     an aggregate whole-factory claim (factory_runner.retain_evidence)
#   "observed" one phase runner's own vocabulary for "this phase ran and its own
#              lifecycle validation held" -- arch_install_run,
#              windows_install_run, dualboot_acceptance, lifecycle_recovery, and
#              arch_identity_prepare.PASS_STATUS all record exactly this
#
# Accepting only "pass" made every real phase bundle FAIL for a vocabulary
# mismatch alone, which is neither a measurement nor a defect in the run.  An
# "observed" phase bundle is still a narrower assertion than a whole-factory
# "pass", so the check's detail and the receipt's ``run_status`` block say which
# was read; nothing upgrades "observed" into "pass".
AGGREGATE_PASS_STATUS = "pass"
PHASE_PASS_STATUS = "observed"
RUN_FAIL_STATUS = "fail"
PASS_STATUS_SCOPES = {
    AGGREGATE_PASS_STATUS: "aggregate",
    PHASE_PASS_STATUS: "phase",
}

# A credential-like token that survived redaction is a leak, not evidence.
#
# The post-delimiter run is same-line whitespace only (``[^\S\r\n]``, never
# ``\s``, which matches ``\r\n``).  With ``\s*`` a bare ``Password:`` prompt
# paired with the FIRST TOKEN OF THE NEXT LINE, and on real arch-install
# evidence that was a 100% false-positive rate: 12 of 23 retained bundles
# flagged, all 18 matches crossing a line boundary onto a shell-integration
# escape marker or the next console prompt.
#
# The residual gap is deliberate: a secret echoed on the line AFTER its label is
# no longer detected.  This scanner exists to catch what the redactor missed,
# and the redactors are same-line by construction
# (factory_runner._redact, simulation_evidence._SECRET), so a next-line match
# could never be remediated by redaction -- it produced permanent, unactionable
# FAILs that train an operator to ignore a fail-closed check.  The controls that
# do cover that shape are the guests' no-echo credential discipline and
# mode-0600 retention, not this regex.
_CREDENTIAL = re.compile(
    rb"(?i)(?:password|passphrase|token|secret)[^\S\r\n]*[:=]"
    rb"[^\S\r\n]*(?!\[REDACTED\])\S+"
)

# Arch is recorded either bare or as the full PXE target name.
_ARCH_NAMES = frozenset({"arch", "arch-workstation"})

# Receipt leaves whose per-run variation is expected and non-divergent.
_EXPECTED_VARYING = frozenset(
    {
        "evidence", "run", "run_id", "pid", "stamp", "timestamp",
        "started_at", "ended_at", "generated_at", "destination", "path",
    }
)

_ABSENT = "<absent>"

# A persisted receipt carries a whole run's evidence summary and must stay as
# private as the evidence it summarizes (factory_runner retains at 0600 too).
RECEIPT_MODE = 0o600


class VerifyError(RuntimeError):
    """Retained evidence is unreadable, unsafe, or oversized."""


def _record(status: str, detail: str) -> dict:
    return {"status": status, "detail": detail}


def _waived(detail: str, waiver: dict) -> dict:
    """A ``WAIVED`` check carrying the decision record that waives it.

    The waiver travels inside the check record, so ``compare_runs`` treats two
    iterations as agreeing only when both were waived for the same reason.
    """
    return {"status": WAIVED, "detail": detail,
            "waiver": {key: (list(value) if isinstance(value, list) else value)
                       for key, value in waiver.items()}}


def _safe_regular_bytes(path: Path, limit: int) -> bytes:
    """Read a regular, non-symlink file, refusing symlinks and oversize."""
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode):
            raise VerifyError(f"{path.name} is not a regular file")
        if info.st_size > limit:
            raise VerifyError(f"{path.name} exceeds the evidence size limit")
        data = bytearray()
        while len(data) < info.st_size:
            chunk = os.read(descriptor, info.st_size - len(data))
            if not chunk:
                break
            data.extend(chunk)
        return bytes(data)
    except OSError as exc:
        raise VerifyError(f"{path.name} cannot be read safely: {exc}") from exc
    finally:
        os.close(descriptor)


def _list_evidence(evidence_dir: Path) -> tuple[dict[str, int], list[str]]:
    """Enumerate retained artifacts, refusing anything that is not a plain file.

    Returns the retained *files* with their sizes plus the names of the
    subdirectories that sit beside them.  A real run bundle's ``evidence/``
    holds working trees next to the retained logs — the staged publication
    tree, the controller guard directory, per-boot frame captures — so a
    subdirectory is a structural fact about the bundle, not an unexpected
    retained artifact, and it must not abort the whole receipt.  It is still
    never silently ignored: the names are reported so the receipt states
    exactly what was accepted without being inspected.  Anything that is
    neither a plain file nor a plain directory (a symlink, socket, FIFO, or
    device node) has no place in evidence and still fails closed, and an
    unrecognised *file* is refused by ``ALLOWED_EVIDENCE`` downstream.
    """
    if evidence_dir.is_symlink() or not evidence_dir.is_dir():
        raise VerifyError("evidence directory is missing or not a directory")
    entries: dict[str, int] = {}
    subdirectories: list[str] = []
    with os.scandir(evidence_dir) as scan:
        for entry in scan:
            if entry.is_symlink():
                raise VerifyError(f"unexpected evidence entry: {entry.name}")
            if entry.is_dir(follow_symlinks=False):
                subdirectories.append(entry.name)
                continue
            if not entry.is_file(follow_symlinks=False):
                raise VerifyError(f"unexpected evidence entry: {entry.name}")
            entries[entry.name] = entry.stat(follow_symlinks=False).st_size
    if RESULT not in entries:
        raise VerifyError("evidence is missing result.json")
    return entries, sorted(subdirectories)


def _measurement(measurements: dict, key: str):
    value = measurements.get(key)
    return value if key in measurements else None, key in measurements


def _check_controller_unchanged(m: dict) -> dict:
    disk = m.get("controller_disk_unchanged")
    firmware = m.get("firmware_vars_unchanged")
    if "controller_disk_unchanged" not in m and "firmware_vars_unchanged" not in m:
        return _record(NOT_RUN, "controller disk/firmware identity not recorded")
    if disk is True and firmware is True:
        return _record(PASS, "canonical controller disk and firmware unchanged")
    return _record(FAIL, "canonical controller disk or firmware changed or unrecorded")


def _check_guest_disks(m: dict) -> dict:
    disks = m.get("guest_disks")
    if "guest_disks" not in m:
        return _record(NOT_RUN, "guest disk identities not recorded")
    if not isinstance(disks, list) or not disks:
        return _record(FAIL, "guest disk inventory is empty or malformed")
    for disk in disks:
        if not isinstance(disk, dict):
            return _record(FAIL, "guest disk record is malformed")
        if disk.get("disposable") is not True or disk.get("run_scoped") is not True:
            return _record(FAIL, "a guest disk is not disposable and run-scoped")
    return _record(PASS, "all guest disks disposable and scoped to the run")


def _is_zero_count(value: object) -> bool:
    """A proven zero count.  ``False`` is not a count, so it is not a zero."""
    return isinstance(value, int) and not isinstance(value, bool) and value == 0


def _check_host_network(m: dict) -> dict:
    """Check 9, including ADR 0080's waiver of the ``unifi`` counter.

    ``WAIVED`` requires the measurement to be present, all seven counters to
    be present, every counter the waiver does not cover to be a proven zero,
    and the covered counter to carry exactly the unproven sentinel.  A proven
    non-zero or malformed ``unifi`` value, or any change or unproven slot in a
    provable counter, still fails; an absent measurement stays NOT-RUN,
    because a waiver never stands in for a measurement that was not taken.
    An optional ``basis`` must be one :data:`HOST_NETWORK_BASES` allows; a
    privilege basis for ``forwarding`` is named in the PASS or WAIVED detail.
    """
    changes = m.get("host_network_changes")
    if "host_network_changes" not in m:
        return _record(NOT_RUN, "host network change inventory not recorded")
    if not isinstance(changes, dict) or not set(HOST_NETWORK_CATEGORIES).issubset(changes):
        return _record(FAIL, "host network change inventory is incomplete")
    basis = changes.get("basis", {})
    if not isinstance(basis, dict) or any(
            basis[name] not in HOST_NETWORK_BASES.get(name, ()) for name in basis):
        return _record(
            FAIL, "host network change inventory states an unrecognised proof basis")
    # A privilege basis proves only that the run could not change forwarding,
    # so the detail says so instead of claiming no forwarding change occurred.
    by_privilege = basis.get("forwarding") == PRIVILEGE_BASIS
    forwarding = ("; forwarding proven by privilege (the run could not change "
                  "it), not by a ruleset snapshot" if by_privilege else "")
    surfaces = "TAP/bridge/route/VLAN/" + ("" if by_privilege else "forwarding/")
    unchanged = f"no {surfaces}listener change{forwarding}"
    unchanged_all = f"no {surfaces}listener/UniFi change{forwarding}"
    offenders = sorted(
        name for name in HOST_NETWORK_CATEGORIES if not _is_zero_count(changes[name]))
    if not offenders:
        return _record(PASS, unchanged_all)
    covered = HOST_NETWORK_WAIVER["covers"]
    provable = [name for name in offenders if name not in covered]
    unproven = [name for name in covered if changes[name] == UNPROVEN_COUNTER]
    if provable:
        note = (
            f"; {', '.join(unproven)} unproven, which {HOST_NETWORK_WAIVER['adr']} "
            "waives only beside proven-zero counters" if unproven else "")
        return _record(
            FAIL, f"host network change recorded or unproven: {', '.join(provable)}{note}")
    if unproven == offenders:
        return _waived(
            f"{unchanged}; the unprovable {', '.join(unproven)} counter is "
            f"waived under {HOST_NETWORK_WAIVER['adr']}",
            HOST_NETWORK_WAIVER)
    return _record(
        FAIL, f"host network change recorded: {', '.join(offenders)} "
        "(a proven or malformed count is never waived)")


def _check_external_connection(m: dict) -> dict:
    count = m.get("external_connections_after_offline_gate")
    if "external_connections_after_offline_gate" not in m:
        return _record(NOT_RUN, "post-offline-gate external connection count not recorded")
    if not isinstance(count, int) or count < 0:
        return _record(FAIL, "external connection count is malformed")
    if count == 0:
        return _record(PASS, "no external connection after the offline gate")
    return _record(FAIL, "an external connection occurred after the offline gate")


def _check_windows_before_arch(m: dict) -> dict:
    order = m.get("install_order")
    if "install_order" not in m:
        return _record(NOT_RUN, "install order not recorded")
    if not isinstance(order, list):
        return _record(FAIL, "install order is malformed")
    windows = [i for i, name in enumerate(order) if name == "windows"]
    arch = [i for i, name in enumerate(order) if name in _ARCH_NAMES]
    if not windows or not arch:
        return _record(NOT_RUN, "single run does not record both Windows and Arch install")
    if min(windows) < min(arch):
        return _record(PASS, "Windows was installed before Arch")
    return _record(FAIL, "Arch was installed before Windows")


def _check_default_boot(m: dict) -> dict:
    if "default_boot" not in m:
        return _record(NOT_RUN, "default boot entry not recorded")
    if m.get("default_boot") == "windows":
        return _record(PASS, "Windows remains the default boot entry")
    return _record(FAIL, "Windows is not the default boot entry")


def _check_login(m: dict) -> dict:
    login = m.get("login")
    if "login" not in m:
        return _record(NOT_RUN, "login evidence not recorded")
    if not isinstance(login, dict):
        return _record(FAIL, "login evidence is malformed")
    statuses = []
    for system in ("windows", "arch"):
        entry = login.get(system)
        if not isinstance(entry, dict):
            statuses.append(NOT_RUN)
            continue
        if entry.get("online") is True and entry.get("offline_cached") is True:
            statuses.append(PASS)
        else:
            statuses.append(FAIL)
    if FAIL in statuses:
        return _record(FAIL, "an operating system failed online or cached-offline login")
    if NOT_RUN in statuses:
        return _record(NOT_RUN, "login evidence is incomplete for both operating systems")
    return _record(PASS, "both operating systems pass online and cached-offline login")


def _check_optional_storage(m: dict) -> dict:
    if "optional_storage_absence_nonblocking" not in m:
        return _record(NOT_RUN, "optional-storage absence behaviour not recorded")
    if m.get("optional_storage_absence_nonblocking") is True:
        return _record(PASS, "optional storage absence does not delay or prevent login")
    return _record(FAIL, "optional storage absence delayed or prevented login")


def _check_artifact_scan(m: dict) -> dict:
    scan = m.get("artifact_scan")
    if "artifact_scan" not in m:
        return _record(NOT_RUN, "publishable-artifact content scan not recorded")
    required = {"media", "credentials", "private", "oversized"}
    if not isinstance(scan, dict) or not required.issubset(scan):
        return _record(FAIL, "artifact content scan is incomplete")
    offenders = [
        name for name in required
        if not isinstance(scan[name], int) or scan[name] != 0
    ]
    if offenders:
        return _record(
            FAIL,
            f"publishable artifact contains forbidden objects: {', '.join(sorted(offenders))}",
        )
    return _record(
        PASS, "no tracked/publishable artifact carries media/credentials/private/oversized objects"
    )


def _check_no_secret_material(evidence_dir: Path, entries: dict[str, int]) -> dict:
    """Scan retained logs for credential tokens that survived redaction."""
    leaks = 0
    for name in LOG_FILES:
        if name not in entries:
            continue
        try:
            data = _safe_regular_bytes(evidence_dir / name, EVIDENCE_LIMIT)
        except VerifyError as exc:
            return _record(FAIL, str(exc))
        leaks += len(_CREDENTIAL.findall(data))
    if leaks:
        # Report the count only; never echo the matched bytes.
        return _record(FAIL, f"{leaks} unredacted credential token(s) in retained evidence")
    return _record(PASS, "no unredacted credential material in retained evidence")


def _check_dhcp_authority(evidence_dir: Path, entries: dict[str, int]) -> dict:
    """From switch evidence, require exactly one gateway DHCP authority."""
    if "switch.jsonl" not in entries:
        return _record(NOT_RUN, "switch evidence not retained")
    try:
        data = _safe_regular_bytes(evidence_dir / "switch.jsonl", EVIDENCE_LIMIT)
    except VerifyError as exc:
        return _record(FAIL, str(exc))
    authorities: set[str] = set()
    foreign = False
    for line in data.splitlines():
        try:
            event = json.loads(line)
        except (json.JSONDecodeError, UnicodeDecodeError):
            continue
        if not isinstance(event, dict) or event.get("event") != "dhcp":
            continue
        if event.get("kind") not in ("OFFER", "ACK"):
            continue
        source = event.get("source_mac")
        if isinstance(source, str):
            authorities.add(source)
        if event.get("peer") != "gateway":
            foreign = True
    if not authorities:
        return _record(NOT_RUN, "no DHCP authority transaction observed in switch evidence")
    if foreign or len(authorities) != 1:
        return _record(FAIL, "more than one DHCP authority or a non-gateway authority was observed")
    return _record(PASS, "the simulated gateway was the only DHCP authority")


def _pxe_authority_audit(evidence_dir: Path, entries: dict[str, int]) -> dict:
    """Render the read-only gate-4 PXE authority verdict from switch evidence.

    Delegates entirely to ``pxe_authority_audit`` (never reimplemented here).
    Returns the auditor's own machine-readable result, or a fail-closed stub
    when the audit cannot run.  The auditor's native verdict vocabulary
    (PASS / FAIL / NOT-PROVABLE) is preserved; this is a distinct gate whose
    result is embedded for the record, not folded into the gate-12 verdict.
    """
    if "switch.jsonl" not in entries:
        return {"gate": "workstation-factory-gate-4", "verdict": NOT_RUN,
                "detail": "switch evidence not retained"}
    try:
        try:
            from homelab.vm import pxe_authority_audit
        except ModuleNotFoundError:
            import pxe_authority_audit  # type: ignore[no-redef]
        topology = pxe_authority_audit.factory_topology()
        return pxe_authority_audit.audit_paths(
            [evidence_dir / "switch.jsonl"], topology)
    except Exception as exc:  # fail closed: an unrunnable gate is not a pass
        return {"gate": "workstation-factory-gate-4", "verdict": FAIL,
                "detail": f"gate-4 audit could not run: {exc}"}


def _pxe_authority_summary(result: dict) -> dict:
    """A size-bounded projection of the gate-4 result for the run receipt."""
    summary = {"gate": result.get("gate", "workstation-factory-gate-4"),
               "verdict": result.get("verdict")}
    if "detail" in result:
        summary["detail"] = result["detail"]
    checks = result.get("checks")
    if isinstance(checks, list):
        summary["checks"] = {
            check.get("check"): check.get("verdict")
            for check in checks if isinstance(check, dict)}
    return summary


def _release_set_identity(release_set: Path) -> dict | None:
    """Read the reproducibility-critical release-set aggregate identity.

    Returned for the receipt so ``compare_runs`` can distinguish a benign
    per-run version change from a genuine sealed-media divergence.  Any read
    problem yields ``None``; the integrity verdict is owned by
    :func:`_check_release_set`, not by this diagnostic block.
    """
    manifest = Path(release_set) / pxe_release_set.MANIFEST
    try:
        raw = _safe_regular_bytes(manifest, EVIDENCE_LIMIT)
        value = json.loads(raw)
    except (VerifyError, OSError, json.JSONDecodeError, UnicodeDecodeError):
        return None
    if not isinstance(value, dict):
        return None
    return {
        "version": value.get("version"),
        "media_seal_sha256": value.get("media_seal_sha256"),
        "manifest_sha256": hashlib.sha256(raw).hexdigest(),
    }


def _resolve_release_set(release_set, releases) -> tuple[Path | None, str | None]:
    """The release-set directory to verify, or why it could not be named.

    ``release_set`` names a versioned set directly.  ``releases`` names a PXE
    release root -- what ``factory_runner``, ``factory_repeat`` and every
    phase's ``--releases`` mean -- whose selection descriptor
    (``pxe_release_set.selected_release_set``) names the set the lifecycle
    actually served.  Handing the root itself to ``pxe_release_set.verify`` is
    the 2026-10-01 gate-12 defect: it can only fail, on the root's name and on
    a manifest that a root never holds.
    """
    if release_set is not None and releases is not None:
        raise ValueError("name either a release set or a release root, not both")
    if releases is None:
        return (None if release_set is None else Path(release_set)), None
    try:
        return pxe_release_set.selected_release_set(Path(releases)), None
    except pxe_release_set.ReleaseSetError as exc:
        return None, f"selected release set could not be resolved: {exc}"


def _check_release_set(release_set: Path | None, *,
                       unresolved: str | None = None) -> dict:
    if unresolved is not None:
        return _record(FAIL, unresolved)
    if release_set is None:
        return _record(NOT_RUN, "no release set supplied for aggregate integrity")
    try:
        # The set is verified against the media seal its own aggregate manifest
        # records (no ``expected_media_seal_sha256``): a set stays bound to the
        # seal it was built from, and the receipt's ``release_set`` identity
        # carries that digest so ``compare_runs`` sees any change of seal.
        problems = pxe_release_set.verify(Path(release_set))
    except pxe_release_set.ReleaseSetError as exc:
        return _record(FAIL, f"release set could not be verified: {exc}")
    except OSError as exc:
        return _record(FAIL, f"release set could not be read: {exc}")
    if problems:
        # Bound the detail so a large problem list cannot bloat the receipt.
        head = "; ".join(problems[:5])
        more = "" if len(problems) <= 5 else f" (+{len(problems) - 5} more)"
        return _record(FAIL, f"release set failed aggregate verification: {head}{more}")
    return _record(PASS, "release-set aggregate manifest and all leaves verify")


def _verdict(checks: dict[str, dict]) -> str:
    """FAIL beats NOT-RUN beats a waiver; only an all-PASS run is ``PASS``.

    A waiver never masks a failure or a missing measurement, and a run that
    needed one is ``PASS-WITH-WAIVER`` so it cannot be read as full acceptance.
    """
    statuses = {check["status"] for check in checks.values()}
    if FAIL in statuses:
        return FAIL
    if NOT_RUN in statuses:
        return NOT_RUN
    if WAIVED in statuses:
        return PASS_WITH_WAIVER
    return PASS


def _summarize(checks: dict[str, dict]) -> dict[str, int]:
    return {
        "pass": sum(1 for c in checks.values() if c["status"] == PASS),
        "fail": sum(1 for c in checks.values() if c["status"] == FAIL),
        "not_run": sum(1 for c in checks.values() if c["status"] == NOT_RUN),
        "waived": sum(1 for c in checks.values() if c["status"] == WAIVED),
    }


def _waivers(checks: dict[str, dict]) -> list[dict]:
    """Every waived check and the decision record behind it, by check name."""
    return [
        dict(check["waiver"], check=name)
        for name, check in sorted(checks.items())
        if check["status"] == WAIVED
    ]


CHECK_NAMES = (
    "evidence_readable",
    "evidence_contents_expected",
    "evidence_within_size_limit",
    "run_status_pass",
    "no_secret_material_in_evidence",
    "single_dhcp_authority",
    "controller_disk_and_firmware_unchanged",
    "guest_disks_disposable_run_scoped",
    "no_host_network_change",
    "no_external_connection_after_offline_gate",
    "windows_installed_before_arch",
    "windows_default_boot",
    "both_os_online_and_cached_offline_login",
    "optional_storage_absence_nonblocking",
    "no_forbidden_artifact_content",
    "release_set_integrity",
)


def _fail_receipt(evidence_dir: Path, detail: str) -> dict:
    """A precondition failure: everything else is unverifiable, none pass."""
    checks = {"evidence_readable": _record(FAIL, detail)}
    for name in CHECK_NAMES:
        if name == "evidence_readable":
            continue
        checks[name] = _record(NOT_RUN, "not evaluated: evidence was unreadable")
    return {
        "schema": SCHEMA,
        "kind": "factory-verify-run",
        "evidence": evidence_dir.name,
        "verdict": FAIL,
        "checks": checks,
        "needs_live_gate": sorted(
            name for name, c in checks.items() if c["status"] == NOT_RUN
        ),
        "summary": _summarize(checks),
        "waivers": _waivers(checks),
    }


def verify_run(evidence_dir, *, release_set=None, releases=None,
               audit_out=None) -> dict:
    """Validate one retained run's evidence; never mutates, never installs.

    Check 16 verifies ``release_set`` (a versioned set directory) or, given
    ``releases`` (a PXE release root) instead, the set its selection
    descriptor names; naming both is a caller error.

    ``audit_out`` optionally names a file (outside the retained evidence) to
    receive the full gate-4 PXE authority audit JSON.  Its verdict is always
    embedded in the receipt regardless; passing ``audit_out`` only additionally
    persists the standalone artifact.
    """
    release_set, unresolved = _resolve_release_set(release_set, releases)
    evidence_dir = Path(evidence_dir)
    try:
        entries, subdirectories = _list_evidence(evidence_dir)
    except VerifyError as exc:
        return _fail_receipt(evidence_dir, str(exc))

    checks: dict[str, dict] = {}
    checks["evidence_readable"] = _record(PASS, "result.json is present and enumerable")

    unexpected = sorted(set(entries) - ALLOWED_EVIDENCE)
    # Only retained *files* can be an unexpected retained artifact.  The
    # accompanying working trees are named in the receipt (below) instead, so
    # accepting them structurally still leaves nothing unaccounted for.
    accepted = (
        "evidence contains only the expected retained artifacts"
        if not subdirectories
        else "evidence contains only the expected retained artifacts beside "
        f"{len(subdirectories)} uninspected working "
        f"director{'y' if len(subdirectories) == 1 else 'ies'}: "
        f"{', '.join(subdirectories)}"
    )
    checks["evidence_contents_expected"] = (
        _record(FAIL, f"unexpected evidence file(s): {', '.join(unexpected)}")
        if unexpected
        else _record(PASS, accepted)
    )

    # The limit mirrors factory_runner's per-artifact truncation of the logs it
    # retains, so it governs those files only; it is deliberately not applied
    # inside a working tree, where a legitimately large sealed release payload
    # lives and would otherwise fail every real run bundle.
    oversized = sorted(name for name, size in entries.items() if size > EVIDENCE_LIMIT)
    checks["evidence_within_size_limit"] = (
        _record(FAIL, f"oversized evidence file(s): {', '.join(oversized)}")
        if oversized
        else _record(PASS, "every retained artifact is within the size limit")
    )

    try:
        raw = _safe_regular_bytes(evidence_dir / RESULT, EVIDENCE_LIMIT)
        result = json.loads(raw)
        if not isinstance(result, dict):
            raise VerifyError("result.json is not a JSON object")
    except (VerifyError, json.JSONDecodeError, UnicodeDecodeError) as exc:
        return _fail_receipt(evidence_dir, f"result.json is unreadable: {exc}")

    status = result.get("status")
    scope = (
        PASS_STATUS_SCOPES.get(status) if isinstance(status, str) else None)
    if scope is not None:
        checks["run_status_pass"] = _record(
            PASS,
            "the retained run recorded a pass status in the "
            f"{scope} vocabulary ({status})")
    elif status == RUN_FAIL_STATUS:
        checks["run_status_pass"] = _record(FAIL, "the retained run recorded a fail status")
    else:
        checks["run_status_pass"] = _record(
            FAIL, "the retained run has a missing or unrecognized status")

    checks["no_secret_material_in_evidence"] = _check_no_secret_material(
        evidence_dir, entries)
    checks["single_dhcp_authority"] = _check_dhcp_authority(evidence_dir, entries)

    measurements = result.get("measurements")
    measurements = measurements if isinstance(measurements, dict) else {}
    checks["controller_disk_and_firmware_unchanged"] = _check_controller_unchanged(
        measurements)
    checks["guest_disks_disposable_run_scoped"] = _check_guest_disks(measurements)
    checks["no_host_network_change"] = _check_host_network(measurements)
    checks["no_external_connection_after_offline_gate"] = _check_external_connection(
        measurements)
    checks["windows_installed_before_arch"] = _check_windows_before_arch(measurements)
    checks["windows_default_boot"] = _check_default_boot(measurements)
    checks["both_os_online_and_cached_offline_login"] = _check_login(measurements)
    checks["optional_storage_absence_nonblocking"] = _check_optional_storage(
        measurements)
    checks["no_forbidden_artifact_content"] = _check_artifact_scan(measurements)
    checks["release_set_integrity"] = _check_release_set(
        release_set, unresolved=unresolved)

    receipt = {
        "schema": SCHEMA,
        "kind": "factory-verify-run",
        "evidence": evidence_dir.name,
        "verdict": _verdict(checks),
        "checks": checks,
        "needs_live_gate": sorted(
            name for name, c in checks.items() if c["status"] == NOT_RUN
        ),
        "summary": _summarize(checks),
        # Every WAIVED check with the decision record behind it; empty unless
        # the verdict is PASS-WITH-WAIVER or a waiver sits beside a FAIL or
        # NOT-RUN.  Named here so the reason a run is not a plain PASS is one
        # lookup away from the verdict.
        "waivers": _waivers(checks),
        # Which pass vocabulary the evidence used.  A phase runner's "observed"
        # and an aggregate driver's "pass" both render one PASS check, so the
        # receipt keeps the distinction here instead of losing it in the counts:
        # ``scope`` is "phase", "aggregate", or None for a fail/unknown status.
        "run_status": {
            "status": status if isinstance(status, str) else None,
            "scope": scope,
        },
        # The working trees accepted structurally but not inspected.  Naming
        # them keeps the accept auditable, and makes a changed working-tree set
        # a divergence the repeat comparison reports rather than absorbs.
        "evidence_subdirectories": subdirectories,
    }
    if release_set is not None:
        identity = _release_set_identity(Path(release_set))
        if identity is not None:
            receipt["release_set"] = identity

    audit_result = _pxe_authority_audit(evidence_dir, entries)
    receipt["pxe_authority_audit"] = _pxe_authority_summary(audit_result)
    if audit_out is not None:
        Path(audit_out).write_text(
            json.dumps(audit_result, indent=2, sort_keys=True) + "\n",
            encoding="utf-8")
    return receipt


# --------------------------------------------------------------------------
# Two-run comparison
# --------------------------------------------------------------------------


def _diff_tree(path: str, left, right, out: list[dict]) -> None:
    if isinstance(left, dict) and isinstance(right, dict):
        for key in sorted(set(left) | set(right)):
            child = f"{path}.{key}" if path else key
            _diff_tree(
                child,
                left.get(key, _ABSENT) if key in left else _ABSENT,
                right.get(key, _ABSENT) if key in right else _ABSENT,
                out,
            )
        return
    if isinstance(left, list) and isinstance(right, list):
        if len(left) == len(right):
            for index, (a_item, b_item) in enumerate(zip(left, right)):
                _diff_tree(f"{path}[{index}]", a_item, b_item, out)
            return
        # Length mismatch is a single structural difference.
    if left != right:
        out.append({"path": path, "a": left, "b": right})


def _leaf_key(path: str) -> str:
    tail = path.rsplit(".", 1)[-1]
    return tail.split("[", 1)[0]


def _classify(path: str, version_differs: bool) -> tuple[str, str]:
    key = _leaf_key(path)
    if key in _EXPECTED_VARYING:
        return "content-equivalent", "expected per-run nondeterminism"
    if key == "version":
        return "content-equivalent", "each run receives its own release identifier"
    if key == "manifest_sha256":
        if version_differs:
            return (
                "content-equivalent",
                "manifest digest derives from the differing release version",
            )
        return "divergent", "manifest digest diverged under an identical version"
    if key == "media_seal_sha256":
        return "divergent", "sealed media must reproduce byte-for-byte"
    return "divergent", "unexplained receipt divergence"


def compare_runs(receipt_a: dict, receipt_b: dict) -> dict:
    """Diff two run receipts, explaining every differing byte.

    Differences whose leaf is expected to vary per run (evidence names, run
    identifiers, timestamps, release version, and digests that derive from a
    differing version) are content-equivalent; everything else is a genuine
    divergence.  The pair is ``equivalent`` only when nothing diverges.
    """
    raw: list[dict] = []
    _diff_tree("", receipt_a, receipt_b, raw)
    version_differs = any(_leaf_key(item["path"]) == "version" for item in raw)
    differences = []
    for item in sorted(raw, key=lambda entry: entry["path"]):
        classification, reason = _classify(item["path"], version_differs)
        differences.append(
            {
                "path": item["path"],
                "a": item["a"],
                "b": item["b"],
                "classification": classification,
                "reason": reason,
            }
        )
    divergent = [d for d in differences if d["classification"] == "divergent"]
    return {
        "schema": SCHEMA,
        "kind": "factory-verify-compare",
        "equivalent": not divergent,
        "differences": differences,
        "content_equivalent_count": len(differences) - len(divergent),
        "divergent_count": len(divergent),
    }


# --------------------------------------------------------------------------
# Receipt persistence
# --------------------------------------------------------------------------


def render_receipt(document: dict) -> str:
    """The one canonical serialization of any receipt this module emits.

    Both the standard output and the persisted file go through this, so a
    persisted receipt is byte-identical to what the operator saw.
    """
    return json.dumps(document, indent=2, sort_keys=True) + "\n"


def write_receipt(document: dict, path) -> Path:
    """Persist a receipt as a private regular file, replacing any prior one.

    Until this existed a receipt lived only in a terminal's scrollback, so the
    gate-12 repeat evidence -- the thing the gate exists to produce -- could not
    be retained, re-read, or compared later without re-running the verifier.

    ``O_NOFOLLOW`` refuses a symlinked destination outright rather than writing
    through it, and the mode is forced to 0600 on the descriptor so an existing
    world-readable file cannot keep its mode.  The destination is the operator's
    choice and must be outside the retained evidence: writing it inside would
    make the very next ``verify_run`` of that directory FAIL check 2 as an
    unexpected retained artifact.
    """
    path = Path(path)
    encoded = render_receipt(document).encode("utf-8")
    descriptor = os.open(
        path,
        os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW | os.O_CLOEXEC,
        RECEIPT_MODE,
    )
    try:
        os.fchmod(descriptor, RECEIPT_MODE)
        written = 0
        while written < len(encoded):
            written += os.write(descriptor, encoded[written:])
    finally:
        os.close(descriptor)
    return path


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------


def waiver_note(waivers) -> str:
    """`` waived: <check> (<ADR>)...`` for a stderr verdict line, or ``""``."""
    if not waivers:
        return ""
    return " waived: " + ", ".join(
        f"{waiver.get('check')} ({waiver.get('adr')})" for waiver in waivers)


def _summary_line(receipt: dict) -> str:
    summary = receipt["summary"]
    return (
        f"{receipt['verdict']}: factory-verify "
        f"pass={summary['pass']} fail={summary['fail']} not-run={summary['not_run']} "
        f"waived={summary.get('waived', 0)} "
        f"(evidence {receipt['evidence']})"
        f"{waiver_note(receipt.get('waivers'))}"
    )


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("evidence", type=Path, help="retained run evidence directory")
    releases = result.add_mutually_exclusive_group()
    releases.add_argument(
        "--release-set", type=Path, default=None,
        help="versioned release-set directory (release-sets/YYYYMMDD.NNN) "
        "to validate with pxe_release_set.verify")
    releases.add_argument(
        "--releases", type=Path, default=None,
        help="PXE release root (e.g. homelab/var/pxe): validate the release "
        "set its selected-release-set.json names")
    result.add_argument(
        "--compare-with", type=Path, default=None,
        help="a second retained run to compare receipts against")
    result.add_argument(
        "--audit-json", type=Path, default=None,
        help="also write the full gate-4 PXE authority audit JSON to this "
        "path (its verdict is embedded in the receipt regardless)")
    result.add_argument(
        "--receipt", type=Path, default=None,
        help="also persist the receipt (or the two-run comparison document) "
        "to this path, mode 0600, byte-identical to standard output.  Name a "
        "path outside the retained evidence: a receipt written inside it "
        "would be an unexpected retained artifact on the next verification")
    result.add_argument(
        "--plan", action="store_true",
        help="dry run: list the checks without emitting a receipt")
    return result


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    if args.plan:
        print("dry run: factory-verify would validate retained evidence read-only")
        print(f"evidence: {args.evidence}")
        if args.release_set is not None:
            print(f"release set: {args.release_set}")
        if args.releases is not None:
            print(f"release root: {args.releases} (verifies its selected set)")
        if args.compare_with is not None:
            # The repeat gate's second run: name it in the plan so an operator
            # can confirm the comparison is wired before spending a live run.
            print(f"compare with: {args.compare_with}")
        if args.receipt is not None:
            print(f"receipt: {args.receipt} (mode 0600)")
        print("checks:")
        for name in CHECK_NAMES:
            print(f"  - {name}")
        print("repeat with APPLY=1 to emit the receipt and "
              "PASS/PASS-WITH-WAIVER/FAIL/NOT-RUN summary")
        return 0

    receipt = verify_run(
        args.evidence, release_set=args.release_set, releases=args.releases,
        audit_out=args.audit_json)
    if args.compare_with is not None:
        other = verify_run(args.compare_with, release_set=args.release_set,
                           releases=args.releases)
        comparison = compare_runs(receipt, other)
        output = {"run_a": receipt, "run_b": other, "comparison": comparison}
    else:
        comparison = None
        output = receipt
    print(render_receipt(output), end="")
    # Persisted before the verdict lines so a non-zero exit never costs the
    # receipt the operator asked to keep.
    if args.receipt is not None:
        write_receipt(output, args.receipt)
        print(f"receipt written: {args.receipt}", file=sys.stderr)
    print(_summary_line(receipt), file=sys.stderr)
    if comparison is not None:
        verdict = "PASS" if comparison["equivalent"] else "FAIL"
        print(
            f"{verdict}: two-run comparison "
            f"equivalent={comparison['equivalent']} "
            f"divergent={comparison['divergent_count']}",
            file=sys.stderr,
        )
        if not comparison["equivalent"]:
            return 1
    return 1 if receipt["verdict"] == FAIL else 0


if __name__ == "__main__":
    raise SystemExit(main())
