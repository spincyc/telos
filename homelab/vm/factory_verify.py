#!/usr/bin/env python3
"""Gate-12 acceptance verifier and two-run receipt comparator.

This module is pure, deterministic, read-only, and unprivileged.  It never
boots a guest, opens a socket, mutates a file, or performs an installation.
It reads one retained factory run's evidence (as produced by
``factory_runner.retain_evidence``) and produces a machine-readable receipt
that classifies every acceptance measurement it can check from evidence alone
as ``PASS``, ``FAIL``, or ``NOT-RUN``.  A measurement that was never recorded
stays ``NOT-RUN``; it is never promoted to ``PASS``.  Anything unreadable,
oversized, unexpected, or ambiguous fails closed to ``FAIL``.

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

RESULT = "result.json"
ALLOWED_EVIDENCE = frozenset(
    {RESULT, "controller-publication.log", "workstation-serial.log", "switch.jsonl"}
)
LOG_FILES = ("controller-publication.log", "workstation-serial.log")

# A credential-like token that survived redaction is a leak, not evidence.
_CREDENTIAL = re.compile(
    rb"(?i)(?:password|passphrase|token|secret)\s*[:=]\s*(?!\[REDACTED\])\S+"
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


class VerifyError(RuntimeError):
    """Retained evidence is unreadable, unsafe, or oversized."""


def _record(status: str, detail: str) -> dict:
    return {"status": status, "detail": detail}


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


def _list_evidence(evidence_dir: Path) -> dict[str, int]:
    """Enumerate the evidence directory, refusing anything unexpected."""
    if evidence_dir.is_symlink() or not evidence_dir.is_dir():
        raise VerifyError("evidence directory is missing or not a directory")
    entries: dict[str, int] = {}
    with os.scandir(evidence_dir) as scan:
        for entry in scan:
            if entry.is_symlink() or not entry.is_file(follow_symlinks=False):
                raise VerifyError(f"unexpected evidence entry: {entry.name}")
            entries[entry.name] = entry.stat(follow_symlinks=False).st_size
    if RESULT not in entries:
        raise VerifyError("evidence is missing result.json")
    return entries


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


def _check_host_network(m: dict) -> dict:
    changes = m.get("host_network_changes")
    if "host_network_changes" not in m:
        return _record(NOT_RUN, "host network change inventory not recorded")
    required = {"tap", "bridge", "route", "vlan", "forwarding", "listener", "unifi"}
    if not isinstance(changes, dict) or not required.issubset(changes):
        return _record(FAIL, "host network change inventory is incomplete")
    offenders = [
        name for name in required
        if not isinstance(changes[name], int) or changes[name] != 0
    ]
    if offenders:
        return _record(FAIL, f"host network change recorded: {', '.join(sorted(offenders))}")
    return _record(PASS, "no TAP/bridge/route/VLAN/forwarding/listener/UniFi change")


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


def _check_release_set(release_set: Path | None) -> dict:
    if release_set is None:
        return _record(NOT_RUN, "no release set supplied for aggregate integrity")
    try:
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
    statuses = {check["status"] for check in checks.values()}
    if FAIL in statuses:
        return FAIL
    if NOT_RUN in statuses:
        return NOT_RUN
    return PASS


def _summarize(checks: dict[str, dict]) -> dict[str, int]:
    return {
        "pass": sum(1 for c in checks.values() if c["status"] == PASS),
        "fail": sum(1 for c in checks.values() if c["status"] == FAIL),
        "not_run": sum(1 for c in checks.values() if c["status"] == NOT_RUN),
    }


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
    }


def verify_run(evidence_dir, *, release_set=None) -> dict:
    """Validate one retained run's evidence; never mutates, never installs."""
    evidence_dir = Path(evidence_dir)
    try:
        entries = _list_evidence(evidence_dir)
    except VerifyError as exc:
        return _fail_receipt(evidence_dir, str(exc))

    checks: dict[str, dict] = {}
    checks["evidence_readable"] = _record(PASS, "result.json is present and enumerable")

    unexpected = sorted(set(entries) - ALLOWED_EVIDENCE)
    checks["evidence_contents_expected"] = (
        _record(FAIL, f"unexpected evidence file(s): {', '.join(unexpected)}")
        if unexpected
        else _record(PASS, "evidence contains only the expected retained artifacts")
    )

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
    if status == "pass":
        checks["run_status_pass"] = _record(PASS, "the retained run recorded a pass status")
    elif status == "fail":
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
    checks["release_set_integrity"] = _check_release_set(release_set)

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
    }
    if release_set is not None:
        identity = _release_set_identity(Path(release_set))
        if identity is not None:
            receipt["release_set"] = identity
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
# CLI
# --------------------------------------------------------------------------


def _summary_line(receipt: dict) -> str:
    summary = receipt["summary"]
    return (
        f"{receipt['verdict']}: factory-verify "
        f"pass={summary['pass']} fail={summary['fail']} not-run={summary['not_run']} "
        f"(evidence {receipt['evidence']})"
    )


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("evidence", type=Path, help="retained run evidence directory")
    result.add_argument(
        "--release-set", type=Path, default=None,
        help="release-set root to validate with pxe_release_set.verify")
    result.add_argument(
        "--compare-with", type=Path, default=None,
        help="a second retained run to compare receipts against")
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
        print("checks:")
        for name in CHECK_NAMES:
            print(f"  - {name}")
        print("repeat with APPLY=1 to emit the receipt and PASS/FAIL/NOT-RUN summary")
        return 0

    receipt = verify_run(args.evidence, release_set=args.release_set)
    if args.compare_with is not None:
        other = verify_run(args.compare_with, release_set=args.release_set)
        comparison = compare_runs(receipt, other)
        output = {"run_a": receipt, "run_b": other, "comparison": comparison}
    else:
        comparison = None
        output = receipt
    print(json.dumps(output, indent=2, sort_keys=True))
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
