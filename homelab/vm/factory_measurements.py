#!/usr/bin/env python3
"""Derive gate-12 login measurements from retained identity evidence.

Two of ``factory_runner``'s permitted ``measurements`` fields -- ``login`` and
``optional_storage_absence_nonblocking`` -- have no producer, so checks 13 and
14 of ``factory_verify`` can never be anything but ``NOT-RUN``.  The live
proofs, however, already exist: gate 6 retains a Windows identity acceptance
stream judged by ``workstations/windows_identity_acceptance.py`` and gate 8
retains a cross-OS identity lifecycle stream judged by
``workstations/identity_lifecycle.py``.  This module is the faithful mapping
from those two retained streams onto the two measurement fields.  It invents
nothing: every verdict is the verdict its own judge already reached.

The mapping, field by field:

===========================================  ====================================
measurement                                  proving check (evidence stream)
===========================================  ====================================
``login.windows.online``                     ``windows-standard-online`` (gate 6)
``login.windows.offline_cached``             ``windows-cached-login`` (gate 6)
``login.arch.online``                        ``arch-standard-online`` (gate 8)
``login.arch.offline_cached``                ``arch-cached-login`` (gate 8)
``optional_storage_absence_nonblocking``     ``optional-storage-offline`` (gate 6)
                                             and ``arch-storage-absent-login``
                                             (gate 8)
===========================================  ====================================

Every verdict is derived in two stages, and both must hold:

1.  The whole stream is handed to its real judge.  A judged record is not
    trustworthy in isolation: the judges validate ordering, uniqueness, the
    per-record envelope, a single ``run_id``, and ``external_access is False``
    across the whole file, so a record lifted out of a stream the judge would
    reject proves nothing.  The judge is imported and called, never
    reimplemented, so this module cannot drift away from the contract.
2.  The decisive fields of the individual proving record are restated here.
    Stage 1 already asserts them, so this can only ever narrow the verdict; it
    exists so the mapping from a measurement to the facts that prove it is
    stated in one readable place, and so a future contract that loosened a
    record would not silently loosen a gate-12 measurement.

Everything fails closed.  A missing path, a symlink, an oversized or unreadable
file, malformed JSON, a stream the judge rejects, an absent record, or a record
whose decisive fields do not hold all yield ``False`` -- never an optimistic
default, and never a silently skipped proof.  This module is pure: it reads the
named files and returns booleans.  It never mutates, boots, installs, opens a
socket, or returns a path, hostname, or credential.

A run that observed no identity evidence at all should pass ``None`` to
``factory_runner.measurement_block`` rather than the all-false block these
helpers return, per that module's rule that a runner emits only the fields its
own run actually observed: an absent field is an honest ``NOT-RUN``, while an
all-false block asserts a login that failed.
"""

from __future__ import annotations

import math
import os
import stat
import sys
from collections.abc import Mapping
from pathlib import Path
from typing import Any

# The judges live under ``workstations/`` and are imported by path, exactly as
# ``arch_identity_run`` imports them and for the same reason: this module is
# imported both as ``homelab.vm.factory_measurements`` and as
# ``factory_measurements`` (the tests put ``homelab/vm`` on ``sys.path``), and a
# ``..workstations`` relative import reaches beyond the top-level package in the
# second case.
_WORKSTATIONS = Path(__file__).resolve().parents[1] / "workstations"
if str(_WORKSTATIONS) not in sys.path:
    sys.path.insert(0, str(_WORKSTATIONS))
import identity_lifecycle as _arch_judge  # noqa: E402
import windows_identity_acceptance as _windows_judge  # noqa: E402


# Mirrors factory_verify.EVIDENCE_LIMIT, which in turn mirrors
# factory_runner.EVIDENCE_LIMIT: no retained artifact may exceed it, and an
# oversized one is refused rather than parsed.
EVIDENCE_LIMIT = 1024 * 1024

WINDOWS_ONLINE_CHECK = "windows-standard-online"
WINDOWS_CACHED_CHECK = "windows-cached-login"
WINDOWS_STORAGE_CHECK = "optional-storage-offline"
ARCH_ONLINE_CHECK = "arch-standard-online"
ARCH_CACHED_CHECK = "arch-cached-login"
ARCH_STORAGE_CHECK = "arch-storage-absent-login"

# The decisive fields each judge asserts on each proving record.  These restate
# the judges' own expectations (windows_identity_acceptance.judge's ``_expect``
# calls, identity_lifecycle.judge's per-OS and storage blocks); they never add a
# field no judge reads, and they never relax one.
_WINDOWS_FIELDS: dict[str, dict[str, Any]] = {
    # _expect(by["windows-standard-online"], principal_role="standard",
    #         elevated=False, identity_resolved=True, cache_primed=True,
    #         synthetic_directory=True)
    WINDOWS_ONLINE_CHECK: {
        "principal_role": "standard", "elevated": False,
        "identity_resolved": True, "cache_primed": True,
        "synthetic_directory": True},
    # _expect(by["windows-cached-login"], controller_online=False, cached=True,
    #         principal_role="standard", login="allowed")
    WINDOWS_CACHED_CHECK: {
        "controller_online": False, "cached": True,
        "principal_role": "standard", "login": "allowed"},
    # _expect(by["optional-storage-offline"], storage_reachable=False,
    #         login_succeeded=True); _validate_login_time(...) supplies the bound
    WINDOWS_STORAGE_CHECK: {
        "storage_reachable": False, "login_succeeded": True},
}
_ARCH_FIELDS: dict[str, dict[str, Any]] = {
    # standard.get("principal_role") != "standard" or standard.get("elevated")
    # is not False -> "standard user authorization is unsafe"
    ARCH_ONLINE_CHECK: {"principal_role": "standard", "elevated": False},
    # cached.get("controller_online") is not False or cached.get("cached") is
    # not True -> "cached login was not proven during outage"
    ARCH_CACHED_CHECK: {"controller_online": False, "cached": True},
    # absent.get("storage_reachable") is not False or mount_state != "absent"
    # or login != "allowed" or login_path_independent is not True; the bound is
    # then checked against the contract's login_bound_seconds
    ARCH_STORAGE_CHECK: {
        "storage_reachable": False, "mount_state": "absent",
        "login": "allowed", "login_path_independent": True},
}

# The records whose login had to stay inside the contract's login bound: this is
# the whole meaning of check 14, which reads "absence does not DELAY or prevent
# login", so the timing is restated rather than left to stage 1 alone.
_BOUNDED_LOGIN = frozenset({WINDOWS_STORAGE_CHECK, ARCH_STORAGE_CHECK})


class _Stream:
    """One retained evidence stream its own judge accepted, or nothing at all.

    ``by_check`` is empty whenever the stream was missing, unreadable, or
    rejected, so every derived verdict fails closed on an empty stream without
    any caller needing to test for the failure separately.
    """

    __slots__ = ("by_check", "login_bound_seconds")

    def __init__(
        self,
        by_check: Mapping[str, Mapping[str, Any]] | None = None,
        login_bound_seconds: int | float | None = None,
    ) -> None:
        self.by_check: Mapping[str, Mapping[str, Any]] = dict(by_check or {})
        self.login_bound_seconds = login_bound_seconds


def _safe_regular_text(path: Path) -> str:
    """Read a regular, non-symlink, size-bounded evidence file as UTF-8.

    Mirrors ``factory_verify._safe_regular_bytes``: retained evidence is read
    with ``O_NOFOLLOW`` so a symlink planted in a bundle cannot redirect the
    read, and an oversized artifact is refused rather than parsed.
    """
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode):
            raise OSError(f"{path.name} is not a regular file")
        if info.st_size > EVIDENCE_LIMIT:
            raise OSError(f"{path.name} exceeds the evidence size limit")
        data = bytearray()
        while len(data) < info.st_size:
            chunk = os.read(descriptor, info.st_size - len(data))
            if not chunk:
                break
            data.extend(chunk)
    finally:
        os.close(descriptor)
    return bytes(data).decode("utf-8")


def _judged(evidence: Path | str | None, judge) -> _Stream:
    """Read one evidence stream and keep it only if its judge accepts it.

    Any failure at all -- absent path, symlink, oversize, unreadable bytes,
    malformed JSON, an invalid contract, or a judged rejection -- yields an
    empty stream.  ``except Exception`` is deliberate and matches
    ``factory_verify._pxe_authority_audit``: an unrunnable gate is not a pass,
    so an unexpected error must fail closed rather than escape and be mistaken
    for a producer bug in the caller.
    """
    if evidence is None:
        return _Stream()
    try:
        contract = judge.load_json(judge.CONTRACT)
        events = judge.load_events(_safe_regular_text(Path(evidence)).splitlines())
        judge.judge(contract, events)
        by_check = {
            event["check"]: event
            for event in events
            if isinstance(event.get("check"), str)
        }
        bound = contract["login_bound_seconds"]
    except Exception:  # fail closed: an unproven stream proves nothing
        return _Stream()
    return _Stream(by_check, bound)


def _matches(value: Any, expected: Any) -> bool:
    """Compare one field, keeping ``True``/``1`` and ``False``/``0`` distinct.

    The judges compare with ``!=``, under which ``0 != False`` is false; a
    measurement that renders a gate-12 PASS is not the place to inherit that,
    so a boolean expectation is matched by identity.
    """
    if isinstance(expected, bool):
        return value is expected
    return value == expected


def _within_login_bound(event: Mapping[str, Any], bound: Any) -> bool:
    """Require a finite, non-negative login inside the contract's own bound."""
    if isinstance(bound, bool) or not isinstance(bound, (int, float)):
        return False
    if not math.isfinite(bound) or bound <= 0:
        return False
    if not _matches(event.get("login_bound_seconds"), bound):
        return False
    seconds = event.get("login_seconds")
    if isinstance(seconds, bool) or not isinstance(seconds, (int, float)):
        return False
    return math.isfinite(seconds) and 0 <= seconds <= bound


def _proves(stream: _Stream, check: str, fields: Mapping[str, Any]) -> bool:
    """Whether one judged record proves the measurement it is mapped to."""
    event = stream.by_check.get(check)
    if not isinstance(event, Mapping):
        return False
    if event.get("result") != "pass" or event.get("external_access") is not False:
        return False
    if not all(_matches(event.get(name), value) for name, value in fields.items()):
        return False
    if check in _BOUNDED_LOGIN:
        return _within_login_bound(event, stream.login_bound_seconds)
    return True


def _windows(evidence: Path | str | None) -> _Stream:
    return _judged(evidence, _windows_judge)


def _arch(evidence: Path | str | None) -> _Stream:
    return _judged(evidence, _arch_judge)


def login_measurement(
    windows_evidence: Path | str | None,
    arch_evidence: Path | str | None,
) -> dict[str, dict[str, bool]]:
    """The gate-12 ``login`` measurement, in the exact shape check 13 reads.

    Returns ``{"windows": {"online": bool, "offline_cached": bool}, "arch":
    {...}}`` and nothing else, because ``factory_verify._check_login`` reads
    exactly those keys and ``factory_runner.MEASUREMENT_KEYS`` pins the
    vocabulary.  All four booleans are always present: a stream this module
    could not prove yields ``False``, so check 13 renders ``FAIL`` rather than
    the ``NOT-RUN`` an omitted key would render.  A run with no identity
    evidence at all should omit the whole field instead (see the module
    docstring).
    """
    return _login_from(_windows(windows_evidence), _arch(arch_evidence))


def optional_storage_measurement(
    windows_evidence: Path | str | None,
    arch_evidence: Path | str | None,
) -> bool:
    """The gate-12 ``optional_storage_absence_nonblocking`` measurement.

    True only when BOTH operating systems proved a bounded login with the
    optional storage target absent: Windows through ``optional-storage-offline``
    and Arch through ``arch-storage-absent-login``.  One system's proof is half
    a proof, so a missing or unproven stream on either side yields ``False``.
    """
    return _optional_storage_from(_windows(windows_evidence), _arch(arch_evidence))


def identity_measurements(
    windows_evidence: Path | str | None,
    arch_evidence: Path | str | None,
) -> dict[str, Any]:
    """Both measurements from a single read of each stream.

    The keys are exactly ``login`` and ``optional_storage_absence_nonblocking``,
    so the result can be splatted straight into
    ``factory_runner.measurement_block``.
    """
    windows = _windows(windows_evidence)
    arch = _arch(arch_evidence)
    return {
        "login": _login_from(windows, arch),
        "optional_storage_absence_nonblocking": _optional_storage_from(windows, arch),
    }


def _login_from(windows: _Stream, arch: _Stream) -> dict[str, dict[str, bool]]:
    return {
        "windows": {
            "online": _proves(
                windows, WINDOWS_ONLINE_CHECK, _WINDOWS_FIELDS[WINDOWS_ONLINE_CHECK]),
            "offline_cached": _proves(
                windows, WINDOWS_CACHED_CHECK, _WINDOWS_FIELDS[WINDOWS_CACHED_CHECK]),
        },
        "arch": {
            "online": _proves(
                arch, ARCH_ONLINE_CHECK, _ARCH_FIELDS[ARCH_ONLINE_CHECK]),
            "offline_cached": _proves(
                arch, ARCH_CACHED_CHECK, _ARCH_FIELDS[ARCH_CACHED_CHECK]),
        },
    }


def _optional_storage_from(windows: _Stream, arch: _Stream) -> bool:
    return (
        _proves(windows, WINDOWS_STORAGE_CHECK, _WINDOWS_FIELDS[WINDOWS_STORAGE_CHECK])
        and _proves(arch, ARCH_STORAGE_CHECK, _ARCH_FIELDS[ARCH_STORAGE_CHECK])
    )
