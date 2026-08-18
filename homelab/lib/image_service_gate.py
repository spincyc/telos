"""Judge a captured guest transcript of systemd unit state, fail-closed.

The static promotion gate (:mod:`homelab.lib.image_promotion_gate`) proves what
a candidate image *contains*; it cannot prove what the image *runs*, because
that needs a boot.  This module is the host-side half of that missing proof,
split the way every other live proof in this repository is split: a live
capture step that produces retained evidence, and a pure judge over that
evidence which needs no guest, no root, and no QEMU.

Transcript shape
================

The capture runs inside the booted candidate and prints one token-scoped,
line-anchored marker record per fact, on the serial console, in the idiom
``homelab/workstations/arch_second.py`` already uses for its measurements::

    __TELOS_SERVICE_BEGIN_<token> schema=1 profile=<profile>
    __TELOS_SERVICE_UNIT_<token> name=<unit> enabled=<state> active=<state> type=<type> result=<result>
    ...
    __TELOS_SERVICE_END_<token> units=<count> external_access=false verdict=PASS

Why this shape and not JSON per line: a serial console interleaves kernel
messages with program output at arbitrary byte boundaries, and a chunked read
can cut a line in half.  A framed marker record either matches a whole line or
is refused; a JSON document cut in half is simply unreadable, and -- worse --
a JSON document with a *plausible* half is readable and wrong.  The frame also
carries its own length, which is the only way a truncated capture can be told
apart from a short one.

Every defence here exists because this repository has been bitten by its
absence:

``__TELOS_SERVICE_`` off column zero is a refusal
    A shell that echoes the capture script prints the marker *text* without
    running the program.  Any line carrying the marker family anywhere but at
    offset zero is treated as interleaved or echoed output and fails the
    transcript, so a marker printed by the shell can never be mistaken for the
    output of the program that was supposed to produce it.

Values are anchored on both ends
    The live 2026-08-14 run read ``owner_uid=1`` from a guest that printed
    ``10001`` because the pattern had no line anchor.  Here a record must match
    the whole line, the transcript must end with a line terminator, and the
    ``END`` count must equal the number of ``UNIT`` records actually read.  A
    partial read therefore fails as a truncation rather than matching a short
    value.

Judgement
=========

Declared services come from the tracked contract
(``homelab/package-contract.json``) merged for the profile under test; this
module never carries its own copy of the list.  For every declared unit the
capture must prove ``enabled`` plus one of:

* ``active=active`` -- the unit is running; or
* ``active=inactive type=oneshot result=success`` -- a ``oneshot`` that ran to
  completion.  Requiring ``active=active`` of every declared unit would fail
  every real image: ``telos-arch-join-once.service``,
  ``homelab-first-boot.service`` and ``systemd-networkd-wait-online.service``
  are all oneshots that are *supposed* to be inactive once they have run.  The
  exemption is driven by the evidence the capture recorded, not by a hardcoded
  list, and it still fails closed: a oneshot whose ``result`` is anything but
  ``success`` is a failure, and so is any non-oneshot that is not active.

Anything else -- an absent unit, a unit that is not installed, a unit that is
enabled but dead, a duplicated record, a transcript for another profile, a
missing or doubled frame, an unreadable or truncated capture -- raises
:class:`ImageServiceGateError`.  There is no code path that passes on absent
evidence.

An *undeclared* enabled unit is a finding, not a failure: stock systemd presets
legitimately enable units the role contract has no opinion about, so refusing
them outright would make the judge unusable.  Every one is named in the verdict
under ``undeclared_enabled`` and the verdict becomes ``partial`` -- the same
honest-deferral vocabulary ``homelab/workstations/lifecycle_recovery.py`` uses.
Only a ``pass`` may be read as "declared services verified".
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import json
from pathlib import Path
import re
import sys
from typing import Any

from .package_contract import (
    PROFILE_OVERLAYS,
    PackageContractError,
    load_registry,
    merge_contract,
)


#: The transcript is retained console output, so it is bounded before it is
#: read: one byte past the bound is enough to refuse a pipe, a device, or a
#: capture that never stopped, without first holding it in memory.
TRANSCRIPT_LIMIT = 16 * 1024 * 1024

#: The marker family.  Searched for anywhere in a line, accepted only at
#: offset zero.
MARKER_FAMILY = "__TELOS_SERVICE_"

#: One capture record: the family, a record kind, the run token, then the
#: kind's fields in a fixed order.  ``fullmatch`` against a whole line, so no
#: prefix, suffix, or embedded whitespace can slip a record past.
RECORD_RE = re.compile(
    r"__TELOS_SERVICE_(BEGIN|UNIT|END)_([A-Za-z0-9]{8,64})"
    r"((?: [^ =]+=[^ ]+)+)")

#: A field value: no spaces, no control characters, no shell metacharacters.
VALUE_RE = re.compile(r"[A-Za-z0-9@._:+-]+")

#: An observed unit name.  Deliberately wider than
#: ``package_contract.UNIT_RE``, which constrains what a role may *declare*:
#: the capture enumerates whatever the image actually enables, and that
#: legitimately includes targets, paths, and mounts.
OBSERVED_UNIT_RE = re.compile(
    r"[A-Za-z0-9][A-Za-z0-9@._-]*"
    r"\.(?:service|socket|timer|target|path|mount|automount|swap|slice"
    r"|scope|device)")

#: Each record kind's fields, in the exact order the capture must print them.
#: Positional matching makes an unknown field, a missing field, a duplicated
#: field, and a reordered field the same single failure.
RECORD_FIELDS: dict[str, tuple[str, ...]] = {
    "BEGIN": ("schema", "profile"),
    "UNIT": ("name", "enabled", "active", "type", "result"),
    "END": ("units", "external_access", "verdict"),
}

#: ``systemctl is-enabled`` vocabulary.  A value outside it is a capture that
#: printed something this judge does not understand, which is a failure and
#: never a pass.
ENABLED_STATES = frozenset({
    "enabled", "enabled-runtime", "disabled", "static", "masked",
    "masked-runtime", "alias", "linked", "linked-runtime", "indirect",
    "generated", "transient", "not-found", "bad",
})
#: ``systemctl is-active`` vocabulary.
ACTIVE_STATES = frozenset({
    "active", "reloading", "inactive", "failed", "activating", "deactivating",
    "maintenance", "unknown",
})
#: ``systemctl show -p Type`` vocabulary; ``-`` for a unit that has no Type.
UNIT_TYPES = frozenset({
    "simple", "exec", "forking", "oneshot", "dbus", "notify", "notify-reload",
    "idle", "-",
})
#: ``systemctl show -p Result`` vocabulary; ``-`` for a unit that has no Result.
UNIT_RESULTS = frozenset({
    "success", "protocol", "timeout", "exit-code", "signal", "core-dump",
    "watchdog", "start-limit-hit", "resources", "oom-kill", "exec-condition",
    "-",
})

#: The only enablement a promotion may rest on.  ``enabled-runtime`` is
#: deliberately absent: it does not survive the next boot, so an image that
#: only enables a declared unit at runtime has not met its contract.
REQUIRED_ENABLEMENT = "enabled"
#: What counts as drift when the unit is not declared.
DRIFT_ENABLEMENT = frozenset({"enabled", "enabled-runtime"})


class ImageServiceGateError(ValueError):
    """The transcript does not prove the profile's declared services."""


@dataclass(frozen=True)
class UnitObservation:
    """One unit as the guest reported it."""

    name: str
    enabled: str
    active: str
    type: str
    result: str

    @property
    def running(self) -> bool:
        """Running now, or a ``oneshot`` that ran to completion."""
        if self.active == "active":
            return True
        return (
            self.active == "inactive"
            and self.type == "oneshot"
            and self.result == "success"
        )

    @property
    def completed_oneshot(self) -> bool:
        return self.active == "inactive" and self.running


@dataclass(frozen=True)
class ServiceCapture:
    """One whole, framed, attributable capture."""

    token: str
    profile: str
    units: tuple[UnitObservation, ...]


def _split_lines(text: str) -> list[str]:
    """Split a console transcript, refusing one that does not end a line.

    ``\\r`` separates lines on a serial console as surely as ``\\n`` does, so
    both terminate a record here.  A transcript whose last byte is not a line
    terminator was cut mid-line, which is exactly the truncation that once read
    ``owner_uid=1`` from a guest printing ``10001``.
    """
    if not text:
        raise ImageServiceGateError("transcript is empty")
    if not text.endswith(("\n", "\r")):
        raise ImageServiceGateError(
            "transcript is truncated: it does not end with a line terminator")
    lines = re.split(r"\r\n|\n|\r", text)
    return lines[:-1]


def _parse_fields(kind: str, remainder: str) -> dict[str, str]:
    expected = RECORD_FIELDS[kind]
    # ``remainder`` always opens with the single space the record regex
    # requires; everything after it is one space-delimited field each, and a
    # doubled space therefore yields an empty part that cannot parse.
    parts = remainder[1:].split(" ")
    if len(parts) != len(expected):
        raise ImageServiceGateError(
            f"{kind} record must carry exactly "
            f"{len(expected)} fields, not {len(parts)}")
    fields: dict[str, str] = {}
    for name, part in zip(expected, parts):
        key, separator, value = part.partition("=")
        if not separator or key != name:
            raise ImageServiceGateError(
                f"{kind} record expects field {name!r} where it carries "
                f"{key!r}")
        if not VALUE_RE.fullmatch(value):
            raise ImageServiceGateError(
                f"{kind} record has an unusable {name!r} value")
        fields[name] = value
    return fields


def _observation(fields: dict[str, str]) -> UnitObservation:
    name = fields["name"]
    if not OBSERVED_UNIT_RE.fullmatch(name):
        raise ImageServiceGateError(
            f"capture reports an invalid unit name: {name}")
    for key, vocabulary in (
        ("enabled", ENABLED_STATES),
        ("active", ACTIVE_STATES),
        ("type", UNIT_TYPES),
        ("result", UNIT_RESULTS),
    ):
        if fields[key] not in vocabulary:
            raise ImageServiceGateError(
                f"capture reports an unknown {key} state for {name}: "
                f"{fields[key]}")
    return UnitObservation(
        name=name,
        enabled=fields["enabled"],
        active=fields["active"],
        type=fields["type"],
        result=fields["result"],
    )


def parse_capture(text: str, *, token: str | None = None) -> ServiceCapture:
    """Read one framed capture out of a console transcript, fail-closed."""
    begin: dict[str, str] | None = None
    end: dict[str, str] | None = None
    units: list[UnitObservation] = []
    seen: set[str] = set()
    run_token: str | None = None

    for number, line in enumerate(_split_lines(text), 1):
        offset = line.find(MARKER_FAMILY)
        if offset < 0:
            continue
        if offset > 0:
            # A shell echoing the capture script, or a kernel message that
            # landed on the same line, prints the marker text without the
            # program ever running.  Neither is evidence.
            raise ImageServiceGateError(
                f"line {number}: capture marker is not line-anchored")
        match = RECORD_RE.fullmatch(line)
        if match is None:
            raise ImageServiceGateError(
                f"line {number}: malformed capture record")
        kind, line_token, remainder = match.groups()
        if run_token is None:
            run_token = line_token
        elif line_token != run_token:
            raise ImageServiceGateError(
                f"line {number}: transcript interleaves two capture tokens")
        fields = _parse_fields(kind, remainder)
        if kind == "BEGIN":
            if begin is not None:
                raise ImageServiceGateError(
                    f"line {number}: transcript carries more than one capture "
                    "frame")
            begin = fields
        elif end is not None:
            raise ImageServiceGateError(
                f"line {number}: capture record follows the frame end")
        elif begin is None:
            raise ImageServiceGateError(
                f"line {number}: capture record precedes the frame start")
        elif kind == "UNIT":
            observation = _observation(fields)
            if observation.name in seen:
                raise ImageServiceGateError(
                    f"line {number}: duplicate record for {observation.name}")
            seen.add(observation.name)
            units.append(observation)
        else:
            end = fields

    if begin is None:
        raise ImageServiceGateError("transcript carries no capture frame")
    if end is None:
        raise ImageServiceGateError(
            "transcript is truncated: the capture frame never ended")
    if begin["schema"] != "1":
        raise ImageServiceGateError(
            f"unsupported capture schema: {begin['schema']}")
    if end["verdict"] != "PASS":
        raise ImageServiceGateError(
            f"the guest capture itself reported {end['verdict']}")
    if end["external_access"] != "false":
        raise ImageServiceGateError(
            "capture does not prove external_access=false")
    declared_count = end["units"]
    if not declared_count.isdigit():
        raise ImageServiceGateError(
            "capture frame has a non-numeric unit count")
    if int(declared_count) != len(units):
        raise ImageServiceGateError(
            "transcript is truncated: the frame declares "
            f"{int(declared_count)} units and carries {len(units)}")
    assert run_token is not None
    if token is not None and token != run_token:
        raise ImageServiceGateError(
            "transcript carries another run's capture token")
    return ServiceCapture(
        token=run_token, profile=begin["profile"], units=tuple(units))


def read_transcript(path: Path) -> str:
    """Read a bounded transcript, refusing an endless or undecodable one."""
    try:
        with path.open("rb") as stream:
            raw = stream.read(TRANSCRIPT_LIMIT + 1)
    except OSError as error:
        raise ImageServiceGateError(
            f"cannot read capture transcript: {error.strerror or error}"
        ) from error
    if len(raw) > TRANSCRIPT_LIMIT:
        raise ImageServiceGateError("capture transcript is too large")
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError as error:
        raise ImageServiceGateError(
            f"capture transcript is not UTF-8: {error.reason}") from error


def judge_capture(
    profile: str, registry_path: Path, text: str, *, token: str | None = None,
) -> dict[str, Any]:
    """Grade one capture against the profile's tracked declared services."""
    overlays = PROFILE_OVERLAYS.get(profile)
    if overlays is None:
        raise ImageServiceGateError(f"unknown image profile: {profile}")
    try:
        contract = merge_contract(load_registry(registry_path), overlays)
    except PackageContractError as error:
        raise ImageServiceGateError(f"contract: {error}") from error

    capture = parse_capture(text, token=token)
    if capture.profile != profile:
        raise ImageServiceGateError(
            f"transcript was captured for profile {capture.profile}, "
            f"not {profile}")

    declared = contract.services
    observed = {unit.name: unit for unit in capture.units}
    if not declared:
        raise ImageServiceGateError(
            f"profile {profile} declares no services to verify")

    verified: list[str] = []
    completed: list[str] = []
    for name in declared:
        unit = observed.get(name)
        if unit is None:
            raise ImageServiceGateError(
                f"declared unit is absent from the capture: {name}")
        if unit.enabled == "not-found":
            raise ImageServiceGateError(
                f"declared unit is not installed in the image: {name}")
        if unit.enabled != REQUIRED_ENABLEMENT:
            raise ImageServiceGateError(
                f"declared unit is not enabled: {name} reports "
                f"{unit.enabled}")
        if not unit.running:
            raise ImageServiceGateError(
                f"declared unit is enabled but not running: {name} reports "
                f"active={unit.active} type={unit.type} result={unit.result}")
        (completed if unit.completed_oneshot else verified).append(name)

    undeclared = sorted(
        name for name, unit in observed.items()
        if name not in set(declared) and unit.enabled in DRIFT_ENABLEMENT
    )
    return {
        "schema_version": 1,
        "kind": "image-declared-service-observation",
        "profile": profile,
        "overlays": list(contract.overlays),
        "checks": len(declared),
        "result": "partial" if undeclared else "pass",
        "external_access": False,
        "declared_services": list(declared),
        "running_services": verified,
        "completed_oneshots": completed,
        "undeclared_enabled": undeclared,
        "records": len(capture.units),
    }


HOMELAB_ROOT = Path(__file__).resolve().parents[1]
# The tracked contract, and only the tracked contract -- the same rule
# ``image_promotion_cli`` holds itself to. A service gate that accepted a
# caller-supplied registry could be satisfied by supplying one that declares
# nothing, which would make every verdict it signs meaningless. This is not a
# default that can be overridden; there is no flag for it. ``judge_capture``
# still takes the path so tests can grade synthetic contracts.
REGISTRY = HOMELAB_ROOT / "package-contract.json"


def main(argv: list[str] | None = None) -> int:
    """Grade one retained capture transcript and print its verdict."""
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--profile", required=True,
                        choices=sorted(PROFILE_OVERLAYS))
    parser.add_argument("--token", help="require this capture run token")
    parser.add_argument("--evidence", type=Path,
                        help="write the verdict here instead of stdout")
    parser.add_argument("transcript", type=Path,
                        help="retained guest console capture to grade")
    args = parser.parse_args(argv)

    try:
        verdict = judge_capture(
            args.profile, REGISTRY, read_transcript(args.transcript),
            token=args.token)
    except ImageServiceGateError as error:
        print(f"image service gate: {error}", file=sys.stderr)
        return 1
    document = json.dumps(verdict, sort_keys=True)
    if verdict["undeclared_enabled"]:
        # Drift is named on stderr as well as in the verdict: a partial exits
        # zero, the way the lifecycle-recovery judge's honest deferral does,
        # so the operator must be told rather than left to read the JSON.
        print(
            "image service gate: image enables undeclared units: "
            + ", ".join(verdict["undeclared_enabled"]),
            file=sys.stderr)
    if args.evidence is None:
        print(document)
        return 0
    try:
        args.evidence.write_text(document + "\n", encoding="utf-8")
    except OSError as error:
        print(f"image service gate: cannot write verdict: "
              f"{error.strerror or error}", file=sys.stderr)
        return 1
    print(f"service verdict: {args.evidence}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
