#!/usr/bin/env python3
"""Capture and compare host networking state around an isolated simulation."""

from __future__ import annotations

import json
import re
import subprocess
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Sequence

try:
    from .secure_artifacts import atomic_write_text
except ImportError:
    from secure_artifacts import atomic_write_text

ALLOWED_QEMU_PORTS = frozenset({12971, 12972})


@dataclass(frozen=True)
class Observation:
    command: tuple[str, ...]
    returncode: int
    stdout: str
    stderr: str


LINK_COMMAND = ("ip", "-j", "-details", "link", "show")
ADDRESS_COMMAND = ("ip", "-j", "address", "show")
ROUTE4_COMMAND = ("ip", "-j", "route", "show", "table", "all")
ROUTE6_COMMAND = ("ip", "-j", "-6", "route", "show", "table", "all")
BRIDGE_LINK_COMMAND = ("bridge", "-j", "link", "show")
BRIDGE_VLAN_COMMAND = ("bridge", "-j", "vlan", "show")
NETNS_COMMAND = ("ip", "netns", "list")
# --stateless omits counters that can legitimately advance during a test.
NFT_COMMAND = ("nft", "-j", "--stateless", "list", "ruleset")
SOCKET_COMMAND = ("ss", "-H", "-lntup")

COMMANDS: tuple[tuple[str, ...], ...] = (
    LINK_COMMAND,
    ADDRESS_COMMAND,
    ROUTE4_COMMAND,
    ROUTE6_COMMAND,
    BRIDGE_LINK_COMMAND,
    BRIDGE_VLAN_COMMAND,
    NETNS_COMMAND,
    NFT_COMMAND,
    SOCKET_COMMAND,
)

NFT_UNAVAILABLE = (
    "src/mnl.c:66: Unable to initialize Netlink socket: "
    "Protocol not supported"
)


def _run(command: Sequence[str]) -> Observation:
    try:
        result = subprocess.run(
            command, check=False, text=True, capture_output=True)
        return Observation(
            tuple(command), result.returncode,
            result.stdout.rstrip(), result.stderr.rstrip())
    except FileNotFoundError as error:
        return Observation(tuple(command), 127, "", str(error))


# ---------------------------------------------------------------------------
# The forwarding counter's privilege basis (owner decision 2026-09-30)
# ---------------------------------------------------------------------------
#
# ``nft -j --stateless list ruleset`` needs CAP_NET_ADMIN.  The factory runs
# unprivileged, so it exits 1 "Operation not permitted" and no snapshot pair
# can prove the ``forwarding`` counter.  When the ruleset cannot be read the
# counter may instead be proven by PRIVILEGE: not "the host's forwarding state
# did not change" -- an unreadable ruleset cannot show that -- but "this run
# could not have changed it".  Three facts, read into every snapshot (so at
# run start and again at run end), carry that proof:
#
# 1. ``NoNewPrivs: 1`` in ``/proc/self/status``.  The repeat driver sets
#    PR_SET_NO_NEW_PRIVS on itself before it spawns anything; the flag is
#    inherited across fork and execve and can never be cleared.  With it set,
#    execve honours neither setuid/setgid bits nor file capabilities -- sudo
#    runs as the invoking user and refuses -- so no descendant can gain a
#    privilege the driver lacks.
# 2. CAP_NET_ADMIN (bit 12) and CAP_SYS_ADMIN (bit 21) absent from CapEff,
#    CapPrm and CapAmb, and no uid 0.  Changing the host's ruleset or a
#    forwarding sysctl needs CAP_NET_ADMIN in the host network namespace's
#    owning (initial) user namespace, or for a sysctl euid 0 (below);
#    CAP_SYS_ADMIN, the catch-all administrative capability, is
#    refused as well so no indirect route is left open.  Effective and ambient
#    are always subsets of permitted, and under NoNewPrivs the kernel clamps
#    any post-execve permitted set to the pre-execve one, so neither bit can
#    reappear anywhere in the process tree.  The bounding set (CapBnd,
#    typically full) is therefore irrelevant: it only limits what an execve
#    may ADD from file capabilities or the inheritable set, and NoNewPrivs
#    already forbids every addition.  CapInh is irrelevant for the same
#    reason.  No ``Uid`` value (real, effective, saved, filesystem) may be 0
#    either: the kernel lets euid 0 write a root-owned sysctl through its
#    owner permission bits with no capability at all, and an unprivileged
#    process may switch its euid to its real or saved uid, so all four are
#    required non-zero.
# 3. The world-readable forwarding sysctls (:data:`FORWARDING_SYSCTLS`) are
#    equal at start and end -- the direct effect of a forwarding change,
#    observed rather than assumed.  A differing value is counted as a
#    forwarding change whatever the privilege facts say.
#
# A user namespace does not escape this.  An unprivileged descendant may create
# one (and a network namespace inside it) and hold every capability there, but
# those capabilities reach only namespaces that user namespace owns.  The
# host's network namespace -- its ruleset and its forwarding sysctls -- is
# owned by the initial user namespace, where the process tree holds neither
# bit; a private netns it builds is not the host's and dies with it.
#
# What the privilege basis does NOT cover, so no receipt overclaims: a
# privileged service asked over IPC (NetworkManager, firewalld, libvirt via
# polkit) acts with its own privilege, not the run's.  The sysctl comparison
# still catches the forwarding switch such a service would flip, but a
# ruleset-only change made that way is outside this proof.  That is why the
# measurement always states its basis: ``snapshot`` proves "nothing changed",
# ``privilege`` proves only "the run changed nothing".

PROC_STATUS = "/proc/self/status"
FORWARDING_SYSCTLS: tuple[str, ...] = (
    "/proc/sys/net/ipv4/ip_forward",
    "/proc/sys/net/ipv6/conf/all/forwarding",
    "/proc/sys/net/ipv6/conf/default/forwarding",
)
#: ``linux/capability.h`` bit numbers the privilege basis requires absent.
FORBIDDEN_CAPABILITIES: dict[str, int] = {
    "CAP_NET_ADMIN": 12, "CAP_SYS_ADMIN": 21}
#: The capability sets that must lack them; CapBnd and CapInh are deliberately
#: not among them (see the block comment above).
CAPABILITY_SETS: tuple[str, ...] = ("CapEff", "CapPrm", "CapAmb")
PRIVILEGE_FIELDS: tuple[str, ...] = ("NoNewPrivs", "Uid", *CAPABILITY_SETS)
PRIVILEGE_SCHEMA = 1

#: How the ``forwarding`` counter was proven; ``factory_verify`` mirrors these.
BASIS_SNAPSHOT = "snapshot"
BASIS_PRIVILEGE = "privilege"

_CAPABILITY_MASK = re.compile(r"\A[0-9a-fA-F]{1,16}\Z")
_SYSCTL_VALUE = re.compile(r"\A-?[0-9]+\Z")
_UID = re.compile(r"\A[0-9]+\Z")


def _read_text(path: str) -> str | None:
    """A file's text, or ``None`` when it cannot be read."""
    try:
        with open(path, "rb") as handle:
            return handle.read().decode("utf-8", "replace")
    except OSError:
        return None


def privilege_facts(
    read: Callable[[str], str | None] = _read_text,
) -> dict[str, object]:
    """Record -- never judge -- what the forwarding privilege basis reads.

    ``read`` maps a path to its text or ``None``.  The default reads this
    process's own ``/proc/self/status`` in-process, so "self" is the process
    whose privilege is in question rather than a helper it spawned.  Values are
    kept as the kernel printed them, stripped; :func:`classify` judges them.  A
    field that is absent, unreadable or listed twice is recorded as ``None``.
    """
    status = read(PROC_STATUS)
    fields: dict[str, str | None] = {name: None for name in PRIVILEGE_FIELDS}
    counts: dict[str, int] = {}
    for line in (status or "").splitlines():
        name, separator, value = line.partition(":")
        if separator and name in fields:
            counts[name] = counts.get(name, 0) + 1
            fields[name] = value.strip() if counts[name] == 1 else None
    sysctls: dict[str, str | None] = {}
    for path in FORWARDING_SYSCTLS:
        text = read(path)
        sysctls[path] = None if text is None else text.strip()
    return {"schema": PRIVILEGE_SCHEMA, "status": fields, "sysctls": sysctls}


def capture(
    *, read: Callable[[str], str | None] = _read_text,
) -> dict[str, object]:
    """Return complete, machine-readable evidence without changing the host.

    ``privilege`` records the facts the ``forwarding`` counter's privilege
    basis reads; ``read`` is injectable so a test never reads the host.
    """
    return {
        "schema": 1,
        "captured_at": datetime.now(timezone.utc).isoformat(),
        "privilege": privilege_facts(read),
        "observations": [asdict(_run(command)) for command in COMMANDS],
    }


def write(evidence: dict[str, object], destination: Path) -> None:
    atomic_write_text(
        destination,
        json.dumps(evidence, indent=2, sort_keys=True) + "\n",
    )


def _observations(evidence: dict[str, object]) -> dict[tuple[str, ...], dict]:
    result = {}
    for item in evidence.get("observations", []):
        command = tuple(item["command"])
        result[command] = item
    return result


def _invalid_evidence(evidence: dict[str, object], label: str) -> list[str]:
    """Return reasons a snapshot cannot be trusted as evidence."""
    violations: list[str] = []
    if evidence.get("schema") != 1:
        violations.append(f"{label} evidence has an unsupported schema")
    items = evidence.get("observations")
    if not isinstance(items, list):
        violations.append(f"{label} evidence has no observation list")
        return violations
    commands: list[tuple[str, ...]] = []
    for item in items:
        if not isinstance(item, dict):
            violations.append(f"{label} evidence contains a malformed observation")
            continue
        raw_command = item.get("command")
        if (not isinstance(raw_command, (list, tuple))
                or not all(isinstance(part, str) for part in raw_command)):
            violations.append(f"{label} evidence contains a malformed command")
            continue
        command = tuple(raw_command)
        commands.append(command)
        if not isinstance(item.get("stdout"), str) or \
                not isinstance(item.get("stderr"), str):
            violations.append(
                f"{label} command has malformed output: " + " ".join(command))
        unavailable_nft = (
            command == NFT_COMMAND
            and item.get("returncode") == 3
            and item.get("stdout") == ""
            and item.get("stderr") == NFT_UNAVAILABLE
        )
        if item.get("returncode") != 0 and not unavailable_nft:
            violations.append(
                f"{label} command failed ({item.get('returncode')}): "
                + " ".join(command))
    required = set(COMMANDS)
    observed = set(commands)
    for command in sorted(required - observed):
        violations.append(
            f"{label} evidence is missing command: " + " ".join(command))
    for command in sorted(observed - required):
        violations.append(
            f"{label} evidence has unexpected command: " + " ".join(command))
    if len(commands) != len(observed):
        violations.append(f"{label} evidence contains duplicate commands")
    return violations


def _socket_lines(item: dict) -> set[str]:
    return {
        " ".join(line.split())
        for line in item["stdout"].splitlines()
        if line.strip()
    }


def _allowed_socket(line: str, allowed_ports: frozenset[int]) -> bool:
    fields = line.split()
    if len(fields) < 5 or fields[0] != "tcp" or fields[1] != "LISTEN":
        return False
    local = fields[4]
    return any(
        local in {f"127.0.0.1:{port}", f"[::ffff:127.0.0.1]:{port}"}
        for port in allowed_ports
    )


def _socket_port(line: str) -> int | None:
    fields = line.split()
    if len(fields) < 5:
        return None
    local = fields[4]
    try:
        return int(local.rsplit(":", 1)[1])
    except (IndexError, ValueError):
        return None


def _comparable_stdout(command: tuple[str, ...], stdout: str) -> object:
    """Remove only time-to-expiry fields while retaining the raw evidence."""
    if command != ADDRESS_COMMAND:
        return stdout
    try:
        addresses = json.loads(stdout)
    except json.JSONDecodeError:
        return stdout
    for interface in addresses:
        for address in interface.get("addr_info", []):
            address.pop("valid_life_time", None)
            address.pop("preferred_life_time", None)
    return addresses


def compare(
    before: dict[str, object],
    after: dict[str, object],
    *,
    allow_qemu_listeners: bool = False,
    allowed_ports: frozenset[int] = ALLOWED_QEMU_PORTS,
) -> list[str]:
    """Return invariant violations; an empty result means the host is unchanged."""
    violations = _invalid_evidence(before, "before")
    violations.extend(_invalid_evidence(after, "comparison"))
    if violations:
        return violations
    left = _observations(before)
    right = _observations(after)
    if set(left) != set(right):
        violations.append("the evidence command set changed")
        return violations

    socket_command = SOCKET_COMMAND
    for command in sorted(left):
        old = left[command]
        new = right[command]
        if command == socket_command:
            if old["returncode"] != new["returncode"] or \
                    old["stderr"] != new["stderr"]:
                violations.append("socket observation status changed")
                continue
            if not allow_qemu_listeners:
                if _socket_lines(old) != _socket_lines(new):
                    violations.append(
                        "ss -H -lntup changed listening sockets")
                continue
            added = _socket_lines(new) - _socket_lines(old)
            removed = _socket_lines(old) - _socket_lines(new)
            bad = sorted(
                line for line in added
                if not _allowed_socket(line, allowed_ports))
            observed_ports = {
                port for line in added
                if (port := _socket_port(line)) is not None
                and _allowed_socket(line, allowed_ports)
            }
            allowed_lines = [
                line for line in added
                if _allowed_socket(line, allowed_ports)
            ]
            if removed:
                violations.append(
                    "pre-existing listening sockets disappeared: "
                    + " | ".join(sorted(removed)))
            if bad:
                violations.append(
                    "unexpected listening sockets appeared: " + " | ".join(bad))
            if (observed_ports != set(allowed_ports)
                    or len(allowed_lines) != len(allowed_ports)):
                violations.append(
                    "allowed listener set did not match: expected "
                    + ",".join(str(port) for port in sorted(allowed_ports))
                    + "; observed "
                    + ",".join(str(port) for port in sorted(observed_ports)))
            continue
        for field in ("returncode", "stdout", "stderr"):
            old_value = old[field]
            new_value = new[field]
            if field == "stdout":
                old_value = _comparable_stdout(command, old_value)
                new_value = _comparable_stdout(command, new_value)
            if old_value != new_value:
                violations.append(
                    f"{' '.join(command)} changed field {field}")
    return violations


def assert_unchanged(
    before: dict[str, object],
    after: dict[str, object],
    *,
    allow_qemu_listeners: bool = False,
) -> None:
    violations = compare(
        before, after, allow_qemu_listeners=allow_qemu_listeners)
    if violations:
        raise RuntimeError(
            "host network invariants failed:\n- " + "\n- ".join(violations))


def compare_cycle(
    before: dict[str, object],
    during: dict[str, object],
    after: dict[str, object],
    *,
    allowed_ports: frozenset[int] = ALLOWED_QEMU_PORTS,
) -> list[str]:
    """Judge both the live simulation boundary and complete cleanup."""
    violations = [
        f"during simulation: {item}" for item in compare(
            before, during, allow_qemu_listeners=True,
            allowed_ports=allowed_ports)
    ]
    violations.extend(
        f"after simulation: {item}" for item in compare(before, after))
    return violations


# ---------------------------------------------------------------------------
# Gate-12 host-network change counters
# ---------------------------------------------------------------------------
#
# ``factory_verify._check_host_network`` reads exactly one measurement,
# ``host_network_changes``.  It renders the acceptance check
# ``no_host_network_change`` as:
#
#   NOT-RUN  the ``host_network_changes`` key is absent entirely
#   WAIVED   (ADR 0080) six counters are the integer zero and ``unifi`` holds
#            exactly the :data:`UNPROVEN` sentinel; the run verdict is then
#            ``PASS-WITH-WAIVER``, never ``PASS``
#   FAIL     otherwise, when the value is not a mapping, or does not carry all
#            seven of tap/bridge/route/vlan/forwarding/listener/unifi, or any
#            of those seven is not an ``int`` or is not ``0``
#   PASS     all seven are present and are the integer zero
#
# So a category this module cannot prove must never reach that mapping as a
# zero.  The mapping also carries ``basis``, which says how ``forwarding`` was
# proven (``snapshot`` or ``privilege``, see above); check 9 names a privilege
# basis in its detail so a receipt cannot read it as "nothing changed".  Two
# honest renderings exist and both are supported here:
#
#   * :func:`change_counters` raises :class:`UnprovenCategory` rather than
#     return a fabricated zero.  A producer that catches it and omits the
#     whole ``host_network_changes`` key leaves check 9 at NOT-RUN, which is
#     the honest verdict for "this run did not measure it".
#   * :func:`classify` never raises for an unproven category: it puts the
#     :data:`UNPROVEN` string sentinel in that counter's slot.  A producer
#     that emits that mapping renders check 9 FAIL, because the sentinel is
#     not an ``int`` -- except when ``unifi`` is the only unproven slot,
#     which ADR 0080 waives.  It can never render PASS.
#
# Nothing here returns a hostname, address, MAC, or interface name.  Object
# identities are built only to be compared and are never surfaced: the public
# results carry counts, category names, and observation command names.

CATEGORIES: tuple[str, ...] = (
    "tap", "bridge", "route", "vlan", "forwarding", "listener", "unifi")

#: Placed in a counter slot that has no positive observation behind it.  It is
#: deliberately not an integer so gate-12 check 9 cannot read it as a PASS.
UNPROVEN = "unproven"

UNIFI_SCHEMA = 1

# Which counters each observation can prove.  A command that is missing,
# failed, unparseable, or that produced a difference this module cannot
# attribute to a shape leaves every category listed here UNPROVEN.
#
# ``ip -j address show`` informs the interface categories because an address
# belongs to an interface whose kind the link observation names, and informs
# ``route`` because an address implies its connected route.
#
# ``ip netns list`` informs every topology category: a namespace that appears
# or disappears can hide taps, bridges, routes, VLANs, and rules from every
# other command in this list, so its own stability is part of their proof.
_CATEGORY_SOURCES: dict[tuple[str, ...], tuple[str, ...]] = {
    LINK_COMMAND: ("tap", "bridge", "vlan"),
    ADDRESS_COMMAND: ("tap", "bridge", "vlan", "route"),
    ROUTE4_COMMAND: ("route",),
    ROUTE6_COMMAND: ("route",),
    BRIDGE_LINK_COMMAND: ("bridge",),
    BRIDGE_VLAN_COMMAND: ("vlan",),
    NETNS_COMMAND: ("tap", "bridge", "route", "vlan", "forwarding"),
    NFT_COMMAND: ("forwarding",),
    SOCKET_COMMAND: ("listener",),
}

# ``linkinfo.info_kind`` to counter category.  A kind that is absent (a
# physical NIC, loopback) or unlisted (veth, dummy, bond, wireguard) is
# deliberately unmapped: such a device is not one of the seven categories, so
# a *change* to one cannot be attributed and must leave the link-derived
# categories UNPROVEN rather than silently count as nothing.
_LINK_KINDS: dict[str, str] = {
    "tun": "tap",
    "tap": "tap",
    "bridge": "bridge",
    "vlan": "vlan",
    "macvlan": "vlan",
    "macvtap": "vlan",
    "vxlan": "vlan",
}

_VOLATILE_ADDRESS_FIELDS = ("valid_life_time", "preferred_life_time")


class ClassificationError(RuntimeError):
    """Snapshots cannot support a host-network change count."""


class UnprovenCategory(ClassificationError):
    """A gate-12 category has no positive observation behind it.

    Raised instead of returning a zero.  ``reasons`` maps each unproven
    category to a shape-only explanation.
    """

    def __init__(self, reasons: dict[str, str]) -> None:
        self.reasons = dict(reasons)
        super().__init__(
            "host network change counters are unproven:\n- "
            + "\n- ".join(
                f"{name}: {self.reasons[name]}"
                for name in sorted(self.reasons)))


def _is_count(value: object, *, minimum: int = 0) -> bool:
    """A real, non-boolean count.  ``True`` is not an observation of one."""
    return (isinstance(value, int) and not isinstance(value, bool)
            and value >= minimum)


def _is_named(value: object) -> bool:
    """A non-empty label naming what made an observation."""
    return isinstance(value, str) and bool(value.strip())


def unifi_no_contact(
    *,
    audited_processes: int,
    auditor: str,
    egress_contacts: int,
    egress_observation: str,
) -> dict[str, object]:
    """Build the positive observation the ``unifi`` counter requires.

    ``COMMANDS`` observes no UniFi surface at all, so this module can never
    derive a UniFi verdict from a host snapshot.  A zero there is only
    defensible when a caller supplies an observation that something actually
    watched for a UniFi contact and saw none; without this argument
    :func:`classify` reports ``unifi`` as :data:`UNPROVEN`.

    The two halves are both required because they cover different actors:

    ``audited_processes`` / ``auditor``
        how many *guest* processes were proved, from the kernel's own view of
        their argv, to carry a loopback socket NIC only -- the audit
        ``vm.network.assert_isolated`` performs and
        ``factory_runner.audit_live_process`` re-performs live, which refuses
        the literal term ``unifi`` along with tap/bridge/user/slirp.  It
        proves no guest could reach a UniFi controller.
    ``egress_contacts`` / ``egress_observation``
        how many contacts to a UniFi endpoint an observation of the *host's*
        own outbound traffic saw across the whole run window, and what made
        that observation.  The guest audit says nothing about the host
        process, and ``ss -H -lntup`` lists listening sockets only, so this
        half cannot be derived from anything in ``COMMANDS`` today.

    Raises ``ValueError`` for an observation that does not actually observe
    anything (no audited process, an unnamed auditor or observation, or a
    negative contact count).
    """
    if not _is_count(audited_processes, minimum=1):
        raise ValueError("a UniFi observation must audit at least one process")
    if not _is_count(egress_contacts):
        raise ValueError("egress contacts must be a non-negative count")
    if not _is_named(auditor):
        raise ValueError("a UniFi observation must name its auditor")
    if not _is_named(egress_observation):
        raise ValueError(
            "a UniFi observation must name its egress observation")
    return {
        "schema": UNIFI_SCHEMA,
        "guest_isolation_audit": {
            "audited_processes": audited_processes,
            "auditor": auditor,
        },
        "host_egress": {
            "contacts": egress_contacts,
            "observation": egress_observation,
        },
    }


def _load_json(text: str) -> object | None:
    try:
        return json.loads(text)
    except (json.JSONDecodeError, ValueError):
        return None


def _canonical(value: object) -> str:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), default=str)


def _place(objects: dict, prefix: str, shape: str, category, owner) -> None:
    """Record one object, preserving multiplicity of identical shapes."""
    occurrence = 0
    while f"{prefix}/{occurrence}/{shape}" in objects:
        occurrence += 1
    objects[f"{prefix}/{occurrence}/{shape}"] = (category, owner)


def _link_objects(text: str):
    entries = _load_json(text)
    if not isinstance(entries, list):
        return None
    objects: dict[str, tuple] = {}
    for entry in entries:
        if not isinstance(entry, dict):
            return None
        info = entry.get("linkinfo")
        kind = info.get("info_kind") if isinstance(info, dict) else None
        category = _LINK_KINDS.get(kind) if isinstance(kind, str) else None
        name = entry.get("ifname")
        _place(objects, "link", _canonical(entry), category,
               name if isinstance(name, str) else None)
    return objects


def _address_objects(text: str):
    entries = _load_json(text)
    if not isinstance(entries, list):
        return None
    objects: dict[str, tuple] = {}
    for entry in entries:
        if not isinstance(entry, dict):
            return None
        name = entry.get("ifname")
        owner = name if isinstance(name, str) else None
        infos = entry.get("addr_info", [])
        if not isinstance(infos, list):
            return None
        for address in infos:
            if not isinstance(address, dict):
                return None
            stable = {
                key: value for key, value in address.items()
                if key not in _VOLATILE_ADDRESS_FIELDS
            }
            # The owner resolves to a category once the link observation has
            # been parsed; an address on an interface of an unmapped kind
            # stays unattributed.
            _place(objects, "address", _canonical([owner, stable]),
                   None, owner)
    return objects


def _flat_objects(prefix: str, category: str | None):
    def parse(text: str):
        entries = _load_json(text)
        if not isinstance(entries, list):
            return None
        objects: dict[str, tuple] = {}
        for entry in entries:
            _place(objects, prefix, _canonical(entry), category, None)
        return objects
    return parse


def _nft_objects(text: str):
    document = _load_json(text)
    if not isinstance(document, dict):
        return None
    elements = document.get("nftables")
    if not isinstance(elements, list):
        return None
    objects: dict[str, tuple] = {}
    for element in elements:
        _place(objects, "ruleset", _canonical(element), "forwarding", None)
    return objects


def _netns_objects(text: str):
    objects: dict[str, tuple] = {}
    for line in text.splitlines():
        if line.strip():
            # A namespace is not one of the seven categories, so a namespace
            # difference is deliberately unattributable.
            _place(objects, "netns", _canonical(" ".join(line.split())),
                   None, None)
    return objects


_PARSERS = {
    LINK_COMMAND: _link_objects,
    ADDRESS_COMMAND: _address_objects,
    ROUTE4_COMMAND: _flat_objects("route4", "route"),
    ROUTE6_COMMAND: _flat_objects("route6", "route"),
    BRIDGE_LINK_COMMAND: _flat_objects("bridge-port", "bridge"),
    BRIDGE_VLAN_COMMAND: _flat_objects("bridge-vlan", "vlan"),
    NETNS_COMMAND: _netns_objects,
    NFT_COMMAND: _nft_objects,
}


def _observation_map(evidence: object) -> dict[tuple[str, ...], dict | None]:
    """Return every required command mapped to its usable observation or None.

    ``None`` means the command cannot be used as evidence: the snapshot is
    malformed, the command is missing or duplicated, it exited non-zero (the
    tolerated "nft is unavailable" exit included -- an unreadable ruleset is
    not a ruleset that did not change), or its output is not text.
    """
    result: dict[tuple[str, ...], dict | None] = {
        command: None for command in COMMANDS}
    if not isinstance(evidence, dict) or evidence.get("schema") != 1:
        return result
    items = evidence.get("observations")
    if not isinstance(items, list):
        return result
    seen: set[tuple[str, ...]] = set()
    for item in items:
        if not isinstance(item, dict):
            continue
        raw = item.get("command")
        if not isinstance(raw, (list, tuple)) or \
                not all(isinstance(part, str) for part in raw):
            continue
        command = tuple(raw)
        if command not in result:
            continue
        if command in seen:
            result[command] = None
            continue
        seen.add(command)
        if item.get("returncode") != 0:
            continue
        if not isinstance(item.get("stdout"), str) or \
                not isinstance(item.get("stderr"), str):
            continue
        result[command] = item
    return result


def _link_kind_map(parsed: list[dict | None]) -> dict[str, str]:
    kinds: dict[str, str] = {}
    for objects in parsed:
        for category, owner in (objects or {}).values():
            if isinstance(owner, str) and category is not None:
                kinds[owner] = category
    return kinds


def _unifi_counter(observation: object) -> tuple[int | None, str | None]:
    if observation is None:
        return None, (
            "no UniFi observation was supplied; COMMANDS observes no UniFi "
            "surface, so a zero would rest on the absence of a check rather "
            "than on evidence (see unifi_no_contact)")
    if not isinstance(observation, dict) or \
            observation.get("schema") != UNIFI_SCHEMA:
        return None, "the UniFi observation has an unsupported schema"
    audit = observation.get("guest_isolation_audit")
    egress = observation.get("host_egress")
    if not isinstance(audit, dict) or not isinstance(egress, dict):
        return None, "the UniFi observation is missing a required half"
    audited = audit.get("audited_processes")
    auditor = audit.get("auditor")
    contacts = egress.get("contacts")
    source = egress.get("observation")
    if not _is_count(audited, minimum=1) or not _is_named(auditor):
        return None, "the UniFi observation records no guest isolation audit"
    if not _is_count(contacts) or not _is_named(source):
        return None, "the UniFi observation records no host egress observation"
    return contacts, None


def _command_of(item: object) -> tuple[str, ...] | None:
    raw = item.get("command") if isinstance(item, dict) else None
    if not isinstance(raw, (list, tuple)) or \
            not all(isinstance(part, str) for part in raw):
        return None
    return tuple(raw)


def _ruleset_unreadable(evidence: object) -> bool:
    """The snapshot ran ``nft`` exactly once, well formed, and it failed.

    Only this -- the ruleset could not be READ -- opens the privilege basis.
    A snapshot that is malformed, or never ran ``nft``, or ran it twice, is not
    an unreadable ruleset; it is unusable evidence and stays unproven.
    """
    if not isinstance(evidence, dict) or evidence.get("schema") != 1:
        return False
    items = evidence.get("observations")
    if not isinstance(items, list):
        return False
    matches = [item for item in items if _command_of(item) == NFT_COMMAND]
    if len(matches) != 1:
        return False
    item = matches[0]
    returncode = item.get("returncode")
    return (_is_count(returncode, minimum=1)
            and isinstance(item.get("stdout"), str)
            and isinstance(item.get("stderr"), str))


def _privilege_record(evidence: object) -> dict | None:
    facts = evidence.get("privilege") if isinstance(evidence, dict) else None
    if not isinstance(facts, dict) or facts.get("schema") != PRIVILEGE_SCHEMA:
        return None
    return facts


def _privilege_problem(evidence: object) -> str | None:
    """Why one snapshot does not show an unprivileged, NoNewPrivs process."""
    facts = _privilege_record(evidence)
    status = facts.get("status") if facts is not None else None
    if not isinstance(status, dict):
        return "no privilege facts were recorded"
    if status.get("NoNewPrivs") != "1":
        return "NoNewPrivs was not recorded as 1"
    uids = status.get("Uid")
    uids = uids.split() if isinstance(uids, str) else []
    if len(uids) != 4 or not all(_UID.match(uid) for uid in uids):
        return "Uid was not recorded"
    if any(int(uid) == 0 for uid in uids):
        return "Uid holds 0, which may write the forwarding sysctls"
    for name in CAPABILITY_SETS:
        mask = status.get(name)
        if not isinstance(mask, str) or not _CAPABILITY_MASK.match(mask):
            return f"{name} was not recorded"
        held = sorted(
            capability
            for capability, bit in FORBIDDEN_CAPABILITIES.items()
            if int(mask, 16) >> bit & 1)
        if held:
            return f"{name} holds {', '.join(held)}"
    return None


def _sysctl_changes(snapshots: Sequence[object]) -> int | None:
    """How many forwarding sysctls differ across the cycle, or ``None``.

    ``None`` unless every snapshot recorded every sysctl as an integer.
    """
    values = []
    for evidence in snapshots:
        facts = _privilege_record(evidence)
        sysctls = facts.get("sysctls") if facts is not None else None
        if not isinstance(sysctls, dict):
            return None
        recorded = {path: sysctls.get(path) for path in FORWARDING_SYSCTLS}
        if not all(isinstance(value, str) and _SYSCTL_VALUE.match(value)
                   for value in recorded.values()):
            return None
        values.append(recorded)
    return sum(1 for path in FORWARDING_SYSCTLS
               if len({recorded[path] for recorded in values}) > 1)


def _forwarding_privilege_reason(
    snapshots: Sequence[object], labels: Sequence[str],
    sysctl_changes: int | None,
) -> str | None:
    """Why the privilege basis cannot prove ``forwarding``, or ``None``.

    A counted sysctl change needs no privilege proof: it is a positive
    observation of a forwarding change, and is counted as one.
    """
    if sysctl_changes is None:
        return ("the nft ruleset was unreadable and the forwarding sysctls "
                "were not recorded in every snapshot")
    if sysctl_changes:
        return None
    for label, evidence in zip(labels, snapshots):
        problem = _privilege_problem(evidence)
        if problem is not None:
            return (f"the nft ruleset was unreadable and the {label} snapshot "
                    f"does not prove the run unprivileged: {problem}")
    return None


def classify(
    before: dict[str, object],
    after: dict[str, object],
    *,
    during: dict[str, object] | None = None,
    allowed_ports: frozenset[int] = frozenset(),
    unifi: dict[str, object] | None = None,
) -> dict[str, object]:
    """Reduce a host-network snapshot cycle to the seven gate-12 counters.

    ``before`` and ``after`` bracket the run; ``during`` is the live snapshot
    :func:`compare_cycle` already takes, and should always be supplied when it
    exists (see the attribution rule).  ``allowed_ports`` names the run's own
    private loopback control ports, which are exempt from the ``listener``
    counter for the duration of ``during`` only -- exactly the allowance
    :func:`compare` implements.  ``unifi`` is the positive observation
    :func:`unifi_no_contact` builds.

    CHANGE ATTRIBUTION RULE.  Every observation is reduced to a multiset of
    shape-only object identities: one link, one address, one route, one bridge
    port, one VLAN entry, one ruleset element, one namespace, one listening
    socket.  An identity present in *every* snapshot of the cycle is
    pre-existing host state and is never a change, no matter what it is: a
    host's own taps, bridges and routes cost nothing.  An identity absent from
    at least one snapshot is one change, counted against the category its
    shape belongs to.  With ``during`` supplied this counts an object that was
    created and torn down inside the run (absent from before and after, present
    in during) exactly as it counts one the run left behind (absent from
    before).  Without ``during`` such an object is invisible, which is why the
    live snapshot should always be passed.

    Returns a report; it never raises for an unproven category.  ``counters``
    holds an ``int`` per category, or the :data:`UNPROVEN` sentinel where no
    positive observation stands behind a zero: a failed, missing, duplicated
    or unparseable observation, a difference whose shape cannot be attributed
    to any of the seven categories, or (always, by default) ``unifi``.
    ``proven`` is True only when every counter is an integer.  Nothing in the
    report identifies a host: counts, category names, and the observation
    command names only.

    FORWARDING BASIS.  ``basis["forwarding"]`` says how that counter was
    proven.  ``snapshot`` -- the ruleset was readable in every snapshot, and
    its differences are counted as above.  ``privilege`` -- ``nft`` ran and
    failed in at least one snapshot, so the counter is proven only if every
    snapshot records NoNewPrivs 1, no uid 0, and no CAP_NET_ADMIN or
    CAP_SYS_ADMIN in CapEff, CapPrm or CapAmb, and the forwarding sysctls are
    equal throughout (see the privilege-basis comment above).  Any fact
    missing, unreadable or wrong leaves it UNPROVEN.  Under either basis a forwarding sysctl recorded
    in every snapshot that differs is counted as a forwarding change, and the
    ``ip netns list`` observation must still be usable and stable.
    """
    snapshots = [before] if during is None else [before, during]
    snapshots.append(after)
    labels = ["before"] if during is None else ["before", "during"]
    labels.append("after")
    maps = [_observation_map(snapshot) for snapshot in snapshots]
    # The privilege basis replaces the ruleset comparison only when the
    # ruleset could not be read; a readable ruleset is always compared.
    by_privilege = any(entry[NFT_COMMAND] is None for entry in maps) and all(
        entry[NFT_COMMAND] is not None or _ruleset_unreadable(snapshot)
        for entry, snapshot in zip(maps, snapshots))

    counters: dict[str, object] = {name: 0 for name in CATEGORIES}
    reasons: dict[str, str] = {}

    def unprove(categories, reason: str) -> None:
        for name in categories:
            reasons.setdefault(name, reason)

    parsed: dict[tuple[str, ...], list[dict] | None] = {}
    for command in COMMANDS:
        if command == SOCKET_COMMAND:
            continue
        if command == NFT_COMMAND and by_privilege:
            parsed[command] = None
            continue
        sources = _CATEGORY_SOURCES[command]
        if any(entry[command] is None for entry in maps):
            unprove(
                sources,
                "no usable observation from: " + " ".join(command))
            parsed[command] = None
            continue
        objects = [
            _PARSERS[command](entry[command]["stdout"]) for entry in maps]
        if any(item is None for item in objects):
            unprove(sources, "unparseable output from: " + " ".join(command))
            parsed[command] = None
            continue
        parsed[command] = objects

    kinds = _link_kind_map(parsed.get(LINK_COMMAND) or [])
    for command, objects in parsed.items():
        if objects is None:
            continue
        sources = _CATEGORY_SOURCES[command]
        identities = set().union(*(set(item) for item in objects))
        for identity in sorted(identities):
            present = [item for item in objects if identity in item]
            if len(present) == len(objects):
                continue
            category, owner = present[0][identity]
            if category is None and isinstance(owner, str):
                category = kinds.get(owner)
            if category is None:
                unprove(
                    sources,
                    "a difference could not be attributed to a category: "
                    + " ".join(command))
                continue
            counters[category] = counters[category] + 1

    sysctl_changes = _sysctl_changes(snapshots)
    if by_privilege:
        reason = _forwarding_privilege_reason(
            snapshots, labels, sysctl_changes)
        if reason is not None:
            unprove(("forwarding",), reason)
    if sysctl_changes:
        counters["forwarding"] = counters["forwarding"] + sysctl_changes

    if any(entry[SOCKET_COMMAND] is None for entry in maps):
        unprove(("listener",),
                "no usable observation from: " + " ".join(SOCKET_COMMAND))
    else:
        lines = [_socket_lines(entry[SOCKET_COMMAND]) for entry in maps]
        listener = len(lines[0] ^ lines[-1])
        if during is not None:
            listener += len(lines[0] - lines[1])
            listener += sum(
                1 for line in lines[1] - lines[0]
                if not _allowed_socket(line, allowed_ports))
        counters["listener"] = listener

    contacts, unifi_reason = _unifi_counter(unifi)
    if unifi_reason is not None:
        reasons.setdefault("unifi", unifi_reason)
    else:
        counters["unifi"] = contacts

    for name in reasons:
        counters[name] = UNPROVEN
    return {
        "schema": 1,
        "kind": "host-network-change-classification",
        "counters": counters,
        "unproven": sorted(reasons),
        "reasons": dict(sorted(reasons.items())),
        "proven": not reasons,
        "snapshots": len(maps),
        "basis": {
            "forwarding": BASIS_PRIVILEGE if by_privilege else BASIS_SNAPSHOT},
    }


def change_counters(
    before: dict[str, object],
    after: dict[str, object],
    *,
    during: dict[str, object] | None = None,
    allowed_ports: frozenset[int] = frozenset(),
    unifi: dict[str, object] | None = None,
) -> dict[str, object]:
    """The gate-12 ``host_network_changes`` measurement, or nothing at all.

    Same arguments and same attribution rule as :func:`classify`, of which
    this is the fail-closed form: it returns the seven counters as integers,
    plus the ``basis`` mapping that says how ``forwarding`` was proven, only
    when every counter is proven, and raises :class:`UnprovenCategory`
    otherwise.  It never returns a zero it cannot support, so a producer may
    put the result straight into ``measurements["host_network_changes"]``.
    Catching the exception and omitting that key leaves gate-12 check 9 at
    NOT-RUN; emitting ``classify(...)["counters"]`` (with its ``basis``)
    instead renders it FAIL, or WAIVED under ADR 0080 when ``unifi`` is the
    only unproven counter.  Neither can render PASS.
    """
    report = classify(
        before, after, during=during, allowed_ports=allowed_ports, unifi=unifi)
    if not report["proven"]:
        raise UnprovenCategory(report["reasons"])
    measurement: dict[str, object] = {
        name: int(value) for name, value in report["counters"].items()}
    measurement["basis"] = dict(report["basis"])
    return measurement
