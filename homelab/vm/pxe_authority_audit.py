#!/usr/bin/env python3
"""Read-only gate-4 PXE authority audit over switch evidence logs.

Gate 4 (homelab/WORKSTATION-FACTORY-STATE.md) requires packet evidence that
the simulated gateway remains the sole DHCP authority, that the controller
supplies only the approved boot and identity services, and that no frame
reaches an endpoint outside the enumerated loopback fabric.

This module never mutates anything.  It parses one or more `switch.jsonl`
evidence files written by ``homelab/vm/simulated_switch.py`` and renders one
machine-readable verdict per check: PASS, FAIL, or NOT-PROVABLE.  A check is
NOT-PROVABLE when the recorded events cannot support the claim; a planned
assertion is never reported as a pass.

What the switch records today (schema derived from ``simulated_switch.py``
and ``HubPolicy`` in ``simulated_gateway.py``):

* ``switch-ready``   -- the enumerated fabric: ``ports`` = [{port, mac}].
* ``port-connected`` / ``port-disconnected`` / ``port-connection-refused``
  -- authenticated peer lifecycle with ``port``, ``mac``, ``generation``.
* ``peer-abandoned-before-authentication`` -- a socket closed pre-identity.
* ``source-mac-blocked`` -- an authenticated port sent a frame whose source
  MAC was not its pinned identity (``expected`` vs ``observed``).
* ``dhcp``           -- one record per parseable DHCP frame from any peer
  (``kind`` DISCOVER/OFFER/REQUEST/ACK/NAK, ``peer``, ``source_mac``,
  ``client_mac``, ``transaction``, optional ``delivered_to``, ``blocked``,
  ``offered_ip``, ``requested_ip``, ``boot_file``, ``next_server``,
  ``architecture``, generation annotations).
* ``switch-summary`` -- final counters; ``evidence-limit`` -- events were
  omitted after the bounded-evidence cap.

``simulated_switch.py`` now records one ``flow`` event per distinct delivery
with fields ``peer``, ``delivered_to``, ``ethertype``, ``ip_protocol``,
``src_port``, ``dst_port`` (header fields only, never payloads), so the
approved-service-flow check is provable against current evidence.  A log with
no ``flow`` events at all (an older log, or a run that delivered no frames)
leaves that check NOT-PROVABLE.

The approved controller service ports are rooted in the reviewed controller
convergence verification in
``homelab/vm/controller_factory.py::verification_commands`` (``ss -H -lun``
must show UDP {53, 69, 123}; ``ss -H -ltn`` must show TCP {53, 80, 88, 389,
445}; UDP {67, 4011} DHCP/ProxyDHCP must not be listening) and extended to the
rest of the surface a real Samba AD DC + PXE controller serves -- see the
``APPROVED_CONTROLLER_*`` constants below for the per-port authority.  The
flow check treats the port the controller itself occupies as the service
port, tolerates the return leg of an approved request (a reply to an ephemeral
client port), correlates TFTP data transfers to their initiating 69/udp read
request, and treats ambient link-local traffic (ARP, IPv6 ND/MLD, EAPOL,
ICMP, IGMP, and LLMNR/mDNS/SSDP discovery multicast) as non-service.  It still
fails a controller that serves DHCP/ProxyDHCP, emits an identity announcement,
or is contacted on / answers from any unapproved service port.  The gateway
label ``gateway`` is hard-coded evidence vocabulary in ``HubPolicy`` and the
pinned gateway port name in ``factory_runner.switch_command``.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path

try:
    from .simulated_gateway import GATEWAY_MAC, IDENTITY_ETHERTYPE
    from .simulated_topology import MACS
except ImportError:  # pragma: no cover - direct script execution
    from simulated_gateway import GATEWAY_MAC, IDENTITY_ETHERTYPE
    from simulated_topology import MACS


PASS = "PASS"
FAIL = "FAIL"
NOT_PROVABLE = "NOT-PROVABLE"

GATE = "workstation-factory-gate-4"

# Approved controller service ports.  Root of authority: the reviewed Samba
# Active Directory domain controller + PXE controller in
# ``homelab/vm/controller_factory.py``.  ``verification_commands`` asserts the
# required listeners (``ss -lun`` UDP {53,69,123}; ``ss -ltn`` TCP
# {53,80,88,389,445}) and forbids any DHCP/ProxyDHCP listener (UDP {67,4011});
# it is a required-presence check, not an exhaustive allowlist.  A real Samba
# AD DC (``samba.service`` with ``smbd``/``nmbd`` and ``netbios``) additionally
# answers the AD identity surface below, so the audit models the actual served
# ports rather than only the grepped subset:
#   * DNS 53, Kerberos 88 and LDAP/CLDAP 389 are served over BOTH TCP and UDP.
#   * NetBIOS name 137/udp and datagram 138/udp (nmbd), session 139/tcp (smbd).
#   * MSRPC endpoint mapper 135/tcp and the DC's fixed dynamic RPC endpoints
#     49152/49153 (netlogon, lsarpc, samr, drsuapi), observed uniformly across
#     every recorded domain-join run.
#   * TFTP 69/udp and HTTP 80/tcp (PXE boot); NTP 123/udp; SMB 445/tcp.
APPROVED_CONTROLLER_UDP = frozenset({53, 69, 88, 123, 137, 138, 389})
APPROVED_CONTROLLER_TCP = frozenset({53, 80, 88, 135, 139, 389, 445, 49152, 49153})
# The controller must never *serve* DHCP/ProxyDHCP: a frame whose controller-
# side port is one of these means the controller is offering the service.  Port
# 68 is a client port and is handled by DHCP_CLIENT_PORTS below, not here.
FORBIDDEN_DHCP_PORTS = frozenset({67, 4011})
# The controller may act as a DHCP *client* to acquire its own lease from the
# gateway (BOOTP client/server ports); this is not a competing authority.
DHCP_CLIENT_PORTS = frozenset({67, 68})
# Client use of the simulated gateway's own resolver/clock by the controller
# stays inside the fabric (homelab/vm/simulated_gateway.py serves 53/123).
GATEWAY_CLIENT_UDP = frozenset({53, 123})
# Link-local discovery multicast the workstation emits (LLMNR, mDNS, SSDP/UPnP)
# that merely reaches the controller as a segment recipient; not a service.
DISCOVERY_UDP_PORTS = frozenset({5353, 5355, 1900})

ETHERTYPE_IPV4 = 0x0800
ETHERTYPE_ARP = 0x0806
ETHERTYPE_IPV6 = 0x86DD
ETHERTYPE_EAPOL = 0x888E
# Ambient L2 control frames that carry no controller service and cannot leave
# the fabric: ARP resolution, IPv6 neighbour discovery / MLD, 802.1X EAPOL.
AMBIENT_ETHERTYPES = frozenset({ETHERTYPE_ARP, ETHERTYPE_IPV6, ETHERTYPE_EAPOL})

# IP protocol numbers.
IP_PROTO_ICMP = 1
IP_PROTO_IGMP = 2
IP_PROTO_TCP = 6
IP_PROTO_UDP = 17
# ICMP and IGMP are network-control protocols with no service port.
AMBIENT_IP_PROTOCOLS = frozenset({IP_PROTO_ICMP, IP_PROTO_IGMP})

DHCP_KINDS = frozenset({"DISCOVER", "OFFER", "REQUEST", "ACK", "NAK"})
DHCP_SERVER_KINDS = frozenset({"OFFER", "ACK", "NAK"})

KNOWN_EVENTS = frozenset({
    "switch-ready", "port-connected", "port-disconnected",
    "port-connection-refused", "peer-abandoned-before-authentication",
    "source-mac-blocked", "dhcp", "flow", "switch-summary", "evidence-limit",
})

CHECK_SOLE_AUTHORITY = "gate4.dhcp-sole-authority"
CHECK_CONTROLLER_SILENCE = "gate4.controller-no-dhcp"
CHECK_APPROVED_FLOWS = "gate4.controller-approved-flows-only"
CHECK_FABRIC_CLOSURE = "gate4.no-external-endpoint"

MISSING_FLOW_FIELDS = (
    'per-delivery "flow" events with fields peer, delivered_to, ethertype, '
    "ip_protocol, src_port, dst_port (this evidence recorded no flow events, "
    "so no controller service delivery can be examined -- either a log that "
    "predates simulated_switch.py flow logging or a run that delivered no "
    "frames)"
)

_MAC = re.compile(r"^[0-9a-f]{2}(?::[0-9a-f]{2}){5}$")


class EvidenceFormatError(ValueError):
    """A switch evidence file is malformed; the audit refuses to guess."""


class TopologyError(ValueError):
    """The endpoint topology description is unusable."""


@dataclass(frozen=True)
class Event:
    source: str
    line: int
    data: dict

    @property
    def kind(self) -> str:
        return str(self.data["event"])

    def where(self) -> str:
        return f"{self.source}:{self.line}"


@dataclass(frozen=True)
class Topology:
    """Enumerated fabric endpoints with gateway and controller roles."""

    endpoints: tuple[tuple[str, str], ...]
    gateway: str
    controller: str

    @property
    def by_name(self) -> dict[str, str]:
        return dict(self.endpoints)

    @property
    def names(self) -> frozenset[str]:
        return frozenset(name for name, _mac in self.endpoints)

    @property
    def gateway_mac(self) -> str:
        return self.by_name[self.gateway]

    @property
    def controller_mac(self) -> str:
        return self.by_name[self.controller]

    def as_json(self) -> dict:
        return {
            "endpoints": dict(sorted(self.endpoints)),
            "gateway": self.gateway,
            "controller": self.controller,
        }


@dataclass
class Check:
    check: str
    verdict: str
    details: list[str] = field(default_factory=list)
    missing: list[str] = field(default_factory=list)

    def as_json(self) -> dict:
        return {
            "check": self.check,
            "verdict": self.verdict,
            "details": self.details,
            "missing": self.missing,
        }


def _normalize_mac(value: object, context: str) -> str:
    if not isinstance(value, str):
        raise TopologyError(f"{context}: MAC must be a string")
    mac = value.strip().lower()
    if not _MAC.fullmatch(mac):
        raise TopologyError(f"{context}: invalid MAC address {value!r}")
    return mac


def make_topology(
    endpoints: dict[str, str], gateway: str, controller: str,
) -> Topology:
    if not endpoints:
        raise TopologyError("topology must enumerate at least one endpoint")
    normalized: dict[str, str] = {}
    for name, mac in endpoints.items():
        if not isinstance(name, str) or not name:
            raise TopologyError("endpoint names must be non-empty strings")
        normalized[name] = _normalize_mac(mac, f"endpoint {name}")
    if len(set(normalized.values())) != len(normalized):
        raise TopologyError("endpoint MAC addresses must be unique")
    for role, name in (("gateway", gateway), ("controller", controller)):
        if name not in normalized:
            raise TopologyError(f"{role} endpoint {name!r} is not enumerated")
    if gateway == controller:
        raise TopologyError("gateway and controller must be distinct")
    if gateway != "gateway":
        # HubPolicy hard-codes the evidence label "gateway" and the factory
        # pins the gateway port under that name; any other name would make
        # gateway-origin evidence unattributable.
        raise TopologyError(
            'the gateway endpoint must be named "gateway" to match the '
            "switch evidence vocabulary")
    return Topology(
        endpoints=tuple(sorted(normalized.items())),
        gateway=gateway, controller=controller)


def factory_topology() -> Topology:
    """The live factory fabric.

    Authoritative binding: ``factory_runner.switch_command`` pins exactly
    ``gateway=GATEWAY_MAC``, ``controller=MACS['controller']``, and
    ``workstation=MACS['client']``; a contract test keeps this in sync.
    """
    return make_topology(
        {
            "gateway": ":".join(f"{part:02x}" for part in GATEWAY_MAC),
            "controller": MACS["controller"],
            "workstation": MACS["client"],
        },
        gateway="gateway", controller="controller")


def load_topology(path: Path) -> Topology:
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as error:
        raise TopologyError(f"cannot read topology {path}: {error}") from error
    if not isinstance(raw, dict) or not isinstance(raw.get("endpoints"), dict):
        raise TopologyError(
            f'{path}: topology must be an object with an "endpoints" map')
    gateway = raw.get("gateway", "gateway")
    controller = raw.get("controller", "controller")
    if not isinstance(gateway, str) or not isinstance(controller, str):
        raise TopologyError(f"{path}: gateway/controller must be names")
    return make_topology(raw["endpoints"], gateway, controller)


def _require(event: Event, name: str, kinds: tuple[type, ...]) -> object:
    value = event.data.get(name)
    if not isinstance(value, kinds) or isinstance(value, bool):
        raise EvidenceFormatError(
            f"{event.where()}: {event.kind} event lacks a valid "
            f"{name!r} field")
    return value


def _validate_event(event: Event) -> None:
    kind = event.kind
    if kind == "dhcp":
        dhcp_kind = _require(event, "kind", (str,))
        if dhcp_kind not in DHCP_KINDS:
            raise EvidenceFormatError(
                f"{event.where()}: unknown DHCP kind {dhcp_kind!r}")
        _require(event, "peer", (str,))
        _require(event, "source_mac", (str,))
    elif kind in ("port-connected", "port-disconnected",
                  "port-connection-refused"):
        _require(event, "port", (str,))
        _require(event, "mac", (str,))
    elif kind == "switch-ready":
        ports = _require(event, "ports", (list,))
        for entry in ports:
            if (not isinstance(entry, dict)
                    or not isinstance(entry.get("port"), str)
                    or not isinstance(entry.get("mac"), str)):
                raise EvidenceFormatError(
                    f"{event.where()}: switch-ready ports must be "
                    "{port, mac} objects")
    elif kind == "source-mac-blocked":
        _require(event, "port", (str,))
        _require(event, "observed", (str,))
    elif kind == "flow":
        _require(event, "peer", (str,))
        _require(event, "delivered_to", (str,))
        _require(event, "ethertype", (int,))


def load_events(path: Path) -> list[Event]:
    """Parse one switch.jsonl strictly; refuse rather than guess."""
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as error:
        raise EvidenceFormatError(
            f"cannot read evidence {path}: {error}") from error
    events: list[Event] = []
    for number, line in enumerate(text.splitlines(), 1):
        if not line.strip():
            raise EvidenceFormatError(f"{path}:{number}: blank evidence line")
        try:
            data = json.loads(line)
        except ValueError as error:
            raise EvidenceFormatError(
                f"{path}:{number}: not valid JSON: {error}") from error
        if not isinstance(data, dict) or not isinstance(
                data.get("event"), str):
            raise EvidenceFormatError(
                f'{path}:{number}: event must be an object with an "event" '
                "name")
        event = Event(str(path), number, data)
        _validate_event(event)
        events.append(event)
    if not events:
        raise EvidenceFormatError(f"{path}: evidence file records no events")
    return events


def _mac(value: object) -> str:
    return str(value).strip().lower()


def _check_sole_authority(
    events: list[Event], topology: Topology, limited: bool,
) -> Check:
    result = Check(CHECK_SOLE_AUTHORITY, PASS)
    served = 0
    for event in events:
        if event.kind != "dhcp":
            continue
        kind = str(event.data["kind"])
        if kind not in DHCP_SERVER_KINDS:
            continue
        peer = str(event.data["peer"])
        source = _mac(event.data["source_mac"])
        if peer != topology.gateway or source != topology.gateway_mac:
            blocked = " (blocked by switch)" if event.data.get(
                "blocked") else ""
            result.verdict = FAIL
            result.details.append(
                f"{event.where()}: rogue DHCP {kind} from peer {peer!r} "
                f"source {source}{blocked}")
        else:
            served += 1
    if result.verdict == FAIL:
        return result
    if limited:
        result.verdict = NOT_PROVABLE
        result.missing.append(
            "complete event stream (evidence-limit reports omitted events)")
        return result
    if not served:
        result.verdict = NOT_PROVABLE
        result.missing.append(
            "at least one gateway DHCP OFFER/ACK (no DHCP service was "
            "exercised in this evidence)")
        return result
    result.details.append(
        f"{served} DHCP server frame(s), all from gateway "
        f"{topology.gateway_mac}")
    return result


def _check_controller_silence(
    events: list[Event], topology: Topology, limited: bool,
) -> Check:
    result = Check(CHECK_CONTROLLER_SILENCE, PASS)
    connected = False
    for event in events:
        if event.kind == "port-connected" and (
                str(event.data["port"]) == topology.controller):
            connected = True
        if event.kind != "dhcp":
            continue
        peer = str(event.data["peer"])
        source = _mac(event.data["source_mac"])
        if peer == topology.controller or source == topology.controller_mac:
            result.verdict = FAIL
            result.details.append(
                f"{event.where()}: controller emitted DHCP "
                f"{event.data['kind']} (peer {peer!r}, source {source})")
    if result.verdict == FAIL:
        return result
    if limited:
        result.verdict = NOT_PROVABLE
        result.missing.append(
            "complete event stream (evidence-limit reports omitted events)")
        return result
    if not connected:
        result.verdict = NOT_PROVABLE
        result.missing.append(
            f"a port-connected event for {topology.controller!r} (the "
            "controller never joined this fabric, so its silence proves "
            "nothing)")
        return result
    result.details.append(
        "controller connected and emitted no DHCP frames of any kind")
    return result


def _port(value: object) -> int | None:
    return value if type(value) is int else None


def _tftp_client_sessions(
    flows: list[Event], topology: Topology,
) -> frozenset[tuple[str, int]]:
    """Peer client sockets that opened an approved 69/udp TFTP read request.

    TFTP switches to an ephemeral transfer identifier after the initial read
    request, so the data/ack phase runs ephemeral-to-ephemeral with no
    well-known port.  Recording the ``(peer, client_port)`` that reached the
    controller's ``69/udp`` lets the flow check recognise that transfer's
    later frames as the return of an already-approved boot request rather than
    an unexplained high-port service.
    """
    sessions: set[tuple[str, int]] = set()
    for event in flows:
        if int(event.data["ethertype"]) != ETHERTYPE_IPV4:
            continue
        if event.data.get("ip_protocol") != IP_PROTO_UDP:
            continue
        if str(event.data["delivered_to"]) != topology.controller:
            continue
        client_port = _port(event.data.get("src_port"))
        if event.data.get("dst_port") == 69 and client_port is not None:
            sessions.add((str(event.data["peer"]), client_port))
    return frozenset(sessions)


def _flow_violation(
    event: Event, topology: Topology,
    tftp_sessions: frozenset[tuple[str, int]],
) -> str | None:
    peer = str(event.data["peer"])
    delivered = str(event.data["delivered_to"])
    if topology.controller not in (peer, delivered):
        return None
    ethertype = int(event.data["ethertype"])
    protocol = event.data.get("ip_protocol")
    src_port = event.data.get("src_port")
    dst_port = event.data.get("dst_port")
    label = (
        f"{event.where()}: {peer} -> {delivered} ethertype "
        f"{ethertype:#06x} proto {protocol} ports {src_port}->{dst_port}")
    # Identity announcements: only host-side peers (gateway, identity
    # dependencies) may emit them; the controller guest never may.
    if ethertype == IDENTITY_ETHERTYPE:
        if peer == topology.controller:
            return f"controller emitted an identity announcement: {label}"
        return None
    # Ambient L2 control frames carry no service and cannot leave the fabric.
    if ethertype in AMBIENT_ETHERTYPES:
        return None
    if ethertype != ETHERTYPE_IPV4:
        return f"unexpected non-IPv4 frame touched the controller: {label}"
    # ICMP/IGMP: network control, no service port to judge.
    if protocol in AMBIENT_IP_PROTOCOLS:
        return None
    # The port the controller itself occupies in this unidirectional flow.
    controller_port = dst_port if delivered == topology.controller else src_port
    if controller_port in FORBIDDEN_DHCP_PORTS:
        return f"controller served DHCP/ProxyDHCP: {label}"
    # Link-local discovery multicast (LLMNR/mDNS/SSDP) the workstation emits.
    if protocol == IP_PROTO_UDP and (
            src_port in DISCOVERY_UDP_PORTS or dst_port in DISCOVERY_UDP_PORTS):
        return None
    # The controller acquiring its own lease from the gateway (DHCP client);
    # the gateway remains the sole DHCP authority (a separate check).
    other = {peer, delivered} - {topology.controller}
    if (protocol == IP_PROTO_UDP and other == {topology.gateway}
            and {src_port, dst_port} <= DHCP_CLIENT_PORTS):
        return None
    if protocol == IP_PROTO_TCP:
        approved = APPROVED_CONTROLLER_TCP
    elif protocol == IP_PROTO_UDP:
        approved = APPROVED_CONTROLLER_UDP
    else:
        return f"non-TCP/UDP IPv4 flow touched the controller: {label}"
    if delivered == topology.controller:
        # A request to an approved controller service.
        if dst_port in approved:
            return None
        # The gateway answering the controller's own DNS/NTP client query.
        if (peer == topology.gateway and protocol == IP_PROTO_UDP
                and src_port in GATEWAY_CLIENT_UDP):
            return None
        # The data/ack phase of an approved TFTP read request.
        if (peer, _port(src_port)) in tftp_sessions:
            return None
        return f"unapproved service flow to the controller: {label}"
    # Controller egress: an approved service reply, a client query to the
    # gateway's resolver/clock, or approved TFTP data to the client port.
    if src_port in approved:
        return None
    if (protocol == IP_PROTO_UDP and delivered == topology.gateway
            and dst_port in GATEWAY_CLIENT_UDP):
        return None
    if (delivered, _port(dst_port)) in tftp_sessions:
        return None
    return f"unapproved controller egress: {label}"


def _check_approved_flows(
    events: list[Event], topology: Topology, limited: bool,
) -> Check:
    result = Check(CHECK_APPROVED_FLOWS, PASS)
    flows = [event for event in events if event.kind == "flow"]
    if not flows:
        result.verdict = NOT_PROVABLE
        result.missing.append(MISSING_FLOW_FIELDS)
        return result
    tftp_sessions = _tftp_client_sessions(flows, topology)
    touched = 0
    for event in flows:
        violation = _flow_violation(event, topology, tftp_sessions)
        if violation is not None:
            result.verdict = FAIL
            result.details.append(violation)
        elif topology.controller in (
                str(event.data["peer"]), str(event.data["delivered_to"])):
            touched += 1
    if result.verdict == FAIL:
        return result
    if limited:
        result.verdict = NOT_PROVABLE
        result.missing.append(
            "complete event stream (evidence-limit reports omitted events)")
        return result
    result.details.append(
        f"{len(flows)} recorded flow(s); {touched} touched the controller, "
        "all within the approved AD identity and PXE boot service set "
        "(DNS/Kerberos/LDAP/SMB/NetBIOS/RPC/TFTP/HTTP/NTP)")
    return result


def _check_fabric_closure(
    events: list[Event], topology: Topology, limited: bool,
) -> Check:
    result = Check(CHECK_FABRIC_CLOSURE, PASS)
    expected = {name: mac for name, mac in topology.endpoints}
    saw_ready = False
    for event in events:
        kind = event.kind
        if kind == "switch-ready":
            saw_ready = True
            enumerated = {
                str(entry["port"]): _mac(entry["mac"])
                for entry in event.data["ports"]
            }
            if enumerated != expected:
                result.verdict = FAIL
                result.details.append(
                    f"{event.where()}: switch enumerated "
                    f"{sorted(enumerated.items())} instead of the approved "
                    f"fabric {sorted(expected.items())}")
        elif kind in ("port-connected", "port-disconnected",
                      "port-connection-refused"):
            name = str(event.data["port"])
            mac = _mac(event.data["mac"])
            if expected.get(name) != mac:
                result.verdict = FAIL
                result.details.append(
                    f"{event.where()}: {kind} for endpoint outside the "
                    f"fabric: {name!r} {mac}")
        elif kind == "source-mac-blocked":
            result.verdict = FAIL
            result.details.append(
                f"{event.where()}: frame with non-fabric source MAC "
                f"{_mac(event.data['observed'])} on port "
                f"{event.data['port']!r} (blocked at ingress)")
        elif kind in ("dhcp", "flow"):
            names = [str(event.data["peer"])]
            if "delivered_to" in event.data:
                names.append(str(event.data["delivered_to"]))
            for name in names:
                if name not in topology.names:
                    result.verdict = FAIL
                    result.details.append(
                        f"{event.where()}: {kind} event names endpoint "
                        f"{name!r} outside the fabric")
    if result.verdict == FAIL:
        return result
    if not saw_ready:
        result.verdict = NOT_PROVABLE
        result.missing.append(
            "a switch-ready event enumerating the fabric ports")
        return result
    if limited:
        result.verdict = NOT_PROVABLE
        result.missing.append(
            "complete event stream (evidence-limit reports omitted events)")
        return result
    result.details.append(
        "every recorded endpoint, delivery, and enumeration stayed inside "
        f"the approved fabric {sorted(expected)}")
    return result


def audit_events(events: list[Event], topology: Topology) -> dict:
    limited = any(event.kind == "evidence-limit" for event in events)
    unrecognized = sorted({
        event.kind for event in events if event.kind not in KNOWN_EVENTS})
    checks = [
        _check_sole_authority(events, topology, limited),
        _check_controller_silence(events, topology, limited),
        _check_approved_flows(events, topology, limited),
        _check_fabric_closure(events, topology, limited),
    ]
    verdicts = {check.verdict for check in checks}
    overall = (
        FAIL if FAIL in verdicts
        else NOT_PROVABLE if NOT_PROVABLE in verdicts
        else PASS)
    sources: dict[str, int] = {}
    for event in events:
        sources[event.source] = sources.get(event.source, 0) + 1
    return {
        "gate": GATE,
        "sources": [
            {"path": path, "events": count}
            for path, count in sorted(sources.items())
        ],
        "topology": topology.as_json(),
        "evidence_limited": limited,
        "unrecognized_events": unrecognized,
        "checks": [check.as_json() for check in checks],
        "verdict": overall,
    }


def audit_paths(paths: list[Path], topology: Topology) -> dict:
    events: list[Event] = []
    for path in paths:
        events.extend(load_events(path))
    return audit_events(events, topology)


def render(result: dict, stream) -> None:
    for check in result["checks"]:
        summary = "; ".join(check["details"] + [
            f"missing: {item}" for item in check["missing"]])
        print(f"{check['verdict']:<12} {check['check']}  {summary}",
              file=stream)
    print(f"VERDICT {result['verdict']} {result['gate']}", file=stream)


def exit_code(result: dict) -> int:
    if result["verdict"] == PASS:
        return 0
    if result["verdict"] == FAIL:
        return 1
    return 3


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="pxe_authority_audit",
        description="Audit switch evidence for the gate-4 PXE authority "
        "boundary (read-only)")
    commands = parser.add_subparsers(dest="command", required=True)
    audit = commands.add_parser(
        "audit", help="render a gate-4 verdict from switch.jsonl evidence")
    audit.add_argument("evidence", nargs="+", type=Path,
                       help="one or more switch.jsonl files")
    audit.add_argument(
        "--topology", type=Path,
        help="endpoint topology JSON ({endpoints: {name: mac}, gateway, "
        "controller}); defaults to the live factory fabric")
    audit.add_argument(
        "--json", type=Path, dest="json_path",
        help="also write the result JSON to this path")
    args = parser.parse_args(argv)
    try:
        topology = (
            load_topology(args.topology) if args.topology
            else factory_topology())
        result = audit_paths(args.evidence, topology)
    except (EvidenceFormatError, TopologyError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 2
    render(result, sys.stdout)
    payload = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if args.json_path is not None:
        args.json_path.write_text(payload, encoding="utf-8")
    else:
        sys.stdout.write(payload)
    return exit_code(result)


if __name__ == "__main__":
    raise SystemExit(main())
