#!/usr/bin/env python3
"""Concurrent, loopback-only Ethernet switch for the local factory.

The process accepts an already-bound listener.  It never creates an outbound
socket.  QEMU socket-netdev frames are switched between MAC-pinned ports while
the embedded simulated gateway supplies DHCP, DNS, NTP, ARP, and health probes.
"""

from __future__ import annotations

import argparse
import os
import queue
import re
import socket
import struct
import threading
import time
from dataclasses import dataclass
from pathlib import Path

try:
    from .simulated_gateway import Gateway, HubPolicy
    from .simulation_evidence import append_json_event
except ImportError:
    from simulated_gateway import Gateway, HubPolicy
    from simulation_evidence import append_json_event


MAX_FRAME = 65_535
QUEUE_DEPTH = 128
MAX_EVIDENCE_EVENTS = 20_000


class PeerAbandonedBeforeAuthentication(RuntimeError):
    """A candidate socket closed without presenting an Ethernet identity."""


def receive_exact(connection: socket.socket, size: int) -> bytes | None:
    """Read one bounded field while tolerating ordinary socket timeouts."""
    chunks = bytearray()
    while len(chunks) < size:
        try:
            chunk = connection.recv(size - len(chunks))
        except TimeoutError:
            continue
        if not chunk:
            return None
        chunks.extend(chunk)
    return bytes(chunks)


def mac_bytes(value: str) -> bytes:
    compact = value.replace(":", "").lower()
    if len(compact) != 12:
        raise ValueError(f"invalid MAC address: {value}")
    result = bytes.fromhex(compact)
    if result == b"\0" * 6 or result[0] & 1:
        raise ValueError(f"MAC must be unicast: {value}")
    return result


def mac_text(value: bytes) -> str:
    return ":".join(f"{part:02x}" for part in value)


def flow_summary(
    frame: bytes,
) -> tuple[int, int | None, int | None, int | None]:
    """Summarize one frame as (ethertype, ip_protocol, src_port, dst_port).

    Only fixed header fields are read; payloads are never recorded.
    """
    ethertype = struct.unpack("!H", frame[12:14])[0]
    if ethertype != 0x0800 or len(frame) < 34:
        return ethertype, None, None, None
    ihl = (frame[14] & 0x0F) * 4
    protocol = frame[23]
    if protocol not in (6, 17) or len(frame) < 14 + ihl + 4:
        return ethertype, protocol, None, None
    src_port, dst_port = struct.unpack("!HH", frame[14 + ihl:14 + ihl + 4])
    return ethertype, protocol, src_port, dst_port


@dataclass(frozen=True)
class Port:
    number: int
    name: str
    mac: bytes


class Evidence:
    """Thread-safe, bounded JSONL evidence writer."""

    def __init__(self, path: Path | None, limit: int = MAX_EVIDENCE_EVENTS):
        self.path = path
        self.limit = limit
        self.count = 0
        self.omitted = 0
        self.lock = threading.Lock()

    def write(self, event: dict[str, object]) -> None:
        with self.lock:
            if self.count >= self.limit:
                self.omitted += 1
                return
            self.count += 1
            if self.path is None:
                return
            self._append(event)

    def close(self) -> None:
        if self.omitted:
            self.write_unbounded({
                "event": "evidence-limit",
                "omitted": self.omitted,
            })

    def write_unbounded(self, event: dict[str, object]) -> None:
        if self.path is not None:
            self._append(event)

    def _append(self, event: dict[str, object]) -> None:
        assert self.path is not None
        append_json_event(self.path, event)


class ConcurrentSwitch:
    """A bounded concurrent switch around :class:`HubPolicy`."""

    def __init__(
        self,
        listener: socket.socket,
        ports: list[Port],
        *,
        evidence_path: Path | None = None,
        ready_fd: int | None = None,
        accept_timeout: float = 30.0,
        idle_timeout: float = 120.0,
        identity_mode: bool = False,
    ) -> None:
        if not ports or len({port.number for port in ports}) != len(ports):
            raise ValueError("ports must have unique numbers")
        if len({port.mac for port in ports}) != len(ports):
            raise ValueError("ports must have unique MAC addresses")
        if accept_timeout <= 0 or idle_timeout <= 0:
            raise ValueError("switch timeouts must be positive")
        address = listener.getsockname()
        if not isinstance(address, tuple) or address[0] != "127.0.0.1":
            raise RuntimeError("listener must be bound to 127.0.0.1")
        self.listener = listener
        self.ports = ports
        self.port_names = {port.number: port.name for port in ports}
        self.accept_timeout = accept_timeout
        self.idle_timeout = idle_timeout
        self.ready_fd = ready_fd
        gateway_ports = [port.number for port in ports if port.name == "gateway"]
        if len(gateway_ports) > 1:
            raise ValueError("at most one pinned gateway port is allowed")
        self.policy = HubPolicy(
            gateway=Gateway(identity_mode=identity_mode),
            gateway_peer=gateway_ports[0] if gateway_ports else None)
        self.evidence = Evidence(evidence_path)
        self.incoming: queue.Queue[
            tuple[int, int, dict[int, int | None], bytes | None] | None
        ] = queue.Queue(
            maxsize=QUEUE_DEPTH)
        self.connections: dict[
            int, tuple[socket.socket, queue.Queue[bytes | None], int]
        ] = {}
        self.pending_outputs: dict[int, queue.Queue[bytes | None]] = {
            port.number: queue.Queue(maxsize=QUEUE_DEPTH) for port in ports
        }
        self.generations = {port.number: 0 for port in ports}
        self.connection_lock = threading.Lock()
        self.accepted_ports: set[int] = set()
        self.stop = threading.Event()
        self.error: queue.Queue[BaseException] = queue.Queue()
        self.frames = 0
        self.deliveries = 0
        self.blocked = 0
        self.names_by_mac = {port.mac: port.name for port in ports}
        self.flows: dict[tuple[object, ...], int] = {}

    def _fail(self, error: BaseException) -> None:
        if self.error.empty():
            self.error.put(error)
        self.stop.set()

    def _accept(self, threads: list[threading.Thread]) -> None:
        deadline = time.monotonic() + self.accept_timeout
        ports_by_mac = {port.mac: port for port in self.ports}
        signalled_all = False
        while not self.stop.is_set():
            if len(self.accepted_ports) < len(self.ports):
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError("timed out waiting for all switch peers")
                self.listener.settimeout(remaining)
            else:
                self.listener.settimeout(1.0)
            try:
                connection, address = self.listener.accept()
            except TimeoutError:
                if len(self.accepted_ports) < len(self.ports):
                    raise TimeoutError("timed out waiting for all switch peers")
                continue
            if address[0] != "127.0.0.1":
                connection.close()
                raise RuntimeError("refusing non-loopback peer")
            authentication_deadline = min(
                deadline if len(self.accepted_ports) < len(self.ports)
                else time.monotonic() + self.accept_timeout,
                time.monotonic() + self.accept_timeout,
            )
            connection.settimeout(self.accept_timeout)
            try:
                frame = self._authentication_frame(
                    connection, authentication_deadline)
            except PeerAbandonedBeforeAuthentication:
                connection.close()
                self.evidence.write({
                    "event": "peer-abandoned-before-authentication",
                })
                continue
            except BaseException:
                connection.close()
                raise
            observed = frame[6:12]
            port = ports_by_mac.get(observed)
            if port is None:
                connection.close()
                raise RuntimeError(
                    "refusing switch peer with unconfigured source MAC "
                    f"{mac_text(observed)}")
            with self.connection_lock:
                if port.number in self.connections:
                    connection.close()
                    self.evidence.write({
                        "event": "port-connection-refused",
                        "port": port.name,
                        "mac": mac_text(observed),
                        "reason": "active-generation",
                        "generation": self.generations[port.number],
                    })
                    raise RuntimeError(
                        f"refusing duplicate switch peer for {port.name} "
                        f"{mac_text(observed)}")
                generation = self.generations[port.number] + 1
                self.generations[port.number] = generation
                output = self.pending_outputs[port.number]
                connection.settimeout(1.0)
                self.connections[port.number] = (
                    connection, output, generation)
                self.accepted_ports.add(port.number)
                target_generations = self._target_generations()
            self.incoming.put_nowait(
                (port.number, generation, target_generations, frame))
            self.evidence.write({
                "event": "port-connected",
                "port": port.name,
                "mac": mac_text(port.mac),
                "generation": generation,
            })
            self._signal(f"ACCEPTED {port.name} {mac_text(port.mac)}\n")
            peer_threads = [
                threading.Thread(
                    target=self._reader,
                    args=(port, connection, generation), daemon=True),
                threading.Thread(
                    target=self._writer,
                    args=(port, connection, output, generation), daemon=True),
            ]
            threads.extend(peer_threads)
            for thread in peer_threads:
                thread.start()
            if not signalled_all and len(self.accepted_ports) == len(self.ports):
                self._signal("ALL-PEERS\n", close=True)
                signalled_all = True

    @staticmethod
    def _authentication_frame(
        connection: socket.socket, deadline: float,
    ) -> bytes:
        """Read and validate the first frame used to bind a socket to a port."""
        def receive_before_deadline(size: int) -> bytes | None:
            chunks = bytearray()
            while len(chunks) < size:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError("timed out authenticating switch peer")
                connection.settimeout(remaining)
                try:
                    chunk = connection.recv(size - len(chunks))
                except TimeoutError as error:
                    raise TimeoutError(
                        "timed out authenticating switch peer") from error
                if not chunk:
                    return None
                chunks.extend(chunk)
            return bytes(chunks)

        header = receive_before_deadline(4)
        if header is None:
            raise PeerAbandonedBeforeAuthentication(
                "switch peer closed before authentication")
        size = struct.unpack("!I", header)[0]
        if not 14 <= size <= MAX_FRAME:
            raise RuntimeError(
                f"invalid authentication Ethernet frame size {size}")
        frame = receive_before_deadline(size)
        if frame is None:
            raise RuntimeError("truncated authentication Ethernet frame")
        return frame

    def _signal(self, message: str, *, close: bool = False) -> None:
        if self.ready_fd is None:
            return
        try:
            os.write(self.ready_fd, message.encode("ascii"))
        except BrokenPipeError:
            os.close(self.ready_fd)
            self.ready_fd = None
            return
        if close:
            os.close(self.ready_fd)
            self.ready_fd = None

    def _ready(self) -> None:
        """Signal that the inherited listener has passed boundary checks."""
        self.evidence.write({
            "event": "switch-ready",
            "ports": [
                {"port": port.name, "mac": mac_text(port.mac)}
                for port in self.ports
            ],
        })
        self._signal("READY\n")

    def _reader(
        self, port: Port, connection: socket.socket, generation: int,
    ) -> None:
        try:
            while not self.stop.is_set():
                try:
                    header = receive_exact(connection, 4)
                except TimeoutError:
                    continue
                if header is None:
                    break
                size = struct.unpack("!I", header)[0]
                if not 14 <= size <= MAX_FRAME:
                    raise RuntimeError(
                        f"{port.name}: invalid Ethernet frame size {size}")
                try:
                    frame = receive_exact(connection, size)
                except TimeoutError:
                    raise RuntimeError(f"{port.name}: truncated Ethernet frame")
                if frame is None:
                    raise RuntimeError(f"{port.name}: truncated Ethernet frame")
                if frame[6:12] != port.mac:
                    self.evidence.write({
                        "event": "source-mac-blocked",
                        "port": port.name,
                        "expected": mac_text(port.mac),
                        "observed": mac_text(frame[6:12]),
                    })
                    continue
                try:
                    with self.connection_lock:
                        target_generations = self._target_generations()
                    self.incoming.put((
                        port.number, generation, target_generations, frame
                    ), timeout=1.0)
                except queue.Full:
                    raise RuntimeError("switch input queue exhausted")
        except (ConnectionResetError, BrokenPipeError):
            pass
        except BaseException as error:
            self._fail(error)
        finally:
            with self.connection_lock:
                active = self.connections.get(port.number)
                if active is not None and active[2] == generation:
                    del self.connections[port.number]
                    self.pending_outputs[port.number] = queue.Queue(
                        maxsize=QUEUE_DEPTH)
                    try:
                        active[1].put_nowait(None)
                    except queue.Full:
                        pass
            try:
                connection.close()
            finally:
                self.evidence.write({
                    "event": "port-disconnected",
                    "port": port.name,
                    "mac": mac_text(port.mac),
                    "generation": generation,
                })
                try:
                    self.incoming.put(
                        (port.number, generation, {}, None), timeout=1.0)
                except queue.Full:
                    self._fail(RuntimeError("switch input queue exhausted"))

    def _writer(
        self, port: Port, connection: socket.socket,
        output: queue.Queue[bytes | None], generation: int,
    ) -> None:
        try:
            while not self.stop.is_set():
                try:
                    frame = output.get(timeout=1.0)
                except queue.Empty:
                    continue
                if frame is None:
                    return
                connection.sendall(struct.pack("!I", len(frame)) + frame)
        except OSError:
            # The reader owns authenticated-session teardown and evidence.
            return
        except BaseException as error:
            self._fail(error)

    def _target_generations(self) -> dict[int, int | None]:
        """Snapshot exact target sessions while connection_lock is held."""
        return {
            port.number: (
                self.connections[port.number][2]
                if port.number in self.connections
                else (None if port.number in self.accepted_ports else 0)
            )
            for port in self.ports
        }

    def _dispatch(self) -> None:
        last_frame = time.monotonic()
        while not self.stop.is_set():
            timeout = max(0.05, self.idle_timeout - (
                time.monotonic() - last_frame))
            try:
                item = self.incoming.get(timeout=timeout)
            except queue.Empty:
                raise RuntimeError("switch idle timeout")
            if item is None:
                continue
            sender, generation, target_generations, frame = item
            if frame is None:
                with self.connection_lock:
                    if (
                        len(self.accepted_ports) == len(self.ports)
                        and not self.connections
                    ):
                        self.stop.set()
                        return
                continue
            with self.connection_lock:
                active = self.connections.get(sender)
                if (
                    active is None
                    or active[2] != generation
                ):
                    continue
                peers = {port.number for port in self.ports}
                session_snapshot = dict(self.connections)
                output_snapshot = {
                    target: (
                        session_snapshot[target][1]
                        if (
                            target_generations.get(target) == 0
                            and target in session_snapshot
                            and session_snapshot[target][2] == 1
                        ) or (
                            target in session_snapshot
                            and target_generations.get(target)
                            == session_snapshot[target][2]
                        )
                        else (
                            self.pending_outputs[target]
                            if target_generations.get(target) == 0
                            and target not in self.accepted_ports
                            else None
                        )
                    )
                    for target in peers
                }
            self.frames += 1
            last_frame = time.monotonic()
            deliveries, events = self.policy.route(sender, frame, peers)
            for event in events:
                named = dict(event)
                if isinstance(named.get("peer"), int):
                    named["peer"] = self.port_names[int(named["peer"])]
                if isinstance(named.get("delivered_to"), int):
                    named["delivered_to"] = self.port_names[
                        int(named["delivered_to"])]
                if named.get("blocked"):
                    self.blocked += 1
                peer_number = next((
                    number for number, name in self.port_names.items()
                    if name == named.get("peer")
                ), None)
                delivered_number = next((
                    number for number, name in self.port_names.items()
                    if name == named.get("delivered_to")
                ), None)
                peer_session = (
                    session_snapshot.get(peer_number)
                    if peer_number is not None else None)
                delivered_session = (
                    session_snapshot.get(delivered_number)
                    if delivered_number is not None else None)
                peer_ingress = target_generations.get(peer_number)
                if type(peer_ingress) is int and peer_ingress > 0:
                    named["peer_generation"] = peer_ingress
                elif (
                    peer_ingress == 0 and peer_session is not None
                    and peer_session[2] == 1
                ):
                    named["peer_generation"] = 1
                delivered_ingress = target_generations.get(delivered_number)
                if (
                    delivered_number is not None
                    and output_snapshot[delivered_number] is not None
                    and type(delivered_ingress) is int
                    and delivered_ingress > 0
                ):
                    named["delivered_to_generation"] = delivered_ingress
                elif (
                    delivered_number is not None
                    and output_snapshot[delivered_number] is not None
                    and delivered_ingress == 0
                    and delivered_session is not None
                    and delivered_session[2] == 1
                ):
                    named["delivered_to_generation"] = 1
                elif delivered_number is not None:
                    named.pop("delivered_to", None)
                    named["delivery_dropped"] = True
                self.evidence.write({"event": "dhcp", **named})
            for target, frames in deliveries.items():
                for delivered in frames:
                    output = output_snapshot[target]
                    if output is None:
                        continue
                    self.deliveries += 1
                    origin = self.names_by_mac.get(
                        delivered[6:12], self.port_names[sender])
                    key = (origin, self.port_names[target],
                           *flow_summary(delivered))
                    seen = self.flows.get(key, 0)
                    self.flows[key] = seen + 1
                    if not seen:
                        record: dict[str, object] = {
                            "event": "flow",
                            "peer": key[0],
                            "delivered_to": key[1],
                            "ethertype": key[2],
                        }
                        if key[3] is not None:
                            record["ip_protocol"] = key[3]
                        if key[4] is not None:
                            record["src_port"] = key[4]
                            record["dst_port"] = key[5]
                        self.evidence.write(record)
                    try:
                        output.put(delivered, timeout=1.0)
                    except queue.Full:
                        raise RuntimeError(
                            f"switch output queue exhausted for port {target}")

    def run(self) -> None:
        threads: list[threading.Thread] = []
        dispatch_error: list[BaseException] = []

        def dispatch() -> None:
            try:
                self._dispatch()
            except BaseException as error:
                dispatch_error.append(error)
                self._fail(error)

        try:
            self._ready()
            dispatch_thread = threading.Thread(
                target=dispatch, name="switch-dispatch", daemon=True)
            threads.append(dispatch_thread)
            dispatch_thread.start()
            self._accept(threads)
            dispatch_thread.join()
            if dispatch_error:
                raise dispatch_error[0]
            if not self.error.empty():
                raise self.error.get()
        finally:
            self.stop.set()
            try:
                self.incoming.put_nowait(None)
            except queue.Full:
                pass
            if self.ready_fd is not None:
                os.close(self.ready_fd)
                self.ready_fd = None
            with self.connection_lock:
                sessions = list(self.connections.values())
            for connection, output, _generation in sessions:
                try:
                    output.put_nowait(None)
                except queue.Full:
                    pass
                try:
                    connection.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
                connection.close()
            self.listener.close()
            for thread in threads:
                thread.join(timeout=2.0)
            self.evidence.write_unbounded({
                "event": "switch-summary",
                "frames": self.frames,
                "deliveries": self.deliveries,
                "blocked": self.blocked,
                "flows": len(self.flows),
                "accepted_ports": len(self.accepted_ports),
            })
            self.evidence.close()
        if not self.error.empty():
            raise self.error.get()


def parse_port(value: str, number: int) -> Port:
    try:
        name, mac = value.split("=", 1)
    except ValueError as error:
        raise ValueError("port must be NAME=MAC") from error
    if not re.fullmatch(r"[A-Za-z0-9_.-]{1,32}", name):
        raise ValueError(
            "port name must contain 1-32 letters, digits, dots, dashes, "
            "or underscores")
    return Port(number, name, mac_bytes(mac))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--listener-fd", required=True, type=int)
    parser.add_argument("--port", action="append", required=True)
    parser.add_argument("--evidence", type=Path)
    parser.add_argument("--ready-fd", type=int)
    parser.add_argument("--accept-timeout", type=float, default=30.0)
    parser.add_argument("--idle-timeout", type=float, default=120.0)
    parser.add_argument("--identity-mode", action="store_true")
    args = parser.parse_args()
    if not 1 <= len(args.port) <= 8:
        parser.error("between 1 and 8 --port values are required")
    ports = [parse_port(value, number)
             for number, value in enumerate(args.port, 1)]
    listener = socket.socket(fileno=args.listener_fd)
    ConcurrentSwitch(
        listener, ports, evidence_path=args.evidence,
        ready_fd=args.ready_fd,
        accept_timeout=args.accept_timeout,
        idle_timeout=args.idle_timeout,
        identity_mode=args.identity_mode,
    ).run()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
