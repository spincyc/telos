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
    from .simulated_gateway import HubPolicy
    from .simulation_evidence import append_json_event
except ImportError:
    from simulated_gateway import HubPolicy
    from simulation_evidence import append_json_event


MAX_FRAME = 65_535
QUEUE_DEPTH = 128
MAX_EVIDENCE_EVENTS = 20_000


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
        self.policy = HubPolicy()
        self.evidence = Evidence(evidence_path)
        self.incoming: queue.Queue[tuple[int, bytes] | None] = queue.Queue(
            maxsize=QUEUE_DEPTH)
        self.outgoing = {
            port.number: queue.Queue(maxsize=QUEUE_DEPTH) for port in ports
        }
        self.connections: dict[int, socket.socket] = {}
        self.stop = threading.Event()
        self.error: queue.Queue[BaseException] = queue.Queue()
        self.frames = 0
        self.deliveries = 0
        self.blocked = 0

    def _fail(self, error: BaseException) -> None:
        if self.error.empty():
            self.error.put(error)
        self.stop.set()

    def _accept(self) -> None:
        deadline = time.monotonic() + self.accept_timeout
        for port in self.ports:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("timed out waiting for all switch peers")
            self.listener.settimeout(remaining)
            connection, address = self.listener.accept()
            if address[0] != "127.0.0.1":
                connection.close()
                raise RuntimeError("refusing non-loopback peer")
            connection.settimeout(1.0)
            self.connections[port.number] = connection
            self.evidence.write({
                "event": "port-connected",
                "port": port.name,
                "mac": mac_text(port.mac),
            })
            self._signal(f"ACCEPTED {port.name} {mac_text(port.mac)}\n")
        self._signal("ALL-PEERS\n", close=True)

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

    def _reader(self, port: Port) -> None:
        connection = self.connections[port.number]
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
                    self.incoming.put((port.number, frame), timeout=1.0)
                except queue.Full:
                    raise RuntimeError("switch input queue exhausted")
        except BaseException as error:
            self._fail(error)
        finally:
            try:
                self.incoming.put(None, timeout=1.0)
            except queue.Full:
                self._fail(RuntimeError("switch input queue exhausted"))

    def _writer(self, port: Port) -> None:
        connection = self.connections[port.number]
        output = self.outgoing[port.number]
        try:
            while not self.stop.is_set():
                try:
                    frame = output.get(timeout=1.0)
                except queue.Empty:
                    continue
                if frame is None:
                    return
                connection.sendall(struct.pack("!I", len(frame)) + frame)
        except BaseException as error:
            self._fail(error)

    def _dispatch(self) -> None:
        peers = {port.number for port in self.ports}
        disconnected = 0
        last_frame = time.monotonic()
        while disconnected < len(peers) and not self.stop.is_set():
            timeout = max(0.05, self.idle_timeout - (
                time.monotonic() - last_frame))
            try:
                item = self.incoming.get(timeout=timeout)
            except queue.Empty:
                raise RuntimeError("switch idle timeout")
            if item is None:
                disconnected += 1
                continue
            sender, frame = item
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
                self.evidence.write({"event": "dhcp", **named})
            for target, frames in deliveries.items():
                for delivered in frames:
                    self.deliveries += 1
                    try:
                        self.outgoing[target].put(delivered, timeout=1.0)
                    except queue.Full:
                        raise RuntimeError(
                            f"switch output queue exhausted for port {target}")

    def run(self) -> None:
        threads: list[threading.Thread] = []
        try:
            self._ready()
            self._accept()
            for port in self.ports:
                threads.extend([
                    threading.Thread(
                        target=self._reader, args=(port,), daemon=True),
                    threading.Thread(
                        target=self._writer, args=(port,), daemon=True),
                ])
            for thread in threads:
                thread.start()
            self._dispatch()
            if not self.error.empty():
                raise self.error.get()
        finally:
            self.stop.set()
            if self.ready_fd is not None:
                os.close(self.ready_fd)
                self.ready_fd = None
            for output in self.outgoing.values():
                try:
                    output.put_nowait(None)
                except queue.Full:
                    pass
            for connection in self.connections.values():
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
                "accepted_ports": len(self.connections),
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
    ).run()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
