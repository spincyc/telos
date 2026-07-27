#!/usr/bin/env python3
"""Judge DHCP authority and client continuity from a simulation transcript."""

from __future__ import annotations

import argparse
import ipaddress
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable


SERVER_MESSAGES = frozenset({"OFFER", "ACK", "NAK"})


@dataclass(frozen=True)
class Event:
    sequence: int
    kind: str
    actor: str
    recipient: str | None = None
    server_id: str | None = None
    address: str | None = None


class TranscriptError(ValueError):
    pass


def load(path: Path) -> list[Event]:
    events: list[Event] = []
    for line_number, line in enumerate(path.read_text().splitlines(), 1):
        if not line.strip():
            continue
        try:
            item = json.loads(line)
            events.append(Event(
                sequence=int(item["sequence"]),
                kind=str(item["kind"]).upper(),
                actor=str(item["actor"]),
                recipient=item.get("recipient"),
                server_id=item.get("server_id"),
                address=item.get("address"),
            ))
        except (KeyError, TypeError, ValueError, json.JSONDecodeError) as error:
            raise TranscriptError(f"line {line_number}: invalid event: {error}") from error
    if not events:
        raise TranscriptError("transcript is empty")
    sequences = [event.sequence for event in events]
    if sequences != sorted(sequences) or len(sequences) != len(set(sequences)):
        raise TranscriptError("event sequence numbers are not strictly increasing")
    return events


def assess(events: Iterable[Event], *, gateway: str, controller: str,
           client: str) -> list[str]:
    events = list(events)
    failures: list[str] = []
    server_events = [event for event in events if event.kind in SERVER_MESSAGES]
    authorities = {
        event.server_id for event in server_events if event.server_id is not None
    }
    if authorities != {gateway}:
        failures.append(
            f"DHCP authority set is {sorted(authorities)}; expected only {gateway}")
    for message in ("OFFER", "ACK"):
        matches = [
            event for event in server_events
            if event.kind == message and event.server_id == gateway
        ]
        if len(matches) != 1:
            failures.append(
                f"expected one {message} from {gateway}; observed {len(matches)}")
    cycle = [
        event.kind for event in events
        if event.kind in {"DISCOVER", "OFFER", "REQUEST", "ACK"}
    ]
    if cycle != ["DISCOVER", "OFFER", "REQUEST", "ACK"]:
        failures.append(
            "expected one ordered DISCOVER/OFFER/REQUEST/ACK exchange")
    if any(event.actor == controller and event.kind in SERVER_MESSAGES
           for event in events):
        failures.append(f"{controller} emitted a DHCP server message")

    acks = [
        event for event in events
        if event.kind == "ACK" and event.server_id == gateway
        and event.recipient == client
    ]
    if len(acks) == 1:
        try:
            lease = ipaddress.ip_address(acks[0].address or "")
        except ValueError:
            failures.append("gateway ACK has no valid leased address")
        else:
            poweroffs = [
                event.sequence for event in events
                if event.kind == "POWEROFF" and event.actor == controller
            ]
            if len(poweroffs) != 1:
                failures.append(
                    f"expected one {controller} poweroff; observed {len(poweroffs)}")
            else:
                probes = [
                    event for event in events
                    if event.sequence > poweroffs[0] and event.actor == client
                    and event.kind == "CONNECTIVITY_PASS"
                    and event.address == str(lease)
                ]
                if not probes:
                    failures.append(
                        "client did not retain its lease and pass connectivity "
                        "after controller poweroff")
    else:
        failures.append(
            f"expected one ACK addressed to {client}; observed {len(acks)}")
    return failures


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("transcript", type=Path)
    parser.add_argument("--gateway", required=True)
    parser.add_argument("--controller", required=True)
    parser.add_argument("--client", required=True)
    args = parser.parse_args()
    try:
        failures = assess(load(args.transcript), gateway=args.gateway,
                          controller=args.controller, client=args.client)
    except (OSError, TranscriptError) as error:
        parser.error(str(error))
    if failures:
        for failure in failures:
            print(f"FAIL {failure}")
        return 1
    print("PASS gateway is sole DHCP authority")
    print("PASS controller emitted no DHCP server messages")
    print("PASS client retained connectivity after controller poweroff")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
