#!/usr/bin/env python3
"""Command-line interface for deterministic reading-list tooling."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .actions import (
    EntrySelector,
    scan,
    enqueue_entry,
    list_entries,
    load_state,
    mark_finished,
    mark_started,
    update_pages,
    update_words,
)
from .core import (
    DEFAULT_JSON_OUTPUT,
    DEFAULT_YAML_OUTPUT,
    DEFAULT_SOURCE,
    format_entry,
    parse_counted_date,
    ingest_from_source,
    write_payload,
)
from .core import EntryMatchError, EntryNotFoundError, ReadingListError
from .genres import DEFAULT_GENRE_SPEC


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Manage the reading tracker dataset.")
    parser.add_argument(
        "--yaml",
        default=str(DEFAULT_YAML_OUTPUT),
        help=f"path to YAML output (default: {DEFAULT_YAML_OUTPUT})",
    )
    parser.add_argument(
        "--json",
        default=str(DEFAULT_JSON_OUTPUT),
        help=f"path to JSON output (default: {DEFAULT_JSON_OUTPUT})",
    )
    parser.add_argument(
        "--source",
        default=str(DEFAULT_SOURCE),
        help=f"path to Reading.List.ods (default: {DEFAULT_SOURCE})",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    list_command = subparsers.add_parser("list", help="list known entries")
    list_command.add_argument("--status", choices=["all", "pending", "active", "complete"], default="all")
    list_command.add_argument("--query", default="")
    list_command.set_defaults(handler=handle_list)

    ingest = subparsers.add_parser("ingest", help="rebuild from Reading.List.ods and optionally delete it")
    ingest.add_argument("--delete-source", action="store_true", help="remove source after a successful ingest")
    ingest.set_defaults(handler=handle_ingest)

    enqueue = subparsers.add_parser("enqueue", help="add a book to pending reading")
    enqueue.add_argument("--title", required=True)
    enqueue.add_argument("--author", required=True)
    enqueue.add_argument("--notes", default="")
    enqueue.add_argument("--pages", type=parse_count, default=None)
    enqueue.add_argument("--words", type=parse_count, default=None)
    enqueue.set_defaults(handler=handle_enqueue)

    start = subparsers.add_parser("start", help="record a start date for an entry")
    add_selector(start)
    start.add_argument(
        "--date",
        type=parse_tracker_date,
        help="start date in YYYY-MM-DD or similar format",
        required=True,
    )
    start.set_defaults(handler=handle_start)

    finish = subparsers.add_parser("finish", help="record a finish date for an entry")
    add_selector(finish)
    finish.add_argument(
        "--date",
        type=parse_tracker_date,
        help="completed date in YYYY-MM-DD or similar format",
        required=True,
    )
    finish.set_defaults(handler=handle_finish)

    update_pages = subparsers.add_parser("update-pages", help="set page count for an entry")
    add_selector(update_pages)
    update_pages.add_argument("--pages", type=parse_count, required=True)
    update_pages.set_defaults(handler=handle_update_pages)

    update_words = subparsers.add_parser("update-words", help="set word count for an entry")
    add_selector(update_words)
    update_words.add_argument("--words", type=parse_count, required=True)
    update_words.set_defaults(handler=handle_update_words)

    scan = subparsers.add_parser("scan", help="classify all entries from genre spec")
    scan.add_argument(
        "--genres",
        default=str(DEFAULT_GENRE_SPEC),
        help=f"path to genre spec YAML (default: {DEFAULT_GENRE_SPEC})",
    )
    scan.set_defaults(handler=handle_scan)

    return parser


def add_selector(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--id", default="")
    parser.add_argument("--title", default="")
    parser.add_argument("--author", default="")


def parse_count(value: str) -> int:
    try:
        return int(str(value).replace(",", "").strip())
    except ValueError as error:
        raise argparse.ArgumentTypeError(str(error))


def parse_tracker_date(value: str) -> str:
    text = str(value).strip()
    if not parse_counted_date(text):
        raise argparse.ArgumentTypeError(f"invalid date format: {text}")
    return text


def selector_from_args(args: argparse.Namespace) -> EntrySelector:
    return EntrySelector(
        entry_id=args.id or None,
        title=args.title or None,
        author=args.author or None,
    )


def handle_list(args: argparse.Namespace) -> int:
    payload = load_state(Path(args.json))
    entries = payload.get("entries", [])
    selected = list_entries(
        payload,
        target_status=args.status,
        query=args.query,
    )

    if not selected:
        print("reading-list: no matching entries.")
        return 0

    for row in selected:
        print(format_entry(row))
    print(
        f"reading-list: {len(selected)} of {len(entries)} entries shown. "
        f"Complete={payload['summary']['status']['complete']} "
        f"Active={payload['summary']['status']['active']} "
        f"Pending={payload['summary']['status']['pending']}"
    )
    return 0


def handle_ingest(args: argparse.Namespace) -> int:
    source = Path(args.source)
    payload = ingest_from_source(source)
    write_payload(
        payload,
        yaml_path=Path(args.yaml),
        json_path=Path(args.json),
        source=payload["generated"]["source"],
        source_sha256=payload["generated"].get("source_sha256"),
        source_size_bytes=payload["generated"].get("source_size_bytes"),
        generated_at=payload["generated"]["at"],
    )
    if args.delete_source:
        source.unlink()
    print(f"reading-list: wrote {args.yaml} and {args.json}")
    if args.delete_source:
        print(f"reading-list: removed {source}")
    return 0


def handle_enqueue(args: argparse.Namespace) -> int:
    payload = load_state(Path(args.json))
    result, entry = enqueue_entry(
        payload,
        title=args.title,
        author=args.author,
        notes=args.notes,
        pages=args.pages,
        words=args.words,
        yaml_path=Path(args.yaml),
        json_path=Path(args.json),
    )
    print(f"reading-list: queued {entry.get('id')} | {entry.get('title')} by {entry.get('author')}")
    print(
        "reading-list: summary -> "
        f"total={result['summary']['total']} "
        f"pending={result['summary']['status']['pending']} "
        f"active={result['summary']['status']['active']} "
        f"complete={result['summary']['status']['complete']}"
    )
    return 0


def handle_start(args: argparse.Namespace) -> int:
    payload = load_state(Path(args.json))
    date_value = args.date.strip()
    result, entry = mark_started(
        payload,
        selector_from_args(args),
        date_value=date_value,
        yaml_path=Path(args.yaml),
        json_path=Path(args.json),
    )
    print(f"reading-list: started {entry['id']} | {entry['title']} on {date_value}")
    print(
        f"reading-list: {result['summary']['status']['pending']} pending, "
        f"{result['summary']['status']['active']} active, "
        f"{result['summary']['status']['complete']} complete"
    )
    return 0


def handle_finish(args: argparse.Namespace) -> int:
    payload = load_state(Path(args.json))
    date_value = args.date.strip()
    result, entry = mark_finished(
        payload,
        selector_from_args(args),
        date_value=date_value,
        yaml_path=Path(args.yaml),
        json_path=Path(args.json),
    )
    print(f"reading-list: finished {entry['id']} | {entry['title']} on {date_value}")
    print(
        f"reading-list: {result['summary']['status']['pending']} pending, "
        f"{result['summary']['status']['active']} active, "
        f"{result['summary']['status']['complete']} complete"
    )
    return 0


def handle_update_pages(args: argparse.Namespace) -> int:
    payload = load_state(Path(args.json))
    result, entry = update_pages(
        payload,
        selector_from_args(args),
        pages=args.pages,
        yaml_path=Path(args.yaml),
        json_path=Path(args.json),
    )
    print(f"reading-list: updated pages for {entry['id']} | {entry['title']} -> {entry['pages']}")
    print(f"reading-list: page rate now {entry.get('pages_per_day')}")
    print(
        f"reading-list: active={result['summary']['status']['active']} "
        f"complete={result['summary']['status']['complete']}"
    )
    return 0


def handle_update_words(args: argparse.Namespace) -> int:
    payload = load_state(Path(args.json))
    result, entry = update_words(
        payload,
        selector_from_args(args),
        words=args.words,
        yaml_path=Path(args.yaml),
        json_path=Path(args.json),
    )
    print(f"reading-list: updated words for {entry['id']} | {entry['title']} -> {entry['words']}")
    print(f"reading-list: words rate now {entry.get('words_per_day')}")
    print(
        f"reading-list: pending={result['summary']['status']['pending']} "
        f"active={result['summary']['status']['active']}"
    )
    return 0


def handle_scan(args: argparse.Namespace) -> int:
    payload = load_state(Path(args.json))
    result, report = scan(
        payload,
        genre_spec_path=Path(args.genres),
        yaml_path=Path(args.yaml),
        json_path=Path(args.json),
    )
    print(
        f"reading-list: scanned {report['scanned']} entries; "
        f"classified={report['classified']} updated={report['updated']}"
    )
    print(
        "reading-list: category breakdown -> "
        + ", ".join(
            f"{category}={count}" for category, count in sorted(report["category_breakdown"].items(), key=lambda item: item[0])
        )
    )
    print(
        f"reading-list: complete={result['summary']['status']['complete']} "
        f"active={result['summary']['status']['active']} "
        f"pending={result['summary']['status']['pending']}"
    )
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    arguments = parser.parse_args(argv)
    try:
        return arguments.handler(arguments)
    except (EntryNotFoundError, EntryMatchError, ReadingListError) as error:
        print(f"reading-list: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
