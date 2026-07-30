#!/usr/bin/env python3
"""Core deterministic operations for the reading list."""

from __future__ import annotations

import hashlib
import json
import re
from collections import defaultdict
from datetime import date, datetime, timezone
from pathlib import Path
import zipfile
from typing import Any
import xml.etree.ElementTree as ET


ROOT = Path(__file__).resolve().parents[2]
DEFAULT_SOURCE = ROOT / "Reading.List.ods"
DEFAULT_YAML_OUTPUT = ROOT / "site/data/reading-list.yaml"
DEFAULT_JSON_OUTPUT = ROOT / "site/data/reading-list.json"

NS = {
    "office": "urn:oasis:names:tc:opendocument:xmlns:office:1.0",
    "table": "urn:oasis:names:tc:opendocument:xmlns:table:1.0",
    "text": "urn:oasis:names:tc:opendocument:xmlns:text:1.0",
}

FIELD_MAP = {
    "title": "title",
    "author": "author",
    "date started": "started",
    "date completed": "completed",
    "pages": "pages",
    "words": "words",
    "days to read": "days",
    "pages/day": "pages_per_day",
    "words/day": "words_per_day",
    "notes": "notes",
}

CELL_REPEAT_KEY = f"{{{NS['table']}}}number-columns-repeated"
ROW_REPEAT_KEY = f"{{{NS['table']}}}number-rows-repeated"

DATE_FORMATS = (
    "%Y-%m-%d",
    "%Y/%m/%d",
    "%d %B %Y",
    "%d %b %Y",
    "%d %B, %Y",
    "%d %b, %Y",
)

STATUS_ORDER = {"pending": 0, "active": 1, "complete": 2}
GENRE_DEFAULT_CATEGORY = "unclassified"


class ReadingListError(RuntimeError):
    """Raised when a deterministic reading-list action cannot be completed."""


class EntryNotFoundError(ReadingListError):
    """Raised when no entry matches a target selector."""


class EntryMatchError(ReadingListError):
    """Raised when a target selector is incomplete or ambiguous."""


def now_utc_iso() -> str:
    return datetime.now(tz=timezone.utc).isoformat(timespec="seconds")


def normalize_field_name(name: str) -> str:
    return re.sub(r"\s+", " ", name.strip().lower())


def normalize_text(value: Any) -> str:
    return " ".join(str(value).strip().split()) if value is not None else ""


def normalize_genre_label(value: Any) -> str | None:
    text = normalize_text(value)
    return text or None


def normalize_genre_category(value: Any) -> str:
    text = normalize_text(value).replace("_", "-").replace("\u2011", "-").lower()
    if text in {"f", "fict", "fiction"}:
        return "fiction"
    if text in {"nonfiction", "non-fiction", "non fiction", "nf"}:
        return "non-fiction"
    if text in {"unclassified", "unknown", ""}:
        return GENRE_DEFAULT_CATEGORY
    return text


def parse_int(raw: Any) -> int | None:
    if raw is None:
        return None
    compact = str(raw).replace(",", "").strip()
    if not compact:
        return None
    try:
        return int(float(compact))
    except ValueError:
        return None


def parse_float(raw: Any) -> float | None:
    if raw is None:
        return None
    compact = str(raw).replace(",", "").strip()
    if not compact:
        return None
    try:
        return float(compact)
    except ValueError:
        return None


def parse_counted_date(raw: str | None) -> date | None:
    text = normalize_text(raw)
    if not text:
        return None
    for template in DATE_FORMATS:
        try:
            return datetime.strptime(text, template).date()
        except ValueError:
            continue
    return None


def days_between(started: str | None, completed: str | None) -> int | None:
    start_date = parse_counted_date(started)
    complete_date = parse_counted_date(completed)
    if not start_date or not complete_date:
        return None
    delta = complete_date - start_date
    if delta.days < 0:
        return None
    return delta.days + 1


def rate(total: int | None, count: int | None) -> float | None:
    if total is None or count is None or count <= 0:
        return None
    return round(total / count, 2)


def classify_status(started: str | None, completed: str | None, title: str | None) -> str:
    if normalize_text(title) == "":
        return ""
    if normalize_text(completed):
        return "complete"
    if normalize_text(started):
        return "active"
    return "pending"


def compute_id(title: str, author: str, reader: str) -> str:
    key = "\u0000".join((normalize_text(title).lower(), normalize_text(author).lower(), normalize_text(reader).lower()))
    return hashlib.sha1(key.encode("utf-8")).hexdigest()[:16]


def yaml_scalar(value: Any) -> str:
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int | float):
        return str(value)
    if isinstance(value, str):
        return json.dumps(value, ensure_ascii=False)
    return json.dumps(value, ensure_ascii=False)


def dump_yaml(value: Any, indent: int = 0) -> list[str]:
    pad = " " * indent
    lines: list[str] = []
    if isinstance(value, dict):
        for key, child in value.items():
            key_text = str(key)
            if isinstance(child, (dict, list)):
                lines.append(f"{pad}{key_text}:")
                if not child:
                    lines.append(f"{pad}  {{}}")
                else:
                    lines.extend(dump_yaml(child, indent + 2))
            else:
                lines.append(f"{pad}{key_text}: {yaml_scalar(child)}")
        return lines

    if isinstance(value, list):
        if not value:
            lines.append(f"{pad}[]")
            return lines
        for child in value:
            if isinstance(child, (dict, list)):
                lines.append(f"{pad}-")
                lines.extend(dump_yaml(child, indent + 2))
            else:
                lines.append(f"{pad}- {yaml_scalar(child)}")
        return lines

    lines.append(f"{pad}{yaml_scalar(value)}")
    return lines


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    digest.update(path.read_bytes())
    return digest.hexdigest()


def write_yaml(payload: dict[str, Any], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(dump_yaml(payload, 0)) + "\n", encoding="utf-8")


def write_json(payload: dict[str, Any], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(payload, indent=2, ensure_ascii=False, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def read_table_rows(table: ET.Element) -> list[list[str]]:
    rows: list[list[str]] = []
    for raw_row in table.findall("table:table-row", NS):
        repeat = int(raw_row.attrib.get(ROW_REPEAT_KEY, "1"))
        values: list[str] = []
        for cell in raw_row.findall("table:table-cell", NS):
            cell_repeat = int(cell.attrib.get(CELL_REPEAT_KEY, "1"))
            pieces: list[str] = []
            for child in cell:
                if child.tag == f"{{{NS['text']}}}p" and child.text:
                    pieces.append(child.text.strip())
            text = "\n".join(pieces).strip()
            values.extend([text] * cell_repeat)
        while values and values[-1] == "":
            values.pop()
        for _ in range(repeat):
            rows.append(values[:])
    return rows


def canonicalize_entry(raw: dict[str, Any], force_id: bool = False) -> dict[str, Any] | None:
    title = normalize_text(raw.get("title"))
    if not title:
        return None

    author = normalize_text(raw.get("author")) or "Unknown"
    reader = normalize_text(raw.get("reader")) or "Unknown"
    started = normalize_text(raw.get("started")) or None
    completed = normalize_text(raw.get("completed")) or None
    pages = parse_int(raw.get("pages"))
    words = parse_int(raw.get("words"))
    days = parse_int(raw.get("days"))
    genre_category = normalize_genre_category(raw.get("genre_category"))
    genre_coarse = normalize_genre_label(raw.get("genre_coarse"))
    genre_fine = normalize_genre_label(raw.get("genre_fine"))
    if not genre_category and normalize_text(raw.get("genre_type")):
        genre_category = normalize_genre_category(raw.get("genre_type"))
    genre_rule = normalize_genre_label(raw.get("genre_rule"))
    notes = normalize_text(raw.get("notes")) or None
    source_row = parse_int(raw.get("source_row"))
    existing_id = normalize_text(raw.get("id"))
    status = classify_status(started, completed, title)
    if days is None:
        days = days_between(started, completed)
    pages_per_day = parse_float(raw.get("pages_per_day"))
    words_per_day = parse_float(raw.get("words_per_day"))
    if pages is not None or days is not None:
        pages_per_day = rate(pages, days)
    if words is not None or days is not None:
        words_per_day = rate(words, days)
    entry = {
        "title": title,
        "author": author,
        "reader": reader,
        "status": status,
        "started": started,
        "completed": completed,
        "pages": pages,
        "words": words,
        "days": days,
        "pages_per_day": pages_per_day,
        "words_per_day": words_per_day,
        "notes": notes,
        "genre_category": genre_category if genre_category else None,
        "genre_coarse": genre_coarse,
        "genre_fine": genre_fine,
        "genre_rule": genre_rule,
    }
    if source_row is not None:
        entry["source_row"] = source_row
    entry["id"] = existing_id if existing_id and not force_id else compute_id(title, author, reader)
    return entry


def sort_entries(entries: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return sorted(
        entries,
        key=lambda item: (
            normalize_text(item.get("reader", "unknown")).lower(),
            STATUS_ORDER.get(item.get("status", "pending"), 0),
            normalize_text(item.get("title", "")).lower(),
            normalize_text(item.get("author", "")).lower(),
        ),
    )


def _build_readers(entries: list[dict[str, Any]]) -> list[dict[str, Any]]:
    buckets: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in entries:
        buckets[row.get("reader", "Unknown")].append(row)

    readers: list[dict[str, Any]] = []
    for name in sorted(buckets):
        rows = sorted(
            buckets[name],
            key=lambda item: (
                STATUS_ORDER.get(item.get("status", "pending"), 0),
                normalize_text(item.get("title", "")).lower(),
                normalize_text(item.get("author", "")).lower(),
            ),
        )
        readers.append({"name": name, "count": len(rows), "entries": rows})
    return readers


def _build_summary(entries: list[dict[str, Any]]) -> dict[str, int]:
    return {
        "complete": sum(1 for row in entries if row.get("status") == "complete"),
        "active": sum(1 for row in entries if row.get("status") == "active"),
        "pending": sum(1 for row in entries if row.get("status") == "pending"),
    }


def normalize_payload(
    payload: dict[str, Any],
    *,
    source: str | None = None,
    source_sha256: str | None = None,
    source_size_bytes: int | None = None,
    generated_at: str | None = None,
) -> dict[str, Any]:
    source_name = source if source is not None else payload.get("generated", {}).get("source", "manual")
    is_manual = source_name == "manual"
    normalized: list[dict[str, Any]] = []
    for raw_entry in payload.get("entries", []):
        normalized_entry = canonicalize_entry(raw_entry if isinstance(raw_entry, dict) else {})
        if normalized_entry is not None:
            normalized.append(normalized_entry)

    normalized = sort_entries(normalized)
    readers = _build_readers(normalized)
    source_payload = {
        "at": generated_at or now_utc_iso(),
        "source": source_name,
        "source_sha256": None if is_manual else (source_sha256 if source_sha256 is not None else payload.get("generated", {}).get("source_sha256")),
        "source_size_bytes": None if is_manual else (
            source_size_bytes if source_size_bytes is not None else payload.get("generated", {}).get("source_size_bytes")
        ),
    }

    summary = {
        "total": len(normalized),
        "readers": len(readers),
        "status": _build_summary(normalized),
    }

    return {
        "generated": source_payload,
        "summary": summary,
        "readers": readers,
        "entries": normalized,
    }


def write_payload(
    payload: dict[str, Any],
    *,
    yaml_path: Path,
    json_path: Path,
    source: str | None = None,
    source_sha256: str | None = None,
    source_size_bytes: int | None = None,
    generated_at: str | None = None,
) -> dict[str, Any]:
    canonical = normalize_payload(
        payload,
        source=source,
        source_sha256=source_sha256,
        source_size_bytes=source_size_bytes,
        generated_at=generated_at,
    )
    write_yaml(canonical, yaml_path)
    write_json(canonical, json_path)
    return canonical


def load_payload(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {
            "generated": {
                "at": now_utc_iso(),
                "source": "manual",
                "source_sha256": None,
                "source_size_bytes": None,
            },
            "summary": {"total": 0, "readers": 0, "status": {"complete": 0, "active": 0, "pending": 0}},
            "readers": [],
            "entries": [],
        }

    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ReadingListError(f"invalid JSON payload in {path}: {exc}") from exc

    if not isinstance(raw, dict):
        raise ReadingListError(f"expected dict payload in {path}")
    return normalize_payload(raw, source=raw.get("generated", {}).get("source", "manual"), generated_at=now_utc_iso())


def read_ods_payload(source: Path) -> list[dict[str, Any]]:
    with zipfile.ZipFile(source) as archive:
        content = archive.read("content.xml")
    root = ET.fromstring(content)

    rows: list[dict[str, Any]] = []
    for table in root.findall(".//table:table", NS):
        name = table.attrib.get(f"{{{NS['table']}}}name", "Unknown")
        parsed_rows = read_table_rows(table)
        if not parsed_rows:
            continue

        header_cells = [normalize_field_name(str(v)) for v in parsed_rows[0]]
        if not header_cells:
            continue

        for source_row, cells in enumerate(parsed_rows[1:], 1):
            if not any(normalize_text(value) for value in cells):
                continue
            record: dict[str, Any] = {"reader": name, "source_row": source_row}
            for key, value in zip(header_cells, cells):
                record[FIELD_MAP.get(key, key)] = value
            if record.get("title", "").strip().lower() == "total":
                continue
            if normalize_text(record.get("title")) == "":
                continue
            rows.append(record)

    entries = [canonicalize_entry(row) for row in rows]
    return [row for row in entries if row is not None]


def ingest_from_source(source: Path) -> dict[str, Any]:
    if not source.is_file():
        raise ReadingListError(f"missing source {source}")
    entries = read_ods_payload(source)
    digest = sha256(source)
    source_size = source.stat().st_size
    payload = {
        "generated": {
            "at": now_utc_iso(),
            "source": source.name,
            "source_sha256": digest,
            "source_size_bytes": source_size,
        },
        "entries": entries,
        "readers": [],
        "summary": {"total": 0, "readers": 0, "status": {"complete": 0, "active": 0, "pending": 0}},
    }
    return normalize_payload(
        payload,
        source=source.name,
        source_sha256=digest,
        source_size_bytes=source_size,
        generated_at=payload["generated"]["at"],
    )


def find_entry(
    entries: list[dict[str, Any]],
    *,
    entry_id: str | None = None,
    title: str | None = None,
    author: str | None = None,
    reader: str | None = None,
) -> tuple[dict[str, Any], int]:
    if entry_id:
        normalized_target = normalize_text(entry_id).lower()
        for index, entry in enumerate(entries):
            candidate_id = normalize_text(entry.get("id", "")).lower()
            if candidate_id == normalized_target:
                return entry, index
        raise EntryNotFoundError(f"no entry found with id {entry_id!r}")

    if not title:
        raise EntryMatchError("no entry selector: provide --id or --title")

    normalized_title = normalize_text(title).lower()
    candidates: list[tuple[dict[str, Any], int]] = []
    for index, entry in enumerate(entries):
        candidate_title = normalize_text(entry.get("title", "")).lower()
        if candidate_title != normalized_title:
            continue
        if author and normalize_text(entry.get("author", "")).lower() != normalize_text(author).lower():
            continue
        if reader and normalize_text(entry.get("reader", "")).lower() != normalize_text(reader).lower():
            continue
        candidates.append((entry, index))

    if not candidates:
        contains: list[tuple[dict[str, Any], int]] = []
        for index, entry in enumerate(entries):
            if normalized_title in normalize_text(entry.get("title", "")).lower():
                if author and normalize_text(entry.get("author", "")).lower() != normalize_text(author).lower():
                    continue
                if reader and normalize_text(entry.get("reader", "")).lower() != normalize_text(reader).lower():
                    continue
                contains.append((entry, index))
        candidates = contains

    if not candidates:
        raise EntryNotFoundError(f"no entry matches title {title!r}")
    if len(candidates) > 1:
        options = ", ".join(
            (
                f"{entry.get('title')} by {entry.get('author')} ({entry.get('id')})"
                for entry, _ in candidates[:5]
            )
        )
        raise EntryMatchError(
            f"multiple entries match {title!r}; include --author, --reader, or --id. "
            f"examples: {options}"
        )
    return candidates[0]


def format_entry(entry: dict[str, Any]) -> str:
    return (
        f'{entry.get("id")} | {entry.get("status", "pending"):8} | '
        f'{entry.get("title")} — {entry.get("author")} ({entry.get("reader")})'
    )
