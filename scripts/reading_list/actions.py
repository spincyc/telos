#!/usr/bin/env python3
"""Reusable deterministic actions for the reading tracker."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

from .core import (
    ReadingListError,
    canonicalize_entry,
    find_entry,
    load_payload,
    write_payload,
)
from .genres import scan_library_entries


@dataclass(frozen=True)
class EntrySelector:
    """Selector for a specific reading-list entry."""

    entry_id: str | None = None
    title: str | None = None
    author: str | None = None


def load_state(json_path: Path) -> dict[str, Any]:
    return load_payload(json_path)


def persist_state(
    payload: dict[str, Any],
    *,
    yaml_path: Path,
    json_path: Path,
    source: str = "manual",
    source_sha256: str | None = None,
    source_size_bytes: int | None = None,
) -> dict[str, Any]:
    return write_payload(
        payload,
        yaml_path=yaml_path,
        json_path=json_path,
        source=source,
        source_sha256=source_sha256,
        source_size_bytes=source_size_bytes,
    )


def list_entries(
    payload: dict[str, Any],
    *,
    target_status: str = "all",
    query: str = "",
) -> list[dict[str, Any]]:
    entries = payload.get("entries", [])
    target = target_status.strip().lower()
    normalized_query = query.strip().lower()

    selected: list[dict[str, Any]] = []
    for entry in entries:
        if target != "all" and entry.get("status") != target:
            continue
        haystack = " ".join(
            str(value or "").lower()
            for value in (
                entry.get("title", ""),
                entry.get("author", ""),
                entry.get("notes", ""),
                entry.get("id", ""),
                entry.get("genre_category", ""),
                entry.get("genre_coarse", ""),
                entry.get("genre_fine", ""),
            )
        )
        if normalized_query and normalized_query not in haystack:
            continue
        selected.append(entry)
    return selected


def _resolve(payload: dict[str, Any], selector: EntrySelector) -> tuple[dict[str, Any], int]:
    return find_entry(
        payload.get("entries", []),
        entry_id=selector.entry_id,
        title=selector.title,
        author=selector.author,
    )


def _write_selected(
    payload: dict[str, Any],
    *,
    selector: EntrySelector,
    yaml_path: Path,
    json_path: Path,
    mutate: Callable[[dict[str, Any]], None],
) -> tuple[dict[str, Any], dict[str, Any]]:
    entry, _ = _resolve(payload, selector)
    mutate(entry)
    updated = persist_state(payload, yaml_path=yaml_path, json_path=json_path, source="manual")
    refreshed, _ = find_entry(updated.get("entries", []), entry_id=entry.get("id"))
    if refreshed is None:
        raise ReadingListError("failed to reload updated entry")
    return updated, refreshed


def enqueue_entry(
    payload: dict[str, Any],
    *,
    title: str,
    author: str,
    notes: str = "",
    pages: int | None = None,
    words: int | None = None,
    yaml_path: Path,
    json_path: Path,
) -> tuple[dict[str, Any], dict[str, Any]]:
    payload.setdefault("entries", [])
    record = canonicalize_entry(
        {
            "title": title,
            "author": author,
            "status": "pending",
            "started": None,
            "completed": None,
            "pages": pages,
            "words": words,
            "days": None,
            "pages_per_day": None,
            "words_per_day": None,
            "notes": notes,
        },
        force_id=True,
    )
    if record is None:
        raise ReadingListError("cannot enqueue an entry without a title")

    payload["entries"].append(record)
    updated = persist_state(payload, yaml_path=yaml_path, json_path=json_path, source="manual")
    entry, _ = find_entry(
        updated.get("entries", []),
        entry_id=record.get("id"),
    )
    if entry is None:
        raise ReadingListError("failed to locate newly enqueued entry")
    return updated, entry


def mark_started(
    payload: dict[str, Any],
    selector: EntrySelector,
    *,
    date_value: str,
    yaml_path: Path,
    json_path: Path,
) -> tuple[dict[str, Any], dict[str, Any]]:
    def mark_started_entry(entry: dict[str, Any]) -> None:
        entry["started"] = date_value

    return _write_selected(
        payload,
        selector=selector,
        yaml_path=yaml_path,
        json_path=json_path,
        mutate=mark_started_entry,
    )


def mark_finished(
    payload: dict[str, Any],
    selector: EntrySelector,
    *,
    date_value: str,
    yaml_path: Path,
    json_path: Path,
) -> tuple[dict[str, Any], dict[str, Any]]:
    def mark_finished_entry(entry: dict[str, Any]) -> None:
        entry["completed"] = date_value
        if not entry.get("started"):
            entry["started"] = date_value

    return _write_selected(
        payload,
        selector=selector,
        yaml_path=yaml_path,
        json_path=json_path,
        mutate=mark_finished_entry,
    )


def update_pages(
    payload: dict[str, Any],
    selector: EntrySelector,
    *,
    pages: int,
    yaml_path: Path,
    json_path: Path,
) -> tuple[dict[str, Any], dict[str, Any]]:
    def set_pages(entry: dict[str, Any]) -> None:
        entry["pages"] = pages

    return _write_selected(
        payload,
        selector=selector,
        yaml_path=yaml_path,
        json_path=json_path,
        mutate=set_pages,
    )


def update_words(
    payload: dict[str, Any],
    selector: EntrySelector,
    *,
    words: int,
    yaml_path: Path,
    json_path: Path,
) -> tuple[dict[str, Any], dict[str, Any]]:
    def set_words(entry: dict[str, Any]) -> None:
        entry["words"] = words

    return _write_selected(
        payload,
        selector=selector,
        yaml_path=yaml_path,
        json_path=json_path,
        mutate=set_words,
    )


def scan(
    payload: dict[str, Any],
    *,
    genre_spec_path: Path,
    yaml_path: Path,
    json_path: Path,
) -> tuple[dict[str, Any], dict[str, int]]:
    report, updated_entries = scan_library_entries(payload.get("entries", []), genre_spec_path=genre_spec_path)
    payload["entries"] = updated_entries
    updated = persist_state(payload, yaml_path=yaml_path, json_path=json_path, source="manual")
    return updated, report
