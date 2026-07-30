"""Reusable reading list tooling package."""

from .core import (
    DEFAULT_JSON_OUTPUT,
    DEFAULT_SOURCE,
    DEFAULT_YAML_OUTPUT,
    ingest_from_source,
    load_payload,
    normalize_payload,
    write_payload,
)
from .actions import (
    EntrySelector,
    enqueue_entry,
    list_entries,
    load_state,
    mark_finished,
    mark_started,
    scan,
    update_pages,
    update_words,
)
from .genres import (
    DEFAULT_GENRE_SPEC,
    GenreMatch,
    load_genre_spec,
    scan_library_entries,
)
from .cli import main

__all__ = [
    "DEFAULT_SOURCE",
    "DEFAULT_YAML_OUTPUT",
    "DEFAULT_JSON_OUTPUT",
    "ingest_from_source",
    "load_payload",
    "normalize_payload",
    "write_payload",
    "EntrySelector",
    "scan",
    "load_state",
    "list_entries",
    "enqueue_entry",
    "mark_started",
    "mark_finished",
    "update_pages",
    "update_words",
    "DEFAULT_GENRE_SPEC",
    "GenreMatch",
    "scan_library_entries",
    "load_genre_spec",
    "main",
]
