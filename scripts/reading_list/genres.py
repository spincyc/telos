#!/usr/bin/env python3
"""Genre classification helpers for reading-list tooling."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any
import re

import yaml

from .core import GENRE_DEFAULT_CATEGORY, ReadingListError, normalize_text


DEFAULT_GENRE_SPEC = Path(__file__).resolve().parents[2] / "site/data/reading-genres.yaml"


@dataclass(frozen=True)
class GenreMatch:
    category: str
    coarse: str
    fine: str
    source: str
    score: int


def _coerce_list(raw: Any) -> list[str]:
    if raw is None:
        return []
    if isinstance(raw, str):
        return [str(raw)]
    if isinstance(raw, list):
        return [str(value) for value in raw]
    return []


def _as_text(value: Any) -> str:
    text = normalize_text(value)
    return text


def normalize_genre_id(raw: Any) -> str:
    return normalize_text(raw).lower().replace("_", "-").replace(" ", "-")


def normalize_genre_category(raw: Any) -> str:
    value = normalize_genre_id(raw)
    if value == "fiction":
        return "fiction"
    if value in {"non-fiction", "nonfict", "nonfiction", "non fiction"}:
        return "non-fiction"
    if value in {"", "unclassified", "unknown"}:
        return GENRE_DEFAULT_CATEGORY
    return GENRE_DEFAULT_CATEGORY


def _label(rule: dict[str, Any], fallback: str) -> str:
    value = str(rule.get("name") or rule.get("label") or rule.get("id") or "").strip()
    return value if value else fallback


def _coerce_rule_list(raw: Any) -> list[dict[str, Any]]:
    if not isinstance(raw, list):
        return []
    return [candidate for candidate in raw if isinstance(candidate, dict)]


def load_genre_spec(path: Path) -> dict[str, Any]:
    if not path.is_file():
        raise ReadingListError(f"missing genre spec {path}")
    raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise ReadingListError(f"genre spec must be a mapping: {path}")
    return raw


def _score_rule(rule: dict[str, Any], context: dict[str, str]) -> int:
    signals = rule.get("signals", {})
    if not isinstance(signals, dict):
        return 0

    score = int(rule.get("base_score", 0))
    title = context.get("title", "")
    author = context.get("author", "")
    notes = context.get("notes", "")

    for token in _coerce_list(signals.get("title_exact")):
        if token and _as_text(token).lower() == title:
            score += 12

    for token in _coerce_list(signals.get("author_exact")):
        if token and _as_text(token).lower() == author:
            score += 10

    for token in _coerce_list(signals.get("title_keywords")):
        if token and _as_text(token).lower() in title:
            score += 6

    for token in _coerce_list(signals.get("author_keywords")):
        if token and _as_text(token).lower() in author:
            score += 5

    for token in _coerce_list(signals.get("notes_keywords")):
        if token and _as_text(token).lower() in notes:
            score += 2

    for pattern in _coerce_list(signals.get("title_regex")):
        if not pattern:
            continue
        try:
            if re.search(pattern, title, flags=re.IGNORECASE):
                score += 8
        except re.error:
            continue

    for pattern in _coerce_list(signals.get("notes_regex")):
        if not pattern:
            continue
        try:
            if re.search(pattern, notes, flags=re.IGNORECASE):
                score += 4
        except re.error:
            continue

    return score


def _best_match(
    rules: list[dict[str, Any]],
    context: dict[str, str],
) -> tuple[dict[str, Any] | None, int]:
    if not rules:
        return None, 0

    selected: dict[str, Any] | None = None
    selected_id = ""
    selected_score = -1
    for rule in rules:
        candidate_id = normalize_genre_id(rule.get("id"))
        score = _score_rule(rule, context)
        if score > selected_score or (
            score == selected_score
            and selected is not None
            and candidate_id
            and selected_id
            and candidate_id < selected_id
        ):
            selected = rule
            selected_id = candidate_id
            selected_score = score

    if selected is not None:
        return selected, selected_score
    return None, 0


def _best_or_default(
    rules: list[dict[str, Any]],
    context: dict[str, str],
    *,
    default_id: str | None = None,
) -> tuple[dict[str, Any], int]:
    rule, score = _best_match(rules, context)
    if rule is not None:
        return rule, score

    if default_id:
        normalized_default = normalize_genre_id(default_id)
        for candidate in rules:
            if normalize_genre_id(candidate.get("id")) == normalized_default:
                return candidate, 0

    for candidate in rules:
        if candidate.get("default", False):
            return candidate, 0

    if rules:
        return rules[0], 0

    fallback = {"id": GENRE_DEFAULT_CATEGORY, "name": "Unclassified"}
    return fallback, 0


def _category_candidates(raw_categories: dict[str, Any]) -> list[dict[str, Any]]:
    candidates: list[dict[str, Any]] = []
    for key, raw in raw_categories.items():
        if not isinstance(raw, dict):
            continue
        candidate = dict(raw)
        candidate.setdefault("id", key)
        candidates.append(candidate)
    return candidates


def _to_context(entry: dict[str, Any]) -> dict[str, str]:
    return {
        "title": _as_text(entry.get("title")).lower(),
        "author": _as_text(entry.get("author")).lower(),
        "notes": _as_text(entry.get("notes")).lower(),
    }


def _match_exact_entries(
    exact_matches: list[dict[str, Any]],
    context: dict[str, str],
) -> GenreMatch | None:
    if not exact_matches:
        return None

    title = context["title"]
    author = context["author"]
    for rule in exact_matches:
        if not isinstance(rule, dict):
            continue
        if _as_text(rule.get("title")).lower() != title:
            continue
        expected_author = _as_text(rule.get("author")).lower()
        if expected_author and expected_author != author:
            continue
        category = normalize_genre_category(rule.get("category"))
        coarse = _label({"name": rule.get("coarse")}, "Unspecified")
        fine = _label({"name": rule.get("fine")}, coarse)
        return GenreMatch(
            category=category,
            coarse=coarse,
            fine=fine,
            source=f"exact:{normalize_text(rule.get('title'))}",
            score=999,
        )

    return None


def _classify_entry(entry: dict[str, Any], spec: dict[str, Any]) -> GenreMatch:
    context = _to_context(entry)
    defaults = spec.get("defaults", {})
    if not isinstance(defaults, dict):
        defaults = {}

    exact = _match_exact_entries(spec.get("exact_matches", []), context)
    if exact is not None:
        return exact

    raw_categories = spec.get("categories", {})
    if not isinstance(raw_categories, dict):
        raw_categories = {}
    candidates = _category_candidates(raw_categories)
    category_rule, category_score = _best_match(candidates, context)

    category_id = normalize_genre_category(defaults.get("category"))
    category_payload: dict[str, Any] = {}

    if category_rule is not None and category_score > 0:
        candidate_id = normalize_genre_category(category_rule.get("id"))
        if candidate_id in {"fiction", "non-fiction"}:
            category_id = candidate_id
            category_payload = category_rule

    if not category_payload:
        category_payload = raw_categories.get(category_id, {})
        if not isinstance(category_payload, dict):
            category_payload = {}

    coarse_rules = _coerce_rule_list(category_payload.get("coarse"))
    default_coarse = normalize_text(category_payload.get("default_coarse"))
    coarse_rule, coarse_score = _best_or_default(coarse_rules, context, default_id=default_coarse)
    coarse_label = _label(
        coarse_rule,
        _as_text(defaults.get("coarse", "Unclassified")),
    )

    fine_rules = _coerce_rule_list(coarse_rule.get("fine"))
    default_fine = normalize_text(coarse_rule.get("default_fine"))
    fine_rule, fine_score = _best_or_default(fine_rules, context, default_id=default_fine)
    fine_label = _label(
        fine_rule,
        _as_text(defaults.get("fine", "Unspecified")),
    )

    return GenreMatch(
        category=category_id,
        coarse=coarse_label,
        fine=fine_label,
        source=f"{category_id}:{normalize_genre_id(coarse_rule.get('id'))}:{normalize_genre_id(fine_rule.get('id'))}",
        score=category_score + coarse_score + fine_score,
    )


def scan_library_entries(
    entries: list[dict[str, Any]],
    *,
    genre_spec_path: Path,
) -> tuple[dict[str, int], list[dict[str, Any]]]:
    spec = load_genre_spec(genre_spec_path)
    defaults = spec.get("defaults", {})
    if not isinstance(defaults, dict):
        defaults = {}

    scanned = 0
    updated = 0
    matched = 0
    category_breakdown: dict[str, int] = {}

    for entry in entries:
        scanned += 1
        before_category = normalize_genre_category(entry.get("genre_category"))
        before_coarse = _as_text(entry.get("genre_coarse"))
        before_fine = _as_text(entry.get("genre_fine"))

        classification = _classify_entry(entry, spec)
        if classification.category != GENRE_DEFAULT_CATEGORY:
            matched += 1

        if (
            before_category != classification.category
            or before_coarse != classification.coarse
            or before_fine != classification.fine
        ):
            updated += 1

        entry["genre_category"] = classification.category
        entry["genre_coarse"] = classification.coarse
        entry["genre_fine"] = classification.fine
        entry["genre_rule"] = classification.source

        category_breakdown[classification.category] = category_breakdown.get(classification.category, 0) + 1

    if not category_breakdown:
        category_breakdown = {GENRE_DEFAULT_CATEGORY: 0}
    if GENRE_DEFAULT_CATEGORY in category_breakdown and defaults.get("category") == GENRE_DEFAULT_CATEGORY:
        category_breakdown.setdefault(GENRE_DEFAULT_CATEGORY, 0)

    return (
        {
            "scanned": scanned,
            "classified": matched,
            "updated": updated,
            "category_breakdown": category_breakdown,
        },
        entries,
    )
