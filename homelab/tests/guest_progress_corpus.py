"""Shared loader and JSON Schema validator for the guest-progress corpus.

One corpus, three consumers: the host protocol, the Arch guest reporter that
ships in the image, and the Windows COM1 reporter.  Each consumer asserts the
same byte-exact canonical payloads, so the three canonicalisers cannot drift
apart unnoticed.

`jsonschema` is not available here and this repository ships no third-party
dependencies, so the validator below implements exactly the keyword subset the
published schema uses.  `test_guest_progress_schema` asserts the schema uses no
keyword outside `SUPPORTED_KEYWORDS`, which closes the drift hole: adding an
unimplemented keyword fails a test rather than silently validating nothing.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "guest-progress"
SCHEMA_PATH = FIXTURES / "guest-progress-event-v1.schema.json"
CORPUS_PATH = FIXTURES / "corpus.json"

# Every keyword the validator below implements.  Annotation-only keywords are
# listed too, so an unknown keyword is genuinely unknown.
SUPPORTED_KEYWORDS = frozenset({
    "$schema", "$id", "$comment", "title", "description",
    "type", "enum", "const", "pattern",
    "properties", "required", "additionalProperties",
    "minimum", "maximum",
    "allOf", "if", "then", "else", "not",
})

_TYPES = {
    "object": dict,
    "array": list,
    "string": str,
    "boolean": bool,
    "null": type(None),
}


class SchemaViolation(Exception):
    """The instance does not satisfy the published schema."""


def load_schema() -> dict:
    return json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))


def load_corpus() -> dict:
    return json.loads(CORPUS_PATH.read_text(encoding="utf-8"))


def schema_keywords(schema) -> set[str]:
    """Every keyword appearing anywhere in the schema document."""

    found: set[str] = set()
    if isinstance(schema, dict):
        for key, value in schema.items():
            found.add(key)
            if key == "properties" and isinstance(value, dict):
                for subschema in value.values():
                    found |= schema_keywords(subschema)
            elif key in ("required", "enum", "type"):
                continue
            else:
                found |= schema_keywords(value)
    elif isinstance(schema, list):
        for item in schema:
            found |= schema_keywords(item)
    return found


def _compile(pattern: str) -> re.Pattern:
    # JSON Schema patterns are ECMAScript regular expressions applied with a
    # substring search.  Without the `m` flag ECMAScript `$` means end of
    # input, while Python's `$` also matches before a trailing newline, so a
    # trailing `$` is translated to `\Z`.  Nothing else differs for the
    # character classes this schema uses.
    if pattern.endswith("$") and not pattern.endswith("\\$"):
        pattern = pattern[:-1] + r"\Z"
    return re.compile(pattern)


def _matches_type(value, declared) -> bool:
    names = declared if isinstance(declared, list) else [declared]
    for name in names:
        if name == "integer":
            # Faithful to JSON Schema: any number with a zero fractional part
            # is an integer, and booleans never are.  The transport is
            # stricter -- it refuses `1.0` outright -- and the corpus records
            # that divergence explicitly.
            if isinstance(value, bool):
                continue
            if isinstance(value, int):
                return True
            if isinstance(value, float) and value.is_integer():
                return True
            continue
        if name == "number":
            if not isinstance(value, bool) and isinstance(value, (int, float)):
                return True
            continue
        expected = _TYPES.get(name)
        if expected is None:
            raise SchemaViolation(f"unsupported schema type {name!r}")
        if name == "boolean":
            if isinstance(value, bool):
                return True
            continue
        if isinstance(value, bool) and expected is not bool:
            continue
        if isinstance(value, expected):
            return True
    return False


def validates(schema, instance) -> bool:
    """Return whether the instance satisfies the schema subset."""

    try:
        validate(schema, instance)
    except SchemaViolation:
        return False
    return True


def validate(schema, instance, path: str = "") -> None:
    """Validate one instance, raising SchemaViolation on the first failure."""

    if schema is True:
        return
    if schema is False:
        raise SchemaViolation(f"{path or 'instance'} is refused")
    if not isinstance(schema, dict):
        raise SchemaViolation("schema must be an object or boolean")
    unknown = set(schema) - SUPPORTED_KEYWORDS
    if unknown:
        raise SchemaViolation(f"unsupported schema keywords: {sorted(unknown)}")

    if "type" in schema and not _matches_type(instance, schema["type"]):
        raise SchemaViolation(f"{path or 'instance'} has the wrong type")
    if "const" in schema and instance != schema["const"]:
        raise SchemaViolation(f"{path or 'instance'} is not the required const")
    if "enum" in schema and not any(
        instance == option and type(instance) is type(option)
        for option in schema["enum"]
    ):
        raise SchemaViolation(f"{path or 'instance'} is outside the enum")
    if "pattern" in schema and isinstance(instance, str):
        if _compile(schema["pattern"]).search(instance) is None:
            raise SchemaViolation(f"{path or 'instance'} fails its pattern")
    if "minimum" in schema and isinstance(instance, (int, float)) and (
        not isinstance(instance, bool)
    ):
        if instance < schema["minimum"]:
            raise SchemaViolation(f"{path or 'instance'} is below the minimum")
    if "maximum" in schema and isinstance(instance, (int, float)) and (
        not isinstance(instance, bool)
    ):
        if instance > schema["maximum"]:
            raise SchemaViolation(f"{path or 'instance'} is above the maximum")

    if isinstance(instance, dict):
        properties = schema.get("properties", {})
        for name in schema.get("required", ()):
            if name not in instance:
                raise SchemaViolation(f"{path}/{name} is required")
        if schema.get("additionalProperties") is False:
            extra = set(instance) - set(properties)
            if extra:
                raise SchemaViolation(
                    f"{path or 'instance'} has additional properties "
                    f"{sorted(extra)}")
        for name, subschema in properties.items():
            if name in instance:
                validate(subschema, instance[name], f"{path}/{name}")

    if "not" in schema and validates(schema["not"], instance):
        raise SchemaViolation(f"{path or 'instance'} matches a forbidden shape")
    for index, subschema in enumerate(schema.get("allOf", ())):
        validate(subschema, instance, f"{path}/allOf/{index}")
    if "if" in schema:
        branch = "then" if validates(schema["if"], instance) else "else"
        if branch in schema:
            validate(schema[branch], instance, f"{path}/{branch}")
