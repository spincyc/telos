#!/usr/bin/env python3
"""Bounded detection of raw and one-layer Base64-wrapped secrets."""

from __future__ import annotations

import base64
from collections.abc import Iterable


MAX_BASE64_TOKEN = 1024 * 1024
_BASE64_BYTES = frozenset(
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=_-")


def secret_needles(secrets: Iterable[str | bytes]) -> tuple[bytes, ...]:
    """Return nonempty UTF encodings that must not be retained."""
    variants: set[bytes] = set()
    for secret in secrets:
        if isinstance(secret, str):
            encoded = secret.encode("utf-8")
            variants.update((
                encoded,
                secret.encode("utf-16-le"),
                secret.encode("utf-16-be"),
            ))
        elif isinstance(secret, bytes):
            encoded = secret
            variants.add(encoded)
        else:
            raise TypeError("known secrets must be strings or bytes")
        if not encoded:
            raise ValueError("known secrets must not be empty")
    if not variants:
        raise ValueError("at least one known secret is required")
    return tuple(sorted(variants, key=len, reverse=True))


def _decoded_base64(token: bytes) -> bytes | None:
    if len(token) < 4 or len(token) > MAX_BASE64_TOKEN:
        return None
    unpadded = token.rstrip(b"=")
    if b"=" in unpadded:
        return None
    padded = unpadded + b"=" * (-len(unpadded) % 4)
    try:
        return base64.b64decode(padded, altchars=b"-_", validate=True)
    except (ValueError, base64.binascii.Error):
        return None


def count_secret_occurrences(
    chunks: Iterable[bytes], needles: tuple[bytes, ...],
) -> int:
    """Count raw hits and hits inside bounded, one-layer Base64 tokens."""
    if not needles or any(not needle for needle in needles):
        raise ValueError("nonempty secret needles are required")
    tails = [b""] * len(needles)
    token = bytearray()
    token_oversized = False
    found = 0

    def finish_token() -> None:
        nonlocal found, token_oversized
        if not token_oversized:
            decoded = _decoded_base64(bytes(token))
            if decoded is not None:
                found += sum(decoded.count(needle) for needle in needles)
        token.clear()
        token_oversized = False

    for chunk in chunks:
        if not isinstance(chunk, bytes):
            raise TypeError("secret scan chunks must be bytes")
        for index, needle in enumerate(needles):
            window = tails[index] + chunk
            found += window.count(needle)
            overlap = len(needle) - 1
            tails[index] = window[-overlap:] if overlap else b""
        for value in chunk:
            if value in _BASE64_BYTES:
                if not token_oversized:
                    if len(token) < MAX_BASE64_TOKEN:
                        token.append(value)
                    else:
                        token.clear()
                        token_oversized = True
            elif token or token_oversized:
                finish_token()
    if token or token_oversized:
        finish_token()
    return found
