"""Packaged integration resources for generated consumer files."""

from __future__ import annotations

from importlib.resources import files
from importlib.resources.abc import Traversable


MAKE_FRAGMENT_NAME = "worktree-marshal.mk"


def make_fragment() -> Traversable:
    """Return the packaged GNU Make integration fragment."""

    return files(__package__).joinpath(MAKE_FRAGMENT_NAME)


def read_make_fragment() -> str:
    """Read the packaged GNU Make integration fragment as UTF-8 text."""

    return make_fragment().read_text(encoding="utf-8")


__all__ = ["MAKE_FRAGMENT_NAME", "make_fragment", "read_make_fragment"]
