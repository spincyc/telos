#!/usr/bin/env python3
"""Focused tests for the pre-release package metadata and imports."""

from __future__ import annotations

import importlib
import inspect
import re
import sys
import unittest
from pathlib import Path


PACKAGE_ROOT = Path(__file__).resolve().parents[1]
SOURCE_ROOT = PACKAGE_ROOT / "src"
PYPROJECT = PACKAGE_ROOT / "pyproject.toml"


def project_section() -> str:
    text = PYPROJECT.read_text(encoding="utf-8")
    _, section = text.split("[project]\n", 1)
    return section.split("\n[", 1)[0]


def project_string(name: str) -> str:
    match = re.search(
        rf'(?m)^{re.escape(name)}\s*=\s*"([^"]+)"\s*$',
        project_section(),
    )
    if match is None:
        raise AssertionError(f"missing string project metadata: {name}")
    return match.group(1)


class PackageTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        sys.path.insert(0, str(SOURCE_ROOT))

    @classmethod
    def tearDownClass(cls) -> None:
        try:
            sys.path.remove(str(SOURCE_ROOT))
        except ValueError:
            pass

    def test_distribution_metadata_matches_imported_package(self) -> None:
        package = importlib.import_module("worktree_marshal")

        self.assertEqual(project_string("name"), "worktree-marshal")
        self.assertEqual(project_string("version"), package.__version__)
        self.assertEqual(package.__version__, "0.0.0")
        self.assertEqual(project_string("license"), "MIT")

    def test_supported_python_and_runtime_dependency_contract(self) -> None:
        section = project_section()

        self.assertEqual(project_string("requires-python"), ">=3.10")
        self.assertRegex(section, r"(?m)^dependencies\s*=\s*\[\]\s*$")

    def test_make_fragment_is_an_importable_package_resource(self) -> None:
        resources = importlib.import_module("worktree_marshal.resources")
        fragment = resources.make_fragment()

        self.assertTrue(fragment.is_file())
        self.assertEqual(fragment.name, "worktree-marshal.mk")
        self.assertIn(
            "Worktree Marshal Make-fragment API 1",
            resources.read_make_fragment(),
        )

    def test_triptych_engine_import_has_no_git_pinning_side_effect(self) -> None:
        engine = importlib.import_module("worktree_marshal.engine")
        compatibility = importlib.import_module("worktree_marshal.triptych_compat")

        self.assertIsNone(engine._PINNED_GIT)
        signature = inspect.signature(compatibility.main)
        invocation_path = signature.parameters["invocation_path"]
        self.assertEqual(invocation_path.kind, inspect.Parameter.KEYWORD_ONLY)
        self.assertIs(invocation_path.default, inspect.Parameter.empty)

    def test_shared_engine_requires_an_explicit_profile_context(self) -> None:
        engine = importlib.import_module("worktree_marshal.engine")
        profiles = importlib.import_module("worktree_marshal.profiles")

        with self.assertRaisesRegex(RuntimeError, "profile is not bound"):
            engine.active_profile()
        with engine.profile_context(profiles.GENERIC_V1_PROFILE):
            self.assertIs(engine.active_profile(), profiles.GENERIC_V1_PROFILE)
        with self.assertRaisesRegex(RuntimeError, "profile is not bound"):
            engine.active_profile()

    def test_package_publishes_only_the_generic_command_entry_point(self) -> None:
        metadata = PYPROJECT.read_text(encoding="utf-8")

        self.assertIn(
            '[project.scripts]\nworktree-marshal = "worktree_marshal.cli:main"\n',
            metadata,
        )
        self.assertNotIn("triptych-codex =", metadata)


if __name__ == "__main__":
    unittest.main()
