"""Tests for the shared research-library contract."""

import importlib.machinery
import importlib.util
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]


def load():
    loader = importlib.machinery.SourceFileLoader(
        "research_library", str(ROOT / "scripts" / "research-library")
    )
    spec = importlib.util.spec_from_loader("research_library", loader)
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


library = load()


class ResearchLibraryTests(unittest.TestCase):
    def test_repository_library_resolves(self):
        self.assertEqual(library.validate(), [])

    def test_unknown_selected_claim_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            project = root / "example"
            project.mkdir()
            (project / "sources.md").write_text(
                "## SOURCE\n\nhttps://example.gov/original\n", encoding="utf-8"
            )
            (project / "claims.md").write_text(
                "### EX-FACT-001\n\nSupported fact.\n", encoding="utf-8"
            )
            (project / "chatgpt-selection.md").write_text(
                "Selected EX-FACT-999.\n", encoding="utf-8"
            )
            with mock.patch.object(library, "RESEARCH_ROOT", root):
                problems = library.validate()
        self.assertTrue(any("unknown claim ID EX-FACT-999" in item for item in problems))


if __name__ == "__main__":
    unittest.main()
