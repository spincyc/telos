import re
import unittest
from pathlib import Path


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
SOURCE_ROOT = REPOSITORY_ROOT / "src"
VERSION = re.compile(r"\{20\d{6}\.\d{3}\}")
META = re.compile(r"\\telosmeta")
LEGACY_DATE = re.compile(r"\{20\d{2}-\d{2}-\d{2}\}")


class PublicationVersionTests(unittest.TestCase):
    def test_every_metadata_declaration_has_a_version(self):
        failures = []
        for source in sorted(SOURCE_ROOT.rglob("*.tex")):
            if source == SOURCE_ROOT / "common" / "preamble.tex":
                continue
            text = source.read_text(encoding="utf-8")
            count = len(META.findall(text))
            if not count:
                continue
            versions = len(VERSION.findall(text))
            if versions < count or LEGACY_DATE.search(text):
                failures.append(
                    f"{source.relative_to(REPOSITORY_ROOT)}: "
                    f"{count} metadata declarations, {versions} versions"
                )
        self.assertFalse(failures, "\n".join(failures))


if __name__ == "__main__":
    unittest.main()
