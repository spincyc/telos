"""Command agreement between the homelab site guides and the Makefile.

Every `make homelab-...` invocation printed in a homelab human/operator guide
must name a real `.PHONY` homelab target. A guide that cites a renamed or
deleted target is stale documentation, and this test fails closed on it so the
staleness is caught before publication rather than by a reader whose command
errors out.

Modeled on ``test_controller_network_docs.py``: parse the contract out of the
Makefile, scan the published sources, and assert agreement.
"""

import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
MAKEFILE = ROOT / "Makefile"
PAGES_DIR = ROOT / "site/pages/homelab"

# A `make homelab-<target>` invocation in prose or a fenced code block. Target
# names are lowercase words with hyphens; the class stops at the first space,
# backslash line-continuation, or Make variable assignment that follows.
INVOCATION_RE = re.compile(r"\bmake\s+(homelab-[a-z0-9-]+)")


def join_continuations(text: str) -> str:
    """Fold Makefile backslash line-continuations into single logical lines."""
    return re.sub(r"\\\n\s*", " ", text)


def phony_homelab_targets(makefile_text: str) -> set[str]:
    """Every homelab target declared on a ``.PHONY:`` line."""
    targets: set[str] = set()
    for logical_line in join_continuations(makefile_text).splitlines():
        stripped = logical_line.strip()
        if not stripped.startswith(".PHONY:"):
            continue
        for token in stripped[len(".PHONY:"):].split():
            if token.startswith("homelab-"):
                targets.add(token)
    return targets


def referenced_commands() -> dict[str, list[str]]:
    """Map each cited ``make homelab-*`` target to the pages that cite it."""
    references: dict[str, list[str]] = {}
    for page in sorted(PAGES_DIR.glob("*.md")):
        text = page.read_text(encoding="utf-8")
        for target in dict.fromkeys(INVOCATION_RE.findall(text)):
            references.setdefault(target, []).append(page.name)
    return references


class HomelabDocCommandTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.phony = phony_homelab_targets(MAKEFILE.read_text(encoding="utf-8"))
        cls.references = referenced_commands()

    def test_makefile_exposes_homelab_targets(self) -> None:
        # A parser that silently found nothing would make the agreement test
        # vacuously pass; prove the contract is non-empty first.
        self.assertGreater(len(self.phony), 10)

    def test_guides_cite_commands(self) -> None:
        # The guides are meaningless as an operator reference if none of them
        # actually name a command; catch a scan that matched nothing.
        self.assertGreater(len(self.references), 0)

    def test_every_cited_command_is_a_real_phony_target(self) -> None:
        stale = {
            target: pages
            for target, pages in self.references.items()
            if target not in self.phony
        }
        self.assertEqual(
            stale,
            {},
            "homelab guides cite make targets absent from the Makefile .PHONY "
            f"list: {stale}",
        )


if __name__ == "__main__":
    unittest.main()
