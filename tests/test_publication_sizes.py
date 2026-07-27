from pathlib import Path
import unittest


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
PUBLICATION_ROOT = REPOSITORY_ROOT / "doc"
MAX_PUBLISHED_PDF_BYTES = 50_000_000


class PublicationSizeTests(unittest.TestCase):
    def test_tracked_publications_fit_github_without_lfs(self):
        oversized = []
        for publication in sorted(PUBLICATION_ROOT.rglob("*.pdf")):
            size = publication.stat().st_size
            if size > MAX_PUBLISHED_PDF_BYTES:
                oversized.append(
                    f"{publication.relative_to(REPOSITORY_ROOT)}: {size} bytes"
                )

        self.assertEqual(
            oversized,
            [],
            "Published PDFs must remain directly cloneable without Git LFS:\n"
            + "\n".join(oversized),
        )


if __name__ == "__main__":
    unittest.main()
