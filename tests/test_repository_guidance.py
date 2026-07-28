import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
GUIDANCE = " ".join(
    (ROOT / "AGENTS.md").read_text(encoding="utf-8").split())
PAGES = (ROOT / ".github/workflows/pages.yml").read_text(encoding="utf-8")


class RepositoryGuidanceTests(unittest.TestCase):
    def test_every_push_requires_exact_sha_pages_workflow_proof(self):
        self.assertIn(
            "After every push, find the `Publish GitHub Pages` workflow run "
            "whose `headSha` exactly equals the pushed commit",
            GUIDANCE,
        )
        self.assertIn(
            "require a successful conclusion before reporting the push "
            "complete or starting another push",
            GUIDANCE,
        )

    def test_main_push_requires_deployment_url_inspection(self):
        self.assertIn(
            "After every push to `main`, also verify that the successful "
            "`github-pages` deployment references the pushed SHA",
            GUIDANCE,
        )
        self.assertIn(
            "inspect the deployment URL, and verify the affected public pages",
            GUIDANCE,
        )

    def test_pages_verifies_every_push_but_deploys_only_main(self):
        self.assertIn("on:\n  push:\n", PAGES)
        self.assertNotIn("branches: [main]", PAGES)
        self.assertIn("if: github.ref == 'refs/heads/main'", PAGES)
        self.assertIn("needs: verify", PAGES)


if __name__ == "__main__":
    unittest.main()
