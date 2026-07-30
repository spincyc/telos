import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
GUIDANCE = " ".join(
    (ROOT / "AGENTS.md").read_text(encoding="utf-8").split())
PAGES = (ROOT / ".github/workflows/pages.yml").read_text(encoding="utf-8")


class RepositoryGuidanceTests(unittest.TestCase):
    def test_terminal_response_requires_fail_closed_yield_check(self):
        self.assertIn(
            "Before every terminal response or handoff, run `aiq status` as "
            "the immediately preceding action",
            GUIDANCE,
        )
        self.assertIn(
            "Ready tasks, unexpired active claims, or messages awaiting "
            "interpretation deny yield: discard the proposed final response, "
            "return to queue scheduling, and execute the highest-priority "
            "runnable task in the same turn",
            GUIDANCE,
        )
        self.assertIn(
            "Any later tool call, commit, push, progress message, user "
            "question, or checkpoint invalidates a prior successful check",
            GUIDANCE,
        )

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
