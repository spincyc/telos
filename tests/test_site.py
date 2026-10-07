"""Source-relative publication links must stay inside tracked public source."""

import argparse
import contextlib
import importlib.machinery
import importlib.util
import io
import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
loader = importlib.machinery.SourceFileLoader("telos_site", str(ROOT / "scripts/site"))
spec = importlib.util.spec_from_loader(loader.name, loader)
site = importlib.util.module_from_spec(spec)
loader.exec_module(site)


class SourceRelativeLinkTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.git("init", "--quiet")
        self.guide = {
            "source": "notes/docs/guide.md",
            "output": "projects/notes/guide/index.html",
            "source_relative_links": True,
            "title": "Human guide", "layout": "default",
        }
        self.runbook = {
            "source": "notes/docs/runbook.md",
            "output": "projects/notes/runbook/index.html",
            "source_relative_links": True,
            "title": "Runbook", "layout": "default",
        }
        self.manifest = {
            "title": "Telos", "tagline": "Test site",
            "navigation": [{"label": "Home", "output": "index.html"}],
            "pages": [self.guide, self.runbook, {
                "source": "README.md", "output": "index.html",
                "title": "Home", "layout": "default",
            }],
        }
        self.write(self.guide["source"], """# Human guide

[Runbook](runbook.md?view=full&plain=1#usage)
[Ledger][state]
[Decisions](../decisions/)
[Home](../../README.md#home)
[This section](#human-guide)

[state]: ../STATE.md?plain=1#evidence
""")
        self.write(self.runbook["source"], "# Usage\n\n[Human guide](guide.md)")
        self.write("README.md", "# Home")
        self.write("notes/STATE.md", "# Evidence")
        self.write("notes/decisions/decision.md", "# Decision")
        self.write("release/site/layouts/default.html", "<html>{{content}}</html>")
        self.write("release/site/assets/style.css", "body {}")
        self.write(".gitignore", "/notes/private/\n/notes/var/\n/build/\n")
        self.write("site/site.json", json.dumps(self.manifest))
        self.git("add", ".")
        patches = mock.patch.multiple(
            site, ROOT=self.root, MANIFEST_PATH=self.root / "site/site.json",
            LAYOUT_ROOT=self.root / "release/site/layouts",
            ASSET_ROOT=self.root / "release/site/assets",
            DATA_ROOT=self.root / "site/data", DOC_ROOT=self.root / "doc",
            OUTPUT_ROOT=self.root / "build/site",
        )
        patches.start()
        self.addCleanup(patches.stop)

    def git(self, *arguments):
        return subprocess.run(
            ["git", "-C", str(self.root), *arguments], check=True,
            capture_output=True, text=True,
        )

    def write(self, name, text):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
        return path

    def test_build_resolves_crosslinks_and_public_source_with_fragments_and_queries(self):
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(site.command_build(argparse.Namespace(serve=False)), 0)
            self.assertEqual(site.command_verify(argparse.Namespace()), 0)
        guide = (site.OUTPUT_ROOT / self.guide["output"]).read_text()
        runbook = (site.OUTPUT_ROOT / self.runbook["output"]).read_text()
        self.assertIn('href="../runbook/index.html?view=full&amp;plain=1#usage"', guide)
        self.assertIn('href="../guide/index.html"', runbook)
        self.assertIn(
            'href="https://github.com/spincyc/telos/blob/main/notes/STATE.md?plain=1#evidence"',
            guide,
        )
        self.assertIn('href="https://github.com/spincyc/telos/tree/main/notes/decisions"', guide)
        self.assertIn('href="../../../index.html#home"', guide)
        self.assertIn('href="#human-guide"', guide)

    def test_missing_escaped_and_private_targets_fail_in_check_and_rewrite(self):
        self.write("notes/untracked.md", "untracked")
        self.write("notes/private/private.json", "private")
        self.write("notes/var/evidence.md", "private")
        # Even an accidentally force-added ignored file cannot become a link.
        self.git("add", "--force", "notes/private/private.json")
        public_files = site.public_repository_files()
        for href in (
            "missing.md", "../../../outside.md", "%2e%2e/%2e%2e/%2e%2e/outside.md",
            "/etc/passwd", "../untracked.md", "../private/private.json",
            "../var/evidence.md", "../private/", "../../.git/config",
        ):
            with self.subTest(href=href):
                text = f"[Target]({href})"
                self.write(self.guide["source"], text)
                problems, _ = site.check_links(self.manifest)
                self.assertEqual(len(problems), 1, problems)
                self.assertIn(href, problems[0])
                with self.assertRaises(site.SiteError):
                    site.rewrite_source_links(
                        site.render_markdown(text), self.guide, self.manifest, public_files
                    )

    def test_symlink_and_symlinked_parent_are_rejected(self):
        (self.root / "notes/link.md").symlink_to("STATE.md")
        (self.root / "notes/outside").symlink_to("/etc", target_is_directory=True)
        self.git("add", "notes/link.md", "notes/outside")
        for href in ("../link.md", "../outside/passwd"):
            with self.subTest(href=href), self.assertRaisesRegex(site.SiteError, "symlink"):
                site.source_relative_link(
                    href, self.guide, self.manifest, site.public_repository_files()
                )

    def test_reference_links_images_and_html_cannot_bypass_public_target_check(self):
        for text in (
            "[Secret][target]\n\n[target]: ../private/private.json",
            "![Secret](../private/private.json)",
            '<a href="../private/private.json">Secret</a>',
        ):
            with self.subTest(text=text):
                self.write(self.guide["source"], text)
                problems, _ = site.check_links(self.manifest)
                self.assertEqual(len(problems), 1, problems)
                self.assertIn("missing, untracked, or ignored", problems[0])

    def test_url_encoded_file_names_and_external_links_are_preserved(self):
        self.write("notes/a file.md", "# Evidence")
        self.git("add", "notes/a file.md")
        public_files = site.public_repository_files()
        self.assertEqual(
            site.source_relative_link("../a%20file.md#evidence", self.guide, self.manifest, public_files),
            "https://github.com/spincyc/telos/blob/main/notes/a%20file.md#evidence",
        )
        for href in ("#usage", "?view=plain#usage", "https://example.org/a.md#b", "mailto:owner@example.org"):
            with self.subTest(href=href):
                self.assertEqual(
                    site.source_relative_link(href, self.guide, self.manifest, public_files), href
                )

    def test_existing_pages_keep_output_relative_markdown_links(self):
        self.guide.pop("source_relative_links")
        self.write(self.guide["source"], "[Runbook](../runbook/index.md#usage)")
        self.assertEqual(site.check_links(self.manifest), ([], set()))
        self.assertEqual(
            site.rewrite_page_links('<a href="../runbook/index.md#usage">Runbook</a>'),
            '<a href="../runbook/index.html#usage">Runbook</a>',
        )

    def test_manifest_requires_boolean_opt_in(self):
        self.guide["source_relative_links"] = "true"
        self.write("site/site.json", json.dumps(self.manifest))
        with self.assertRaisesRegex(site.SiteError, "source_relative_links must be a boolean"):
            site.load_manifest()

    def test_published_pages_reject_any_private_address(self):
        self.write("site/pages/notes/index.md", "Address: 10.1.31.4")
        problems = site.check_instance_leaks()
        self.assertTrue(any(
            "site/pages/notes/index.md:1: RFC 1918" in problem for problem in problems
        ), problems)


if __name__ == "__main__":
    unittest.main()
