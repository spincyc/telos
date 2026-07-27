"""Contracts for the honest, locally supportable factory Make targets."""

from pathlib import Path
import re
import unittest


ROOT = Path(__file__).resolve().parents[2]
MAKEFILE = (ROOT / "Makefile").read_text(encoding="utf-8")


def recipe(target: str) -> str:
    match = re.search(
        rf"^{re.escape(target)}(?:\s*:[^\n]*)?\n"
        rf"(?P<body>(?:\t[^\n]*\n|#[^\n]*\n|\n)*)",
        MAKEFILE,
        re.MULTILINE,
    )
    if not match:
        raise AssertionError(f"missing Make target: {target}")
    return match.group("body")


class FactoryMakeTargetTests(unittest.TestCase):
    def test_supportable_targets_are_phony(self):
        phony = re.search(
            r"^\.PHONY:(?P<body>.*?)(?=^\S|\Z)",
            MAKEFILE,
            re.MULTILINE | re.DOTALL,
        )
        self.assertIsNotNone(phony)
        for target in (
            "homelab-factory-deps",
            "homelab-factory-media",
            "homelab-factory-cache-seal",
            "homelab-factory-offline-check",
            "homelab-factory-controller-bundle",
            "homelab-factory-pxe",
        ):
            self.assertIn(target, phony.group("body"))

    def test_offline_check_cannot_invoke_acquisition(self):
        declaration = re.search(
            r"^homelab-factory-offline-check:(.*)$", MAKEFILE, re.MULTILINE)
        self.assertIsNotNone(declaration)
        self.assertIn("homelab-factory-cache-seal", declaration.group(1))
        text = recipe("homelab-factory-offline-check")
        for forbidden in ("homelab-media", "fetch-", "curl", "wget", "git "):
            self.assertNotIn(forbidden, text)

    def test_cache_seal_verifies_all_three_media_inputs(self):
        text = recipe("homelab-factory-cache-seal")
        self.assertIn("ARCH_ISO", text)
        self.assertIn("homelab-verify-windows", text)
        self.assertIn("WIMBOOT", text)
        self.assertIn("sha256sum", text)

    def test_controller_bundle_is_dry_run_by_default(self):
        text = recipe("homelab-factory-controller-bundle")
        self.assertIn("APPLY", text)
        self.assertIn("--print-guest-command", text)
        self.assertIn("--output", text)

    def test_pxe_aggregate_requires_local_source_trees(self):
        text = recipe("homelab-factory-pxe")
        self.assertIn("CONTROLLER_SOURCE", text)
        self.assertIn("ARCH_SOURCE", text)
        self.assertIn("WINDOWS_ISO_CACHE", text)
        self.assertNotIn("fetch-", text)


if __name__ == "__main__":
    unittest.main()
