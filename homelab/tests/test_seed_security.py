"""Security and integrity contract for the offline Controller seed."""

from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch


MODULE_PATH = Path(__file__).parents[1] / "seed" / "build.py"
SPEC = importlib.util.spec_from_file_location("seed_security_build", MODULE_PATH)
assert SPEC and SPEC.loader
seed = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(seed)


class SeedSourcePrivacyTests(unittest.TestCase):
    def test_rejects_private_and_secret_tracked_paths(self) -> None:
        rejected = (
            "homelab/instance/site.json",
            "secrets/controller.yaml",
            "keys/controller.pem",
            "telos-private/inventory/hosts.yml",
        )
        clean_scan = subprocess.CompletedProcess([], 1, "", "")
        for path in rejected:
            with self.subTest(path=path):
                with patch.object(seed, "git_text", return_value=path), patch.object(
                    seed.subprocess, "run", return_value=clean_scan
                ):
                    with self.assertRaisesRegex(ValueError, "private-looking"):
                        seed.validate_public_source()

    def test_rejects_private_key_material_in_otherwise_public_path(self) -> None:
        finding = subprocess.CompletedProcess(
            [], 0, "HEAD:docs/example.txt\n", ""
        )
        with patch.object(
            seed, "git_text", return_value="docs/example.txt"
        ), patch.object(seed.subprocess, "run", return_value=finding):
            with self.assertRaisesRegex(ValueError, "private-key material"):
                seed.validate_public_source()


class SeedManifestTests(unittest.TestCase):
    def test_receipt_has_exact_coverage_sizes_and_hashes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            stage = Path(directory)
            payloads = {
                "install-controller-deps": b"installer",
                "packages.txt": b"base\n",
                "pacman.conf": b"SigLevel = Required\n",
                "packages/base.pkg.tar.zst": b"package",
                "packages/base.pkg.tar.zst.sig": b"signature",
                "packages/telos.db.tar.gz": b"database",
                "source/telos.tar.gz": b"source",
            }
            for relative, content in payloads.items():
                target = stage / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(content)

            seed.write_receipt(stage, ["base"], {"commit": "a" * 40})
            receipt = json.loads((stage / "receipt.json").read_text())
            entries = {
                entry["path"]: entry for entry in receipt["payload_files"]
            }

            self.assertEqual(set(entries), set(payloads))
            for relative, content in payloads.items():
                self.assertEqual(entries[relative]["bytes"], len(content))
                self.assertEqual(
                    entries[relative]["sha256"],
                    hashlib.sha256(content).hexdigest(),
                )
            self.assertNotIn("receipt.json", entries)


class SeedSignatureTests(unittest.TestCase):
    def test_build_and_install_require_package_signatures(self) -> None:
        config = seed.PACMAN_CONFIG.read_text(encoding="utf-8")
        self.assertRegex(
            config,
            r"(?m)^SigLevel\s*=\s*Required\s+DatabaseOptional\s*$",
        )
        self.assertRegex(config, r"(?m)^LocalFileSigLevel\s*=\s*Required\s*$")

        plan = seed.command_plan(
            ["base"], Path("/temporary/stage"), Path("/temporary/seed.iso")
        )
        self.assertEqual(
            plan[0][plan[0].index("--config") + 1],
            str(seed.PACMAN_CONFIG),
        )

        installer = MODULE_PATH.with_name("install-controller-deps").read_text(
            encoding="utf-8"
        )
        self.assertIn('pacman --config "$seed_root/pacman.conf" -U', installer)
        self.assertIn(
            'if [ ! -f "$archive.sig" ]',
            installer,
        )


if __name__ == "__main__":
    unittest.main()
