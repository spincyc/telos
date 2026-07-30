import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

from homelab.lib.image_promotion_cli import main
from homelab.tests.test_image_promotion_gate import receipt, registry


class ImagePromotionCliTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        base = Path(self.temporary.name)
        self.root = base / "root"
        (self.root / "var/lib/pacman/local/alpha-1.2-3").mkdir(parents=True)
        (self.root / "usr/bin").mkdir(parents=True)
        database = self.root / "var/lib/pacman/local/alpha-1.2-3"
        (database / "desc").write_text(
            "%NAME%\nalpha\n\n%VERSION%\n1.2-3\n\n", encoding="utf-8")
        (database / "files").write_text(
            "%FILES%\nusr/bin/alpha\n\n", encoding="utf-8")
        executable = self.root / "usr/bin/alpha"
        executable.write_bytes(b"binary")
        executable.chmod(0o755)
        self.registry_path = base / "package-contract.json"
        self.registry_path.write_text(json.dumps(registry()), encoding="utf-8")
        self.receipt_path = base / "receipt.json"
        self.receipt_path.write_text(json.dumps(receipt()), encoding="utf-8")
        self.evidence_path = base / "evidence.json"

    def tearDown(self):
        self.temporary.cleanup()

    def run_main(self, *extra):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = main([
                "--profile", "workstation-install",
                "--root", str(self.root),
                "--receipt", str(self.receipt_path),
                "--registry", str(self.registry_path),
                *extra,
            ])
        return code, out.getvalue(), err.getvalue()

    def test_prints_sorted_evidence_document(self):
        code, out, err = self.run_main()
        self.assertEqual((code, err), (0, ""))
        document = json.loads(out)
        self.assertEqual(document["kind"], "image-promotion-static-evidence")
        self.assertEqual(document["profile"], "workstation-install")
        self.assertEqual(
            document["accounted_installed"],
            [{"name": "alpha", "version": "1.2-3"}])
        self.assertEqual(out, json.dumps(document, sort_keys=True) + "\n")

    def test_writes_evidence_file_when_requested(self):
        code, out, err = self.run_main("--evidence", str(self.evidence_path))
        self.assertEqual((code, err), (0, ""))
        self.assertIn(str(self.evidence_path), out)
        written = json.loads(self.evidence_path.read_text(encoding="utf-8"))
        self.assertEqual(written["seed_source_commit"], "a" * 40)

    def test_reports_stage_attributed_failure_without_evidence(self):
        self.receipt_path.write_text("{}", encoding="utf-8")
        code, out, err = self.run_main("--evidence", str(self.evidence_path))
        self.assertEqual(code, 1)
        self.assertEqual(out, "")
        self.assertIn("image promotion gate: seed-closure:", err)
        self.assertFalse(self.evidence_path.exists())

    def test_reports_absent_root(self):
        self.root.rename(self.root.with_name("moved"))
        code, _, err = self.run_main()
        self.assertEqual(code, 1)
        self.assertIn("root-audit:", err)

    def test_rejects_unknown_profile(self):
        with self.assertRaises(SystemExit) as raised:
            with contextlib.redirect_stderr(io.StringIO()):
                main([
                    "--profile", "rogue",
                    "--root", str(self.root),
                    "--receipt", str(self.receipt_path),
                ])
        self.assertEqual(raised.exception.code, 2)


if __name__ == "__main__":
    unittest.main()
