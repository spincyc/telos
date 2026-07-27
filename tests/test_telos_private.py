import importlib.machinery
import importlib.util
from pathlib import Path
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "telos-private"


def run_tool(*args):
    return subprocess.run(
        ["python3", str(SCRIPT), *map(str, args)],
        text=True,
        capture_output=True,
    )


BOOTSTRAP_ANSWERS = (
    "--non-interactive",
    "--site-name",
    "example-home",
    "--primary-prefix",
    "10.1.0.0/16",
)


class PrivateBootstrapTests(unittest.TestCase):
    def test_bootstrap_is_safe_and_refuses_overwrite(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "private"
            result = run_tool(
                "bootstrap", "--target", target, "--git-init", *BOOTSTRAP_ANSWERS
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertTrue((target / ".git").is_dir())
            self.assertTrue((target / "inventory/users.yml").is_file())
            self.assertTrue((target / "secrets/README.md").is_file())
            self.assertIn(
                "name: example-home",
                (target / "inventory/network.yml").read_text(),
            )
            summary = (target / "review/redacted-summary.txt").read_text()
            self.assertIn("private IPv4 /16", summary)
            self.assertNotIn("example-home", summary)
            self.assertIn("SOPS", (target / "secrets/README.md").read_text())
            self.assertFalse((target / "secrets/plaintext").exists())
            self.assertEqual(
                subprocess.run(
                    ["git", "-C", str(target), "remote"],
                    text=True,
                    capture_output=True,
                    check=True,
                ).stdout,
                "",
            )
            again = run_tool("bootstrap", "--target", target, *BOOTSTRAP_ANSWERS)
            self.assertNotEqual(again.returncode, 0)
            self.assertIn("refusing to overwrite", again.stderr)

    def test_bootstrap_validates_project_name(self):
        with tempfile.TemporaryDirectory() as directory:
            result = run_tool(
                "bootstrap",
                "--target",
                Path(directory) / "private",
                "--project-name",
                "../bad",
                *BOOTSTRAP_ANSWERS,
            )
            self.assertNotEqual(result.returncode, 0)

    def test_bootstrap_validates_private_network_answers(self):
        with tempfile.TemporaryDirectory() as directory:
            result = run_tool(
                "bootstrap",
                "--target",
                Path(directory) / "private",
                "--non-interactive",
                "--site-name",
                "example-home",
                "--primary-prefix",
                "8.8.8.0/24",
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("private IPv4", result.stderr)

    def test_public_checker_uses_private_denylist(self):
        with tempfile.TemporaryDirectory() as directory:
            public = Path(directory) / "public"
            public.mkdir()
            subprocess.run(["git", "-C", str(public), "init", "-q"], check=True)
            (public / "guide.md").write_text("Example belongs to private-person.\n")
            subprocess.run(["git", "-C", str(public), "add", "guide.md"], check=True)
            denylist = Path(directory) / "denylist"
            denylist.write_text("private-person\n")
            result = run_tool(
                "check-public",
                "--public-root",
                public,
                "--identifiers",
                denylist,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("protected identifier", result.stderr)

    def test_preflight_accepts_no_remote_and_rejects_plaintext_key(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "private"
            self.assertEqual(
                run_tool(
                    "bootstrap",
                    "--target",
                    target,
                    "--git-init",
                    *BOOTSTRAP_ANSWERS,
                ).returncode,
                0,
            )
            result = run_tool("preflight", "--root", target)
            self.assertEqual(result.returncode, 0, result.stderr)
            key = target / "oops.key"
            key.write_text("not a real key")
            subprocess.run(["git", "-C", str(target), "add", "-f", "oops.key"], check=True)
            result = run_tool("preflight", "--root", target)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("unsafe tracked secret", result.stderr)

    def test_public_contract_example_validates_and_review_is_redacted(self):
        validator = ROOT / "src/homelab/private-contract/validate.py"
        example = ROOT / "src/homelab/private-contract/instance.example.json"
        result = subprocess.run(
            ["python3", str(validator), "--review", str(example)],
            text=True,
            capture_output=True,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('"dns_domain": "<configured>"', result.stdout)
        self.assertNotIn("lab.home.arpa", result.stdout)
        self.assertNotIn("example-site", result.stdout)


if __name__ == "__main__":
    unittest.main()
