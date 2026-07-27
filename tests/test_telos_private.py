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
    def test_onboard_builds_valid_private_contract(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "private"
            result = run_tool(
                "onboard", "--target", target, "--git-init", "--non-interactive",
                "--site-name", "sample-home", "--timezone", "Etc/UTC",
                "--identity-domain", "directory.home.arpa",
                "--netbios-name", "SAMPLE", "--primary-prefix", "10.7.0.0/24",
                "--managed-prefix", "10.7.0.0/24",
                "--dhcp-first", "10.7.0.100", "--dhcp-last", "10.7.0.199",
                "--network-id", "managed-clients", "--vlan", "20",
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            instance = (target / "homelab/instance.json").read_text()
            self.assertIn('"dns_domain": "directory.home.arpa"', instance)
            self.assertIn('"gateway": "10.7.0.1"', instance)
            summary = (target / "review/contract-summary.json").read_text()
            self.assertIn('"dns_domain": "<configured>"', summary)
            self.assertNotIn("directory.home.arpa", summary)
            self.assertIn("contract validated", result.stdout)

    def test_onboard_prompts_for_one_value_per_question(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "private"
            result = subprocess.run(
                ["python3", str(SCRIPT), "onboard", "--target", str(target), "--git-init"],
                input="\n\n\n\n\n\n\n\n\n\n\n\n\n",
                text=True,
                capture_output=True,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            questions = (
                "Short private site label",
                "IANA timezone",
                "Private identity domain",
                "NetBIOS name",
                "Bootstrap domain-controller FQDN",
                "Permanent domain-controller FQDN",
                "PXE service FQDN",
                "Primary RFC1918 allocation root",
                "Managed-client IPv4 subnet",
                "DHCP pool first address",
                "DHCP pool last address",
                "Managed-client network ID",
                "Managed-client VLAN",
            )
            offsets = [result.stdout.index(question) for question in questions]
            self.assertEqual(offsets, sorted(offsets))
            self.assertTrue(all(result.stdout.count(question) == 1 for question in questions))
            self.assertTrue((target / "homelab/instance.json").is_file())
            self.assertEqual(
                subprocess.run(
                    ["git", "-C", str(target), "branch", "--show-current"],
                    text=True, capture_output=True, check=True,
                ).stdout.strip(),
                "main",
            )

    def test_onboard_rejects_child_outside_allocation_root(self):
        with tempfile.TemporaryDirectory() as directory:
            result = run_tool(
                "onboard", "--target", Path(directory) / "private",
                "--non-interactive", "--site-name", "sample-home",
                "--timezone", "Etc/UTC", "--identity-domain", "directory.home.arpa",
                "--netbios-name", "SAMPLE", "--primary-prefix", "10.7.0.0/16",
                "--managed-prefix", "10.8.1.0/24",
                "--dhcp-first", "10.8.1.100", "--dhcp-last", "10.8.1.199",
                "--network-id", "managed-clients", "--vlan", "20",
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("contained", result.stderr)

    def test_onboard_rejects_unbounded_or_invalid_dhcp_pool(self):
        common = (
            "onboard", "--non-interactive", "--site-name", "sample-home",
            "--timezone", "Etc/UTC", "--identity-domain", "directory.home.arpa",
            "--netbios-name", "SAMPLE", "--primary-prefix", "10.7.0.0/16",
            "--managed-prefix", "10.7.2.0/23", "--dhcp-first", "10.7.2.1",
            "--dhcp-last", "10.7.2.200", "--network-id", "managed-clients",
            "--vlan", "20",
        )
        with tempfile.TemporaryDirectory() as directory:
            result = run_tool(*common, "--target", Path(directory) / "private")
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("between /24 and /28", result.stderr)
        with tempfile.TemporaryDirectory() as directory:
            args = list(common)
            args[args.index("10.7.2.0/23")] = "10.7.2.0/24"
            args[args.index("10.7.2.1")] = "10.7.3.100"
            result = run_tool(*args, "--target", Path(directory) / "private")
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("DHCP bounds", result.stderr)

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

    def test_bootstrap_refuses_private_data_inside_public_tree(self):
        target = ROOT / "private-do-not-create"
        result = run_tool("bootstrap", "--target", target, *BOOTSTRAP_ANSWERS)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("must be a sibling", result.stderr)
        self.assertFalse(target.exists())

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

    def test_public_checker_ignores_only_secret_markers_in_known_fixtures(self):
        with tempfile.TemporaryDirectory() as directory:
            public = Path(directory) / "public"
            fixture = public / "scripts" / "telos-private"
            fixture.parent.mkdir(parents=True)
            fixture.write_text('"BEGIN PRIVATE KEY"\n')
            subprocess.run(["git", "-C", str(public), "init", "-q"], check=True)
            subprocess.run(["git", "-C", str(public), "add", "."], check=True)
            denylist = Path(directory) / "denylist"
            denylist.write_text("protected-person\n")

            result = run_tool(
                "check-public",
                "--public-root",
                public,
                "--identifiers",
                denylist,
            )
            self.assertEqual(result.returncode, 0, result.stderr)

            fixture.write_text('"BEGIN PRIVATE KEY"\nprotected-person\n')
            subprocess.run(["git", "-C", str(public), "add", "."], check=True)
            result = run_tool(
                "check-public",
                "--public-root",
                public,
                "--identifiers",
                denylist,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("protected identifier", result.stderr)

    def test_public_checker_rejects_secret_marker_outside_fixture(self):
        with tempfile.TemporaryDirectory() as directory:
            public = Path(directory) / "public"
            public.mkdir()
            subprocess.run(["git", "-C", str(public), "init", "-q"], check=True)
            (public / "guide.md").write_text("BEGIN PRIVATE KEY\n")
            subprocess.run(["git", "-C", str(public), "add", "."], check=True)
            denylist = Path(directory) / "denylist"
            denylist.write_text("# no private identifiers\n")

            result = run_tool(
                "check-public",
                "--public-root",
                public,
                "--identifiers",
                denylist,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("secret marker", result.stderr)

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
