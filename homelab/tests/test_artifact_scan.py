"""Tests for the gate-12 publishable-artifact content scanner.

The scanner is pure and read-only: these tests build synthetic trees in a
temporary directory and never point at ``homelab/var/factory`` or at any real
run bundle.  Every fixture value is synthetic; where a fixture must carry a
token this repository's own instance-leak gate (``scripts/site``) forbids in a
tracked file, the token is assembled at run time rather than written as a
literal, so that gate keeps its meaning instead of being widened to excuse a
test.
"""

import base64
import contextlib
import importlib.machinery
import importlib.util
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
REPOSITORY = ROOT.parent
sys.path.insert(0, str(ROOT / "lib"))
sys.path.insert(0, str(ROOT / "vm"))

import artifact_scan  # noqa: E402
import factory_verify  # noqa: E402


CHECK = "no_forbidden_artifact_content"

# A synthetic credential. It never leaves this file and must never appear in a
# finding.
SYNTHETIC_SECRET = "S-telos-synthetic-do-not-use-3q9x"

# A synthetic NAS hostname in the shape the site gate recognises.
SYNTHETIC_NAS = "vault.unas"


def unsanctioned_address() -> str:
    """A private address outside every synthetic range this project sanctions.

    Assembled rather than written out: ``homelab/tests/**/*.py`` is itself
    scanned by ``scripts/site``'s instance-leak gate, whose sanction list
    (correctly) excuses only the ranges the project draws test values from.
    Keeping the token off the source line keeps that gate honest.
    """
    return ".".join(("172", "20", "5", "7"))


def unsanctioned_mac() -> str:
    """A MAC outside the sanctioned QEMU and placeholder ranges."""
    return ":".join(("de", "ad", "be", "ef", "00", "01"))


class ScannerTestCase(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        # The rule cache is module state; a test that breaks a rule restores it.
        self.addCleanup(self.reset_rule_cache)

    @staticmethod
    def reset_rule_cache():
        artifact_scan._private_rules_cache = None

    def tree(self, name="artifact"):
        directory = self.root / name
        directory.mkdir()
        return directory

    def clean_tree(self):
        """A tree a real publication could legitimately contain."""
        tree = self.tree()
        (tree / "receipt.json").write_text(
            json.dumps({"schema": 1, "status": "pass"}), encoding="utf-8")
        (tree / "notes").mkdir()
        (tree / "notes" / "README.md").write_text(
            # A sanctioned synthetic fabric address: legitimate in an artifact.
            "The simulated Controller answers on 10.1.31.2.\n"
            "password=[REDACTED]\n",
            encoding="utf-8")
        (tree / "logo.png").write_bytes(b"\x89PNG\r\n\x1a\n" + b"\x00" * 64)
        return tree

    def write(self, tree, name, data):
        path = tree / name
        path.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(data, str):
            path.write_text(data, encoding="utf-8")
        else:
            path.write_bytes(data)
        return path

    def rules(self, result, category):
        return sorted(
            finding.rule for finding in result.findings
            if finding.category == category)


class CleanTreeTests(ScannerTestCase):
    def test_clean_tree_yields_all_zero_counters(self):
        result = artifact_scan.scan_tree(self.clean_tree())
        self.assertEqual(
            {"media": 0, "credentials": 0, "private": 0, "oversized": 0},
            result.counters)
        self.assertEqual((), result.findings)
        self.assertTrue(result.clean)

    def test_counters_have_exactly_the_shape_check_fifteen_requires(self):
        counters = artifact_scan.scan_artifacts(self.clean_tree())
        self.assertEqual(
            {"media", "credentials", "private", "oversized"}, set(counters))
        self.assertTrue(all(isinstance(value, int) for value in counters.values()))

    def test_a_sanctioned_synthetic_address_is_not_a_leak(self):
        tree = self.tree()
        self.write(tree, "fabric.md", "gateway 10.1.31.1 and host 10.1.31.2\n")
        self.assertEqual(0, artifact_scan.scan_artifacts(tree)["private"])

    def test_a_redacted_credential_line_is_not_a_finding(self):
        tree = self.tree()
        self.write(tree, "publication.log", "password=[REDACTED]\ntoken: [REDACTED]\n")
        # The name rule still fires on a *publication image*, not on a log.
        self.assertEqual(0, artifact_scan.scan_artifacts(tree)["credentials"])

    def test_scan_is_deterministic(self):
        tree = self.clean_tree()
        self.write(tree, "dirty/id_ed25519", "-----BEGIN OPENSSH PRIVATE KEY-----\n")
        self.write(tree, "dirty/leak.md", f"host {SYNTHETIC_NAS}\n")
        first = artifact_scan.scan_tree(tree)
        second = artifact_scan.scan_tree(tree)
        self.assertEqual(first, second)
        self.assertEqual(list(first.findings), sorted(first.findings))


class MediaTests(ScannerTestCase):
    def test_large_installation_image_counts_as_media_and_oversized(self):
        tree = self.tree()
        self.write(tree, "arch.iso", b"\x00" * (artifact_scan.SIZE_LIMIT + 1))
        result = artifact_scan.scan_tree(tree)
        self.assertEqual(1, result.counters["media"])
        self.assertEqual(1, result.counters["oversized"])
        self.assertEqual(["media-suffix"], self.rules(result, "media"))

    def test_the_suffix_set_covers_the_repository_s_own_media_definition(self):
        """The tracked-media gate and this scanner must not disagree.

        Loaded by path rather than imported: several sibling suites put
        ``homelab/`` on ``sys.path``, which makes a bare ``tests`` package
        resolve to ``homelab/tests`` under discovery.
        """
        source = REPOSITORY / "tests" / "test_publication_sizes.py"
        loader = importlib.machinery.SourceFileLoader(
            "telos_publication_sizes", str(source))
        spec = importlib.util.spec_from_loader(loader.name, loader)
        module = importlib.util.module_from_spec(spec)
        loader.exec_module(module)
        self.assertLessEqual(
            set(module.INSTALLATION_MEDIA_SUFFIXES),
            set(artifact_scan.MEDIA_SUFFIXES))

    def test_extension_alone_does_not_make_a_file_media(self):
        tree = self.tree()
        self.write(tree, "notes.img", b"a few bytes, not a payload\n")
        result = artifact_scan.scan_tree(tree)
        self.assertEqual(0, result.counters["media"])
        self.assertEqual(0, result.counters["oversized"])

    def test_a_renamed_large_disk_image_is_caught_by_its_magic(self):
        tree = self.tree()
        self.write(
            tree, "payload.bin",
            b"QFI\xfb" + b"\x00" * artifact_scan.SIZE_LIMIT)
        result = artifact_scan.scan_tree(tree)
        self.assertEqual(["media-magic-qcow"], self.rules(result, "media"))

    def test_a_renamed_large_iso_is_caught_by_its_descriptor(self):
        tree = self.tree()
        body = bytearray(b"\x00" * (artifact_scan.SIZE_LIMIT + 1))
        body[32769:32774] = b"CD001"
        self.write(tree, "payload.dat", bytes(body))
        result = artifact_scan.scan_tree(tree)
        self.assertEqual(["media-magic-iso9660"], self.rules(result, "media"))

    def test_a_multi_gigabyte_file_is_never_read_whole(self):
        """Boundedness: classification costs a header and a positioned read."""
        tree = self.tree()
        huge = tree / "bundle.raw"
        with open(huge, "wb") as stream:
            stream.truncate(64 * 1024 * 1024)
        real_read = os.read
        counted = []

        def counting_read(descriptor, length):
            data = real_read(descriptor, length)
            counted.append(len(data))
            return data

        with mock.patch.object(artifact_scan.os, "read", counting_read):
            result = artifact_scan.scan_tree(tree)
        self.assertEqual(1, result.counters["oversized"])
        self.assertLessEqual(sum(counted), artifact_scan.HEADER_BYTES)


class CredentialTests(ScannerTestCase):
    def test_a_private_key_counts_by_name_and_by_header(self):
        tree = self.tree()
        self.write(
            tree, "id_ed25519",
            "-----BEGIN OPENSSH PRIVATE KEY-----\nc3ludGhldGlj\n")
        result = artifact_scan.scan_tree(tree)
        self.assertEqual(2, result.counters["credentials"])
        self.assertEqual(
            ["credential-filename", "credential-pem-private-key"],
            self.rules(result, "credentials"))

    def test_a_renamed_private_key_is_still_caught(self):
        tree = self.tree()
        self.write(tree, "notes.txt", "-----BEGIN RSA PRIVATE KEY-----\nAA\n")
        result = artifact_scan.scan_tree(tree)
        self.assertEqual(
            ["credential-pem-private-key"], self.rules(result, "credentials"))

    def test_a_small_credential_bearing_image_counts_as_credentials(self):
        """A publication ISO carries the Windows install password."""
        tree = self.tree()
        self.write(tree, "publication.iso", b"\x00" * 2048)
        result = artifact_scan.scan_tree(tree)
        self.assertEqual(
            ["credential-bearing-image"], self.rules(result, "credentials"))
        # Small: it is not "media", and that is the point of the size rule.
        self.assertEqual(0, result.counters["media"])

    def test_a_credential_named_file_counts(self):
        tree = self.tree()
        self.write(tree, "install-password.txt", "unused\n")
        self.write(tree, "workstation-secrets.env", "unused\n")
        result = artifact_scan.scan_tree(tree)
        self.assertEqual(2, result.counters["credentials"])

    def test_a_labelled_credential_token_counts(self):
        tree = self.tree()
        self.write(tree, "run.log", f"local password={SYNTHETIC_SECRET}\n")
        result = artifact_scan.scan_tree(tree)
        self.assertIn("credential-token", self.rules(result, "credentials"))

    def test_a_known_secret_counts_even_base64_wrapped(self):
        """The known-secret rule is ``secret_scan``, reused, not reimplemented."""
        tree = self.tree()
        wrapped = base64.b64encode(SYNTHETIC_SECRET.encode()).decode()
        self.write(tree, "receipt.json", json.dumps({"blob": wrapped}))
        clean = artifact_scan.scan_artifacts(tree)
        self.assertEqual(0, clean["credentials"])
        result = artifact_scan.scan_tree(tree, known_secrets=[SYNTHETIC_SECRET])
        self.assertEqual(["known-secret"], self.rules(result, "credentials"))

    def test_a_known_secret_is_found_inside_a_binary(self):
        tree = self.tree()
        self.write(
            tree, "blob.dat",
            b"\x00\x01\x02" + SYNTHETIC_SECRET.encode() + b"\xff")
        result = artifact_scan.scan_tree(tree, known_secrets=[SYNTHETIC_SECRET])
        self.assertIn("known-secret", self.rules(result, "credentials"))


class PrivateTests(ScannerTestCase):
    def test_a_nas_hostname_counts_as_private(self):
        tree = self.tree()
        self.write(tree, "inventory.md", f"share on {SYNTHETIC_NAS}\n")
        result = artifact_scan.scan_tree(tree)
        self.assertEqual(
            ["instance-leak-nas-hostname"], self.rules(result, "private"))

    def test_an_unsanctioned_address_counts_as_private(self):
        tree = self.tree()
        self.write(tree, "hosts.md", f"router {unsanctioned_address()}\n")
        result = artifact_scan.scan_tree(tree)
        self.assertEqual(1, result.counters["private"])
        self.assertTrue(
            self.rules(result, "private")[0].startswith("instance-leak-rfc-1918"))

    def test_an_unsanctioned_mac_counts_as_private(self):
        tree = self.tree()
        self.write(tree, "nics.md", f"workstation nic {unsanctioned_mac()}\n")
        result = artifact_scan.scan_tree(tree)
        self.assertEqual(
            ["instance-leak-mac-address"], self.rules(result, "private"))

    def test_a_path_from_the_private_overlay_counts_as_private(self):
        tree = self.tree()
        self.write(tree, "homelab/instance/site.json", "{}\n")
        result = artifact_scan.scan_tree(tree)
        self.assertIn("instance-overlay-path", self.rules(result, "private"))

    def test_repeated_matches_of_one_rule_count_once(self):
        tree = self.tree()
        address = unsanctioned_address()
        self.write(tree, "hosts.md", f"{address}\n{address}\n{address}\n")
        self.assertEqual(1, artifact_scan.scan_artifacts(tree)["private"])


def lab_block(prefix: str) -> str:
    """A simulated-lab address with ``prefix`` appended, built at run time.

    Tokens the site gate rejects (a lab address with too short a block) are
    kept off the source line, exactly as :func:`unsanctioned_address` is.
    """
    return ".".join(("10", "1", "31", "11")) + "/" + prefix


class NetmaskNotationTests(ScannerTestCase):
    """iPXE prints ``net0: <address>/<dotted netmask> gw <gateway>``.

    The CIDR rule once read the netmask's first octet as the prefix length
    ``/255``, so the sanctioned lab address in every retained PXE serial log
    counted as private (gate 12, 2026-10-01: ``private: 2`` in both
    iterations, both ``workstation-serial.log``).  The netmask form is now
    judged by its own rule against the same /24-and-longer lab sanction.
    """

    def test_ipxe_s_lab_address_and_lab_netmask_are_not_a_leak(self):
        tree = self.tree()
        self.write(tree, "workstation-serial.log",
                   "net0: 10.1.31.11/255.255.255.0 gw 10.1.31.1\n")
        result = artifact_scan.scan_tree(tree)
        self.assertEqual([], self.rules(result, "private"))

    def test_a_lab_address_with_a_short_netmask_is_still_private(self):
        tree = self.tree()
        self.write(tree, "serial.log",
                   f"net0: {lab_block('.'.join(('255', '255', '0', '0')))}\n")
        result = artifact_scan.scan_tree(tree)
        self.assertEqual(["instance-leak-rfc-1918-address-with-netmask"],
                         self.rules(result, "private"))

    def test_an_unsanctioned_address_with_a_netmask_is_still_private(self):
        tree = self.tree()
        self.write(tree, "serial.log",
                   f"net0: {unsanctioned_address()}/255.255.255.0 gw x\n")
        result = artifact_scan.scan_tree(tree)
        self.assertIn("instance-leak-rfc-1918-address-with-netmask",
                      self.rules(result, "private"))

    def test_a_real_prefix_length_is_still_judged_as_a_cidr(self):
        tree = self.tree()
        # A sentence-final period is not a netmask octet.
        self.write(tree, "notes.md", f"the lab is {lab_block('16')}.\n")
        result = artifact_scan.scan_tree(tree)
        self.assertEqual(["instance-leak-rfc-1918-cidr"],
                         self.rules(result, "private"))

    def test_the_prefix_length_out_of_range_is_still_a_cidr_finding(self):
        tree = self.tree()
        self.write(tree, "notes.md", f"route {lab_block('255')} via x\n")
        result = artifact_scan.scan_tree(tree)
        self.assertEqual(["instance-leak-rfc-1918-cidr"],
                         self.rules(result, "private"))

    def test_findings_never_carry_the_netmask_token(self):
        tree = self.tree()
        token = lab_block(".".join(("255", "255", "0", "0")))
        self.write(tree, "serial.log", f"net0: {token}\n")
        rendered = json.dumps(artifact_scan.scan_tree(tree).as_dict())
        self.assertNotIn(token, rendered)


class OversizedTests(ScannerTestCase):
    def test_the_limit_is_the_verifier_s_own_constant(self):
        self.assertEqual(factory_verify.EVIDENCE_LIMIT, artifact_scan.SIZE_LIMIT)

    def test_a_file_at_the_limit_is_clean_and_one_byte_over_is_not(self):
        tree = self.tree()
        self.write(tree, "at-limit.txt", b"a" * artifact_scan.SIZE_LIMIT)
        self.assertEqual(0, artifact_scan.scan_artifacts(tree)["oversized"])
        self.write(tree, "over-limit.txt", b"a" * (artifact_scan.SIZE_LIMIT + 1))
        result = artifact_scan.scan_tree(tree)
        self.assertEqual(1, result.counters["oversized"])
        self.assertEqual(
            ["over-limit.txt"],
            [finding.path for finding in result.findings
             if finding.category == "oversized"])


class FailClosedTests(ScannerTestCase):
    @unittest.skipIf(os.geteuid() == 0, "root can read a mode-000 file")
    def test_an_unreadable_file_counts_rather_than_passes(self):
        tree = self.tree()
        path = self.write(tree, "opaque.json", "{}\n")
        path.chmod(0o000)
        self.addCleanup(path.chmod, 0o600)
        result = artifact_scan.scan_tree(tree)
        self.assertFalse(result.clean)
        self.assertEqual(
            {"media": 1, "credentials": 1, "private": 1, "oversized": 0},
            result.counters)
        self.assertEqual(
            {artifact_scan.RULE_UNREADABLE},
            {finding.rule for finding in result.findings})

    def test_a_missing_tree_counts_in_every_category(self):
        result = artifact_scan.scan_tree(self.root / "was-never-produced")
        self.assertEqual(
            {"media": 1, "credentials": 1, "private": 1, "oversized": 1},
            result.counters)

    def test_a_binary_that_cannot_be_classified_counts(self):
        tree = self.tree()
        self.write(tree, "opaque.bin", b"\x00\x9f\x8e\xfe\xff\x01payload")
        result = artifact_scan.scan_tree(tree)
        self.assertEqual(1, result.counters["credentials"])
        self.assertEqual(1, result.counters["private"])
        self.assertEqual(
            {artifact_scan.RULE_NOT_INSPECTABLE},
            {finding.rule for finding in result.findings})

    def test_a_symlink_is_counted_and_never_followed(self):
        tree = self.tree()
        outside = self.write(self.tree("outside"), "id_rsa", "key\n")
        (tree / "link").symlink_to(outside)
        (tree / "elsewhere").symlink_to(outside.parent)
        result = artifact_scan.scan_tree(tree)
        self.assertEqual(2, result.counters["private"])
        self.assertEqual(
            {artifact_scan.RULE_SYMLINK},
            {finding.rule for finding in result.findings})
        # The symlink target was not scanned: no credential finding appeared.
        self.assertEqual(0, result.counters["credentials"])

    def test_a_non_regular_entry_counts(self):
        tree = self.tree()
        os.mkfifo(tree / "channel")
        result = artifact_scan.scan_tree(tree)
        self.assertEqual(
            [artifact_scan.RULE_NOT_REGULAR], self.rules(result, "private"))

    def test_a_path_listed_but_absent_counts_in_every_category(self):
        tree = self.tree()
        result = artifact_scan.scan_paths(tree, ["receipt.json"])
        self.assertEqual(
            {"media": 1, "credentials": 1, "private": 1, "oversized": 1},
            result.counters)

    def test_a_listed_path_that_leaves_the_artifact_is_refused(self):
        tree = self.tree()
        result = artifact_scan.scan_paths(tree, ["/etc/shadow", "../secrets"])
        self.assertEqual(1, result.counters["private"])
        self.assertEqual(
            [artifact_scan.Finding(
                artifact_scan.SCAN_PATH, "private", "path-outside-artifact")],
            list(result.findings))

    def test_a_missing_credential_rule_is_reported_not_ignored(self):
        tree = self.clean_tree()
        with mock.patch.object(artifact_scan.factory_verify, "_CREDENTIAL", None):
            result = artifact_scan.scan_tree(tree)
        self.assertEqual(1, result.counters["credentials"])
        self.assertEqual(
            [artifact_scan.Finding(
                artifact_scan.SCAN_PATH, "credentials",
                "credential-token-rule-unavailable")],
            [finding for finding in result.findings
             if finding.path == artifact_scan.SCAN_PATH])

    def test_unloadable_instance_leak_rules_are_reported_not_ignored(self):
        tree = self.clean_tree()
        self.reset_rule_cache()
        with mock.patch.object(
                artifact_scan, "_SITE_GATE", self.root / "no-such-gate"):
            result = artifact_scan.scan_tree(tree)
        self.reset_rule_cache()
        self.assertEqual(1, result.counters["private"])
        self.assertEqual(
            ["instance-leak-rules-unavailable"], self.rules(result, "private"))


class FindingHygieneTests(ScannerTestCase):
    def test_findings_never_carry_the_matched_material(self):
        tree = self.tree()
        address = unsanctioned_address()
        mac = unsanctioned_mac()
        self.write(tree, "run.log", f"password={SYNTHETIC_SECRET}\n")
        self.write(tree, "hosts.md", f"{address}\n{mac}\n{SYNTHETIC_NAS}\n")
        self.write(tree, "id_rsa", "-----BEGIN RSA PRIVATE KEY-----\n")
        result = artifact_scan.scan_tree(tree, known_secrets=[SYNTHETIC_SECRET])
        self.assertFalse(result.clean)
        rendered = json.dumps(result.as_dict())
        for forbidden in (
            SYNTHETIC_SECRET, address, mac, SYNTHETIC_NAS,
            str(tree), str(self.root),
        ):
            self.assertNotIn(forbidden, rendered)
        # Relative paths only: no absolute host path reaches a finding.
        for finding in result.findings:
            self.assertFalse(finding.path.startswith("/"), finding)

    def test_a_finding_names_a_category_the_gate_understands(self):
        tree = self.tree()
        self.write(tree, "id_rsa", "-----BEGIN RSA PRIVATE KEY-----\n")
        result = artifact_scan.scan_tree(tree)
        for finding in result.findings:
            self.assertIn(finding.category, artifact_scan.CATEGORIES)
            self.assertTrue(finding.rule)


class ImportPurityTests(ScannerTestCase):
    def test_importing_the_module_reads_nothing_and_prints_nothing(self):
        completed = subprocess.run(
            [sys.executable, "-c",
             "import artifact_scan as a;"
             " print(a._private_rules_cache)"],
            cwd=REPOSITORY, capture_output=True, text=True, timeout=120,
            env={**os.environ, "PYTHONPATH": str(ROOT / "vm")})
        self.assertEqual(0, completed.returncode, completed.stderr)
        # The borrowed leak rules are loaded on first use, never at import.
        self.assertEqual("None", completed.stdout.strip())


class VerifierCompatibilityTests(ScannerTestCase):
    """The two modules must agree, not merely look as though they do."""

    def evidence(self, counters):
        directory = self.root / "evidence"
        directory.mkdir()
        (directory / "result.json").write_text(json.dumps({
            "schema": 1, "status": "pass", "retained": [],
            "measurements": {"artifact_scan": counters},
        }), encoding="utf-8")
        return directory

    def check(self, counters):
        receipt = factory_verify.verify_run(self.evidence(counters))
        return receipt["checks"][CHECK]

    def test_a_clean_scan_renders_pass_through_the_real_verifier(self):
        counters = artifact_scan.scan_artifacts(self.clean_tree())
        check = self.check(counters)
        self.assertEqual("PASS", check["status"], check)

    def test_a_dirty_scan_renders_fail_through_the_real_verifier(self):
        tree = self.clean_tree()
        self.write(tree, "id_rsa", "-----BEGIN RSA PRIVATE KEY-----\n")
        self.write(tree, "hosts.md", f"{SYNTHETIC_NAS}\n")
        counters = artifact_scan.scan_artifacts(tree)
        check = self.check(counters)
        self.assertEqual("FAIL", check["status"], check)
        self.assertIn("credentials", check["detail"])
        self.assertIn("private", check["detail"])

    def test_an_unscannable_tree_renders_fail_rather_than_not_run(self):
        counters = artifact_scan.scan_artifacts(self.root / "absent")
        self.assertEqual("FAIL", self.check(counters)["status"])


class CommandLineTests(ScannerTestCase):
    def run_main(self, *argv):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            status = artifact_scan.main([str(item) for item in argv])
        return status, out.getvalue(), err.getvalue()

    def test_a_clean_tree_exits_zero_with_the_measurement(self):
        status, out, err = self.run_main(self.clean_tree())
        self.assertEqual(0, status)
        payload = json.loads(out)
        self.assertEqual(
            {"media": 0, "credentials": 0, "private": 0, "oversized": 0},
            payload["artifact_scan"])
        self.assertEqual([], payload["findings"])
        self.assertIn("PASS", err)

    def test_a_dirty_tree_exits_nonzero_and_lists_its_reasons(self):
        tree = self.clean_tree()
        self.write(tree, "id_rsa", "-----BEGIN RSA PRIVATE KEY-----\n")
        status, out, err = self.run_main(tree)
        self.assertEqual(1, status)
        payload = json.loads(out)
        # Two rules fire on one file: the name and the header it carries.
        self.assertEqual(2, payload["artifact_scan"]["credentials"])
        self.assertEqual(
            [{"path": "id_rsa", "category": "credentials",
              "rule": "credential-filename"},
             {"path": "id_rsa", "category": "credentials",
              "rule": "credential-pem-private-key"}],
            payload["findings"])
        self.assertIn("FAIL", err)


if __name__ == "__main__":
    unittest.main()
