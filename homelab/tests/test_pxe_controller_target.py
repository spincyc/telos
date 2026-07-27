"""Tests for the offline, versioned Controller PXE target."""

import importlib.util
import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "lib"))
import pxe_release  # noqa: E402

MODULE = ROOT / "pxe/targets/controller.py"
SPEC = importlib.util.spec_from_file_location("controller_target", MODULE)
controller = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(controller)


class ControllerTargetCase(unittest.TestCase):
    def setUp(self):
        self.temp = Path(tempfile.mkdtemp(prefix="controller-target-test-"))
        self.addCleanup(shutil.rmtree, self.temp, ignore_errors=True)
        self.source = self.temp / "mkarchiso"
        for relative in controller.REQUIRED_PAYLOADS:
            path = self.source / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(relative.encode())
        self.releases = self.temp / "releases"

    def stage(self):
        return controller.stage(
            self.source, self.releases, "20260727.001",
            "http://boot.example.test/controller/20260727.001")


class TestBuild(ControllerTargetCase):
    def test_stages_the_common_target_contract(self):
        release = self.stage()
        metadata = json.loads((release / "target.json").read_text())
        self.assertEqual(metadata, {
            "schema": 1,
            "id": "controller",
            "kind": "archiso-netboot",
            "version": "20260727.001",
            "entrypoints": ["boot.ipxe"],
        })
        self.assertEqual(controller.verify(release), [])
        self.assertEqual(pxe_release.verify(release), [])

    def test_boots_only_the_versioned_payload(self):
        script = (self.stage() / "boot.ipxe").read_text()
        self.assertIn(
            "http://boot.example.test/controller/20260727.001", script)
        self.assertIn("/payload/arch/boot/x86_64/vmlinuz-linux", script)
        self.assertNotIn("menu", script.lower())
        self.assertIn("shell", script)

    def test_manifest_covers_metadata_entrypoint_and_payload(self):
        release = self.stage()
        names = set(json.loads(
            (release / "release.json").read_text())["artifacts"])
        self.assertIn("target.json", names)
        self.assertIn("boot.ipxe", names)
        self.assertIn("payload/arch/x86_64/airootfs.sfs", names)

    def test_existing_release_is_never_replaced(self):
        self.stage()
        with self.assertRaises(controller.TargetError):
            self.stage()

    def test_missing_root_filesystem_stops_staging(self):
        (self.source / "arch/x86_64/airootfs.sfs").unlink()
        with self.assertRaisesRegex(controller.TargetError, "required"):
            self.stage()

    def test_version_must_be_document_style(self):
        with self.assertRaisesRegex(controller.TargetError, "YYYYMMDD"):
            controller.stage(self.source, self.releases, "latest",
                             "http://boot.example.test/controller/latest")

    def test_non_http_base_url_is_refused(self):
        with self.assertRaisesRegex(controller.TargetError, "http"):
            controller.stage(self.source, self.releases, "20260727.001",
                             "file:///tmp/controller")

    def test_symlink_in_source_is_refused(self):
        (self.source / "arch/link").symlink_to("x86_64/airootfs.sfs")
        with self.assertRaisesRegex(controller.TargetError, "symlink"):
            self.stage()


class TestVerify(ControllerTargetCase):
    def test_altered_payload_is_rejected(self):
        release = self.stage()
        (release / "payload/arch/x86_64/airootfs.sfs").write_bytes(b"changed")
        self.assertTrue(any("checksum mismatch" in problem
                            for problem in controller.verify(release)))

    def test_unlisted_file_is_rejected(self):
        release = self.stage()
        (release / "surprise").write_text("not in manifest")
        self.assertTrue(any("unlisted" in problem
                            for problem in controller.verify(release)))

    def test_wrong_directory_version_is_rejected(self):
        release = self.stage()
        renamed = release.with_name("latest")
        release.rename(renamed)
        problems = controller.verify(renamed)
        self.assertTrue(any("YYYYMMDD" in problem for problem in problems))
        self.assertTrue(any("target contract" in problem for problem in problems))


if __name__ == "__main__":
    unittest.main()
