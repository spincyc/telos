"""Tests for the offline, versioned Controller PXE target."""

import importlib.util
import hashlib
import json
import os
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
        self.root_image = self.source / controller.ROOT_IMAGES[0]
        self.root_image.parent.mkdir(parents=True, exist_ok=True)
        self.root_image.write_bytes(b"root image")
        self.write_root_checksum()
        self.releases = self.temp / "releases"

    def write_root_checksum(self):
        digest = hashlib.sha512(self.root_image.read_bytes()).hexdigest()
        (self.root_image.parent / "airootfs.sha512").write_text(
            f"{digest}  {self.root_image.name}\n")

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
            "source": {
                "kind": "mkarchiso-netboot",
                "artifacts": {
                    relative: {
                        "sha256": controller.sha256(self.source / relative),
                        "size": (self.source / relative).stat().st_size,
                    }
                    for relative in (
                        *controller.REQUIRED_PAYLOADS,
                        controller.ROOT_IMAGES[0],
                        controller.ROOT_CHECKSUM,
                    )
                },
            },
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
        self.assertNotIn("cms_verify=y", script)
        self.assertIn("checksum=y", script)

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
        self.root_image.unlink()
        with self.assertRaisesRegex(controller.TargetError, "exactly one"):
            self.stage()

    def test_accepts_current_mkarchiso_erofs_layout(self):
        self.root_image.unlink()
        self.root_image = self.source / controller.ROOT_IMAGES[1]
        self.root_image.write_bytes(b"erofs root image")
        self.write_root_checksum()
        (self.source / "arch/version").write_text("2026.07.27\n")
        (self.source / "arch/pkglist.x86_64.txt").write_text("base\n")
        release = self.stage()
        metadata = json.loads((release / "target.json").read_text())
        artifacts = metadata["source"]["artifacts"]
        self.assertIn("arch/x86_64/airootfs.erofs", artifacts)
        self.assertIn("arch/x86_64/airootfs.sha512", artifacts)
        self.assertIn("arch/version", artifacts)
        self.assertEqual(controller.verify(release), [])

    def test_two_root_images_are_refused(self):
        (self.source / controller.ROOT_IMAGES[1]).write_bytes(b"other root")
        with self.assertRaisesRegex(controller.TargetError, "exactly one"):
            self.stage()

    def test_root_image_checksum_mismatch_is_refused(self):
        self.root_image.write_bytes(b"changed after checksum")
        with self.assertRaisesRegex(controller.TargetError, "SHA-512"):
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

    def test_symlink_as_source_root_is_refused(self):
        linked = self.temp / "linked-output"
        linked.symlink_to(self.source, target_is_directory=True)
        with self.assertRaisesRegex(controller.TargetError, "symlink"):
            controller.stage(
                linked, self.releases, "20260727.001",
                "http://boot.example.test/controller/20260727.001")

    def test_special_file_in_source_is_refused(self):
        fifo = self.source / "arch/input.fifo"
        os.mkfifo(fifo)
        with self.assertRaisesRegex(controller.TargetError, "special"):
            self.stage()

    def test_empty_required_payload_is_refused(self):
        (self.source / controller.REQUIRED_PAYLOADS[0]).write_bytes(b"")
        with self.assertRaisesRegex(controller.TargetError, "empty"):
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

    def test_source_provenance_mutation_is_rejected_even_if_manifest_is_rewritten(self):
        release = self.stage()
        payload = release / "payload/arch/x86_64/airootfs.sfs"
        payload.write_bytes(b"replacement")
        manifest_path = release / "release.json"
        manifest = json.loads(manifest_path.read_text())
        manifest["artifacts"]["payload/arch/x86_64/airootfs.sfs"] = {
            "sha256": controller.sha256(payload),
            "size": payload.stat().st_size,
        }
        manifest_path.write_text(json.dumps(manifest))
        self.assertTrue(any(
            "target contract" in problem
            for problem in controller.verify(release)
        ))


if __name__ == "__main__":
    unittest.main()
