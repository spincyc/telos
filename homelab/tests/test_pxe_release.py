"""Tests for immutable local PXE release staging."""

import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "lib"))

import pxe_release  # noqa: E402


class TestPxeRelease(unittest.TestCase):
    def target(self, root: Path) -> Path:
        source = root / "arch-workstation"
        (source / "payload").mkdir(parents=True)
        (source / "payload" / "boot.ipxe").write_text("#!ipxe\n")
        (source / "target.json").write_text(json.dumps({
            "schema": 1,
            "id": "arch-workstation",
            "kind": "workstation",
            "entrypoints": ["payload/boot.ipxe"],
        }))
        return source

    def test_stage_is_versioned_and_verifiable(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            release = pxe_release.stage(
                self.target(root), root / "releases", version="20260727.001")
            self.assertEqual(
                release, root / "releases/arch-workstation/20260727.001")
            self.assertEqual(pxe_release.verify(release), [])

    def test_existing_release_is_immutable(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = self.target(root)
            pxe_release.stage(source, root / "releases", version="20260727.001")
            with self.assertRaisesRegex(pxe_release.ReleaseError, "already exists"):
                pxe_release.stage(
                    source, root / "releases", version="20260727.001")

    def test_tampering_and_unlisted_files_are_reported(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            release = pxe_release.stage(
                self.target(root), root / "releases", version="20260727.001")
            (release / "payload/boot.ipxe").write_text("changed\n")
            (release / "extra").write_text("extra\n")
            problems = pxe_release.verify(release)
            self.assertTrue(any("checksum mismatch" in item for item in problems))
            self.assertIn("extra: unlisted", problems)

    def test_bad_version_and_missing_entrypoint_stop_staging(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = self.target(root)
            with self.assertRaisesRegex(pxe_release.ReleaseError, "YYYYMMDD"):
                pxe_release.build_manifest(source, version="latest")
            (source / "payload/boot.ipxe").unlink()
            with self.assertRaisesRegex(pxe_release.ReleaseError, "missing entrypoint"):
                pxe_release.build_manifest(source, version="20260727.001")

    def test_symlinks_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = self.target(root)
            (source / "payload/link").symlink_to("boot.ipxe")
            with self.assertRaisesRegex(pxe_release.ReleaseError, "symlinks"):
                pxe_release.build_manifest(source, version="20260727.001")


if __name__ == "__main__":
    unittest.main()
