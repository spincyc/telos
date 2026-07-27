"""Tests for the offline Arch workstation PXE release builder."""

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "pxe"))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "lib"))

import arch_workstation as target  # noqa: E402
import pxe_release  # noqa: E402


def fake_media(root: Path) -> Path:
    files = {
        ".disk/info": b"Arch Linux test media\n",
        "arch/boot/x86_64/vmlinuz-linux": b"kernel",
        "arch/boot/x86_64/initramfs-linux.img": b"initramfs",
        "arch/x86_64/airootfs.sfs": b"root image",
        "arch/pkglist.x86_64.txt": b"base\nlinux\n",
    }
    for name, content in files.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
    return root


class TestMediaValidation(unittest.TestCase):
    def test_requires_the_boot_and_root_images(self):
        with tempfile.TemporaryDirectory() as directory:
            media = fake_media(Path(directory))
            (media / "arch/x86_64/airootfs.sfs").unlink()
            with self.assertRaisesRegex(target.TargetError, "airootfs.sfs"):
                target.validate_source(media)

    def test_rejects_a_non_version(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with self.assertRaisesRegex(target.TargetError, "YYYYMMDD"):
                target.stage(source=fake_media(root / "media"),
                             releases=root / "releases", version="latest",
                             base_url="http://boot.example.test/pxe/releases")


class TestIsoExtraction(unittest.TestCase):
    def test_extracts_mount_free_into_digest_addressed_cache(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            image = root / "arch.iso"
            image.write_bytes(b"iso bytes")
            calls = []

            def runner(command, **options):
                calls.append((command, options))
                fake_media(Path(command[-1]))
                return subprocess.CompletedProcess(command, 0, "", "")

            extracted = target.extract_iso(image, root / "cache", runner)
            self.assertEqual(extracted.parent.name, target.sha256(image))
            self.assertEqual(calls[0][0][0:3], ("xorriso", "-osirrox", "on"))
            self.assertNotIn("mount", calls[0][0])
            self.assertEqual(
                json.loads((extracted.parent / "receipt.json").read_text())[
                    "image_sha256"
                ],
                target.sha256(image),
            )

    def test_reuses_only_an_untouched_extraction(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            image = root / "arch.iso"
            image.write_bytes(b"iso bytes")
            calls = 0

            def runner(command, **_options):
                nonlocal calls
                calls += 1
                fake_media(Path(command[-1]))
                return subprocess.CompletedProcess(command, 0, "", "")

            first = target.extract_iso(image, root / "cache", runner)
            second = target.extract_iso(image, root / "cache", runner)
            self.assertEqual(first, second)
            self.assertEqual(calls, 1)

    def test_refuses_a_tampered_cache_entry(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            image = root / "arch.iso"
            image.write_bytes(b"iso bytes")

            def runner(command, **_options):
                fake_media(Path(command[-1]))
                return subprocess.CompletedProcess(command, 0, "", "")

            extracted = target.extract_iso(image, root / "cache", runner)
            (extracted / "arch/x86_64/airootfs.sfs").write_bytes(b"tampered")
            with self.assertRaisesRegex(target.TargetError, "invalid.*cache"):
                target.extract_iso(image, root / "cache", runner)

    def test_failed_extraction_leaves_no_cache_entry(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            image = root / "arch.iso"
            image.write_bytes(b"iso bytes")

            def runner(command, **_options):
                raise subprocess.CalledProcessError(5, command, stderr="bad ISO")

            with self.assertRaisesRegex(target.TargetError, "bad ISO"):
                target.extract_iso(image, root / "cache", runner)
            self.assertEqual(list((root / "cache").iterdir()), [])


class TestRelease(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.release = target.stage(
            source=fake_media(self.root / "media"),
            releases=self.root / "releases",
            version="20260727.001",
            base_url="http://boot.example.test/pxe/releases")

    def tearDown(self):
        self.temporary.cleanup()

    def test_uses_the_shared_target_contract(self):
        descriptor = json.loads((self.release / "target.json").read_text())
        self.assertEqual(descriptor["schema"], 1)
        self.assertEqual(descriptor["id"], "arch-workstation")
        self.assertEqual(descriptor["kind"], "archiso-netboot")
        self.assertEqual(descriptor["entrypoints"], ["boot.ipxe"])

    def test_copies_the_complete_arch_tree_beneath_payload(self):
        self.assertEqual(
            (self.release / "payload/arch/pkglist.x86_64.txt").read_text(),
            "base\nlinux\n")

    def test_ipxe_uses_the_immutable_version_url(self):
        script = (self.release / "boot.ipxe").read_text()
        self.assertIn("/arch-workstation/20260727.001/payload", script)
        self.assertIn("archiso_http_srv=${base}/", script)

    def test_an_untouched_release_verifies(self):
        self.assertEqual(target.verify(self.release), [])
        self.assertEqual(pxe_release.verify(self.release), [])

    def test_changed_content_fails_verification(self):
        image = self.release / "payload/arch/x86_64/airootfs.sfs"
        image.write_bytes(b"changed")
        self.assertTrue(any("airootfs.sfs: checksum mismatch" in problem
                            for problem in target.verify(self.release)))

    def test_unlisted_content_fails_verification(self):
        (self.release / "payload/surprise").write_text("no")
        self.assertIn("payload/surprise: present but not listed",
                      target.verify(self.release))

    def test_existing_version_is_immutable(self):
        with self.assertRaisesRegex(target.TargetError, "already exists"):
            target.stage(
                source=self.root / "media", releases=self.root / "releases",
                version="20260727.001",
                base_url="http://boot.example.test/pxe/releases")

    def test_no_partial_release_survives_a_failed_copy(self):
        with self.assertRaises(target.TargetError):
            target.stage(
                source=self.root / "missing", releases=self.root / "releases",
                version="20260727.002",
                base_url="http://boot.example.test/pxe/releases")
        self.assertFalse(
            (self.root / "releases/arch-workstation/20260727.002").exists())


if __name__ == "__main__":
    unittest.main()
