import importlib.util
import json
import tempfile
import unittest
from unittest import mock
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "lib"))
import pxe_release  # noqa: E402

WINDOWS = ROOT / "pxe" / "windows"


def load_common():
    spec = importlib.util.spec_from_file_location("windows_pxe_common", WINDOWS / "common.py")
    module = importlib.util.module_from_spec(spec)
    assert spec.loader
    spec.loader.exec_module(module)
    return module


def load_stage():
    sys.path.insert(0, str(WINDOWS))
    spec = importlib.util.spec_from_file_location("windows_pxe_stage", WINDOWS / "stage.py")
    module = importlib.util.module_from_spec(spec)
    assert spec.loader
    spec.loader.exec_module(module)
    return module


class WindowsPxeTests(unittest.TestCase):
    def setUp(self):
        self.common = load_common()

    def make_release(self, root: Path):
        for relative in (*self.common.PAYLOADS, "boot.ipxe"):
            path = root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(f"fixture:{relative}".encode())
        records = {
            relative: {
                "size": (root / relative).stat().st_size,
                "sha256": self.common.sha256(root / relative),
            }
            for relative in (*self.common.PAYLOADS, "boot.ipxe")
        }
        (root / "release.json").write_text(
            json.dumps(
                {
                    "schema": 1,
                    "version": root.name,
                    "target": "windows",
                    "redistributable": False,
                    "wimboot_sha256": records["wimboot"]["sha256"],
                    "wimboot_provenance": {
                        "project": "https://github.com/ipxe/wimboot",
                        "release": "https://github.com/ipxe/wimboot/releases/tag/v2.9.0",
                        "version": "2.9.0",
                        "url": "https://github.com/ipxe/wimboot/releases/download/v2.9.0/wimboot",
                        "size": records["wimboot"]["size"],
                        "sha256": records["wimboot"]["sha256"],
                    },
                    "artifacts": records,
                }
            )
        )

    def test_valid_release(self):
        with tempfile.TemporaryDirectory() as name:
            release = Path(name) / "windows" / "20260727.001"
            release.mkdir(parents=True)
            self.make_release(release)
            self.assertEqual([], self.common.verify_release(release))
            self.assertEqual([], pxe_release.verify(release))

    def test_tampered_payload_fails(self):
        with tempfile.TemporaryDirectory() as name:
            release = Path(name) / "20260727.001"
            release.mkdir()
            self.make_release(release)
            (release / "sources/boot.wim").write_bytes(b"tampered")
            errors = self.common.verify_release(release)
            self.assertTrue(any("boot.wim" in error for error in errors))

    def test_answer_file_is_forbidden(self):
        with tempfile.TemporaryDirectory() as name:
            release = Path(name) / "20260727.001"
            release.mkdir()
            self.make_release(release)
            (release / "Autounattend.xml").write_text("secret")
            errors = self.common.verify_release(release)
            self.assertTrue(any("forbidden" in error for error in errors))

    def test_release_name_rejects_paths(self):
        with self.assertRaises(ValueError):
            self.common.validate_release_name("../current")
        self.common.validate_release_name("20260727.001")

    def test_provenance_must_match_staged_wimboot(self):
        with tempfile.TemporaryDirectory() as name:
            release = Path(name) / "20260727.001"
            release.mkdir()
            self.make_release(release)
            manifest = json.loads((release / "release.json").read_text())
            manifest["wimboot_provenance"]["sha256"] = "0" * 64
            (release / "release.json").write_text(json.dumps(manifest))
            errors = self.common.verify_release(release)
            self.assertTrue(any("provenance" in error for error in errors))

    def test_sealed_install_source_stages_without_extraction_tools(self):
        stage = load_stage()
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            source = root / "install-source"
            for relative in (
                "bootmgr", "boot/BCD", "boot/boot.sdi", "sources/boot.wim",
            ):
                path = source / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(relative.encode())
            wimboot = root / "wimboot"
            wimboot.write_bytes(b"wimboot")
            metadata = root / "wimboot.json"
            metadata.write_text(json.dumps({
                "schema": 1,
                "name": "wimboot",
                "version": "test",
                "source": "https://github.com/ipxe/wimboot",
                "release": "https://github.com/ipxe/wimboot/releases/tag/vtest",
                "url": "https://github.com/ipxe/wimboot/releases/download/vtest/wimboot",
                "size": wimboot.stat().st_size,
                "sha256": stage.sha256(wimboot),
            }))
            args = type("Args", (), {
                "release": "20260727.001",
                "install_source": source,
                "source_iso_sha256": "a" * 64,
                "wimboot": wimboot,
                "wimboot_metadata": metadata,
                "output": root / "releases",
                "base_url": "http://boot.example.test/windows",
            })()
            receipt = {
                "edition": "Windows 11 Pro",
                "install_image": "sources/install.wim",
                "source_iso_sha256": "a" * 64,
            }
            with mock.patch.object(
                stage.windows_install_source, "verify_cache",
                return_value=receipt,
            ) as verifier, mock.patch.object(
                stage.shutil, "which",
                side_effect=AssertionError("extractor lookup is forbidden"),
            ):
                release = stage.stage_from_install_source(args)
            verifier.assert_called_once_with(source, "a" * 64)
            self.assertEqual(stage.verify_release(release), [])
            manifest = json.loads((release / "release.json").read_text())
            self.assertEqual(manifest["source_iso_sha256"], "a" * 64)

    def test_sealed_install_source_rejects_missing_boot_payload(self):
        stage = load_stage()
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            source = root / "install-source"
            source.mkdir()
            wimboot = root / "wimboot"
            wimboot.write_bytes(b"x")
            metadata = root / "wimboot.json"
            metadata.write_text(json.dumps({
                "schema": 1, "name": "wimboot", "version": "v",
                "source": "https://github.com/ipxe/wimboot",
                "release": "https://github.com/ipxe/wimboot/releases/tag/vv",
                "url": "https://github.com/ipxe/wimboot/releases/download/vv/wimboot",
                "size": 1, "sha256": stage.sha256(wimboot),
            }))
            args = type("Args", (), {
                "release": "20260727.001", "install_source": source,
                "source_iso_sha256": "a" * 64, "wimboot": wimboot,
                "wimboot_metadata": metadata, "output": root / "out",
                "base_url": "http://boot.example.test/windows",
            })()
            with mock.patch.object(
                stage.windows_install_source, "verify_cache",
                return_value={
                    "edition": "Windows 11 Pro",
                    "install_image": "sources/install.wim",
                    "source_iso_sha256": "a" * 64,
                },
            ):
                with self.assertRaisesRegex(RuntimeError, "exactly one bootmgr"):
                    stage.stage_from_install_source(args)


if __name__ == "__main__":
    unittest.main()
