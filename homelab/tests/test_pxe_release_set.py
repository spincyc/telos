"""Tests for transactional aggregate PXE release sets."""

import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "lib"))

import pxe_release  # noqa: E402
import pxe_release_set as release_set  # noqa: E402


class ReleaseSetTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.releases = self.root / "releases"
        self.seal = self.root / "seal.json"
        self.seal_value = {
            "schema": 1,
            "content": [
                {"name": "arch-iso", "sha256": "a" * 64},
                {"name": "windows-iso", "sha256": "b" * 64},
                {"name": "wimboot", "sha256": "c" * 64},
                {
                    "name": "windows-install-source",
                    "source_iso_sha256": "b" * 64,
                    "receipt_sha256": "d" * 64,
                    "bytes": 8_000_000_000,
                    "file_count": 976,
                },
            ],
        }
        self.seal.write_text(json.dumps(self.seal_value), encoding="utf-8")

    def source(self, root: Path, target: str) -> Path:
        source = root / target
        source.mkdir(parents=True)
        (source / "boot.ipxe").write_text("#!ipxe\n", encoding="utf-8")
        (source / "target.json").write_text(json.dumps({
            "schema": 1,
            "id": target,
            "entrypoints": ["boot.ipxe"],
        }), encoding="utf-8")
        return source

    def builder(
        self, *, version="20260727.001", omit=None, mixed=False,
        tamper=False, interrupt=False,
    ):
        def stage(root):
            leaves = {}
            for target in release_set.TARGETS:
                if target == omit:
                    continue
                leaf_version = (
                    "20260727.999" if mixed and target == "windows" else version)
                leaves[target] = pxe_release.stage(
                    self.source(root / "sources", target),
                    root / "releases",
                    version=leaf_version,
                )
            if tamper:
                (leaves["controller"] / "boot.ipxe").write_text("changed\n")
            if interrupt:
                raise RuntimeError("simulated interruption")
            return leaves
        return stage

    def build(self, builder=None, version="20260727.001"):
        return release_set.build(
            self.releases, version, self.seal, self.seal_value,
            builder or self.builder(),
        )

    def test_complete_set_is_verified_and_selected_atomically(self):
        result = self.build()
        self.assertEqual(result, self.releases / "release-sets/20260727.001")
        self.assertEqual(release_set.verify(result), [])
        selected = json.loads(
            (self.releases / release_set.SELECTED).read_text(encoding="utf-8"))
        self.assertEqual(selected["version"], "20260727.001")
        windows = json.loads(
            (result / release_set.MANIFEST).read_text())["targets"]["windows"]
        self.assertEqual(
            windows["install_source"]["receipt_sha256"], "d" * 64)
        self.assertFalse(windows["install_source"]["copied_into_release_set"])
        self.assertEqual(
            windows["install_source"]["publication"],
            {
                "transport": "smb",
                "share_name": "windows-20260727.001",
                "read_only": True,
                "verify_receipt_before_serving": True,
            },
        )
        self.assertEqual(
            release_set.verify(
                result,
                expected_media_seal_sha256=release_set._digest(self.seal),
            ),
            [],
        )
        self.assertIn(
            "expected media seal",
            release_set.verify(
                result, expected_media_seal_sha256="f" * 64)[0],
        )

    def test_missing_mixed_and_tampered_leaf_never_replace_selection(self):
        self.build()
        selected_before = (
            self.releases / release_set.SELECTED).read_bytes()
        for builder in (
            self.builder(omit="windows"),
            self.builder(mixed=True),
            self.builder(tamper=True),
        ):
            with self.subTest(builder=builder):
                with self.assertRaises(release_set.ReleaseSetError):
                    self.build(builder, version="20260727.002")
                self.assertEqual(
                    (self.releases / release_set.SELECTED).read_bytes(),
                    selected_before,
                )
                self.assertFalse(
                    (self.releases / "release-sets/20260727.002").exists())
                staging = self.releases / ".release-set-staging"
                self.assertFalse(staging.exists() and any(staging.iterdir()))

    def test_interruption_cleans_staging_and_preserves_prior_selection(self):
        self.build()
        selected_before = (
            self.releases / release_set.SELECTED).read_bytes()
        with self.assertRaisesRegex(RuntimeError, "interruption"):
            self.build(self.builder(interrupt=True), version="20260727.002")
        self.assertEqual(
            (self.releases / release_set.SELECTED).read_bytes(), selected_before)
        self.assertFalse(
            (self.releases / "release-sets/20260727.002").exists())

    def test_wrong_version_and_changed_seal_are_rejected_before_staging(self):
        called = False

        def builder(_root):
            nonlocal called
            called = True
            return {}

        with self.assertRaisesRegex(release_set.ReleaseSetError, "YYYYMMDD"):
            self.build(builder, version="latest")
        self.assertFalse(called)
        changed = dict(self.seal_value)
        changed["schema"] = 2
        self.seal.write_text(json.dumps(changed), encoding="utf-8")
        with self.assertRaisesRegex(release_set.ReleaseSetError, "changed"):
            self.build(builder)
        self.assertFalse(called)

    def test_rollback_selects_only_a_verified_existing_set(self):
        first = self.build()
        release_set.build(
            self.releases, "20260727.002", self.seal, self.seal_value,
            self.builder(version="20260727.002"), select=True,
        )
        release_set.select(self.releases, "20260727.001")
        selected = json.loads(
            (self.releases / release_set.SELECTED).read_text())
        self.assertEqual(selected["version"], "20260727.001")
        (first / "targets/controller/20260727.001/boot.ipxe").write_text("tampered\n")
        with self.assertRaisesRegex(release_set.ReleaseSetError, "invalid"):
            release_set.select(self.releases, "20260727.001")

    def test_the_selected_set_resolves_from_the_release_root(self):
        built = self.build()
        self.assertEqual(release_set.selected_release_set(self.releases), built)
        release_set.build(
            self.releases, "20260727.002", self.seal, self.seal_value,
            self.builder(version="20260727.002"), select=False)
        # Present is not selected: the descriptor still names the first set.
        self.assertEqual(release_set.selected_release_set(self.releases), built)

    def test_an_unresolvable_selection_is_refused(self):
        self.build()
        selected = self.releases / release_set.SELECTED
        descriptor = json.loads(selected.read_text(encoding="utf-8"))
        cases = {
            "cannot read": None,
            "unlisted fields": dict(descriptor, extra=1),
            "schema": dict(descriptor, schema=2),
            "YYYYMMDD.NNN": dict(descriptor, version="latest"),
            "does not match": dict(descriptor, manifest_sha256="0" * 64),
        }
        for message, value in cases.items():
            with self.subTest(message=message):
                selected.unlink(missing_ok=True)
                if value is not None:
                    selected.write_text(json.dumps(value), encoding="utf-8")
                with self.assertRaisesRegex(release_set.ReleaseSetError, message):
                    release_set.selected_release_set(self.releases)
        # A set directory is not a release root: it holds no selection.
        with self.assertRaisesRegex(release_set.ReleaseSetError, "cannot read"):
            release_set.selected_release_set(
                self.releases / "release-sets/20260727.001")

    def test_install_source_must_match_the_sealed_windows_iso(self):
        self.seal_value["content"][-1]["source_iso_sha256"] = "e" * 64
        self.seal.write_text(json.dumps(self.seal_value), encoding="utf-8")
        with self.assertRaisesRegex(release_set.ReleaseSetError, "sealed ISO"):
            self.build()


if __name__ == "__main__":
    unittest.main()
