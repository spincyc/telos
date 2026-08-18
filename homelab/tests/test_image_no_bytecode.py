"""No host-built Python bytecode may reach the published image.

`archiso/airootfs/usr/local/bin/homelab-progress` is a real Python program
that lives inside the image tree, and `test_guest_progress_units` loads it by
path to prove its frames against the host receiver.  Importing a file writes
`__pycache__` beside it by default, and `homelab-image` copies the whole
profile into the staged tree, so a test artifact -- host-built, tied to the
host interpreter version, and nothing a person wrote -- would have been baked
into an artifact published with its checksum.

The fix is at both ends, and both ends are tested here: the loader no longer
dirties the tree, and the builder refuses to stage bytecode even when
something else does.  The builder is the load-bearing half, because it is the
single gate between the tracked profile and the image, and it holds no matter
which tool left the junk behind.
"""

import importlib.machinery
import importlib.util
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PROFILE = ROOT / "archiso"

_loader = importlib.machinery.SourceFileLoader(
    "homelab_image_bytecode", str(ROOT / "bin/homelab-image"))
_spec = importlib.util.spec_from_loader("homelab_image_bytecode", _loader)
image = importlib.util.module_from_spec(_spec)
_loader.exec_module(image)


def bytecode_under(root: Path) -> list[str]:
    return sorted(
        str(path.relative_to(root))
        for path in root.rglob("*")
        if path.name == "__pycache__" or path.suffix in (".pyc", ".pyo")
    )


class StagedImageBytecodeTests(unittest.TestCase):
    def setUp(self):
        self.work = Path(tempfile.mkdtemp(prefix="homelab-image-bytecode-"))
        self.addCleanup(shutil.rmtree, self.work, ignore_errors=True)
        self.overlay = self.work / "overlay"
        self.overlay.mkdir()

    def stage(self):
        image.stage(self.work, overlay=self.overlay)
        return self.work / "profile"

    def test_no_bytecode_appears_under_the_staged_airootfs(self):
        build = self.stage()
        self.assertEqual(bytecode_under(build / "airootfs"), [])
        self.assertEqual(bytecode_under(build), [])

    def test_bytecode_left_in_the_profile_is_never_staged(self):
        # Simulate exactly what a stray import does to the tracked profile.
        # Anything else in this suite may already have dirtied it, so plant
        # only what this test owns and remove only that.
        cache = PROFILE / "airootfs/usr/local/bin/__pycache__"
        created = not cache.exists()
        cache.mkdir(parents=True, exist_ok=True)
        planted = cache / "homelab-progress.cpython-999.pyc"
        planted.write_bytes(b"\x00")
        if created:
            self.addCleanup(shutil.rmtree, cache, ignore_errors=True)
        else:
            self.addCleanup(planted.unlink, True)
        build = self.stage()
        self.assertEqual(bytecode_under(build), [])
        self.assertEqual(image.audit(build), [])

    def test_the_audit_refuses_bytecode_planted_after_staging(self):
        build = self.stage()
        stray = build / "airootfs/usr/local/bin/__pycache__"
        stray.mkdir(parents=True)
        (stray / "homelab-progress.cpython-999.pyc").write_bytes(b"\x00")
        problems = image.audit(build)
        self.assertTrue(
            any("bytecode" in problem for problem in problems), problems)

    def test_the_guest_script_loader_writes_no_bytecode(self):
        # A delta, not an absolute: other suites may load image scripts by
        # path too, and each such loader owns its own guard. This proves the
        # guest-progress loader adds nothing.
        from homelab.tests import test_guest_progress_units as units

        airootfs = PROFILE / "airootfs"
        before = bytecode_under(airootfs)
        previous = sys.dont_write_bytecode
        sys.dont_write_bytecode = False
        try:
            units.load_script()
        finally:
            sys.dont_write_bytecode = previous
        self.assertEqual(bytecode_under(airootfs), before)


if __name__ == "__main__":
    unittest.main()
