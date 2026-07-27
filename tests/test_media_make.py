"""Offline integration proof for installation-media Make targets."""

from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import textwrap
import unittest


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]


def candidate_repository(destination: Path) -> None:
    """Commit the tracked plus candidate worktree into a local test remote."""
    destination.mkdir()
    subprocess.run(["git", "init", "--quiet", str(destination)], check=True)
    listed = subprocess.run(
        [
            "git",
            "-C",
            str(REPOSITORY_ROOT),
            "ls-files",
            "--cached",
            "--others",
            "--exclude-standard",
            "-z",
        ],
        check=True,
        capture_output=True,
    )
    for encoded in listed.stdout.split(b"\0"):
        if not encoded:
            continue
        relative = Path(os.fsdecode(encoded))
        source = REPOSITORY_ROOT / relative
        target = destination / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        if source.is_symlink():
            target.symlink_to(os.readlink(source))
        else:
            shutil.copy2(source, target)
    subprocess.run(["git", "-C", str(destination), "add", "--all"], check=True)
    subprocess.run(
        [
            "git",
            "-C",
            str(destination),
            "-c",
            "user.name=Telos test",
            "-c",
            "user.email=test@invalid",
            "commit",
            "--quiet",
            "-m",
            "candidate",
        ],
        check=True,
    )


class MediaMakeTests(unittest.TestCase):
    def test_fresh_pull_needs_no_preexisting_media_artifacts(self):
        """A pulled public tree can dispatch every acquisition from scratch."""
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            remote = root / "candidate"
            candidate_repository(remote)
            clone = root / "telos-public"
            subprocess.run(
                [
                    "git",
                    "clone",
                    "--quiet",
                    "--no-hardlinks",
                    str(remote),
                    str(clone),
                ],
                check=True,
            )
            subprocess.run(
                ["git", "-C", str(clone), "pull", "--ff-only", "--quiet"],
                check=True,
            )

            cache_roots = (clone / "homelab/cache", clone / "homelab/var/media")
            self.assertTrue(all(not path.exists() for path in cache_roots))

            log = root / "media-invocations.jsonl"
            launcher = root / "mock-fetcher"
            launcher.write_text(
                textwrap.dedent(
                    """\
                    #!/usr/bin/env python3
                    import json
                    import os
                    from pathlib import Path
                    import sys

                    with Path(os.environ["TELOS_MEDIA_TEST_LOG"]).open(
                        "a", encoding="utf-8"
                    ) as stream:
                        stream.write(json.dumps(
                            [Path(sys.argv[0]).as_posix(), *sys.argv[1:]]
                        ) + "\\n")
                    if Path(sys.argv[0]).name == "homelab-fetch-windows":
                        raise SystemExit(2)
                    """
                ),
                encoding="utf-8",
            )
            launcher.chmod(0o755)
            fetchers = (
                clone / "homelab/media/fetch-arch",
                clone / "homelab/bin/homelab-fetch-wimboot",
                clone / "homelab/bin/homelab-fetch-windows",
            )
            for fetcher in fetchers:
                shutil.copy2(launcher, fetcher)
            environment = os.environ.copy()
            environment["TELOS_MEDIA_TEST_LOG"] = str(log)
            result = subprocess.run(
                [
                    "make",
                    "--no-print-directory",
                    "homelab-media",
                ],
                cwd=clone,
                env=environment,
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(result.returncode, 2)

            calls = [
                json.loads(line)
                for line in log.read_text(encoding="utf-8").splitlines()
            ]
            self.assertEqual(
                [[Path(call[0]).name, *call[1:]] for call in calls],
                [
                    ["fetch-arch"],
                    ["homelab-fetch-wimboot", "--output", "homelab/var/media/wimboot"],
                    [
                        "homelab-fetch-windows",
                        "--output",
                        "homelab/var/media/windows/windows-11-x64.iso",
                    ],
                ],
            )
            self.assertTrue(all(not path.exists() for path in cache_roots))

            without_iso = subprocess.run(
                ["make", "--no-print-directory", "--dry-run", "homelab-bootstrap-vm-run"],
                cwd=clone,
                check=True,
                capture_output=True,
                text=True,
            ).stdout
            with_iso = subprocess.run(
                [
                    "make",
                    "--no-print-directory",
                    "--dry-run",
                    "homelab-bootstrap-vm-run",
                    "ISO=/tmp/operator.iso",
                ],
                cwd=clone,
                check=True,
                capture_output=True,
                text=True,
            ).stdout
            self.assertIn("homelab/media/fetch-arch", without_iso)
            self.assertNotIn("homelab/media/fetch-arch", with_iso)
            self.assertIn("--iso '/tmp/operator.iso'", with_iso)

            with_seed = subprocess.run(
                [
                    "make",
                    "--no-print-directory",
                    "--dry-run",
                    "homelab-bootstrap-vm-run",
                    "ISO=/tmp/operator.iso",
                    "SEED_ISO=/tmp/controller-seed.iso",
                ],
                cwd=clone,
                check=True,
                capture_output=True,
                text=True,
            ).stdout
            self.assertIn(
                "--seed-iso '/tmp/controller-seed.iso'",
                with_seed,
            )


if __name__ == "__main__":
    unittest.main()
