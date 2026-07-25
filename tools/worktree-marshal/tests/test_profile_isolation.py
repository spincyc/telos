#!/usr/bin/env python3
"""Black-box profile-isolation tests for the source-tree console."""

from __future__ import annotations

import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path


PACKAGE_ROOT = Path(__file__).resolve().parents[1]
SOURCE_ROOT = PACKAGE_ROOT / "src"
REPOSITORY_ROOT = PACKAGE_ROOT.parents[1]
LEGACY_LAUNCHER = REPOSITORY_ROOT / "scripts" / "triptych-codex"
COMMAND_TIMEOUT_SECONDS = 30


CONSOLE_SOURCE = """\
#!/usr/bin/env python3
from worktree_marshal.cli import main

raise SystemExit(main())
"""


FAKE_CODEX_SOURCE = """\
#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path


def git(cwd: Path, *arguments: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["git", *arguments],
        cwd=cwd,
        check=True,
        capture_output=True,
        text=True,
    )


arguments = sys.argv[1:]
workdir_index = arguments.index("-C")
workdir = Path(arguments[workdir_index + 1]).resolve()
root = Path(git(workdir, "rev-parse", "--show-toplevel").stdout.strip()).resolve()
branch = git(root, "symbolic-ref", "--quiet", "--short", "HEAD").stdout.strip()
environment_names = (
    "WORKTREE_MARSHAL_ROLE",
    "WORKTREE_MARSHAL_RUN_ID",
    "WORKTREE_MARSHAL_PROFILE_ID",
    "WORKTREE_MARSHAL_AGENT_ID",
    "WORKTREE_MARSHAL_REAL_CODEX",
    "TRIPTYCH_CODEX_ROLE",
    "TRIPTYCH_CODEX_RUN_ID",
    "TRIPTYCH_CODEX_REAL",
)
record = {
    "argv": arguments,
    "branch": branch,
    "root": str(root),
    "environment": {name: os.environ.get(name) for name in environment_names},
    "temporary_environment": {
        name: os.environ.get(name) for name in ("TMPDIR", "TMP", "TEMP")
    },
}
log = Path(os.environ["FAKE_CODEX_LOG"])
log.parent.mkdir(parents=True, exist_ok=True)
with log.open("a", encoding="utf-8") as stream:
    json.dump(record, stream, sort_keys=True)
    stream.write("\\n")

if os.environ.get("FAKE_CODEX_ACTION") == "dirty":
    (root / "agent-result.txt").write_text("isolated result\\n", encoding="utf-8")
elif os.environ.get("FAKE_CODEX_ACTION") == "commit":
    (root / "agent-result.txt").write_text("integrated result\\n", encoding="utf-8")
    git(root, "add", "agent-result.txt")
    git(root, "commit", "-m", "Agent result")

raise SystemExit(int(os.environ.get("FAKE_CODEX_EXIT", "0")))
"""


class ProfileIsolationTests(unittest.TestCase):
    maxDiff = None

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(
            prefix="worktree-marshal-profile-test-"
        )
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.control = self.root / "control"
        self.control.mkdir()
        self.home = self.root / "home"
        self.home.mkdir()
        self.bin = self.root / "bin"
        self.bin.mkdir()
        self.console = self.bin / "worktree-marshal"
        self.console.write_text(CONSOLE_SOURCE, encoding="utf-8")
        self.console.chmod(0o755)
        self.fake_codex = self.bin / "codex"
        self.fake_codex.write_text(FAKE_CODEX_SOURCE, encoding="utf-8")
        self.fake_codex.chmod(0o755)
        self.fake_log = self.root / "fake-codex.jsonl"
        self.generic_state = self.root / "generic-state"
        self.triptych_state = self.root / "triptych-state"

        self.git("init", "-b", "main")
        self.git("config", "user.name", "Worktree Marshal Test")
        self.git("config", "user.email", "marshal-test@example.invalid")
        self.git("config", "commit.gpgSign", "false")
        (self.control / "baseline.txt").write_text("baseline\n", encoding="utf-8")
        self.git("add", "baseline.txt")
        self.git("commit", "-m", "Synthetic baseline")

    @property
    def generic_profile_state(self) -> Path:
        return self.generic_state / "profiles" / "generic-v1"

    def environment(self, additions: dict[str, str] | None = None) -> dict[str, str]:
        environment = os.environ.copy()
        for name in list(environment):
            if (
                name.startswith("WORKTREE_MARSHAL_")
                or name.startswith("TRIPTYCH_CODEX_")
                or name
                in {
                    "GIT_ALTERNATE_OBJECT_DIRECTORIES",
                    "GIT_COMMON_DIR",
                    "GIT_DIR",
                    "GIT_INDEX_FILE",
                    "GIT_OBJECT_DIRECTORY",
                    "GIT_PREFIX",
                    "GIT_WORK_TREE",
                }
            ):
                environment.pop(name, None)
        environment.update(
            {
                "HOME": str(self.home),
                "GIT_CONFIG_GLOBAL": os.devnull,
                "GIT_CONFIG_NOSYSTEM": "1",
                "PYTHONDONTWRITEBYTECODE": "1",
                "PYTHONPATH": str(SOURCE_ROOT),
                "FAKE_CODEX_LOG": str(self.fake_log),
                "WORKTREE_MARSHAL_REAL_CODEX": str(self.fake_codex),
                "WORKTREE_MARSHAL_STATE_DIR": str(self.generic_state),
                "TRIPTYCH_CODEX_REAL": str(self.fake_codex),
                "TRIPTYCH_CODEX_STATE_DIR": str(self.triptych_state),
            }
        )
        if additions:
            environment.update(additions)
        return environment

    def git(
        self,
        *arguments: str,
        check: bool = True,
        cwd: Path | None = None,
    ) -> subprocess.CompletedProcess:
        return subprocess.run(
            ["git", *arguments],
            cwd=cwd or self.control,
            env=self.environment(),
            check=check,
            capture_output=True,
            text=True,
            timeout=COMMAND_TIMEOUT_SECONDS,
        )

    def run_console(
        self,
        arguments: list[str],
        *,
        cwd: Path | None = None,
        environment: dict[str, str] | None = None,
    ) -> subprocess.CompletedProcess:
        return subprocess.run(
            [str(self.console), *arguments],
            cwd=cwd or self.control,
            env=self.environment(environment),
            check=False,
            capture_output=True,
            text=True,
            timeout=COMMAND_TIMEOUT_SECONDS,
        )

    def run_legacy(
        self,
        arguments: list[str] | None = None,
        *,
        environment: dict[str, str] | None = None,
    ) -> subprocess.CompletedProcess:
        return subprocess.run(
            [str(LEGACY_LAUNCHER), *(arguments or [])],
            cwd=self.control,
            env=self.environment(environment),
            check=False,
            capture_output=True,
            text=True,
            timeout=COMMAND_TIMEOUT_SECONDS,
        )

    def manifests(self, state_root: Path) -> list[Path]:
        return sorted(state_root.glob("*/runs/*.json"))

    def only_manifest(self, state_root: Path) -> tuple[Path, dict]:
        paths = self.manifests(state_root)
        self.assertEqual(len(paths), 1, paths)
        return paths[0], json.loads(paths[0].read_text(encoding="utf-8"))

    def generic_repository_state(self) -> Path:
        repositories = [
            path for path in self.generic_profile_state.iterdir() if path.is_dir()
        ]
        self.assertEqual(len(repositories), 1, repositories)
        return repositories[0]

    def fake_records(self) -> list[dict]:
        if not self.fake_log.exists():
            return []
        return [
            json.loads(line)
            for line in self.fake_log.read_text(encoding="utf-8").splitlines()
        ]

    def create_legacy_retained_run(self) -> tuple[Path, dict]:
        result = self.run_legacy(
            ["legacy compatibility run"],
            environment={"FAKE_CODEX_EXIT": "3"},
        )
        self.assertEqual(result.returncode, 3, result.stderr)
        path, manifest = self.only_manifest(self.triptych_state)
        self.assertEqual(manifest["state"], "failed-preserved")
        self.assertFalse(manifest["dirty"])
        return path, manifest

    def test_generic_changed_run_uses_only_generic_identities(self) -> None:
        result = self.run_console(
            ["--profile", "generic-v1", "run", "--agent", "codex"],
            environment={"FAKE_CODEX_ACTION": "dirty"},
        )
        self.assertEqual(result.returncode, 0, result.stderr)

        _, manifest = self.only_manifest(self.generic_profile_state)
        run_id = manifest["run_id"]
        expected_branch = f"worktree-marshal/generic-v1/isolated/{run_id}"
        self.assertEqual(manifest["state"], "preserved")
        self.assertTrue(manifest["dirty"])
        self.assertEqual(manifest["format_id"], "worktree-marshal-run")
        self.assertEqual(manifest["profile_id"], "generic-v1")
        self.assertEqual(manifest["agent"], "codex")
        self.assertEqual(manifest["schema_version"], 1)
        self.assertEqual(manifest["branch"], expected_branch)
        self.assertEqual(manifest["target_ref"], "refs/heads/main")
        self.assertTrue(Path(manifest["worktree"]).is_dir())
        self.assertTrue(Path(manifest["tmpdir"]).is_dir())
        self.assertTrue(
            Path(manifest["worktree"]).is_relative_to(self.generic_profile_state)
        )
        self.assertTrue(
            Path(manifest["tmpdir"]).is_relative_to(self.generic_profile_state)
        )

        refs = set(
            self.git("for-each-ref", "--format=%(refname)").stdout.splitlines()
        )
        self.assertIn(f"refs/heads/{expected_branch}", refs)
        self.assertFalse(
            any(ref.startswith("refs/heads/codex/isolated/") for ref in refs)
        )
        self.assertFalse(
            any(ref.startswith("refs/triptych-codex/runs/") for ref in refs)
        )

        worktrees = self.git("worktree", "list", "--porcelain").stdout
        self.assertIn(f"branch refs/heads/{expected_branch}\n", worktrees)
        self.assertIn(
            f"locked worktree-marshal generic-v1 {run_id}\n",
            worktrees,
        )

        records = self.fake_records()
        self.assertEqual(len(records), 1, records)
        record = records[0]
        self.assertEqual(record["branch"], expected_branch)
        self.assertEqual(
            record["environment"],
            {
                "WORKTREE_MARSHAL_AGENT_ID": "codex",
                "WORKTREE_MARSHAL_PROFILE_ID": "generic-v1",
                "WORKTREE_MARSHAL_REAL_CODEX": str(self.fake_codex),
                "WORKTREE_MARSHAL_ROLE": "worker",
                "WORKTREE_MARSHAL_RUN_ID": run_id,
                "TRIPTYCH_CODEX_REAL": None,
                "TRIPTYCH_CODEX_ROLE": None,
                "TRIPTYCH_CODEX_RUN_ID": None,
            },
        )
        self.assertEqual(
            set(record["temporary_environment"].values()),
            {manifest["tmpdir"]},
        )

    def test_generic_status_never_falls_back_to_triptych_state(self) -> None:
        triptych_path, triptych_manifest = self.create_legacy_retained_run()
        run_id = triptych_manifest["run_id"]
        before = triptych_path.read_bytes()

        overview = self.run_console(["--profile", "generic-v1", "status"])
        self.assertEqual(overview.returncode, 0, overview.stderr)
        self.assertEqual(overview.stdout, "No Worktree Marshal runs.\n")
        self.assertNotIn(run_id, overview.stdout)

        selected = self.run_console(
            ["--profile", "generic-v1", "status", run_id]
        )
        self.assertEqual(selected.returncode, 2)
        self.assertIn(f"unknown Worktree Marshal run {run_id}", selected.stderr)
        self.assertNotIn("Triptych", selected.stderr)
        self.assertEqual(self.manifests(self.generic_profile_state), [])
        self.assertEqual(triptych_path.read_bytes(), before)
        self.assertTrue(Path(triptych_manifest["worktree"]).is_dir())

    def test_generic_profile_marker_mismatch_is_not_rewritten(self) -> None:
        initialized = self.run_console(["--profile", "generic-v1", "status"])
        self.assertEqual(initialized.returncode, 0, initialized.stderr)
        marker = self.generic_repository_state() / "profile.json"
        contents = json.loads(marker.read_text(encoding="utf-8"))
        contents["profile_id"] = "triptych"
        marker.write_text(
            json.dumps(contents, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        before = marker.read_bytes()

        rejected = self.run_console(["--profile", "generic-v1", "status"])
        self.assertEqual(rejected.returncode, 2)
        self.assertIn("profile marker does not match", rejected.stderr)
        self.assertEqual(marker.read_bytes(), before)
        self.assertEqual(self.manifests(self.generic_profile_state), [])

    def test_generic_symbolic_profile_marker_is_not_followed(self) -> None:
        initialized = self.run_console(["--profile", "generic-v1", "status"])
        self.assertEqual(initialized.returncode, 0, initialized.stderr)
        marker = self.generic_repository_state() / "profile.json"
        external = self.root / "external-profile.json"
        external.write_bytes(marker.read_bytes())
        before = external.read_bytes()
        marker.unlink()
        marker.symlink_to(external)

        rejected = self.run_console(["--profile", "generic-v1", "status"])
        self.assertEqual(rejected.returncode, 2)
        self.assertIn("profile marker", rejected.stderr)
        self.assertTrue(marker.is_symlink())
        self.assertEqual(external.read_bytes(), before)
        self.assertEqual(self.manifests(self.generic_profile_state), [])

    def test_generic_unmarked_nonempty_state_is_not_adopted(self) -> None:
        initialized = self.run_console(["--profile", "generic-v1", "status"])
        self.assertEqual(initialized.returncode, 0, initialized.stderr)
        repository_state = self.generic_repository_state()
        marker = repository_state / "profile.json"
        marker.unlink()
        entries_before = {path.name for path in repository_state.iterdir()}

        rejected = self.run_console(["--profile", "generic-v1", "status"])
        self.assertEqual(rejected.returncode, 2)
        self.assertIn("state root is unmarked and nonempty", rejected.stderr)
        self.assertFalse(marker.exists())
        self.assertEqual(
            {path.name for path in repository_state.iterdir()},
            entries_before,
        )
        self.assertEqual(self.manifests(self.generic_profile_state), [])

    def test_generic_manifest_requires_exact_profile_identity(self) -> None:
        launched = self.run_console(
            ["--profile", "generic-v1", "run", "--agent", "codex"],
            environment={"FAKE_CODEX_ACTION": "dirty"},
        )
        self.assertEqual(launched.returncode, 0, launched.stderr)
        manifest_path, original = self.only_manifest(self.generic_profile_state)
        run_id = original["run_id"]
        cases = (
            (
                "missing format",
                {key: value for key, value in original.items() if key != "format_id"},
            ),
            ("wrong profile", {**original, "profile_id": "triptych"}),
            ("wrong agent", {**original, "agent": "other"}),
        )
        for label, tampered in cases:
            with self.subTest(label=label):
                manifest_path.write_text(
                    json.dumps(tampered, indent=2, sort_keys=True) + "\n",
                    encoding="utf-8",
                )
                before = manifest_path.read_bytes()
                rejected = self.run_console(
                    ["--profile", "generic-v1", "status", run_id]
                )
                self.assertEqual(rejected.returncode, 2)
                self.assertIn("invalid manifest", rejected.stderr)
                self.assertEqual(manifest_path.read_bytes(), before)

        self.assertEqual(self.manifests(self.triptych_state), [])
        self.assertTrue(Path(original["worktree"]).is_dir())

    def test_generic_committed_run_integrates_and_cleans_its_namespace(self) -> None:
        launched = self.run_console(
            ["--profile", "generic-v1", "run", "--agent", "codex"],
            environment={"FAKE_CODEX_ACTION": "commit"},
        )
        self.assertEqual(launched.returncode, 0, launched.stderr)
        manifest_path, manifest = self.only_manifest(self.generic_profile_state)
        run_id = manifest["run_id"]
        worker_head = manifest["final_head"]
        self.assertEqual(manifest["state"], "preserved")
        self.assertFalse(manifest["dirty"])
        self.assertNotEqual(worker_head, manifest["base_sha"])

        integrated = self.run_console(
            ["--profile", "generic-v1", "integrate", run_id]
        )
        self.assertEqual(integrated.returncode, 0, integrated.stderr)
        cleaned = json.loads(manifest_path.read_text(encoding="utf-8"))
        self.assertEqual(cleaned["state"], "cleaned")
        self.assertEqual(cleaned["integrated_head"], worker_head)
        self.assertEqual(
            self.git("rev-parse", "refs/heads/main").stdout.strip(),
            worker_head,
        )
        self.assertEqual(
            (self.control / "agent-result.txt").read_text(encoding="utf-8"),
            "integrated result\n",
        )
        self.assertFalse(Path(manifest["worktree"]).exists())
        self.assertFalse(Path(manifest["tmpdir"]).exists())
        refs = set(
            self.git("for-each-ref", "--format=%(refname)").stdout.splitlines()
        )
        self.assertNotIn(f"refs/heads/{manifest['branch']}", refs)
        self.assertFalse(
            any(
                ref.startswith(
                    f"refs/worktree-marshal/generic-v1/runs/{run_id}/"
                )
                for ref in refs
            )
        )
        self.assertFalse(
            any(ref.startswith("refs/triptych-codex/runs/") for ref in refs)
        )

    def test_explicit_triptych_profile_manages_legacy_run(self) -> None:
        triptych_path, triptych_manifest = self.create_legacy_retained_run()
        run_id = triptych_manifest["run_id"]

        status = self.run_console(
            ["--profile", "triptych", "status", run_id]
        )
        self.assertEqual(status.returncode, 0, status.stderr)
        self.assertIn(run_id, status.stdout)
        self.assertIn("failed-preserved", status.stdout)

        clean = self.run_console(
            ["--profile", "triptych", "clean", run_id]
        )
        self.assertEqual(clean.returncode, 0, clean.stderr)
        cleaned = json.loads(triptych_path.read_text(encoding="utf-8"))
        self.assertEqual(cleaned["state"], "cleaned")
        self.assertFalse(Path(triptych_manifest["worktree"]).exists())
        branch = self.git(
            "show-ref",
            "--verify",
            f"refs/heads/{triptych_manifest['branch']}",
            check=False,
        )
        self.assertNotEqual(branch.returncode, 0)

    def test_explicit_triptych_run_is_visible_to_legacy_launcher(self) -> None:
        launched = self.run_console(
            ["--profile", "triptych", "run", "--agent", "codex"],
            environment={"FAKE_CODEX_EXIT": "3"},
        )
        self.assertEqual(launched.returncode, 3, launched.stderr)
        manifest_path, manifest = self.only_manifest(self.triptych_state)
        run_id = manifest["run_id"]
        self.assertEqual(manifest["state"], "failed-preserved")
        self.assertTrue(manifest["branch"].startswith("codex/isolated/"))
        self.assertNotIn("format_id", manifest)
        self.assertNotIn("profile_id", manifest)
        self.assertNotIn("agent", manifest)
        self.assertEqual(self.manifests(self.generic_profile_state), [])
        record = self.fake_records()[0]["environment"]
        self.assertEqual(record["TRIPTYCH_CODEX_ROLE"], "worker")
        self.assertEqual(record["TRIPTYCH_CODEX_RUN_ID"], run_id)
        self.assertEqual(record["TRIPTYCH_CODEX_REAL"], str(self.fake_codex))
        self.assertIsNone(record["WORKTREE_MARSHAL_ROLE"])
        self.assertIsNone(record["WORKTREE_MARSHAL_RUN_ID"])
        self.assertIsNone(record["WORKTREE_MARSHAL_PROFILE_ID"])
        self.assertIsNone(record["WORKTREE_MARSHAL_AGENT_ID"])
        self.assertIsNone(record["WORKTREE_MARSHAL_REAL_CODEX"])

        status = self.run_legacy(["--triptych-status", run_id])
        self.assertEqual(status.returncode, 0, status.stderr)
        self.assertIn(run_id, status.stdout)
        clean = self.run_legacy(["--triptych-clean", run_id])
        self.assertEqual(clean.returncode, 0, clean.stderr)
        cleaned = json.loads(manifest_path.read_text(encoding="utf-8"))
        self.assertEqual(cleaned["state"], "cleaned")

    def test_cross_profile_primary_marker_refuses_before_allocation(self) -> None:
        cases = (
            (
                "generic-v1",
                {"TRIPTYCH_CODEX_ROLE": "worker"},
            ),
            (
                "triptych",
                {"WORKTREE_MARSHAL_ROLE": "worker"},
            ),
        )
        for profile, marker in cases:
            with self.subTest(profile=profile):
                result = self.run_console(
                    ["--profile", profile, "run", "--agent", "codex"],
                    environment=marker,
                )
                self.assertEqual(result.returncode, 2)
                self.assertIn(
                    "worker marker is invalid in the primary checkout",
                    result.stderr,
                )

        self.assertEqual(self.manifests(self.generic_profile_state), [])
        self.assertEqual(self.manifests(self.triptych_state), [])
        self.assertFalse(self.fake_log.exists())
        worktrees = self.git("worktree", "list", "--porcelain").stdout
        self.assertEqual(worktrees.count("worktree "), 1)

    def test_profile_and_agent_markers_block_detached_unlocked_nesting(self) -> None:
        launched = self.run_console(
            ["--profile", "generic-v1", "run", "--agent", "codex"],
            environment={"FAKE_CODEX_ACTION": "dirty"},
        )
        self.assertEqual(launched.returncode, 0, launched.stderr)
        _, manifest = self.only_manifest(self.generic_profile_state)
        worktree = Path(manifest["worktree"])
        self.git("worktree", "unlock", str(worktree))
        self.git("switch", "--detach", cwd=worktree)
        records_before = self.fake_records()

        cases = (
            (
                "generic-v1",
                {"WORKTREE_MARSHAL_PROFILE_ID": "generic-v1"},
            ),
            (
                "generic-v1",
                {"WORKTREE_MARSHAL_AGENT_ID": "codex"},
            ),
            (
                "triptych",
                {"WORKTREE_MARSHAL_PROFILE_ID": "generic-v1"},
            ),
            (
                "triptych",
                {"WORKTREE_MARSHAL_AGENT_ID": "codex"},
            ),
        )
        for profile, marker in cases:
            with self.subTest(profile=profile, marker=marker):
                nested = self.run_console(
                    ["--profile", profile, "run", "--agent", "codex"],
                    cwd=worktree,
                    environment=marker,
                )
                self.assertEqual(nested.returncode, 2)
                self.assertIn("nested Codex launch refused", nested.stderr)

        self.assertEqual(self.fake_records(), records_before)
        self.assertEqual(len(self.manifests(self.generic_profile_state)), 1)
        self.assertEqual(self.manifests(self.triptych_state), [])

    def test_generic_real_codex_rejects_console_symlink_and_hardlink(self) -> None:
        hardlink = self.bin / "worktree-marshal-hardlink"
        symlink = self.bin / "worktree-marshal-symlink"
        os.link(self.console, hardlink)
        symlink.symlink_to(self.console)

        for candidate in (self.console, hardlink, symlink):
            with self.subTest(candidate=candidate.name):
                result = self.run_console(
                    ["--profile", "generic-v1", "run", "--agent", "codex"],
                    environment={"WORKTREE_MARSHAL_REAL_CODEX": str(candidate)},
                )
                self.assertEqual(result.returncode, 2)
                self.assertIn("non-launcher executable", result.stderr)

        self.assertEqual(self.manifests(self.generic_profile_state), [])
        self.assertFalse(self.fake_log.exists())
        worktrees = self.git("worktree", "list", "--porcelain").stdout
        self.assertEqual(worktrees.count("worktree "), 1)


if __name__ == "__main__":
    unittest.main()
