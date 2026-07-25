#!/usr/bin/env python3
"""Bounded stateful lifecycle coverage for the sdist-rebuilt wheel."""

from __future__ import annotations

import fcntl
import json
import os
import signal
import shutil
import subprocess
import time
import unittest
from dataclasses import dataclass
from pathlib import Path

if __package__:
    from ._artifact_fixture import (
        SETUPTOOLS_AVAILABLE,
        get_built_artifacts,
    )
else:
    from _artifact_fixture import (  # type: ignore[import-not-found]
        SETUPTOOLS_AVAILABLE,
        get_built_artifacts,
    )


PACKAGE_ROOT = Path(__file__).resolve().parents[1]
COMMAND_TIMEOUT_SECONDS = 60


FAKE_CODEX_SOURCE = """\
#!/usr/bin/env python3
from __future__ import annotations

import os
import subprocess
import sys
import time
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

action = os.environ.get("FAKE_CODEX_ACTION")
if action == "commit":
    result_name = os.environ.get("FAKE_CODEX_RESULT_PATH", "agent-result.txt")
    result_path = Path(result_name)
    if (
        not result_name
        or result_path == Path(".")
        or result_path.is_absolute()
        or ".." in result_path.parts
    ):
        raise SystemExit("FAKE_CODEX_RESULT_PATH must be a relative child path")
    result = root / result_path
    result.parent.mkdir(parents=True, exist_ok=True)
    result.write_text(
        os.environ.get("FAKE_CODEX_CONTENT", "installed result\\n"),
        encoding="utf-8",
    )
    git(root, "add", "--", result_path.as_posix())
    git(root, "commit", "-m", "Installed agent result")
elif action == "rewrite-sibling":
    git(root, "reset", "--hard", "HEAD^")
    rewritten = root / "rewritten-sibling-result.txt"
    rewritten.write_text(
        "installed clean rewritten sibling result\\n",
        encoding="utf-8",
    )
    git(root, "add", "--", rewritten.name)
    git(root, "commit", "-m", "Replace installed audited result")
elif action == "stage-conflict":
    conflict = root / os.environ.get(
        "FAKE_CODEX_CONFLICT_PATH",
        "agent-result.txt",
    )
    conflict.write_text(
        os.environ.get("FAKE_CODEX_CONTENT", "installed resolved result\\n"),
        encoding="utf-8",
    )
    git(root, "add", str(conflict.relative_to(root)))

ready = os.environ.get("FAKE_CODEX_READY")
release = os.environ.get("FAKE_CODEX_RELEASE")
if ready:
    Path(ready).touch()
if release:
    release_path = Path(release)
    deadline = time.monotonic() + 60
    while not release_path.exists():
        if time.monotonic() >= deadline:
            raise SystemExit(124)
        time.sleep(0.02)

raise SystemExit(int(os.environ.get("FAKE_CODEX_EXIT", "0")))
"""


@dataclass(frozen=True)
class OverlapSpecification:
    name: str
    result_path: str
    content: str
    ready: Path


@dataclass
class InstalledOverlapRun:
    specification: OverlapSpecification
    process: subprocess.Popen[str]
    manifest_path: Path
    manifest: dict
    worker: Path
    run_lock: Path
    source_head: str


class InstalledLifecycleTests(unittest.TestCase):
    maxDiff = None

    @classmethod
    def checked(
        cls,
        arguments: list[str],
        *,
        cwd: Path,
        environment: dict[str, str],
        purpose: str,
        timeout: int = COMMAND_TIMEOUT_SECONDS,
    ) -> subprocess.CompletedProcess[str]:
        result = subprocess.run(
            arguments,
            cwd=cwd,
            env=environment,
            text=True,
            capture_output=True,
            check=False,
            timeout=timeout,
        )
        if result.returncode:
            raise AssertionError(
                f"{purpose} failed with status {result.returncode}\n"
                f"stdout:\n{result.stdout}\n"
                f"stderr:\n{result.stderr}"
            )
        return result

    @classmethod
    def setUpClass(cls) -> None:
        if not SETUPTOOLS_AVAILABLE:
            raise AssertionError("setuptools build backend is unavailable")
        git = shutil.which("git")
        if git is None:
            raise AssertionError("Git is unavailable")
        cls.git_executable = Path(git).resolve()
        make = shutil.which("make")
        if make is None:
            raise AssertionError("GNU Make is unavailable")
        make_version = subprocess.run(
            [make, "--version"],
            text=True,
            capture_output=True,
            check=False,
            timeout=COMMAND_TIMEOUT_SECONDS,
        )
        if make_version.returncode or "GNU Make" not in make_version.stdout:
            raise AssertionError("GNU Make is unavailable")
        cls.make_executable = Path(make).resolve()

        artifacts = get_built_artifacts(PACKAGE_ROOT)
        cls.artifacts = artifacts
        cls.root = artifacts.root
        cls.copied_build_source = artifacts.copied_source
        cls.extracted_sdist = artifacts.extracted_sdist
        cls.venv = artifacts.venv
        cls.venv_bin = artifacts.venv_bin
        cls.venv_python = artifacts.venv_python
        cls.console = artifacts.installed_command

    def setUp(self) -> None:
        self.case = self.artifacts.new_case(
            prefix="outside-checkout-",
        )
        self.addCleanup(self.case.cleanup)
        self.lifecycle_root = Path(self.case.name)
        self.control = self.lifecycle_root / "control"
        self.consumer = self.lifecycle_root / "consumer"
        self.home = self.lifecycle_root / "home"
        self.bin = self.lifecycle_root / "bin"
        self.consumer_fragment = self.consumer / "worktree-marshal.mk"
        self.consumer_makefile = self.consumer / "Makefile"
        self.consumer_console = self.consumer / "worktree-marshal"
        self.control.mkdir(parents=True)
        self.consumer.mkdir()
        self.home.mkdir()
        self.bin.mkdir()
        self.fake_codex = self.bin / "codex"
        self.fake_codex.write_text(FAKE_CODEX_SOURCE, encoding="utf-8")
        self.fake_codex.chmod(0o755)
        self.compatibility = self.bin / "triptych-compat-installed"
        self.compatibility.write_text(
            (
                f"#!{self.venv_python}\n"
                "from pathlib import Path\n"
                "from worktree_marshal import triptych_compat\n\n"
                "raise SystemExit(\n"
                "    triptych_compat.main(invocation_path=Path(__file__).resolve())\n"
                ")\n"
            ),
            encoding="utf-8",
        )
        self.compatibility.chmod(0o755)
        self.generic_state = self.lifecycle_root / "generic-state"
        self.triptych_state = self.lifecycle_root / "triptych-state"

        self.git("init", "-b", "main")
        self.git("config", "user.name", "Worktree Marshal Installed Test")
        self.git("config", "user.email", "marshal-installed@example.invalid")
        self.git("config", "commit.gpgSign", "false")
        (self.control / "baseline.txt").write_text("baseline\n", encoding="utf-8")
        self.git("add", "baseline.txt")
        self.git("commit", "-m", "Synthetic installed baseline")
        self.installed_origins = self.prepare_installed_consumer()

    @property
    def generic_profile_state(self) -> Path:
        return self.generic_state / "profiles" / "generic-v1"

    def environment(self, additions: dict[str, str] | None = None) -> dict[str, str]:
        environment = os.environ.copy()
        for name in list(environment):
            if (
                name.startswith("WORKTREE_MARSHAL_")
                or name.startswith("TRIPTYCH_CODEX_")
                or name.startswith("FAKE_CODEX_")
                or name
                in {
                    "GIT_ALTERNATE_OBJECT_DIRECTORIES",
                    "GIT_COMMON_DIR",
                    "GIT_DIR",
                    "GIT_INDEX_FILE",
                    "GIT_OBJECT_DIRECTORY",
                    "GIT_PREFIX",
                    "GIT_WORK_TREE",
                    "GNUMAKEFLAGS",
                    "MAKEFILES",
                    "MAKEFLAGS",
                    "MAKELEVEL",
                    "MAKEOVERRIDES",
                    "MFLAGS",
                    "PYTHONHOME",
                    "PYTHONPATH",
                    "RUN",
                }
            ):
                environment.pop(name, None)
        search_path = [
            str(self.venv_bin),
            str(self.git_executable.parent),
            *os.defpath.split(os.pathsep),
        ]
        environment.update(
            {
                "HOME": str(self.home),
                "PATH": os.pathsep.join(dict.fromkeys(search_path)),
                "GIT_CONFIG_GLOBAL": os.devnull,
                "GIT_CONFIG_NOSYSTEM": "1",
                "PYTHONDONTWRITEBYTECODE": "1",
                "PYTHONNOUSERSITE": "1",
                "XDG_STATE_HOME": str(self.lifecycle_root / "xdg-state"),
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
    ) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [str(self.git_executable), *arguments],
            cwd=cwd or self.control,
            env=self.environment(),
            text=True,
            capture_output=True,
            check=check,
            timeout=COMMAND_TIMEOUT_SECONDS,
        )

    def run_console(
        self,
        *arguments: str,
        environment: dict[str, str] | None = None,
    ) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [str(self.console), *arguments],
            cwd=self.control,
            env=self.environment(environment),
            text=True,
            capture_output=True,
            check=False,
            timeout=COMMAND_TIMEOUT_SECONDS,
        )

    def run_compatibility(
        self,
        *arguments: str,
        environment: dict[str, str] | None = None,
    ) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [str(self.compatibility), *arguments],
            cwd=self.control,
            env=self.environment(environment),
            text=True,
            capture_output=True,
            check=False,
            timeout=COMMAND_TIMEOUT_SECONDS,
        )

    def run_make(
        self,
        *arguments: str,
        environment: dict[str, str] | None = None,
    ) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [
                str(self.make_executable),
                "--no-print-directory",
                "-f",
                str(self.consumer_makefile),
                *arguments,
            ],
            cwd=self.control,
            env=self.environment(environment),
            text=True,
            capture_output=True,
            check=False,
            timeout=COMMAND_TIMEOUT_SECONDS,
        )

    @staticmethod
    def manifests(state_root: Path) -> set[Path]:
        return set(state_root.glob("*/runs/*.json"))

    @staticmethod
    def manifest_snapshot(path: Path) -> tuple[bytes, int, int]:
        metadata = path.stat()
        return path.read_bytes(), metadata.st_mode, metadata.st_mtime_ns

    def prepare_installed_consumer(self) -> dict[str, Path]:
        provenance = self.checked(
            [
                str(self.venv_python),
                "-c",
                "\n".join(
                    (
                        "import json",
                        "from importlib.resources import files",
                        "import worktree_marshal",
                        "import worktree_marshal.git as git_policy",
                        "import worktree_marshal.identity as identity",
                        "import worktree_marshal.locks as locks",
                        "import worktree_marshal.model as model",
                        "import worktree_marshal.process as process_policy",
                        "import worktree_marshal.resources as resources",
                        "import worktree_marshal.state as state_policy",
                        (
                            "from worktree_marshal import "
                            "cli, engine, profiles, triptych_compat"
                        ),
                        (
                            "fragment = files('worktree_marshal.resources')"
                            ".joinpath('worktree-marshal.mk')"
                        ),
                        "print(json.dumps({",
                        "    'package': worktree_marshal.__file__,",
                        "    'cli': cli.__file__,",
                        "    'engine': engine.__file__,",
                        "    'git': git_policy.__file__,",
                        "    'identity': identity.__file__,",
                        "    'locks': locks.__file__,",
                        "    'model': model.__file__,",
                        "    'process': process_policy.__file__,",
                        "    'profiles': profiles.__file__,",
                        "    'triptych_compat': triptych_compat.__file__,",
                        "    'resources': resources.__file__,",
                        "    'state': state_policy.__file__,",
                        "    'make_fragment': str(fragment),",
                        "}, sort_keys=True))",
                    )
                ),
            ],
            cwd=self.control,
            environment=self.environment(),
            purpose="installed-package provenance check",
        )
        origins = {
            name: Path(value).resolve()
            for name, value in json.loads(provenance.stdout).items()
        }
        for name, origin in origins.items():
            with self.subTest(installed_origin=name):
                self.assertTrue(origin.is_relative_to(self.venv), origin)
                self.assertFalse(origin.is_relative_to(PACKAGE_ROOT), origin)
                self.assertTrue(origin.is_file(), origin)

        installed_fragment = origins["make_fragment"]
        shutil.copy2(installed_fragment, self.consumer_fragment)
        self.consumer_console.symlink_to(self.console)
        self.consumer_makefile.write_text(
            (
                "override WORKTREE_MARSHAL := ../consumer/worktree-marshal\n"
                "include ../consumer/worktree-marshal.mk\n"
            ),
            encoding="utf-8",
        )
        self.assertEqual(
            self.consumer_fragment.read_bytes(),
            installed_fragment.read_bytes(),
        )
        self.assertFalse(
            self.consumer_makefile.resolve().is_relative_to(self.control.resolve())
        )
        self.assertFalse(
            self.consumer_fragment.resolve().is_relative_to(self.control.resolve())
        )
        self.assertEqual(self.consumer_console.resolve(), self.console.resolve())
        self.assertEqual(self.git("status", "--porcelain").stdout, "")
        return origins

    def active_rebase_paths(self, worker: Path) -> list[Path]:
        paths: list[Path] = []
        for name in ("rebase-merge", "rebase-apply"):
            path = Path(
                self.git(
                    "rev-parse",
                    "--git-path",
                    name,
                    cwd=worker,
                ).stdout.strip()
            )
            if not path.is_absolute():
                path = worker / path
            if path.exists():
                paths.append(path)
        return paths

    def worktree_paths(self) -> list[Path]:
        return [
            Path(line.removeprefix("worktree ")).resolve()
            for line in self.git("worktree", "list", "--porcelain").stdout.splitlines()
            if line.startswith("worktree ")
        ]

    def worktree_records(self) -> dict[Path, dict[str, str]]:
        records: dict[Path, dict[str, str]] = {}
        output = self.git("worktree", "list", "--porcelain").stdout
        for block in output.strip().split("\n\n"):
            fields: dict[str, str] = {}
            for line in block.splitlines():
                name, separator, value = line.partition(" ")
                fields[name] = value if separator else ""
            worktree = fields.get("worktree")
            if worktree is not None:
                records[Path(worktree).resolve()] = fields
        return records

    def refs_under(self, prefix: str) -> list[str]:
        return self.git(
            "for-each-ref",
            "--format=%(refname)",
            prefix,
        ).stdout.splitlines()

    @staticmethod
    def file_lock_is_held(path: Path) -> bool:
        with path.open("r+", encoding="utf-8") as stream:
            try:
                fcntl.flock(stream.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                return True
            fcntl.flock(stream.fileno(), fcntl.LOCK_UN)
        return False

    @staticmethod
    def process_group_exists(process: subprocess.Popen[str]) -> bool:
        try:
            os.killpg(process.pid, 0)
        except ProcessLookupError:
            return False
        return True

    @classmethod
    def wait_for_process_group(
        cls,
        process: subprocess.Popen[str],
        timeout: float,
    ) -> bool:
        deadline = time.monotonic() + timeout
        while cls.process_group_exists(process):
            if time.monotonic() >= deadline:
                return False
            time.sleep(0.02)
        return True

    @classmethod
    def reap_process_groups(
        cls,
        processes: list[subprocess.Popen[str]],
        release: Path,
    ) -> None:
        release.touch(exist_ok=True)
        for process in processes:
            try:
                process.communicate(timeout=5)
            except subprocess.TimeoutExpired:
                try:
                    os.killpg(process.pid, signal.SIGTERM)
                except ProcessLookupError:
                    pass
                try:
                    process.communicate(timeout=5)
                except subprocess.TimeoutExpired:
                    try:
                        os.killpg(process.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    try:
                        process.communicate(timeout=5)
                    except subprocess.TimeoutExpired:
                        pass
            if not cls.process_group_exists(process):
                continue
            try:
                os.killpg(process.pid, signal.SIGTERM)
            except ProcessLookupError:
                continue
            if cls.wait_for_process_group(process, 2):
                continue
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                continue
            if not cls.wait_for_process_group(process, 2):
                raise AssertionError(
                    "installed launcher process group survived cleanup"
                )

    def start_overlap_process(
        self,
        specification: OverlapSpecification,
        release: Path,
    ) -> subprocess.Popen[str]:
        return subprocess.Popen(
            [
                str(self.console),
                "--profile",
                "generic-v1",
                "run",
                "--agent",
                "codex",
            ],
            cwd=self.control,
            env=self.environment(
                {
                    "FAKE_CODEX_ACTION": "commit",
                    "FAKE_CODEX_RESULT_PATH": specification.result_path,
                    "FAKE_CODEX_CONTENT": specification.content,
                    "FAKE_CODEX_READY": str(specification.ready),
                    "FAKE_CODEX_RELEASE": str(release),
                }
            ),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            start_new_session=True,
        )

    def await_overlap_barrier(
        self,
        runs: list[tuple[OverlapSpecification, subprocess.Popen[str]]],
    ) -> None:
        deadline = time.monotonic() + 30
        while not all(specification.ready.is_file() for specification, _ in runs):
            for specification, process in runs:
                if process.poll() is None:
                    continue
                stdout, stderr = process.communicate()
                self.fail(
                    f"{specification.name} installed launcher exited before the "
                    f"overlap barrier with status {process.returncode}\n"
                    f"stdout:\n{stdout}\nstderr:\n{stderr}"
                )
            if time.monotonic() >= deadline:
                self.fail("installed launchers did not reach the overlap barrier")
            time.sleep(0.02)
        for _, process in runs:
            self.assertIsNone(process.poll())

    def assert_live_overlap_run(
        self,
        run: InstalledOverlapRun,
        peer: InstalledOverlapRun,
        base_head: str,
        record: dict[str, str],
    ) -> None:
        manifest = run.manifest
        branch = manifest["branch"]
        result = run.worker / run.specification.result_path
        self.assertEqual(manifest["state"], "running")
        self.assertEqual(
            (
                manifest["schema_version"],
                manifest["format_id"],
                manifest["profile_id"],
                manifest["agent"],
            ),
            (1, "worktree-marshal-run", "generic-v1", "codex"),
        )
        self.assertEqual(manifest["base_sha"], base_head)
        self.assertEqual(manifest["target_ref"], "refs/heads/main")
        self.assertNotEqual(run.manifest["run_id"], peer.manifest["run_id"])
        self.assertNotEqual(branch, peer.manifest["branch"])
        self.assertNotEqual(run.worker, peer.worker)
        self.assertNotEqual(manifest["tmpdir"], peer.manifest["tmpdir"])
        self.assertTrue(Path(manifest["tmpdir"]).is_dir())
        self.assertEqual(
            result.read_text(encoding="utf-8"),
            run.specification.content,
        )
        self.assertFalse((run.worker / peer.specification.result_path).exists())
        self.assertEqual(
            (run.worker / "baseline.txt").read_text(encoding="utf-8"),
            "baseline\n",
        )
        self.assertEqual(
            self.git(
                "diff-tree",
                "--no-commit-id",
                "--name-only",
                "-r",
                run.source_head,
            ).stdout.splitlines(),
            [run.specification.result_path],
        )
        self.assertEqual(
            self.git(
                "status",
                "--porcelain=v1",
                "--untracked-files=all",
                cwd=run.worker,
            ).stdout,
            "",
        )
        self.assertEqual(
            self.git("rev-parse", f"refs/heads/{branch}").stdout.strip(),
            run.source_head,
        )
        self.assertEqual(
            self.git("rev-parse", "HEAD^", cwd=run.worker).stdout.strip(),
            base_head,
        )
        self.assertEqual(record["branch"], f"refs/heads/{branch}")
        self.assertEqual(record["HEAD"], run.source_head)
        self.assertEqual(
            record["locked"],
            f"worktree-marshal generic-v1 {manifest['run_id']}",
        )
        self.assertTrue(self.file_lock_is_held(run.run_lock))

    def assert_cleaned_overlap_run(self, run: InstalledOverlapRun) -> dict:
        cleaned = json.loads(run.manifest_path.read_text(encoding="utf-8"))
        self.assertEqual(cleaned["state"], "cleaned")
        self.assertFalse(run.worker.exists())
        self.assertFalse(Path(run.manifest["tmpdir"]).exists())
        self.assertIsNone(self.ref_oid(f"refs/heads/{run.manifest['branch']}"))
        self.assertEqual(
            self.refs_under(
                "refs/worktree-marshal/generic-v1/"
                f"runs/{run.manifest['run_id']}/"
            ),
            [],
        )
        return cleaned

    def ref_oid(self, ref: str) -> str | None:
        result = self.git("rev-parse", "--verify", ref, check=False)
        return result.stdout.strip() if result.returncode == 0 else None

    def launch_and_read_manifest(
        self,
        state_root: Path,
        *arguments: str,
        expected_status: int,
        environment: dict[str, str] | None = None,
        compatibility: bool = False,
    ) -> tuple[Path, dict]:
        before = self.manifests(state_root)
        runner = self.run_compatibility if compatibility else self.run_console
        launched = runner(*arguments, environment=environment)
        self.assertEqual(launched.returncode, expected_status, launched.stderr)
        created = self.manifests(state_root) - before
        self.assertEqual(len(created), 1, created)
        path = created.pop()
        return path, json.loads(path.read_text(encoding="utf-8"))

    def test_sdist_rebuilt_wheel_runs_generic_and_triptych_lifecycles(self) -> None:
        self.assertFalse(self.control.resolve().is_relative_to(PACKAGE_ROOT))
        self.assertFalse(self.copied_build_source.exists())
        self.assertFalse(self.extracted_sdist.exists())
        self.assertNotIn("PYTHONPATH", self.environment())
        self.assertNotIn("PYTHONHOME", self.environment())
        self.assertTrue(self.compatibility.resolve().is_relative_to(self.lifecycle_root))
        self.assertTrue(self.venv_python.is_relative_to(self.venv))
        self.assertEqual(
            self.compatibility.read_text(encoding="utf-8").splitlines()[0],
            f"#!{self.venv_python}",
        )

        hardlink = self.bin / "worktree-marshal-hardlink"
        symlink = self.bin / "worktree-marshal-symlink"
        os.link(self.console, hardlink)
        symlink.symlink_to(self.console)
        for candidate in (self.console, hardlink, symlink):
            with self.subTest(real_agent=candidate.name):
                rejected = self.run_console(
                    "--profile",
                    "generic-v1",
                    "run",
                    "--agent",
                    "codex",
                    environment={"WORKTREE_MARSHAL_REAL_CODEX": str(candidate)},
                )
                self.assertEqual(rejected.returncode, 2, rejected.stderr)
                self.assertIn("non-launcher executable", rejected.stderr)
        self.assertEqual(self.manifests(self.generic_profile_state), set())
        self.assertEqual(self.manifests(self.triptych_state), set())
        worktrees = self.git("worktree", "list", "--porcelain").stdout
        self.assertEqual(worktrees.count("worktree "), 1)

        before_committed = self.manifests(self.generic_profile_state)
        committed_launch = self.run_make(
            "codex",
            environment={"FAKE_CODEX_ACTION": "commit"},
        )
        self.assertEqual(
            committed_launch.returncode,
            0,
            committed_launch.stderr,
        )
        created_committed = (
            self.manifests(self.generic_profile_state) - before_committed
        )
        self.assertEqual(len(created_committed), 1, created_committed)
        committed_path = created_committed.pop()
        committed = json.loads(committed_path.read_text(encoding="utf-8"))
        committed_id = committed["run_id"]
        committed_head = committed["final_head"]
        self.assertEqual(committed["state"], "preserved")
        self.assertFalse(committed["dirty"])
        self.assertEqual(committed["profile_id"], "generic-v1")
        self.assertEqual(committed["agent"], "codex")

        generic_before_cross_profile = self.manifest_snapshot(committed_path)
        cross_profile = self.run_console(
            "--profile", "triptych", "status", committed_id
        )
        self.assertEqual(cross_profile.returncode, 2, cross_profile.stderr)
        self.assertIn(
            f"unknown Triptych Codex run {committed_id}",
            cross_profile.stderr,
        )
        self.assertEqual(
            self.manifest_snapshot(committed_path),
            generic_before_cross_profile,
        )
        self.assertFalse(
            any(path.stem == committed_id for path in self.manifests(self.triptych_state))
        )
        self.assertTrue(Path(committed["worktree"]).is_dir())

        status = self.run_make("status", f"RUN={committed_id}")
        self.assertEqual(status.returncode, 0, status.stderr)
        self.assertIn(committed_id, status.stdout)
        self.assertIn("preserved", status.stdout)

        integrated = self.run_make("integrate", f"RUN={committed_id}")
        self.assertEqual(integrated.returncode, 0, integrated.stderr)
        committed_cleaned = json.loads(committed_path.read_text(encoding="utf-8"))
        self.assertEqual(committed_cleaned["state"], "cleaned")
        self.assertEqual(committed_cleaned["integrated_head"], committed_head)
        self.assertEqual(
            self.git("rev-parse", "refs/heads/main").stdout.strip(),
            committed_head,
        )
        self.assertEqual(
            (self.control / "agent-result.txt").read_text(encoding="utf-8"),
            "installed result\n",
        )
        self.assertEqual(self.git("status", "--porcelain").stdout, "")
        self.assertFalse(Path(committed["worktree"]).exists())
        self.assertFalse(Path(committed["tmpdir"]).exists())

        clean_path, clean_run = self.launch_and_read_manifest(
            self.generic_profile_state,
            "--profile",
            "generic-v1",
            "run",
            "--agent",
            "codex",
            expected_status=3,
            environment={"FAKE_CODEX_EXIT": "3"},
        )
        self.assertEqual(clean_run["state"], "failed-preserved")
        self.assertFalse(clean_run["dirty"])
        cleaned = self.run_make("clean-run", f"RUN={clean_run['run_id']}")
        self.assertEqual(cleaned.returncode, 0, cleaned.stderr)
        self.assertEqual(
            json.loads(clean_path.read_text(encoding="utf-8"))["state"],
            "cleaned",
        )
        self.assertFalse(Path(clean_run["worktree"]).exists())
        self.assertFalse(Path(clean_run["tmpdir"]).exists())

        compatibility_path, compatibility_run = self.launch_and_read_manifest(
            self.triptych_state,
            "installed compatibility run",
            expected_status=3,
            environment={"FAKE_CODEX_EXIT": "3"},
            compatibility=True,
        )
        compatibility_id = compatibility_run["run_id"]
        self.assertEqual(compatibility_run["state"], "failed-preserved")
        self.assertNotIn("profile_id", compatibility_run)
        self.assertNotIn("agent", compatibility_run)

        compatibility_before_cross_profile = self.manifest_snapshot(
            compatibility_path
        )
        generic_cross_profile = self.run_console(
            "--profile", "generic-v1", "status", compatibility_id
        )
        self.assertEqual(
            generic_cross_profile.returncode,
            2,
            generic_cross_profile.stderr,
        )
        self.assertIn(
            f"unknown Worktree Marshal run {compatibility_id}",
            generic_cross_profile.stderr,
        )
        self.assertEqual(
            self.manifest_snapshot(compatibility_path),
            compatibility_before_cross_profile,
        )
        self.assertFalse(
            any(
                path.stem == compatibility_id
                for path in self.manifests(self.generic_profile_state)
            )
        )
        self.assertTrue(Path(compatibility_run["worktree"]).is_dir())

        compatibility_status = self.run_console(
            "--profile", "triptych", "status", compatibility_id
        )
        self.assertEqual(
            compatibility_status.returncode,
            0,
            compatibility_status.stderr,
        )
        self.assertIn(compatibility_id, compatibility_status.stdout)
        self.assertIn("failed-preserved", compatibility_status.stdout)
        compatibility_cleaned = self.run_console(
            "--profile", "triptych", "clean", compatibility_id
        )
        self.assertEqual(
            compatibility_cleaned.returncode,
            0,
            compatibility_cleaned.stderr,
        )
        self.assertEqual(
            json.loads(compatibility_path.read_text(encoding="utf-8"))["state"],
            "cleaned",
        )
        self.assertFalse(Path(compatibility_run["worktree"]).exists())

        triptych_path, triptych = self.launch_and_read_manifest(
            self.triptych_state,
            "--profile",
            "triptych",
            "run",
            "--agent",
            "codex",
            expected_status=3,
            environment={"FAKE_CODEX_EXIT": "3"},
        )
        triptych_id = triptych["run_id"]
        self.assertEqual(triptych["state"], "failed-preserved")
        self.assertNotIn("profile_id", triptych)
        self.assertNotIn("agent", triptych)
        triptych_status = self.run_compatibility(
            "--triptych-status", triptych_id
        )
        self.assertEqual(triptych_status.returncode, 0, triptych_status.stderr)
        self.assertIn(triptych_id, triptych_status.stdout)
        self.assertIn("failed-preserved", triptych_status.stdout)
        triptych_cleaned = self.run_compatibility(
            "--triptych-clean", triptych_id
        )
        self.assertEqual(triptych_cleaned.returncode, 0, triptych_cleaned.stderr)
        self.assertEqual(
            json.loads(triptych_path.read_text(encoding="utf-8"))["state"],
            "cleaned",
        )
        self.assertFalse(Path(triptych["worktree"]).exists())
        self.assertEqual(
            self.manifests(self.triptych_state),
            {compatibility_path, triptych_path},
        )

    def test_installed_overlapping_generic_runs_land_as_flat_serial_history(
        self,
    ) -> None:
        base_head = self.git("rev-parse", "HEAD").stdout.strip()
        release = self.lifecycle_root / "overlapping.release"
        specifications = [
            OverlapSpecification(
                "first",
                "parallel-first.txt",
                "installed parallel first\n",
                self.lifecycle_root / "parallel-first.ready",
            ),
            OverlapSpecification(
                "second",
                "parallel-second.txt",
                "installed parallel second\n",
                self.lifecycle_root / "parallel-second.ready",
            ),
        ]
        processes: list[subprocess.Popen[str]] = []
        self.addCleanup(self.reap_process_groups, processes, release)
        pending: list[
            tuple[OverlapSpecification, subprocess.Popen[str]]
        ] = []
        for specification in specifications:
            process = self.start_overlap_process(specification, release)
            processes.append(process)
            pending.append((specification, process))
        self.await_overlap_barrier(pending)

        manifest_paths = self.manifests(self.generic_profile_state)
        self.assertEqual(len(manifest_paths), 2, manifest_paths)
        live_by_worktree: dict[Path, tuple[Path, dict]] = {}
        for manifest_path in manifest_paths:
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            live_by_worktree[Path(manifest["worktree"]).resolve()] = (
                manifest_path,
                manifest,
            )
        self.assertEqual(len(live_by_worktree), 2)

        runs: list[InstalledOverlapRun] = []
        for specification, process in pending:
            matches = [
                worker
                for worker in live_by_worktree
                if (worker / specification.result_path).is_file()
            ]
            self.assertEqual(len(matches), 1, matches)
            worker = matches[0]
            manifest_path, manifest = live_by_worktree[worker]
            runs.append(
                InstalledOverlapRun(
                    specification=specification,
                    process=process,
                    manifest_path=manifest_path,
                    manifest=manifest,
                    worker=worker,
                    run_lock=manifest_path.with_suffix(".lock"),
                    source_head=self.git(
                        "rev-parse",
                        "HEAD",
                        cwd=worker,
                    ).stdout.strip(),
                )
            )

        first, second = runs
        records = self.worktree_records()
        self.assertEqual(
            set(records),
            {self.control.resolve(), first.worker, second.worker},
        )
        self.assert_live_overlap_run(first, second, base_head, records[first.worker])
        self.assert_live_overlap_run(second, first, base_head, records[second.worker])
        self.assertNotEqual(first.source_head, second.source_head)
        self.assertEqual(self.git("rev-parse", "HEAD").stdout.strip(), base_head)
        self.assertEqual(
            self.git(
                "status",
                "--porcelain=v1",
                "--untracked-files=all",
            ).stdout,
            "",
        )
        self.assertFalse(self.triptych_state.exists())
        self.assertEqual(self.refs_under("refs/heads/codex/isolated/"), [])
        self.assertEqual(self.refs_under("refs/triptych-codex/"), [])
        self.assertEqual(
            self.refs_under("refs/worktree-marshal/generic-v1/runs/"),
            [],
        )

        release.touch()
        for run in runs:
            stdout, stderr = run.process.communicate(
                timeout=COMMAND_TIMEOUT_SECONDS
            )
            self.assertEqual(
                run.process.returncode,
                0,
                (
                    run.specification.name,
                    run.process.returncode,
                    stdout,
                    stderr,
                ),
            )
            run.manifest = json.loads(
                run.manifest_path.read_text(encoding="utf-8")
            )
            self.assertEqual(run.manifest["state"], "preserved")
            self.assertFalse(run.manifest["dirty"])
            self.assertEqual(run.manifest["final_head"], run.source_head)
            self.assertEqual(
                self.ref_oid(f"refs/heads/{run.manifest['branch']}"),
                run.source_head,
            )
            self.assertFalse(self.file_lock_is_held(run.run_lock))

        second_manifest_snapshot = self.manifest_snapshot(second.manifest_path)
        second_status = self.git(
            "status",
            "--porcelain=v1",
            "--untracked-files=all",
            cwd=second.worker,
        ).stdout
        second_record = self.worktree_records()[second.worker].copy()

        integrated_first = self.run_make(
            "integrate",
            f"RUN={first.manifest['run_id']}",
        )
        self.assertEqual(
            integrated_first.returncode,
            0,
            integrated_first.stderr,
        )
        first_landed = self.git("rev-parse", "HEAD").stdout.strip()
        self.assertEqual(first_landed, first.source_head)
        first_cleaned = self.assert_cleaned_overlap_run(first)
        self.assertEqual(first_cleaned["final_head"], first.source_head)
        self.assertEqual(first_cleaned["integrated_head"], first_landed)
        self.assertEqual(
            self.manifest_snapshot(second.manifest_path),
            second_manifest_snapshot,
        )
        self.assertEqual(
            self.git("rev-parse", "HEAD", cwd=second.worker).stdout.strip(),
            second.source_head,
        )
        self.assertEqual(
            self.git(
                "status",
                "--porcelain=v1",
                "--untracked-files=all",
                cwd=second.worker,
            ).stdout,
            second_status,
        )
        self.assertEqual(
            self.worktree_records()[second.worker],
            second_record,
        )
        self.assertEqual(
            (self.control / first.specification.result_path).read_text(
                encoding="utf-8"
            ),
            first.specification.content,
        )
        self.assertFalse(
            (self.control / second.specification.result_path).exists()
        )

        integrated_second = self.run_make(
            "integrate",
            f"RUN={second.manifest['run_id']}",
        )
        self.assertEqual(
            integrated_second.returncode,
            0,
            integrated_second.stderr,
        )
        final_head = self.git("rev-parse", "HEAD").stdout.strip()
        second_cleaned = self.assert_cleaned_overlap_run(second)
        self.assertEqual(second_cleaned["final_head"], second.source_head)
        self.assertEqual(
            second_cleaned["integration_source_head"],
            second.source_head,
        )
        self.assertEqual(
            second_cleaned["integration_target_head"],
            first_landed,
        )
        self.assertEqual(
            second_cleaned["integration_candidate_head"],
            final_head,
        )
        self.assertEqual(second_cleaned["integrated_head"], final_head)
        self.assertNotIn(
            final_head,
            {first_landed, second.source_head},
        )
        self.assertEqual(
            self.git("rev-parse", "HEAD^").stdout.strip(),
            first_landed,
        )
        self.assertEqual(
            self.git(
                "diff-tree",
                "--no-commit-id",
                "--name-only",
                "-r",
                final_head,
            ).stdout.splitlines(),
            [second.specification.result_path],
        )
        self.assertEqual(
            self.git(
                "rev-list",
                "--count",
                f"{base_head}..HEAD",
            ).stdout.strip(),
            "2",
        )
        self.assertEqual(
            self.git(
                "rev-list",
                "--merges",
                f"{base_head}..HEAD",
            ).stdout,
            "",
        )
        self.assertEqual(
            self.git(
                "merge-base",
                "--is-ancestor",
                second.source_head,
                final_head,
                check=False,
            ).returncode,
            1,
        )
        self.assertEqual(
            self.git(
                "ls-tree",
                "-r",
                "--name-only",
                "HEAD",
            ).stdout.splitlines(),
            [
                "baseline.txt",
                first.specification.result_path,
                second.specification.result_path,
            ],
        )
        self.assertEqual(
            (self.control / "baseline.txt").read_text(encoding="utf-8"),
            "baseline\n",
        )
        for run in runs:
            self.assertEqual(
                (self.control / run.specification.result_path).read_text(
                    encoding="utf-8"
                ),
                run.specification.content,
            )
        self.assertEqual(
            self.git(
                "status",
                "--porcelain=v1",
                "--untracked-files=all",
            ).stdout,
            "",
        )
        self.assertEqual(self.worktree_paths(), [self.control.resolve()])
        self.assertEqual(
            self.manifests(self.generic_profile_state),
            {first.manifest_path, second.manifest_path},
        )
        self.assertFalse(self.triptych_state.exists())
        self.assertEqual(self.refs_under("refs/heads/codex/isolated/"), [])
        self.assertEqual(self.refs_under("refs/triptych-codex/"), [])

    def test_installed_generic_retirement_is_exact_and_idempotent(self) -> None:
        manifest_path, initial = self.launch_and_read_manifest(
            self.generic_profile_state,
            "--profile",
            "generic-v1",
            "run",
            "--agent",
            "codex",
            expected_status=0,
            environment={
                "FAKE_CODEX_ACTION": "commit",
                "FAKE_CODEX_CONTENT": "installed audited retirement result\n",
            },
        )
        run_id = initial["run_id"]
        worker = Path(initial["worktree"])
        temporary = Path(initial["tmpdir"])
        final_head = initial["final_head"]
        base_head = initial["base_sha"]
        target_ref = initial["target_ref"]
        selected_checkpoint = self.git(
            "rev-parse",
            "--verify",
            f"{target_ref}^{{commit}}",
        ).stdout.strip()
        self.assertEqual(selected_checkpoint, base_head)
        self.assertEqual(initial["state"], "preserved")
        self.assertFalse(initial["dirty"])
        self.assertEqual(
            self.git("rev-parse", f"{final_head}^").stdout.strip(),
            base_head,
        )

        reopened = self.run_console(
            "--profile",
            "generic-v1",
            "reopen",
            run_id,
            environment={"FAKE_CODEX_ACTION": "rewrite-sibling"},
        )
        self.assertEqual(reopened.returncode, 0, reopened.stderr)
        quarantined = json.loads(
            manifest_path.read_text(encoding="utf-8")
        )
        discard_head = quarantined["observed_head"]
        branch_ref = f"refs/heads/{quarantined['branch']}"
        private_prefix = (
            f"refs/worktree-marshal/generic-v1/runs/{run_id}/"
        )
        anchor_ref = f"{private_prefix}retirement-discard"
        receipt_ref = f"{private_prefix}retirement-receipt"
        self.assertEqual(quarantined["state"], "quarantined")
        self.assertEqual(
            (
                quarantined["schema_version"],
                quarantined["format_id"],
                quarantined["profile_id"],
                quarantined["agent"],
            ),
            (1, "worktree-marshal-run", "generic-v1", "codex"),
        )
        self.assertEqual(quarantined["final_head"], final_head)
        self.assertFalse(quarantined["observed_dirty"])
        self.assertEqual(
            quarantined["quarantine_reason"],
            (
                "the retained worker history no longer descends from its "
                "last terminal audit"
            ),
        )
        self.assertNotEqual(discard_head, final_head)
        self.assertEqual(
            self.git("rev-parse", f"{discard_head}^").stdout.strip(),
            base_head,
        )
        self.assertEqual(
            self.git(
                "merge-base",
                "--is-ancestor",
                final_head,
                discard_head,
                check=False,
            ).returncode,
            1,
        )
        self.assertEqual(
            self.git("rev-parse", "HEAD", cwd=worker).stdout.strip(),
            discard_head,
        )
        self.assertEqual(self.ref_oid(branch_ref), discard_head)
        self.assertEqual(
            self.git(
                "status",
                "--porcelain=v1",
                "--untracked-files=all",
                cwd=worker,
            ).stdout,
            "",
        )
        self.assertEqual(
            self.git(
                "diff-tree",
                "--no-commit-id",
                "--name-only",
                "-r",
                final_head,
            ).stdout.splitlines(),
            ["agent-result.txt"],
        )
        self.assertEqual(
            self.git(
                "diff-tree",
                "--no-commit-id",
                "--name-only",
                "-r",
                discard_head,
            ).stdout.splitlines(),
            ["rewritten-sibling-result.txt"],
        )
        worker_record = self.worktree_records()[worker.resolve()]
        self.assertEqual(
            worker_record["locked"],
            f"worktree-marshal generic-v1 {run_id}",
        )
        self.assertTrue(temporary.is_dir())
        self.assertEqual(self.refs_under(private_prefix), [])

        nested_temporary = temporary / "downloads" / "source"
        nested_temporary.mkdir(parents=True)
        temporary_sentinel = nested_temporary / "sentinel.bin"
        temporary_sentinel_bytes = b"installed retirement temporary sentinel"
        temporary_sentinel.write_bytes(temporary_sentinel_bytes)
        temporary_metadata = temporary.stat()
        adjacent_temporary = temporary.parent / "retirement-neighbor"
        adjacent_temporary.mkdir()
        adjacent_sentinel = adjacent_temporary / "preserved.txt"
        adjacent_sentinel.write_text(
            "adjacent retirement state survives\n",
            encoding="utf-8",
        )
        (self.control / "retirement-target.txt").write_text(
            "independent target result\n",
            encoding="utf-8",
        )
        self.git("add", "retirement-target.txt")
        self.git("commit", "-m", "Advance installed retirement target")
        target_head = self.git("rev-parse", "HEAD").stdout.strip()
        survivor_ref = "refs/heads/retirement-survivor"
        self.git("update-ref", survivor_ref, target_head)
        self.assertEqual(
            self.git(
                "merge-base",
                "--is-ancestor",
                discard_head,
                target_head,
                check=False,
            ).returncode,
            1,
        )

        control_head = self.git("rev-parse", "HEAD").stdout.strip()
        control_tree = self.git("write-tree").stdout.strip()
        control_status = self.git(
            "status",
            "--porcelain=v1",
            "--untracked-files=all",
        ).stdout
        quarantine_snapshot = self.manifest_snapshot(manifest_path)
        worker_metadata = worker.stat()

        def assert_quarantine_unchanged(
            refusal: subprocess.CompletedProcess[str],
        ) -> None:
            self.assertEqual(refusal.returncode, 2, refusal.stderr)
            self.assertEqual(
                self.manifest_snapshot(manifest_path),
                quarantine_snapshot,
            )
            retained_metadata = worker.stat()
            self.assertEqual(
                (retained_metadata.st_dev, retained_metadata.st_ino),
                (worker_metadata.st_dev, worker_metadata.st_ino),
            )
            self.assertEqual(
                self.worktree_records()[worker.resolve()],
                worker_record,
            )
            self.assertEqual(
                self.git("rev-parse", "HEAD", cwd=worker).stdout.strip(),
                discard_head,
            )
            self.assertEqual(self.ref_oid(branch_ref), discard_head)
            self.assertEqual(
                self.git(
                    "status",
                    "--porcelain=v1",
                    "--untracked-files=all",
                    cwd=worker,
                ).stdout,
                "",
            )
            self.assertEqual(
                self.git(
                    "ls-tree",
                    "-r",
                    "--name-only",
                    "HEAD",
                    cwd=worker,
                ).stdout.splitlines(),
                ["baseline.txt", "rewritten-sibling-result.txt"],
            )
            self.assertEqual(
                (worker / "rewritten-sibling-result.txt").read_text(
                    encoding="utf-8"
                ),
                "installed clean rewritten sibling result\n",
            )
            retained_temporary = temporary.stat()
            self.assertEqual(
                (retained_temporary.st_dev, retained_temporary.st_ino),
                (temporary_metadata.st_dev, temporary_metadata.st_ino),
            )
            self.assertEqual(self.refs_under(private_prefix), [])
            self.assertEqual(
                temporary_sentinel.read_bytes(),
                temporary_sentinel_bytes,
            )
            self.assertEqual(
                adjacent_sentinel.read_text(encoding="utf-8"),
                "adjacent retirement state survives\n",
            )
            self.assertEqual(
                self.git("rev-parse", "--verify", target_ref).stdout.strip(),
                target_head,
            )
            self.assertEqual(self.ref_oid(survivor_ref), target_head)
            self.assertEqual(self.git("rev-parse", "HEAD").stdout.strip(), control_head)
            self.assertEqual(self.git("write-tree").stdout.strip(), control_tree)
            self.assertEqual(
                self.git(
                    "status",
                    "--porcelain=v1",
                    "--untracked-files=all",
                ).stdout,
                control_status,
            )

        no_make_wrapper = self.run_make("retire", f"RUN={run_id}")
        self.assertIn("No rule to make target", no_make_wrapper.stderr)
        assert_quarantine_unchanged(no_make_wrapper)
        ordinary_clean = self.run_make("clean-run", f"RUN={run_id}")
        self.assertIn("no retirement checkpoint", ordinary_clean.stderr)
        assert_quarantine_unchanged(ordinary_clean)
        wrong_discard = self.run_console(
            "--profile",
            "generic-v1",
            "retire",
            run_id,
            "--discard-head",
            final_head,
            "--target-contains",
            selected_checkpoint,
        )
        assert_quarantine_unchanged(wrong_discard)
        uncontained_checkpoint = self.run_console(
            "--profile",
            "generic-v1",
            "retire",
            run_id,
            "--discard-head",
            discard_head,
            "--target-contains",
            discard_head,
        )
        assert_quarantine_unchanged(uncontained_checkpoint)

        retirement_arguments = (
            "--profile",
            "generic-v1",
            "retire",
            run_id,
            "--discard-head",
            discard_head,
            "--target-contains",
            selected_checkpoint,
        )
        retired = self.run_console(*retirement_arguments)
        self.assertEqual(retired.returncode, 0, retired.stderr)
        self.assertIn("retired and cleaned", retired.stderr)
        for private_path in (
            str(worker),
            str(temporary),
            str(self.generic_state),
        ):
            self.assertNotIn(private_path, retired.stdout)
            self.assertNotIn(private_path, retired.stderr)

        cleaned = json.loads(manifest_path.read_text(encoding="utf-8"))
        self.assertEqual(cleaned["state"], "cleaned")
        self.assertEqual(
            (
                cleaned["schema_version"],
                cleaned["format_id"],
                cleaned["profile_id"],
                cleaned["agent"],
            ),
            (1, "worktree-marshal-run", "generic-v1", "codex"),
        )
        self.assertEqual(cleaned["retirement_discard_head"], discard_head)
        self.assertEqual(
            cleaned["retirement_target_contains"],
            selected_checkpoint,
        )
        self.assertEqual(cleaned["retirement_initial_target_head"], target_head)
        self.assertEqual(cleaned["retirement_cleanup_target_head"], target_head)
        self.assertIs(cleaned["retirement_anchor_created"], True)
        for field in (
            "retirement_started_at",
            "retirement_worktree_removed_at",
            "retirement_ref_cleanup_started_at",
            "retirement_ref_transaction_committed_at",
            "retirement_receipt_removed_at",
            "retirement_completed_at",
        ):
            self.assertIn(field, cleaned)
        self.assertEqual(
            cleaned["cleaned_at"],
            cleaned["retirement_completed_at"],
        )
        self.assertNotIn("retirement_cleanup_warning", cleaned)
        self.assertEqual(cleaned["final_head"], final_head)
        self.assertEqual(cleaned["observed_head"], discard_head)
        self.assertFalse(cleaned["observed_dirty"])
        self.assertFalse(worker.exists())
        self.assertFalse(temporary.exists())
        self.assertFalse(temporary_sentinel.exists())
        self.assertEqual(
            adjacent_sentinel.read_text(encoding="utf-8"),
            "adjacent retirement state survives\n",
        )
        self.assertEqual(self.worktree_paths(), [self.control.resolve()])
        for ref in (branch_ref, anchor_ref, receipt_ref):
            self.assertIsNone(self.ref_oid(ref))
        self.assertEqual(self.refs_under(private_prefix), [])
        self.assertEqual(self.ref_oid(survivor_ref), target_head)
        self.assertEqual(
            self.git("rev-parse", "--verify", target_ref).stdout.strip(),
            target_head,
        )
        self.assertEqual(self.git("rev-parse", "HEAD").stdout.strip(), control_head)
        self.assertEqual(self.git("write-tree").stdout.strip(), control_tree)
        self.assertEqual(
            self.git(
                "status",
                "--porcelain=v1",
                "--untracked-files=all",
            ).stdout,
            control_status,
        )
        self.assertFalse(self.triptych_state.exists())
        self.assertEqual(self.refs_under("refs/triptych-codex/"), [])

        cleaned_snapshot = self.manifest_snapshot(manifest_path)
        cleaned_ref_snapshot = self.git(
            "for-each-ref",
            "--format=%(refname) %(objectname)",
        ).stdout
        cleaned_worktree_snapshot = self.git(
            "worktree",
            "list",
            "--porcelain",
        ).stdout
        cleaned_manifest_paths = self.manifests(self.generic_profile_state)
        self.assertEqual(cleaned_manifest_paths, {manifest_path})

        def assert_cleaned_unchanged(
            result: subprocess.CompletedProcess[str],
            expected_status: int,
        ) -> None:
            self.assertEqual(result.returncode, expected_status, result.stderr)
            self.assertEqual(
                self.manifest_snapshot(manifest_path),
                cleaned_snapshot,
            )
            self.assertEqual(
                self.git("rev-parse", "--verify", target_ref).stdout.strip(),
                target_head,
            )
            self.assertEqual(self.ref_oid(survivor_ref), target_head)
            self.assertEqual(self.git("rev-parse", "HEAD").stdout.strip(), control_head)
            self.assertEqual(self.git("write-tree").stdout.strip(), control_tree)
            self.assertEqual(
                self.git(
                    "status",
                    "--porcelain=v1",
                    "--untracked-files=all",
                ).stdout,
                control_status,
            )
            self.assertEqual(self.worktree_paths(), [self.control.resolve()])
            self.assertEqual(
                self.git(
                    "worktree",
                    "list",
                    "--porcelain",
                ).stdout,
                cleaned_worktree_snapshot,
            )
            self.assertEqual(
                self.git(
                    "for-each-ref",
                    "--format=%(refname) %(objectname)",
                ).stdout,
                cleaned_ref_snapshot,
            )
            self.assertEqual(
                self.manifests(self.generic_profile_state),
                cleaned_manifest_paths,
            )
            self.assertEqual(self.refs_under(private_prefix), [])
            self.assertEqual(
                self.refs_under(
                    "refs/heads/worktree-marshal/generic-v1/isolated/"
                ),
                [],
            )
            self.assertFalse(worker.exists())
            self.assertFalse(temporary.exists())
            self.assertEqual(
                adjacent_sentinel.read_text(encoding="utf-8"),
                "adjacent retirement state survives\n",
            )
            for ref in (branch_ref, anchor_ref, receipt_ref):
                self.assertIsNone(self.ref_oid(ref))

        repeated = self.run_console(*retirement_arguments)
        self.assertIn("already retired and cleaned", repeated.stderr)
        assert_cleaned_unchanged(repeated, 0)
        changed_discard = self.run_console(
            "--profile",
            "generic-v1",
            "retire",
            run_id,
            "--discard-head",
            final_head,
            "--target-contains",
            selected_checkpoint,
        )
        assert_cleaned_unchanged(changed_discard, 2)
        changed_checkpoint = self.run_console(
            "--profile",
            "generic-v1",
            "retire",
            run_id,
            "--discard-head",
            discard_head,
            "--target-contains",
            target_head,
        )
        assert_cleaned_unchanged(changed_checkpoint, 2)

        overview = self.run_console("--profile", "generic-v1", "status")
        self.assertEqual(overview.returncode, 0, overview.stderr)
        self.assertNotIn(run_id, overview.stdout)
        exact_status = self.run_console(
            "--profile",
            "generic-v1",
            "status",
            run_id,
        )
        self.assertEqual(exact_status.returncode, 0, exact_status.stderr)
        self.assertIn(run_id, exact_status.stdout)
        self.assertIn("cleaned", exact_status.stdout)

    def test_installed_generic_managed_conflict_lifecycle(self) -> None:
        before = self.manifests(self.generic_profile_state)
        launched = self.run_make(
            "codex",
            environment={
                "FAKE_CODEX_ACTION": "commit",
                "FAKE_CODEX_CONTENT": "installed worker result\n",
            },
        )
        self.assertEqual(launched.returncode, 0, launched.stderr)
        created = self.manifests(self.generic_profile_state) - before
        self.assertEqual(len(created), 1, created)
        manifest_path = created.pop()
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        run_id = manifest["run_id"]
        worker = Path(manifest["worktree"])
        source_head = manifest["final_head"]
        source_anchor = (
            f"refs/worktree-marshal/generic-v1/runs/{run_id}/"
            "integration-source"
        )
        self.assertEqual(manifest["state"], "preserved")
        self.assertFalse(manifest["dirty"])
        self.assertEqual(manifest["format_id"], "worktree-marshal-run")
        self.assertEqual(manifest["profile_id"], "generic-v1")
        self.assertEqual(manifest["agent"], "codex")

        (self.control / "agent-result.txt").write_text(
            "installed conflicting target\n",
            encoding="utf-8",
        )
        self.git("add", "agent-result.txt")
        self.git("commit", "-m", "Add installed conflicting target")
        target_head = self.git("rev-parse", "HEAD").stdout.strip()

        conflicted_result = self.run_make("integrate", f"RUN={run_id}")
        self.assertEqual(
            conflicted_result.returncode,
            2,
            conflicted_result.stderr,
        )
        self.assertIn("conflict", conflicted_result.stderr.lower())
        self.assertNotIn(str(worker), conflicted_result.stderr)
        conflicted = json.loads(manifest_path.read_text(encoding="utf-8"))
        self.assertEqual(conflicted["state"], "integration-conflict")
        self.assertEqual(conflicted["final_head"], source_head)
        self.assertEqual(conflicted["integration_source_head"], source_head)
        self.assertEqual(conflicted["integration_target_head"], target_head)
        self.assertEqual(
            conflicted["integration_conflict_paths"],
            ["agent-result.txt"],
        )
        self.assertNotIn("integration_candidate_head", conflicted)
        self.assertNotIn("integrated_head", conflicted)
        self.assertEqual(self.ref_oid(source_anchor), source_head)
        self.assertTrue(self.active_rebase_paths(worker))
        self.assertEqual(
            self.git(
                "diff",
                "--name-only",
                "--diff-filter=U",
                cwd=worker,
            ).stdout.splitlines(),
            ["agent-result.txt"],
        )
        self.assertEqual(
            self.git("rev-parse", "refs/heads/main").stdout.strip(),
            target_head,
        )

        resolved = self.run_make(
            "resolve",
            f"RUN={run_id}",
            environment={
                "FAKE_CODEX_ACTION": "stage-conflict",
                "FAKE_CODEX_CONTENT": "installed resolved result\n",
            },
        )
        self.assertEqual(resolved.returncode, 0, resolved.stderr)
        staged = json.loads(manifest_path.read_text(encoding="utf-8"))
        self.assertEqual(staged["state"], "integration-conflict")
        self.assertNotIn("integration_candidate_head", staged)
        self.assertEqual(
            self.git(
                "diff",
                "--name-only",
                "--diff-filter=U",
                cwd=worker,
            ).stdout,
            "",
        )
        self.assertEqual(
            self.git(
                "diff",
                "--cached",
                "--name-only",
                cwd=worker,
            ).stdout.splitlines(),
            ["agent-result.txt"],
        )

        continued = self.run_make("continue", f"RUN={run_id}")
        self.assertEqual(continued.returncode, 0, continued.stderr)
        self.assertIn("review", continued.stderr.lower())
        pending = json.loads(manifest_path.read_text(encoding="utf-8"))
        candidate_head = pending["integration_candidate_head"]
        self.assertEqual(pending["state"], "integration-review-pending")
        self.assertTrue(pending["integration_manual_resolution"])
        self.assertEqual(pending["integration_unmerged_paths"], [])
        self.assertEqual(pending["integration_source_head"], source_head)
        self.assertEqual(pending["integration_target_head"], target_head)
        self.assertNotEqual(candidate_head, source_head)
        self.assertEqual(
            self.git("rev-parse", "HEAD", cwd=worker).stdout.strip(),
            candidate_head,
        )
        self.assertEqual(
            self.git("rev-parse", "HEAD^", cwd=worker).stdout.strip(),
            target_head,
        )
        self.assertEqual(
            self.git("status", "--porcelain=v1", cwd=worker).stdout,
            "",
        )
        self.assertEqual(
            self.git(
                "symbolic-ref",
                "--short",
                "HEAD",
                cwd=worker,
            ).stdout.strip(),
            manifest["branch"],
        )
        self.assertEqual(self.active_rebase_paths(worker), [])
        self.assertEqual(
            self.git("rev-parse", "refs/heads/main").stdout.strip(),
            target_head,
        )

        manifest_before_diff = self.manifest_snapshot(manifest_path)
        worker_status_before_diff = self.git(
            "status",
            "--porcelain=v1",
            cwd=worker,
        ).stdout
        control_status_before_diff = self.git(
            "status",
            "--porcelain=v1",
            "--untracked-files=all",
        ).stdout
        reviewed = self.run_make("final-diff", f"RUN={run_id}")
        self.assertEqual(reviewed.returncode, 0, reviewed.stderr)
        self.assertIn("installed conflicting target", reviewed.stdout)
        self.assertIn("installed resolved result", reviewed.stdout)
        for private_path in (
            str(self.control),
            str(worker),
            manifest["tmpdir"],
            str(self.generic_state),
        ):
            self.assertNotIn(private_path, reviewed.stdout)
            self.assertNotIn(private_path, reviewed.stderr)
        self.assertEqual(
            self.manifest_snapshot(manifest_path),
            manifest_before_diff,
        )
        self.assertEqual(
            self.git("rev-parse", "HEAD", cwd=worker).stdout.strip(),
            candidate_head,
        )
        self.assertEqual(
            self.git("status", "--porcelain=v1", cwd=worker).stdout,
            worker_status_before_diff,
        )
        self.assertEqual(
            self.git("rev-parse", "refs/heads/main").stdout.strip(),
            target_head,
        )
        self.assertEqual(
            self.git(
                "status",
                "--porcelain=v1",
                "--untracked-files=all",
            ).stdout,
            control_status_before_diff,
        )

        landed = self.run_make("integrate", f"RUN={run_id}")
        self.assertEqual(landed.returncode, 0, landed.stderr)
        cleaned = json.loads(manifest_path.read_text(encoding="utf-8"))
        self.assertEqual(cleaned["state"], "cleaned")
        self.assertEqual(cleaned["integration_candidate_head"], candidate_head)
        self.assertEqual(cleaned["integrated_head"], candidate_head)
        self.assertEqual(
            self.git("rev-parse", "refs/heads/main").stdout.strip(),
            candidate_head,
        )
        self.assertEqual(
            (self.control / "agent-result.txt").read_text(encoding="utf-8"),
            "installed resolved result\n",
        )
        self.assertEqual(self.git("status", "--porcelain=v1").stdout, "")
        self.assertEqual(self.worktree_paths(), [self.control.resolve()])
        self.assertFalse(worker.exists())
        self.assertFalse(Path(manifest["tmpdir"]).exists())
        self.assertIsNone(self.ref_oid(f"refs/heads/{manifest['branch']}"))
        self.assertIsNone(self.ref_oid(source_anchor))

    def test_installed_triptych_conflict_abort_restores_audited_source(
        self,
    ) -> None:
        manifest_path, manifest = self.launch_and_read_manifest(
            self.triptych_state,
            "installed Triptych conflict run",
            expected_status=0,
            environment={
                "FAKE_CODEX_ACTION": "commit",
                "FAKE_CODEX_CONTENT": "installed Triptych worker result\n",
            },
            compatibility=True,
        )
        run_id = manifest["run_id"]
        worker = Path(manifest["worktree"])
        source_head = manifest["final_head"]
        source_anchor = (
            f"refs/triptych-codex/runs/{run_id}/integration-source"
        )
        self.assertEqual(manifest["state"], "preserved")
        self.assertNotIn("format_id", manifest)
        self.assertNotIn("profile_id", manifest)
        self.assertNotIn("agent", manifest)

        (self.control / "agent-result.txt").write_text(
            "installed Triptych conflicting target\n",
            encoding="utf-8",
        )
        self.git("add", "agent-result.txt")
        self.git("commit", "-m", "Add installed Triptych conflicting target")
        target_head = self.git("rev-parse", "HEAD").stdout.strip()

        conflicted_result = self.run_console(
            "--profile",
            "triptych",
            "integrate",
            run_id,
        )
        self.assertEqual(
            conflicted_result.returncode,
            2,
            conflicted_result.stderr,
        )
        conflicted = json.loads(manifest_path.read_text(encoding="utf-8"))
        self.assertEqual(conflicted["state"], "integration-conflict")
        self.assertEqual(conflicted["integration_source_head"], source_head)
        self.assertEqual(conflicted["integration_target_head"], target_head)
        self.assertEqual(
            conflicted["integration_conflict_paths"],
            ["agent-result.txt"],
        )
        self.assertEqual(self.ref_oid(source_anchor), source_head)
        self.assertTrue(self.active_rebase_paths(worker))

        resolved = self.run_console(
            "--profile",
            "triptych",
            "resolve",
            run_id,
            environment={
                "FAKE_CODEX_ACTION": "stage-conflict",
                "FAKE_CODEX_CONTENT": "discarded Triptych resolution\n",
            },
        )
        self.assertEqual(resolved.returncode, 0, resolved.stderr)
        self.assertEqual(
            self.git(
                "diff",
                "--name-only",
                "--diff-filter=U",
                cwd=worker,
            ).stdout,
            "",
        )
        self.assertEqual(
            self.git(
                "diff",
                "--cached",
                "--name-only",
                cwd=worker,
            ).stdout.splitlines(),
            ["agent-result.txt"],
        )
        self.assertEqual(
            (worker / "agent-result.txt").read_text(encoding="utf-8"),
            "discarded Triptych resolution\n",
        )

        aborted = self.run_console(
            "--profile",
            "triptych",
            "abort",
            run_id,
        )
        self.assertEqual(aborted.returncode, 0, aborted.stderr)
        self.assertIn("restored", aborted.stderr.lower())
        self.assertEqual(
            self.git("rev-parse", "refs/heads/main").stdout.strip(),
            target_head,
        )
        self.assertEqual(
            (self.control / "agent-result.txt").read_text(encoding="utf-8"),
            "installed Triptych conflicting target\n",
        )
        self.assertEqual(
            self.git("rev-parse", "HEAD", cwd=worker).stdout.strip(),
            source_head,
        )
        self.assertEqual(
            self.git("status", "--porcelain=v1", cwd=worker).stdout,
            "",
        )
        self.assertEqual(
            self.git(
                "symbolic-ref",
                "--short",
                "HEAD",
                cwd=worker,
            ).stdout.strip(),
            manifest["branch"],
        )
        self.assertEqual(self.active_rebase_paths(worker), [])
        self.assertEqual(
            (worker / "agent-result.txt").read_text(encoding="utf-8"),
            "installed Triptych worker result\n",
        )

        restored = json.loads(manifest_path.read_text(encoding="utf-8"))
        self.assertEqual(restored["state"], "preserved")
        self.assertEqual(restored["final_head"], source_head)
        self.assertNotIn("format_id", restored)
        self.assertNotIn("profile_id", restored)
        self.assertNotIn("agent", restored)
        self.assertEqual(
            restored["last_integration_source_head"],
            source_head,
        )
        self.assertEqual(
            restored["last_integration_target_head"],
            target_head,
        )
        self.assertEqual(
            restored["last_integration_conflict_paths"],
            ["agent-result.txt"],
        )
        self.assertIn("last_integration_aborted_at", restored)
        self.assertEqual(
            [key for key in restored if key.startswith("integration_")],
            [],
        )
        self.assertIsNone(self.ref_oid(source_anchor))
        self.assertTrue(worker.is_dir())
        self.assertTrue(Path(manifest["tmpdir"]).is_dir())
        self.assertEqual(
            self.ref_oid(f"refs/heads/{manifest['branch']}"),
            source_head,
        )
        self.assertEqual(
            set(self.worktree_paths()),
            {self.control.resolve(), worker.resolve()},
        )
        self.assertEqual(self.manifests(self.generic_profile_state), set())


if __name__ == "__main__":
    unittest.main()
