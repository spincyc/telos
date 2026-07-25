#!/usr/bin/env python3
"""Build and inspect the extraction-stage wheel and source distribution."""

from __future__ import annotations

import os
import subprocess
import tarfile
import unittest
import zipfile
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


@unittest.skipUnless(SETUPTOOLS_AVAILABLE, "setuptools build backend is unavailable")
class DistributionArtifactTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        artifacts = get_built_artifacts(PACKAGE_ROOT)
        cls.artifacts = artifacts
        cls.wheel = artifacts.wheel
        cls.source_distribution = artifacts.source_distribution
        cls.sdist_wheel = artifacts.sdist_wheel
        cls.venv = artifacts.venv
        cls.venv_bin = artifacts.venv_bin
        cls.venv_python = artifacts.venv_python
        cls.installed_command = artifacts.installed_command

        cls.runtime_case = artifacts.new_case(prefix="distribution-runtime-")
        cls.addClassCleanup(cls.runtime_case.cleanup)
        cls.outside = Path(cls.runtime_case.name)
        cls.home = cls.outside / "home"
        cls.home.mkdir(parents=True)
        cls.state_home = cls.outside / "state"
        cls.installed_environment = os.environ.copy()
        cls.installed_environment.pop("PYTHONHOME", None)
        cls.installed_environment.pop("PYTHONPATH", None)
        cls.installed_environment.update(
            {
                "HOME": str(cls.home),
                "PATH": str(cls.venv_bin),
                "PYTHONDONTWRITEBYTECODE": "1",
                "PYTHONNOUSERSITE": "1",
                "XDG_STATE_HOME": str(cls.state_home),
            }
        )

    def run_installed(self, *arguments: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [str(self.installed_command), *arguments],
            cwd=self.outside,
            env=self.installed_environment,
            text=True,
            capture_output=True,
            check=False,
            timeout=10,
        )

    def test_wheel_contains_importable_code_resource_and_license(self) -> None:
        with zipfile.ZipFile(self.wheel) as archive:
            names = set(archive.namelist())

        self.assertIn("worktree_marshal/__init__.py", names)
        self.assertIn("worktree_marshal/adapters/__init__.py", names)
        self.assertIn("worktree_marshal/adapters/codex.py", names)
        self.assertIn("worktree_marshal/cli.py", names)
        self.assertIn("worktree_marshal/engine.py", names)
        self.assertIn("worktree_marshal/git.py", names)
        self.assertIn("worktree_marshal/identity.py", names)
        self.assertIn("worktree_marshal/locks.py", names)
        self.assertIn("worktree_marshal/model.py", names)
        self.assertIn("worktree_marshal/process.py", names)
        self.assertIn("worktree_marshal/profiles.py", names)
        self.assertIn("worktree_marshal/state.py", names)
        self.assertIn("worktree_marshal/triptych_compat.py", names)
        self.assertIn("worktree_marshal/resources/__init__.py", names)
        self.assertIn(
            "worktree_marshal/resources/worktree-marshal.mk",
            names,
        )
        self.assertTrue(
            any(name.endswith(".dist-info/licenses/LICENSE") for name in names),
            names,
        )

    def test_wheel_publishes_only_the_generic_console_script(self) -> None:
        with zipfile.ZipFile(self.wheel) as archive:
            entry_point_names = [
                name
                for name in archive.namelist()
                if name.endswith(".dist-info/entry_points.txt")
            ]
            self.assertEqual(len(entry_point_names), 1, entry_point_names)
            entry_points = archive.read(entry_point_names[0]).decode("utf-8")

        self.assertEqual(
            entry_points.strip().splitlines(),
            [
                "[console_scripts]",
                "worktree-marshal = worktree_marshal.cli:main",
            ],
        )
        self.assertNotIn("triptych-codex", entry_points)

    def test_wheel_metadata_records_no_runtime_dependency(self) -> None:
        with zipfile.ZipFile(self.wheel) as archive:
            metadata_names = [
                name for name in archive.namelist() if name.endswith(".dist-info/METADATA")
            ]
            self.assertEqual(len(metadata_names), 1, metadata_names)
            metadata = archive.read(metadata_names[0]).decode("utf-8")

        self.assertIn("Name: worktree-marshal\n", metadata)
        self.assertIn("Version: 0.0.0\n", metadata)
        self.assertIn("Requires-Python: >=3.10\n", metadata)
        self.assertNotIn("Requires-Dist:", metadata)

    def test_source_distribution_contains_build_review_and_test_inputs(self) -> None:
        with tarfile.open(self.source_distribution, mode="r:gz") as archive:
            names = set(archive.getnames())

        roots = {name.split("/", 1)[0] for name in names if name}
        self.assertEqual(len(roots), 1, roots)
        root = roots.pop()
        expected = {
            "LICENSE",
            "MANIFEST.in",
            "README.md",
            "pyproject.toml",
            "docs/compatibility-contract.md",
            "docs/design.md",
            "docs/generic-v1.md",
            "src/worktree_marshal/__init__.py",
            "src/worktree_marshal/adapters/__init__.py",
            "src/worktree_marshal/adapters/codex.py",
            "src/worktree_marshal/cli.py",
            "src/worktree_marshal/engine.py",
            "src/worktree_marshal/git.py",
            "src/worktree_marshal/identity.py",
            "src/worktree_marshal/locks.py",
            "src/worktree_marshal/model.py",
            "src/worktree_marshal/process.py",
            "src/worktree_marshal/profiles.py",
            "src/worktree_marshal/state.py",
            "src/worktree_marshal/triptych_compat.py",
            "src/worktree_marshal/resources/__init__.py",
            "src/worktree_marshal/resources/worktree-marshal.mk",
            "tests/__init__.py",
            "tests/_artifact_fixture.py",
            "tests/test_codex_adapter.py",
            "tests/test_distribution.py",
            "tests/test_git.py",
            "tests/test_identity.py",
            "tests/test_installed_lifecycle.py",
            "tests/test_locks.py",
            "tests/test_cli.py",
            "tests/test_make_fragment.py",
            "tests/test_model.py",
            "tests/test_package.py",
            "tests/test_process.py",
            "tests/test_profile_isolation.py",
            "tests/test_state.py",
        }
        missing = {
            relative for relative in expected if f"{root}/{relative}" not in names
        }
        self.assertEqual(missing, set())

    def test_wheel_rebuilt_from_sdist_has_command_and_runtime_modules(self) -> None:
        with zipfile.ZipFile(self.sdist_wheel) as archive:
            names = set(archive.namelist())
            entry_point_names = [
                name for name in names if name.endswith(".dist-info/entry_points.txt")
            ]
            self.assertEqual(len(entry_point_names), 1, entry_point_names)
            entry_points = archive.read(entry_point_names[0]).decode("utf-8")

        self.assertIn("worktree_marshal/cli.py", names)
        self.assertIn("worktree_marshal/adapters/__init__.py", names)
        self.assertIn("worktree_marshal/adapters/codex.py", names)
        self.assertIn("worktree_marshal/git.py", names)
        self.assertIn("worktree_marshal/identity.py", names)
        self.assertIn("worktree_marshal/locks.py", names)
        self.assertIn("worktree_marshal/model.py", names)
        self.assertIn("worktree_marshal/process.py", names)
        self.assertIn("worktree_marshal/state.py", names)
        self.assertIn(
            "worktree-marshal = worktree_marshal.cli:main",
            entry_points,
        )

    def test_installed_command_metadata_is_pure_outside_source_tree(self) -> None:
        version = self.run_installed("--version")
        help_result = self.run_installed("--help")

        self.assertEqual(version.returncode, 0, version.stderr)
        self.assertEqual(version.stdout, "worktree-marshal 0.0.0\n")
        self.assertEqual(help_result.returncode, 0, help_result.stderr)
        self.assertIn("usage: worktree-marshal", help_result.stdout)
        self.assertIn("--profile", help_result.stdout)
        self.assertIn("generic-v1", help_result.stdout)
        self.assertIn("triptych", help_result.stdout)
        self.assertFalse(
            self.state_home.exists(),
            "metadata commands must not discover Git or create launcher state",
        )

    def test_installed_stateful_command_requires_profile_before_git(self) -> None:
        missing = self.run_installed("status")
        unknown = self.run_installed("--profile", "unknown", "status")

        self.assertEqual(missing.returncode, 2, missing)
        self.assertIn("--profile", missing.stderr)
        self.assertEqual(unknown.returncode, 2, unknown)
        self.assertIn("unknown", unknown.stderr)
        self.assertFalse(
            self.state_home.exists(),
            "invalid profile selection must fail before launcher state discovery",
        )


if __name__ == "__main__":
    unittest.main()
