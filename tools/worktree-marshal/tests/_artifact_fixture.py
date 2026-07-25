"""Process-lifetime distribution artifacts shared by package tests."""

from __future__ import annotations

import atexit
import importlib.util
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
import threading
from dataclasses import dataclass, field
from pathlib import Path


COMMAND_TIMEOUT_SECONDS = 60
SETUPTOOLS_AVAILABLE = importlib.util.find_spec("setuptools") is not None


@dataclass(frozen=True)
class BuiltArtifacts:
    """One source build, exact sdist rebuild, and installed rebuilt wheel."""

    package_root: Path
    root: Path
    wheel: Path
    source_distribution: Path
    sdist_wheel: Path
    venv: Path
    venv_bin: Path
    venv_python: Path
    installed_command: Path
    copied_source: Path
    extracted_sdist: Path
    _temporary_directory: tempfile.TemporaryDirectory = field(
        repr=False,
        compare=False,
    )

    def assert_intact(self) -> None:
        required = (
            self.root,
            self.wheel,
            self.source_distribution,
            self.sdist_wheel,
            self.venv,
            self.venv_bin,
            self.venv_python,
            self.installed_command,
        )
        missing = [path for path in required if not path.exists()]
        if missing:
            raise AssertionError(
                f"shared artifact fixture is no longer intact: {missing!r}"
            )
        unexpected = [
            path
            for path in (self.copied_source, self.extracted_sdist)
            if path.exists()
        ]
        if unexpected:
            raise AssertionError(
                "shared artifact fixture retained non-artifact build trees: "
                f"{unexpected!r}"
            )

    def new_case(
        self,
        *,
        prefix: str = "worktree-marshal-artifact-case-",
    ) -> tempfile.TemporaryDirectory:
        """Return a unique caller-owned runtime directory below the fixture."""

        self.assert_intact()
        return tempfile.TemporaryDirectory(dir=self.root, prefix=prefix)

    def _cleanup(self) -> None:
        self._temporary_directory.cleanup()


_CACHE: dict[Path, BuiltArtifacts] = {}
_CACHE_LOCK = threading.Lock()


def _checked(
    arguments: list[str],
    *,
    cwd: Path,
    environment: dict[str, str],
    purpose: str,
) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(
        arguments,
        cwd=cwd,
        env=environment,
        text=True,
        capture_output=True,
        check=False,
        timeout=COMMAND_TIMEOUT_SECONDS,
    )
    if result.returncode:
        raise AssertionError(
            f"{purpose} failed with status {result.returncode}\n"
            f"stdout:\n{result.stdout}\n"
            f"stderr:\n{result.stderr}"
        )
    return result


def _build_environment(root: Path) -> dict[str, str]:
    home = root / "build-home"
    home.mkdir()
    environment = os.environ.copy()
    for name in list(environment):
        if name.startswith("PIP_") or name in {
            "PYTHONHOME",
            "PYTHONPATH",
            "PYTHONSTARTUP",
            "PYTHONUSERBASE",
            "SETUPTOOLS_USE_DISTUTILS",
            "VIRTUAL_ENV",
            "__PYVENV_LAUNCHER__",
        }:
            environment.pop(name, None)
    environment.update(
        {
            "HOME": str(home),
            "PIP_DISABLE_PIP_VERSION_CHECK": "1",
            "PYTHONDONTWRITEBYTECODE": "1",
            "PYTHONNOUSERSITE": "1",
            "XDG_CACHE_HOME": str(home / ".cache"),
            "XDG_CONFIG_HOME": str(home / ".config"),
            "XDG_STATE_HOME": str(home / ".state"),
        }
    )
    return environment


def _one_path(paths: list[Path], *, description: str) -> Path:
    if len(paths) != 1:
        raise AssertionError(
            f"expected one {description}; found {paths!r}"
        )
    return paths[0]


def _build_artifacts(package_root: Path) -> BuiltArtifacts:
    temporary_directory = tempfile.TemporaryDirectory(
        prefix="worktree-marshal-artifacts-"
    )
    root = Path(temporary_directory.name)
    copied_source = root / "source"
    artifacts = root / "artifacts"
    extracted_sdist = root / "extracted-sdist"
    rebuilt_artifacts = root / "rebuilt-artifacts"
    venv = root / "venv"

    try:
        shutil.copytree(
            package_root,
            copied_source,
            ignore=shutil.ignore_patterns(
                "__pycache__",
                "*.pyc",
                "*.pyo",
                "*.egg-info",
                "build",
                "dist",
            ),
        )
        artifacts.mkdir()
        extracted_sdist.mkdir()
        rebuilt_artifacts.mkdir()
        environment = _build_environment(root)

        _checked(
            [
                sys.executable,
                "-c",
                (
                    "import pathlib, sys; "
                    "from setuptools.build_meta import build_sdist, build_wheel; "
                    "output = pathlib.Path(sys.argv[1]); "
                    "build_sdist(str(output)); "
                    "build_wheel(str(output))"
                ),
                str(artifacts),
            ],
            cwd=copied_source,
            environment=environment,
            purpose="wheel and source-distribution build",
        )
        wheel = _one_path(
            sorted(artifacts.glob("*.whl")),
            description="wheel",
        )
        source_distribution = _one_path(
            sorted(artifacts.glob("*.tar.gz")),
            description="source distribution",
        )

        with tarfile.open(source_distribution, mode="r:gz") as archive:
            archive.extractall(extracted_sdist)
        extracted_root = _one_path(
            sorted(path for path in extracted_sdist.iterdir() if path.is_dir()),
            description="extracted source-distribution root",
        )

        _checked(
            [
                sys.executable,
                "-c",
                (
                    "import pathlib, sys; "
                    "from setuptools.build_meta import build_wheel; "
                    "build_wheel(str(pathlib.Path(sys.argv[1])))"
                ),
                str(rebuilt_artifacts),
            ],
            cwd=extracted_root,
            environment=environment,
            purpose="wheel rebuild from source distribution",
        )
        sdist_wheel = _one_path(
            sorted(rebuilt_artifacts.glob("*.whl")),
            description="wheel rebuilt from the source distribution",
        )

        _checked(
            [sys.executable, "-m", "venv", str(venv)],
            cwd=root,
            environment=environment,
            purpose="test virtual-environment creation",
        )
        venv_bin = venv / "bin"
        venv_python = venv_bin / "python"
        installed_command = venv_bin / "worktree-marshal"
        _checked(
            [
                str(venv_python),
                "-m",
                "pip",
                "install",
                "--disable-pip-version-check",
                "--no-cache-dir",
                "--no-deps",
                "--no-index",
                str(sdist_wheel),
            ],
            cwd=root,
            environment=environment,
            purpose="sdist-rebuilt wheel installation",
        )
        if not installed_command.is_file():
            raise AssertionError(
                "the rebuilt wheel did not install the worktree-marshal command"
            )

        for build_tree in (copied_source, extracted_sdist):
            if build_tree.parent != root:
                raise AssertionError(
                    f"refusing to remove unexpected build path {build_tree}"
                )
            shutil.rmtree(build_tree)
            if build_tree.exists():
                raise AssertionError(
                    f"temporary build tree remains at {build_tree}"
                )

        built = BuiltArtifacts(
            package_root=package_root,
            root=root,
            wheel=wheel,
            source_distribution=source_distribution,
            sdist_wheel=sdist_wheel,
            venv=venv,
            venv_bin=venv_bin,
            venv_python=venv_python,
            installed_command=installed_command,
            copied_source=copied_source,
            extracted_sdist=extracted_sdist,
            _temporary_directory=temporary_directory,
        )
        built.assert_intact()
        return built
    except BaseException:
        temporary_directory.cleanup()
        raise


def get_built_artifacts(package_root: Path) -> BuiltArtifacts:
    """Build once per resolved package root and retain until process exit."""

    resolved_root = package_root.resolve(strict=True)
    if not (resolved_root / "pyproject.toml").is_file():
        raise AssertionError(
            f"package root has no pyproject.toml: {resolved_root}"
        )
    with _CACHE_LOCK:
        cached = _CACHE.get(resolved_root)
        if cached is None:
            cached = _build_artifacts(resolved_root)
            _CACHE[resolved_root] = cached
        cached.assert_intact()
        return cached


def _cleanup_cached_artifacts() -> None:
    with _CACHE_LOCK:
        cached = tuple(_CACHE.values())
        _CACHE.clear()
    for artifacts in cached:
        artifacts._cleanup()


atexit.register(_cleanup_cached_artifacts)


__all__ = [
    "BuiltArtifacts",
    "COMMAND_TIMEOUT_SECONDS",
    "SETUPTOOLS_AVAILABLE",
    "get_built_artifacts",
]
