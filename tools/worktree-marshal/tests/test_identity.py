#!/usr/bin/env python3
"""Direct parity tests for runtime identities and launcher authentication."""

from __future__ import annotations

import importlib
import inspect
import os
import stat
import subprocess
import sys
import tempfile
import unittest
from dataclasses import MISSING, FrozenInstanceError, fields, is_dataclass
from pathlib import Path
from types import SimpleNamespace
from typing import get_type_hints
from unittest import mock


PACKAGE_ROOT = Path(__file__).resolve().parents[1]
SOURCE_ROOT = PACKAGE_ROOT / "src"


class OpaqueValue:
    """Stable test value that exposes accidental conversion in repr or identity."""

    def __init__(self, label: str) -> None:
        self.label = label

    def __eq__(self, other: object) -> bool:
        return (
            isinstance(other, OpaqueValue)
            and self.label == other.label
        )

    def __hash__(self) -> int:
        return hash((OpaqueValue, self.label))

    def __repr__(self) -> str:
        return f"<opaque:{self.label}>"


class LinkedValidationError(RuntimeError):
    """Selected policy error for linked-worktree kernel tests."""


class LinkedDependencyError(RuntimeError):
    """Selected untranslated dependency error for kernel tests."""


class LinkedValidationHarness:
    """Observable linked-worktree validation dependency graph."""

    def __init__(
        self,
        test_case: unittest.TestCase,
        *,
        expected_common: bool = True,
        forward_starts: bool = True,
        forward_equals_prefix: bool = False,
        common_mismatch: bool = False,
        parent_mismatch: bool = False,
        git_dir_equals_admin: bool = False,
        backlink_mismatch: bool = False,
        fail_stage: str | None = None,
    ) -> None:
        self.test_case = test_case
        self.events: list[tuple[str, object]] = []
        self.fail_stage = fail_stage
        self.failure = LinkedDependencyError(
            fail_stage or "unused failure"
        )
        self.worktree = OpaqueValue("worktree-input")
        self.expected_common_input = (
            OpaqueValue("expected-common-input")
            if expected_common
            else None
        )
        self.git_file = OpaqueValue("git-file")
        self.raw_git_dir = OpaqueValue("raw-git-dir")
        self.commondir_file = OpaqueValue("commondir-file")
        self.commondir_value = OpaqueValue("commondir-value")
        self.raw_common = OpaqueValue("raw-common")
        self.gitdir_file = OpaqueValue("gitdir-file")
        self.backlink_value = OpaqueValue("backlink-value")
        self.length_value = OpaqueValue("prefix-length")

        harness = self

        class Truth:
            def __init__(
                truth_self,
                stage: str,
                value: bool,
            ) -> None:
                truth_self.stage = stage
                truth_self.value = value

            def __bool__(truth_self) -> bool:
                harness.record(
                    truth_self.stage,
                    truth_self.value,
                )
                return truth_self.value

        class CanonicalWorktree:
            def __truediv__(
                worktree_self,
                component: object,
            ) -> object:
                harness.record(
                    "canonical-git-file",
                    component,
                )
                return harness.git_file

        self.canonical_worktree = CanonicalWorktree()

        class Forward:
            def startswith(
                forward_self,
                prefix: object,
            ) -> object:
                harness.record("forward-startswith", prefix)
                return Truth(
                    "forward-startswith-truth",
                    forward_starts,
                )

            def __eq__(
                forward_self,
                other: object,
            ) -> object:
                harness.record("forward-equality", other)
                return Truth(
                    "forward-equality-truth",
                    forward_equals_prefix,
                )

            def __getitem__(
                forward_self,
                key: object,
            ) -> object:
                harness.record("forward-slice", key)
                return harness.raw_git_dir

        self.forward = Forward()

        class GitParent:
            def __ne__(
                parent_self,
                other: object,
            ) -> object:
                harness.record("parent-mismatch", other)
                return Truth(
                    "parent-mismatch-truth",
                    parent_mismatch,
                )

        self.git_parent = GitParent()

        class GitDirectory:
            @property
            def parent(directory_self) -> object:
                harness.record("git-directory-parent", None)
                return harness.git_parent

            def __eq__(
                directory_self,
                other: object,
            ) -> object:
                harness.record(
                    "git-directory-admin-equality",
                    other,
                )
                return Truth(
                    "git-directory-admin-equality-truth",
                    git_dir_equals_admin,
                )

            def __truediv__(
                directory_self,
                component: object,
            ) -> object:
                if component == "commondir":
                    harness.record(
                        "git-directory-commondir",
                        component,
                    )
                    return harness.commondir_file
                harness.record(
                    "git-directory-gitdir",
                    component,
                )
                return harness.gitdir_file

        self.git_dir = GitDirectory()
        self.expected_common = OpaqueValue("expected-common")
        self.worktrees_path = OpaqueValue("worktrees-path")

        class CommonDirectory:
            def __ne__(
                common_self,
                other: object,
            ) -> object:
                harness.record("common-mismatch", other)
                return Truth(
                    "common-mismatch-truth",
                    common_mismatch,
                )

            def __truediv__(
                common_self,
                component: object,
            ) -> object:
                harness.record("common-worktrees", component)
                return harness.worktrees_path

        self.common_git_dir = CommonDirectory()
        self.worktrees_admin = OpaqueValue("worktrees-admin")

        class Backlink:
            def __ne__(
                backlink_self,
                other: object,
            ) -> object:
                harness.record("backlink-mismatch", other)
                return Truth(
                    "backlink-mismatch-truth",
                    backlink_mismatch,
                )

        self.backlink = Backlink()

        real_results: list[object] = [
            self.canonical_worktree,
            self.git_dir,
            self.common_git_dir,
        ]
        if expected_common:
            real_results.append(self.expected_common)
        real_results.append(self.worktrees_admin)
        self.real_results = iter(real_results)
        self.line_results = iter(
            (
                self.forward,
                self.commondir_value,
                self.backlink_value,
            )
        )
        self.pointer_results = iter(
            (
                self.raw_git_dir,
                self.raw_common,
                self.backlink,
            )
        )
        self.real_provider_count = 0
        self.line_provider_count = 0
        self.pointer_provider_count = 0

    def record(self, stage: str, value: object) -> None:
        self.events.append((stage, value))
        if stage == self.fail_stage:
            raise self.failure

    def real_directory(self) -> object:
        self.real_provider_count += 1
        number = self.real_provider_count
        self.record(f"real-directory-provider-{number}", None)
        result = next(self.real_results)

        def validate(path: object, *, label: object) -> object:
            self.record(
                f"real-directory-call-{number}",
                (path, label),
            )
            return result

        return validate

    def single_line(self) -> object:
        self.line_provider_count += 1
        number = self.line_provider_count
        self.record(f"single-line-provider-{number}", None)
        result = next(self.line_results)

        def read(path: object, *, label: object) -> object:
            self.record(
                f"single-line-call-{number}",
                (path, label),
            )
            return result

        return read

    def pointer_path(self) -> object:
        self.pointer_provider_count += 1
        number = self.pointer_provider_count
        self.record(f"pointer-provider-{number}", None)
        result = next(self.pointer_results)

        def validate(
            raw_value: object,
            *,
            relative_to: object,
            label: object,
        ) -> object:
            self.record(
                f"pointer-call-{number}",
                (raw_value, relative_to, label),
            )
            return result

        return validate

    def length(self) -> object:
        self.record("length-provider", None)

        def measure(value: object) -> object:
            self.record("length-call", value)
            return self.length_value

        return measure

    def error_type(self) -> type[BaseException]:
        self.record("error-provider", None)
        return LinkedValidationError

    def validate(self, identity_module: object) -> object:
        return identity_module.validate_linked_worktree_path(
            self.worktree,
            expected_common_git_dir=self.expected_common_input,
            real_directory=self.real_directory,
            single_line=self.single_line,
            pointer_path=self.pointer_path,
            length=self.length,
            error_type=self.error_type,
        )


class RecordingRegistry:
    """Small observable mapping for linked-worktree wrapper tests."""

    def __init__(
        self,
        name: str,
        events: list[tuple[str, object]],
        *,
        values: dict[object, object] | None = None,
        get_failure: BaseException | None = None,
        set_failure: BaseException | None = None,
        on_get: object = None,
        on_set: object = None,
    ) -> None:
        self.name = name
        self.events = events
        self.values = {} if values is None else dict(values)
        self.get_failure = get_failure
        self.set_failure = set_failure
        self.on_get = on_get
        self.on_set = on_set

    def get(self, key: object) -> object:
        self.events.append((f"{self.name}-get", key))
        if self.get_failure is not None:
            raise self.get_failure
        if self.on_get is not None:
            self.on_get()
        return self.values.get(key)

    def __setitem__(self, key: object, value: object) -> None:
        self.events.append(
            (f"{self.name}-set", (key, value))
        )
        if self.set_failure is not None:
            raise self.set_failure
        self.values[key] = value
        if self.on_set is not None:
            self.on_set()


class IdentityModelTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        sys.path.insert(0, str(SOURCE_ROOT))
        cls.identity = importlib.import_module("worktree_marshal.identity")
        cls.engine = importlib.import_module("worktree_marshal.engine")

    @classmethod
    def tearDownClass(cls) -> None:
        try:
            sys.path.remove(str(SOURCE_ROOT))
        except ValueError:
            pass

    def schemas(
        self,
    ) -> tuple[
        tuple[type, tuple[tuple[str, type], ...]],
        ...,
    ]:
        return (
            (
                self.identity.Repository,
                (
                    ("root", Path),
                    ("git_dir", Path),
                    ("common_git_dir", Path),
                    ("relative_cwd", Path),
                    ("linked_worktree", bool),
                    ("state_root", Path),
                ),
            ),
            (
                self.identity.LinkedWorktreeIdentity,
                (
                    ("worktree", Path),
                    ("git_file", Path),
                    ("git_dir", Path),
                    ("common_git_dir", Path),
                ),
            ),
            (
                self.identity.LauncherIdentity,
                (
                    ("path", Path),
                    ("device", int),
                    ("inode", int),
                ),
            ),
        )

    def read_regular_bytes(
        self,
        path: Path | None = None,
        *,
        label: object = "the file",
        **overrides: object,
    ) -> bytes:
        metadata = SimpleNamespace(
            st_mode=stat.S_IFREG | 0o600,
            st_nlink=1,
            st_size=0,
            st_dev=1,
            st_ino=2,
            st_mtime_ns=3,
            st_ctime_ns=4,
        )
        dependencies = {
            "open_flags": lambda: 0,
            "file_open": lambda: lambda _path, _flags: 7,
            "os_error_type": lambda: OSError,
            "error_type": lambda: RuntimeError,
            "file_stat": lambda: lambda _descriptor: metadata,
            "regular_file_test": lambda: lambda _mode: True,
            "maximum_file_bytes": lambda: 16,
            "file_read": lambda: lambda _descriptor, _size: b"",
            "minimum": lambda: min,
            "length": lambda: len,
            "file_close": lambda: lambda _descriptor: None,
        }
        dependencies.update(overrides)
        return self.identity.safe_regular_file_bytes(
            Path("/regular-file") if path is None else path,
            label=label,
            **dependencies,
        )

    def pointer_path(
        self,
        raw_value: object,
        *,
        relative_to: object,
        label: object = "the pointer",
        **overrides: object,
    ) -> object:
        dependencies = {
            "path_factory": lambda: Path,
            "absolute_path": lambda: os.path.abspath,
            "filesystem_path": lambda: os.fspath,
            "os_error_type": lambda: OSError,
            "runtime_error_type": lambda: RuntimeError,
            "error_type": lambda: RuntimeError,
        }
        dependencies.update(overrides)
        return self.identity.exact_pointer_path(
            raw_value,
            relative_to=relative_to,
            label=label,
            **dependencies,
        )

    def real_directory(
        self,
        path: object,
        *,
        label: object = "the directory",
        **overrides: object,
    ) -> object:
        dependencies = {
            "path_factory": lambda: Path,
            "absolute_path": lambda: os.path.abspath,
            "filesystem_path": lambda: os.fspath,
            "os_error_type": lambda: OSError,
            "runtime_error_type": lambda: RuntimeError,
            "directory_test": lambda: stat.S_ISDIR,
            "error_type": lambda: RuntimeError,
        }
        dependencies.update(overrides)
        return self.identity.exact_real_directory(
            path,
            label=label,
            **dependencies,
        )

    def git_cwd(
        self,
        cwd: object,
        **overrides: object,
    ) -> None:
        dependencies = {
            "path_factory": lambda: Path,
            "os_error_type": lambda: OSError,
            "runtime_error_type": lambda: RuntimeError,
            "file_not_found_error_type": (
                lambda: FileNotFoundError
            ),
            "directory_test": lambda: stat.S_ISDIR,
            "regular_file_test": lambda: stat.S_ISREG,
            "identity_lookup": lambda: (
                lambda candidate: None
            ),
            "linked_worktree_authenticator": lambda: (
                lambda candidate, *, expected_common_git_dir: None
            ),
            "error_type": lambda: RuntimeError,
        }
        dependencies.update(overrides)
        return self.identity.authenticate_git_cwd(
            cwd,
            **dependencies,
        )

    def test_identity_import_is_cycle_free_and_environment_neutral(
        self,
    ) -> None:
        sibling_modules = (
            "engine",
            "git",
            "locks",
            "model",
            "process",
            "profiles",
            "state",
        )
        script = (
            "import os, sys; "
            "before = dict(os.environ); "
            "before_cwd = os.getcwd(); "
            f"sys.path.insert(0, {str(SOURCE_ROOT)!r}); "
            "import worktree_marshal.identity; "
            f"siblings = {sibling_modules!r}; "
            "raise SystemExit("
            "dict(os.environ) != before or "
            "os.getcwd() != before_cwd or "
            "any(f'worktree_marshal.{name}' in sys.modules for name in siblings)"
            ")"
        )
        result = subprocess.run(
            [sys.executable, "-c", script],
            cwd=PACKAGE_ROOT,
            text=True,
            capture_output=True,
            check=False,
            timeout=10,
        )

        self.assertEqual(result.returncode, 0, result.stderr)

    def test_engine_reexports_the_exact_identity_classes(self) -> None:
        for class_name in (
            "Repository",
            "LinkedWorktreeIdentity",
            "LauncherIdentity",
        ):
            with self.subTest(identity=class_name):
                identity_type = getattr(self.identity, class_name)
                self.assertIs(
                    getattr(self.engine, class_name),
                    identity_type,
                )
                self.assertEqual(
                    identity_type.__module__,
                    "worktree_marshal.identity",
                )
        self.assertFalse(hasattr(self.identity, "Audit"))
        self.assertFalse(hasattr(self.identity, "PrimaryCheckoutState"))
        self.assertEqual(
            self.engine.Audit.__module__,
            "worktree_marshal.engine",
        )
        self.assertEqual(
            self.engine.PrimaryCheckoutState.__module__,
            "worktree_marshal.engine",
        )
        self.assertEqual(
            self.identity.LauncherIdentity.__doc__,
            "Authenticated identity of the in-process command entry point.",
        )

    def test_launcher_authentication_kernel_and_wrapper_signatures(
        self,
    ) -> None:
        parameters = inspect.signature(
            self.identity.authenticate_launcher
        ).parameters
        self.assertEqual(
            tuple(parameters),
            (
                "path",
                "os_error_type",
                "error_type",
                "regular_file_test",
                "access_check",
                "executable_mode",
                "identity_factory",
            ),
        )
        self.assertIs(
            parameters["path"].kind,
            inspect.Parameter.POSITIONAL_OR_KEYWORD,
        )
        for name in tuple(parameters)[1:]:
            self.assertIs(
                parameters[name].kind,
                inspect.Parameter.KEYWORD_ONLY,
            )
        for parameter in parameters.values():
            self.assertIs(parameter.default, inspect.Parameter.empty)

        self.assertIsNot(
            self.engine.authenticate_launcher,
            self.identity.authenticate_launcher,
        )
        wrapper_parameters = inspect.signature(
            self.engine.authenticate_launcher
        ).parameters
        self.assertEqual(tuple(wrapper_parameters), ("path",))
        self.assertIs(
            wrapper_parameters["path"].kind,
            inspect.Parameter.POSITIONAL_OR_KEYWORD,
        )
        self.assertIs(
            wrapper_parameters["path"].default,
            inspect.Parameter.empty,
        )

    def test_exact_path_kernels_and_engine_wrapper_signatures(
        self,
    ) -> None:
        cases = (
            (
                "_exact_pointer_path",
                "exact_pointer_path",
                (
                    "raw_value",
                    "relative_to",
                    "label",
                    "path_factory",
                    "absolute_path",
                    "filesystem_path",
                    "os_error_type",
                    "runtime_error_type",
                    "error_type",
                ),
                ("raw_value", "relative_to", "label"),
            ),
            (
                "_exact_real_directory",
                "exact_real_directory",
                (
                    "path",
                    "label",
                    "path_factory",
                    "absolute_path",
                    "filesystem_path",
                    "os_error_type",
                    "runtime_error_type",
                    "directory_test",
                    "error_type",
                ),
                ("path", "label"),
            ),
        )

        for (
            alias_name,
            public_name,
            kernel_names,
            wrapper_names,
        ) in cases:
            with self.subTest(kernel=public_name):
                kernel = getattr(self.identity, public_name)
                self.assertIs(getattr(self.engine, alias_name), kernel)

                parameters = inspect.signature(kernel).parameters
                self.assertEqual(tuple(parameters), kernel_names)
                self.assertIs(
                    parameters[kernel_names[0]].kind,
                    inspect.Parameter.POSITIONAL_OR_KEYWORD,
                )
                for name in kernel_names[1:]:
                    self.assertIs(
                        parameters[name].kind,
                        inspect.Parameter.KEYWORD_ONLY,
                    )
                for parameter in parameters.values():
                    self.assertIs(
                        parameter.default,
                        inspect.Parameter.empty,
                    )

                wrapper = getattr(self.engine, public_name)
                self.assertIsNot(wrapper, kernel)
                wrapper_parameters = inspect.signature(
                    wrapper
                ).parameters
                self.assertEqual(
                    tuple(wrapper_parameters),
                    wrapper_names,
                )
                self.assertIs(
                    wrapper_parameters[wrapper_names[0]].kind,
                    inspect.Parameter.POSITIONAL_OR_KEYWORD,
                )
                for name in wrapper_names[1:]:
                    self.assertIs(
                        wrapper_parameters[name].kind,
                        inspect.Parameter.KEYWORD_ONLY,
                    )
                for parameter in wrapper_parameters.values():
                    self.assertIs(
                        parameter.default,
                        inspect.Parameter.empty,
                    )

    def test_exact_pointer_path_preserves_relative_success_order(
        self,
    ) -> None:
        events: list[tuple[str, object]] = []
        raw_value = object()

        class Value:
            def is_absolute(value_self) -> bool:
                events.append(("is-absolute", None))
                return False

        value = Value()

        class Resolved:
            def __ne__(resolved_self, other: object) -> bool:
                events.append(("resolved-ne", other))
                self.assertIs(other, absolute)
                return False

        resolved = Resolved()

        class Candidate:
            def resolve(
                candidate_self,
                *,
                strict: bool,
            ) -> object:
                events.append(("resolve", strict))
                return resolved

        candidate = Candidate()

        class RelativeTo:
            def __truediv__(
                relative_self,
                other: object,
            ) -> object:
                events.append(("join", other))
                self.assertIs(other, value)
                return candidate

        relative_to = RelativeTo()
        absolute = object()
        filesystem_value = object()
        absolute_value = object()

        def raw_factory(observed: object) -> object:
            events.append(("raw-factory-call", observed))
            self.assertIs(observed, raw_value)
            return value

        def absolute_factory(observed: object) -> object:
            events.append(("absolute-factory-call", observed))
            self.assertIs(observed, absolute_value)
            return absolute

        factories = iter(
            (
                ("raw", raw_factory),
                ("absolute", absolute_factory),
            )
        )

        def path_factory() -> object:
            name, factory = next(factories)
            events.append(("path-factory-provider", name))
            return factory

        def absolute_path() -> object:
            events.append(("absolute-path-provider", None))

            def make_absolute(observed: object) -> object:
                events.append(("absolute-path-call", observed))
                self.assertIs(observed, filesystem_value)
                return absolute_value

            return make_absolute

        def filesystem_path() -> object:
            events.append(("filesystem-path-provider", None))

            def convert(observed: object) -> object:
                events.append(("filesystem-path-call", observed))
                self.assertIs(observed, candidate)
                return filesystem_value

            return convert

        observed = self.pointer_path(
            raw_value,
            relative_to=relative_to,
            path_factory=path_factory,
            absolute_path=absolute_path,
            filesystem_path=filesystem_path,
            os_error_type=mock.Mock(
                side_effect=AssertionError(
                    "resolved OSError on success"
                )
            ),
            runtime_error_type=mock.Mock(
                side_effect=AssertionError(
                    "resolved RuntimeError on success"
                )
            ),
            error_type=mock.Mock(
                side_effect=AssertionError(
                    "resolved launcher error on success"
                )
            ),
        )

        self.assertIs(observed, resolved)
        self.assertEqual(
            events,
            [
                ("path-factory-provider", "raw"),
                ("raw-factory-call", raw_value),
                ("is-absolute", None),
                ("join", value),
                ("path-factory-provider", "absolute"),
                ("absolute-path-provider", None),
                ("filesystem-path-provider", None),
                ("filesystem-path-call", candidate),
                ("absolute-path-call", filesystem_value),
                ("absolute-factory-call", absolute_value),
                ("resolve", True),
                ("resolved-ne", absolute),
            ],
        )
        with self.assertRaises(StopIteration):
            next(factories)

    def test_exact_pointer_path_preserves_absolute_short_circuit(
        self,
    ) -> None:
        events: list[str] = []
        raw_value = object()
        absolute = object()

        class Resolved:
            def __ne__(resolved_self, other: object) -> bool:
                events.append("compare")
                self.assertIs(other, absolute)
                return False

        resolved = Resolved()

        class Value:
            def is_absolute(value_self) -> bool:
                events.append("is-absolute")
                return True

            def resolve(
                value_self,
                *,
                strict: bool,
            ) -> object:
                events.append("resolve")
                self.assertTrue(strict)
                return resolved

        value = Value()

        class RelativeTo:
            def __truediv__(
                relative_self,
                other: object,
            ) -> object:
                raise AssertionError(
                    "joined an already-absolute pointer"
                )

        path_factories = iter(
            (
                lambda observed: value,
                lambda observed: absolute,
            )
        )

        observed = self.pointer_path(
            raw_value,
            relative_to=RelativeTo(),
            path_factory=lambda: next(path_factories),
            absolute_path=lambda: (
                lambda observed: "/absolute"
            ),
            filesystem_path=lambda: (
                lambda observed: "/candidate"
            ),
        )

        self.assertIs(observed, resolved)
        self.assertEqual(
            events,
            ["is-absolute", "resolve", "compare"],
        )

    def test_exact_pointer_path_translates_only_resolve_os_failures(
        self,
    ) -> None:
        class SelectedOSError(Exception):
            pass

        class SelectedRuntimeError(Exception):
            pass

        class PointerError(Exception):
            pass

        for selected_type in (
            SelectedOSError,
            SelectedRuntimeError,
        ):
            with self.subTest(selected_type=selected_type.__name__):
                events: list[str] = []
                original = selected_type("resolution failed")

                class Label:
                    def __format__(
                        label_self,
                        specification: str,
                    ) -> str:
                        self.assertEqual(specification, "")
                        events.append("format-label")
                        return "the pointer"

                class Candidate:
                    def is_absolute(candidate_self) -> bool:
                        return True

                    def resolve(
                        candidate_self,
                        *,
                        strict: bool,
                    ) -> None:
                        self.assertTrue(strict)
                        events.append("resolve")
                        raise original

                candidate = Candidate()
                factories = iter(
                    (
                        lambda observed: candidate,
                        lambda observed: object(),
                    )
                )

                def os_error_type() -> type[BaseException]:
                    events.append("os-error-provider")
                    return SelectedOSError

                def runtime_error_type() -> type[BaseException]:
                    events.append("runtime-error-provider")
                    return SelectedRuntimeError

                def error_type() -> type[BaseException]:
                    events.append("error-provider")
                    return PointerError

                with self.assertRaises(PointerError) as caught:
                    self.pointer_path(
                        object(),
                        relative_to=object(),
                        label=Label(),
                        path_factory=lambda: next(factories),
                        absolute_path=lambda: (
                            lambda observed: "/candidate"
                        ),
                        filesystem_path=lambda: (
                            lambda observed: "/candidate"
                        ),
                        os_error_type=os_error_type,
                        runtime_error_type=runtime_error_type,
                        error_type=error_type,
                    )

                self.assertEqual(
                    str(caught.exception),
                    "the pointer points to an unavailable path",
                )
                self.assertIs(caught.exception.__cause__, original)
                self.assertIs(caught.exception.__context__, original)
                self.assertEqual(
                    events,
                    [
                        "resolve",
                        "os-error-provider",
                        "runtime-error-provider",
                        "error-provider",
                        "format-label",
                    ],
                )

    def test_exact_pointer_path_leaves_conversion_failures_untranslated(
        self,
    ) -> None:
        class SelectedOSError(Exception):
            pass

        stages = (
            "raw-path-provider",
            "raw-path-call",
            "is-absolute",
            "relative-join",
            "absolute-path-provider",
            "absolute-function-provider",
            "filesystem-function-provider",
            "filesystem-function-call",
            "absolute-function-call",
            "absolute-path-call",
        )

        for stage in stages:
            with self.subTest(unwrapped_stage=stage):
                original = SelectedOSError(stage)
                provider_count = 0

                def fail_at(observed: str) -> None:
                    if stage == observed:
                        raise original

                class Candidate:
                    def resolve(
                        candidate_self,
                        *,
                        strict: bool,
                    ) -> None:
                        raise AssertionError(
                            "resolved after a conversion failure"
                        )

                candidate = Candidate()

                class Value:
                    def is_absolute(value_self) -> bool:
                        fail_at("is-absolute")
                        return stage != "relative-join"

                    def resolve(
                        value_self,
                        *,
                        strict: bool,
                    ) -> None:
                        raise AssertionError(
                            "resolved after a conversion failure"
                        )

                value = Value()

                class RelativeTo:
                    def __truediv__(
                        relative_self,
                        other: object,
                    ) -> object:
                        fail_at("relative-join")
                        return candidate

                def path_factory() -> object:
                    nonlocal provider_count
                    provider_count += 1
                    provider_stage = (
                        "raw-path-provider"
                        if provider_count == 1
                        else "absolute-path-provider"
                    )
                    fail_at(provider_stage)
                    call_stage = (
                        "raw-path-call"
                        if provider_count == 1
                        else "absolute-path-call"
                    )

                    def construct(observed: object) -> object:
                        fail_at(call_stage)
                        return (
                            value
                            if provider_count == 1
                            else object()
                        )

                    return construct

                def absolute_path() -> object:
                    fail_at("absolute-function-provider")

                    def make_absolute(observed: object) -> str:
                        fail_at("absolute-function-call")
                        return "/candidate"

                    return make_absolute

                def filesystem_path() -> object:
                    fail_at("filesystem-function-provider")

                    def convert(observed: object) -> str:
                        fail_at("filesystem-function-call")
                        return "/candidate"

                    return convert

                blocked_os_type = mock.Mock(
                    side_effect=AssertionError(
                        "caught a pre-resolution OSError"
                    )
                )
                blocked_runtime_type = mock.Mock(
                    side_effect=AssertionError(
                        "caught a pre-resolution RuntimeError"
                    )
                )
                blocked_error_type = mock.Mock(
                    side_effect=AssertionError(
                        "translated a pre-resolution failure"
                    )
                )

                with self.assertRaises(SelectedOSError) as caught:
                    self.pointer_path(
                        object(),
                        relative_to=RelativeTo(),
                        path_factory=path_factory,
                        absolute_path=absolute_path,
                        filesystem_path=filesystem_path,
                        os_error_type=blocked_os_type,
                        runtime_error_type=blocked_runtime_type,
                        error_type=blocked_error_type,
                    )

                self.assertIs(caught.exception, original)
                blocked_os_type.assert_not_called()
                blocked_runtime_type.assert_not_called()
                blocked_error_type.assert_not_called()

    def test_exact_pointer_path_does_not_translate_nonmatching_resolution(
        self,
    ) -> None:
        class SelectedOSError(Exception):
            pass

        class SelectedRuntimeError(Exception):
            pass

        original = LookupError("resolution failed")
        events: list[str] = []

        class Candidate:
            def is_absolute(candidate_self) -> bool:
                return True

            def resolve(
                candidate_self,
                *,
                strict: bool,
            ) -> None:
                raise original

        candidate = Candidate()
        factories = iter(
            (
                lambda observed: candidate,
                lambda observed: object(),
            )
        )

        def os_error_type() -> type[BaseException]:
            events.append("os-error-provider")
            return SelectedOSError

        def runtime_error_type() -> type[BaseException]:
            events.append("runtime-error-provider")
            return SelectedRuntimeError

        blocked_error_type = mock.Mock(
            side_effect=AssertionError(
                "translated a nonmatching resolution failure"
            )
        )
        with self.assertRaises(LookupError) as caught:
            self.pointer_path(
                object(),
                relative_to=object(),
                path_factory=lambda: next(factories),
                absolute_path=lambda: (
                    lambda observed: "/candidate"
                ),
                filesystem_path=lambda: (
                    lambda observed: "/candidate"
                ),
                os_error_type=os_error_type,
                runtime_error_type=runtime_error_type,
                error_type=blocked_error_type,
            )

        self.assertIs(caught.exception, original)
        self.assertEqual(
            events,
            ["os-error-provider", "runtime-error-provider"],
        )
        blocked_error_type.assert_not_called()

    def test_exact_pointer_path_matcher_failures_replace_resolution(
        self,
    ) -> None:
        class SelectedOSError(Exception):
            pass

        original = SelectedOSError("resolution failed")

        class Candidate:
            def is_absolute(candidate_self) -> bool:
                return True

            def resolve(
                candidate_self,
                *,
                strict: bool,
            ) -> None:
                raise original

        for broken_matcher in ("os", "runtime"):
            with self.subTest(broken_matcher=broken_matcher):
                matcher_failure = RuntimeError(
                    f"{broken_matcher} matcher failed"
                )

                def os_error_type() -> type[BaseException]:
                    if broken_matcher == "os":
                        raise matcher_failure
                    return LookupError

                def runtime_error_type() -> type[BaseException]:
                    if broken_matcher == "runtime":
                        raise matcher_failure
                    return SelectedOSError

                factories = iter(
                    (
                        lambda observed: Candidate(),
                        lambda observed: object(),
                    )
                )
                blocked_error_type = mock.Mock(
                    side_effect=AssertionError(
                        "translated after matcher failure"
                    )
                )

                with self.assertRaises(RuntimeError) as caught:
                    self.pointer_path(
                        object(),
                        relative_to=object(),
                        path_factory=lambda: next(factories),
                        absolute_path=lambda: (
                            lambda observed: "/candidate"
                        ),
                        filesystem_path=lambda: (
                            lambda observed: "/candidate"
                        ),
                        os_error_type=os_error_type,
                        runtime_error_type=runtime_error_type,
                        error_type=blocked_error_type,
                    )

                self.assertIs(caught.exception, matcher_failure)
                self.assertIs(caught.exception.__context__, original)
                blocked_error_type.assert_not_called()

    def test_exact_pointer_path_mismatch_and_comparison_boundaries(
        self,
    ) -> None:
        class PointerError(Exception):
            pass

        events: list[str] = []

        class Label:
            def __format__(
                label_self,
                specification: str,
            ) -> str:
                self.assertEqual(specification, "")
                events.append("format-label")
                return "the pointer"

        class Comparison:
            def __bool__(comparison_self) -> bool:
                events.append("comparison-truth")
                return True

        class Resolved:
            def __ne__(resolved_self, other: object) -> object:
                events.append("compare")
                return Comparison()

        class Candidate:
            def is_absolute(candidate_self) -> bool:
                return True

            def resolve(
                candidate_self,
                *,
                strict: bool,
            ) -> object:
                return Resolved()

        candidate = Candidate()
        factories = iter(
            (
                lambda observed: candidate,
                lambda observed: object(),
            )
        )

        def error_type() -> type[BaseException]:
            events.append("error-provider")
            return PointerError

        with self.assertRaises(PointerError) as caught:
            self.pointer_path(
                object(),
                relative_to=object(),
                label=Label(),
                path_factory=lambda: next(factories),
                absolute_path=lambda: (
                    lambda observed: "/candidate"
                ),
                filesystem_path=lambda: (
                    lambda observed: "/candidate"
                ),
                os_error_type=mock.Mock(
                    side_effect=AssertionError(
                        "resolved matcher after successful resolution"
                    )
                ),
                runtime_error_type=mock.Mock(
                    side_effect=AssertionError(
                        "resolved matcher after successful resolution"
                    )
                ),
                error_type=error_type,
            )

        self.assertEqual(
            str(caught.exception),
            "the pointer traverses a symbolic path",
        )
        self.assertIsNone(caught.exception.__cause__)
        self.assertEqual(
            events,
            [
                "compare",
                "comparison-truth",
                "error-provider",
                "format-label",
            ],
        )

        original = OSError("comparison failed")

        class BrokenResolved:
            def __ne__(
                resolved_self,
                other: object,
            ) -> bool:
                raise original

        class BrokenCandidate(Candidate):
            def resolve(
                candidate_self,
                *,
                strict: bool,
            ) -> object:
                return BrokenResolved()

        factories = iter(
            (
                lambda observed: BrokenCandidate(),
                lambda observed: object(),
            )
        )
        blocked_error_type = mock.Mock(
            side_effect=AssertionError(
                "translated a post-resolution comparison failure"
            )
        )
        with self.assertRaises(OSError) as comparison_caught:
            self.pointer_path(
                object(),
                relative_to=object(),
                path_factory=lambda: next(factories),
                absolute_path=lambda: (
                    lambda observed: "/candidate"
                ),
                filesystem_path=lambda: (
                    lambda observed: "/candidate"
                ),
                os_error_type=mock.Mock(
                    side_effect=AssertionError(
                        "matched a post-resolution failure"
                    )
                ),
                runtime_error_type=mock.Mock(
                    side_effect=AssertionError(
                        "matched a post-resolution failure"
                    )
                ),
                error_type=blocked_error_type,
            )

        self.assertIs(comparison_caught.exception, original)
        blocked_error_type.assert_not_called()

    def test_exact_real_directory_preserves_success_order_and_return(
        self,
    ) -> None:
        events: list[tuple[str, object]] = []
        path = object()
        filesystem_value = object()
        absolute_value = object()

        class Metadata:
            @property
            def st_mode(metadata_self) -> object:
                events.append(("metadata-mode", None))
                return mode

        metadata = Metadata()
        mode = object()

        class Comparison:
            def __bool__(comparison_self) -> bool:
                events.append(("comparison-truth", None))
                return False

        class Resolved:
            def __ne__(resolved_self, other: object) -> object:
                events.append(("resolved-ne", other))
                self.assertIs(other, absolute)
                return Comparison()

        resolved = Resolved()

        class Absolute:
            def lstat(absolute_self) -> object:
                events.append(("lstat", None))
                return metadata

            def resolve(
                absolute_self,
                *,
                strict: bool,
            ) -> object:
                events.append(("resolve", strict))
                return resolved

        absolute = Absolute()

        def path_factory() -> object:
            events.append(("path-factory-provider", None))

            def construct(observed: object) -> object:
                events.append(("path-factory-call", observed))
                self.assertIs(observed, absolute_value)
                return absolute

            return construct

        def absolute_path() -> object:
            events.append(("absolute-path-provider", None))

            def make_absolute(observed: object) -> object:
                events.append(("absolute-path-call", observed))
                self.assertIs(observed, filesystem_value)
                return absolute_value

            return make_absolute

        def filesystem_path() -> object:
            events.append(("filesystem-path-provider", None))

            def convert(observed: object) -> object:
                events.append(("filesystem-path-call", observed))
                self.assertIs(observed, path)
                return filesystem_value

            return convert

        class DirectoryTruth:
            def __bool__(truth_self) -> bool:
                events.append(("directory-truth", None))
                return True

        def directory_test() -> object:
            events.append(("directory-test-provider", None))

            def test(observed: object) -> object:
                events.append(("directory-test-call", observed))
                self.assertIs(observed, mode)
                return DirectoryTruth()

            return test

        observed = self.real_directory(
            path,
            path_factory=path_factory,
            absolute_path=absolute_path,
            filesystem_path=filesystem_path,
            os_error_type=mock.Mock(
                side_effect=AssertionError(
                    "resolved OSError on success"
                )
            ),
            runtime_error_type=mock.Mock(
                side_effect=AssertionError(
                    "resolved RuntimeError on success"
                )
            ),
            directory_test=directory_test,
            error_type=mock.Mock(
                side_effect=AssertionError(
                    "resolved launcher error on success"
                )
            ),
        )

        self.assertIs(observed, absolute)
        self.assertIsNot(observed, resolved)
        self.assertEqual(
            events,
            [
                ("path-factory-provider", None),
                ("absolute-path-provider", None),
                ("filesystem-path-provider", None),
                ("filesystem-path-call", path),
                ("absolute-path-call", filesystem_value),
                ("path-factory-call", absolute_value),
                ("lstat", None),
                ("resolve", True),
                ("directory-test-provider", None),
                ("metadata-mode", None),
                ("directory-test-call", mode),
                ("directory-truth", None),
                ("resolved-ne", absolute),
                ("comparison-truth", None),
            ],
        )

    def test_exact_real_directory_translates_lstat_and_resolve_failures(
        self,
    ) -> None:
        class SelectedOSError(Exception):
            pass

        class SelectedRuntimeError(Exception):
            pass

        class DirectoryError(Exception):
            pass

        for stage in ("lstat", "resolve"):
            for selected_type in (
                SelectedOSError,
                SelectedRuntimeError,
            ):
                with self.subTest(
                    stage=stage,
                    selected_type=selected_type.__name__,
                ):
                    events: list[str] = []
                    original = selected_type(f"{stage} failed")

                    class Label:
                        def __format__(
                            label_self,
                            specification: str,
                        ) -> str:
                            self.assertEqual(specification, "")
                            events.append("format-label")
                            return "the directory"

                    class Absolute:
                        def lstat(absolute_self) -> object:
                            events.append("lstat")
                            if stage == "lstat":
                                raise original
                            return SimpleNamespace(st_mode=0)

                        def resolve(
                            absolute_self,
                            *,
                            strict: bool,
                        ) -> None:
                            self.assertTrue(strict)
                            events.append("resolve")
                            raise original

                    def os_error_type() -> type[BaseException]:
                        events.append("os-error-provider")
                        return SelectedOSError

                    def runtime_error_type() -> type[BaseException]:
                        events.append("runtime-error-provider")
                        return SelectedRuntimeError

                    def error_type() -> type[BaseException]:
                        events.append("error-provider")
                        return DirectoryError

                    with self.assertRaises(DirectoryError) as caught:
                        self.real_directory(
                            object(),
                            label=Label(),
                            path_factory=lambda: (
                                lambda observed: Absolute()
                            ),
                            absolute_path=lambda: (
                                lambda observed: "/directory"
                            ),
                            filesystem_path=lambda: (
                                lambda observed: "/directory"
                            ),
                            os_error_type=os_error_type,
                            runtime_error_type=runtime_error_type,
                            directory_test=mock.Mock(
                                side_effect=AssertionError(
                                    "tested a directory after failure"
                                )
                            ),
                            error_type=error_type,
                        )

                    self.assertEqual(
                        str(caught.exception),
                        "the directory is unavailable",
                    )
                    self.assertIs(
                        caught.exception.__cause__,
                        original,
                    )
                    self.assertIs(
                        caught.exception.__context__,
                        original,
                    )
                    self.assertEqual(
                        events,
                        (
                            ["lstat"]
                            if stage == "lstat"
                            else ["lstat", "resolve"]
                        )
                        + [
                            "os-error-provider",
                            "runtime-error-provider",
                            "error-provider",
                            "format-label",
                        ],
                    )

    def test_exact_real_directory_leaves_conversion_failures_untranslated(
        self,
    ) -> None:
        class SelectedOSError(Exception):
            pass

        stages = (
            "path-provider",
            "absolute-function-provider",
            "filesystem-function-provider",
            "filesystem-function-call",
            "absolute-function-call",
            "path-call",
        )

        for stage in stages:
            with self.subTest(unwrapped_stage=stage):
                original = SelectedOSError(stage)

                def fail_at(observed: str) -> None:
                    if stage == observed:
                        raise original

                def path_factory() -> object:
                    fail_at("path-provider")

                    def construct(observed: object) -> object:
                        fail_at("path-call")
                        raise AssertionError(
                            "constructed after selected failure"
                        )

                    return construct

                def absolute_path() -> object:
                    fail_at("absolute-function-provider")

                    def make_absolute(observed: object) -> str:
                        fail_at("absolute-function-call")
                        return "/directory"

                    return make_absolute

                def filesystem_path() -> object:
                    fail_at("filesystem-function-provider")

                    def convert(observed: object) -> str:
                        fail_at("filesystem-function-call")
                        return "/directory"

                    return convert

                blocked_os_type = mock.Mock(
                    side_effect=AssertionError(
                        "caught a pre-lstat OSError"
                    )
                )
                blocked_runtime_type = mock.Mock(
                    side_effect=AssertionError(
                        "caught a pre-lstat RuntimeError"
                    )
                )
                blocked_directory_test = mock.Mock(
                    side_effect=AssertionError(
                        "tested a pre-lstat value"
                    )
                )
                blocked_error_type = mock.Mock(
                    side_effect=AssertionError(
                        "translated a pre-lstat failure"
                    )
                )

                with self.assertRaises(SelectedOSError) as caught:
                    self.real_directory(
                        object(),
                        path_factory=path_factory,
                        absolute_path=absolute_path,
                        filesystem_path=filesystem_path,
                        os_error_type=blocked_os_type,
                        runtime_error_type=blocked_runtime_type,
                        directory_test=blocked_directory_test,
                        error_type=blocked_error_type,
                    )

                self.assertIs(caught.exception, original)
                blocked_os_type.assert_not_called()
                blocked_runtime_type.assert_not_called()
                blocked_directory_test.assert_not_called()
                blocked_error_type.assert_not_called()

    def test_exact_real_directory_does_not_translate_nonmatching_io(
        self,
    ) -> None:
        class SelectedOSError(Exception):
            pass

        class SelectedRuntimeError(Exception):
            pass

        for stage in ("lstat", "resolve"):
            with self.subTest(unwrapped_stage=stage):
                original = LookupError(f"{stage} failed")
                events: list[str] = []

                class Absolute:
                    def lstat(absolute_self) -> object:
                        if stage == "lstat":
                            raise original
                        return SimpleNamespace(st_mode=0)

                    def resolve(
                        absolute_self,
                        *,
                        strict: bool,
                    ) -> None:
                        raise original

                def os_error_type() -> type[BaseException]:
                    events.append("os-error-provider")
                    return SelectedOSError

                def runtime_error_type() -> type[BaseException]:
                    events.append("runtime-error-provider")
                    return SelectedRuntimeError

                blocked_directory_test = mock.Mock(
                    side_effect=AssertionError(
                        "tested directory after failed I/O"
                    )
                )
                blocked_error_type = mock.Mock(
                    side_effect=AssertionError(
                        "translated nonmatching I/O"
                    )
                )

                with self.assertRaises(LookupError) as caught:
                    self.real_directory(
                        object(),
                        path_factory=lambda: (
                            lambda observed: Absolute()
                        ),
                        absolute_path=lambda: (
                            lambda observed: "/directory"
                        ),
                        filesystem_path=lambda: (
                            lambda observed: "/directory"
                        ),
                        os_error_type=os_error_type,
                        runtime_error_type=runtime_error_type,
                        directory_test=blocked_directory_test,
                        error_type=blocked_error_type,
                    )

                self.assertIs(caught.exception, original)
                self.assertEqual(
                    events,
                    [
                        "os-error-provider",
                        "runtime-error-provider",
                    ],
                )
                blocked_directory_test.assert_not_called()
                blocked_error_type.assert_not_called()

    def test_exact_real_directory_matcher_failures_replace_io_failure(
        self,
    ) -> None:
        class SelectedOSError(Exception):
            pass

        original = SelectedOSError("lstat failed")

        class Absolute:
            def lstat(absolute_self) -> None:
                raise original

            def resolve(
                absolute_self,
                *,
                strict: bool,
            ) -> None:
                raise AssertionError("resolved after lstat failure")

        for broken_matcher in ("os", "runtime"):
            with self.subTest(broken_matcher=broken_matcher):
                matcher_failure = RuntimeError(
                    f"{broken_matcher} matcher failed"
                )

                def os_error_type() -> type[BaseException]:
                    if broken_matcher == "os":
                        raise matcher_failure
                    return LookupError

                def runtime_error_type() -> type[BaseException]:
                    if broken_matcher == "runtime":
                        raise matcher_failure
                    return SelectedOSError

                blocked_error_type = mock.Mock(
                    side_effect=AssertionError(
                        "translated after matcher failure"
                    )
                )
                with self.assertRaises(RuntimeError) as caught:
                    self.real_directory(
                        object(),
                        path_factory=lambda: (
                            lambda observed: Absolute()
                        ),
                        absolute_path=lambda: (
                            lambda observed: "/directory"
                        ),
                        filesystem_path=lambda: (
                            lambda observed: "/directory"
                        ),
                        os_error_type=os_error_type,
                        runtime_error_type=runtime_error_type,
                        directory_test=mock.Mock(
                            side_effect=AssertionError(
                                "tested after lstat failure"
                            )
                        ),
                        error_type=blocked_error_type,
                    )

                self.assertIs(caught.exception, matcher_failure)
                self.assertIs(
                    caught.exception.__context__,
                    original,
                )
                blocked_error_type.assert_not_called()

    def test_exact_real_directory_rejections_short_circuit_exactly(
        self,
    ) -> None:
        class DirectoryError(Exception):
            pass

        for rejection in ("not-directory", "symbolic"):
            with self.subTest(rejection=rejection):
                events: list[str] = []

                class Label:
                    def __format__(
                        label_self,
                        specification: str,
                    ) -> str:
                        self.assertEqual(specification, "")
                        events.append("format-label")
                        return "the directory"

                class Metadata:
                    @property
                    def st_mode(metadata_self) -> object:
                        events.append("metadata-mode")
                        return object()

                class Comparison:
                    def __bool__(comparison_self) -> bool:
                        events.append("comparison-truth")
                        return True

                class Resolved:
                    def __ne__(
                        resolved_self,
                        other: object,
                    ) -> object:
                        events.append("compare")
                        return Comparison()

                class Absolute:
                    def lstat(absolute_self) -> object:
                        events.append("lstat")
                        return Metadata()

                    def resolve(
                        absolute_self,
                        *,
                        strict: bool,
                    ) -> object:
                        events.append("resolve")
                        return Resolved()

                class DirectoryTruth:
                    def __bool__(truth_self) -> bool:
                        events.append("directory-truth")
                        return rejection == "symbolic"

                def directory_test() -> object:
                    events.append("directory-provider")

                    def test(observed: object) -> object:
                        events.append("directory-call")
                        return DirectoryTruth()

                    return test

                def error_type() -> type[BaseException]:
                    events.append("error-provider")
                    return DirectoryError

                with self.assertRaises(DirectoryError) as caught:
                    self.real_directory(
                        object(),
                        label=Label(),
                        path_factory=lambda: (
                            lambda observed: Absolute()
                        ),
                        absolute_path=lambda: (
                            lambda observed: "/directory"
                        ),
                        filesystem_path=lambda: (
                            lambda observed: "/directory"
                        ),
                        os_error_type=mock.Mock(
                            side_effect=AssertionError(
                                "matched successful I/O"
                            )
                        ),
                        runtime_error_type=mock.Mock(
                            side_effect=AssertionError(
                                "matched successful I/O"
                            )
                        ),
                        directory_test=directory_test,
                        error_type=error_type,
                    )

                self.assertEqual(
                    str(caught.exception),
                    "the directory is not an exact real directory",
                )
                self.assertIsNone(caught.exception.__cause__)
                self.assertEqual(
                    events,
                    [
                        "lstat",
                        "resolve",
                        "directory-provider",
                        "metadata-mode",
                        "directory-call",
                        "directory-truth",
                    ]
                    + (
                        ["compare", "comparison-truth"]
                        if rejection == "symbolic"
                        else []
                    )
                    + ["error-provider", "format-label"],
                )

    def test_exact_real_directory_leaves_post_io_failures_untranslated(
        self,
    ) -> None:
        class SelectedOSError(Exception):
            pass

        stages = (
            "directory-provider",
            "metadata-mode",
            "directory-call",
            "directory-truth",
            "compare",
            "comparison-truth",
        )

        for stage in stages:
            with self.subTest(unwrapped_stage=stage):
                original = SelectedOSError(stage)

                def fail_at(observed: str) -> None:
                    if stage == observed:
                        raise original

                class Metadata:
                    @property
                    def st_mode(metadata_self) -> object:
                        fail_at("metadata-mode")
                        return object()

                class Comparison:
                    def __bool__(comparison_self) -> bool:
                        fail_at("comparison-truth")
                        return False

                class Resolved:
                    def __ne__(
                        resolved_self,
                        other: object,
                    ) -> object:
                        fail_at("compare")
                        return Comparison()

                class Absolute:
                    def lstat(absolute_self) -> object:
                        return Metadata()

                    def resolve(
                        absolute_self,
                        *,
                        strict: bool,
                    ) -> object:
                        return Resolved()

                class DirectoryTruth:
                    def __bool__(truth_self) -> bool:
                        fail_at("directory-truth")
                        return True

                def directory_test() -> object:
                    fail_at("directory-provider")

                    def test(observed: object) -> object:
                        fail_at("directory-call")
                        return DirectoryTruth()

                    return test

                blocked_os_type = mock.Mock(
                    side_effect=AssertionError(
                        "matched a post-I/O failure"
                    )
                )
                blocked_runtime_type = mock.Mock(
                    side_effect=AssertionError(
                        "matched a post-I/O failure"
                    )
                )
                blocked_error_type = mock.Mock(
                    side_effect=AssertionError(
                        "translated a post-I/O failure"
                    )
                )

                with self.assertRaises(SelectedOSError) as caught:
                    self.real_directory(
                        object(),
                        path_factory=lambda: (
                            lambda observed: Absolute()
                        ),
                        absolute_path=lambda: (
                            lambda observed: "/directory"
                        ),
                        filesystem_path=lambda: (
                            lambda observed: "/directory"
                        ),
                        os_error_type=blocked_os_type,
                        runtime_error_type=blocked_runtime_type,
                        directory_test=directory_test,
                        error_type=blocked_error_type,
                    )

                self.assertIs(caught.exception, original)
                blocked_os_type.assert_not_called()
                blocked_runtime_type.assert_not_called()
                blocked_error_type.assert_not_called()

    def test_engine_exact_path_wrappers_forward_fresh_lazy_globals(
        self,
    ) -> None:
        raw_value = object()
        relative_to = object()
        directory_path = object()
        pointer_result = object()
        directory_result = object()

        initial_path = object()
        pointer_path_one = object()
        pointer_path_two = object()
        directory_path_one = object()
        directory_path_two = object()

        initial_absolute = object()
        pointer_absolute_one = object()
        pointer_absolute_two = object()
        directory_absolute_one = object()
        directory_absolute_two = object()

        initial_filesystem = object()
        pointer_filesystem_one = object()
        pointer_filesystem_two = object()
        directory_filesystem_one = object()
        directory_filesystem_two = object()

        initial_directory_test = object()
        directory_test_one = object()
        directory_test_two = object()

        class InitialOSError(Exception):
            pass

        class PointerOSErrorOne(Exception):
            pass

        class PointerOSErrorTwo(Exception):
            pass

        class DirectoryOSErrorOne(Exception):
            pass

        class DirectoryOSErrorTwo(Exception):
            pass

        class InitialRuntimeError(Exception):
            pass

        class PointerRuntimeErrorOne(Exception):
            pass

        class PointerRuntimeErrorTwo(Exception):
            pass

        class DirectoryRuntimeErrorOne(Exception):
            pass

        class DirectoryRuntimeErrorTwo(Exception):
            pass

        class InitialLauncherError(Exception):
            pass

        class PointerLauncherErrorOne(Exception):
            pass

        class PointerLauncherErrorTwo(Exception):
            pass

        class DirectoryLauncherErrorOne(Exception):
            pass

        class DirectoryLauncherErrorTwo(Exception):
            pass

        def os_namespace(
            absolute: object,
            filesystem: object,
        ) -> object:
            return SimpleNamespace(
                path=SimpleNamespace(abspath=absolute),
                fspath=filesystem,
            )

        initial_os = os_namespace(
            initial_absolute,
            initial_filesystem,
        )

        def pointer_kernel(
            observed_raw: object,
            **dependencies: object,
        ) -> object:
            self.assertIs(observed_raw, raw_value)
            self.assertEqual(
                tuple(dependencies),
                (
                    "relative_to",
                    "label",
                    "path_factory",
                    "absolute_path",
                    "filesystem_path",
                    "os_error_type",
                    "runtime_error_type",
                    "error_type",
                ),
            )
            self.assertIs(
                dependencies["relative_to"],
                relative_to,
            )
            self.assertEqual(
                dependencies["label"],
                "the pointer",
            )

            self.engine.Path = pointer_path_one
            self.assertIs(
                dependencies["path_factory"](),
                pointer_path_one,
            )
            self.engine.Path = pointer_path_two
            self.assertIs(
                dependencies["path_factory"](),
                pointer_path_two,
            )

            self.engine.os = os_namespace(
                pointer_absolute_one,
                pointer_filesystem_one,
            )
            self.assertIs(
                dependencies["absolute_path"](),
                pointer_absolute_one,
            )
            self.assertIs(
                dependencies["filesystem_path"](),
                pointer_filesystem_one,
            )
            self.engine.os = os_namespace(
                pointer_absolute_two,
                pointer_filesystem_two,
            )
            self.assertIs(
                dependencies["absolute_path"](),
                pointer_absolute_two,
            )
            self.assertIs(
                dependencies["filesystem_path"](),
                pointer_filesystem_two,
            )

            self.engine.OSError = PointerOSErrorOne
            self.assertIs(
                dependencies["os_error_type"](),
                PointerOSErrorOne,
            )
            self.engine.OSError = PointerOSErrorTwo
            self.assertIs(
                dependencies["os_error_type"](),
                PointerOSErrorTwo,
            )
            self.engine.RuntimeError = PointerRuntimeErrorOne
            self.assertIs(
                dependencies["runtime_error_type"](),
                PointerRuntimeErrorOne,
            )
            self.engine.RuntimeError = PointerRuntimeErrorTwo
            self.assertIs(
                dependencies["runtime_error_type"](),
                PointerRuntimeErrorTwo,
            )
            self.engine.LauncherError = PointerLauncherErrorOne
            self.assertIs(
                dependencies["error_type"](),
                PointerLauncherErrorOne,
            )
            self.engine.LauncherError = PointerLauncherErrorTwo
            self.assertIs(
                dependencies["error_type"](),
                PointerLauncherErrorTwo,
            )
            return pointer_result

        def directory_kernel(
            observed_path: object,
            **dependencies: object,
        ) -> object:
            self.assertIs(observed_path, directory_path)
            self.assertEqual(
                tuple(dependencies),
                (
                    "label",
                    "path_factory",
                    "absolute_path",
                    "filesystem_path",
                    "os_error_type",
                    "runtime_error_type",
                    "directory_test",
                    "error_type",
                ),
            )
            self.assertEqual(
                dependencies["label"],
                "the directory",
            )

            self.engine.Path = directory_path_one
            self.assertIs(
                dependencies["path_factory"](),
                directory_path_one,
            )
            self.engine.Path = directory_path_two
            self.assertIs(
                dependencies["path_factory"](),
                directory_path_two,
            )

            self.engine.os = os_namespace(
                directory_absolute_one,
                directory_filesystem_one,
            )
            self.assertIs(
                dependencies["absolute_path"](),
                directory_absolute_one,
            )
            self.assertIs(
                dependencies["filesystem_path"](),
                directory_filesystem_one,
            )
            self.engine.os = os_namespace(
                directory_absolute_two,
                directory_filesystem_two,
            )
            self.assertIs(
                dependencies["absolute_path"](),
                directory_absolute_two,
            )
            self.assertIs(
                dependencies["filesystem_path"](),
                directory_filesystem_two,
            )

            self.engine.OSError = DirectoryOSErrorOne
            self.assertIs(
                dependencies["os_error_type"](),
                DirectoryOSErrorOne,
            )
            self.engine.OSError = DirectoryOSErrorTwo
            self.assertIs(
                dependencies["os_error_type"](),
                DirectoryOSErrorTwo,
            )
            self.engine.RuntimeError = DirectoryRuntimeErrorOne
            self.assertIs(
                dependencies["runtime_error_type"](),
                DirectoryRuntimeErrorOne,
            )
            self.engine.RuntimeError = DirectoryRuntimeErrorTwo
            self.assertIs(
                dependencies["runtime_error_type"](),
                DirectoryRuntimeErrorTwo,
            )

            self.engine.stat = SimpleNamespace(
                S_ISDIR=directory_test_one
            )
            self.assertIs(
                dependencies["directory_test"](),
                directory_test_one,
            )
            self.engine.stat = SimpleNamespace(
                S_ISDIR=directory_test_two
            )
            self.assertIs(
                dependencies["directory_test"](),
                directory_test_two,
            )

            self.engine.LauncherError = DirectoryLauncherErrorOne
            self.assertIs(
                dependencies["error_type"](),
                DirectoryLauncherErrorOne,
            )
            self.engine.LauncherError = DirectoryLauncherErrorTwo
            self.assertIs(
                dependencies["error_type"](),
                DirectoryLauncherErrorTwo,
            )
            return directory_result

        with (
            mock.patch.object(
                self.engine,
                "_exact_pointer_path",
                side_effect=pointer_kernel,
            ) as pointer_mock,
            mock.patch.object(
                self.engine,
                "_exact_real_directory",
                side_effect=directory_kernel,
            ) as directory_mock,
            mock.patch.object(
                self.engine,
                "Path",
                initial_path,
            ),
            mock.patch.object(
                self.engine,
                "os",
                initial_os,
            ),
            mock.patch.object(
                self.engine,
                "stat",
                SimpleNamespace(S_ISDIR=initial_directory_test),
            ),
            mock.patch.object(
                self.engine,
                "OSError",
                InitialOSError,
                create=True,
            ),
            mock.patch.object(
                self.engine,
                "RuntimeError",
                InitialRuntimeError,
                create=True,
            ),
            mock.patch.object(
                self.engine,
                "LauncherError",
                InitialLauncherError,
            ),
        ):
            observed_pointer = self.engine.exact_pointer_path(
                raw_value,
                relative_to=relative_to,
                label="the pointer",
            )
            observed_directory = self.engine.exact_real_directory(
                directory_path,
                label="the directory",
            )

        self.assertIs(observed_pointer, pointer_result)
        self.assertIs(observed_directory, directory_result)
        pointer_mock.assert_called_once()
        directory_mock.assert_called_once()

    def test_engine_exact_path_wrappers_match_real_filesystem_behavior(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            real_directory = root / "real-directory"
            real_directory.mkdir()
            nested = root / "nested"
            nested.mkdir()
            real_file = root / "real-file"
            real_file.write_bytes(b"contents")

            self.assertEqual(
                self.engine.exact_pointer_path(
                    "real-directory",
                    relative_to=root,
                    label="the pointer",
                ),
                real_directory.resolve(strict=True),
            )
            self.assertEqual(
                self.engine.exact_pointer_path(
                    "real-file",
                    relative_to=root,
                    label="the pointer",
                ),
                real_file.resolve(strict=True),
            )
            self.assertEqual(
                self.engine.exact_pointer_path(
                    "../real-file",
                    relative_to=nested,
                    label="the pointer",
                ),
                real_file.resolve(strict=True),
            )
            self.assertEqual(
                self.engine.exact_pointer_path(
                    "nested/../real-directory",
                    relative_to=root,
                    label="the pointer",
                ),
                real_directory.resolve(strict=True),
            )

            class PoisonRelative:
                def __truediv__(
                    relative_self,
                    other: object,
                ) -> object:
                    raise AssertionError(
                        "joined an absolute filesystem pointer"
                    )

            self.assertEqual(
                self.engine.exact_pointer_path(
                    os.fspath(real_file),
                    relative_to=PoisonRelative(),
                    label="the pointer",
                ),
                real_file.resolve(strict=True),
            )

            directory_symlink = root / "directory-link"
            directory_symlink.symlink_to(
                real_directory,
                target_is_directory=True,
            )
            with self.assertRaises(
                self.engine.LauncherError
            ) as caught:
                self.engine.exact_pointer_path(
                    "directory-link",
                    relative_to=root,
                    label="the symbolic pointer",
                )
            self.assertEqual(
                str(caught.exception),
                "the symbolic pointer traverses a symbolic path",
            )
            self.assertIsNone(caught.exception.__cause__)

            parent_symlink = root / "parent-link"
            parent_symlink.symlink_to(root, target_is_directory=True)
            with self.assertRaises(
                self.engine.LauncherError
            ) as caught:
                self.engine.exact_pointer_path(
                    "parent-link/real-file",
                    relative_to=root,
                    label="the parent-symbolic pointer",
                )
            self.assertEqual(
                str(caught.exception),
                "the parent-symbolic pointer "
                "traverses a symbolic path",
            )
            self.assertIsNone(caught.exception.__cause__)

            for raw_value in ("missing", "broken-link"):
                if raw_value == "broken-link":
                    (root / raw_value).symlink_to(root / "absent")
                with self.subTest(pointer=raw_value):
                    with self.assertRaises(
                        self.engine.LauncherError
                    ) as caught:
                        self.engine.exact_pointer_path(
                            raw_value,
                            relative_to=root,
                            label="the unavailable pointer",
                        )
                    self.assertEqual(
                        str(caught.exception),
                        "the unavailable pointer "
                        "points to an unavailable path",
                    )
                    self.assertIsInstance(
                        caught.exception.__cause__,
                        OSError,
                    )

            self.assertEqual(
                self.engine.exact_real_directory(
                    real_directory,
                    label="the directory",
                ),
                real_directory,
            )
            dotted_directory = nested / ".." / "real-directory"
            self.assertEqual(
                self.engine.exact_real_directory(
                    dotted_directory,
                    label="the dotted directory",
                ),
                Path(
                    os.path.abspath(
                        os.fspath(dotted_directory)
                    )
                ),
            )
            relative_directory = Path(
                os.path.relpath(real_directory, Path.cwd())
            )
            self.assertEqual(
                self.engine.exact_real_directory(
                    relative_directory,
                    label="the relative directory",
                ),
                Path(
                    os.path.abspath(
                        os.fspath(relative_directory)
                    )
                ),
            )

            for path, label in (
                (real_file, "the file"),
                (directory_symlink, "the symbolic directory"),
                (
                    parent_symlink / "real-directory",
                    "the parent-symbolic directory",
                ),
            ):
                with self.subTest(directory=label):
                    with self.assertRaises(
                        self.engine.LauncherError
                    ) as caught:
                        self.engine.exact_real_directory(
                            path,
                            label=label,
                        )
                    self.assertEqual(
                        str(caught.exception),
                        f"{label} is not an exact real directory",
                    )
                    self.assertIsNone(caught.exception.__cause__)

            missing = root / "missing-directory"
            with self.assertRaises(
                self.engine.LauncherError
            ) as caught:
                self.engine.exact_real_directory(
                    missing,
                    label="the missing directory",
                )
            self.assertEqual(
                str(caught.exception),
                "the missing directory is unavailable",
            )
            self.assertIsInstance(
                caught.exception.__cause__,
                OSError,
            )

    def test_git_cwd_kernel_and_wrapper_signatures(self) -> None:
        self.assertIs(
            self.engine._authenticate_git_cwd,
            self.identity.authenticate_git_cwd,
        )
        parameters = inspect.signature(
            self.identity.authenticate_git_cwd
        ).parameters
        self.assertEqual(
            tuple(parameters),
            (
                "cwd",
                "path_factory",
                "os_error_type",
                "runtime_error_type",
                "file_not_found_error_type",
                "directory_test",
                "regular_file_test",
                "identity_lookup",
                "linked_worktree_authenticator",
                "error_type",
            ),
        )
        self.assertIs(
            parameters["cwd"].kind,
            inspect.Parameter.POSITIONAL_OR_KEYWORD,
        )
        for name in tuple(parameters)[1:]:
            self.assertIs(
                parameters[name].kind,
                inspect.Parameter.KEYWORD_ONLY,
            )
        for parameter in parameters.values():
            self.assertIs(
                parameter.default,
                inspect.Parameter.empty,
            )

        self.assertIsNot(
            self.engine.authenticate_git_cwd,
            self.identity.authenticate_git_cwd,
        )
        wrapper = inspect.signature(
            self.engine.authenticate_git_cwd
        ).parameters
        self.assertEqual(tuple(wrapper), ("cwd",))
        self.assertIs(
            wrapper["cwd"].kind,
            inspect.Parameter.POSITIONAL_OR_KEYWORD,
        )
        self.assertIs(
            wrapper["cwd"].default,
            inspect.Parameter.empty,
        )

    def test_git_cwd_materializes_all_parents_before_missing_scan(
        self,
    ) -> None:
        events: list[tuple[str, object]] = []
        raw_cwd = OpaqueValue("raw-git-cwd")

        class MissingMarker(Exception):
            pass

        class Marker:
            def __init__(
                marker_self,
                name: str,
            ) -> None:
                marker_self.name = name

            def lstat(marker_self) -> None:
                events.append(
                    ("lstat", marker_self.name)
                )
                raise MissingMarker(marker_self.name)

        class Candidate:
            def __init__(
                candidate_self,
                name: str,
            ) -> None:
                candidate_self.name = name

            def __truediv__(
                candidate_self,
                component: object,
            ) -> object:
                events.append(
                    (
                        "join",
                        (candidate_self.name, component),
                    )
                )
                return Marker(candidate_self.name)

        parent_one = Candidate("parent-one")
        parent_two = Candidate("parent-two")

        class ParentIterator:
            def __init__(iterator_self) -> None:
                iterator_self.index = 0

            def __iter__(
                iterator_self,
            ) -> object:
                events.append(("parents-iterator-iter", None))
                return iterator_self

            def __next__(
                iterator_self,
            ) -> object:
                values = (parent_one, parent_two)
                if iterator_self.index == len(values):
                    events.append(
                        ("parents-iterator-stop", None)
                    )
                    raise StopIteration
                value = values[iterator_self.index]
                iterator_self.index += 1
                events.append(
                    (
                        "parents-iterator-yield",
                        value.name,
                    )
                )
                return value

        class Parents:
            def __iter__(parents_self) -> object:
                events.append(("parents-iter", None))
                return ParentIterator()

        class Directory(Candidate):
            @property
            def parents(directory_self) -> object:
                events.append(("parents-attribute", None))
                return Parents()

        directory = Directory("directory")

        class InputPath:
            def resolve(
                input_self,
                *,
                strict: bool,
            ) -> object:
                events.append(("resolve", strict))
                return directory

        def path_factory() -> object:
            events.append(("path-provider", None))

            def construct(value: object) -> object:
                events.append(("path-call", value))
                self.assertIs(value, raw_cwd)
                return InputPath()

            return construct

        def missing_error_type() -> type[BaseException]:
            events.append(("missing-error-provider", None))
            return MissingMarker

        observed = self.git_cwd(
            raw_cwd,
            path_factory=path_factory,
            os_error_type=mock.Mock(
                side_effect=AssertionError(
                    "resolved OSError for missing marker"
                )
            ),
            runtime_error_type=mock.Mock(
                side_effect=AssertionError(
                    "resolved RuntimeError without cwd failure"
                )
            ),
            file_not_found_error_type=missing_error_type,
            directory_test=mock.Mock(
                side_effect=AssertionError(
                    "classified a missing marker"
                )
            ),
            regular_file_test=mock.Mock(
                side_effect=AssertionError(
                    "classified a missing marker"
                )
            ),
            identity_lookup=mock.Mock(
                side_effect=AssertionError(
                    "looked up identity without marker"
                )
            ),
            linked_worktree_authenticator=mock.Mock(
                side_effect=AssertionError(
                    "authenticated without marker"
                )
            ),
            error_type=mock.Mock(
                side_effect=AssertionError(
                    "raised for an all-missing scan"
                )
            ),
        )

        self.assertIsNone(observed)
        self.assertEqual(
            events,
            [
                ("path-provider", None),
                ("path-call", raw_cwd),
                ("resolve", True),
                ("parents-attribute", None),
                ("parents-iter", None),
                ("parents-iterator-yield", "parent-one"),
                ("parents-iterator-yield", "parent-two"),
                ("parents-iterator-stop", None),
                ("join", ("directory", ".git")),
                ("lstat", "directory"),
                ("missing-error-provider", None),
                ("join", ("parent-one", ".git")),
                ("lstat", "parent-one"),
                ("missing-error-provider", None),
                ("join", ("parent-two", ".git")),
                ("lstat", "parent-two"),
                ("missing-error-provider", None),
            ],
        )

    def test_git_cwd_translates_initial_path_failures_exactly(
        self,
    ) -> None:
        class SelectedOSError(Exception):
            pass

        class SelectedRuntimeError(Exception):
            pass

        class CwdError(Exception):
            pass

        stages = (
            "path-provider",
            "path-call",
            "resolve-attribute",
            "resolve-call",
        )
        for stage in stages:
            for selected_type in (
                SelectedOSError,
                SelectedRuntimeError,
            ):
                with self.subTest(
                    stage=stage,
                    selected_type=selected_type.__name__,
                ):
                    events: list[str] = []
                    original = selected_type(stage)

                    def fail_at(observed: str) -> None:
                        events.append(observed)
                        if stage == observed:
                            raise original

                    class InputPath:
                        @property
                        def resolve(input_self) -> object:
                            fail_at("resolve-attribute")

                            def resolve(*, strict: bool) -> None:
                                self.assertTrue(strict)
                                fail_at("resolve-call")
                                raise AssertionError(
                                    "resolve unexpectedly succeeded"
                                )

                            return resolve

                    def path_factory() -> object:
                        fail_at("path-provider")

                        def construct(value: object) -> object:
                            fail_at("path-call")
                            return InputPath()

                        return construct

                    def os_error_type() -> type[BaseException]:
                        events.append("os-error-provider")
                        return SelectedOSError

                    def runtime_error_type() -> type[BaseException]:
                        events.append(
                            "runtime-error-provider"
                        )
                        return SelectedRuntimeError

                    class Error(CwdError):
                        def __init__(
                            error_self,
                            message: str,
                        ) -> None:
                            events.append("error-constructor")
                            super().__init__(message)

                    def error_type() -> type[BaseException]:
                        events.append("error-provider")
                        return Error

                    with self.assertRaises(Error) as caught:
                        self.git_cwd(
                            object(),
                            path_factory=path_factory,
                            os_error_type=os_error_type,
                            runtime_error_type=(
                                runtime_error_type
                            ),
                            file_not_found_error_type=mock.Mock(
                                side_effect=AssertionError(
                                    "resolved marker matcher"
                                )
                            ),
                            error_type=error_type,
                        )

                    self.assertEqual(
                        str(caught.exception),
                        "the Git working directory is unavailable",
                    )
                    self.assertIs(
                        caught.exception.__cause__,
                        original,
                    )
                    self.assertIs(
                        caught.exception.__context__,
                        original,
                    )
                    self.assertEqual(
                        events[-4:],
                        [
                            "os-error-provider",
                            "runtime-error-provider",
                            "error-provider",
                            "error-constructor",
                        ],
                    )

    def test_git_cwd_initial_matchers_leave_nonmatches_untranslated(
        self,
    ) -> None:
        class SelectedOSError(Exception):
            pass

        class SelectedRuntimeError(Exception):
            pass

        original = LookupError("resolve failed")
        events: list[str] = []

        class InputPath:
            def resolve(
                input_self,
                *,
                strict: bool,
            ) -> None:
                raise original

        def os_error_type() -> type[BaseException]:
            events.append("os-error-provider")
            return SelectedOSError

        def runtime_error_type() -> type[BaseException]:
            events.append("runtime-error-provider")
            return SelectedRuntimeError

        blocked_error = mock.Mock(
            side_effect=AssertionError(
                "translated nonmatching cwd failure"
            )
        )
        with self.assertRaises(LookupError) as caught:
            self.git_cwd(
                object(),
                path_factory=lambda: (
                    lambda value: InputPath()
                ),
                os_error_type=os_error_type,
                runtime_error_type=runtime_error_type,
                error_type=blocked_error,
            )

        self.assertIs(caught.exception, original)
        self.assertEqual(
            events,
            ["os-error-provider", "runtime-error-provider"],
        )
        blocked_error.assert_not_called()

        original = SelectedRuntimeError("resolve failed")
        for broken_matcher in ("os", "runtime"):
            with self.subTest(broken_matcher=broken_matcher):
                matcher_failure = RuntimeError(
                    f"{broken_matcher} matcher failed"
                )

                def broken_os() -> type[BaseException]:
                    if broken_matcher == "os":
                        raise matcher_failure
                    return LookupError

                def broken_runtime() -> type[BaseException]:
                    if broken_matcher == "runtime":
                        raise matcher_failure
                    return SelectedRuntimeError

                with self.assertRaises(RuntimeError) as caught:
                    self.git_cwd(
                        object(),
                        path_factory=lambda: (
                            lambda value: InputPath()
                        ),
                        os_error_type=broken_os,
                        runtime_error_type=broken_runtime,
                        error_type=blocked_error,
                    )

                self.assertIs(caught.exception, matcher_failure)
                self.assertIs(
                    caught.exception.__context__,
                    original,
                )
        blocked_error.assert_not_called()

    def test_git_cwd_parent_expansion_and_join_failures_are_raw(
        self,
    ) -> None:
        class SelectedFailure(Exception):
            pass

        stages = (
            "parents-attribute",
            "parents-iter",
            "parents-next",
            "marker-join",
        )

        for stage in stages:
            with self.subTest(unwrapped_stage=stage):
                original = SelectedFailure(stage)

                def fail_at(observed: str) -> None:
                    if stage == observed:
                        raise original

                class ParentIterator:
                    def __iter__(
                        iterator_self,
                    ) -> object:
                        return iterator_self

                    def __next__(
                        iterator_self,
                    ) -> object:
                        fail_at("parents-next")
                        raise StopIteration

                class Parents:
                    def __iter__(parents_self) -> object:
                        fail_at("parents-iter")
                        return ParentIterator()

                class Directory:
                    @property
                    def parents(directory_self) -> object:
                        fail_at("parents-attribute")
                        return Parents()

                    def __truediv__(
                        directory_self,
                        component: object,
                    ) -> object:
                        fail_at("marker-join")
                        raise AssertionError(
                            "marker join unexpectedly succeeded"
                        )

                blocked_matcher = mock.Mock(
                    side_effect=AssertionError(
                        "matched failure outside a try block"
                    )
                )
                blocked_error = mock.Mock(
                    side_effect=AssertionError(
                        "translated failure outside a try block"
                    )
                )
                with self.assertRaises(
                    SelectedFailure
                ) as caught:
                    self.git_cwd(
                        object(),
                        path_factory=lambda: (
                            lambda value: SimpleNamespace(
                                resolve=lambda *, strict: Directory()
                            )
                        ),
                        os_error_type=blocked_matcher,
                        runtime_error_type=blocked_matcher,
                        file_not_found_error_type=(
                            blocked_matcher
                        ),
                        error_type=blocked_error,
                    )

                self.assertIs(caught.exception, original)
                blocked_matcher.assert_not_called()
                blocked_error.assert_not_called()

    def test_git_cwd_lstat_exception_partition_is_exact(
        self,
    ) -> None:
        class SelectedMissing(Exception):
            pass

        class SelectedOSError(Exception):
            pass

        class MarkerError(Exception):
            pass

        for stage in ("lstat-attribute", "lstat-call"):
            for failure in ("missing", "os"):
                with self.subTest(stage=stage, failure=failure):
                    events: list[str] = []
                    selected_type = (
                        SelectedMissing
                        if failure == "missing"
                        else SelectedOSError
                    )
                    original = selected_type(stage)

                    def fail_at(observed: str) -> None:
                        events.append(observed)
                        if stage == observed:
                            raise original

                    class Marker:
                        @property
                        def lstat(marker_self) -> object:
                            fail_at("lstat-attribute")

                            def lstat() -> None:
                                fail_at("lstat-call")
                                raise AssertionError(
                                    "lstat unexpectedly succeeded"
                                )

                            return lstat

                    class Candidate:
                        parents = ()

                        def __truediv__(
                            candidate_self,
                            component: object,
                        ) -> object:
                            return Marker()

                    def missing_error_type() -> type[BaseException]:
                        events.append("missing-error-provider")
                        return SelectedMissing

                    def os_error_type() -> type[BaseException]:
                        events.append("os-error-provider")
                        return SelectedOSError

                    class Error(MarkerError):
                        def __init__(
                            error_self,
                            message: str,
                        ) -> None:
                            events.append("error-constructor")
                            super().__init__(message)

                    def error_type() -> type[BaseException]:
                        events.append("error-provider")
                        return Error

                    if failure == "missing":
                        observed = self.git_cwd(
                            object(),
                            path_factory=lambda: (
                                lambda value: SimpleNamespace(
                                    resolve=lambda *, strict: (
                                        Candidate()
                                    )
                                )
                            ),
                            os_error_type=os_error_type,
                            runtime_error_type=mock.Mock(
                                side_effect=AssertionError(
                                    "resolved initial matcher"
                                )
                            ),
                            file_not_found_error_type=(
                                missing_error_type
                            ),
                            directory_test=mock.Mock(
                                side_effect=AssertionError(
                                    "classified missing marker"
                                )
                            ),
                            error_type=error_type,
                        )
                        self.assertIsNone(observed)
                        self.assertEqual(
                            events[-1],
                            "missing-error-provider",
                        )
                        self.assertNotIn(
                            "os-error-provider",
                            events,
                        )
                        self.assertNotIn(
                            "error-provider",
                            events,
                        )
                    else:
                        with self.assertRaises(Error) as caught:
                            self.git_cwd(
                                object(),
                                path_factory=lambda: (
                                    lambda value: (
                                        SimpleNamespace(
                                            resolve=(
                                                lambda *, strict: (
                                                    Candidate()
                                                )
                                            )
                                        )
                                    )
                                ),
                                os_error_type=os_error_type,
                                runtime_error_type=mock.Mock(
                                    side_effect=AssertionError(
                                        "resolved initial matcher"
                                    )
                                ),
                                file_not_found_error_type=(
                                    missing_error_type
                                ),
                                error_type=error_type,
                            )
                        self.assertEqual(
                            str(caught.exception),
                            "cannot inspect the Git "
                            "administration marker",
                        )
                        self.assertIs(
                            caught.exception.__cause__,
                            original,
                        )
                        self.assertEqual(
                            events[-4:],
                            [
                                "missing-error-provider",
                                "os-error-provider",
                                "error-provider",
                                "error-constructor",
                            ],
                        )

    def test_git_cwd_lstat_nonmatches_and_matcher_failures_are_raw(
        self,
    ) -> None:
        class SelectedMissing(Exception):
            pass

        class SelectedOSError(Exception):
            pass

        class Candidate:
            parents = ()

            def __truediv__(
                candidate_self,
                component: object,
            ) -> object:
                return marker

        class Marker:
            def lstat(marker_self) -> None:
                raise original

        marker = Marker()

        events: list[str] = []
        original = LookupError("lstat failed")

        def missing_error_type() -> type[BaseException]:
            events.append("missing-error-provider")
            return SelectedMissing

        def os_error_type() -> type[BaseException]:
            events.append("os-error-provider")
            return SelectedOSError

        blocked_error = mock.Mock(
            side_effect=AssertionError(
                "translated nonmatching lstat failure"
            )
        )
        with self.assertRaises(LookupError) as caught:
            self.git_cwd(
                object(),
                path_factory=lambda: (
                    lambda value: SimpleNamespace(
                        resolve=lambda *, strict: Candidate()
                    )
                ),
                os_error_type=os_error_type,
                runtime_error_type=mock.Mock(
                    side_effect=AssertionError(
                        "resolved initial matcher"
                    )
                ),
                file_not_found_error_type=missing_error_type,
                error_type=blocked_error,
            )

        self.assertIs(caught.exception, original)
        self.assertEqual(
            events,
            ["missing-error-provider", "os-error-provider"],
        )
        blocked_error.assert_not_called()

        original = SelectedOSError("lstat failed")
        for broken_matcher in ("missing", "os"):
            with self.subTest(broken_matcher=broken_matcher):
                matcher_failure = RuntimeError(
                    f"{broken_matcher} matcher failed"
                )

                def broken_missing() -> type[BaseException]:
                    if broken_matcher == "missing":
                        raise matcher_failure
                    return LookupError

                def broken_os() -> type[BaseException]:
                    if broken_matcher == "os":
                        raise matcher_failure
                    return SelectedOSError

                with self.assertRaises(RuntimeError) as caught:
                    self.git_cwd(
                        object(),
                        path_factory=lambda: (
                            lambda value: SimpleNamespace(
                                resolve=lambda *, strict: (
                                    Candidate()
                                )
                            )
                        ),
                        os_error_type=broken_os,
                        runtime_error_type=mock.Mock(
                            side_effect=AssertionError(
                                "resolved initial matcher"
                            )
                        ),
                        file_not_found_error_type=(
                            broken_missing
                        ),
                        error_type=blocked_error,
                    )

                self.assertIs(caught.exception, matcher_failure)
                self.assertIs(
                    caught.exception.__context__,
                    original,
                )
        blocked_error.assert_not_called()

    def test_git_cwd_directory_marker_order_and_symbolic_rejection(
        self,
    ) -> None:
        class MarkerError(RuntimeError):
            pass

        for symbolic in (False, True):
            with self.subTest(symbolic=symbolic):
                events: list[tuple[str, object]] = []
                mode = OpaqueValue("directory-mode")

                class Metadata:
                    @property
                    def st_mode(metadata_self) -> object:
                        events.append(("metadata-mode", None))
                        return mode

                class ComparisonTruth:
                    def __bool__(
                        truth_self,
                    ) -> bool:
                        events.append(
                            ("comparison-truth", symbolic)
                        )
                        return symbolic

                class ResolvedMarker:
                    def __ne__(
                        resolved_self,
                        other: object,
                    ) -> object:
                        events.append(("resolved-ne", other))
                        self.assertIs(other, marker)
                        return ComparisonTruth()

                class Marker:
                    def lstat(marker_self) -> object:
                        events.append(("lstat", None))
                        return Metadata()

                    def resolve(
                        marker_self,
                        *,
                        strict: bool,
                    ) -> object:
                        events.append(("marker-resolve", strict))
                        return ResolvedMarker()

                marker = Marker()

                class Parent:
                    def __truediv__(
                        parent_self,
                        component: object,
                    ) -> object:
                        raise AssertionError(
                            "scanned parent after directory marker"
                        )

                class Candidate:
                    @property
                    def parents(candidate_self) -> object:
                        events.append(("parents", None))
                        return (Parent(),)

                    def __truediv__(
                        candidate_self,
                        component: object,
                    ) -> object:
                        events.append(("join", component))
                        return marker

                class DirectoryTruth:
                    def __bool__(truth_self) -> bool:
                        events.append(("directory-truth", True))
                        return True

                def directory_test() -> object:
                    events.append(("directory-provider", None))

                    def test(observed_mode: object) -> object:
                        events.append(
                            ("directory-call", observed_mode)
                        )
                        self.assertIs(observed_mode, mode)
                        return DirectoryTruth()

                    return test

                class Error(MarkerError):
                    def __init__(
                        error_self,
                        message: str,
                    ) -> None:
                        events.append(
                            ("error-constructor", message)
                        )
                        super().__init__(message)

                def error_type() -> type[BaseException]:
                    events.append(("error-provider", None))
                    return Error

                arguments = {
                    "path_factory": lambda: (
                        lambda value: SimpleNamespace(
                            resolve=lambda *, strict: Candidate()
                        )
                    ),
                    "os_error_type": mock.Mock(
                        side_effect=AssertionError(
                            "resolved matcher after successful lstat"
                        )
                    ),
                    "runtime_error_type": mock.Mock(
                        side_effect=AssertionError(
                            "resolved initial matcher"
                        )
                    ),
                    "file_not_found_error_type": mock.Mock(
                        side_effect=AssertionError(
                            "resolved matcher after successful lstat"
                        )
                    ),
                    "directory_test": directory_test,
                    "regular_file_test": mock.Mock(
                        side_effect=AssertionError(
                            "tested regular mode after directory"
                        )
                    ),
                    "identity_lookup": mock.Mock(
                        side_effect=AssertionError(
                            "read cache for directory marker"
                        )
                    ),
                    "linked_worktree_authenticator": mock.Mock(
                        side_effect=AssertionError(
                            "used linked auth for directory marker"
                        )
                    ),
                    "error_type": error_type,
                }

                if symbolic:
                    with self.assertRaises(Error) as caught:
                        self.git_cwd(object(), **arguments)
                    self.assertEqual(
                        str(caught.exception),
                        "the primary Git administration "
                        "directory is symbolic",
                    )
                    self.assertIsNone(
                        caught.exception.__cause__
                    )
                else:
                    observed = self.git_cwd(
                        object(),
                        **arguments,
                    )
                    self.assertIsNone(observed)

                self.assertEqual(
                    events,
                    [
                        ("parents", None),
                        ("join", ".git"),
                        ("lstat", None),
                        ("directory-provider", None),
                        ("metadata-mode", None),
                        ("directory-call", mode),
                        ("directory-truth", True),
                        ("marker-resolve", True),
                        ("resolved-ne", marker),
                        ("comparison-truth", symbolic),
                    ]
                    + (
                        [
                            ("error-provider", None),
                            (
                                "error-constructor",
                                "the primary Git administration "
                                "directory is symbolic",
                            ),
                        ]
                        if symbolic
                        else []
                    ),
                )

    def test_git_cwd_directory_post_lstat_failures_are_raw(
        self,
    ) -> None:
        class SelectedFailure(Exception):
            pass

        stages = (
            "directory-provider",
            "metadata-mode",
            "directory-call",
            "directory-truth",
            "marker-resolve-attribute",
            "marker-resolve-call",
            "marker-ne",
            "marker-truth",
        )

        for stage in stages:
            with self.subTest(unwrapped_stage=stage):
                original = SelectedFailure(stage)

                def fail_at(observed: str) -> None:
                    if stage == observed:
                        raise original

                class Metadata:
                    @property
                    def st_mode(metadata_self) -> int:
                        fail_at("metadata-mode")
                        return 1

                class ComparisonTruth:
                    def __bool__(truth_self) -> bool:
                        fail_at("marker-truth")
                        return False

                class ResolvedMarker:
                    def __ne__(
                        resolved_self,
                        other: object,
                    ) -> object:
                        fail_at("marker-ne")
                        return ComparisonTruth()

                class Marker:
                    def lstat(marker_self) -> object:
                        return Metadata()

                    @property
                    def resolve(marker_self) -> object:
                        fail_at("marker-resolve-attribute")

                        def resolve(*, strict: bool) -> object:
                            fail_at("marker-resolve-call")
                            return ResolvedMarker()

                        return resolve

                marker = Marker()

                class Candidate:
                    parents = ()

                    def __truediv__(
                        candidate_self,
                        component: object,
                    ) -> object:
                        return marker

                class DirectoryTruth:
                    def __bool__(truth_self) -> bool:
                        fail_at("directory-truth")
                        return True

                def directory_test() -> object:
                    fail_at("directory-provider")

                    def test(mode: object) -> object:
                        fail_at("directory-call")
                        return DirectoryTruth()

                    return test

                blocked_matcher = mock.Mock(
                    side_effect=AssertionError(
                        "matched post-lstat failure"
                    )
                )
                blocked_error = mock.Mock(
                    side_effect=AssertionError(
                        "translated post-lstat failure"
                    )
                )
                with self.assertRaises(
                    SelectedFailure
                ) as caught:
                    self.git_cwd(
                        object(),
                        path_factory=lambda: (
                            lambda value: SimpleNamespace(
                                resolve=lambda *, strict: Candidate()
                            )
                        ),
                        os_error_type=blocked_matcher,
                        runtime_error_type=blocked_matcher,
                        file_not_found_error_type=(
                            blocked_matcher
                        ),
                        directory_test=directory_test,
                        regular_file_test=mock.Mock(
                            side_effect=AssertionError(
                                "reached regular predicate"
                            )
                        ),
                        error_type=blocked_error,
                    )

                self.assertIs(caught.exception, original)
                blocked_matcher.assert_not_called()
                blocked_error.assert_not_called()

    def test_git_cwd_regular_marker_cache_and_auth_order(
        self,
    ) -> None:
        for prior_present in (False, True):
            with self.subTest(prior_present=prior_present):
                events: list[tuple[str, object]] = []
                first_mode = OpaqueValue("first-mode")
                second_mode = OpaqueValue("second-mode")
                expected_common = OpaqueValue(
                    "cached-common-directory"
                )
                auth_result = OpaqueValue(
                    "ignored-linked-auth-result"
                )

                class Prior:
                    def __bool__(prior_self) -> bool:
                        raise AssertionError(
                            "truth-tested cached identity"
                        )

                    @property
                    def common_git_dir(
                        prior_self,
                    ) -> object:
                        events.append(("prior-common", None))
                        return expected_common

                prior = Prior() if prior_present else None

                class Metadata:
                    def __init__(
                        metadata_self,
                    ) -> None:
                        metadata_self.reads = 0

                    @property
                    def st_mode(metadata_self) -> object:
                        metadata_self.reads += 1
                        events.append(
                            (
                                "metadata-mode",
                                metadata_self.reads,
                            )
                        )
                        return (
                            first_mode
                            if metadata_self.reads == 1
                            else second_mode
                        )

                class Marker:
                    def lstat(marker_self) -> object:
                        events.append(("lstat", None))
                        return Metadata()

                marker = Marker()

                class Parent:
                    def __truediv__(
                        parent_self,
                        component: object,
                    ) -> object:
                        raise AssertionError(
                            "scanned parent after regular marker"
                        )

                class Candidate:
                    @property
                    def parents(candidate_self) -> object:
                        events.append(("parents", None))
                        return (Parent(),)

                    def __truediv__(
                        candidate_self,
                        component: object,
                    ) -> object:
                        events.append(("join", component))
                        return marker

                candidate = Candidate()

                class PredicateTruth:
                    def __init__(
                        truth_self,
                        name: str,
                        value: bool,
                    ) -> None:
                        truth_self.name = name
                        truth_self.value = value

                    def __bool__(truth_self) -> bool:
                        events.append(
                            (
                                f"{truth_self.name}-truth",
                                truth_self.value,
                            )
                        )
                        return truth_self.value

                def directory_test() -> object:
                    events.append(("directory-provider", None))

                    def test(mode: object) -> object:
                        events.append(("directory-call", mode))
                        self.assertIs(mode, first_mode)
                        return PredicateTruth(
                            "directory",
                            False,
                        )

                    return test

                def regular_file_test() -> object:
                    events.append(("regular-provider", None))

                    def test(mode: object) -> object:
                        events.append(("regular-call", mode))
                        self.assertIs(mode, second_mode)
                        return PredicateTruth("regular", True)

                    return test

                def identity_lookup() -> object:
                    events.append(("identity-provider", None))

                    def lookup(observed: object) -> object:
                        events.append(
                            ("identity-call", observed)
                        )
                        self.assertIs(observed, candidate)
                        return prior

                    return lookup

                def authenticator_provider() -> object:
                    events.append(("auth-provider", None))

                    def authenticate(
                        observed: object,
                        *,
                        expected_common_git_dir: object,
                    ) -> object:
                        events.append(
                            (
                                "auth-call",
                                (
                                    observed,
                                    expected_common_git_dir,
                                ),
                            )
                        )
                        self.assertIs(observed, candidate)
                        self.assertIs(
                            expected_common_git_dir,
                            (
                                expected_common
                                if prior_present
                                else None
                            ),
                        )
                        return auth_result

                    return authenticate

                observed = self.git_cwd(
                    object(),
                    path_factory=lambda: (
                        lambda value: SimpleNamespace(
                            resolve=lambda *, strict: candidate
                        )
                    ),
                    os_error_type=mock.Mock(
                        side_effect=AssertionError(
                            "resolved matcher after successful lstat"
                        )
                    ),
                    runtime_error_type=mock.Mock(
                        side_effect=AssertionError(
                            "resolved initial matcher"
                        )
                    ),
                    file_not_found_error_type=mock.Mock(
                        side_effect=AssertionError(
                            "resolved matcher after successful lstat"
                        )
                    ),
                    directory_test=directory_test,
                    regular_file_test=regular_file_test,
                    identity_lookup=identity_lookup,
                    linked_worktree_authenticator=(
                        authenticator_provider
                    ),
                    error_type=mock.Mock(
                        side_effect=AssertionError(
                            "raised for regular marker"
                        )
                    ),
                )

                self.assertIsNone(observed)
                self.assertEqual(
                    events,
                    [
                        ("parents", None),
                        ("join", ".git"),
                        ("lstat", None),
                        ("directory-provider", None),
                        ("metadata-mode", 1),
                        ("directory-call", first_mode),
                        ("directory-truth", False),
                        ("regular-provider", None),
                        ("metadata-mode", 2),
                        ("regular-call", second_mode),
                        ("regular-truth", True),
                        ("identity-provider", None),
                        ("identity-call", candidate),
                    ]
                    + (
                        [("prior-common", None)]
                        if prior_present
                        else []
                    )
                    + [
                        ("auth-provider", None),
                        (
                            "auth-call",
                            (
                                candidate,
                                (
                                    expected_common
                                    if prior_present
                                    else None
                                ),
                            ),
                        ),
                    ],
                )

    def test_git_cwd_invalid_marker_stops_ancestor_scan(
        self,
    ) -> None:
        events: list[str] = []

        class Metadata:
            @property
            def st_mode(metadata_self) -> int:
                events.append("metadata-mode")
                return 0

        class Marker:
            def lstat(marker_self) -> object:
                events.append("lstat")
                return Metadata()

        class Parent:
            def __truediv__(
                parent_self,
                component: object,
            ) -> object:
                raise AssertionError(
                    "scanned parent after invalid marker"
                )

        class Candidate:
            parents = (Parent(),)

            def __truediv__(
                candidate_self,
                component: object,
            ) -> object:
                events.append("join")
                return Marker()

        class PredicateTruth:
            def __init__(
                truth_self,
                name: str,
            ) -> None:
                truth_self.name = name

            def __bool__(truth_self) -> bool:
                events.append(f"{truth_self.name}-truth")
                return False

        def predicate(name: str) -> object:
            def provider() -> object:
                events.append(f"{name}-provider")

                def test(mode: object) -> object:
                    events.append(f"{name}-call")
                    return PredicateTruth(name)

                return test

            return provider

        class MarkerError(RuntimeError):
            pass

        def error_type() -> type[BaseException]:
            events.append("error-provider")
            return MarkerError

        with self.assertRaises(MarkerError) as caught:
            self.git_cwd(
                object(),
                path_factory=lambda: (
                    lambda value: SimpleNamespace(
                        resolve=lambda *, strict: Candidate()
                    )
                ),
                os_error_type=mock.Mock(
                    side_effect=AssertionError(
                        "resolved matcher after lstat"
                    )
                ),
                runtime_error_type=mock.Mock(
                    side_effect=AssertionError(
                        "resolved initial matcher"
                    )
                ),
                file_not_found_error_type=mock.Mock(
                    side_effect=AssertionError(
                        "resolved matcher after lstat"
                    )
                ),
                directory_test=predicate("directory"),
                regular_file_test=predicate("regular"),
                identity_lookup=mock.Mock(
                    side_effect=AssertionError(
                        "read cache for invalid marker"
                    )
                ),
                linked_worktree_authenticator=mock.Mock(
                    side_effect=AssertionError(
                        "authenticated invalid marker"
                    )
                ),
                error_type=error_type,
            )

        self.assertEqual(
            str(caught.exception),
            "the Git administration marker is not "
            "a real file or directory",
        )
        self.assertIsNone(caught.exception.__cause__)
        self.assertEqual(
            events,
            [
                "join",
                "lstat",
                "directory-provider",
                "metadata-mode",
                "directory-call",
                "directory-truth",
                "regular-provider",
                "metadata-mode",
                "regular-call",
                "regular-truth",
                "error-provider",
            ],
        )

    def test_git_cwd_regular_branch_failures_are_raw(
        self,
    ) -> None:
        class SelectedFailure(Exception):
            pass

        stages = (
            "regular-provider",
            "metadata-mode-second",
            "regular-call",
            "regular-truth",
            "identity-provider",
            "identity-call",
            "prior-common",
            "auth-provider",
            "auth-call",
        )

        for stage in stages:
            with self.subTest(unwrapped_stage=stage):
                original = SelectedFailure(stage)

                def fail_at(observed: str) -> None:
                    if stage == observed:
                        raise original

                class Prior:
                    @property
                    def common_git_dir(
                        prior_self,
                    ) -> object:
                        fail_at("prior-common")
                        return object()

                class Metadata:
                    def __init__(
                        metadata_self,
                    ) -> None:
                        metadata_self.reads = 0

                    @property
                    def st_mode(metadata_self) -> int:
                        metadata_self.reads += 1
                        if metadata_self.reads == 2:
                            fail_at("metadata-mode-second")
                        return metadata_self.reads

                class Marker:
                    def lstat(marker_self) -> object:
                        return Metadata()

                marker = Marker()

                class Candidate:
                    parents = ()

                    def __truediv__(
                        candidate_self,
                        component: object,
                    ) -> object:
                        return marker

                candidate = Candidate()

                class RegularTruth:
                    def __bool__(truth_self) -> bool:
                        fail_at("regular-truth")
                        return True

                def regular_file_test() -> object:
                    fail_at("regular-provider")

                    def test(mode: object) -> object:
                        fail_at("regular-call")
                        return RegularTruth()

                    return test

                def identity_lookup() -> object:
                    fail_at("identity-provider")

                    def lookup(observed: object) -> object:
                        fail_at("identity-call")
                        return (
                            Prior()
                            if stage == "prior-common"
                            else None
                        )

                    return lookup

                def authenticator_provider() -> object:
                    fail_at("auth-provider")

                    def authenticate(
                        observed: object,
                        *,
                        expected_common_git_dir: object,
                    ) -> None:
                        fail_at("auth-call")
                        raise AssertionError(
                            "authentication unexpectedly succeeded"
                        )

                    return authenticate

                blocked_matcher = mock.Mock(
                    side_effect=AssertionError(
                        "matched post-lstat failure"
                    )
                )
                blocked_error = mock.Mock(
                    side_effect=AssertionError(
                        "translated regular-branch failure"
                    )
                )
                with self.assertRaises(
                    SelectedFailure
                ) as caught:
                    self.git_cwd(
                        object(),
                        path_factory=lambda: (
                            lambda value: SimpleNamespace(
                                resolve=lambda *, strict: candidate
                            )
                        ),
                        os_error_type=blocked_matcher,
                        runtime_error_type=blocked_matcher,
                        file_not_found_error_type=(
                            blocked_matcher
                        ),
                        directory_test=lambda: (
                            lambda mode: False
                        ),
                        regular_file_test=regular_file_test,
                        identity_lookup=identity_lookup,
                        linked_worktree_authenticator=(
                            authenticator_provider
                        ),
                        error_type=blocked_error,
                    )

                self.assertIs(caught.exception, original)
                blocked_matcher.assert_not_called()
                blocked_error.assert_not_called()

    def test_git_cwd_error_dependency_failures_are_untranslated(
        self,
    ) -> None:
        class ProtectedFailure(Exception):
            pass

        class ErrorDependencyFailure(Exception):
            pass

        for rejection in (
            "initial",
            "lstat",
            "symbolic",
            "invalid",
        ):
            for error_stage in ("provider", "constructor"):
                with self.subTest(
                    rejection=rejection,
                    error_stage=error_stage,
                ):
                    protected = ProtectedFailure(rejection)
                    original = ErrorDependencyFailure(
                        f"{rejection}-{error_stage}"
                    )

                    class Metadata:
                        st_mode = 1

                    class ResolvedMarker:
                        def __ne__(
                            resolved_self,
                            other: object,
                        ) -> bool:
                            return True

                    class Marker:
                        def lstat(marker_self) -> object:
                            if rejection == "lstat":
                                raise protected
                            return Metadata()

                        def resolve(
                            marker_self,
                            *,
                            strict: bool,
                        ) -> object:
                            return ResolvedMarker()

                    marker = Marker()

                    class Candidate:
                        parents = ()

                        def __truediv__(
                            candidate_self,
                            component: object,
                        ) -> object:
                            return marker

                    class InputPath:
                        def resolve(
                            input_self,
                            *,
                            strict: bool,
                        ) -> object:
                            if rejection == "initial":
                                raise protected
                            return Candidate()

                    class BrokenError:
                        def __new__(
                            cls,
                            message: object,
                        ) -> object:
                            if error_stage == "constructor":
                                raise original
                            raise AssertionError(
                                "error constructor was reached "
                                "for provider failure"
                            )

                    def error_type() -> type:
                        if error_stage == "provider":
                            raise original
                        return BrokenError

                    def directory_test() -> object:
                        return lambda mode: (
                            rejection == "symbolic"
                        )

                    def regular_file_test() -> object:
                        return lambda mode: False

                    with self.assertRaises(
                        ErrorDependencyFailure
                    ) as caught:
                        self.git_cwd(
                            object(),
                            path_factory=lambda: (
                                lambda value: InputPath()
                            ),
                            os_error_type=lambda: (
                                ProtectedFailure
                            ),
                            runtime_error_type=lambda: LookupError,
                            file_not_found_error_type=(
                                lambda: LookupError
                            ),
                            directory_test=directory_test,
                            regular_file_test=regular_file_test,
                            error_type=error_type,
                        )

                    self.assertIs(caught.exception, original)
                    self.assertIsNone(
                        caught.exception.__cause__
                    )
                    if rejection in {"initial", "lstat"}:
                        self.assertIs(
                            caught.exception.__context__,
                            protected,
                        )
                    else:
                        self.assertIsNone(
                            caught.exception.__context__
                        )

    def test_engine_git_cwd_wrapper_uses_fresh_globals_and_ignores_result(
        self,
    ) -> None:
        cwd = OpaqueValue("engine-git-cwd")
        ignored = OpaqueValue("ignored-git-cwd-result")
        initial_path = object()
        path_one = object()
        path_two = object()
        initial_directory_test = object()
        directory_one = object()
        directory_two = object()
        initial_regular_test = object()
        regular_one = object()
        regular_two = object()
        initial_authenticator = object()
        authenticator_one = object()
        authenticator_two = object()

        class InitialOSError(Exception):
            pass

        class OSErrorOne(Exception):
            pass

        class OSErrorTwo(Exception):
            pass

        class InitialRuntimeError(Exception):
            pass

        class RuntimeErrorOne(Exception):
            pass

        class RuntimeErrorTwo(Exception):
            pass

        class InitialMissingError(Exception):
            pass

        class MissingErrorOne(Exception):
            pass

        class MissingErrorTwo(Exception):
            pass

        class InitialLauncherError(Exception):
            pass

        class LauncherErrorOne(Exception):
            pass

        class LauncherErrorTwo(Exception):
            pass

        initial_registry: dict[object, object] = {}
        registry_one: dict[object, object] = {}
        registry_two: dict[object, object] = {}

        def stat_api(
            directory_value: object,
            regular_value: object,
        ) -> object:
            return SimpleNamespace(
                S_ISDIR=directory_value,
                S_ISREG=regular_value,
            )

        def kernel(
            observed_cwd: object,
            **dependencies: object,
        ) -> object:
            self.assertIs(observed_cwd, cwd)
            self.assertEqual(
                tuple(dependencies),
                (
                    "path_factory",
                    "os_error_type",
                    "runtime_error_type",
                    "file_not_found_error_type",
                    "directory_test",
                    "regular_file_test",
                    "identity_lookup",
                    "linked_worktree_authenticator",
                    "error_type",
                ),
            )

            self.engine.Path = path_one
            self.assertIs(
                dependencies["path_factory"](),
                path_one,
            )
            self.engine.Path = path_two
            self.assertIs(
                dependencies["path_factory"](),
                path_two,
            )
            self.engine.OSError = OSErrorOne
            self.assertIs(
                dependencies["os_error_type"](),
                OSErrorOne,
            )
            self.engine.OSError = OSErrorTwo
            self.assertIs(
                dependencies["os_error_type"](),
                OSErrorTwo,
            )
            self.engine.RuntimeError = RuntimeErrorOne
            self.assertIs(
                dependencies["runtime_error_type"](),
                RuntimeErrorOne,
            )
            self.engine.RuntimeError = RuntimeErrorTwo
            self.assertIs(
                dependencies["runtime_error_type"](),
                RuntimeErrorTwo,
            )
            self.engine.FileNotFoundError = MissingErrorOne
            self.assertIs(
                dependencies[
                    "file_not_found_error_type"
                ](),
                MissingErrorOne,
            )
            self.engine.FileNotFoundError = MissingErrorTwo
            self.assertIs(
                dependencies[
                    "file_not_found_error_type"
                ](),
                MissingErrorTwo,
            )

            self.engine.stat = stat_api(
                directory_one,
                regular_one,
            )
            self.assertIs(
                dependencies["directory_test"](),
                directory_one,
            )
            self.assertIs(
                dependencies["regular_file_test"](),
                regular_one,
            )
            self.engine.stat = stat_api(
                directory_two,
                regular_two,
            )
            self.assertIs(
                dependencies["directory_test"](),
                directory_two,
            )
            self.assertIs(
                dependencies["regular_file_test"](),
                regular_two,
            )

            self.engine._LINKED_WORKTREE_IDENTITIES = (
                registry_one
            )
            lookup = dependencies["identity_lookup"]()
            self.assertIs(lookup.__self__, registry_one)
            self.assertEqual(lookup, registry_one.get)
            self.engine._LINKED_WORKTREE_IDENTITIES = (
                registry_two
            )
            lookup = dependencies["identity_lookup"]()
            self.assertIs(lookup.__self__, registry_two)
            self.assertEqual(lookup, registry_two.get)

            self.engine.authenticate_linked_worktree_path = (
                authenticator_one
            )
            self.assertIs(
                dependencies[
                    "linked_worktree_authenticator"
                ](),
                authenticator_one,
            )
            self.engine.authenticate_linked_worktree_path = (
                authenticator_two
            )
            self.assertIs(
                dependencies[
                    "linked_worktree_authenticator"
                ](),
                authenticator_two,
            )
            self.engine.LauncherError = LauncherErrorOne
            self.assertIs(
                dependencies["error_type"](),
                LauncherErrorOne,
            )
            self.engine.LauncherError = LauncherErrorTwo
            self.assertIs(
                dependencies["error_type"](),
                LauncherErrorTwo,
            )
            return ignored

        with (
            mock.patch.object(
                self.engine,
                "_authenticate_git_cwd",
                side_effect=kernel,
            ) as kernel_mock,
            mock.patch.object(
                self.engine,
                "Path",
                initial_path,
            ),
            mock.patch.object(
                self.engine,
                "OSError",
                InitialOSError,
                create=True,
            ),
            mock.patch.object(
                self.engine,
                "RuntimeError",
                InitialRuntimeError,
                create=True,
            ),
            mock.patch.object(
                self.engine,
                "FileNotFoundError",
                InitialMissingError,
                create=True,
            ),
            mock.patch.object(
                self.engine,
                "stat",
                stat_api(
                    initial_directory_test,
                    initial_regular_test,
                ),
            ),
            mock.patch.object(
                self.engine,
                "_LINKED_WORKTREE_IDENTITIES",
                initial_registry,
            ),
            mock.patch.object(
                self.engine,
                "authenticate_linked_worktree_path",
                initial_authenticator,
            ),
            mock.patch.object(
                self.engine,
                "LauncherError",
                InitialLauncherError,
            ),
        ):
            observed = self.engine.authenticate_git_cwd(cwd)

        self.assertIsNone(observed)
        kernel_mock.assert_called_once()

    def test_engine_git_cwd_matches_real_filesystem_behavior(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            plain = root / "plain"
            plain.mkdir()
            repository = root / "repository"
            subprocess.run(
                ("git", "init", "-q", os.fspath(repository)),
                cwd=root,
                text=True,
                capture_output=True,
                check=True,
                timeout=20,
            )
            nested = repository / "one" / "two"
            nested.mkdir(parents=True)
            cwd_link = root / "cwd-link"
            cwd_link.symlink_to(nested, target_is_directory=True)
            relative_nested = Path(
                os.path.relpath(nested, Path.cwd())
            )

            with (
                mock.patch.object(
                    self.engine,
                    "_LINKED_WORKTREE_IDENTITIES",
                    {},
                ),
                mock.patch.object(
                    self.engine,
                    "_LINKED_ADMIN_OWNERS",
                    {},
                ),
            ):
                self.assertIsNone(
                    self.engine.authenticate_git_cwd(plain)
                )
                self.assertIsNone(
                    self.engine.authenticate_git_cwd(nested)
                )
                self.assertIsNone(
                    self.engine.authenticate_git_cwd(
                        relative_nested
                    )
                )
                self.assertIsNone(
                    self.engine.authenticate_git_cwd(cwd_link)
                )

                missing = root / "missing"
                with self.assertRaises(
                    self.engine.LauncherError
                ) as caught:
                    self.engine.authenticate_git_cwd(missing)
                self.assertEqual(
                    str(caught.exception),
                    "the Git working directory is unavailable",
                )
                self.assertIsInstance(
                    caught.exception.__cause__,
                    FileNotFoundError,
                )

                regular_cwd = root / "regular-cwd"
                regular_cwd.write_text(
                    "not a directory\n",
                    encoding="utf-8",
                )
                with self.assertRaises(
                    self.engine.LauncherError
                ) as caught:
                    self.engine.authenticate_git_cwd(
                        regular_cwd
                    )
                self.assertEqual(
                    str(caught.exception),
                    "cannot inspect the Git "
                    "administration marker",
                )
                self.assertIsInstance(
                    caught.exception.__cause__,
                    OSError,
                )

                symbolic_root = root / "symbolic-marker"
                symbolic_root.mkdir()
                symbolic_target = root / "symbolic-target"
                symbolic_target.mkdir()
                (symbolic_root / ".git").symlink_to(
                    symbolic_target,
                    target_is_directory=True,
                )
                with self.assertRaises(
                    self.engine.LauncherError
                ) as caught:
                    self.engine.authenticate_git_cwd(
                        symbolic_root
                    )
                self.assertEqual(
                    str(caught.exception),
                    "the Git administration marker is not "
                    "a real file or directory",
                )
                self.assertIsNone(
                    caught.exception.__cause__
                )

    def test_engine_git_cwd_matches_real_linked_worktree_cache(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            repository = root / "repository"
            worker = root / "worker"

            def run_git(*arguments: str) -> None:
                subprocess.run(
                    ("git", *arguments),
                    cwd=root,
                    text=True,
                    capture_output=True,
                    check=True,
                    timeout=20,
                )

            run_git("init", "-q", os.fspath(repository))
            run_git(
                "-C",
                os.fspath(repository),
                "config",
                "user.name",
                "Worktree Marshal Test",
            )
            run_git(
                "-C",
                os.fspath(repository),
                "config",
                "user.email",
                "marshal@example.invalid",
            )
            (repository / "tracked").write_text(
                "initial\n",
                encoding="utf-8",
            )
            run_git(
                "-C",
                os.fspath(repository),
                "add",
                "tracked",
            )
            run_git(
                "-C",
                os.fspath(repository),
                "commit",
                "-q",
                "-m",
                "initial",
            )
            run_git(
                "-C",
                os.fspath(repository),
                "worktree",
                "add",
                "-q",
                "--detach",
                os.fspath(worker),
                "HEAD",
            )
            nested = worker / "nested"
            nested.mkdir()
            git_file = worker / ".git"
            raw_git_dir = (
                git_file.read_text(encoding="utf-8")
                .removeprefix("gitdir: ")
                .removesuffix("\n")
            )
            git_dir_candidate = Path(raw_git_dir)
            if not git_dir_candidate.is_absolute():
                git_dir_candidate = worker / git_dir_candidate
            git_dir = git_dir_candidate.resolve(strict=True)
            raw_common = (
                (git_dir / "commondir")
                .read_text(encoding="utf-8")
                .removesuffix("\n")
            )
            common_candidate = Path(raw_common)
            if not common_candidate.is_absolute():
                common_candidate = git_dir / common_candidate
            common_git_dir = common_candidate.resolve(strict=True)
            identities: dict[Path, object] = {}
            owners: dict[Path, Path] = {}

            with (
                mock.patch.object(
                    self.engine,
                    "_LINKED_WORKTREE_IDENTITIES",
                    identities,
                ),
                mock.patch.object(
                    self.engine,
                    "_LINKED_ADMIN_OWNERS",
                    owners,
                ),
            ):
                self.assertIsNone(
                    self.engine.authenticate_git_cwd(nested)
                )
                cached = identities[worker]
                self.assertEqual(
                    cached.common_git_dir,
                    common_git_dir,
                )
                self.assertEqual(owners, {git_dir: worker})
                self.assertIsNone(
                    self.engine.authenticate_git_cwd(nested)
                )
                cached_again = identities[worker]
                self.assertEqual(cached_again, cached)
                self.assertIsNot(cached_again, cached)

                other_common = root / "other-common"
                other_common.mkdir()
                (git_dir / "commondir").write_text(
                    os.fspath(other_common) + "\n",
                    encoding="utf-8",
                )
                with self.assertRaises(
                    self.engine.LauncherError
                ) as caught:
                    self.engine.authenticate_git_cwd(nested)
                self.assertEqual(
                    str(caught.exception),
                    "the retained worktree has an unexpected "
                    "common Git directory",
                )
                self.assertIs(
                    identities[worker],
                    cached_again,
                )
                self.assertEqual(owners, {git_dir: worker})

    def test_retained_worktree_kernel_and_wrapper_signatures(
        self,
    ) -> None:
        self.assertIs(
            self.engine._authenticate_retained_worktree,
            self.identity.authenticate_retained_worktree,
        )
        parameters = inspect.signature(
            self.identity.authenticate_retained_worktree
        ).parameters
        self.assertEqual(
            tuple(parameters),
            (
                "repository",
                "manifest",
                "stringifier",
                "error_type",
                "linked_worktree_authenticator",
                "path_factory",
            ),
        )
        for name in ("repository", "manifest"):
            self.assertIs(
                parameters[name].kind,
                inspect.Parameter.POSITIONAL_OR_KEYWORD,
            )
        for name in tuple(parameters)[2:]:
            self.assertIs(
                parameters[name].kind,
                inspect.Parameter.KEYWORD_ONLY,
            )
        for parameter in parameters.values():
            self.assertIs(
                parameter.default,
                inspect.Parameter.empty,
            )

        self.assertIsNot(
            self.engine.authenticate_retained_worktree,
            self.identity.authenticate_retained_worktree,
        )
        wrapper_parameters = inspect.signature(
            self.engine.authenticate_retained_worktree
        ).parameters
        self.assertEqual(
            tuple(wrapper_parameters),
            ("repository", "manifest"),
        )
        for parameter in wrapper_parameters.values():
            self.assertIs(
                parameter.kind,
                inspect.Parameter.POSITIONAL_OR_KEYWORD,
            )
            self.assertIs(
                parameter.default,
                inspect.Parameter.empty,
            )

    def test_retained_worktree_kernel_preserves_exact_success_order(
        self,
    ) -> None:
        events: list[tuple[str, object]] = []
        first_common = OpaqueValue("first-common-read")
        second_common = OpaqueValue("second-common-read")
        stringified_common = OpaqueValue("stringified-common")
        worktree_value = OpaqueValue("manifest-worktree")
        worktree_path = OpaqueValue("constructed-worktree")
        result = OpaqueValue("linked-authentication-result")

        class Repository:
            def __init__(repository_self) -> None:
                repository_self.reads = 0

            @property
            def common_git_dir(
                repository_self,
            ) -> object:
                repository_self.reads += 1
                events.append(
                    (
                        "repository-common",
                        repository_self.reads,
                    )
                )
                return (
                    first_common
                    if repository_self.reads == 1
                    else second_common
                )

        repository = Repository()

        class ComparisonTruth:
            def __bool__(truth_self) -> bool:
                events.append(("comparison-truth", False))
                return False

        class RecordedCommon:
            def __ne__(
                recorded_self,
                other: object,
            ) -> object:
                events.append(("recorded-common-ne", other))
                self.assertIs(other, stringified_common)
                return ComparisonTruth()

        recorded_common = RecordedCommon()

        class Manifest:
            @property
            def get(manifest_self) -> object:
                events.append(("manifest-get-attribute", None))

                def get(key: object) -> object:
                    events.append(("manifest-get-call", key))
                    return recorded_common

                return get

            def __getitem__(
                manifest_self,
                key: object,
            ) -> object:
                events.append(("manifest-subscript", key))
                return worktree_value

        manifest = Manifest()

        def stringifier() -> object:
            events.append(("stringifier-provider", None))

            def stringify(value: object) -> object:
                events.append(("stringifier-call", value))
                self.assertIs(value, first_common)
                return stringified_common

            return stringify

        def linked_worktree_authenticator() -> object:
            events.append(("authenticator-provider", None))

            def authenticate(
                path: object,
                *,
                expected_common_git_dir: object,
            ) -> object:
                events.append(
                    (
                        "authenticator-call",
                        (path, expected_common_git_dir),
                    )
                )
                self.assertIs(path, worktree_path)
                self.assertIs(
                    expected_common_git_dir,
                    second_common,
                )
                return result

            return authenticate

        def path_factory() -> object:
            events.append(("path-provider", None))

            def construct(value: object) -> object:
                events.append(("path-call", value))
                self.assertIs(value, worktree_value)
                return worktree_path

            return construct

        observed = self.identity.authenticate_retained_worktree(
            repository,
            manifest,
            stringifier=stringifier,
            error_type=mock.Mock(
                side_effect=AssertionError(
                    "resolved error type on success"
                )
            ),
            linked_worktree_authenticator=(
                linked_worktree_authenticator
            ),
            path_factory=path_factory,
        )

        self.assertIs(observed, result)
        self.assertEqual(repository.reads, 2)
        self.assertEqual(
            events,
            [
                ("manifest-get-attribute", None),
                ("manifest-get-call", "common_git_dir"),
                ("stringifier-provider", None),
                ("repository-common", 1),
                ("stringifier-call", first_common),
                ("recorded-common-ne", stringified_common),
                ("comparison-truth", False),
                ("authenticator-provider", None),
                ("path-provider", None),
                ("manifest-subscript", "worktree"),
                ("path-call", worktree_value),
                ("repository-common", 2),
                (
                    "authenticator-call",
                    (worktree_path, second_common),
                ),
            ],
        )

    def test_retained_worktree_mismatch_short_circuits_exactly(
        self,
    ) -> None:
        events: list[tuple[str, object]] = []
        common = OpaqueValue("mismatch-common")
        rendered = OpaqueValue("mismatch-rendered")

        class Repository:
            @property
            def common_git_dir(
                repository_self,
            ) -> object:
                events.append(("repository-common", None))
                return common

        class Truth:
            def __bool__(truth_self) -> bool:
                events.append(("comparison-truth", True))
                return True

        class Recorded:
            def __ne__(
                recorded_self,
                other: object,
            ) -> object:
                events.append(("recorded-ne", other))
                return Truth()

        class Manifest:
            def get(
                manifest_self,
                key: object,
            ) -> object:
                events.append(("manifest-get", key))
                return Recorded()

            def __getitem__(
                manifest_self,
                key: object,
            ) -> object:
                raise AssertionError(
                    "read worktree after common mismatch"
                )

        class RetainedError(RuntimeError):
            def __init__(
                error_self,
                message: str,
            ) -> None:
                events.append(("error-constructor", message))
                super().__init__(message)

        def error_type() -> type[BaseException]:
            events.append(("error-provider", None))
            return RetainedError

        with self.assertRaises(RetainedError) as caught:
            self.identity.authenticate_retained_worktree(
                Repository(),
                Manifest(),
                stringifier=lambda: (
                    lambda value: (
                        events.append(
                            ("stringifier-call", value)
                        )
                        or rendered
                    )
                ),
                error_type=error_type,
                linked_worktree_authenticator=mock.Mock(
                    side_effect=AssertionError(
                        "resolved authenticator after mismatch"
                    )
                ),
                path_factory=mock.Mock(
                    side_effect=AssertionError(
                        "resolved Path after mismatch"
                    )
                ),
            )

        self.assertEqual(
            str(caught.exception),
            "the retained run's common Git directory changed",
        )
        self.assertIsNone(caught.exception.__cause__)
        self.assertEqual(
            events,
            [
                ("manifest-get", "common_git_dir"),
                ("repository-common", None),
                ("stringifier-call", common),
                ("recorded-ne", rendered),
                ("comparison-truth", True),
                ("error-provider", None),
                (
                    "error-constructor",
                    "the retained run's common "
                    "Git directory changed",
                ),
            ],
        )

    def test_retained_worktree_kernel_never_translates_failures(
        self,
    ) -> None:
        stages = (
            "manifest-get-attribute",
            "manifest-get-call",
            "stringifier-provider",
            "repository-common-first",
            "stringifier-call",
            "recorded-ne",
            "recorded-truth",
            "authenticator-provider",
            "path-provider",
            "manifest-subscript",
            "path-call",
            "repository-common-second",
            "authenticator-call",
            "error-provider",
            "error-constructor",
        )

        for stage in stages:
            with self.subTest(unwrapped_stage=stage):
                original = LinkedDependencyError(stage)
                events: list[str] = []

                def fail_at(observed: str) -> None:
                    events.append(observed)
                    if stage == observed:
                        raise original

                class Repository:
                    def __init__(repository_self) -> None:
                        repository_self.reads = 0

                    @property
                    def common_git_dir(
                        repository_self,
                    ) -> object:
                        repository_self.reads += 1
                        fail_at(
                            "repository-common-first"
                            if repository_self.reads == 1
                            else "repository-common-second"
                        )
                        return OpaqueValue(
                            f"common-{repository_self.reads}"
                        )

                class Truth:
                    def __bool__(truth_self) -> bool:
                        fail_at("recorded-truth")
                        return stage in {
                            "error-provider",
                            "error-constructor",
                        }

                class Recorded:
                    def __ne__(
                        recorded_self,
                        other: object,
                    ) -> object:
                        fail_at("recorded-ne")
                        return Truth()

                class Manifest:
                    @property
                    def get(manifest_self) -> object:
                        fail_at("manifest-get-attribute")

                        def get(key: object) -> object:
                            fail_at("manifest-get-call")
                            return Recorded()

                        return get

                    def __getitem__(
                        manifest_self,
                        key: object,
                    ) -> object:
                        fail_at("manifest-subscript")
                        return OpaqueValue("worktree-value")

                def stringifier() -> object:
                    fail_at("stringifier-provider")

                    def stringify(value: object) -> str:
                        fail_at("stringifier-call")
                        return "common"

                    return stringify

                def authenticator_provider() -> object:
                    fail_at("authenticator-provider")

                    def authenticate(
                        path: object,
                        *,
                        expected_common_git_dir: object,
                    ) -> object:
                        fail_at("authenticator-call")
                        return OpaqueValue("identity")

                    return authenticate

                def path_factory() -> object:
                    fail_at("path-provider")

                    def construct(value: object) -> object:
                        fail_at("path-call")
                        return OpaqueValue("worktree-path")

                    return construct

                class BrokenError:
                    def __new__(
                        cls,
                        message: object,
                    ) -> object:
                        fail_at("error-constructor")
                        raise AssertionError(
                            "error construction unexpectedly succeeded"
                        )

                def error_type() -> type:
                    fail_at("error-provider")
                    return BrokenError

                with self.assertRaises(
                    LinkedDependencyError
                ) as caught:
                    self.identity.authenticate_retained_worktree(
                        Repository(),
                        Manifest(),
                        stringifier=stringifier,
                        error_type=error_type,
                        linked_worktree_authenticator=(
                            authenticator_provider
                        ),
                        path_factory=path_factory,
                    )

                self.assertIs(caught.exception, original)
                self.assertEqual(events[-1], stage)

    def test_engine_retained_worktree_wrapper_uses_fresh_globals(
        self,
    ) -> None:
        repository = OpaqueValue("engine-retained-repository")
        manifest = OpaqueValue("engine-retained-manifest")
        result = OpaqueValue("engine-retained-result")
        initial_stringifier = object()
        stringifier_one = object()
        stringifier_two = object()
        initial_authenticator = object()
        authenticator_one = object()
        authenticator_two = object()
        initial_path = object()
        path_one = object()
        path_two = object()

        class InitialError(RuntimeError):
            pass

        class ErrorOne(RuntimeError):
            pass

        class ErrorTwo(RuntimeError):
            pass

        def kernel(
            observed_repository: object,
            observed_manifest: object,
            **dependencies: object,
        ) -> object:
            self.assertIs(observed_repository, repository)
            self.assertIs(observed_manifest, manifest)
            self.assertEqual(
                tuple(dependencies),
                (
                    "stringifier",
                    "error_type",
                    "linked_worktree_authenticator",
                    "path_factory",
                ),
            )

            self.engine.str = stringifier_one
            self.assertIs(
                dependencies["stringifier"](),
                stringifier_one,
            )
            self.engine.str = stringifier_two
            self.assertIs(
                dependencies["stringifier"](),
                stringifier_two,
            )
            self.engine.LauncherError = ErrorOne
            self.assertIs(
                dependencies["error_type"](),
                ErrorOne,
            )
            self.engine.LauncherError = ErrorTwo
            self.assertIs(
                dependencies["error_type"](),
                ErrorTwo,
            )
            self.engine.authenticate_linked_worktree_path = (
                authenticator_one
            )
            self.assertIs(
                dependencies[
                    "linked_worktree_authenticator"
                ](),
                authenticator_one,
            )
            self.engine.authenticate_linked_worktree_path = (
                authenticator_two
            )
            self.assertIs(
                dependencies[
                    "linked_worktree_authenticator"
                ](),
                authenticator_two,
            )
            self.engine.Path = path_one
            self.assertIs(
                dependencies["path_factory"](),
                path_one,
            )
            self.engine.Path = path_two
            self.assertIs(
                dependencies["path_factory"](),
                path_two,
            )
            return result

        with (
            mock.patch.object(
                self.engine,
                "_authenticate_retained_worktree",
                side_effect=kernel,
            ) as kernel_mock,
            mock.patch.object(
                self.engine,
                "str",
                initial_stringifier,
                create=True,
            ),
            mock.patch.object(
                self.engine,
                "LauncherError",
                InitialError,
            ),
            mock.patch.object(
                self.engine,
                "authenticate_linked_worktree_path",
                initial_authenticator,
            ),
            mock.patch.object(
                self.engine,
                "Path",
                initial_path,
            ),
        ):
            observed = self.engine.authenticate_retained_worktree(
                repository,
                manifest,
            )

        self.assertIs(observed, result)
        kernel_mock.assert_called_once()

    def test_retained_worktree_wrapper_matches_real_manifest_values(
        self,
    ) -> None:
        common_git_dir = Path("/repository/.git")
        worktree = Path("/state/worktrees/run")
        repository = self.identity.Repository(
            root=Path("/repository"),
            git_dir=common_git_dir,
            common_git_dir=common_git_dir,
            relative_cwd=Path("."),
            linked_worktree=False,
            state_root=Path("/state"),
        )
        manifest = {
            "common_git_dir": os.fspath(common_git_dir),
            "worktree": os.fspath(worktree),
        }
        result = OpaqueValue("real-manifest-result")
        authenticator = mock.Mock(return_value=result)

        with mock.patch.object(
            self.engine,
            "authenticate_linked_worktree_path",
            authenticator,
        ):
            observed = self.engine.authenticate_retained_worktree(
                repository,
                manifest,
            )

        self.assertIs(observed, result)
        authenticator.assert_called_once_with(
            worktree,
            expected_common_git_dir=common_git_dir,
        )

        for recorded_common in (
            None,
            "",
            "/different/.git",
            common_git_dir,
        ):
            with self.subTest(
                recorded_common=recorded_common
            ):
                blocked_authenticator = mock.Mock(
                    side_effect=AssertionError(
                        "authenticated mismatched manifest"
                    )
                )
                with mock.patch.object(
                    self.engine,
                    "authenticate_linked_worktree_path",
                    blocked_authenticator,
                ):
                    with self.assertRaises(
                        self.engine.LauncherError
                    ) as caught:
                        (
                            self.engine
                            .authenticate_retained_worktree(
                                repository,
                                {
                                    "common_git_dir": (
                                        recorded_common
                                    ),
                                    "worktree": os.fspath(
                                        worktree
                                    ),
                                },
                            )
                        )

                self.assertEqual(
                    str(caught.exception),
                    "the retained run's common "
                    "Git directory changed",
                )
                self.assertIsNone(caught.exception.__cause__)
                blocked_authenticator.assert_not_called()

        missing_worktree = {
            "common_git_dir": os.fspath(common_git_dir)
        }
        with mock.patch.object(
            self.engine,
            "authenticate_linked_worktree_path",
            authenticator,
        ):
            with self.assertRaises(KeyError) as caught:
                self.engine.authenticate_retained_worktree(
                    repository,
                    missing_worktree,
                )
        self.assertEqual(caught.exception.args, ("worktree",))

    def test_linked_worktree_validation_kernel_and_wrapper_signatures(
        self,
    ) -> None:
        self.assertIs(
            self.engine._validate_linked_worktree_path,
            self.identity.validate_linked_worktree_path,
        )
        parameters = inspect.signature(
            self.identity.validate_linked_worktree_path
        ).parameters
        self.assertEqual(
            tuple(parameters),
            (
                "worktree",
                "expected_common_git_dir",
                "real_directory",
                "single_line",
                "pointer_path",
                "length",
                "error_type",
            ),
        )
        self.assertIs(
            parameters["worktree"].kind,
            inspect.Parameter.POSITIONAL_OR_KEYWORD,
        )
        for name in tuple(parameters)[1:]:
            self.assertIs(
                parameters[name].kind,
                inspect.Parameter.KEYWORD_ONLY,
            )
        for parameter in parameters.values():
            self.assertIs(
                parameter.default,
                inspect.Parameter.empty,
            )

        wrapper_parameters = inspect.signature(
            self.engine.authenticate_linked_worktree_path
        ).parameters
        self.assertEqual(
            tuple(wrapper_parameters),
            ("worktree", "expected_common_git_dir"),
        )
        self.assertIs(
            wrapper_parameters["worktree"].kind,
            inspect.Parameter.POSITIONAL_OR_KEYWORD,
        )
        self.assertIs(
            wrapper_parameters[
                "expected_common_git_dir"
            ].kind,
            inspect.Parameter.KEYWORD_ONLY,
        )
        self.assertIs(
            wrapper_parameters["worktree"].default,
            inspect.Parameter.empty,
        )
        self.assertIsNone(
            wrapper_parameters[
                "expected_common_git_dir"
            ].default
        )

    def test_linked_worktree_validation_preserves_exact_success_order(
        self,
    ) -> None:
        harness = LinkedValidationHarness(self)

        observed = harness.validate(self.identity)

        self.assertIs(type(observed), tuple)
        self.assertEqual(len(observed), 4)
        self.assertIs(observed[0], harness.canonical_worktree)
        self.assertIs(observed[1], harness.git_file)
        self.assertIs(observed[2], harness.git_dir)
        self.assertIs(observed[3], harness.common_git_dir)
        self.assertEqual(
            harness.events,
            [
                ("real-directory-provider-1", None),
                (
                    "real-directory-call-1",
                    (
                        harness.worktree,
                        "the retained worktree",
                    ),
                ),
                ("canonical-git-file", ".git"),
                ("single-line-provider-1", None),
                (
                    "single-line-call-1",
                    (
                        harness.git_file,
                        "the retained worktree .git file",
                    ),
                ),
                ("forward-startswith", "gitdir: "),
                ("forward-startswith-truth", True),
                ("forward-equality", "gitdir: "),
                ("forward-equality-truth", False),
                ("pointer-provider-1", None),
                ("length-provider", None),
                ("length-call", "gitdir: "),
                (
                    "forward-slice",
                    slice(harness.length_value, None, None),
                ),
                (
                    "pointer-call-1",
                    (
                        harness.raw_git_dir,
                        harness.canonical_worktree,
                        "the retained worktree .git file",
                    ),
                ),
                ("real-directory-provider-2", None),
                (
                    "real-directory-call-2",
                    (
                        harness.raw_git_dir,
                        "the retained worktree "
                        "Git admin directory",
                    ),
                ),
                ("single-line-provider-2", None),
                ("git-directory-commondir", "commondir"),
                (
                    "single-line-call-2",
                    (
                        harness.commondir_file,
                        "the retained worktree commondir file",
                    ),
                ),
                ("pointer-provider-2", None),
                (
                    "pointer-call-2",
                    (
                        harness.commondir_value,
                        harness.git_dir,
                        "the retained worktree commondir file",
                    ),
                ),
                ("real-directory-provider-3", None),
                (
                    "real-directory-call-3",
                    (
                        harness.raw_common,
                        "the retained worktree "
                        "common Git directory",
                    ),
                ),
                ("real-directory-provider-4", None),
                (
                    "real-directory-call-4",
                    (
                        harness.expected_common_input,
                        "the recorded common Git directory",
                    ),
                ),
                ("common-mismatch", harness.expected_common),
                ("common-mismatch-truth", False),
                ("real-directory-provider-5", None),
                ("common-worktrees", "worktrees"),
                (
                    "real-directory-call-5",
                    (
                        harness.worktrees_path,
                        "the common linked-worktree "
                        "administration directory",
                    ),
                ),
                ("git-directory-parent", None),
                ("parent-mismatch", harness.worktrees_admin),
                ("parent-mismatch-truth", False),
                (
                    "git-directory-admin-equality",
                    harness.worktrees_admin,
                ),
                (
                    "git-directory-admin-equality-truth",
                    False,
                ),
                ("single-line-provider-3", None),
                ("git-directory-gitdir", "gitdir"),
                (
                    "single-line-call-3",
                    (
                        harness.gitdir_file,
                        "the retained worktree gitdir backlink",
                    ),
                ),
                ("pointer-provider-3", None),
                (
                    "pointer-call-3",
                    (
                        harness.backlink_value,
                        harness.git_dir,
                        "the retained worktree gitdir backlink",
                    ),
                ),
                ("backlink-mismatch", harness.git_file),
                ("backlink-mismatch-truth", False),
            ],
        )
        self.assertEqual(harness.real_provider_count, 5)
        self.assertEqual(harness.line_provider_count, 3)
        self.assertEqual(harness.pointer_provider_count, 3)

    def test_linked_worktree_validation_optional_expected_common(
        self,
    ) -> None:
        harness = LinkedValidationHarness(
            self,
            expected_common=False,
            common_mismatch=True,
        )

        observed = harness.validate(self.identity)

        self.assertIs(observed[0], harness.canonical_worktree)
        self.assertIs(observed[1], harness.git_file)
        self.assertIs(observed[2], harness.git_dir)
        self.assertIs(observed[3], harness.common_git_dir)
        self.assertEqual(harness.real_provider_count, 4)
        self.assertEqual(harness.line_provider_count, 3)
        self.assertEqual(harness.pointer_provider_count, 3)
        event_names = tuple(name for name, value in harness.events)
        self.assertNotIn("common-mismatch", event_names)
        self.assertNotIn(
            "common-mismatch-truth",
            event_names,
        )
        self.assertNotIn(
            "real-directory-provider-5",
            event_names,
        )
        self.assertIn(
            (
                "real-directory-call-4",
                (
                    harness.worktrees_path,
                    "the common linked-worktree "
                    "administration directory",
                ),
            ),
            harness.events,
        )

    def test_linked_worktree_validation_policy_rejections_short_circuit(
        self,
    ) -> None:
        cases = (
            (
                "wrong-prefix",
                {"forward_starts": False},
                "the retained worktree .git file "
                "has an invalid pointer",
                (
                    "forward-equality",
                    "length-provider",
                    "pointer-provider-1",
                ),
            ),
            (
                "empty-pointer",
                {"forward_equals_prefix": True},
                "the retained worktree .git file "
                "has an invalid pointer",
                (
                    "length-provider",
                    "pointer-provider-1",
                ),
            ),
            (
                "unexpected-common",
                {"common_mismatch": True},
                "the retained worktree has an unexpected "
                "common Git directory",
                (
                    "real-directory-provider-5",
                    "common-worktrees",
                    "single-line-provider-3",
                ),
            ),
            (
                "parent-mismatch",
                {"parent_mismatch": True},
                "the retained worktree Git admin directory "
                "is not its unique direct child",
                (
                    "git-directory-admin-equality",
                    "single-line-provider-3",
                ),
            ),
            (
                "admin-self",
                {"git_dir_equals_admin": True},
                "the retained worktree Git admin directory "
                "is not its unique direct child",
                ("single-line-provider-3",),
            ),
            (
                "backlink-mismatch",
                {"backlink_mismatch": True},
                "the retained worktree Git admin backlink changed",
                (),
            ),
        )

        for (
            rejection,
            settings,
            message,
            forbidden_events,
        ) in cases:
            with self.subTest(rejection=rejection):
                harness = LinkedValidationHarness(
                    self,
                    **settings,
                )

                with self.assertRaises(
                    LinkedValidationError
                ) as caught:
                    harness.validate(self.identity)

                self.assertEqual(str(caught.exception), message)
                self.assertIsNone(caught.exception.__cause__)
                self.assertEqual(
                    harness.events[-1],
                    ("error-provider", None),
                )
                event_names = tuple(
                    name for name, value in harness.events
                )
                for forbidden in forbidden_events:
                    self.assertNotIn(forbidden, event_names)

    def test_linked_worktree_validation_never_translates_dependencies(
        self,
    ) -> None:
        stages = (
            "real-directory-provider-1",
            "real-directory-call-1",
            "canonical-git-file",
            "single-line-provider-1",
            "single-line-call-1",
            "forward-startswith",
            "forward-startswith-truth",
            "forward-equality",
            "forward-equality-truth",
            "pointer-provider-1",
            "length-provider",
            "length-call",
            "forward-slice",
            "pointer-call-1",
            "real-directory-provider-2",
            "real-directory-call-2",
            "single-line-provider-2",
            "git-directory-commondir",
            "single-line-call-2",
            "pointer-provider-2",
            "pointer-call-2",
            "real-directory-provider-3",
            "real-directory-call-3",
            "real-directory-provider-4",
            "real-directory-call-4",
            "common-mismatch",
            "common-mismatch-truth",
            "real-directory-provider-5",
            "common-worktrees",
            "real-directory-call-5",
            "git-directory-parent",
            "parent-mismatch",
            "parent-mismatch-truth",
            "git-directory-admin-equality",
            "git-directory-admin-equality-truth",
            "single-line-provider-3",
            "git-directory-gitdir",
            "single-line-call-3",
            "pointer-provider-3",
            "pointer-call-3",
            "backlink-mismatch",
            "backlink-mismatch-truth",
        )

        for stage in stages:
            with self.subTest(unwrapped_stage=stage):
                harness = LinkedValidationHarness(
                    self,
                    fail_stage=stage,
                )

                with self.assertRaises(
                    LinkedDependencyError
                ) as caught:
                    harness.validate(self.identity)

                self.assertIs(caught.exception, harness.failure)
                self.assertEqual(
                    harness.events[-1][0],
                    stage,
                )
                self.assertNotIn(
                    "error-provider",
                    tuple(
                        name for name, value in harness.events
                    ),
                )

    def test_linked_worktree_validation_error_dependency_is_untranslated(
        self,
    ) -> None:
        harness = LinkedValidationHarness(
            self,
            forward_starts=False,
            fail_stage="error-provider",
        )

        with self.assertRaises(LinkedDependencyError) as caught:
            harness.validate(self.identity)

        self.assertIs(caught.exception, harness.failure)
        self.assertEqual(
            harness.events[-1],
            ("error-provider", None),
        )

        constructor_failure = LookupError(
            "error construction failed"
        )
        harness = LinkedValidationHarness(
            self,
            forward_starts=False,
        )

        class BrokenError:
            def __new__(
                cls,
                message: object,
            ) -> object:
                raise constructor_failure

        def error_type() -> type:
            harness.record("error-provider", None)
            return BrokenError

        harness.error_type = error_type
        with self.assertRaises(LookupError) as caught:
            harness.validate(self.identity)

        self.assertIs(caught.exception, constructor_failure)
        self.assertEqual(
            harness.events[-1],
            ("error-provider", None),
        )

    def test_linked_worktree_cache_kernel_signature_and_alias(
        self,
    ) -> None:
        self.assertIs(
            self.engine._validate_linked_worktree_identity_cache,
            self.identity.validate_linked_worktree_identity_cache,
        )
        parameters = inspect.signature(
            self.identity.validate_linked_worktree_identity_cache
        ).parameters
        self.assertEqual(
            tuple(parameters),
            (
                "identity",
                "canonical_worktree",
                "prior_identity",
                "admin_owner",
                "error_type",
            ),
        )
        self.assertIs(
            parameters["identity"].kind,
            inspect.Parameter.POSITIONAL_OR_KEYWORD,
        )
        for name in tuple(parameters)[1:]:
            self.assertIs(
                parameters[name].kind,
                inspect.Parameter.KEYWORD_ONLY,
            )
        for parameter in parameters.values():
            self.assertIs(
                parameter.default,
                inspect.Parameter.empty,
            )

    def test_linked_worktree_cache_accepts_absent_and_matching_entries(
        self,
    ) -> None:
        for prior_present in (False, True):
            for owner_present in (False, True):
                with self.subTest(
                    prior_present=prior_present,
                    owner_present=owner_present,
                ):
                    events: list[tuple[str, object]] = []
                    identity = OpaqueValue("cache-identity")
                    canonical = OpaqueValue(
                        "cache-canonical-worktree"
                    )

                    class Truth:
                        def __init__(
                            truth_self,
                            name: str,
                        ) -> None:
                            truth_self.name = name

                        def __bool__(truth_self) -> bool:
                            events.append(
                                (
                                    f"{truth_self.name}-truth",
                                    False,
                                )
                            )
                            return False

                    class Prior:
                        def __bool__(prior_self) -> bool:
                            raise AssertionError(
                                "truth-tested a non-None prior"
                            )

                        def __ne__(
                            prior_self,
                            other: object,
                        ) -> object:
                            events.append(("prior-ne", other))
                            self.assertIs(other, identity)
                            return Truth("prior-ne")

                    class Owner:
                        def __bool__(owner_self) -> bool:
                            raise AssertionError(
                                "truth-tested a non-None owner"
                            )

                        def __ne__(
                            owner_self,
                            other: object,
                        ) -> object:
                            events.append(("owner-ne", other))
                            self.assertIs(other, canonical)
                            return Truth("owner-ne")

                    prior = Prior() if prior_present else None
                    owner = Owner() if owner_present else None

                    def prior_identity() -> object:
                        events.append(
                            ("prior-callback", None)
                        )
                        return prior

                    def admin_owner() -> object:
                        events.append(
                            ("owner-callback", None)
                        )
                        return owner

                    observed = (
                        self.identity
                        .validate_linked_worktree_identity_cache(
                            identity,
                            canonical_worktree=canonical,
                            prior_identity=prior_identity,
                            admin_owner=admin_owner,
                            error_type=mock.Mock(
                                side_effect=AssertionError(
                                    "resolved an error on "
                                    "matching cache entries"
                                )
                            ),
                        )
                    )

                    self.assertIsNone(observed)
                    self.assertEqual(
                        events,
                        [("prior-callback", None)]
                        + (
                            [
                                ("prior-ne", identity),
                                ("prior-ne-truth", False),
                            ]
                            if prior_present
                            else []
                        )
                        + [("owner-callback", None)]
                        + (
                            [
                                ("owner-ne", canonical),
                                ("owner-ne-truth", False),
                            ]
                            if owner_present
                            else []
                        ),
                    )

    def test_linked_worktree_cache_collisions_short_circuit_exactly(
        self,
    ) -> None:
        identity = OpaqueValue("collision-identity")
        canonical = OpaqueValue("collision-canonical")

        class InitialError(RuntimeError):
            pass

        cases = (
            (
                "prior",
                "the retained worktree Git identity changed",
            ),
            (
                "owner",
                "the retained worktree Git admin directory "
                "is not unique",
            ),
        )

        for collision, message in cases:
            with self.subTest(collision=collision):
                events: list[tuple[str, object]] = []

                class SelectedError(RuntimeError):
                    def __init__(
                        error_self,
                        diagnostic: str,
                    ) -> None:
                        events.append(
                            ("error-constructor", diagnostic)
                        )
                        super().__init__(diagnostic)

                error_types: list[type[BaseException]] = [
                    InitialError
                ]

                class Truth:
                    def __init__(
                        truth_self,
                        name: str,
                    ) -> None:
                        truth_self.name = name

                    def __bool__(truth_self) -> bool:
                        events.append(
                            (
                                f"{truth_self.name}-truth",
                                True,
                            )
                        )
                        error_types[0] = SelectedError
                        return True

                class Prior:
                    def __ne__(
                        prior_self,
                        other: object,
                    ) -> object:
                        events.append(("prior-ne", other))
                        self.assertIs(other, identity)
                        return Truth("prior-ne")

                class Owner:
                    def __ne__(
                        owner_self,
                        other: object,
                    ) -> object:
                        events.append(("owner-ne", other))
                        self.assertIs(other, canonical)
                        return Truth("owner-ne")

                def prior_identity() -> object:
                    events.append(("prior-callback", None))
                    return Prior() if collision == "prior" else None

                def admin_owner() -> object:
                    events.append(("owner-callback", None))
                    return Owner()

                def error_type() -> type[BaseException]:
                    events.append(("error-provider", None))
                    return error_types[0]

                with self.assertRaises(SelectedError) as caught:
                    (
                        self.identity
                        .validate_linked_worktree_identity_cache(
                            identity,
                            canonical_worktree=canonical,
                            prior_identity=prior_identity,
                            admin_owner=admin_owner,
                            error_type=error_type,
                        )
                    )

                self.assertEqual(str(caught.exception), message)
                self.assertIsNone(caught.exception.__cause__)
                self.assertEqual(
                    events,
                    [("prior-callback", None)]
                    + (
                        [
                            ("prior-ne", identity),
                            ("prior-ne-truth", True),
                        ]
                        if collision == "prior"
                        else [
                            ("owner-callback", None),
                            ("owner-ne", canonical),
                            ("owner-ne-truth", True),
                        ]
                    )
                    + [
                        ("error-provider", None),
                        ("error-constructor", message),
                    ],
                )
                if collision == "prior":
                    self.assertNotIn(
                        "owner-callback",
                        tuple(
                            name for name, value in events
                        ),
                    )

    def test_linked_worktree_cache_never_translates_dependencies(
        self,
    ) -> None:
        stages = (
            "prior-callback",
            "prior-ne",
            "prior-truth",
            "owner-callback",
            "owner-ne",
            "owner-truth",
            "error-provider",
            "error-constructor",
        )

        for stage in stages:
            with self.subTest(unwrapped_stage=stage):
                events: list[str] = []
                original = LinkedDependencyError(stage)
                identity = OpaqueValue(
                    f"cache-failure-{stage}-identity"
                )
                canonical = OpaqueValue(
                    f"cache-failure-{stage}-canonical"
                )

                def fail_at(observed: str) -> None:
                    events.append(observed)
                    if stage == observed:
                        raise original

                class Truth:
                    def __init__(
                        truth_self,
                        observed_stage: str,
                        value: bool,
                    ) -> None:
                        truth_self.observed_stage = (
                            observed_stage
                        )
                        truth_self.value = value

                    def __bool__(truth_self) -> bool:
                        fail_at(truth_self.observed_stage)
                        return truth_self.value

                class Prior:
                    def __ne__(
                        prior_self,
                        other: object,
                    ) -> object:
                        fail_at("prior-ne")
                        return Truth(
                            "prior-truth",
                            stage in {
                                "error-provider",
                                "error-constructor",
                            },
                        )

                class Owner:
                    def __ne__(
                        owner_self,
                        other: object,
                    ) -> object:
                        fail_at("owner-ne")
                        return Truth("owner-truth", False)

                def prior_identity() -> object:
                    fail_at("prior-callback")
                    if stage in {
                        "prior-ne",
                        "prior-truth",
                        "error-provider",
                        "error-constructor",
                    }:
                        return Prior()
                    return None

                def admin_owner() -> object:
                    fail_at("owner-callback")
                    if stage in {"owner-ne", "owner-truth"}:
                        return Owner()
                    return None

                class BrokenError:
                    def __new__(
                        cls,
                        diagnostic: object,
                    ) -> object:
                        fail_at("error-constructor")
                        raise AssertionError(
                            "error construction unexpectedly succeeded"
                        )

                def error_type() -> type:
                    fail_at("error-provider")
                    return BrokenError

                with self.assertRaises(
                    LinkedDependencyError
                ) as caught:
                    (
                        self.identity
                        .validate_linked_worktree_identity_cache(
                            identity,
                            canonical_worktree=canonical,
                            prior_identity=prior_identity,
                            admin_owner=admin_owner,
                            error_type=error_type,
                        )
                    )

                self.assertIs(caught.exception, original)
                self.assertEqual(events[-1], stage)

    def test_linked_worktree_wrapper_sequences_new_cache_kernel(
        self,
    ) -> None:
        events: list[tuple[str, object]] = []
        worktree = OpaqueValue("cache-wrapper-input")
        expected_common = OpaqueValue(
            "cache-wrapper-expected-common"
        )
        canonical = OpaqueValue("cache-wrapper-canonical")
        git_file = OpaqueValue("cache-wrapper-git-file")
        git_dir = OpaqueValue("cache-wrapper-git-dir")
        common = OpaqueValue("cache-wrapper-common")
        identity = OpaqueValue("cache-wrapper-identity")

        class Components:
            def __iter__(
                components_self,
            ) -> object:
                events.append(("components-iter", None))
                for name, value in (
                    ("canonical", canonical),
                    ("git-file", git_file),
                    ("git-dir", git_dir),
                    ("common", common),
                ):
                    events.append(
                        ("component-yield", (name, value))
                    )
                    yield value
                events.append(("components-exhausted", None))

        def path_validator(
            observed_worktree: object,
            **dependencies: object,
        ) -> object:
            events.append(("path-validator", observed_worktree))
            self.assertIs(observed_worktree, worktree)
            self.assertIs(
                dependencies["expected_common_git_dir"],
                expected_common,
            )
            return Components()

        def factory(**values: object) -> object:
            events.append(("constructor", values))
            return identity

        initial_identities = RecordingRegistry(
            "initial-identities",
            events,
            get_failure=AssertionError(
                "captured initial identity registry"
            ),
        )
        initial_owners = RecordingRegistry(
            "initial-owners",
            events,
            get_failure=AssertionError(
                "captured initial owner registry"
            ),
        )
        first_identity_lookup = RecordingRegistry(
            "first-identity-lookup",
            events,
        )
        second_identity_lookup = RecordingRegistry(
            "second-identity-lookup",
            events,
        )
        first_owner_lookup = RecordingRegistry(
            "first-owner-lookup",
            events,
        )
        second_owner_lookup = RecordingRegistry(
            "second-owner-lookup",
            events,
        )
        assignment_identities = RecordingRegistry(
            "assignment-identities",
            events,
        )
        assignment_owners = RecordingRegistry(
            "assignment-owners",
            events,
        )

        class InitialError(RuntimeError):
            pass

        class ErrorOne(RuntimeError):
            pass

        class ErrorTwo(RuntimeError):
            pass

        def cache_validator(
            observed_identity: object,
            **dependencies: object,
        ) -> object:
            events.append(
                ("cache-validator", observed_identity)
            )
            self.assertIs(observed_identity, identity)
            self.assertEqual(
                tuple(dependencies),
                (
                    "canonical_worktree",
                    "prior_identity",
                    "admin_owner",
                    "error_type",
                ),
            )
            self.assertIs(
                dependencies["canonical_worktree"],
                canonical,
            )

            self.engine._LINKED_WORKTREE_IDENTITIES = (
                first_identity_lookup
            )
            self.assertIsNone(
                dependencies["prior_identity"]()
            )
            self.engine._LINKED_WORKTREE_IDENTITIES = (
                second_identity_lookup
            )
            self.assertIsNone(
                dependencies["prior_identity"]()
            )
            self.engine._LINKED_ADMIN_OWNERS = (
                first_owner_lookup
            )
            self.assertIsNone(dependencies["admin_owner"]())
            self.engine._LINKED_ADMIN_OWNERS = (
                second_owner_lookup
            )
            self.assertIsNone(dependencies["admin_owner"]())

            self.engine.LauncherError = ErrorOne
            self.assertIs(
                dependencies["error_type"](),
                ErrorOne,
            )
            self.engine.LauncherError = ErrorTwo
            self.assertIs(
                dependencies["error_type"](),
                ErrorTwo,
            )
            self.engine._LINKED_WORKTREE_IDENTITIES = (
                assignment_identities
            )
            self.engine._LINKED_ADMIN_OWNERS = (
                assignment_owners
            )
            events.append(("cache-validation-complete", None))
            return OpaqueValue("ignored-cache-result")

        with (
            mock.patch.object(
                self.engine,
                "_validate_linked_worktree_path",
                side_effect=path_validator,
            ),
            mock.patch.object(
                self.engine,
                "_validate_linked_worktree_identity_cache",
                side_effect=cache_validator,
            ) as cache_kernel,
            mock.patch.object(
                self.engine,
                "LinkedWorktreeIdentity",
                side_effect=factory,
            ),
            mock.patch.object(
                self.engine,
                "_LINKED_WORKTREE_IDENTITIES",
                initial_identities,
            ),
            mock.patch.object(
                self.engine,
                "_LINKED_ADMIN_OWNERS",
                initial_owners,
            ),
            mock.patch.object(
                self.engine,
                "LauncherError",
                InitialError,
            ),
        ):
            observed = self.engine.authenticate_linked_worktree_path(
                worktree,
                expected_common_git_dir=expected_common,
            )

        self.assertIs(observed, identity)
        cache_kernel.assert_called_once()
        self.assertEqual(
            events,
            [
                ("path-validator", worktree),
                ("components-iter", None),
                (
                    "component-yield",
                    ("canonical", canonical),
                ),
                (
                    "component-yield",
                    ("git-file", git_file),
                ),
                (
                    "component-yield",
                    ("git-dir", git_dir),
                ),
                (
                    "component-yield",
                    ("common", common),
                ),
                ("components-exhausted", None),
                (
                    "constructor",
                    {
                        "worktree": canonical,
                        "git_file": git_file,
                        "git_dir": git_dir,
                        "common_git_dir": common,
                    },
                ),
                ("cache-validator", identity),
                ("first-identity-lookup-get", canonical),
                ("second-identity-lookup-get", canonical),
                ("first-owner-lookup-get", git_dir),
                ("second-owner-lookup-get", git_dir),
                ("cache-validation-complete", None),
                (
                    "assignment-identities-set",
                    (canonical, identity),
                ),
                (
                    "assignment-owners-set",
                    (git_dir, canonical),
                ),
            ],
        )
        self.assertIs(
            assignment_identities.values[canonical],
            identity,
        )
        self.assertIs(
            assignment_owners.values[git_dir],
            canonical,
        )

    def test_linked_worktree_wrapper_forwards_fresh_lazy_globals(
        self,
    ) -> None:
        events: list[tuple[str, object]] = []
        worktree = OpaqueValue("wrapper-worktree")
        expected_common = OpaqueValue("wrapper-expected-common")
        canonical = OpaqueValue("wrapper-canonical")
        git_file = OpaqueValue("wrapper-git-file")
        git_dir = OpaqueValue("wrapper-git-dir")
        common = OpaqueValue("wrapper-common")
        identity = OpaqueValue("wrapper-identity")

        initial_real = object()
        real_one = object()
        real_two = object()
        initial_line = object()
        line_one = object()
        line_two = object()
        initial_pointer = object()
        pointer_one = object()
        pointer_two = object()
        initial_length = object()
        length_one = object()
        length_two = object()

        class InitialError(Exception):
            pass

        class ErrorOne(Exception):
            pass

        class ErrorTwo(Exception):
            pass

        initial_factory = mock.Mock(
            side_effect=AssertionError(
                "constructed before validation completed"
            )
        )
        initial_identities = RecordingRegistry(
            "initial-identities",
            events,
            get_failure=AssertionError(
                "read identity cache before validation"
            ),
        )
        initial_owners = RecordingRegistry(
            "initial-owners",
            events,
            get_failure=AssertionError(
                "read owner cache before validation"
            ),
        )
        identities = RecordingRegistry("identities", events)
        owners = RecordingRegistry("owners", events)

        def rebound_factory(**values: object) -> object:
            events.append(("constructor", values))
            return identity

        def validator(
            observed_worktree: object,
            **dependencies: object,
        ) -> tuple[object, object, object, object]:
            events.append(("validator", observed_worktree))
            self.assertIs(observed_worktree, worktree)
            self.assertEqual(
                tuple(dependencies),
                (
                    "expected_common_git_dir",
                    "real_directory",
                    "single_line",
                    "pointer_path",
                    "length",
                    "error_type",
                ),
            )
            self.assertIs(
                dependencies["expected_common_git_dir"],
                expected_common,
            )

            self.engine.exact_real_directory = real_one
            self.assertIs(
                dependencies["real_directory"](),
                real_one,
            )
            self.engine.exact_real_directory = real_two
            self.assertIs(
                dependencies["real_directory"](),
                real_two,
            )
            self.engine.exact_single_line = line_one
            self.assertIs(
                dependencies["single_line"](),
                line_one,
            )
            self.engine.exact_single_line = line_two
            self.assertIs(
                dependencies["single_line"](),
                line_two,
            )
            self.engine.exact_pointer_path = pointer_one
            self.assertIs(
                dependencies["pointer_path"](),
                pointer_one,
            )
            self.engine.exact_pointer_path = pointer_two
            self.assertIs(
                dependencies["pointer_path"](),
                pointer_two,
            )
            self.engine.len = length_one
            self.assertIs(
                dependencies["length"](),
                length_one,
            )
            self.engine.len = length_two
            self.assertIs(
                dependencies["length"](),
                length_two,
            )
            self.engine.LauncherError = ErrorOne
            self.assertIs(
                dependencies["error_type"](),
                ErrorOne,
            )
            self.engine.LauncherError = ErrorTwo
            self.assertIs(
                dependencies["error_type"](),
                ErrorTwo,
            )

            self.engine.LinkedWorktreeIdentity = rebound_factory
            self.engine._LINKED_WORKTREE_IDENTITIES = identities
            self.engine._LINKED_ADMIN_OWNERS = owners
            events.append(("validation-complete", None))
            return canonical, git_file, git_dir, common

        with (
            mock.patch.object(
                self.engine,
                "_validate_linked_worktree_path",
                side_effect=validator,
            ) as kernel,
            mock.patch.object(
                self.engine,
                "exact_real_directory",
                initial_real,
            ),
            mock.patch.object(
                self.engine,
                "exact_single_line",
                initial_line,
            ),
            mock.patch.object(
                self.engine,
                "exact_pointer_path",
                initial_pointer,
            ),
            mock.patch.object(
                self.engine,
                "len",
                initial_length,
                create=True,
            ),
            mock.patch.object(
                self.engine,
                "LauncherError",
                InitialError,
            ),
            mock.patch.object(
                self.engine,
                "LinkedWorktreeIdentity",
                initial_factory,
            ),
            mock.patch.object(
                self.engine,
                "_LINKED_WORKTREE_IDENTITIES",
                initial_identities,
            ),
            mock.patch.object(
                self.engine,
                "_LINKED_ADMIN_OWNERS",
                initial_owners,
            ),
        ):
            observed = self.engine.authenticate_linked_worktree_path(
                worktree,
                expected_common_git_dir=expected_common,
            )

        self.assertIs(observed, identity)
        kernel.assert_called_once()
        initial_factory.assert_not_called()
        self.assertEqual(
            events,
            [
                ("validator", worktree),
                ("validation-complete", None),
                (
                    "constructor",
                    {
                        "worktree": canonical,
                        "git_file": git_file,
                        "git_dir": git_dir,
                        "common_git_dir": common,
                    },
                ),
                ("identities-get", canonical),
                ("owners-get", git_dir),
                (
                    "identities-set",
                    (canonical, identity),
                ),
                ("owners-set", (git_dir, canonical)),
            ],
        )
        self.assertIs(identities.values[canonical], identity)
        self.assertIs(owners.values[git_dir], canonical)

    def test_linked_worktree_wrapper_registry_policy_and_set_order(
        self,
    ) -> None:
        worktree = OpaqueValue("registry-worktree-input")
        canonical = OpaqueValue("registry-canonical")
        git_file = OpaqueValue("registry-git-file")
        git_dir = OpaqueValue("registry-git-dir")
        common = OpaqueValue("registry-common")
        identity = OpaqueValue("registry-identity")

        cases = (
            ("empty", "none", "none", None),
            ("matching", "equal", "same", None),
            (
                "identity-mismatch",
                "different",
                "none",
                "the retained worktree Git identity changed",
            ),
            (
                "owner-collision",
                "none",
                "different",
                "the retained worktree Git admin directory "
                "is not unique",
            ),
        )

        for (
            case,
            prior_state,
            owner_state,
            diagnostic,
        ) in cases:
            with self.subTest(case=case):
                events: list[tuple[str, object]] = []

                class Truth:
                    def __init__(
                        truth_self,
                        name: str,
                        value: bool,
                    ) -> None:
                        truth_self.name = name
                        truth_self.value = value

                    def __bool__(truth_self) -> bool:
                        events.append(
                            (
                                f"{truth_self.name}-truth",
                                truth_self.value,
                            )
                        )
                        return truth_self.value

                class Prior:
                    def __ne__(
                        prior_self,
                        other: object,
                    ) -> object:
                        events.append(("prior-ne", other))
                        return Truth(
                            "prior-ne",
                            prior_state == "different",
                        )

                class Owner:
                    def __ne__(
                        owner_self,
                        other: object,
                    ) -> object:
                        events.append(("owner-ne", other))
                        return Truth(
                            "owner-ne",
                            owner_state == "different",
                        )

                prior = (
                    None
                    if prior_state == "none"
                    else Prior()
                )
                owner = {
                    "none": None,
                    "same": canonical,
                    "different": Owner(),
                }[owner_state]
                identities = RecordingRegistry(
                    "identities",
                    events,
                    values=(
                        {}
                        if prior is None
                        else {canonical: prior}
                    ),
                )
                owners = RecordingRegistry(
                    "owners",
                    events,
                    values=(
                        {}
                        if owner is None
                        else {git_dir: owner}
                    ),
                )

                def validator(
                    observed: object,
                    **dependencies: object,
                ) -> tuple[object, object, object, object]:
                    events.append(("validator", observed))
                    return canonical, git_file, git_dir, common

                def factory(**values: object) -> object:
                    events.append(("constructor", values))
                    return identity

                with (
                    mock.patch.object(
                        self.engine,
                        "_validate_linked_worktree_path",
                        side_effect=validator,
                    ),
                    mock.patch.object(
                        self.engine,
                        "LinkedWorktreeIdentity",
                        side_effect=factory,
                    ),
                    mock.patch.object(
                        self.engine,
                        "_LINKED_WORKTREE_IDENTITIES",
                        identities,
                    ),
                    mock.patch.object(
                        self.engine,
                        "_LINKED_ADMIN_OWNERS",
                        owners,
                    ),
                ):
                    if diagnostic is None:
                        observed = (
                            self.engine
                            .authenticate_linked_worktree_path(
                                worktree
                            )
                        )
                    else:
                        with self.assertRaises(
                            self.engine.LauncherError
                        ) as caught:
                            (
                                self.engine
                                .authenticate_linked_worktree_path(
                                    worktree
                                )
                            )

                if diagnostic is None:
                    self.assertIs(observed, identity)
                    self.assertIs(
                        identities.values[canonical],
                        identity,
                    )
                    self.assertIs(
                        owners.values[git_dir],
                        canonical,
                    )
                    self.assertEqual(
                        events[-2:],
                        [
                            (
                                "identities-set",
                                (canonical, identity),
                            ),
                            (
                                "owners-set",
                                (git_dir, canonical),
                            ),
                        ],
                    )
                else:
                    self.assertEqual(
                        str(caught.exception),
                        diagnostic,
                    )
                    self.assertIsNone(
                        caught.exception.__cause__
                    )
                    self.assertNotIn(
                        "identities-set",
                        tuple(name for name, value in events),
                    )
                    self.assertNotIn(
                        "owners-set",
                        tuple(name for name, value in events),
                    )

                event_names = tuple(
                    name for name, value in events
                )
                self.assertLess(
                    event_names.index("validator"),
                    event_names.index("constructor"),
                )
                self.assertLess(
                    event_names.index("constructor"),
                    event_names.index("identities-get"),
                )
                if prior_state == "different":
                    self.assertNotIn("owners-get", event_names)
                else:
                    self.assertIn("owners-get", event_names)

    def test_linked_worktree_wrapper_requires_exactly_four_components(
        self,
    ) -> None:
        component = OpaqueValue("unpack-component")

        for count in (0, 3, 5):
            with self.subTest(component_count=count):
                blocked_factory = mock.Mock(
                    side_effect=AssertionError(
                        "constructed from the wrong component count"
                    )
                )
                blocked_identities = RecordingRegistry(
                    "blocked-identities",
                    [],
                    get_failure=AssertionError(
                        "read cache after invalid component count"
                    ),
                )
                blocked_owners = RecordingRegistry(
                    "blocked-owners",
                    [],
                    get_failure=AssertionError(
                        "read cache after invalid component count"
                    ),
                )

                with (
                    mock.patch.object(
                        self.engine,
                        "_validate_linked_worktree_path",
                        return_value=(component,) * count,
                    ),
                    mock.patch.object(
                        self.engine,
                        "LinkedWorktreeIdentity",
                        blocked_factory,
                    ),
                    mock.patch.object(
                        self.engine,
                        "_LINKED_WORKTREE_IDENTITIES",
                        blocked_identities,
                    ),
                    mock.patch.object(
                        self.engine,
                        "_LINKED_ADMIN_OWNERS",
                        blocked_owners,
                    ),
                ):
                    with self.assertRaises(ValueError) as caught:
                        (
                            self.engine
                            .authenticate_linked_worktree_path(
                                OpaqueValue(
                                    f"unpack-input-{count}"
                                )
                            )
                        )

                self.assertIsNone(caught.exception.__cause__)
                blocked_factory.assert_not_called()
                self.assertEqual(blocked_identities.events, [])
                self.assertEqual(blocked_owners.events, [])

    def test_linked_worktree_wrapper_registry_globals_are_reloaded(
        self,
    ) -> None:
        events: list[tuple[str, object]] = []
        canonical = OpaqueValue("rebind-canonical")
        git_file = OpaqueValue("rebind-git-file")
        git_dir = OpaqueValue("rebind-git-dir")
        common = OpaqueValue("rebind-common")
        identity = OpaqueValue("rebind-identity")

        final_owners = RecordingRegistry("final-owners", events)
        intermediate_owners = RecordingRegistry(
            "intermediate-owners",
            events,
        )

        def rebind_owner_after_identity_set() -> None:
            events.append(("rebind-owner-after-set", None))
            self.engine._LINKED_ADMIN_OWNERS = final_owners

        rebound_identities = RecordingRegistry(
            "rebound-identities",
            events,
            on_set=rebind_owner_after_identity_set,
        )

        def rebind_identity_after_get() -> None:
            events.append(("rebind-identity-after-get", None))
            self.engine._LINKED_WORKTREE_IDENTITIES = (
                rebound_identities
            )

        initial_identities = RecordingRegistry(
            "initial-identities",
            events,
            on_get=rebind_identity_after_get,
        )

        def rebind_owner_after_get() -> None:
            events.append(("rebind-owner-after-get", None))
            self.engine._LINKED_ADMIN_OWNERS = (
                intermediate_owners
            )

        initial_owners = RecordingRegistry(
            "initial-owners",
            events,
            on_get=rebind_owner_after_get,
        )

        with (
            mock.patch.object(
                self.engine,
                "_validate_linked_worktree_path",
                return_value=(
                    canonical,
                    git_file,
                    git_dir,
                    common,
                ),
            ),
            mock.patch.object(
                self.engine,
                "LinkedWorktreeIdentity",
                return_value=identity,
            ),
            mock.patch.object(
                self.engine,
                "_LINKED_WORKTREE_IDENTITIES",
                initial_identities,
            ),
            mock.patch.object(
                self.engine,
                "_LINKED_ADMIN_OWNERS",
                initial_owners,
            ),
        ):
            observed = self.engine.authenticate_linked_worktree_path(
                OpaqueValue("rebind-input")
            )

        self.assertIs(observed, identity)
        self.assertEqual(
            events,
            [
                ("initial-identities-get", canonical),
                ("rebind-identity-after-get", None),
                ("initial-owners-get", git_dir),
                ("rebind-owner-after-get", None),
                (
                    "rebound-identities-set",
                    (canonical, identity),
                ),
                ("rebind-owner-after-set", None),
                ("final-owners-set", (git_dir, canonical)),
            ],
        )
        self.assertEqual(initial_identities.values, {})
        self.assertEqual(initial_owners.values, {})
        self.assertEqual(intermediate_owners.values, {})
        self.assertIs(
            rebound_identities.values[canonical],
            identity,
        )
        self.assertIs(final_owners.values[git_dir], canonical)

    def test_linked_worktree_wrapper_failures_and_partial_mutation(
        self,
    ) -> None:
        stages = (
            "validator",
            "unpack",
            "constructor",
            "identity-get",
            "prior-ne",
            "prior-truth",
            "owner-get",
            "owner-ne",
            "owner-truth",
            "identity-set",
            "owner-set",
        )

        for stage in stages:
            with self.subTest(unwrapped_stage=stage):
                original = LinkedDependencyError(stage)
                events: list[tuple[str, object]] = []
                canonical = OpaqueValue(
                    f"failure-{stage}-canonical"
                )
                git_file = OpaqueValue(
                    f"failure-{stage}-git-file"
                )
                git_dir = OpaqueValue(
                    f"failure-{stage}-git-dir"
                )
                common = OpaqueValue(
                    f"failure-{stage}-common"
                )
                identity = OpaqueValue(
                    f"failure-{stage}-identity"
                )

                def fail_at(observed: str) -> None:
                    events.append((observed, None))
                    if stage == observed:
                        raise original

                class Truth:
                    def __init__(
                        truth_self,
                        observed_stage: str,
                    ) -> None:
                        truth_self.observed_stage = (
                            observed_stage
                        )

                    def __bool__(truth_self) -> bool:
                        fail_at(truth_self.observed_stage)
                        return False

                class Prior:
                    def __ne__(
                        prior_self,
                        other: object,
                    ) -> object:
                        fail_at("prior-ne")
                        return Truth("prior-truth")

                class Owner:
                    def __ne__(
                        owner_self,
                        other: object,
                    ) -> object:
                        fail_at("owner-ne")
                        return Truth("owner-truth")

                class BrokenComponents:
                    def __iter__(
                        components_self,
                    ) -> object:
                        fail_at("unpack")
                        return iter(())

                def validator(
                    observed: object,
                    **dependencies: object,
                ) -> object:
                    fail_at("validator")
                    if stage == "unpack":
                        return BrokenComponents()
                    return canonical, git_file, git_dir, common

                def factory(**values: object) -> object:
                    fail_at("constructor")
                    return identity

                prior = (
                    Prior()
                    if stage in {"prior-ne", "prior-truth"}
                    else None
                )
                owner = (
                    Owner()
                    if stage in {"owner-ne", "owner-truth"}
                    else None
                )
                identities = RecordingRegistry(
                    "identities",
                    events,
                    values=(
                        {}
                        if prior is None
                        else {canonical: prior}
                    ),
                    get_failure=(
                        original
                        if stage == "identity-get"
                        else None
                    ),
                    set_failure=(
                        original
                        if stage == "identity-set"
                        else None
                    ),
                )
                owners = RecordingRegistry(
                    "owners",
                    events,
                    values=(
                        {}
                        if owner is None
                        else {git_dir: owner}
                    ),
                    get_failure=(
                        original
                        if stage == "owner-get"
                        else None
                    ),
                    set_failure=(
                        original
                        if stage == "owner-set"
                        else None
                    ),
                )
                initial_owner_values = dict(owners.values)
                blocked_error = mock.Mock(
                    side_effect=AssertionError(
                        "translated wrapper dependency failure"
                    )
                )

                with (
                    mock.patch.object(
                        self.engine,
                        "_validate_linked_worktree_path",
                        side_effect=validator,
                    ),
                    mock.patch.object(
                        self.engine,
                        "LinkedWorktreeIdentity",
                        side_effect=factory,
                    ),
                    mock.patch.object(
                        self.engine,
                        "_LINKED_WORKTREE_IDENTITIES",
                        identities,
                    ),
                    mock.patch.object(
                        self.engine,
                        "_LINKED_ADMIN_OWNERS",
                        owners,
                    ),
                    mock.patch.object(
                        self.engine,
                        "LauncherError",
                        blocked_error,
                    ),
                ):
                    with self.assertRaises(
                        LinkedDependencyError
                    ) as caught:
                        (
                            self.engine
                            .authenticate_linked_worktree_path(
                                OpaqueValue(
                                    f"failure-{stage}-input"
                                )
                            )
                        )

                self.assertIs(caught.exception, original)
                blocked_error.assert_not_called()
                if stage == "owner-set":
                    self.assertIs(
                        identities.values[canonical],
                        identity,
                    )
                    self.assertEqual(
                        owners.values,
                        initial_owner_values,
                    )
                else:
                    self.assertIsNot(
                        identities.values.get(canonical),
                        identity,
                    )
                    self.assertEqual(
                        owners.values,
                        initial_owner_values,
                    )
                if stage == "identity-set":
                    self.assertNotIn(
                        "owners-set",
                        tuple(
                            name for name, value in events
                        ),
                    )

    def test_linked_worktree_wrapper_resolves_rebound_policy_errors(
        self,
    ) -> None:
        canonical = OpaqueValue("error-rebind-canonical")
        git_file = OpaqueValue("error-rebind-git-file")
        git_dir = OpaqueValue("error-rebind-git-dir")
        common = OpaqueValue("error-rebind-common")
        identity = OpaqueValue("error-rebind-identity")

        class InitialError(RuntimeError):
            pass

        class ReboundIdentityError(RuntimeError):
            pass

        class ReboundOwnerError(RuntimeError):
            pass

        class Mismatch:
            def __init__(
                mismatch_self,
                error: type[BaseException],
            ) -> None:
                mismatch_self.error = error

            def __ne__(
                mismatch_self,
                other: object,
            ) -> bool:
                self.engine.LauncherError = (
                    mismatch_self.error
                )
                return True

        cases = (
            (
                "identity",
                {canonical: Mismatch(ReboundIdentityError)},
                {},
                ReboundIdentityError,
                "the retained worktree Git identity changed",
            ),
            (
                "owner",
                {},
                {git_dir: Mismatch(ReboundOwnerError)},
                ReboundOwnerError,
                "the retained worktree Git admin directory "
                "is not unique",
            ),
        )

        for (
            collision,
            identities,
            owners,
            expected_error,
            message,
        ) in cases:
            with self.subTest(collision=collision):
                with (
                    mock.patch.object(
                        self.engine,
                        "_validate_linked_worktree_path",
                        return_value=(
                            canonical,
                            git_file,
                            git_dir,
                            common,
                        ),
                    ),
                    mock.patch.object(
                        self.engine,
                        "LinkedWorktreeIdentity",
                        return_value=identity,
                    ),
                    mock.patch.object(
                        self.engine,
                        "_LINKED_WORKTREE_IDENTITIES",
                        dict(identities),
                    ),
                    mock.patch.object(
                        self.engine,
                        "_LINKED_ADMIN_OWNERS",
                        dict(owners),
                    ),
                    mock.patch.object(
                        self.engine,
                        "LauncherError",
                        InitialError,
                    ),
                ):
                    with self.assertRaises(
                        expected_error
                    ) as caught:
                        (
                            self.engine
                            .authenticate_linked_worktree_path(
                                OpaqueValue(
                                    f"error-rebind-{collision}"
                                )
                            )
                        )

                self.assertEqual(str(caught.exception), message)
                self.assertIsNone(caught.exception.__cause__)

    def test_linked_worktree_authentication_matches_git_and_tampering(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            repository = root / "repository"
            worker = root / "worker"

            def run_git(*arguments: str) -> subprocess.CompletedProcess:
                return subprocess.run(
                    ("git", *arguments),
                    cwd=root,
                    text=True,
                    capture_output=True,
                    check=True,
                    timeout=20,
                )

            run_git("init", "-q", os.fspath(repository))
            run_git(
                "-C",
                os.fspath(repository),
                "config",
                "user.name",
                "Worktree Marshal Test",
            )
            run_git(
                "-C",
                os.fspath(repository),
                "config",
                "user.email",
                "marshal@example.invalid",
            )
            tracked = repository / "tracked"
            tracked.write_text("initial\n", encoding="utf-8")
            run_git(
                "-C",
                os.fspath(repository),
                "add",
                "tracked",
            )
            run_git(
                "-C",
                os.fspath(repository),
                "commit",
                "-q",
                "-m",
                "initial",
            )
            run_git(
                "-C",
                os.fspath(repository),
                "worktree",
                "add",
                "-q",
                "--detach",
                os.fspath(worker),
                "HEAD",
            )

            git_file = worker / ".git"
            forward = git_file.read_text(encoding="utf-8")
            self.assertTrue(forward.startswith("gitdir: "))
            raw_git_dir = forward.removeprefix(
                "gitdir: "
            ).removesuffix("\n")
            git_dir_candidate = Path(raw_git_dir)
            if not git_dir_candidate.is_absolute():
                git_dir_candidate = worker / git_dir_candidate
            git_dir = git_dir_candidate.resolve(strict=True)
            commondir_file = git_dir / "commondir"
            commondir_line = commondir_file.read_text(
                encoding="utf-8"
            )
            raw_common = commondir_line.removesuffix("\n")
            common_candidate = Path(raw_common)
            if not common_candidate.is_absolute():
                common_candidate = git_dir / common_candidate
            common_git_dir = common_candidate.resolve(strict=True)
            backlink_file = git_dir / "gitdir"
            backlink_line = backlink_file.read_text(
                encoding="utf-8"
            )
            original_git_file = git_file.read_bytes()
            original_commondir = commondir_file.read_bytes()
            original_backlink = backlink_file.read_bytes()

            def restore_real_admin() -> None:
                git_file.write_bytes(original_git_file)
                commondir_file.write_bytes(original_commondir)
                backlink_file.write_bytes(original_backlink)

            default_expected = object()

            def authenticate(
                path: Path = worker,
                *,
                expected: object = default_expected,
                identities: dict | None = None,
                owners: dict | None = None,
            ) -> object:
                selected_expected = (
                    common_git_dir
                    if expected is default_expected
                    else expected
                )
                identity_registry = (
                    {} if identities is None else identities
                )
                owner_registry = (
                    {} if owners is None else owners
                )
                with (
                    mock.patch.object(
                        self.engine,
                        "_LINKED_WORKTREE_IDENTITIES",
                        identity_registry,
                    ),
                    mock.patch.object(
                        self.engine,
                        "_LINKED_ADMIN_OWNERS",
                        owner_registry,
                    ),
                ):
                    return (
                        self.engine
                        .authenticate_linked_worktree_path(
                            path,
                            expected_common_git_dir=(
                                selected_expected
                            ),
                        )
                    )

            observed = authenticate()
            self.assertIsInstance(
                observed,
                self.identity.LinkedWorktreeIdentity,
            )
            self.assertEqual(observed.worktree, worker)
            self.assertEqual(observed.git_file, git_file)
            self.assertEqual(observed.git_dir, git_dir)
            self.assertEqual(
                observed.common_git_dir,
                common_git_dir,
            )

            git_file.write_text(
                "gitdir: "
                + os.path.relpath(git_dir, worker)
                + "\n",
                encoding="utf-8",
            )
            commondir_file.write_text(
                os.path.relpath(common_git_dir, git_dir) + "\n",
                encoding="utf-8",
            )
            relative_observed = authenticate()
            self.assertEqual(relative_observed, observed)
            restore_real_admin()

            malformed_cases = (
                (
                    b"not-a-pointer\n",
                    "the retained worktree .git file "
                    "has an invalid pointer",
                    None,
                ),
                (
                    b"gitdir: \n",
                    "the retained worktree .git file "
                    "has an invalid pointer",
                    None,
                ),
                (
                    b"gitdir: missing-admin\n",
                    "the retained worktree .git file "
                    "points to an unavailable path",
                    OSError,
                ),
                (
                    b"gitdir: missing-newline",
                    "the retained worktree .git file "
                    "does not contain one exact line",
                    None,
                ),
            )
            for data, message, cause_type in malformed_cases:
                with self.subTest(git_file=data):
                    git_file.write_bytes(data)
                    with self.assertRaises(
                        self.engine.LauncherError
                    ) as caught:
                        authenticate()
                    self.assertEqual(
                        str(caught.exception),
                        message,
                    )
                    if cause_type is None:
                        self.assertIsNone(
                            caught.exception.__cause__
                        )
                    else:
                        self.assertIsInstance(
                            caught.exception.__cause__,
                            cause_type,
                        )
                    restore_real_admin()

            file_admin = worker / "file-admin"
            file_admin.write_text("not a directory\n")
            git_file.write_text(
                f"gitdir: {file_admin}\n",
                encoding="utf-8",
            )
            with self.assertRaises(
                self.engine.LauncherError
            ) as caught:
                authenticate()
            self.assertEqual(
                str(caught.exception),
                "the retained worktree Git admin directory "
                "is not an exact real directory",
            )
            self.assertIsNone(caught.exception.__cause__)
            restore_real_admin()

            admin_link = worker / "admin-link"
            admin_link.symlink_to(
                git_dir,
                target_is_directory=True,
            )
            git_file.write_text(
                f"gitdir: {admin_link}\n",
                encoding="utf-8",
            )
            with self.assertRaises(
                self.engine.LauncherError
            ) as caught:
                authenticate()
            self.assertEqual(
                str(caught.exception),
                "the retained worktree .git file "
                "traverses a symbolic path",
            )
            self.assertIsNone(caught.exception.__cause__)
            restore_real_admin()

            other_common = root / "other-common"
            other_common.mkdir()
            with self.assertRaises(
                self.engine.LauncherError
            ) as caught:
                authenticate(expected=other_common)
            self.assertEqual(
                str(caught.exception),
                "the retained worktree has an unexpected "
                "common Git directory",
            )
            self.assertIsNone(caught.exception.__cause__)

            nested_admin = (
                common_git_dir
                / "worktrees"
                / "nested"
                / "worker"
            )
            nested_admin.mkdir(parents=True)
            (nested_admin / "commondir").write_text(
                os.path.relpath(
                    common_git_dir,
                    nested_admin,
                )
                + "\n",
                encoding="utf-8",
            )
            (nested_admin / "gitdir").write_text(
                os.fspath(git_file) + "\n",
                encoding="utf-8",
            )
            git_file.write_text(
                f"gitdir: {nested_admin}\n",
                encoding="utf-8",
            )
            with self.assertRaises(
                self.engine.LauncherError
            ) as caught:
                authenticate()
            self.assertEqual(
                str(caught.exception),
                "the retained worktree Git admin directory "
                "is not its unique direct child",
            )
            self.assertIsNone(caught.exception.__cause__)
            restore_real_admin()

            other_backlink = root / "other-git-file"
            other_backlink.write_text("marker\n", encoding="utf-8")
            backlink_file.write_text(
                os.fspath(other_backlink) + "\n",
                encoding="utf-8",
            )
            with self.assertRaises(
                self.engine.LauncherError
            ) as caught:
                authenticate()
            self.assertEqual(
                str(caught.exception),
                "the retained worktree Git admin backlink changed",
            )
            self.assertIsNone(caught.exception.__cause__)
            restore_real_admin()

            identity_registry: dict[Path, object] = {}
            owner_registry: dict[Path, Path] = {}
            cached = authenticate(
                identities=identity_registry,
                owners=owner_registry,
            )
            alternate_admin = (
                common_git_dir / "worktrees" / "alternate"
            )
            alternate_admin.mkdir()
            (alternate_admin / "commondir").write_text(
                os.path.relpath(
                    common_git_dir,
                    alternate_admin,
                )
                + "\n",
                encoding="utf-8",
            )
            (alternate_admin / "gitdir").write_text(
                os.fspath(git_file) + "\n",
                encoding="utf-8",
            )
            git_file.write_text(
                f"gitdir: {alternate_admin}\n",
                encoding="utf-8",
            )
            with self.assertRaises(
                self.engine.LauncherError
            ) as caught:
                authenticate(
                    identities=identity_registry,
                    owners=owner_registry,
                )
            self.assertEqual(
                str(caught.exception),
                "the retained worktree Git identity changed",
            )
            self.assertIs(
                identity_registry[worker],
                cached,
            )
            self.assertEqual(
                owner_registry,
                {git_dir: worker},
            )
            restore_real_admin()

            identity_registry = {}
            owner_registry = {}
            original_identity = authenticate(
                identities=identity_registry,
                owners=owner_registry,
            )
            impostor = root / "impostor"
            impostor.mkdir()
            impostor_git_file = impostor / ".git"
            impostor_git_file.write_text(
                f"gitdir: {git_dir}\n",
                encoding="utf-8",
            )
            backlink_file.write_text(
                os.fspath(impostor_git_file) + "\n",
                encoding="utf-8",
            )
            with self.assertRaises(
                self.engine.LauncherError
            ) as caught:
                authenticate(
                    impostor,
                    identities=identity_registry,
                    owners=owner_registry,
                )
            self.assertEqual(
                str(caught.exception),
                "the retained worktree Git admin directory "
                "is not unique",
            )
            self.assertEqual(
                identity_registry,
                {worker: original_identity},
            )
            self.assertEqual(
                owner_registry,
                {git_dir: worker},
            )

    def test_safe_regular_file_kernel_and_wrapper_signatures(self) -> None:
        self.assertIs(
            self.engine._safe_regular_file_bytes,
            self.identity.safe_regular_file_bytes,
        )
        parameters = inspect.signature(
            self.identity.safe_regular_file_bytes
        ).parameters
        self.assertEqual(
            tuple(parameters),
            (
                "path",
                "label",
                "open_flags",
                "file_open",
                "os_error_type",
                "error_type",
                "file_stat",
                "regular_file_test",
                "maximum_file_bytes",
                "file_read",
                "minimum",
                "length",
                "file_close",
            ),
        )
        self.assertIs(
            parameters["path"].kind,
            inspect.Parameter.POSITIONAL_OR_KEYWORD,
        )
        for name in tuple(parameters)[1:]:
            self.assertIs(
                parameters[name].kind,
                inspect.Parameter.KEYWORD_ONLY,
            )
        for parameter in parameters.values():
            self.assertIs(parameter.default, inspect.Parameter.empty)

        self.assertIsNot(
            self.engine.safe_regular_file_bytes,
            self.identity.safe_regular_file_bytes,
        )
        wrapper = inspect.signature(
            self.engine.safe_regular_file_bytes
        ).parameters
        self.assertEqual(tuple(wrapper), ("path", "label"))
        self.assertIs(
            wrapper["path"].kind,
            inspect.Parameter.POSITIONAL_OR_KEYWORD,
        )
        self.assertIs(
            wrapper["label"].kind,
            inspect.Parameter.KEYWORD_ONLY,
        )
        for parameter in wrapper.values():
            self.assertIs(parameter.default, inspect.Parameter.empty)

    def test_safe_regular_file_builds_flags_before_open_and_accepts_fd_zero(
        self,
    ) -> None:
        events: list[tuple[str, object]] = []
        path = Path("/regular-file")

        def open_flags() -> int:
            events.append(("open-flags", None))
            return 0x123

        def file_open() -> object:
            events.append(("file-open-provider", None))

            def open_file(
                received_path: Path,
                flags: int,
            ) -> int:
                events.append(("file-open", (received_path, flags)))
                return 0

            return open_file

        def file_close() -> object:
            events.append(("file-close-provider", None))

            def close_file(descriptor: int) -> None:
                events.append(("file-close", descriptor))

            return close_file

        observed = self.read_regular_bytes(
            path,
            open_flags=open_flags,
            file_open=file_open,
            file_stat=lambda: lambda descriptor: (
                events.append(("file-stat", descriptor))
                or SimpleNamespace(
                    st_mode=stat.S_IFREG,
                    st_nlink=1,
                    st_size=0,
                    st_dev=1,
                    st_ino=2,
                    st_mtime_ns=3,
                    st_ctime_ns=4,
                )
            ),
            file_read=lambda: lambda descriptor, size: (
                events.append(("file-read", (descriptor, size)))
                or b""
            ),
            file_close=file_close,
            os_error_type=lambda: self.fail(
                "successful open must not resolve the OS error type"
            ),
        )

        self.assertEqual(observed, b"")
        self.assertEqual(
            events,
            [
                ("open-flags", None),
                ("file-open-provider", None),
                ("file-open", (path, 0x123)),
                ("file-stat", 0),
                ("file-read", (0, 17)),
                ("file-stat", 0),
                ("file-close-provider", None),
                ("file-close", 0),
            ],
        )

    def test_safe_regular_file_translates_only_matching_open_errors(
        self,
    ) -> None:
        class MatchingOpenError(OSError):
            pass

        class OtherOpenError(OSError):
            pass

        class ReadError(RuntimeError):
            pass

        events: list[str] = []
        failure = MatchingOpenError("missing")

        class Label:
            def __format__(
                label_self,
                specification: str,
            ) -> str:
                self.assertEqual(specification, "")
                self.assertEqual(events[-1], "error-type")
                events.append("format-label")
                return "the file"

        def open_flags() -> int:
            events.append("open-flags")
            return 9

        def file_open() -> object:
            events.append("file-open-provider")

            def open_file(_path: Path, _flags: int) -> int:
                events.append("file-open")
                raise failure

            return open_file

        def os_error_type() -> type[BaseException]:
            events.append("os-error-type")
            return MatchingOpenError

        def error_type() -> type[BaseException]:
            events.append("error-type")
            return ReadError

        with self.assertRaises(ReadError) as caught:
            self.read_regular_bytes(
                label=Label(),
                open_flags=open_flags,
                file_open=file_open,
                os_error_type=os_error_type,
                error_type=error_type,
                file_close=lambda: self.fail(
                    "failed open must not close a descriptor"
                ),
            )
        self.assertEqual(
            str(caught.exception),
            "the file is not an intact regular file",
        )
        self.assertIs(caught.exception.__cause__, failure)
        self.assertEqual(
            events,
            [
                "open-flags",
                "file-open-provider",
                "file-open",
                "os-error-type",
                "error-type",
                "format-label",
            ],
        )

        other = OtherOpenError("other")
        with self.assertRaises(OtherOpenError) as caught:
            self.read_regular_bytes(
                file_open=lambda: lambda _path, _flags: (
                    (_ for _ in ()).throw(other)
                ),
                os_error_type=lambda: MatchingOpenError,
                error_type=lambda: self.fail(
                    "nonmatching open error must remain untranslated"
                ),
                file_close=lambda: self.fail(
                    "failed open must not close a descriptor"
                ),
            )
        self.assertIs(caught.exception, other)
        self.assertIsNone(caught.exception.__cause__)

        flag_failure = MatchingOpenError("flag")
        with self.assertRaises(MatchingOpenError) as caught:
            self.read_regular_bytes(
                open_flags=lambda: (
                    (_ for _ in ()).throw(flag_failure)
                ),
                file_open=lambda: self.fail(
                    "flag failure must precede file-open lookup"
                ),
                os_error_type=lambda: self.fail(
                    "flag failure is outside the translated-open block"
                ),
                file_close=lambda: self.fail(
                    "flag failure must not close a descriptor"
                ),
            )
        self.assertIs(caught.exception, flag_failure)
        self.assertIsNone(caught.exception.__cause__)

    def test_safe_regular_file_regular_and_link_checks_short_circuit(
        self,
    ) -> None:
        class FileError(RuntimeError):
            pass

        for regular, links, expected_events in (
            (
                False,
                2,
                [
                    "stat-mode",
                    "regular-test",
                    "error-type",
                    "format-label",
                    "close",
                ],
            ),
            (
                True,
                2,
                [
                    "stat-mode",
                    "regular-test",
                    "stat-nlink",
                    "error-type",
                    "format-label",
                    "close",
                ],
            ),
        ):
            events: list[str] = []

            class Metadata:
                @property
                def st_mode(metadata_self) -> int:
                    events.append("stat-mode")
                    return 0o100600

                @property
                def st_nlink(metadata_self) -> int:
                    events.append("stat-nlink")
                    return links

            class Label:
                def __format__(
                    label_self,
                    specification: str,
                ) -> str:
                    self.assertEqual(specification, "")
                    self.assertEqual(events[-1], "error-type")
                    events.append("format-label")
                    return "the file"

            def regular_file_test() -> object:
                def test(_mode: int) -> bool:
                    events.append("regular-test")
                    return regular

                return test

            def error_type() -> type[BaseException]:
                events.append("error-type")
                return FileError

            with self.subTest(regular=regular, links=links):
                with self.assertRaises(FileError) as caught:
                    self.read_regular_bytes(
                        label=Label(),
                        file_stat=lambda: lambda _descriptor: Metadata(),
                        regular_file_test=regular_file_test,
                        error_type=error_type,
                        file_close=lambda: lambda _descriptor: (
                            events.append("close")
                        ),
                    )
                self.assertEqual(
                    str(caught.exception),
                    "the file is not an intact regular file",
                )
                self.assertIsNone(caught.exception.__cause__)
                self.assertEqual(events, expected_events)

    def test_safe_regular_file_reads_bounded_chunks_and_three_lazy_limits(
        self,
    ) -> None:
        maximum = 1024 * 1024 + 2
        first_chunk = b"a" * (1024 * 1024)
        second_chunk = b"bc"
        chunks = iter((first_chunk, second_chunk, b""))
        maximum_calls: list[int] = []
        minimum_calls: list[tuple[int, int]] = []
        length_calls: list[int] = []
        read_calls: list[tuple[int, int]] = []
        close_calls: list[int] = []
        metadata = SimpleNamespace(
            st_mode=stat.S_IFREG,
            st_nlink=1,
            st_size=maximum,
            st_dev=1,
            st_ino=2,
            st_mtime_ns=3,
            st_ctime_ns=4,
        )

        def maximum_file_bytes() -> int:
            maximum_calls.append(len(maximum_calls) + 1)
            return maximum

        def minimum(left: int, right: int) -> int:
            minimum_calls.append((left, right))
            return min(left, right)

        def length(value: object) -> int:
            size = len(value)
            length_calls.append(size)
            return size

        def read_file(descriptor: int, size: int) -> bytes:
            read_calls.append((descriptor, size))
            return next(chunks)

        observed = self.read_regular_bytes(
            file_open=lambda: lambda _path, _flags: 12,
            file_stat=lambda: lambda _descriptor: metadata,
            maximum_file_bytes=maximum_file_bytes,
            file_read=lambda: read_file,
            minimum=lambda: minimum,
            length=lambda: length,
            file_close=lambda: lambda descriptor: (
                close_calls.append(descriptor)
            ),
        )

        self.assertEqual(observed, first_chunk + second_chunk)
        self.assertEqual(maximum_calls, [1, 2, 3])
        self.assertEqual(
            minimum_calls,
            [
                (1024 * 1024, maximum + 1),
                (1024 * 1024, 3),
                (1024 * 1024, 1),
            ],
        )
        self.assertEqual(
            read_calls,
            [(12, 1024 * 1024), (12, 3), (12, 1)],
        )
        self.assertEqual(
            length_calls,
            [len(first_chunk), len(second_chunk), maximum],
        )
        self.assertEqual(close_calls, [12])

    def test_safe_regular_file_enforces_both_size_checks_exactly(
        self,
    ) -> None:
        class FileError(RuntimeError):
            pass

        for stage in ("metadata", "content"):
            events: list[str] = []

            class Label:
                def __format__(
                    label_self,
                    specification: str,
                ) -> str:
                    self.assertEqual(specification, "")
                    self.assertEqual(events[-1], "error-type")
                    events.append("format-label")
                    return "the file"

            def error_type() -> type[BaseException]:
                events.append("error-type")
                return FileError

            metadata = SimpleNamespace(
                st_mode=stat.S_IFREG,
                st_nlink=1,
                st_size=4 if stage == "metadata" else 0,
                st_dev=1,
                st_ino=2,
                st_mtime_ns=3,
                st_ctime_ns=4,
            )
            reads = iter(
                (
                    b"four",
                    b"",
                )
                if stage == "content"
                else ()
            )
            with self.subTest(stage=stage):
                with self.assertRaises(FileError) as caught:
                    self.read_regular_bytes(
                        label=Label(),
                        file_stat=lambda: lambda _descriptor: metadata,
                        maximum_file_bytes=lambda: 3,
                        file_read=(
                            lambda: lambda _descriptor, _size: next(reads)
                        ),
                        error_type=error_type,
                        file_close=lambda: lambda _descriptor: (
                            events.append("close")
                        ),
                    )
                self.assertEqual(
                    str(caught.exception),
                    "the file is unexpectedly large",
                )
                self.assertIsNone(caught.exception.__cause__)
                self.assertEqual(
                    events,
                    ["error-type", "format-label", "close"],
                )

        metadata = SimpleNamespace(
            st_mode=stat.S_IFREG,
            st_nlink=1,
            st_size=3,
            st_dev=1,
            st_ino=2,
            st_mtime_ns=3,
            st_ctime_ns=4,
        )
        chunks = iter((b"abc", b""))
        self.assertEqual(
            self.read_regular_bytes(
                file_stat=lambda: lambda _descriptor: metadata,
                maximum_file_bytes=lambda: 3,
                file_read=lambda: lambda _descriptor, _size: (
                    next(chunks)
                ),
            ),
            b"abc",
        )

    def test_safe_regular_file_compares_second_stat_in_exact_order(
        self,
    ) -> None:
        class ChangedError(RuntimeError):
            pass

        cases = (
            (
                "tuple",
                {"dev": 9},
                [
                    "stat-after",
                    "before-dev",
                    "before-ino",
                    "before-size",
                    "after-dev",
                    "after-ino",
                    "after-size",
                    "error-type",
                    "format-label",
                    "close",
                ],
                True,
            ),
            (
                "mtime",
                {"mtime": 9},
                [
                    "stat-after",
                    "before-dev",
                    "before-ino",
                    "before-size",
                    "after-dev",
                    "after-ino",
                    "after-size",
                    "before-mtime",
                    "after-mtime",
                    "error-type",
                    "format-label",
                    "close",
                ],
                True,
            ),
            (
                "ctime",
                {"ctime": 9},
                [
                    "stat-after",
                    "before-dev",
                    "before-ino",
                    "before-size",
                    "after-dev",
                    "after-ino",
                    "after-size",
                    "before-mtime",
                    "after-mtime",
                    "before-ctime",
                    "after-ctime",
                    "error-type",
                    "format-label",
                    "close",
                ],
                True,
            ),
            (
                "stable",
                {},
                [
                    "stat-after",
                    "before-dev",
                    "before-ino",
                    "before-size",
                    "after-dev",
                    "after-ino",
                    "after-size",
                    "before-mtime",
                    "after-mtime",
                    "before-ctime",
                    "after-ctime",
                    "close",
                ],
                False,
            ),
        )
        for name, changed, expected_events, rejected in cases:
            events: list[str] = []

            class Metadata:
                def __init__(
                    metadata_self,
                    prefix: str,
                    values: dict[str, int],
                ) -> None:
                    metadata_self.prefix = prefix
                    metadata_self.values = values

                @property
                def st_mode(metadata_self) -> int:
                    return stat.S_IFREG

                @property
                def st_nlink(metadata_self) -> int:
                    return 1

                @property
                def st_size(metadata_self) -> int:
                    events.append(f"{metadata_self.prefix}-size")
                    return metadata_self.values.get("size", 0)

                @property
                def st_dev(metadata_self) -> int:
                    events.append(f"{metadata_self.prefix}-dev")
                    return metadata_self.values.get("dev", 1)

                @property
                def st_ino(metadata_self) -> int:
                    events.append(f"{metadata_self.prefix}-ino")
                    return metadata_self.values.get("ino", 2)

                @property
                def st_mtime_ns(metadata_self) -> int:
                    events.append(f"{metadata_self.prefix}-mtime")
                    return metadata_self.values.get("mtime", 3)

                @property
                def st_ctime_ns(metadata_self) -> int:
                    events.append(f"{metadata_self.prefix}-ctime")
                    return metadata_self.values.get("ctime", 4)

            before = Metadata("before", {})
            after = Metadata("after", changed)
            metadata = iter((before, after))
            stat_calls = 0

            def file_stat(_descriptor: int) -> object:
                nonlocal stat_calls
                stat_calls += 1
                if stat_calls == 2:
                    events.append("stat-after")
                return next(metadata)

            def file_read(
                _descriptor: int,
                _size: int,
            ) -> bytes:
                events.clear()
                return b""

            class Label:
                def __format__(
                    label_self,
                    specification: str,
                ) -> str:
                    self.assertEqual(specification, "")
                    self.assertEqual(events[-1], "error-type")
                    events.append("format-label")
                    return "the file"

            def error_type() -> type[BaseException]:
                events.append("error-type")
                return ChangedError

            with self.subTest(comparison=name):
                if rejected:
                    with self.assertRaises(ChangedError) as caught:
                        self.read_regular_bytes(
                            label=Label(),
                            file_stat=lambda: file_stat,
                            file_read=lambda: file_read,
                            error_type=error_type,
                            file_close=lambda: lambda _descriptor: (
                                events.append("close")
                            ),
                        )
                    self.assertEqual(
                        str(caught.exception),
                        "the file changed while it was inspected",
                    )
                    self.assertIsNone(caught.exception.__cause__)
                else:
                    self.assertEqual(
                        self.read_regular_bytes(
                            file_stat=lambda: file_stat,
                            file_read=lambda: file_read,
                            error_type=lambda: self.fail(
                                "stable metadata must not resolve error type"
                            ),
                            file_close=lambda: lambda _descriptor: (
                                events.append("close")
                            ),
                        ),
                        b"",
                    )
                self.assertEqual(events, expected_events)

    def test_safe_regular_file_keeps_other_failures_untranslated(
        self,
    ) -> None:
        class DependencyFailure(RuntimeError):
            pass

        stages = (
            ("open-flags", False),
            ("file-open", False),
            ("os-error-type", False),
            ("file-stat", True),
            ("regular-file-test", True),
            ("error-type", True),
            ("maximum-file-bytes", True),
            ("file-read", True),
            ("minimum", True),
            ("length", True),
            ("second-stat", True),
            ("comparison", True),
        )
        for stage, expected_close in stages:
            failure = DependencyFailure(stage)
            closes: list[int] = []

            def fail(*_args: object, **_kwargs: object) -> object:
                raise failure

            overrides: dict[str, object] = {
                "file_close": lambda: lambda descriptor: (
                    closes.append(descriptor)
                ),
            }
            if stage == "open-flags":
                overrides["open_flags"] = fail
                overrides["file_open"] = lambda: self.fail(
                    "open flags must precede file-open resolution"
                )
            elif stage == "file-open":
                overrides["file_open"] = fail
            elif stage == "os-error-type":
                open_failure = OSError("open")

                def broken_open(
                    _path: Path,
                    _flags: int,
                ) -> int:
                    raise open_failure

                overrides["file_open"] = lambda: broken_open
                overrides["os_error_type"] = fail
            elif stage == "file-stat":
                overrides["file_stat"] = fail
            elif stage == "regular-file-test":
                overrides["regular_file_test"] = fail
            elif stage == "error-type":
                overrides["regular_file_test"] = (
                    lambda: lambda _mode: False
                )
                overrides["error_type"] = fail
            elif stage == "maximum-file-bytes":
                overrides["maximum_file_bytes"] = fail
            elif stage == "file-read":
                overrides["file_read"] = fail
            elif stage == "minimum":
                overrides["minimum"] = fail
            elif stage == "length":
                overrides["file_read"] = lambda: (
                    lambda _descriptor, _size: b"x"
                )
                overrides["length"] = fail
            elif stage == "second-stat":
                metadata = SimpleNamespace(
                    st_mode=stat.S_IFREG,
                    st_nlink=1,
                    st_size=0,
                    st_dev=1,
                    st_ino=2,
                    st_mtime_ns=3,
                    st_ctime_ns=4,
                )
                calls = 0

                def file_stat(_descriptor: int) -> object:
                    nonlocal calls
                    calls += 1
                    if calls == 2:
                        raise failure
                    return metadata

                overrides["file_stat"] = lambda: file_stat
            else:
                class Metadata:
                    st_mode = stat.S_IFREG
                    st_nlink = 1
                    st_size = 0
                    st_ino = 2
                    st_mtime_ns = 3
                    st_ctime_ns = 4

                    @property
                    def st_dev(metadata_self) -> int:
                        raise failure

                overrides["file_stat"] = (
                    lambda: lambda _descriptor: Metadata()
                )

            with self.subTest(stage=stage):
                with self.assertRaises(DependencyFailure) as caught:
                    self.read_regular_bytes(**overrides)
                self.assertIs(caught.exception, failure)
                self.assertIsNone(caught.exception.__cause__)
                self.assertEqual(closes, [7] if expected_close else [])

        class NonBytesChunk:
            def __len__(chunk_self) -> int:
                return 1

        chunks = iter((NonBytesChunk(), b""))
        closes = []
        with self.assertRaises(TypeError) as caught:
            self.read_regular_bytes(
                file_read=lambda: lambda _descriptor, _size: (
                    next(chunks)
                ),
                file_close=lambda: lambda descriptor: (
                    closes.append(descriptor)
                ),
            )
        self.assertIn("bytes-like object", str(caught.exception))
        self.assertIsNone(caught.exception.__cause__)
        self.assertEqual(closes, [7])

    def test_safe_regular_file_close_always_runs_and_can_mask_outcome(
        self,
    ) -> None:
        class BodyFailure(RuntimeError):
            pass

        class CloseFailure(RuntimeError):
            pass

        close_failure = CloseFailure("close")

        def broken_close(_descriptor: int) -> None:
            raise close_failure

        with self.assertRaises(CloseFailure) as caught:
            self.read_regular_bytes(
                file_close=lambda: broken_close,
            )
        self.assertIs(caught.exception, close_failure)
        self.assertIsNone(caught.exception.__cause__)
        self.assertIsNone(caught.exception.__context__)

        body_failure = BodyFailure("read")

        def broken_read(
            _descriptor: int,
            _size: int,
        ) -> bytes:
            raise body_failure

        close_failure = CloseFailure("close after body failure")
        with self.assertRaises(CloseFailure) as caught:
            self.read_regular_bytes(
                file_read=lambda: broken_read,
                file_close=lambda: broken_close,
            )
        self.assertIs(caught.exception, close_failure)
        self.assertIsNone(caught.exception.__cause__)
        self.assertIs(caught.exception.__context__, body_failure)

        close_calls: list[int] = []
        validation_failure = BodyFailure("not regular")
        with self.assertRaises(BodyFailure) as caught:
            self.read_regular_bytes(
                regular_file_test=lambda: lambda _mode: False,
                error_type=lambda: (
                    lambda _message: validation_failure
                ),
                file_close=lambda: lambda descriptor: (
                    close_calls.append(descriptor)
                ),
            )
        self.assertIs(caught.exception, validation_failure)
        self.assertEqual(close_calls, [7])

    def test_engine_safe_regular_file_wrapper_resolves_every_global_lazily(
        self,
    ) -> None:
        class InitialOSError(OSError):
            pass

        class ReboundOSError(OSError):
            pass

        class InitialFileError(RuntimeError):
            pass

        class ReboundFileError(RuntimeError):
            pass

        path = Path("/regular-file")
        label = "the file"
        initial_open = object()
        rebound_open = object()
        rebound_stat = object()
        rebound_regular = object()
        rebound_read = object()
        rebound_minimum = object()
        rebound_length = object()
        rebound_close = object()
        sentinel = object()

        def kernel(
            received_path: Path,
            **dependencies: object,
        ) -> object:
            self.assertIs(received_path, path)
            self.assertEqual(
                tuple(dependencies),
                (
                    "label",
                    "open_flags",
                    "file_open",
                    "os_error_type",
                    "error_type",
                    "file_stat",
                    "regular_file_test",
                    "maximum_file_bytes",
                    "file_read",
                    "minimum",
                    "length",
                    "file_close",
                ),
            )
            self.assertEqual(dependencies.pop("label"), label)

            self.engine.os = SimpleNamespace(
                O_RDONLY=1,
                O_CLOEXEC=2,
                O_NOFOLLOW=4,
                open=rebound_open,
                fstat=object(),
                read=object(),
                close=object(),
            )
            self.assertEqual(dependencies["open_flags"](), 7)
            self.engine.os = SimpleNamespace(O_RDONLY=8)
            self.assertEqual(dependencies["open_flags"](), 8)
            self.engine.os = SimpleNamespace(open=rebound_open)
            self.assertIs(dependencies["file_open"](), rebound_open)

            self.engine.OSError = ReboundOSError
            self.assertIs(
                dependencies["os_error_type"](),
                ReboundOSError,
            )
            self.engine.LauncherError = ReboundFileError
            self.assertIs(
                dependencies["error_type"](),
                ReboundFileError,
            )

            self.engine.os = SimpleNamespace(fstat=rebound_stat)
            self.assertIs(dependencies["file_stat"](), rebound_stat)
            self.engine.stat = SimpleNamespace(
                S_ISREG=rebound_regular,
            )
            self.assertIs(
                dependencies["regular_file_test"](),
                rebound_regular,
            )
            self.engine.MAX_ADMIN_FILE_BYTES = 123
            self.assertEqual(
                dependencies["maximum_file_bytes"](),
                123,
            )

            self.engine.os = SimpleNamespace(read=rebound_read)
            self.assertIs(dependencies["file_read"](), rebound_read)
            self.engine.min = rebound_minimum
            self.assertIs(dependencies["minimum"](), rebound_minimum)
            self.engine.len = rebound_length
            self.assertIs(dependencies["length"](), rebound_length)
            self.engine.os = SimpleNamespace(close=rebound_close)
            self.assertIs(dependencies["file_close"](), rebound_close)
            return sentinel

        initial_os = SimpleNamespace(
            O_RDONLY=8,
            O_CLOEXEC=16,
            O_NOFOLLOW=32,
            open=initial_open,
            fstat=object(),
            read=object(),
            close=object(),
        )
        with (
            mock.patch.object(
                self.engine,
                "_safe_regular_file_bytes",
                side_effect=kernel,
            ) as extracted,
            mock.patch.object(self.engine, "os", initial_os),
            mock.patch.object(
                self.engine,
                "OSError",
                InitialOSError,
                create=True,
            ),
            mock.patch.object(
                self.engine,
                "LauncherError",
                InitialFileError,
            ),
            mock.patch.object(
                self.engine,
                "stat",
                SimpleNamespace(S_ISREG=object()),
            ),
            mock.patch.object(
                self.engine,
                "MAX_ADMIN_FILE_BYTES",
                456,
            ),
            mock.patch.object(
                self.engine,
                "min",
                object(),
                create=True,
            ),
            mock.patch.object(
                self.engine,
                "len",
                object(),
                create=True,
            ),
        ):
            observed = self.engine.safe_regular_file_bytes(
                path,
                label=label,
            )

        self.assertIs(observed, sentinel)
        extracted.assert_called_once()

    def test_safe_regular_file_matches_real_filesystem_behavior(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / "regular"
            payload = b"plain\x00bytes\n"
            path.write_bytes(payload)
            self.assertEqual(
                self.engine.safe_regular_file_bytes(
                    path,
                    label="the real file",
                ),
                payload,
            )

            missing = root / "missing"
            with self.assertRaises(self.engine.LauncherError) as caught:
                self.engine.safe_regular_file_bytes(
                    missing,
                    label="the missing file",
                )
            self.assertEqual(
                str(caught.exception),
                "the missing file is not an intact regular file",
            )
            self.assertIsInstance(caught.exception.__cause__, OSError)

            with self.assertRaises(self.engine.LauncherError) as caught:
                self.engine.safe_regular_file_bytes(
                    root,
                    label="the directory",
                )
            self.assertEqual(
                str(caught.exception),
                "the directory is not an intact regular file",
            )
            self.assertIsNone(caught.exception.__cause__)

            symlink = root / "symbolic"
            symlink.symlink_to(path)
            with self.assertRaises(self.engine.LauncherError) as caught:
                self.engine.safe_regular_file_bytes(
                    symlink,
                    label="the symbolic file",
                )
            self.assertEqual(
                str(caught.exception),
                "the symbolic file is not an intact regular file",
            )
            self.assertIsInstance(caught.exception.__cause__, OSError)

            with mock.patch.object(
                self.engine,
                "MAX_ADMIN_FILE_BYTES",
                len(payload) - 1,
            ):
                with self.assertRaises(self.engine.LauncherError) as caught:
                    self.engine.safe_regular_file_bytes(
                        path,
                        label="the oversized file",
                    )
            self.assertEqual(
                str(caught.exception),
                "the oversized file is unexpectedly large",
            )
            self.assertIsNone(caught.exception.__cause__)

    def test_exact_single_line_kernel_and_wrapper_signatures(self) -> None:
        self.assertIs(
            self.engine._exact_single_line,
            self.identity.exact_single_line,
        )
        parameters = inspect.signature(
            self.identity.exact_single_line
        ).parameters
        self.assertEqual(
            tuple(parameters),
            (
                "path",
                "label",
                "file_reader",
                "decode_error_type",
                "error_type",
            ),
        )
        self.assertIs(
            parameters["path"].kind,
            inspect.Parameter.POSITIONAL_OR_KEYWORD,
        )
        for name in tuple(parameters)[1:]:
            self.assertIs(
                parameters[name].kind,
                inspect.Parameter.KEYWORD_ONLY,
            )
        for parameter in parameters.values():
            self.assertIs(parameter.default, inspect.Parameter.empty)

        self.assertIsNot(
            self.engine.exact_single_line,
            self.identity.exact_single_line,
        )
        wrapper_parameters = inspect.signature(
            self.engine.exact_single_line
        ).parameters
        self.assertEqual(tuple(wrapper_parameters), ("path", "label"))
        self.assertIs(
            wrapper_parameters["path"].kind,
            inspect.Parameter.POSITIONAL_OR_KEYWORD,
        )
        self.assertIs(
            wrapper_parameters["label"].kind,
            inspect.Parameter.KEYWORD_ONLY,
        )
        for parameter in wrapper_parameters.values():
            self.assertIs(parameter.default, inspect.Parameter.empty)

    def test_exact_single_line_kernel_preserves_success_order_and_values(
        self,
    ) -> None:
        events: list[tuple[str, object]] = []
        path = object()

        class TruthValue:
            def __bool__(truth_self) -> bool:
                events.append(("endswith-truth", None))
                return True

        class CountValue:
            def __ne__(count_self, other: object) -> bool:
                events.append(("count-compare", other))
                return False

        class DecodedValue:
            def __bool__(value_self) -> bool:
                events.append(("value-truth", None))
                return True

            def __contains__(value_self, needle: object) -> bool:
                events.append(("value-contains", needle))
                return False

        decoded = DecodedValue()

        class EncodedValue:
            def decode(encoded_self, encoding: str) -> object:
                events.append(("decode", encoding))
                return decoded

        class Data:
            def endswith(data_self, suffix: object) -> object:
                events.append(("endswith", suffix))
                return TruthValue()

            def count(data_self, needle: object) -> object:
                events.append(("count", needle))
                return CountValue()

            def __contains__(data_self, needle: object) -> bool:
                events.append(("data-contains", needle))
                return False

            def __getitem__(data_self, key: object) -> object:
                events.append(("slice", key))
                return EncodedValue()

        data = Data()

        def file_reader() -> object:
            events.append(("reader-provider", None))

            def read(observed_path: object, *, label: str) -> object:
                events.append(
                    ("reader-call", (observed_path, label))
                )
                return data

            return read

        decode_error_type = mock.Mock(
            side_effect=AssertionError(
                "resolved the decode error type on success"
            )
        )
        error_type = mock.Mock(
            side_effect=AssertionError(
                "resolved the launcher error on success"
            )
        )

        observed = self.identity.exact_single_line(
            path,
            label="the admin file",
            file_reader=file_reader,
            decode_error_type=decode_error_type,
            error_type=error_type,
        )

        self.assertIs(observed, decoded)
        self.assertEqual(
            events,
            [
                ("reader-provider", None),
                ("reader-call", (path, "the admin file")),
                ("endswith", b"\n"),
                ("endswith-truth", None),
                ("count", b"\n"),
                ("count-compare", 1),
                ("data-contains", b"\r"),
                ("slice", slice(None, -1, None)),
                ("decode", "utf-8"),
                ("value-truth", None),
                ("value-contains", "\0"),
            ],
        )
        decode_error_type.assert_not_called()
        error_type.assert_not_called()

    def test_exact_single_line_kernel_accepts_the_legacy_byte_domain(
        self,
    ) -> None:
        cases = (
            (b"path\n", "path"),
            ("café/δ\n".encode(), "café/δ"),
            (b"../relative path\n", "../relative path"),
            (b" \t \n", " \t "),
            (b"\x01\n", "\x01"),
            ("\u2028\n".encode(), "\u2028"),
        )

        for data, expected in cases:
            with self.subTest(data=data):
                reader = mock.Mock(return_value=data)
                decode_error_type = mock.Mock(
                    side_effect=AssertionError(
                        "resolved decode error for valid UTF-8"
                    )
                )
                error_type = mock.Mock(
                    side_effect=AssertionError(
                        "resolved launcher error for valid input"
                    )
                )

                observed = self.identity.exact_single_line(
                    Path("/admin/file"),
                    label="the admin file",
                    file_reader=lambda: reader,
                    decode_error_type=decode_error_type,
                    error_type=error_type,
                )

                self.assertEqual(observed, expected)
                reader.assert_called_once_with(
                    Path("/admin/file"),
                    label="the admin file",
                )
                decode_error_type.assert_not_called()
                error_type.assert_not_called()

    def test_exact_single_line_shape_checks_short_circuit_in_order(
        self,
    ) -> None:
        class LineError(RuntimeError):
            pass

        expected_events = {
            "terminal-newline": ["endswith"],
            "newline-count": ["endswith", "count"],
            "carriage-return": ["endswith", "count", "contains"],
        }

        for rejection, expected in expected_events.items():
            with self.subTest(rejection=rejection):
                events: list[str] = []

                class Data:
                    def endswith(data_self, suffix: bytes) -> bool:
                        self.assertEqual(suffix, b"\n")
                        events.append("endswith")
                        return rejection != "terminal-newline"

                    def count(data_self, needle: bytes) -> int:
                        self.assertEqual(needle, b"\n")
                        events.append("count")
                        return 2 if rejection == "newline-count" else 1

                    def __contains__(data_self, needle: bytes) -> bool:
                        self.assertEqual(needle, b"\r")
                        events.append("contains")
                        return rejection == "carriage-return"

                    def __getitem__(data_self, key: object) -> object:
                        raise AssertionError("decoded a malformed line")

                def error_type() -> type[BaseException]:
                    events.append("error-provider")
                    return LineError

                decode_error_type = mock.Mock(
                    side_effect=AssertionError(
                        "resolved decode error for a malformed line"
                    )
                )
                with self.assertRaises(LineError) as caught:
                    self.identity.exact_single_line(
                        Path("/admin/file"),
                        label="the admin file",
                        file_reader=lambda: (
                            lambda path, *, label: Data()
                        ),
                        decode_error_type=decode_error_type,
                        error_type=error_type,
                    )

                self.assertEqual(
                    str(caught.exception),
                    "the admin file does not contain one exact line",
                )
                self.assertIsNone(caught.exception.__cause__)
                self.assertEqual(events, expected + ["error-provider"])
                decode_error_type.assert_not_called()

    def test_exact_single_line_shape_rejection_precedes_decoding(
        self,
    ) -> None:
        class LineError(RuntimeError):
            pass

        cases = (
            b"",
            b"path",
            b"path\nextra",
            b"path\nextra\n",
            b"\n\n",
            b"path\r\n",
            b"pa\rth\n",
            b"\xff",
            b"\xff\r\n",
            b"\xff\n\n",
        )

        for data in cases:
            with self.subTest(data=data):
                decode_error_type = mock.Mock(
                    side_effect=AssertionError(
                        "decoded before validating exact line shape"
                    )
                )
                with self.assertRaises(LineError) as caught:
                    self.identity.exact_single_line(
                        Path("/admin/file"),
                        label="the admin file",
                        file_reader=lambda: (
                            lambda path, *, label: data
                        ),
                        decode_error_type=decode_error_type,
                        error_type=lambda: LineError,
                    )

                self.assertEqual(
                    str(caught.exception),
                    "the admin file does not contain one exact line",
                )
                self.assertIsNone(caught.exception.__cause__)
                decode_error_type.assert_not_called()

    def test_exact_single_line_chains_decode_errors_from_the_narrow_block(
        self,
    ) -> None:
        class SelectedDecodeError(RuntimeError):
            pass

        class LineError(RuntimeError):
            pass

        for stage in ("slice", "decode-attribute", "decode-call"):
            with self.subTest(wrapped_stage=stage):
                original = SelectedDecodeError(stage)
                events: list[str] = []

                class EncodedValue:
                    @property
                    def decode(encoded_self) -> object:
                        events.append("decode-attribute")
                        if stage == "decode-attribute":
                            raise original

                        def decode(encoding: str) -> None:
                            self.assertEqual(encoding, "utf-8")
                            events.append("decode-call")
                            if stage == "decode-call":
                                raise original
                            raise AssertionError(
                                "decode unexpectedly succeeded"
                            )

                        return decode

                class Data:
                    def endswith(data_self, suffix: bytes) -> bool:
                        return True

                    def count(data_self, needle: bytes) -> int:
                        return 1

                    def __contains__(data_self, needle: bytes) -> bool:
                        return False

                    def __getitem__(data_self, key: object) -> EncodedValue:
                        events.append("slice")
                        if stage == "slice":
                            raise original
                        return EncodedValue()

                decode_error_type = mock.Mock(
                    return_value=SelectedDecodeError
                )
                error_type = mock.Mock(return_value=LineError)
                with self.assertRaises(LineError) as caught:
                    self.identity.exact_single_line(
                        Path("/admin/file"),
                        label="the admin file",
                        file_reader=lambda: (
                            lambda path, *, label: Data()
                        ),
                        decode_error_type=decode_error_type,
                        error_type=error_type,
                    )

                self.assertEqual(
                    str(caught.exception),
                    "the admin file is not valid UTF-8",
                )
                self.assertIs(caught.exception.__cause__, original)
                self.assertIs(caught.exception.__context__, original)
                decode_error_type.assert_called_once_with()
                error_type.assert_called_once_with()
                self.assertEqual(
                    events,
                    {
                        "slice": ["slice"],
                        "decode-attribute": [
                            "slice",
                            "decode-attribute",
                        ],
                        "decode-call": [
                            "slice",
                            "decode-attribute",
                            "decode-call",
                        ],
                    }[stage],
                )

    def test_exact_single_line_rejects_actual_invalid_utf8_with_exact_cause(
        self,
    ) -> None:
        class LineError(RuntimeError):
            pass

        with self.assertRaises(LineError) as caught:
            self.identity.exact_single_line(
                Path("/admin/file"),
                label="the admin file",
                file_reader=lambda: (
                    lambda path, *, label: b"\xff\n"
                ),
                decode_error_type=lambda: UnicodeDecodeError,
                error_type=lambda: LineError,
            )

        self.assertEqual(
            str(caught.exception),
            "the admin file is not valid UTF-8",
        )
        self.assertIsInstance(
            caught.exception.__cause__,
            UnicodeDecodeError,
        )
        self.assertIs(
            caught.exception.__context__,
            caught.exception.__cause__,
        )

    def test_exact_single_line_does_not_translate_nonmatching_decode_errors(
        self,
    ) -> None:
        class SelectedDecodeError(RuntimeError):
            pass

        for stage in ("slice", "decode-attribute", "decode-call"):
            with self.subTest(unwrapped_stage=stage):
                original = LookupError(stage)

                class EncodedValue:
                    @property
                    def decode(encoded_self) -> object:
                        if stage == "decode-attribute":
                            raise original

                        def decode(encoding: str) -> None:
                            if stage == "decode-call":
                                raise original
                            raise AssertionError(
                                "decode unexpectedly succeeded"
                            )

                        return decode

                class Data:
                    def endswith(data_self, suffix: bytes) -> bool:
                        return True

                    def count(data_self, needle: bytes) -> int:
                        return 1

                    def __contains__(data_self, needle: bytes) -> bool:
                        return False

                    def __getitem__(data_self, key: object) -> EncodedValue:
                        if stage == "slice":
                            raise original
                        return EncodedValue()

                decode_error_type = mock.Mock(
                    return_value=SelectedDecodeError
                )
                error_type = mock.Mock(
                    side_effect=AssertionError(
                        "translated a nonmatching decode error"
                    )
                )
                with self.assertRaises(LookupError) as caught:
                    self.identity.exact_single_line(
                        Path("/admin/file"),
                        label="the admin file",
                        file_reader=lambda: (
                            lambda path, *, label: Data()
                        ),
                        decode_error_type=decode_error_type,
                        error_type=error_type,
                    )

                self.assertIs(caught.exception, original)
                decode_error_type.assert_called_once_with()
                error_type.assert_not_called()

        original = SelectedDecodeError("decode failed")
        matcher_failure = RuntimeError("decode matcher failed")

        class FailingData:
            def endswith(data_self, suffix: bytes) -> bool:
                return True

            def count(data_self, needle: bytes) -> int:
                return 1

            def __contains__(data_self, needle: bytes) -> bool:
                return False

            def __getitem__(data_self, key: object) -> object:
                raise original

        def broken_decode_error_type() -> type[BaseException]:
            raise matcher_failure

        blocked_error_type = mock.Mock(
            side_effect=AssertionError(
                "translated after decode matcher failure"
            )
        )
        with self.assertRaises(RuntimeError) as matcher_caught:
            self.identity.exact_single_line(
                Path("/admin/file"),
                label="the admin file",
                file_reader=lambda: (
                    lambda path, *, label: FailingData()
                ),
                decode_error_type=broken_decode_error_type,
                error_type=blocked_error_type,
            )

        self.assertIs(matcher_caught.exception, matcher_failure)
        self.assertIs(matcher_caught.exception.__context__, original)
        blocked_error_type.assert_not_called()

    def test_exact_single_line_keeps_all_other_failures_outside_decode_catch(
        self,
    ) -> None:
        class SelectedDecodeError(RuntimeError):
            pass

        stages = (
            "reader-provider",
            "reader-call",
            "endswith",
            "count",
            "carriage-contains",
            "value-truth",
            "value-contains",
        )

        for stage in stages:
            with self.subTest(unwrapped_stage=stage):
                original = SelectedDecodeError(stage)

                def fail_at(observed: str) -> None:
                    if stage == observed:
                        raise original

                class DecodedValue:
                    def __bool__(value_self) -> bool:
                        fail_at("value-truth")
                        return True

                    def __contains__(
                        value_self,
                        needle: object,
                    ) -> bool:
                        self.assertEqual(needle, "\0")
                        fail_at("value-contains")
                        return False

                class EncodedValue:
                    def decode(
                        encoded_self,
                        encoding: str,
                    ) -> DecodedValue:
                        self.assertEqual(encoding, "utf-8")
                        return DecodedValue()

                class Data:
                    def endswith(data_self, suffix: bytes) -> bool:
                        self.assertEqual(suffix, b"\n")
                        fail_at("endswith")
                        return True

                    def count(data_self, needle: bytes) -> int:
                        self.assertEqual(needle, b"\n")
                        fail_at("count")
                        return 1

                    def __contains__(
                        data_self,
                        needle: bytes,
                    ) -> bool:
                        self.assertEqual(needle, b"\r")
                        fail_at("carriage-contains")
                        return False

                    def __getitem__(
                        data_self,
                        key: object,
                    ) -> EncodedValue:
                        return EncodedValue()

                def file_reader() -> object:
                    fail_at("reader-provider")

                    def read(path: object, *, label: str) -> Data:
                        fail_at("reader-call")
                        return Data()

                    return read

                decode_error_type = mock.Mock(
                    return_value=SelectedDecodeError
                )
                error_type = mock.Mock(
                    side_effect=AssertionError(
                        "translated a failure outside decoding"
                    )
                )
                with self.assertRaises(SelectedDecodeError) as caught:
                    self.identity.exact_single_line(
                        Path("/admin/file"),
                        label="the admin file",
                        file_reader=file_reader,
                        decode_error_type=decode_error_type,
                        error_type=error_type,
                    )

                self.assertIs(caught.exception, original)
                decode_error_type.assert_not_called()
                error_type.assert_not_called()

    def test_exact_single_line_invalid_path_checks_short_circuit_in_order(
        self,
    ) -> None:
        class LineError(RuntimeError):
            pass

        for rejection in ("empty", "nul"):
            with self.subTest(rejection=rejection):
                events: list[str] = []

                class DecodedValue:
                    def __bool__(value_self) -> bool:
                        events.append("value-truth")
                        return rejection != "empty"

                    def __contains__(
                        value_self,
                        needle: object,
                    ) -> bool:
                        self.assertEqual(needle, "\0")
                        events.append("value-contains")
                        return rejection == "nul"

                class EncodedValue:
                    def decode(
                        encoded_self,
                        encoding: str,
                    ) -> DecodedValue:
                        return DecodedValue()

                class Data:
                    def endswith(data_self, suffix: bytes) -> bool:
                        return True

                    def count(data_self, needle: bytes) -> int:
                        return 1

                    def __contains__(
                        data_self,
                        needle: bytes,
                    ) -> bool:
                        return False

                    def __getitem__(
                        data_self,
                        key: object,
                    ) -> EncodedValue:
                        return EncodedValue()

                def error_type() -> type[BaseException]:
                    events.append("error-provider")
                    return LineError

                decode_error_type = mock.Mock(
                    side_effect=AssertionError(
                        "resolved decode error after successful decode"
                    )
                )
                with self.assertRaises(LineError) as caught:
                    self.identity.exact_single_line(
                        Path("/admin/file"),
                        label="the admin file",
                        file_reader=lambda: (
                            lambda path, *, label: Data()
                        ),
                        decode_error_type=decode_error_type,
                        error_type=error_type,
                    )

                self.assertEqual(
                    str(caught.exception),
                    "the admin file has an invalid path",
                )
                self.assertIsNone(caught.exception.__cause__)
                self.assertEqual(
                    events,
                    (
                        ["value-truth", "error-provider"]
                        if rejection == "empty"
                        else [
                            "value-truth",
                            "value-contains",
                            "error-provider",
                        ]
                    ),
                )
                decode_error_type.assert_not_called()

        for data in (b"\n", b"a\0b\n"):
            with self.subTest(actual_bytes=data):
                with self.assertRaises(LineError) as caught:
                    self.identity.exact_single_line(
                        Path("/admin/file"),
                        label="the admin file",
                        file_reader=lambda: (
                            lambda path, *, label: data
                        ),
                        decode_error_type=lambda: UnicodeDecodeError,
                        error_type=lambda: LineError,
                    )
                self.assertEqual(
                    str(caught.exception),
                    "the admin file has an invalid path",
                )
                self.assertIsNone(caught.exception.__cause__)

    def test_exact_single_line_resolves_error_before_formatting_label(
        self,
    ) -> None:
        events: list[str] = []

        class CapturedError(RuntimeError):
            pass

        class ReboundError(RuntimeError):
            pass

        class Label:
            def __format__(
                label_self,
                format_specification: str,
            ) -> str:
                self.assertEqual(format_specification, "")
                events.append("format-label")
                error_types[0] = ReboundError
                return "the admin file"

        error_types: list[type[BaseException]] = [CapturedError]

        def error_type() -> type[BaseException]:
            events.append("error-provider")
            return error_types[0]

        with self.assertRaises(CapturedError) as caught:
            self.identity.exact_single_line(
                Path("/admin/file"),
                label=Label(),
                file_reader=lambda: (
                    lambda path, *, label: b"missing-newline"
                ),
                decode_error_type=mock.Mock(
                    side_effect=AssertionError("decoded malformed input")
                ),
                error_type=error_type,
            )

        self.assertEqual(
            str(caught.exception),
            "the admin file does not contain one exact line",
        )
        self.assertEqual(events, ["error-provider", "format-label"])
        self.assertIs(error_types[0], ReboundError)

    def test_engine_exact_single_line_wrapper_forwards_lazy_globals(
        self,
    ) -> None:
        class InitialDecodeError(RuntimeError):
            pass

        class ReboundDecodeError(RuntimeError):
            pass

        class InitialLineError(RuntimeError):
            pass

        class ReboundLineError(RuntimeError):
            pass

        path = Path("/admin/file")
        initial_reader = mock.Mock(name="initial-reader")
        rebound_reader = mock.Mock(name="rebound-reader")
        sentinel = object()

        def exact_single_line(
            observed_path: object,
            **dependencies: object,
        ) -> object:
            self.assertIs(observed_path, path)
            self.assertEqual(
                tuple(dependencies),
                (
                    "label",
                    "file_reader",
                    "decode_error_type",
                    "error_type",
                ),
            )
            self.assertEqual(dependencies["label"], "the admin file")
            self.engine.safe_regular_file_bytes = rebound_reader
            self.assertIs(
                dependencies["file_reader"](),
                rebound_reader,
            )
            self.engine.UnicodeDecodeError = ReboundDecodeError
            self.assertIs(
                dependencies["decode_error_type"](),
                ReboundDecodeError,
            )
            self.engine.LauncherError = ReboundLineError
            self.assertIs(
                dependencies["error_type"](),
                ReboundLineError,
            )
            return sentinel

        with (
            mock.patch.object(
                self.engine,
                "_exact_single_line",
                side_effect=exact_single_line,
            ) as kernel,
            mock.patch.object(
                self.engine,
                "safe_regular_file_bytes",
                initial_reader,
            ),
            mock.patch.object(
                self.engine,
                "UnicodeDecodeError",
                InitialDecodeError,
                create=True,
            ),
            mock.patch.object(
                self.engine,
                "LauncherError",
                InitialLineError,
            ),
        ):
            observed = self.engine.exact_single_line(
                path,
                label="the admin file",
            )

        self.assertIs(observed, sentinel)
        kernel.assert_called_once()
        initial_reader.assert_not_called()
        rebound_reader.assert_not_called()

    def test_engine_real_exact_single_line_kernel_observes_rebound_errors(
        self,
    ) -> None:
        class InitialDecodeError(RuntimeError):
            pass

        class ReboundDecodeError(RuntimeError):
            pass

        class InitialLineError(RuntimeError):
            pass

        class ReboundLineError(RuntimeError):
            pass

        decode_failure = ReboundDecodeError("invalid encoding")
        path = Path("/admin/file")
        reader = mock.Mock()

        class EncodedValue:
            def decode(encoded_self, encoding: str) -> None:
                self.assertEqual(encoding, "utf-8")
                raise decode_failure

        class Data:
            def endswith(data_self, suffix: bytes) -> bool:
                return True

            def count(data_self, needle: bytes) -> int:
                return 1

            def __contains__(data_self, needle: bytes) -> bool:
                return False

            def __getitem__(data_self, key: object) -> EncodedValue:
                return EncodedValue()

        def read(observed_path: object, *, label: str) -> Data:
            self.assertIs(observed_path, path)
            self.assertEqual(label, "the admin file")
            self.engine.UnicodeDecodeError = ReboundDecodeError
            self.engine.LauncherError = ReboundLineError
            return Data()

        reader.side_effect = read
        with (
            mock.patch.object(
                self.engine,
                "_exact_single_line",
                self.identity.exact_single_line,
            ),
            mock.patch.object(
                self.engine,
                "safe_regular_file_bytes",
                reader,
            ),
            mock.patch.object(
                self.engine,
                "UnicodeDecodeError",
                InitialDecodeError,
                create=True,
            ),
            mock.patch.object(
                self.engine,
                "LauncherError",
                InitialLineError,
            ),
        ):
            with self.assertRaises(ReboundLineError) as caught:
                self.engine.exact_single_line(
                    path,
                    label="the admin file",
                )

        self.assertEqual(
            str(caught.exception),
            "the admin file is not valid UTF-8",
        )
        self.assertIs(caught.exception.__cause__, decode_failure)
        reader.assert_called_once_with(path, label="the admin file")

    def test_engine_exact_single_line_matches_real_file_behavior(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "commondir"
            path.write_bytes("../..\n".encode())
            self.assertEqual(
                self.engine.exact_single_line(
                    path,
                    label="the retained worktree commondir file",
                ),
                "../..",
            )

            cases = (
                (
                    b"missing-newline",
                    "the retained worktree commondir file "
                    "does not contain one exact line",
                ),
                (
                    b"\xff\n",
                    "the retained worktree commondir file "
                    "is not valid UTF-8",
                ),
                (
                    b"\n",
                    "the retained worktree commondir file "
                    "has an invalid path",
                ),
            )
            for data, message in cases:
                with self.subTest(data=data):
                    path.write_bytes(data)
                    with self.assertRaisesRegex(
                        self.engine.LauncherError,
                        f"^{message}$",
                    ):
                        self.engine.exact_single_line(
                            path,
                            label=(
                                "the retained worktree commondir file"
                            ),
                        )

    def test_dataclass_schemas_and_constructor_surfaces_are_exact(
        self,
    ) -> None:
        for identity_type, expected_schema in self.schemas():
            with self.subTest(identity=identity_type.__name__):
                self.assertTrue(is_dataclass(identity_type))
                parameters = inspect.signature(identity_type).parameters
                signature = inspect.signature(identity_type)
                self.assertEqual(
                    tuple(parameters),
                    tuple(name for name, annotation in expected_schema),
                )
                self.assertIs(signature.return_annotation, None)
                self.assertEqual(
                    identity_type.__annotations__,
                    {
                        name: annotation.__name__
                        for name, annotation in expected_schema
                    },
                )
                resolved_types = get_type_hints(identity_type)
                self.assertEqual(
                    resolved_types,
                    dict(expected_schema),
                )
                model_fields = fields(identity_type)
                self.assertEqual(
                    tuple(field.name for field in model_fields),
                    tuple(name for name, annotation in expected_schema),
                )
                self.assertEqual(
                    tuple(resolved_types[field.name] for field in model_fields),
                    tuple(annotation for name, annotation in expected_schema),
                )
                self.assertEqual(
                    tuple(field.type for field in model_fields),
                    tuple(
                        annotation.__name__
                        for name, annotation in expected_schema
                    ),
                )
                self.assertEqual(
                    identity_type.__match_args__,
                    tuple(name for name, annotation in expected_schema),
                )

                for parameter in parameters.values():
                    self.assertIs(
                        parameter.kind,
                        inspect.Parameter.POSITIONAL_OR_KEYWORD,
                    )
                    self.assertIs(parameter.default, inspect.Parameter.empty)
                for field in model_fields:
                    self.assertIs(field.default, MISSING)
                    self.assertIs(field.default_factory, MISSING)
                    self.assertTrue(field.init)
                    self.assertTrue(field.repr)
                    self.assertTrue(field.compare)
                    self.assertIsNone(field.hash)
                    self.assertFalse(field.kw_only)
                    self.assertEqual(dict(field.metadata), {})

                settings = identity_type.__dataclass_params__
                self.assertTrue(settings.init)
                self.assertTrue(settings.repr)
                self.assertTrue(settings.eq)
                self.assertFalse(settings.order)
                self.assertFalse(settings.unsafe_hash)
                self.assertTrue(settings.frozen)
                self.assertFalse(hasattr(identity_type, "__slots__"))

                with self.assertRaises(TypeError):
                    identity_type()
                with self.assertRaises(TypeError):
                    identity_type(
                        *(object() for field in expected_schema),
                        object(),
                    )
                with self.assertRaises(TypeError):
                    identity_type(
                        **{
                            **{
                                name: object()
                                for name, annotation in expected_schema
                            },
                            "unexpected": object(),
                        }
                    )

    def test_construction_preserves_every_opaque_value_by_identity(
        self,
    ) -> None:
        for identity_type, expected_schema in self.schemas():
            with self.subTest(identity=identity_type.__name__):
                values = tuple(
                    OpaqueValue(name)
                    for name, annotation in expected_schema
                )
                positional = identity_type(*values)
                keyword = identity_type(
                    **{
                        name: value
                        for (name, annotation), value in zip(
                            expected_schema,
                            values,
                            strict=True,
                        )
                    }
                )

                for (name, annotation), value in zip(
                    expected_schema,
                    values,
                    strict=True,
                ):
                    self.assertIs(getattr(positional, name), value)
                    self.assertIs(getattr(keyword, name), value)
                self.assertEqual(positional, keyword)

                first_name = expected_schema[0][0]
                with self.assertRaises(FrozenInstanceError):
                    setattr(positional, first_name, object())
                with self.assertRaises(FrozenInstanceError):
                    delattr(positional, first_name)
                with self.assertRaises(FrozenInstanceError):
                    positional.unexpected = object()

        class HostileValue:
            def __fspath__(value_self) -> str:
                raise AssertionError("coerced a path field")

            def __bool__(value_self) -> bool:
                raise AssertionError("coerced a boolean field")

            def __int__(value_self) -> int:
                raise AssertionError("coerced an integer field")

            def __index__(value_self) -> int:
                raise AssertionError("indexed an integer field")

        for identity_type, expected_schema in self.schemas():
            with self.subTest(hostile_identity=identity_type.__name__):
                values = tuple(
                    HostileValue()
                    for name, annotation in expected_schema
                )
                observed = identity_type(*values)
                for (name, annotation), value in zip(
                    expected_schema,
                    values,
                    strict=True,
                ):
                    self.assertIs(getattr(observed, name), value)

    def test_value_semantics_hash_repr_and_positional_shape_are_exact(
        self,
    ) -> None:
        for identity_type, expected_schema in self.schemas():
            with self.subTest(identity=identity_type.__name__):
                first_values = tuple(
                    OpaqueValue(name)
                    for name, annotation in expected_schema
                )
                equal_values = tuple(
                    OpaqueValue(name)
                    for name, annotation in expected_schema
                )
                changed_values = (
                    *equal_values[:-1],
                    OpaqueValue("changed"),
                )
                first = identity_type(*first_values)
                equal = identity_type(*equal_values)
                changed = identity_type(*changed_values)

                self.assertIsNot(first, equal)
                self.assertEqual(first, equal)
                self.assertEqual(hash(first), hash(equal))
                self.assertEqual(hash(first), hash(first_values))
                self.assertNotEqual(first, changed)
                self.assertNotEqual(first, tuple(first_values))
                with self.assertRaises(TypeError):
                    first < equal

                expected_repr = (
                    f"{identity_type.__name__}("
                    + ", ".join(
                        f"{name}=<opaque:{name}>"
                        for name, annotation in expected_schema
                    )
                    + ")"
                )
                self.assertEqual(repr(first), expected_repr)
                self.assertEqual(
                    tuple(
                        getattr(first, name)
                        for name in identity_type.__match_args__
                    ),
                    first_values,
                )

                subclass = type(
                    f"Derived{identity_type.__name__}",
                    (identity_type,),
                    {},
                )
                self.assertNotEqual(first, subclass(*equal_values))

                unhashable_values = (*first_values[:-1], [])
                unhashable = identity_type(*unhashable_values)
                with self.assertRaises(TypeError):
                    hash(unhashable)

    def test_launcher_authentication_kernel_preserves_exact_success_order(
        self,
    ) -> None:
        events: list[tuple[str, object]] = []
        sentinel = object()

        class TruthValue:
            def __init__(truth_self, label: str) -> None:
                truth_self.label = label

            def __bool__(truth_self) -> bool:
                events.append(("truth", truth_self.label))
                return True

        class Metadata:
            @property
            def st_mode(metadata_self) -> object:
                events.append(("st-mode", None))
                return "opaque-mode"

            @property
            def st_dev(metadata_self) -> object:
                events.append(("st-dev", None))
                return "opaque-device"

            @property
            def st_ino(metadata_self) -> object:
                events.append(("st-ino", None))
                return "opaque-inode"

        class ResolvedPath:
            def stat(resolved_self) -> object:
                events.append(("stat", None))
                return Metadata()

        resolved = ResolvedPath()

        class InputPath:
            def is_absolute(path_self) -> object:
                events.append(("is-absolute", None))
                return TruthValue("absolute")

            def resolve(path_self, *, strict: bool) -> object:
                events.append(("resolve", strict))
                return resolved

        path = InputPath()

        def os_error_type() -> type[OSError]:
            raise AssertionError("resolved OS error type without an exception")

        def error_type() -> type[Exception]:
            raise AssertionError("resolved launcher error on success")

        def regular_file_test() -> object:
            events.append(("regular-resolver", None))

            def test(mode: object) -> object:
                events.append(("regular-test", mode))
                return TruthValue("regular")

            return test

        def access_check() -> object:
            events.append(("access-resolver", None))

            def check(candidate: object, mode: object) -> object:
                events.append(("access-check", (candidate, mode)))
                return TruthValue("executable")

            return check

        def executable_mode() -> object:
            events.append(("mode-resolver", None))
            return "opaque-executable-mode"

        def identity_factory() -> object:
            events.append(("identity-resolver", None))

            def construct(**values: object) -> object:
                events.append(("identity-constructor", values))
                return sentinel

            return construct

        observed = self.identity.authenticate_launcher(
            path,
            os_error_type=os_error_type,
            error_type=error_type,
            regular_file_test=regular_file_test,
            access_check=access_check,
            executable_mode=executable_mode,
            identity_factory=identity_factory,
        )

        self.assertIs(observed, sentinel)
        self.assertEqual(
            events,
            [
                ("is-absolute", None),
                ("truth", "absolute"),
                ("resolve", True),
                ("stat", None),
                ("regular-resolver", None),
                ("st-mode", None),
                ("regular-test", "opaque-mode"),
                ("truth", "regular"),
                ("access-resolver", None),
                ("mode-resolver", None),
                (
                    "access-check",
                    (resolved, "opaque-executable-mode"),
                ),
                ("truth", "executable"),
                ("identity-resolver", None),
                ("st-dev", None),
                ("st-ino", None),
                (
                    "identity-constructor",
                    {
                        "path": resolved,
                        "device": "opaque-device",
                        "inode": "opaque-inode",
                    },
                ),
            ],
        )

    def test_launcher_authentication_kernel_short_circuits_rejections(
        self,
    ) -> None:
        class AuthenticationError(RuntimeError):
            pass

        dependencies = {
            "os_error_type": mock.Mock(
                side_effect=AssertionError("resolved OS error type")
            ),
            "regular_file_test": mock.Mock(
                side_effect=AssertionError("resolved regular-file test")
            ),
            "access_check": mock.Mock(
                side_effect=AssertionError("resolved access check")
            ),
            "executable_mode": mock.Mock(
                side_effect=AssertionError("resolved executable mode")
            ),
            "identity_factory": mock.Mock(
                side_effect=AssertionError("resolved identity factory")
            ),
        }
        relative = mock.Mock()
        relative.is_absolute.return_value = False
        with self.assertRaisesRegex(
            AuthenticationError,
            "^the launcher entry point must be an absolute path$",
        ):
            self.identity.authenticate_launcher(
                relative,
                error_type=lambda: AuthenticationError,
                **dependencies,
            )
        relative.resolve.assert_not_called()
        for provider in dependencies.values():
            provider.assert_not_called()

        metadata = SimpleNamespace(st_mode="mode", st_dev=1, st_ino=2)
        resolved = mock.Mock()
        resolved.stat.return_value = metadata
        absolute = mock.Mock()
        absolute.is_absolute.return_value = True
        absolute.resolve.return_value = resolved
        os_error_type = mock.Mock(return_value=OSError)
        regular_predicate = mock.Mock(return_value=False)
        regular_file_test = mock.Mock(return_value=regular_predicate)
        access_check = mock.Mock(
            side_effect=AssertionError("checked access for a non-file")
        )
        executable_mode = mock.Mock(
            side_effect=AssertionError("resolved mode for a non-file")
        )
        identity_factory = mock.Mock(
            side_effect=AssertionError("constructed rejected identity")
        )
        with self.assertRaisesRegex(
            AuthenticationError,
            "^the launcher entry point is not a usable executable$",
        ):
            self.identity.authenticate_launcher(
                absolute,
                os_error_type=os_error_type,
                error_type=lambda: AuthenticationError,
                regular_file_test=regular_file_test,
                access_check=access_check,
                executable_mode=executable_mode,
                identity_factory=identity_factory,
            )
        regular_file_test.assert_called_once_with()
        regular_predicate.assert_called_once_with("mode")
        access_check.assert_not_called()
        executable_mode.assert_not_called()
        identity_factory.assert_not_called()
        os_error_type.assert_not_called()

        access_predicate = mock.Mock(return_value=False)
        access_check = mock.Mock(return_value=access_predicate)
        executable_mode = mock.Mock(return_value="execute")
        identity_factory = mock.Mock(
            side_effect=AssertionError("constructed nonexecutable identity")
        )
        with self.assertRaisesRegex(
            AuthenticationError,
            "^the launcher entry point is not a usable executable$",
        ):
            self.identity.authenticate_launcher(
                absolute,
                os_error_type=os_error_type,
                error_type=lambda: AuthenticationError,
                regular_file_test=lambda: (
                    lambda mode: True
                ),
                access_check=access_check,
                executable_mode=executable_mode,
                identity_factory=identity_factory,
            )
        access_check.assert_called_once_with()
        executable_mode.assert_called_once_with()
        access_predicate.assert_called_once_with(resolved, "execute")
        identity_factory.assert_not_called()
        os_error_type.assert_not_called()

    def test_launcher_authentication_kernel_chains_only_lookup_os_errors(
        self,
    ) -> None:
        class ExpectedOsError(OSError):
            pass

        class AuthenticationError(RuntimeError):
            pass

        for stage in (
            "resolve-attribute",
            "resolve-call",
            "stat-attribute",
            "stat-call",
        ):
            with self.subTest(wrapped_stage=stage):
                original = ExpectedOsError(f"{stage} failed")
                events: list[str] = []

                class Resolved:
                    @property
                    def stat(resolved_self) -> object:
                        events.append("stat-attribute")
                        if stage == "stat-attribute":
                            raise original

                        def inspect() -> object:
                            events.append("stat-call")
                            if stage == "stat-call":
                                raise original
                            raise AssertionError(
                                "continued after expected lookup failure"
                            )

                        return inspect

                class InputPath:
                    def is_absolute(path_self) -> bool:
                        return True

                    @property
                    def resolve(path_self) -> object:
                        events.append("resolve-attribute")
                        if stage == "resolve-attribute":
                            raise original

                        def canonicalize(*, strict: bool) -> object:
                            events.append("resolve-call")
                            self.assertTrue(strict)
                            if stage == "resolve-call":
                                raise original
                            return Resolved()

                        return canonicalize

                os_error_type = mock.Mock(
                    return_value=ExpectedOsError
                )
                error_type = mock.Mock(
                    return_value=AuthenticationError
                )
                regular_file_test = mock.Mock(
                    side_effect=AssertionError(
                        "validated after path lookup failed"
                    )
                )
                identity_factory = mock.Mock(
                    side_effect=AssertionError(
                        "constructed after path lookup failed"
                    )
                )

                with self.assertRaises(AuthenticationError) as raised:
                    self.identity.authenticate_launcher(
                        InputPath(),
                        os_error_type=os_error_type,
                        error_type=error_type,
                        regular_file_test=regular_file_test,
                        access_check=mock.Mock(),
                        executable_mode=mock.Mock(),
                        identity_factory=identity_factory,
                    )

                self.assertEqual(
                    str(raised.exception),
                    "cannot authenticate the launcher entry point",
                )
                self.assertIs(raised.exception.__cause__, original)
                self.assertIs(raised.exception.__context__, original)
                self.assertTrue(
                    raised.exception.__suppress_context__
                )
                os_error_type.assert_called_once_with()
                error_type.assert_called_once_with()
                regular_file_test.assert_not_called()
                identity_factory.assert_not_called()
                expected_events = {
                    "resolve-attribute": ["resolve-attribute"],
                    "resolve-call": [
                        "resolve-attribute",
                        "resolve-call",
                    ],
                    "stat-attribute": [
                        "resolve-attribute",
                        "resolve-call",
                        "stat-attribute",
                    ],
                    "stat-call": [
                        "resolve-attribute",
                        "resolve-call",
                        "stat-attribute",
                        "stat-call",
                    ],
                }
                self.assertEqual(events, expected_events[stage])

        class UnexpectedFailure(RuntimeError):
            pass

        for stage in ("resolve", "stat"):
            with self.subTest(unmatched_stage=stage):
                original = UnexpectedFailure(f"{stage} failed")
                path = mock.Mock()
                path.is_absolute.return_value = True
                resolved = mock.Mock()
                if stage == "resolve":
                    path.resolve.side_effect = original
                else:
                    path.resolve.return_value = resolved
                    resolved.stat.side_effect = original
                os_error_type = mock.Mock(return_value=ExpectedOsError)
                error_type = mock.Mock(
                    side_effect=AssertionError(
                        "wrapped a non-OS lookup failure"
                    )
                )

                with self.assertRaises(UnexpectedFailure) as raised:
                    self.identity.authenticate_launcher(
                        path,
                        os_error_type=os_error_type,
                        error_type=error_type,
                        regular_file_test=mock.Mock(),
                        access_check=mock.Mock(),
                        executable_mode=mock.Mock(),
                        identity_factory=mock.Mock(),
                    )

                self.assertIs(raised.exception, original)
                os_error_type.assert_called_once_with()
                error_type.assert_not_called()

    def test_launcher_authentication_kernel_keeps_other_failures_outside_catch(
        self,
    ) -> None:
        stages = (
            "is-absolute",
            "absolute-truth",
            "st-mode",
            "regular-resolver",
            "regular-call",
            "regular-truth",
            "access-resolver",
            "mode-resolver",
            "access-call",
            "access-truth",
            "identity-resolver",
            "st-dev",
            "st-ino",
            "identity-call",
        )
        for stage in stages:
            with self.subTest(stage=stage):
                failure = OSError(f"{stage} failed")

                class ExplodingTruth:
                    def __bool__(truth_self) -> bool:
                        raise failure

                class Metadata:
                    @property
                    def st_mode(metadata_self) -> object:
                        if stage == "st-mode":
                            raise failure
                        return "mode"

                    @property
                    def st_dev(metadata_self) -> object:
                        if stage == "st-dev":
                            raise failure
                        return "device"

                    @property
                    def st_ino(metadata_self) -> object:
                        if stage == "st-ino":
                            raise failure
                        return "inode"

                class Resolved:
                    def stat(resolved_self) -> object:
                        return Metadata()

                class InputPath:
                    def is_absolute(path_self) -> object:
                        if stage == "is-absolute":
                            raise failure
                        if stage == "absolute-truth":
                            return ExplodingTruth()
                        return True

                    def resolve(
                        path_self,
                        *,
                        strict: bool,
                    ) -> object:
                        return Resolved()

                def regular_file_test() -> object:
                    if stage == "regular-resolver":
                        raise failure

                    def test(mode: object) -> object:
                        if stage == "regular-call":
                            raise failure
                        if stage == "regular-truth":
                            return ExplodingTruth()
                        return True

                    return test

                def access_check() -> object:
                    if stage == "access-resolver":
                        raise failure

                    def check(
                        path: object,
                        mode: object,
                    ) -> object:
                        if stage == "access-call":
                            raise failure
                        if stage == "access-truth":
                            return ExplodingTruth()
                        return True

                    return check

                def executable_mode() -> object:
                    if stage == "mode-resolver":
                        raise failure
                    return "execute"

                def identity_factory() -> object:
                    if stage == "identity-resolver":
                        raise failure

                    def construct(**values: object) -> object:
                        if stage == "identity-call":
                            raise failure
                        return values

                    return construct

                os_error_type = mock.Mock(
                    side_effect=AssertionError(
                        "caught an error outside path lookup"
                    )
                )
                error_type = mock.Mock(
                    side_effect=AssertionError(
                        "translated an error outside path lookup"
                    )
                )
                with self.assertRaises(OSError) as raised:
                    self.identity.authenticate_launcher(
                        InputPath(),
                        os_error_type=os_error_type,
                        error_type=error_type,
                        regular_file_test=regular_file_test,
                        access_check=access_check,
                        executable_mode=executable_mode,
                        identity_factory=identity_factory,
                    )

                self.assertIs(raised.exception, failure)
                os_error_type.assert_not_called()
                error_type.assert_not_called()

    def test_engine_launcher_wrapper_resolves_every_global_lazily(
        self,
    ) -> None:
        path = object()
        sentinel = object()
        events: list[tuple[str, object]] = []

        class InitialOsError(OSError):
            pass

        class ReboundOsError(OSError):
            pass

        class InitialLauncherError(RuntimeError):
            pass

        class ReboundLauncherError(RuntimeError):
            pass

        initial_identity = object()
        rebound_identity = object()

        class InitialStatApi:
            @property
            def S_ISREG(api_self) -> object:
                raise AssertionError("resolved regular test eagerly")

        class ReboundStatApi:
            @property
            def S_ISREG(api_self) -> object:
                events.append(("regular-test", None))
                return "rebound-regular-test"

        class InitialOsApi:
            @property
            def access(api_self) -> object:
                raise AssertionError("resolved access eagerly")

            @property
            def X_OK(api_self) -> object:
                raise AssertionError("resolved executable mode eagerly")

        class ModeOsApi:
            @property
            def X_OK(api_self) -> object:
                events.append(("executable-mode", None))
                return "rebound-executable-mode"

        class AccessOsApi:
            @property
            def access(api_self) -> object:
                events.append(("access-check", None))
                self.engine.os = ModeOsApi()
                return "rebound-access-check"

        def kernel(observed_path: object, **providers: object) -> object:
            events.append(("kernel", tuple(providers)))
            self.assertIs(observed_path, path)

            self.engine.OSError = ReboundOsError
            self.assertIs(providers["os_error_type"](), ReboundOsError)
            events.append(("os-error-type", None))

            self.engine.LauncherError = ReboundLauncherError
            self.assertIs(
                providers["error_type"](),
                ReboundLauncherError,
            )
            events.append(("launcher-error-type", None))

            self.engine.stat = ReboundStatApi()
            self.assertEqual(
                providers["regular_file_test"](),
                "rebound-regular-test",
            )

            self.engine.os = AccessOsApi()
            self.assertEqual(
                providers["access_check"](),
                "rebound-access-check",
            )
            self.assertEqual(
                providers["executable_mode"](),
                "rebound-executable-mode",
            )

            self.engine.LauncherIdentity = rebound_identity
            self.assertIs(
                providers["identity_factory"](),
                rebound_identity,
            )
            events.append(("identity-factory", None))
            return sentinel

        with (
            mock.patch.object(
                self.engine,
                "_authenticate_launcher",
                side_effect=kernel,
                create=True,
            ),
            mock.patch.object(
                self.engine,
                "OSError",
                InitialOsError,
                create=True,
            ),
            mock.patch.object(
                self.engine,
                "LauncherError",
                InitialLauncherError,
            ),
            mock.patch.object(
                self.engine,
                "stat",
                InitialStatApi(),
            ),
            mock.patch.object(
                self.engine,
                "os",
                InitialOsApi(),
            ),
            mock.patch.object(
                self.engine,
                "LauncherIdentity",
                initial_identity,
            ),
        ):
            observed = self.engine.authenticate_launcher(path)

        self.assertIs(observed, sentinel)
        self.assertEqual(
            events,
            [
                (
                    "kernel",
                    (
                        "os_error_type",
                        "error_type",
                        "regular_file_test",
                        "access_check",
                        "executable_mode",
                        "identity_factory",
                    ),
                ),
                ("os-error-type", None),
                ("launcher-error-type", None),
                ("regular-test", None),
                ("access-check", None),
                ("executable-mode", None),
                ("identity-factory", None),
            ],
        )

    def test_engine_and_real_kernel_rebind_error_types_at_failure(
        self,
    ) -> None:
        events: list[str] = []

        class InitialOsError(OSError):
            pass

        class ReboundOsError(OSError):
            pass

        class InitialLauncherError(RuntimeError):
            pass

        class ReboundLauncherError(RuntimeError):
            pass

        failure = ReboundOsError("lookup failed")

        class InputPath:
            def is_absolute(path_self) -> bool:
                events.append("is-absolute")
                return True

            def resolve(path_self, *, strict: bool) -> object:
                events.append("resolve")
                self.assertTrue(strict)
                self.engine.OSError = ReboundOsError
                self.engine.LauncherError = ReboundLauncherError
                raise failure

        with (
            mock.patch.object(
                self.engine,
                "OSError",
                InitialOsError,
                create=True,
            ),
            mock.patch.object(
                self.engine,
                "LauncherError",
                InitialLauncherError,
            ),
        ):
            with self.assertRaises(ReboundLauncherError) as raised:
                self.engine.authenticate_launcher(InputPath())

        self.assertEqual(events, ["is-absolute", "resolve"])
        self.assertEqual(
            str(raised.exception),
            "cannot authenticate the launcher entry point",
        )
        self.assertIs(raised.exception.__cause__, failure)
        self.assertIs(raised.exception.__context__, failure)

    def test_engine_and_real_kernel_rebind_validation_globals_in_order(
        self,
    ) -> None:
        events: list[tuple[str, object]] = []

        class InitialLauncherError(RuntimeError):
            pass

        class ReboundLauncherError(RuntimeError):
            def __init__(
                error_self,
                message: str,
            ) -> None:
                events.append(("launcher-error", message))
                super().__init__(message)

        class InitialStatApi:
            @property
            def S_ISREG(api_self) -> object:
                raise AssertionError("captured regular-file test eagerly")

        class InitialOsApi:
            @property
            def access(api_self) -> object:
                raise AssertionError("captured access check eagerly")

            @property
            def X_OK(api_self) -> object:
                raise AssertionError("captured executable mode eagerly")

        class ModeOsApi:
            @property
            def X_OK(api_self) -> object:
                events.append(("mode-lookup", None))
                return "current-executable-mode"

        class AccessOsApi:
            @property
            def access(api_self) -> object:
                events.append(("access-lookup", None))
                self.engine.os = ModeOsApi()

                def access(
                    candidate: object,
                    mode: object,
                ) -> bool:
                    events.append(("access-call", (candidate, mode)))
                    self.engine.LauncherError = ReboundLauncherError
                    return False

                return access

        class ReboundStatApi:
            @property
            def S_ISREG(api_self) -> object:
                events.append(("regular-lookup", None))

                def is_regular(mode: object) -> bool:
                    events.append(("regular-call", mode))
                    self.engine.os = AccessOsApi()
                    return True

                return is_regular

        class Metadata:
            @property
            def st_mode(metadata_self) -> object:
                events.append(("st-mode", None))
                return "current-mode"

        class Resolved:
            def stat(resolved_self) -> object:
                events.append(("stat", None))
                self.engine.stat = ReboundStatApi()
                return Metadata()

        resolved = Resolved()

        class InputPath:
            def is_absolute(path_self) -> bool:
                events.append(("is-absolute", None))
                return True

            def resolve(path_self, *, strict: bool) -> object:
                events.append(("resolve", strict))
                return resolved

        with (
            mock.patch.object(
                self.engine,
                "LauncherError",
                InitialLauncherError,
            ),
            mock.patch.object(
                self.engine,
                "stat",
                InitialStatApi(),
            ),
            mock.patch.object(
                self.engine,
                "os",
                InitialOsApi(),
            ),
        ):
            with self.assertRaises(ReboundLauncherError) as raised:
                self.engine.authenticate_launcher(InputPath())

        self.assertEqual(
            str(raised.exception),
            "the launcher entry point is not a usable executable",
        )
        self.assertEqual(
            events,
            [
                ("is-absolute", None),
                ("resolve", True),
                ("stat", None),
                ("regular-lookup", None),
                ("st-mode", None),
                ("regular-call", "current-mode"),
                ("access-lookup", None),
                ("mode-lookup", None),
                (
                    "access-call",
                    (resolved, "current-executable-mode"),
                ),
                (
                    "launcher-error",
                    "the launcher entry point is not a usable executable",
                ),
            ],
        )

    def test_authenticate_launcher_resolves_rebound_constructor_last(
        self,
    ) -> None:
        sentinel = object()
        rebound_factory = mock.Mock(return_value=sentinel)
        initial_factory = mock.Mock(
            side_effect=AssertionError("captured launcher identity too early")
        )
        real_access = os.access

        with tempfile.TemporaryDirectory() as directory:
            launcher = Path(directory) / "launcher"
            launcher.touch(mode=0o700)
            launcher.chmod(0o700)
            resolved = launcher.resolve(strict=True)
            metadata = resolved.stat()
            access_events: list[tuple[Path, int]] = []

            def validating_access(path: Path, mode: int) -> bool:
                access_events.append((path, mode))
                self.assertTrue(real_access(path, mode))
                self.engine.LauncherIdentity = rebound_factory
                return True

            with (
                mock.patch.object(
                    self.engine,
                    "LauncherIdentity",
                    initial_factory,
                ),
                mock.patch.object(
                    self.engine.os,
                    "access",
                    side_effect=validating_access,
                ),
            ):
                observed = self.engine.authenticate_launcher(launcher)

        self.assertIs(observed, sentinel)
        self.assertEqual(access_events, [(resolved, os.X_OK)])
        initial_factory.assert_not_called()
        rebound_factory.assert_called_once_with(
            path=resolved,
            device=metadata.st_dev,
            inode=metadata.st_ino,
        )

    def test_launcher_authentication_matches_real_filesystem_behavior(
        self,
    ) -> None:
        class AuthenticationError(RuntimeError):
            pass

        def authenticate(path: Path) -> object:
            return self.identity.authenticate_launcher(
                path,
                os_error_type=lambda: OSError,
                error_type=lambda: AuthenticationError,
                regular_file_test=lambda: stat.S_ISREG,
                access_check=lambda: os.access,
                executable_mode=lambda: os.X_OK,
                identity_factory=lambda: (
                    self.identity.LauncherIdentity
                ),
            )

        executable = Path(sys.executable).resolve(strict=True)
        metadata = executable.stat()
        expected = self.identity.LauncherIdentity(
            path=executable,
            device=metadata.st_dev,
            inode=metadata.st_ino,
        )
        self.assertEqual(authenticate(executable), expected)
        self.assertEqual(
            self.engine.authenticate_launcher(executable),
            expected,
        )

        with tempfile.TemporaryDirectory() as directory:
            temporary = Path(directory).resolve(strict=True)
            with self.assertRaisesRegex(
                AuthenticationError,
                "^the launcher entry point is not a usable executable$",
            ):
                authenticate(temporary)

            missing = temporary / "missing-launcher"
            with self.assertRaises(AuthenticationError) as raised:
                authenticate(missing)
            self.assertEqual(
                str(raised.exception),
                "cannot authenticate the launcher entry point",
            )
            self.assertIsInstance(
                raised.exception.__cause__,
                FileNotFoundError,
            )

            nonexecutable = temporary / "nonexecutable"
            nonexecutable.write_text("#!/bin/sh\n", encoding="utf-8")
            nonexecutable.chmod(stat.S_IRUSR | stat.S_IWUSR)
            if not os.access(nonexecutable, os.X_OK):
                with self.assertRaisesRegex(
                    AuthenticationError,
                    "^the launcher entry point is not a usable executable$",
                ):
                    authenticate(nonexecutable)

            link = temporary / "launcher-link"
            try:
                link.symlink_to(executable)
            except (NotImplementedError, OSError):
                pass
            else:
                self.assertEqual(authenticate(link), expected)

        relative = Path("relative-launcher")
        with self.assertRaises(AuthenticationError) as raised:
            authenticate(relative)
        self.assertEqual(
            str(raised.exception),
            "the launcher entry point must be an absolute path",
        )
        self.assertIsNone(raised.exception.__cause__)

    def test_linked_worktree_authentication_resolves_rebound_constructor_last(
        self,
    ) -> None:
        canonical_worktree = Path("/state/worktrees/run")
        git_file = canonical_worktree / ".git"
        common_git_dir = Path("/repository/.git")
        worktrees_admin = common_git_dir / "worktrees"
        git_dir = worktrees_admin / "run"
        sentinel = object()
        events: list[tuple[str, object]] = []
        rebound_factory = mock.Mock(return_value=sentinel)
        initial_factory = mock.Mock(
            side_effect=AssertionError(
                "captured linked-worktree identity too early"
            )
        )

        class RebindingBacklink:
            def __ne__(backlink_self, other: object) -> bool:
                events.append(("validate-backlink", other))
                self.engine.LinkedWorktreeIdentity = rebound_factory
                return False

        backlink = RebindingBacklink()
        real_directory_values = {
            "the retained worktree": canonical_worktree,
            "the retained worktree Git admin directory": git_dir,
            "the retained worktree common Git directory": common_git_dir,
            "the recorded common Git directory": common_git_dir,
            "the common linked-worktree administration directory": (
                worktrees_admin
            ),
        }

        def exact_real_directory(path: Path, *, label: str) -> Path:
            events.append(("real-directory", (path, label)))
            return real_directory_values[label]

        line_values = {
            git_file: f"gitdir: {git_dir}",
            git_dir / "commondir": str(common_git_dir),
            git_dir / "gitdir": str(git_file),
        }

        def exact_single_line(path: Path, *, label: str) -> str:
            events.append(("single-line", (path, label)))
            return line_values[path]

        pointer_values = iter((git_dir, common_git_dir, backlink))

        def exact_pointer_path(
            raw_value: str,
            *,
            relative_to: Path,
            label: str,
        ) -> object:
            events.append(
                ("pointer", (raw_value, relative_to, label))
            )
            return next(pointer_values)

        identity_registry: dict[Path, object] = {}
        owner_registry: dict[Path, Path] = {}
        with (
            mock.patch.object(
                self.engine,
                "LinkedWorktreeIdentity",
                initial_factory,
            ),
            mock.patch.object(
                self.engine,
                "exact_real_directory",
                side_effect=exact_real_directory,
            ),
            mock.patch.object(
                self.engine,
                "exact_single_line",
                side_effect=exact_single_line,
            ),
            mock.patch.object(
                self.engine,
                "exact_pointer_path",
                side_effect=exact_pointer_path,
            ),
            mock.patch.object(
                self.engine,
                "_LINKED_WORKTREE_IDENTITIES",
                identity_registry,
            ),
            mock.patch.object(
                self.engine,
                "_LINKED_ADMIN_OWNERS",
                owner_registry,
            ),
        ):
            observed = self.engine.authenticate_linked_worktree_path(
                canonical_worktree,
                expected_common_git_dir=common_git_dir,
            )

        self.assertIs(observed, sentinel)
        initial_factory.assert_not_called()
        rebound_factory.assert_called_once_with(
            worktree=canonical_worktree,
            git_file=git_file,
            git_dir=git_dir,
            common_git_dir=common_git_dir,
        )
        self.assertIs(identity_registry[canonical_worktree], sentinel)
        self.assertEqual(owner_registry[git_dir], canonical_worktree)
        self.assertEqual(
            events[-1],
            ("validate-backlink", git_file),
        )
        self.assertEqual(
            tuple(
                event[1][1]
                for event in events
                if event[0] == "real-directory"
            ),
            (
                "the retained worktree",
                "the retained worktree Git admin directory",
                "the retained worktree common Git directory",
                "the recorded common Git directory",
                "the common linked-worktree administration directory",
            ),
        )
        self.assertEqual(
            sum(event[0] == "single-line" for event in events),
            3,
        )
        self.assertEqual(
            [
                event[1]
                for event in events
                if event[0] == "single-line"
            ],
            [
                (
                    git_file,
                    "the retained worktree .git file",
                ),
                (
                    git_dir / "commondir",
                    "the retained worktree commondir file",
                ),
                (
                    git_dir / "gitdir",
                    "the retained worktree gitdir backlink",
                ),
            ],
        )
        self.assertEqual(
            sum(event[0] == "pointer" for event in events),
            3,
        )

    def test_discover_repository_resolves_rebound_constructor_after_boundary(
        self,
    ) -> None:
        start = Path("/repository/subdirectory")
        root = Path("/repository")
        git_dir = Path("/repository/.git")
        common_git_dir = Path("/repository/.git")
        sentinel = object()
        events: list[tuple[str, object]] = []
        initial_factory = mock.Mock(
            side_effect=AssertionError("captured repository type too early")
        )

        def rebound_factory(**values: object) -> object:
            events.append(("repository-factory", values))
            return sentinel

        class ResolvedState:
            def __eq__(state_self, other: object) -> bool:
                events.append(("state-equality", other))
                return False

            @property
            def parents(state_self) -> tuple[Path, ...]:
                events.append(("state-parents", None))
                self.engine.Repository = rebound_factory
                return (Path("/marshal-state"), Path("/"))

        resolved_state = ResolvedState()

        class StateCandidate:
            def resolve(candidate_self) -> object:
                events.append(("state-resolve", None))
                return resolved_state

        class StateBase:
            def __truediv__(base_self, component: str) -> object:
                events.append(("state-component", component))
                return StateCandidate()

        git_results = iter(
            (
                SimpleNamespace(returncode=0, stdout="true\n"),
                SimpleNamespace(returncode=0, stdout=f"{root}\n"),
            )
        )
        with (
            mock.patch.object(
                self.engine,
                "Repository",
                initial_factory,
            ),
            mock.patch.object(
                self.engine,
                "git",
                side_effect=lambda *args, **kwargs: next(git_results),
            ),
            mock.patch.object(
                self.engine,
                "absolute_git_path",
                side_effect=(git_dir, common_git_dir),
            ),
            mock.patch.object(
                self.engine,
                "state_base",
                return_value=StateBase(),
            ),
            mock.patch.object(
                self.engine,
                "repository_slug",
                return_value="project",
            ),
        ):
            observed = self.engine.discover_repository(start)

        self.assertIs(observed, sentinel)
        initial_factory.assert_not_called()
        factory_events = [
            event for event in events if event[0] == "repository-factory"
        ]
        self.assertEqual(
            factory_events,
            [
                (
                    "repository-factory",
                    {
                        "root": root,
                        "git_dir": git_dir,
                        "common_git_dir": common_git_dir,
                        "relative_cwd": Path("subdirectory"),
                        "linked_worktree": False,
                        "state_root": resolved_state,
                    },
                )
            ],
        )
        self.assertEqual(
            tuple(event[0] for event in events[-4:]),
            (
                "state-resolve",
                "state-equality",
                "state-parents",
                "repository-factory",
            ),
        )

    def test_repository_discovery_kernel_and_wrapper_signatures(self) -> None:
        self.assertEqual(
            str(inspect.signature(self.identity.discover_repository)),
            "(cwd: 'Path | None', *, path_factory: "
            "'Callable[[], type[Path]]', git_call: "
            "'Callable[[], Callable[..., object]]', absolute_git_path: "
            "'Callable[[], Callable[[Path, str], Path]]', digest_factory: "
            "'Callable[[], Callable[[bytes], object]]', filesystem_encode: "
            "'Callable[[], Callable[[object], bytes]]', state_base: "
            "'Callable[[], Callable[[], Path]]', repository_slug: "
            "'Callable[[], Callable[[Path], str]]', state_environment: "
            "'Callable[[], str]', repository_factory: "
            "'Callable[[], Callable[..., Repository]]', value_error_type: "
            "'Callable[[], type[BaseException]]', error_type: "
            "'Callable[[], type[BaseException]]') -> 'Repository'",
        )
        self.assertEqual(
            str(inspect.signature(self.engine.discover_repository)),
            "(cwd: 'Path | None' = None) -> 'Repository'",
        )
        self.assertIs(
            self.engine.Repository,
            self.identity.Repository,
        )

    def test_path_entry_kernel_and_wrapper_signatures(self) -> None:
        self.assertEqual(
            str(inspect.signature(self.identity.path_entry_exists)),
            "(path: 'Path', *, label: 'str', file_not_found_error_type: "
            "'Callable[[], type[BaseException]]', os_error_type: "
            "'Callable[[], type[BaseException]]', error_type: "
            "'Callable[[], type[BaseException]]') -> 'bool'",
        )
        self.assertEqual(
            str(inspect.signature(self.engine.path_entry_exists)),
            "(path: 'Path', *, label: 'str') -> 'bool'",
        )

    def test_path_entry_kernel_preserves_exception_partition(self) -> None:
        class MissingError(OSError):
            pass

        class OtherError(OSError):
            pass

        class PolicyError(RuntimeError):
            pass

        for failure, expected in (
            (None, True),
            (MissingError("missing"), False),
        ):
            with self.subTest(failure=failure):
                path = mock.Mock()
                if failure is not None:
                    path.lstat.side_effect = failure
                self.assertIs(
                    self.identity.path_entry_exists(
                        path,
                        label="the path",
                        file_not_found_error_type=lambda: MissingError,
                        os_error_type=lambda: OSError,
                        error_type=lambda: PolicyError,
                    ),
                    expected,
                )

        failure = OtherError("blocked")
        with self.assertRaisesRegex(
            PolicyError,
            "^cannot inspect the path$",
        ) as raised:
            self.identity.path_entry_exists(
                mock.Mock(lstat=mock.Mock(side_effect=failure)),
                label="the path",
                file_not_found_error_type=lambda: MissingError,
                os_error_type=lambda: OSError,
                error_type=lambda: PolicyError,
            )
        self.assertIs(raised.exception.__cause__, failure)

    def test_engine_path_entry_wrapper_supplies_lazy_errors(self) -> None:
        sentinel = object()
        captured: dict[str, object] = {}

        def kernel(path: object, **dependencies: object) -> object:
            captured["path"] = path
            captured.update(dependencies)
            return sentinel

        path = Path("/retained/worktree")
        with mock.patch.object(
            self.engine,
            "_path_entry_exists",
            side_effect=kernel,
        ):
            observed = self.engine.path_entry_exists(
                path,
                label="the retirement worktree path",
            )

        self.assertIs(observed, sentinel)
        self.assertIs(captured["path"], path)
        self.assertEqual(
            captured["label"],
            "the retirement worktree path",
        )
        self.assertIs(
            captured["file_not_found_error_type"](),
            FileNotFoundError,
        )
        self.assertIs(captured["os_error_type"](), OSError)
        self.assertIs(
            captured["error_type"](),
            self.engine.LauncherError,
        )

    def test_repository_discovery_kernel_preserves_success_values(self) -> None:
        start = Path("/repository/subdirectory")
        root = Path("/repository")
        git_dir = Path("/repository/.git/worktrees/run")
        common_git_dir = Path("/repository/.git")
        state_root = Path("/state/project-0123456789ab")
        events: list[tuple[str, object]] = []
        git_results = iter(
            (
                SimpleNamespace(returncode=0, stdout="true\n"),
                SimpleNamespace(returncode=0, stdout=f"{root}\n"),
            )
        )
        absolute_paths = iter((git_dir, common_git_dir))
        sentinel = object()

        class Digest:
            def hexdigest(digest_self) -> str:
                events.append(("hexdigest", None))
                return "0123456789abcdef"

        def git_call(*args: object, **kwargs: object) -> object:
            events.append(("git", (args, kwargs)))
            return next(git_results)

        def absolute_path(cwd: Path, selector: str) -> Path:
            events.append(("absolute-git-path", (cwd, selector)))
            return next(absolute_paths)

        def repository_factory(**values: object) -> object:
            events.append(("repository-factory", values))
            return sentinel

        observed = self.identity.discover_repository(
            start,
            path_factory=lambda: Path,
            git_call=lambda: git_call,
            absolute_git_path=lambda: absolute_path,
            digest_factory=lambda: (
                lambda value: (
                    events.append(("digest", value)),
                    Digest(),
                )[1]
            ),
            filesystem_encode=lambda: (
                lambda value: (
                    events.append(("fsencode", value)),
                    b"common-git-directory",
                )[1]
            ),
            state_base=lambda: lambda: Path("/state"),
            repository_slug=lambda: lambda value: "project",
            state_environment=lambda: "STATE_HOME",
            repository_factory=lambda: repository_factory,
            value_error_type=lambda: ValueError,
            error_type=lambda: RuntimeError,
        )

        self.assertIs(observed, sentinel)
        self.assertEqual(
            events[-1],
            (
                "repository-factory",
                {
                    "root": root,
                    "git_dir": git_dir,
                    "common_git_dir": common_git_dir,
                    "relative_cwd": Path("subdirectory"),
                    "linked_worktree": True,
                    "state_root": state_root,
                },
            ),
        )
        self.assertLess(
            events.index(("fsencode", common_git_dir)),
            events.index(("hexdigest", None)),
        )

    def test_engine_repository_discovery_wrapper_supplies_lazy_globals(
        self,
    ) -> None:
        sentinel = object()
        captured: dict[str, object] = {}

        def kernel(cwd: object, **dependencies: object) -> object:
            captured["cwd"] = cwd
            captured.update(dependencies)
            return sentinel

        profile = SimpleNamespace(state_environment="STATE_HOME")
        with (
            mock.patch.object(
                self.engine,
                "_discover_repository",
                side_effect=kernel,
            ),
            mock.patch.object(
                self.engine,
                "active_profile",
                return_value=profile,
            ),
        ):
            observed = self.engine.discover_repository(Path("/start"))
            state_environment = captured["state_environment"]()

        self.assertIs(observed, sentinel)
        self.assertEqual(captured["cwd"], Path("/start"))
        expected = {
            "path_factory": self.engine.Path,
            "git_call": self.engine.git,
            "absolute_git_path": self.engine.absolute_git_path,
            "digest_factory": self.engine.hashlib.sha256,
            "filesystem_encode": self.engine.os.fsencode,
            "state_base": self.engine.state_base,
            "repository_slug": self.engine.repository_slug,
            "repository_factory": self.engine.Repository,
            "value_error_type": ValueError,
            "error_type": self.engine.LauncherError,
        }
        for name, value in expected.items():
            self.assertIs(captured[name](), value)
        self.assertEqual(
            state_environment,
            "STATE_HOME",
        )


if __name__ == "__main__":
    unittest.main()
