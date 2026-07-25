#!/usr/bin/env python3
"""Direct parity tests for the Codex adapter."""

from __future__ import annotations

import importlib
import inspect
import os
import stat
import subprocess
import sys
import tempfile
import unittest
from collections.abc import Sequence
from pathlib import Path
from types import SimpleNamespace
from unittest import mock


PACKAGE_ROOT = Path(__file__).resolve().parents[1]
SOURCE_ROOT = PACKAGE_ROOT / "src"
ENVIRONMENT_NAME = "CUSTOM_REAL_CODEX"


class CodexAdapterTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        sys.path.insert(0, str(SOURCE_ROOT))
        cls.adapter = importlib.import_module(
            "worktree_marshal.adapters.codex"
        )
        cls.engine = importlib.import_module("worktree_marshal.engine")

    @classmethod
    def tearDownClass(cls) -> None:
        try:
            sys.path.remove(str(SOURCE_ROOT))
        except ValueError:
            pass

    def select(
        self,
        *,
        launcher: object | None = None,
        profile: object | None = None,
        **overrides: object,
    ) -> object:
        dependencies = {
            "environment": lambda: {},
            "path_factory": lambda: Path,
            "executable_path": lambda: lambda: [],
            "current_directory": lambda: os.curdir,
            "os_error_type": lambda: OSError,
            "regular_file_test": lambda: stat.S_ISREG,
            "access_check": lambda: os.access,
            "executable_mode": lambda: os.X_OK,
            "error_type": lambda: RuntimeError,
        }
        dependencies.update(overrides)
        return self.adapter.select_codex_executable(
            (
                SimpleNamespace(device=-1, inode=-1)
                if launcher is None
                else launcher
            ),
            profile=(
                SimpleNamespace(
                    real_codex_environment=ENVIRONMENT_NAME
                )
                if profile is None
                else profile
            ),
            **dependencies,
        )

    def scan(
        self,
        arguments: list[str],
        start: int = 0,
        flag_options: set[str] | None = None,
        value_options: set[str] | None = None,
        **overrides: object,
    ) -> tuple[int, bool, bool]:
        dependencies = {
            "length": lambda: len,
            "error_type": lambda: RuntimeError,
        }
        dependencies.update(overrides)
        return self.adapter.scan_allowed_options(
            arguments,
            start,
            set() if flag_options is None else flag_options,
            set() if value_options is None else value_options,
            **dependencies,
        )

    def normalize(
        self,
        arguments: Sequence[str],
        **overrides: object,
    ) -> tuple[list[str], bool]:
        dependencies = {
            "list_factory": lambda: list,
            "length": lambda: len,
            "option_scanner": lambda: (
                lambda values, start, flags, options: self.scan(
                    values,
                    start,
                    flags,
                    options,
                )
            ),
            "root_flag_options": lambda: self.adapter.ROOT_FLAG_OPTIONS,
            "root_value_options": lambda: self.adapter.ROOT_VALUE_OPTIONS,
            "exec_flag_options": lambda: self.adapter.EXEC_FLAG_OPTIONS,
            "exec_value_options": lambda: self.adapter.EXEC_VALUE_OPTIONS,
            "review_flag_options": lambda: (
                self.adapter.REVIEW_FLAG_OPTIONS
            ),
            "review_value_options": lambda: (
                self.adapter.REVIEW_VALUE_OPTIONS
            ),
            "non_agent_commands": lambda: (
                self.adapter.NON_AGENT_CODEX_COMMANDS
            ),
            "reopen_hint": lambda: "make reopen RUN=<run-id>",
            "error_type": lambda: RuntimeError,
        }
        dependencies.update(overrides)
        return self.adapter.normalize_codex_arguments(
            arguments,
            **dependencies,
        )

    def build_environment(
        self,
        real_codex: Path,
        *,
        profile: object | None = None,
        **overrides: object,
    ) -> dict[str, str]:
        dependencies = {
            "sanitized_environment": lambda: lambda: {},
            "control_environments": lambda: (),
            "stringifier": lambda: str,
            "executable_path": lambda: lambda _environment: [],
            "path_separator": lambda: os.pathsep,
        }
        dependencies.update(overrides)
        return self.adapter.codex_environment(
            real_codex,
            profile=(
                SimpleNamespace(
                    real_codex_environment=ENVIRONMENT_NAME,
                )
                if profile is None
                else profile
            ),
            **dependencies,
        )

    def enrich_environment(
        self,
        environment: dict[str, str],
        *,
        profile: object | None = None,
        role: str = "worker",
        manifest: object | None = None,
    ) -> dict[str, str]:
        return self.adapter.enrich_codex_environment(
            environment,
            profile=(
                SimpleNamespace(
                    role_environment="ROLE",
                    run_id_environment="RUN_ID",
                    profile_environment="PROFILE_ID",
                    profile_id="generic-v1",
                    agent_environment="AGENT_ID",
                    manifest_agent="codex",
                )
                if profile is None
                else profile
            ),
            role=role,
            manifest=manifest,
        )

    def test_adapter_import_is_cycle_free_and_environment_neutral(self) -> None:
        script = (
            "import os, sys; "
            "before = dict(os.environ); "
            "before_cwd = os.getcwd(); "
            f"sys.path.insert(0, {str(SOURCE_ROOT)!r}); "
            "import worktree_marshal.adapters.codex; "
            "raise SystemExit("
            "dict(os.environ) != before or "
            "os.getcwd() != before_cwd or "
            "'worktree_marshal.engine' in sys.modules"
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

    def test_kernel_and_engine_wrapper_surfaces_are_exact(self) -> None:
        self.assertIs(
            self.engine._select_codex_executable,
            self.adapter.select_codex_executable,
        )
        parameters = inspect.signature(
            self.adapter.select_codex_executable
        ).parameters
        self.assertEqual(
            tuple(parameters),
            (
                "launcher",
                "profile",
                "environment",
                "path_factory",
                "executable_path",
                "current_directory",
                "os_error_type",
                "regular_file_test",
                "access_check",
                "executable_mode",
                "error_type",
            ),
        )
        self.assertIs(
            parameters["launcher"].kind,
            inspect.Parameter.POSITIONAL_OR_KEYWORD,
        )
        for name in tuple(parameters)[1:]:
            self.assertIs(
                parameters[name].kind,
                inspect.Parameter.KEYWORD_ONLY,
            )
        for parameter in parameters.values():
            self.assertIs(parameter.default, inspect.Parameter.empty)

        wrapper = inspect.signature(self.engine.resolve_real_codex).parameters
        self.assertEqual(tuple(wrapper), ("launcher",))
        self.assertIs(
            wrapper["launcher"].kind,
            inspect.Parameter.POSITIONAL_OR_KEYWORD,
        )
        self.assertIs(wrapper["launcher"].default, inspect.Parameter.empty)

    def test_override_success_preserves_exact_evaluation_order(self) -> None:
        events: list[tuple[str, object]] = []
        result = object()

        class Truth:
            def __init__(truth_self, label: str) -> None:
                truth_self.label = label

            def __bool__(truth_self) -> bool:
                events.append(("truth", truth_self.label))
                return True

        override = Truth("override")

        class Profile:
            @property
            def real_codex_environment(profile_self) -> str:
                events.append(("profile-environment", None))
                return ENVIRONMENT_NAME

        class Environment:
            def get(environment_self, name: str) -> object:
                events.append(("environment-get", name))
                return override

        class Launcher:
            @property
            def device(launcher_self) -> int:
                events.append(("launcher-device", None))
                return 30

            @property
            def inode(launcher_self) -> int:
                events.append(("launcher-inode", None))
                return 40

        class Metadata:
            @property
            def st_mode(metadata_self) -> object:
                events.append(("metadata-mode", None))
                return "mode"

            @property
            def st_dev(metadata_self) -> int:
                events.append(("metadata-device", None))
                return 10

            @property
            def st_ino(metadata_self) -> int:
                events.append(("metadata-inode", None))
                return 20

        class Candidate:
            def is_absolute(candidate_self) -> object:
                events.append(("is-absolute", None))
                return Truth("absolute")

            def stat(candidate_self) -> Metadata:
                events.append(("stat", None))
                return Metadata()

            def absolute(candidate_self) -> object:
                events.append(("absolute", None))
                return result

        candidate = Candidate()

        def environment() -> Environment:
            events.append(("environment-provider", None))
            return Environment()

        def path_factory() -> object:
            events.append(("path-provider", None))

            def make_path(value: object) -> Candidate:
                events.append(("path-call", value))
                return candidate

            return make_path

        def regular_file_test() -> object:
            events.append(("regular-provider", None))

            def is_regular(mode: object) -> object:
                events.append(("regular-call", mode))
                return Truth("regular")

            return is_regular

        def access_check() -> object:
            events.append(("access-provider", None))

            def is_executable(path: object, mode: object) -> object:
                events.append(("access-call", (path, mode)))
                return Truth("access")

            return is_executable

        def executable_mode() -> object:
            events.append(("mode-provider", None))
            return "execute"

        blocked = mock.Mock(
            side_effect=AssertionError("resolved an unused dependency")
        )
        observed = self.adapter.select_codex_executable(
            Launcher(),
            profile=Profile(),
            environment=environment,
            path_factory=path_factory,
            executable_path=blocked,
            current_directory=blocked,
            os_error_type=blocked,
            regular_file_test=regular_file_test,
            access_check=access_check,
            executable_mode=executable_mode,
            error_type=blocked,
        )

        self.assertIs(observed, result)
        self.assertEqual(
            events,
            [
                ("environment-provider", None),
                ("profile-environment", None),
                ("environment-get", ENVIRONMENT_NAME),
                ("truth", "override"),
                ("path-provider", None),
                ("path-call", override),
                ("is-absolute", None),
                ("truth", "absolute"),
                ("stat", None),
                ("regular-provider", None),
                ("metadata-mode", None),
                ("regular-call", "mode"),
                ("truth", "regular"),
                ("access-provider", None),
                ("mode-provider", None),
                ("access-call", (candidate, "execute")),
                ("truth", "access"),
                ("metadata-device", None),
                ("metadata-inode", None),
                ("launcher-device", None),
                ("launcher-inode", None),
                ("absolute", None),
            ],
        )
        blocked.assert_not_called()

    def test_path_candidates_are_built_eagerly_and_in_order(self) -> None:
        events: list[tuple[str, object]] = []
        result = object()
        entries = ("first", "", "third")
        candidates: list[object] = []

        class Candidate:
            def __init__(candidate_self, entry: object) -> None:
                candidate_self.entry = entry

            def __truediv__(
                candidate_self,
                child: str,
            ) -> Candidate:
                events.append(("join", (candidate_self.entry, child)))
                candidates.append(candidate_self)
                return candidate_self

            def stat(candidate_self) -> object:
                events.append(("stat", candidate_self.entry))
                return SimpleNamespace(
                    st_mode=stat.S_IFREG,
                    st_dev=1,
                    st_ino=2,
                )

            def absolute(candidate_self) -> object:
                events.append(("absolute", candidate_self.entry))
                return result

        def entries_iterator() -> object:
            for entry in entries:
                events.append(("yield-entry", entry))
                yield entry
            events.append(("entries-exhausted", None))

        def path_factory() -> object:
            events.append(("path-provider", None))

            def make_path(entry: object) -> Candidate:
                events.append(("path-call", entry))
                return Candidate(entry)

            return make_path

        def executable_path() -> object:
            events.append(("exec-path-provider", None))

            def read_entries() -> object:
                events.append(("exec-path-call", None))
                return entries_iterator()

            return read_entries

        def current_directory() -> str:
            events.append(("current-directory", None))
            return "current"

        observed = self.select(
            environment=lambda: {},
            path_factory=path_factory,
            executable_path=executable_path,
            current_directory=current_directory,
            regular_file_test=lambda: lambda mode: True,
            access_check=lambda: lambda path, mode: True,
            executable_mode=lambda: "execute",
        )

        self.assertIs(observed, result)
        self.assertEqual(
            events,
            [
                ("exec-path-provider", None),
                ("exec-path-call", None),
                ("yield-entry", "first"),
                ("path-provider", None),
                ("path-call", "first"),
                ("join", ("first", "codex")),
                ("yield-entry", ""),
                ("path-provider", None),
                ("current-directory", None),
                ("path-call", "current"),
                ("join", ("current", "codex")),
                ("yield-entry", "third"),
                ("path-provider", None),
                ("path-call", "third"),
                ("join", ("third", "codex")),
                ("entries-exhausted", None),
                ("stat", "first"),
                ("absolute", "first"),
            ],
        )
        self.assertEqual(len(candidates), 3)

    def test_override_rejections_have_exact_profile_diagnostics(self) -> None:
        class SelectionError(RuntimeError):
            pass

        relative = mock.Mock()
        relative.is_absolute.return_value = False
        blocked_exec_path = mock.Mock(
            side_effect=AssertionError("searched PATH with an override")
        )
        with self.assertRaises(SelectionError) as caught:
            self.select(
                environment=lambda: {ENVIRONMENT_NAME: "relative"},
                path_factory=lambda: lambda value: relative,
                executable_path=blocked_exec_path,
                error_type=lambda: SelectionError,
            )
        self.assertEqual(
            str(caught.exception),
            f"{ENVIRONMENT_NAME} must be an absolute path",
        )
        self.assertIsNone(caught.exception.__cause__)
        relative.stat.assert_not_called()
        blocked_exec_path.assert_not_called()

        cases = ("stat-error", "nonregular", "inaccessible", "launcher")
        for rejection in cases:
            with self.subTest(rejection=rejection):
                metadata = SimpleNamespace(
                    st_mode="mode",
                    st_dev=7,
                    st_ino=8,
                )
                candidate = mock.Mock()
                candidate.is_absolute.return_value = True
                if rejection == "stat-error":
                    candidate.stat.side_effect = OSError("missing")
                else:
                    candidate.stat.return_value = metadata
                regular = mock.Mock(
                    return_value=rejection != "nonregular"
                )
                access = mock.Mock(
                    return_value=rejection != "inaccessible"
                )
                launcher = SimpleNamespace(
                    device=7 if rejection == "launcher" else 70,
                    inode=8 if rejection == "launcher" else 80,
                )

                with self.assertRaises(SelectionError) as caught:
                    self.select(
                        launcher=launcher,
                        environment=lambda: {
                            ENVIRONMENT_NAME: "/candidate"
                        },
                        path_factory=lambda: lambda value: candidate,
                        regular_file_test=lambda: regular,
                        access_check=lambda: access,
                        executable_mode=lambda: "execute",
                        error_type=lambda: SelectionError,
                    )

                self.assertEqual(
                    str(caught.exception),
                    f"{ENVIRONMENT_NAME} does not name a usable "
                    "non-launcher executable",
                )
                self.assertIsNone(caught.exception.__cause__)
                candidate.absolute.assert_not_called()
                if rejection in {"stat-error", "nonregular"}:
                    access.assert_not_called()

    def test_path_search_skips_each_rejection_and_selects_first_success(
        self,
    ) -> None:
        events: list[str] = []
        result = object()
        rejections = (
            "stat-error",
            "nonregular",
            "inaccessible",
            "launcher",
            "success",
            "unused",
        )
        launcher = SimpleNamespace(device=7, inode=8)

        class Candidate:
            def __init__(candidate_self, behavior: str) -> None:
                candidate_self.behavior = behavior

            def __truediv__(
                candidate_self,
                child: str,
            ) -> Candidate:
                return candidate_self

            def stat(candidate_self) -> object:
                events.append(f"stat:{candidate_self.behavior}")
                if candidate_self.behavior == "stat-error":
                    raise OSError("unavailable")
                return SimpleNamespace(
                    st_mode=candidate_self.behavior,
                    st_dev=7,
                    st_ino=(
                        8
                        if candidate_self.behavior == "launcher"
                        else 80
                    ),
                )

            def absolute(candidate_self) -> object:
                events.append(f"absolute:{candidate_self.behavior}")
                return result

        def is_regular(mode: str) -> bool:
            events.append(f"regular:{mode}")
            return mode != "nonregular"

        def is_accessible(path: Candidate, mode: object) -> bool:
            events.append(f"access:{path.behavior}")
            return path.behavior != "inaccessible"

        observed = self.select(
            launcher=launcher,
            environment=lambda: {},
            path_factory=lambda: lambda value: Candidate(value),
            executable_path=lambda: lambda: list(rejections),
            regular_file_test=lambda: is_regular,
            access_check=lambda: is_accessible,
            executable_mode=lambda: "execute",
        )

        self.assertIs(observed, result)
        self.assertEqual(
            events,
            [
                "stat:stat-error",
                "stat:nonregular",
                "regular:nonregular",
                "stat:inaccessible",
                "regular:inaccessible",
                "access:inaccessible",
                "stat:launcher",
                "regular:launcher",
                "access:launcher",
                "stat:success",
                "regular:success",
                "access:success",
                "absolute:success",
            ],
        )

    def test_empty_path_search_uses_exact_profile_diagnostic(self) -> None:
        class SelectionError(RuntimeError):
            pass

        for override in (None, ""):
            with self.subTest(override=override):
                with self.assertRaises(SelectionError) as caught:
                    self.select(
                        environment=lambda: {
                            ENVIRONMENT_NAME: override
                        },
                        executable_path=lambda: lambda: [],
                        error_type=lambda: SelectionError,
                    )
                self.assertEqual(
                    str(caught.exception),
                    "cannot find the real Codex executable; set "
                    f"{ENVIRONMENT_NAME}",
                )
                self.assertIsNone(caught.exception.__cause__)

    def test_diagnostics_resolve_error_before_second_profile_lookup(
        self,
    ) -> None:
        class CapturedSelectionError(RuntimeError):
            pass

        class ReboundSelectionError(RuntimeError):
            pass

        cases = (
            (
                "relative-override",
                "relative",
                f"{ENVIRONMENT_NAME} must be an absolute path",
            ),
            (
                "exhausted-override",
                "/missing",
                f"{ENVIRONMENT_NAME} does not name a usable "
                "non-launcher executable",
            ),
            (
                "exhausted-path",
                None,
                "cannot find the real Codex executable; set "
                f"{ENVIRONMENT_NAME}",
            ),
        )

        for case, override, message in cases:
            with self.subTest(case=case):
                events: list[str] = []
                selected_error: list[type[BaseException]] = [
                    CapturedSelectionError
                ]

                class Profile:
                    def __init__(profile_self) -> None:
                        profile_self.lookups = 0

                    @property
                    def real_codex_environment(
                        profile_self,
                    ) -> str:
                        profile_self.lookups += 1
                        events.append(
                            f"profile:{profile_self.lookups}"
                        )
                        if profile_self.lookups == 2:
                            selected_error[0] = ReboundSelectionError
                        return ENVIRONMENT_NAME

                candidate = mock.Mock()
                candidate.is_absolute.return_value = (
                    case != "relative-override"
                )
                candidate.stat.side_effect = OSError("missing")

                def error_type() -> type[BaseException]:
                    events.append("error-provider")
                    return selected_error[0]

                environment = (
                    {}
                    if override is None
                    else {ENVIRONMENT_NAME: override}
                )
                with self.assertRaises(
                    CapturedSelectionError
                ) as caught:
                    self.select(
                        profile=Profile(),
                        environment=lambda: environment,
                        path_factory=lambda: (
                            lambda value: candidate
                        ),
                        executable_path=lambda: lambda: [],
                        error_type=error_type,
                    )

                self.assertEqual(str(caught.exception), message)
                self.assertEqual(
                    events,
                    ["profile:1", "error-provider", "profile:2"],
                )
                self.assertIs(
                    selected_error[0],
                    ReboundSelectionError,
                )

    def test_override_truth_is_rechecked_after_exhaustion(self) -> None:
        class SelectionError(RuntimeError):
            pass

        class ChangingOverride:
            def __init__(
                override_self,
                outcomes: tuple[bool, bool],
            ) -> None:
                override_self.outcomes = iter(outcomes)

            def __bool__(override_self) -> bool:
                return next(override_self.outcomes)

        first_true = ChangingOverride((True, False))
        candidate = mock.Mock()
        candidate.is_absolute.return_value = True
        candidate.stat.side_effect = OSError("missing")
        with self.assertRaisesRegex(
            SelectionError,
            "^cannot find the real Codex executable; set "
            f"{ENVIRONMENT_NAME}$",
        ):
            self.select(
                environment=lambda: {ENVIRONMENT_NAME: first_true},
                path_factory=lambda: lambda value: candidate,
                error_type=lambda: SelectionError,
            )

        first_false = ChangingOverride((False, True))
        with self.assertRaisesRegex(
            SelectionError,
            f"^{ENVIRONMENT_NAME} does not name a usable "
            "non-launcher executable$",
        ):
            self.select(
                environment=lambda: {ENVIRONMENT_NAME: first_false},
                executable_path=lambda: lambda: [],
                error_type=lambda: SelectionError,
            )

    def test_only_candidate_stat_errors_are_silently_rejected(self) -> None:
        class SelectedOSError(OSError):
            pass

        class SelectionError(RuntimeError):
            pass

        for stage in ("stat-attribute", "stat-call"):
            with self.subTest(caught_stage=stage):
                original = SelectedOSError(stage)

                class Candidate:
                    def is_absolute(candidate_self) -> bool:
                        return True

                    @property
                    def stat(candidate_self) -> object:
                        if stage == "stat-attribute":
                            raise original

                        def inspect() -> None:
                            raise original

                        return inspect

                os_error_type = mock.Mock(
                    return_value=SelectedOSError
                )
                with self.assertRaises(SelectionError) as caught:
                    self.select(
                        environment=lambda: {
                            ENVIRONMENT_NAME: "/candidate"
                        },
                        path_factory=lambda: lambda value: Candidate(),
                        os_error_type=os_error_type,
                        error_type=lambda: SelectionError,
                    )
                self.assertEqual(
                    str(caught.exception),
                    f"{ENVIRONMENT_NAME} does not name a usable "
                    "non-launcher executable",
                )
                os_error_type.assert_called_once_with()

        original = LookupError("not selected")
        os_error_type = mock.Mock(return_value=SelectedOSError)
        candidate = mock.Mock()
        candidate.is_absolute.return_value = True
        candidate.stat.side_effect = original
        with self.assertRaises(LookupError) as caught:
            self.select(
                environment=lambda: {ENVIRONMENT_NAME: "/candidate"},
                path_factory=lambda: lambda value: candidate,
                os_error_type=os_error_type,
            )
        self.assertIs(caught.exception, original)
        os_error_type.assert_called_once_with()

        selected = SelectedOSError("selected")
        matcher_failure = RuntimeError("matcher failed")
        candidate.stat.side_effect = selected

        def broken_os_error_type() -> type[BaseException]:
            raise matcher_failure

        with self.assertRaises(RuntimeError) as matcher_caught:
            self.select(
                environment=lambda: {ENVIRONMENT_NAME: "/candidate"},
                path_factory=lambda: lambda value: candidate,
                os_error_type=broken_os_error_type,
            )
        self.assertIs(matcher_caught.exception, matcher_failure)
        self.assertIs(matcher_caught.exception.__context__, selected)

    def test_candidate_source_failures_remain_outside_the_stat_catch(
        self,
    ) -> None:
        override_stages = (
            "environment-provider",
            "profile-environment",
            "environment-get",
            "override-truth",
            "path-provider",
            "path-call",
            "is-absolute-attribute",
            "is-absolute-call",
            "absolute-truth",
        )

        for stage in override_stages:
            with self.subTest(override_stage=stage):
                original = OSError(stage)

                def fail_at(observed: str) -> None:
                    if stage == observed:
                        raise original

                class Override:
                    def __bool__(override_self) -> bool:
                        fail_at("override-truth")
                        return True

                class Profile:
                    @property
                    def real_codex_environment(
                        profile_self,
                    ) -> str:
                        fail_at("profile-environment")
                        return ENVIRONMENT_NAME

                class AbsoluteTruth:
                    def __bool__(truth_self) -> bool:
                        fail_at("absolute-truth")
                        return True

                class Candidate:
                    @property
                    def is_absolute(candidate_self) -> object:
                        fail_at("is-absolute-attribute")

                        def check() -> object:
                            fail_at("is-absolute-call")
                            return AbsoluteTruth()

                        return check

                class Environment:
                    def get(environment_self, name: str) -> Override:
                        fail_at("environment-get")
                        return Override()

                def environment() -> Environment:
                    fail_at("environment-provider")
                    return Environment()

                def path_factory() -> object:
                    fail_at("path-provider")

                    def make_path(value: object) -> Candidate:
                        fail_at("path-call")
                        return Candidate()

                    return make_path

                os_error_type = mock.Mock(return_value=OSError)
                with self.assertRaises(OSError) as caught:
                    self.select(
                        profile=Profile(),
                        environment=environment,
                        path_factory=path_factory,
                        os_error_type=os_error_type,
                    )
                self.assertIs(caught.exception, original)
                os_error_type.assert_not_called()

        path_stages = (
            "exec-provider",
            "exec-call",
            "iteration",
            "entry-truth",
            "current-directory",
            "division",
        )
        for stage in path_stages:
            with self.subTest(path_stage=stage):
                original = OSError(stage)

                def fail_at(observed: str) -> None:
                    if stage == observed:
                        raise original

                class Entry:
                    def __bool__(entry_self) -> bool:
                        fail_at("entry-truth")
                        return False

                class Candidate:
                    def __truediv__(
                        candidate_self,
                        child: str,
                    ) -> Candidate:
                        fail_at("division")
                        return candidate_self

                class Entries:
                    def __iter__(entries_self) -> object:
                        fail_at("iteration")
                        return iter((Entry(),))

                def executable_path() -> object:
                    fail_at("exec-provider")

                    def read() -> Entries:
                        fail_at("exec-call")
                        return Entries()

                    return read

                def current_directory() -> str:
                    fail_at("current-directory")
                    return "."

                os_error_type = mock.Mock(return_value=OSError)
                with self.assertRaises(OSError) as caught:
                    self.select(
                        environment=lambda: {},
                        path_factory=lambda: lambda value: Candidate(),
                        executable_path=executable_path,
                        current_directory=current_directory,
                        os_error_type=os_error_type,
                    )
                self.assertIs(caught.exception, original)
                os_error_type.assert_not_called()

    def test_validation_and_absolutization_failures_remain_uncaught(
        self,
    ) -> None:
        stages = (
            "regular-provider",
            "metadata-mode",
            "regular-call",
            "regular-truth",
            "access-provider",
            "mode-provider",
            "access-call",
            "access-truth",
            "metadata-device",
            "metadata-inode",
            "launcher-device",
            "launcher-inode",
            "identity-equality",
            "absolute-attribute",
            "absolute-call",
        )

        for stage in stages:
            with self.subTest(uncaught_stage=stage):
                original = OSError(stage)

                def fail_at(observed: str) -> None:
                    if stage == observed:
                        raise original

                class Truth:
                    def __init__(
                        truth_self,
                        failure_stage: str,
                    ) -> None:
                        truth_self.failure_stage = failure_stage

                    def __bool__(truth_self) -> bool:
                        fail_at(truth_self.failure_stage)
                        return True

                class Device:
                    def __eq__(
                        device_self,
                        other: object,
                    ) -> bool:
                        fail_at("identity-equality")
                        return False

                class Metadata:
                    @property
                    def st_mode(metadata_self) -> int:
                        fail_at("metadata-mode")
                        return stat.S_IFREG

                    @property
                    def st_dev(metadata_self) -> int:
                        fail_at("metadata-device")
                        return Device()

                    @property
                    def st_ino(metadata_self) -> int:
                        fail_at("metadata-inode")
                        return 2

                class Launcher:
                    @property
                    def device(launcher_self) -> int:
                        fail_at("launcher-device")
                        return 3

                    @property
                    def inode(launcher_self) -> int:
                        fail_at("launcher-inode")
                        return 4

                class Candidate:
                    def is_absolute(candidate_self) -> bool:
                        return True

                    def stat(candidate_self) -> Metadata:
                        return Metadata()

                    @property
                    def absolute(candidate_self) -> object:
                        fail_at("absolute-attribute")

                        def make_absolute() -> object:
                            fail_at("absolute-call")
                            return object()

                        return make_absolute

                def regular_file_test() -> object:
                    fail_at("regular-provider")

                    def check(mode: object) -> bool:
                        fail_at("regular-call")
                        return Truth("regular-truth")

                    return check

                def access_check() -> object:
                    fail_at("access-provider")

                    def check(path: object, mode: object) -> bool:
                        fail_at("access-call")
                        return Truth("access-truth")

                    return check

                def executable_mode() -> int:
                    fail_at("mode-provider")
                    return os.X_OK

                os_error_type = mock.Mock(return_value=OSError)
                with self.assertRaises(OSError) as caught:
                    self.select(
                        launcher=Launcher(),
                        environment=lambda: {
                            ENVIRONMENT_NAME: "/candidate"
                        },
                        path_factory=lambda: lambda value: Candidate(),
                        os_error_type=os_error_type,
                        regular_file_test=regular_file_test,
                        access_check=access_check,
                        executable_mode=executable_mode,
                    )
                self.assertIs(caught.exception, original)
                os_error_type.assert_not_called()

    def test_engine_wrapper_forwards_every_global_lazily(self) -> None:
        class InitialOSError(OSError):
            pass

        class ReboundOSError(OSError):
            pass

        class InitialSelectionError(RuntimeError):
            pass

        class ReboundSelectionError(RuntimeError):
            pass

        profile = object()
        launcher = object()
        sentinel = object()
        initial_path = mock.Mock(name="initial-path")
        rebound_path = mock.Mock(name="rebound-path")
        rebound_environment = object()
        rebound_exec_path = mock.Mock(name="rebound-exec-path")
        rebound_regular = mock.Mock(name="rebound-regular")
        rebound_access = mock.Mock(name="rebound-access")
        rebound_mode = object()

        def select(observed_launcher: object, **dependencies: object) -> object:
            self.assertIs(observed_launcher, launcher)
            self.assertEqual(
                tuple(dependencies),
                (
                    "profile",
                    "environment",
                    "path_factory",
                    "executable_path",
                    "current_directory",
                    "os_error_type",
                    "regular_file_test",
                    "access_check",
                    "executable_mode",
                    "error_type",
                ),
            )
            self.assertIs(dependencies["profile"], profile)
            self.engine.os = SimpleNamespace(
                environ=rebound_environment,
                get_exec_path=rebound_exec_path,
                curdir="rebound-current",
                access=rebound_access,
                X_OK=rebound_mode,
            )
            self.engine.Path = rebound_path
            self.engine.OSError = ReboundOSError
            self.engine.stat = SimpleNamespace(S_ISREG=rebound_regular)
            self.engine.LauncherError = ReboundSelectionError
            self.assertIs(
                dependencies["environment"](),
                rebound_environment,
            )
            self.assertIs(dependencies["path_factory"](), rebound_path)
            self.assertIs(
                dependencies["executable_path"](),
                rebound_exec_path,
            )
            self.assertEqual(
                dependencies["current_directory"](),
                "rebound-current",
            )
            self.assertIs(
                dependencies["os_error_type"](),
                ReboundOSError,
            )
            self.assertIs(
                dependencies["regular_file_test"](),
                rebound_regular,
            )
            self.assertIs(
                dependencies["access_check"](),
                rebound_access,
            )
            self.engine.os = SimpleNamespace(
                environ=object(),
                get_exec_path=mock.Mock(),
                curdir="later-current",
                access=mock.Mock(),
                X_OK=rebound_mode,
            )
            self.assertIs(
                dependencies["executable_mode"](),
                rebound_mode,
            )
            self.assertIs(
                dependencies["error_type"](),
                ReboundSelectionError,
            )
            return sentinel

        initial_os = SimpleNamespace(
            environ=object(),
            get_exec_path=mock.Mock(),
            curdir="initial-current",
            access=mock.Mock(),
            X_OK=object(),
        )
        with (
            mock.patch.object(
                self.engine,
                "active_profile",
                return_value=profile,
            ) as active_profile,
            mock.patch.object(
                self.engine,
                "_select_codex_executable",
                side_effect=select,
            ) as kernel,
            mock.patch.object(self.engine, "os", initial_os),
            mock.patch.object(self.engine, "Path", initial_path),
            mock.patch.object(
                self.engine,
                "OSError",
                InitialOSError,
                create=True,
            ),
            mock.patch.object(
                self.engine,
                "stat",
                SimpleNamespace(S_ISREG=mock.Mock()),
            ),
            mock.patch.object(
                self.engine,
                "LauncherError",
                InitialSelectionError,
            ),
        ):
            observed = self.engine.resolve_real_codex(launcher)

        self.assertIs(observed, sentinel)
        active_profile.assert_called_once_with()
        kernel.assert_called_once()

    def test_engine_and_real_kernel_observe_rebound_error_types(self) -> None:
        class InitialOSError(OSError):
            pass

        class ReboundOSError(OSError):
            pass

        class InitialSelectionError(RuntimeError):
            pass

        class ReboundSelectionError(RuntimeError):
            pass

        failure = ReboundOSError("missing")
        candidate = mock.Mock()
        candidate.is_absolute.return_value = True

        def inspect() -> None:
            self.engine.OSError = ReboundOSError
            self.engine.LauncherError = ReboundSelectionError
            raise failure

        candidate.stat.side_effect = inspect
        profile = SimpleNamespace(
            real_codex_environment=ENVIRONMENT_NAME
        )
        with (
            mock.patch.object(
                self.engine,
                "active_profile",
                return_value=profile,
            ),
            mock.patch.object(
                self.engine,
                "_select_codex_executable",
                self.adapter.select_codex_executable,
            ),
            mock.patch.object(
                self.engine,
                "os",
                SimpleNamespace(
                    environ={ENVIRONMENT_NAME: "/candidate"},
                    access=mock.Mock(),
                    X_OK=os.X_OK,
                ),
            ),
            mock.patch.object(
                self.engine,
                "Path",
                lambda value: candidate,
            ),
            mock.patch.object(
                self.engine,
                "OSError",
                InitialOSError,
                create=True,
            ),
            mock.patch.object(
                self.engine,
                "LauncherError",
                InitialSelectionError,
            ),
        ):
            with self.assertRaises(ReboundSelectionError) as caught:
                self.engine.resolve_real_codex(
                    SimpleNamespace(device=1, inode=2)
                )

        self.assertEqual(
            str(caught.exception),
            f"{ENVIRONMENT_NAME} does not name a usable "
            "non-launcher executable",
        )
        self.assertIsNone(caught.exception.__cause__)

    def test_argument_policy_constants_and_surfaces_are_exact(self) -> None:
        expected_constants = {
            "ROOT_FLAG_OPTIONS": {
                "--help",
                "--no-alt-screen",
                "--oss",
                "--search",
                "--strict-config",
                "--version",
                "-V",
                "-h",
            },
            "ROOT_VALUE_OPTIONS": {
                "--image",
                "--local-provider",
                "--model",
                "--sandbox",
                "-i",
                "-m",
                "-s",
            },
            "EXEC_FLAG_OPTIONS": {
                "--ephemeral",
                "--help",
                "--ignore-user-config",
                "--json",
                "--oss",
                "--skip-git-repo-check",
                "--strict-config",
                "--version",
                "-V",
                "-h",
            },
            "EXEC_VALUE_OPTIONS": {
                "--color",
                "--image",
                "--local-provider",
                "--model",
                "--output-schema",
                "--sandbox",
                "-i",
                "-m",
                "-s",
            },
            "REVIEW_FLAG_OPTIONS": {
                "--help",
                "--strict-config",
                "--uncommitted",
                "-h",
            },
            "REVIEW_VALUE_OPTIONS": {
                "--base",
                "--commit",
                "--title",
            },
            "NON_AGENT_CODEX_COMMANDS": {
                "a",
                "app-server",
                "apply",
                "archive",
                "cloud",
                "completion",
                "debug",
                "delete",
                "doctor",
                "exec-server",
                "features",
                "fork",
                "help",
                "login",
                "logout",
                "mcp",
                "mcp-server",
                "plugin",
                "remote-control",
                "resume",
                "sandbox",
                "unarchive",
                "update",
            },
        }
        for name, expected in expected_constants.items():
            with self.subTest(constant=name):
                actual = getattr(self.adapter, name)
                self.assertIs(type(actual), set)
                self.assertEqual(actual, expected)
                self.assertIs(getattr(self.engine, name), actual)

        surfaces = (
            (
                self.adapter.scan_allowed_options,
                (
                    "arguments",
                    "start",
                    "flag_options",
                    "value_options",
                    "length",
                    "error_type",
                ),
                4,
            ),
            (
                self.adapter.normalize_codex_arguments,
                (
                    "arguments",
                    "list_factory",
                    "length",
                    "option_scanner",
                    "root_flag_options",
                    "root_value_options",
                    "exec_flag_options",
                    "exec_value_options",
                    "review_flag_options",
                    "review_value_options",
                    "non_agent_commands",
                    "reopen_hint",
                    "error_type",
                ),
                1,
            ),
            (
                self.adapter.codex_argv,
                (
                    "real_codex",
                    "workdir",
                    "arguments",
                    "argument_normalizer",
                    "stringifier",
                ),
                3,
            ),
        )
        for function, names, positional_count in surfaces:
            with self.subTest(surface=function.__name__):
                parameters = inspect.signature(function).parameters
                self.assertEqual(tuple(parameters), names)
                for index, parameter in enumerate(parameters.values()):
                    expected_kind = (
                        inspect.Parameter.POSITIONAL_OR_KEYWORD
                        if index < positional_count
                        else inspect.Parameter.KEYWORD_ONLY
                    )
                    self.assertIs(parameter.kind, expected_kind)
                    self.assertIs(
                        parameter.default,
                        inspect.Parameter.empty,
                    )

        wrappers = (
            (
                self.engine.scan_allowed_options,
                (
                    "arguments",
                    "start",
                    "flag_options",
                    "value_options",
                ),
            ),
            (
                self.engine.normalize_codex_arguments,
                ("arguments",),
            ),
            (
                self.engine.codex_argv,
                ("real_codex", "workdir", "arguments"),
            ),
        )
        for function, names in wrappers:
            with self.subTest(wrapper=function.__name__):
                parameters = inspect.signature(function).parameters
                self.assertEqual(tuple(parameters), names)
                for parameter in parameters.values():
                    self.assertIs(
                        parameter.kind,
                        inspect.Parameter.POSITIONAL_OR_KEYWORD,
                    )
                    self.assertIs(
                        parameter.default,
                        inspect.Parameter.empty,
                    )

        self.assertIs(
            self.engine._scan_allowed_options,
            self.adapter.scan_allowed_options,
        )
        self.assertIs(
            self.engine._normalize_codex_arguments,
            self.adapter.normalize_codex_arguments,
        )
        self.assertIs(
            self.engine._codex_argv,
            self.adapter.codex_argv,
        )

    def test_option_scanner_accepts_every_policy_form(self) -> None:
        scopes = (
            (
                "root",
                self.adapter.ROOT_FLAG_OPTIONS,
                self.adapter.ROOT_VALUE_OPTIONS,
            ),
            (
                "exec",
                self.adapter.EXEC_FLAG_OPTIONS,
                self.adapter.EXEC_VALUE_OPTIONS,
            ),
            (
                "review",
                self.adapter.REVIEW_FLAG_OPTIONS,
                self.adapter.REVIEW_VALUE_OPTIONS,
            ),
        )
        for scope, flags, values in scopes:
            with self.subTest(scope=scope, form="flags"):
                arguments = [*sorted(flags), "prompt"]
                self.assertEqual(
                    self.scan(arguments, 0, flags, values),
                    (len(flags), False, False),
                )

            for option in sorted(values):
                value = (
                    "workspace-write"
                    if option in {"-s", "--sandbox"}
                    else "-value"
                )
                arguments = [option, value]
                expected_arguments = (
                    [f"--image={value}"]
                    if option in {"-i", "--image"}
                    else [option, value]
                )
                with self.subTest(
                    scope=scope,
                    form="separated",
                    option=option,
                ):
                    self.assertEqual(
                        self.scan(arguments, 0, flags, values),
                        (
                            len(expected_arguments),
                            option in {"-s", "--sandbox"},
                            False,
                        ),
                    )
                    self.assertEqual(arguments, expected_arguments)

        attached_forms = (
            ("--model=value", False),
            ("--model=", False),
            ("--image=reference.png", False),
            ("--local-provider=provider", False),
            ("--sandbox=read-only", True),
            ("-mvalue", False),
            ("-m=value", False),
            ("-ireference.png", False),
            ("-i=reference.png", False),
            ("-sworkspace-write", True),
            ("-s=read-only", True),
        )
        for token, supplied_sandbox in attached_forms:
            arguments = [token]
            with self.subTest(form="attached", token=token):
                self.assertEqual(
                    self.scan(
                        arguments,
                        0,
                        self.adapter.ROOT_FLAG_OPTIONS,
                        self.adapter.ROOT_VALUE_OPTIONS,
                    ),
                    (1, supplied_sandbox, False),
                )
                self.assertEqual(arguments, [token])

    def test_option_scanner_stops_at_each_boundary(self) -> None:
        cases = (
            ([], 0, (0, False, False)),
            (["prompt"], 0, (0, False, False)),
            (["-"], 0, (0, False, False)),
            (["--", "prompt"], 0, (1, False, True)),
            (
                ["prefix", "--sandbox", "read-only", "--", "prompt"],
                1,
                (4, True, True),
            ),
            (
                ["prefix", "--model", "model", "prompt"],
                1,
                (3, False, False),
            ),
        )
        for arguments, start, expected in cases:
            with self.subTest(arguments=arguments, start=start):
                self.assertEqual(
                    self.scan(
                        list(arguments),
                        start,
                        self.adapter.ROOT_FLAG_OPTIONS,
                        self.adapter.ROOT_VALUE_OPTIONS,
                    ),
                    expected,
                )

    def test_option_scanner_errors_are_exact_and_preserve_prior_mutation(
        self,
    ) -> None:
        class ScanError(RuntimeError):
            pass

        all_value_options = (
            self.adapter.ROOT_VALUE_OPTIONS
            | self.adapter.EXEC_VALUE_OPTIONS
            | self.adapter.REVIEW_VALUE_OPTIONS
        )
        for option in sorted(all_value_options):
            with self.subTest(error="missing-value", option=option):
                with self.assertRaises(ScanError) as caught:
                    self.scan(
                        [option],
                        value_options=all_value_options,
                        error_type=lambda: ScanError,
                    )
                self.assertEqual(
                    str(caught.exception),
                    f"Codex option {option} requires a value",
                )
                self.assertIsNone(caught.exception.__cause__)

        for token in ("--future", "-x"):
            with self.subTest(error="unsupported", token=token):
                with self.assertRaises(ScanError) as caught:
                    self.scan(
                        [token],
                        flag_options=self.adapter.ROOT_FLAG_OPTIONS,
                        value_options=self.adapter.ROOT_VALUE_OPTIONS,
                        error_type=lambda: ScanError,
                    )
                self.assertEqual(
                    str(caught.exception),
                    f"unsupported Codex option {token!r} in isolated sessions",
                )
                self.assertIsNone(caught.exception.__cause__)

        unsafe_forms = (
            ["--sandbox", "danger-full-access"],
            ["--sandbox=danger-full-access"],
            ["-sdanger-full-access"],
            ["-s=danger-full-access"],
        )
        for arguments in unsafe_forms:
            with self.subTest(error="unsafe-sandbox", arguments=arguments):
                with self.assertRaises(ScanError) as caught:
                    self.scan(
                        list(arguments),
                        flag_options=self.adapter.ROOT_FLAG_OPTIONS,
                        value_options=self.adapter.ROOT_VALUE_OPTIONS,
                        error_type=lambda: ScanError,
                    )
                self.assertEqual(
                    str(caught.exception),
                    "unsafe Codex sandbox mode 'danger-full-access'",
                )
                self.assertIsNone(caught.exception.__cause__)

        arguments = ["--image", "reference.png", "--future"]
        with self.assertRaisesRegex(
            ScanError,
            "^unsupported Codex option '--future' in isolated sessions$",
        ):
            self.scan(
                arguments,
                flag_options=self.adapter.ROOT_FLAG_OPTIONS,
                value_options=self.adapter.ROOT_VALUE_OPTIONS,
                error_type=lambda: ScanError,
            )
        self.assertEqual(arguments, ["--image=reference.png", "--future"])

    def test_option_scanner_resolves_error_before_diagnostic_operands(
        self,
    ) -> None:
        class ScanError(RuntimeError):
            pass

        class OrderedText(str):
            def __new__(
                cls,
                value: str,
                events: list[str],
                operation: str,
            ) -> OrderedText:
                instance = super().__new__(cls, value)
                instance.events = events
                instance.operation = operation
                return instance

            def observe(self) -> None:
                if self.events != ["error-type"]:
                    raise AssertionError(
                        "diagnostic operand evaluated before error type"
                    )
                self.events.append(self.operation)

            def __format__(self, specification: str) -> str:
                self.observe()
                return super().__format__(specification)

            def __repr__(self) -> str:
                self.observe()
                return super().__repr__()

        for diagnostic in ("missing", "unsupported", "unsafe"):
            events: list[str] = []
            operation = "format" if diagnostic == "missing" else "repr"
            observed = OrderedText("value", events, operation)
            if diagnostic == "missing":
                observed = OrderedText("--model", events, operation)
                arguments = [observed]
            elif diagnostic == "unsupported":
                observed = OrderedText("--future", events, operation)
                arguments = [observed]
            else:
                observed = OrderedText(
                    "danger-full-access",
                    events,
                    operation,
                )
                arguments = ["--sandbox", observed]

            def error_type() -> type[BaseException]:
                events.append("error-type")
                return ScanError

            with self.subTest(diagnostic=diagnostic):
                with self.assertRaises(ScanError):
                    self.scan(
                        arguments,
                        flag_options=self.adapter.ROOT_FLAG_OPTIONS,
                        value_options=self.adapter.ROOT_VALUE_OPTIONS,
                        error_type=error_type,
                    )
                self.assertEqual(events, ["error-type", operation])

    def test_argument_normalization_covers_each_command_branch(self) -> None:
        cases = (
            ([], [], False),
            (["--help"], ["--help"], False),
            (
                ["--sandbox", "read-only"],
                ["--sandbox", "read-only"],
                True,
            ),
            (["--", "sandbox"], ["--", "sandbox"], False),
            (["prompt"], ["--", "prompt"], False),
            (["-"], ["--", "-"], False),
            (
                ["--model", "model", "prompt"],
                ["--model", "model", "--", "prompt"],
                False,
            ),
            (
                ["--image", "reference.png", "prompt"],
                ["--image=reference.png", "--", "prompt"],
                False,
            ),
            (["exec"], ["exec"], False),
            (["e", "--json"], ["e", "--json"], False),
            (
                ["exec", "--", "resume"],
                ["exec", "--", "resume"],
                False,
            ),
            (
                ["exec", "--json", "prompt"],
                ["exec", "--json", "--", "prompt"],
                False,
            ),
            (
                ["exec", "--sandbox", "workspace-write", "prompt"],
                [
                    "exec",
                    "--sandbox",
                    "workspace-write",
                    "--",
                    "prompt",
                ],
                True,
            ),
            (["review"], ["review"], False),
            (
                ["review", "--uncommitted", "prompt"],
                ["review", "--uncommitted", "--", "prompt"],
                False,
            ),
            (
                ["review", "--title", "Title", "prompt"],
                ["review", "--title", "Title", "--", "prompt"],
                False,
            ),
            (
                ["review", "--", "prompt"],
                ["review", "--", "prompt"],
                False,
            ),
            (["exec", "review"], ["exec", "review"], False),
            (
                ["exec", "review", "--uncommitted", "prompt"],
                [
                    "exec",
                    "review",
                    "--uncommitted",
                    "--",
                    "prompt",
                ],
                False,
            ),
            (
                ["exec", "review", "--title", "Title", "prompt"],
                [
                    "exec",
                    "review",
                    "--title",
                    "Title",
                    "--",
                    "prompt",
                ],
                False,
            ),
            (
                ["exec", "review", "--", "prompt"],
                ["exec", "review", "--", "prompt"],
                False,
            ),
            (
                [
                    "--sandbox",
                    "read-only",
                    "exec",
                    "--sandbox",
                    "workspace-write",
                ],
                [
                    "--sandbox",
                    "read-only",
                    "exec",
                    "--sandbox",
                    "workspace-write",
                ],
                True,
            ),
        )
        for arguments, expected_arguments, expected_sandbox in cases:
            with self.subTest(arguments=arguments):
                original = list(arguments)
                normalized, supplied_sandbox = self.normalize(original)
                self.assertEqual(normalized, expected_arguments)
                self.assertEqual(supplied_sandbox, expected_sandbox)
                self.assertEqual(original, arguments)
                self.assertIsNot(normalized, original)

    def test_argument_normalization_rejects_every_non_agent_command(
        self,
    ) -> None:
        class PolicyError(RuntimeError):
            pass

        hint = "make reopen RUN=example"
        for command in sorted(self.adapter.NON_AGENT_CODEX_COMMANDS):
            hint_calls: list[str] = []

            def reopen_hint() -> str:
                hint_calls.append(command)
                return hint

            with self.subTest(scope="root", command=command):
                with self.assertRaises(PolicyError) as caught:
                    self.normalize(
                        ["--model", "model", command],
                        reopen_hint=reopen_hint,
                        error_type=lambda: PolicyError,
                    )
                if command in {"resume", "fork"}:
                    self.assertEqual(
                        str(caught.exception),
                        f"reopen isolated worktrees with {hint}",
                    )
                    self.assertEqual(hint_calls, [command])
                else:
                    self.assertEqual(
                        str(caught.exception),
                        f"Codex subcommand {command!r} is outside the "
                        "isolated agent launcher",
                    )
                    self.assertEqual(hint_calls, [])
                self.assertIsNone(caught.exception.__cause__)

        for alias in ("exec", "e"):
            for command in ("help", "resume"):
                with self.subTest(scope=alias, command=command):
                    with self.assertRaises(PolicyError) as caught:
                        self.normalize(
                            [alias, command],
                            reopen_hint=lambda: self.fail(
                                "nested rejection must not resolve reopen hint"
                            ),
                            error_type=lambda: PolicyError,
                        )
                    self.assertEqual(
                        str(caught.exception),
                        f"Codex exec subcommand {command!r} is outside the "
                        "isolated agent launcher",
                    )
                    self.assertIsNone(caught.exception.__cause__)

    def test_argument_normalization_resolves_error_before_diagnostics(
        self,
    ) -> None:
        class PolicyError(RuntimeError):
            pass

        class OrderedCommand(str):
            def __new__(
                cls,
                value: str,
                events: list[str],
            ) -> OrderedCommand:
                instance = super().__new__(cls, value)
                instance.events = events
                return instance

            def __repr__(self) -> str:
                if self.events != ["error-type"]:
                    raise AssertionError(
                        "command repr evaluated before error type"
                    )
                self.events.append("repr")
                return super().__repr__()

        for command in ("resume", "fork"):
            events: list[str] = []

            def error_type() -> type[BaseException]:
                events.append("error-type")
                return PolicyError

            def reopen_hint() -> str:
                if events != ["error-type"]:
                    raise AssertionError(
                        "reopen hint evaluated before error type"
                    )
                events.append("reopen-hint")
                return "reopen"

            with self.subTest(scope="root-reopen", command=command):
                with self.assertRaises(PolicyError):
                    self.normalize(
                        [command],
                        error_type=error_type,
                        reopen_hint=reopen_hint,
                    )
                self.assertEqual(
                    events,
                    ["error-type", "reopen-hint"],
                )

        cases = (
            ("root", ["help"]),
            ("nested-help", ["exec", "help"]),
            ("nested-resume", ["exec", "resume"]),
        )
        for scope, plain_arguments in cases:
            events = []
            arguments = [
                (
                    OrderedCommand(argument, events)
                    if argument in {"help", "resume"}
                    else argument
                )
                for argument in plain_arguments
            ]

            def error_type() -> type[BaseException]:
                events.append("error-type")
                return PolicyError

            with self.subTest(scope=scope):
                with self.assertRaises(PolicyError):
                    self.normalize(
                        arguments,
                        error_type=error_type,
                        reopen_hint=lambda: self.fail(
                            "reopen hint must remain unused"
                        ),
                    )
                self.assertEqual(events, ["error-type", "repr"])

    def test_argument_normalization_aggregates_sandbox_across_scopes(
        self,
    ) -> None:
        combinations = (
            (False, False, False, False),
            (True, False, False, True),
            (False, True, False, True),
            (False, False, True, True),
            (True, True, True, True),
        )
        for root, nested, review, expected in combinations:
            responses = iter(
                (
                    (0, root, False),
                    (1, nested, False),
                    (2, review, False),
                )
            )
            calls: list[tuple[int, set[str], set[str]]] = []

            def scanner(
                arguments: list[str],
                start: int,
                flags: set[str],
                values: set[str],
            ) -> tuple[int, bool, bool]:
                self.assertEqual(arguments, ["exec", "review"])
                calls.append((start, flags, values))
                return next(responses)

            with self.subTest(
                root=root,
                nested=nested,
                review=review,
            ):
                self.assertEqual(
                    self.normalize(
                        ["exec", "review"],
                        option_scanner=lambda: scanner,
                    ),
                    (["exec", "review"], expected),
                )
                self.assertEqual(
                    calls,
                    [
                        (
                            0,
                            self.adapter.ROOT_FLAG_OPTIONS,
                            self.adapter.ROOT_VALUE_OPTIONS,
                        ),
                        (
                            1,
                            self.adapter.EXEC_FLAG_OPTIONS,
                            self.adapter.EXEC_VALUE_OPTIONS,
                        ),
                        (
                            2,
                            self.adapter.REVIEW_FLAG_OPTIONS,
                            self.adapter.REVIEW_VALUE_OPTIONS,
                        ),
                    ],
                )

    def test_argument_normalization_preserves_opaque_sandbox_operands(
        self,
    ) -> None:
        class SandboxOperand:
            def __init__(
                operand_self,
                name: str,
                truth: bool | None,
                events: list[str],
            ) -> None:
                operand_self.name = name
                operand_self.truth = truth
                operand_self.events = events

            def __bool__(operand_self) -> bool:
                if operand_self.truth is None:
                    raise AssertionError(
                        f"{operand_self.name} must not be truth-tested"
                    )
                operand_self.events.append(operand_self.name)
                return operand_self.truth

        cases = (
            (True, None, "root", ["root", "root"]),
            (False, True, "exec", ["root", "exec"]),
            (False, False, "review", ["root", "exec"]),
        )
        for root_truth, exec_truth, expected_name, expected_events in cases:
            events: list[str] = []
            operands = {
                "root": SandboxOperand("root", root_truth, events),
                "exec": SandboxOperand("exec", exec_truth, events),
                "review": SandboxOperand("review", None, events),
            }
            responses = iter(
                (
                    (0, operands["root"], False),
                    (1, operands["exec"], False),
                    (2, operands["review"], False),
                )
            )

            def scanner(
                _arguments: list[str],
                _start: int,
                _flags: set[str],
                _values: set[str],
            ) -> tuple[int, bool, bool]:
                return next(responses)

            with self.subTest(expected=expected_name):
                normalized, supplied_sandbox = self.normalize(
                    ["exec", "review"],
                    option_scanner=lambda: scanner,
                )
                self.assertEqual(normalized, ["exec", "review"])
                self.assertIs(
                    supplied_sandbox,
                    operands[expected_name],
                )
                self.assertEqual(events, expected_events)

    def test_codex_argv_has_exact_order_and_resolves_dependencies_lazily(
        self,
    ) -> None:
        real_codex = Path("/opt/codex")
        workdir = Path("/worktree")
        arguments = ("original",)
        normalized = ["--", "prompt"]
        for supplied_sandbox in (False, True):
            events: list[tuple[str, object]] = []
            stringifiers = iter(
                (
                    lambda value: (
                        events.append(("stringify-real", value))
                        or "REAL"
                    ),
                    lambda value: (
                        events.append(("stringify-workdir", value))
                        or "WORKDIR"
                    ),
                )
            )

            def normalizer(
                values: Sequence[str],
            ) -> tuple[list[str], bool]:
                events.append(("normalize", values))
                return normalized, supplied_sandbox

            def normalizer_provider() -> object:
                events.append(("normalizer-provider", None))
                return normalizer

            def stringifier_provider() -> object:
                events.append(("stringifier-provider", None))
                return next(stringifiers)

            expected = [
                "REAL",
                "-C",
                "WORKDIR",
                "--disable",
                "multi_agent",
                "-c",
                "sandbox_workspace_write.writable_roots=[]",
                "-c",
                "sandbox_permissions=[]",
            ]
            if not supplied_sandbox:
                expected.extend(("--sandbox", "workspace-write"))
            expected.extend(normalized)

            with self.subTest(supplied_sandbox=supplied_sandbox):
                self.assertEqual(
                    self.adapter.codex_argv(
                        real_codex,
                        workdir,
                        arguments,
                        argument_normalizer=normalizer_provider,
                        stringifier=stringifier_provider,
                    ),
                    expected,
                )
                self.assertEqual(arguments, ("original",))
                self.assertEqual(
                    events,
                    [
                        ("normalizer-provider", None),
                        ("normalize", arguments),
                        ("stringifier-provider", None),
                        ("stringify-real", real_codex),
                        ("stringifier-provider", None),
                        ("stringify-workdir", workdir),
                    ],
                )

    def test_new_adapter_kernels_leave_dependency_failures_untranslated(
        self,
    ) -> None:
        class DependencyFailure(RuntimeError):
            pass

        failures = []

        scan_failure = DependencyFailure("scan length")

        def broken_length(_: object) -> int:
            raise scan_failure

        failures.append(
            (
                scan_failure,
                lambda: self.scan(
                    ["--help"],
                    flag_options=self.adapter.ROOT_FLAG_OPTIONS,
                    value_options=self.adapter.ROOT_VALUE_OPTIONS,
                    length=lambda: broken_length,
                ),
            )
        )

        normalize_failure = DependencyFailure("list factory")

        def broken_list_factory(_: Sequence[str]) -> list[str]:
            raise normalize_failure

        failures.append(
            (
                normalize_failure,
                lambda: self.normalize(
                    ["prompt"],
                    list_factory=lambda: broken_list_factory,
                ),
            )
        )

        argv_normalizer_failure = DependencyFailure("normalizer")

        def broken_normalizer(
            _: Sequence[str],
        ) -> tuple[list[str], bool]:
            raise argv_normalizer_failure

        failures.append(
            (
                argv_normalizer_failure,
                lambda: self.adapter.codex_argv(
                    Path("/codex"),
                    Path("/worktree"),
                    (),
                    argument_normalizer=lambda: broken_normalizer,
                    stringifier=lambda: str,
                ),
            )
        )

        stringify_failure = DependencyFailure("stringifier")

        def broken_stringifier(_: object) -> str:
            raise stringify_failure

        failures.append(
            (
                stringify_failure,
                lambda: self.adapter.codex_argv(
                    Path("/codex"),
                    Path("/worktree"),
                    (),
                    argument_normalizer=lambda: (
                        lambda _: ([], False)
                    ),
                    stringifier=lambda: broken_stringifier,
                ),
            )
        )

        for failure, operation in failures:
            with self.subTest(failure=str(failure)):
                with self.assertRaises(DependencyFailure) as caught:
                    operation()
                self.assertIs(caught.exception, failure)
                self.assertIsNone(caught.exception.__cause__)

    def test_new_engine_wrappers_resolve_rebound_globals_lazily(self) -> None:
        class InitialError(RuntimeError):
            pass

        class ReboundError(RuntimeError):
            pass

        initial_length = object()
        rebound_length = object()
        scanner_result = (7, True, False)
        arguments = ["--help"]
        flags = {"--help"}
        values = {"--model"}

        def scanner_kernel(
            received_arguments: list[str],
            start: int,
            received_flags: set[str],
            received_values: set[str],
            *,
            length: object,
            error_type: object,
        ) -> tuple[int, bool, bool]:
            self.assertIs(received_arguments, arguments)
            self.assertEqual(start, 3)
            self.assertIs(received_flags, flags)
            self.assertIs(received_values, values)
            self.engine.len = rebound_length
            self.engine.LauncherError = ReboundError
            self.assertIs(length(), rebound_length)
            self.assertIs(error_type(), ReboundError)
            return scanner_result

        with mock.patch.multiple(
            self.engine,
            _scan_allowed_options=scanner_kernel,
            len=initial_length,
            LauncherError=InitialError,
            create=True,
        ):
            self.assertIs(
                self.engine.scan_allowed_options(
                    arguments,
                    3,
                    flags,
                    values,
                ),
                scanner_result,
            )

        initial_values = {
            "list": object(),
            "len": object(),
            "scan_allowed_options": object(),
            "ROOT_FLAG_OPTIONS": object(),
            "ROOT_VALUE_OPTIONS": object(),
            "EXEC_FLAG_OPTIONS": object(),
            "EXEC_VALUE_OPTIONS": object(),
            "REVIEW_FLAG_OPTIONS": object(),
            "REVIEW_VALUE_OPTIONS": object(),
            "NON_AGENT_CODEX_COMMANDS": object(),
        }
        rebound_values = {
            name: object()
            for name in initial_values
        }
        normalize_result = (["normalized"], True)
        normalize_arguments = ("argument",)
        lifecycle_calls: list[str] = []

        def lifecycle_hint(action: str) -> str:
            lifecycle_calls.append(action)
            return "rebound reopen hint"

        rebound_profile = SimpleNamespace(
            lifecycle_hint=lifecycle_hint,
        )

        def normalize_kernel(
            received_arguments: object,
            **dependencies: object,
        ) -> tuple[list[str], bool]:
            self.assertIs(received_arguments, normalize_arguments)
            for name, value in rebound_values.items():
                setattr(self.engine, name, value)
            self.engine.active_profile = lambda: rebound_profile
            self.engine.LauncherError = ReboundError

            expected = {
                "list_factory": rebound_values["list"],
                "length": rebound_values["len"],
                "option_scanner": rebound_values[
                    "scan_allowed_options"
                ],
                "root_flag_options": rebound_values[
                    "ROOT_FLAG_OPTIONS"
                ],
                "root_value_options": rebound_values[
                    "ROOT_VALUE_OPTIONS"
                ],
                "exec_flag_options": rebound_values[
                    "EXEC_FLAG_OPTIONS"
                ],
                "exec_value_options": rebound_values[
                    "EXEC_VALUE_OPTIONS"
                ],
                "review_flag_options": rebound_values[
                    "REVIEW_FLAG_OPTIONS"
                ],
                "review_value_options": rebound_values[
                    "REVIEW_VALUE_OPTIONS"
                ],
                "non_agent_commands": rebound_values[
                    "NON_AGENT_CODEX_COMMANDS"
                ],
                "error_type": ReboundError,
            }
            self.assertEqual(set(dependencies), {*expected, "reopen_hint"})
            for name, value in expected.items():
                self.assertIs(dependencies[name](), value)
            self.assertEqual(
                dependencies["reopen_hint"](),
                "rebound reopen hint",
            )
            return normalize_result

        with mock.patch.multiple(
            self.engine,
            _normalize_codex_arguments=normalize_kernel,
            active_profile=lambda: self.fail(
                "initial active profile must not be captured"
            ),
            LauncherError=InitialError,
            create=True,
            **initial_values,
        ):
            self.assertIs(
                self.engine.normalize_codex_arguments(
                    normalize_arguments
                ),
                normalize_result,
            )
        self.assertEqual(lifecycle_calls, ["reopen"])

        initial_normalizer = object()
        rebound_normalizer = object()
        initial_stringifier = object()
        first_stringifier = object()
        second_stringifier = object()
        argv_result = ["argv"]
        argv_arguments = ("prompt",)
        argv_real = Path("/codex")
        argv_workdir = Path("/worktree")

        def argv_kernel(
            received_real: Path,
            received_workdir: Path,
            received_arguments: object,
            *,
            argument_normalizer: object,
            stringifier: object,
        ) -> list[str]:
            self.assertIs(received_real, argv_real)
            self.assertIs(received_workdir, argv_workdir)
            self.assertIs(received_arguments, argv_arguments)
            self.engine.normalize_codex_arguments = rebound_normalizer
            self.engine.str = first_stringifier
            self.assertIs(
                argument_normalizer(),
                rebound_normalizer,
            )
            self.assertIs(stringifier(), first_stringifier)
            self.engine.str = second_stringifier
            self.assertIs(stringifier(), second_stringifier)
            return argv_result

        with mock.patch.multiple(
            self.engine,
            _codex_argv=argv_kernel,
            normalize_codex_arguments=initial_normalizer,
            str=initial_stringifier,
            create=True,
        ):
            self.assertIs(
                self.engine.codex_argv(
                    argv_real,
                    argv_workdir,
                    argv_arguments,
                ),
                argv_result,
            )

    def test_environment_kernel_and_engine_wrapper_surfaces_are_exact(
        self,
    ) -> None:
        kernel = inspect.signature(
            self.adapter.codex_environment
        ).parameters
        self.assertEqual(
            tuple(kernel),
            (
                "real_codex",
                "profile",
                "sanitized_environment",
                "control_environments",
                "stringifier",
                "executable_path",
                "path_separator",
            ),
        )
        self.assertIs(
            kernel["real_codex"].kind,
            inspect.Parameter.POSITIONAL_OR_KEYWORD,
        )
        for name in tuple(kernel)[1:]:
            self.assertIs(
                kernel[name].kind,
                inspect.Parameter.KEYWORD_ONLY,
            )
        for parameter in kernel.values():
            self.assertIs(parameter.default, inspect.Parameter.empty)

        wrapper = inspect.signature(
            self.engine.codex_environment
        ).parameters
        self.assertEqual(tuple(wrapper), ("real_codex",))
        self.assertIs(
            wrapper["real_codex"].kind,
            inspect.Parameter.POSITIONAL_OR_KEYWORD,
        )
        self.assertIs(
            wrapper["real_codex"].default,
            inspect.Parameter.empty,
        )
        self.assertIs(
            self.engine._codex_environment,
            self.adapter.codex_environment,
        )

    def test_environment_transform_mutates_and_returns_the_sanitized_mapping(
        self,
    ) -> None:
        controls = (
            "INACTIVE_ROLE",
            ENVIRONMENT_NAME,
            "INACTIVE_REAL_CODEX",
        )
        source = {
            "KEEP": "value",
            "PATH": "inherited",
            "INACTIVE_ROLE": "worker",
            ENVIRONMENT_NAME: "/attacker/codex",
            "INACTIVE_REAL_CODEX": "/inactive/codex",
        }
        real_codex = Path("/selected/bin/codex")
        snapshots: list[dict[str, str]] = []

        def executable_path(
            environment: dict[str, str],
        ) -> list[str]:
            self.assertIs(environment, source)
            snapshots.append(dict(environment))
            return [
                "/other",
                "/selected/bin",
                "",
                "/other",
                "/selected/bin",
                "/third",
                "",
            ]

        observed = self.build_environment(
            real_codex,
            sanitized_environment=lambda: lambda: source,
            control_environments=lambda: controls,
            executable_path=lambda: executable_path,
            path_separator=lambda: "<>",
        )

        self.assertIs(observed, source)
        self.assertEqual(
            snapshots,
            [
                {
                    "KEEP": "value",
                    "PATH": "inherited",
                    ENVIRONMENT_NAME: str(real_codex),
                }
            ],
        )
        self.assertEqual(
            source,
            {
                "KEEP": "value",
                ENVIRONMENT_NAME: str(real_codex),
                "PATH": (
                    "/selected/bin<>/other<><>/other<>/third<>"
                ),
            },
        )

        relative = Path("relative/../codex")
        relative_environment = self.build_environment(
            relative,
            sanitized_environment=lambda: lambda: {},
            executable_path=lambda: (
                lambda _environment: [
                    "relative/..",
                    "",
                    "/elsewhere",
                    "relative/..",
                ]
            ),
            path_separator=lambda: "|",
        )
        self.assertEqual(
            relative_environment,
            {
                ENVIRONMENT_NAME: "relative/../codex",
                "PATH": "relative/..||/elsewhere",
            },
        )

        generic_profile = self.engine.BUILTIN_PROFILES["generic-v1"]
        inherited_controls = {
            name: f"inherited:{name}"
            for name in self.engine.CONTROL_ENVIRONMENTS
        }
        inherited_controls["PATH"] = "inherited-path"
        actual_controls = self.build_environment(
            real_codex,
            profile=generic_profile,
            sanitized_environment=lambda: lambda: inherited_controls,
            control_environments=lambda: (
                self.engine.CONTROL_ENVIRONMENTS
            ),
        )
        self.assertEqual(
            {
                name: actual_controls.get(name)
                for name in self.engine.CONTROL_ENVIRONMENTS
            },
            {
                name: (
                    str(real_codex)
                    if name == generic_profile.real_codex_environment
                    else None
                )
                for name in self.engine.CONTROL_ENVIRONMENTS
            },
        )

    def test_environment_transform_preserves_exact_evaluation_order(
        self,
    ) -> None:
        events: list[tuple[str, object]] = []
        real_parent = object()

        class RealCodex:
            @property
            def parent(real_self) -> object:
                events.append(("real-parent", None))
                return real_parent

        real_codex = RealCodex()

        class Profile:
            @property
            def real_codex_environment(profile_self) -> str:
                events.append(("profile-name", None))
                return ENVIRONMENT_NAME

        class Environment(dict):
            def pop(
                environment_self,
                name: str,
                default: object = None,
            ) -> object:
                events.append(("pop", name))
                return super().pop(name, default)

            def __setitem__(
                environment_self,
                name: str,
                value: str,
            ) -> None:
                events.append(("set", (name, value)))
                super().__setitem__(name, value)

        environment = Environment(
            {
                "FIRST": "one",
                ENVIRONMENT_NAME: "old",
                "PATH": "old-path",
            }
        )
        stringifiers = iter(
            (
                lambda value: (
                    events.append(("stringify-real", value))
                    or "REAL"
                ),
                lambda value: (
                    events.append(("stringify-parent", value))
                    or "PARENT"
                ),
            )
        )

        def sanitize() -> dict[str, str]:
            events.append(("sanitize", None))
            return environment

        def sanitized_environment() -> object:
            events.append(("sanitized-environment", None))
            return sanitize

        def control_environments() -> tuple[str, ...]:
            events.append(("control-environments", None))
            return ("FIRST", ENVIRONMENT_NAME)

        def stringifier() -> object:
            events.append(("stringifier-provider", None))
            return next(stringifiers)

        class PathEntry(str):
            def __ne__(entry_self, other: object) -> bool:
                events.append(("compare-entry", str(entry_self)))
                return super().__ne__(other)

        def get_exec_path(
            received: dict[str, str],
        ) -> list[str]:
            events.append(("executable-path-call", dict(received)))
            return [
                PathEntry("PARENT"),
                PathEntry(""),
                PathEntry("tail"),
            ]

        def executable_path() -> object:
            events.append(("executable-path-provider", None))
            return get_exec_path

        def path_separator() -> str:
            events.append(("path-separator", None))
            return ":"

        observed = self.build_environment(
            real_codex,
            profile=Profile(),
            sanitized_environment=sanitized_environment,
            control_environments=control_environments,
            stringifier=stringifier,
            executable_path=executable_path,
            path_separator=path_separator,
        )

        self.assertIs(observed, environment)
        self.assertEqual(
            events,
            [
                ("sanitized-environment", None),
                ("sanitize", None),
                ("control-environments", None),
                ("pop", "FIRST"),
                ("pop", ENVIRONMENT_NAME),
                ("stringifier-provider", None),
                ("stringify-real", real_codex),
                ("profile-name", None),
                ("set", (ENVIRONMENT_NAME, "REAL")),
                ("executable-path-provider", None),
                (
                    "executable-path-call",
                    {
                        "PATH": "old-path",
                        ENVIRONMENT_NAME: "REAL",
                    },
                ),
                ("stringifier-provider", None),
                ("real-parent", None),
                ("stringify-parent", real_parent),
                ("path-separator", None),
                ("compare-entry", "PARENT"),
                ("compare-entry", ""),
                ("compare-entry", "tail"),
                ("set", ("PATH", "PARENT::tail")),
            ],
        )

    def test_environment_transform_leaves_partial_mutation_on_failures(
        self,
    ) -> None:
        class DependencyFailure(RuntimeError):
            pass

        sanitize_failure = DependencyFailure("sanitize")

        def broken_sanitizer() -> dict[str, str]:
            raise sanitize_failure

        with self.assertRaises(DependencyFailure) as caught:
            self.build_environment(
                Path("/bin/codex"),
                sanitized_environment=lambda: broken_sanitizer,
            )
        self.assertIs(caught.exception, sanitize_failure)
        self.assertIsNone(caught.exception.__cause__)

        pop_failure = DependencyFailure("pop")

        class BrokenPopEnvironment(dict):
            def pop(
                environment_self,
                name: str,
                default: object = None,
            ) -> object:
                if name == "SECOND":
                    raise pop_failure
                return super().pop(name, default)

        pop_environment = BrokenPopEnvironment(
            {"FIRST": "one", "SECOND": "two", "PATH": "old"}
        )
        with self.assertRaises(DependencyFailure) as caught:
            self.build_environment(
                Path("/bin/codex"),
                sanitized_environment=lambda: lambda: pop_environment,
                control_environments=lambda: ("FIRST", "SECOND"),
            )
        self.assertIs(caught.exception, pop_failure)
        self.assertIsNone(caught.exception.__cause__)
        self.assertEqual(
            pop_environment,
            {"SECOND": "two", "PATH": "old"},
        )

        path_failure = DependencyFailure("executable path")
        path_environment = {
            "CONTROL": "value",
            ENVIRONMENT_NAME: "old",
            "PATH": "old",
        }

        def broken_executable_path(
            _environment: dict[str, str],
        ) -> list[str]:
            raise path_failure

        with self.assertRaises(DependencyFailure) as caught:
            self.build_environment(
                Path("/selected/codex"),
                sanitized_environment=lambda: lambda: path_environment,
                control_environments=lambda: (
                    "CONTROL",
                    ENVIRONMENT_NAME,
                ),
                executable_path=lambda: broken_executable_path,
            )
        self.assertIs(caught.exception, path_failure)
        self.assertIsNone(caught.exception.__cause__)
        self.assertEqual(
            path_environment,
            {
                ENVIRONMENT_NAME: "/selected/codex",
                "PATH": "old",
            },
        )

        separator_failure = DependencyFailure("separator")
        separator_environment = {"PATH": "old"}

        def broken_separator() -> str:
            raise separator_failure

        with self.assertRaises(DependencyFailure) as caught:
            self.build_environment(
                Path("/selected/codex"),
                sanitized_environment=lambda: (
                    lambda: separator_environment
                ),
                executable_path=lambda: lambda _environment: ["/tail"],
                path_separator=broken_separator,
            )
        self.assertIs(caught.exception, separator_failure)
        self.assertIsNone(caught.exception.__cause__)
        self.assertEqual(
            separator_environment,
            {
                ENVIRONMENT_NAME: "/selected/codex",
                "PATH": "old",
            },
        )

    def test_environment_engine_wrapper_captures_profile_and_rebinds_lazily(
        self,
    ) -> None:
        profile = object()
        real_codex = Path("/codex")
        kernel_result = {"result": "environment"}
        rebound_environment = {"rebound": "environment"}
        rebound_controls = object()
        first_stringifier = object()
        second_stringifier = object()
        rebound_executable_path = object()
        rebound_separator = object()

        def rebound_sanitizer() -> dict[str, str]:
            return rebound_environment

        def kernel(
            received_real: Path,
            **dependencies: object,
        ) -> dict[str, str]:
            self.assertIs(received_real, real_codex)
            self.assertIs(dependencies.pop("profile"), profile)
            self.engine.active_profile = lambda: self.fail(
                "active profile must be captured before the kernel"
            )
            self.engine.sanitized_git_environment = rebound_sanitizer
            self.engine.CONTROL_ENVIRONMENTS = rebound_controls
            self.engine.str = first_stringifier
            self.engine.os = SimpleNamespace(
                get_exec_path=rebound_executable_path,
                pathsep=object(),
            )

            self.assertIs(
                dependencies["sanitized_environment"](),
                rebound_sanitizer,
            )
            self.assertIs(rebound_sanitizer(), rebound_environment)
            self.assertIs(
                dependencies["control_environments"](),
                rebound_controls,
            )
            self.assertIs(
                dependencies["stringifier"](),
                first_stringifier,
            )
            self.engine.str = second_stringifier
            self.assertIs(
                dependencies["stringifier"](),
                second_stringifier,
            )
            self.assertIs(
                dependencies["executable_path"](),
                rebound_executable_path,
            )
            self.engine.os = SimpleNamespace(
                get_exec_path=object(),
                pathsep=rebound_separator,
            )
            self.assertIs(
                dependencies["path_separator"](),
                rebound_separator,
            )
            self.assertEqual(
                set(dependencies),
                {
                    "sanitized_environment",
                    "control_environments",
                    "stringifier",
                    "executable_path",
                    "path_separator",
                },
            )
            return kernel_result

        with (
            mock.patch.object(
                self.engine,
                "active_profile",
                return_value=profile,
            ) as active_profile,
            mock.patch.object(
                self.engine,
                "_codex_environment",
                side_effect=kernel,
            ) as adapter_kernel,
            mock.patch.object(
                self.engine,
                "sanitized_git_environment",
                return_value={"initial": "environment"},
            ),
            mock.patch.object(
                self.engine,
                "CONTROL_ENVIRONMENTS",
                object(),
            ),
            mock.patch.object(
                self.engine,
                "str",
                object(),
                create=True,
            ),
            mock.patch.object(
                self.engine,
                "os",
                SimpleNamespace(
                    get_exec_path=object(),
                    pathsep=object(),
                ),
            ),
        ):
            observed = self.engine.codex_environment(real_codex)

        self.assertIs(observed, kernel_result)
        active_profile.assert_called_once_with()
        adapter_kernel.assert_called_once()

    def test_environment_enrichment_kernel_and_call_surfaces_are_exact(
        self,
    ) -> None:
        kernel = inspect.signature(
            self.adapter.enrich_codex_environment
        ).parameters
        self.assertEqual(
            tuple(kernel),
            ("environment", "profile", "role", "manifest"),
        )
        self.assertIs(
            kernel["environment"].kind,
            inspect.Parameter.POSITIONAL_OR_KEYWORD,
        )
        for name in ("profile", "role", "manifest"):
            self.assertIs(
                kernel[name].kind,
                inspect.Parameter.KEYWORD_ONLY,
            )
        for parameter in kernel.values():
            self.assertIs(parameter.default, inspect.Parameter.empty)
        self.assertIs(
            self.engine._enrich_codex_environment,
            self.adapter.enrich_codex_environment,
        )

        surfaces = (
            (
                self.engine.child_environment,
                ("manifest", "real_codex"),
            ),
            (
                self.engine.resolver_environment,
                ("manifest", "real_codex"),
            ),
            (
                self.engine.pass_through_linked_worktree,
                ("repository", "real_codex", "arguments"),
            ),
        )
        for function, names in surfaces:
            with self.subTest(surface=function.__name__):
                parameters = inspect.signature(function).parameters
                self.assertEqual(tuple(parameters), names)
                for parameter in parameters.values():
                    self.assertIs(
                        parameter.kind,
                        inspect.Parameter.POSITIONAL_OR_KEYWORD,
                    )
                    self.assertIs(
                        parameter.default,
                        inspect.Parameter.empty,
                    )

    def test_environment_enrichment_covers_profiles_roles_and_pass_through(
        self,
    ) -> None:
        generic = self.engine.BUILTIN_PROFILES["generic-v1"]
        triptych = self.engine.BUILTIN_PROFILES["triptych"]
        manifest = {"run_id": "run-1", "tmpdir": "/run/tmp"}
        cases = (
            (
                "generic-worker",
                generic,
                "worker",
                manifest,
                {
                    generic.role_environment: "worker",
                    generic.run_id_environment: "run-1",
                    generic.profile_environment: generic.profile_id,
                    generic.agent_environment: generic.manifest_agent,
                    "TMPDIR": "/run/tmp",
                    "TMP": "/run/tmp",
                    "TEMP": "/run/tmp",
                },
            ),
            (
                "generic-resolver",
                generic,
                "resolver",
                manifest,
                {
                    generic.role_environment: "resolver",
                    generic.run_id_environment: "run-1",
                    generic.profile_environment: generic.profile_id,
                    generic.agent_environment: generic.manifest_agent,
                    "TMPDIR": "/run/tmp",
                    "TMP": "/run/tmp",
                    "TEMP": "/run/tmp",
                },
            ),
            (
                "triptych-worker",
                triptych,
                "worker",
                manifest,
                {
                    triptych.role_environment: "worker",
                    triptych.run_id_environment: "run-1",
                    "TMPDIR": "/run/tmp",
                    "TMP": "/run/tmp",
                    "TEMP": "/run/tmp",
                },
            ),
            (
                "triptych-resolver",
                triptych,
                "resolver",
                manifest,
                {
                    triptych.role_environment: "resolver",
                    triptych.run_id_environment: "run-1",
                    "TMPDIR": "/run/tmp",
                    "TMP": "/run/tmp",
                    "TEMP": "/run/tmp",
                },
            ),
            (
                "generic-pass-through",
                generic,
                "worker",
                None,
                {
                    generic.role_environment: "worker",
                    generic.profile_environment: generic.profile_id,
                    generic.agent_environment: generic.manifest_agent,
                },
            ),
            (
                "triptych-pass-through",
                triptych,
                "worker",
                None,
                {triptych.role_environment: "worker"},
            ),
        )
        for name, profile, role, supplied_manifest, expected in cases:
            environment = {
                "KEEP": "value",
                profile.role_environment: "old-role",
            }
            with self.subTest(case=name):
                observed = self.enrich_environment(
                    environment,
                    profile=profile,
                    role=role,
                    manifest=supplied_manifest,
                )
                self.assertIs(observed, environment)
                self.assertEqual(
                    environment,
                    {"KEEP": "value", **expected},
                )

    def test_environment_enrichment_preserves_exact_access_order(
        self,
    ) -> None:
        events: list[tuple[str, object]] = []

        class Environment(dict):
            def __setitem__(
                environment_self,
                name: str,
                value: str,
            ) -> None:
                events.append(("set", (name, value)))
                super().__setitem__(name, value)

        class Profile:
            @property
            def role_environment(profile_self) -> str:
                events.append(("profile", "role-environment"))
                return "ROLE"

            @property
            def run_id_environment(profile_self) -> str:
                events.append(("profile", "run-id-environment"))
                return "RUN_ID"

            @property
            def profile_environment(profile_self) -> str:
                events.append(("profile", "profile-environment"))
                return "PROFILE_ID"

            @property
            def profile_id(profile_self) -> str:
                events.append(("profile", "profile-id"))
                return "generic-v1"

            @property
            def agent_environment(profile_self) -> str:
                events.append(("profile", "agent-environment"))
                return "AGENT_ID"

            @property
            def manifest_agent(profile_self) -> str:
                events.append(("profile", "manifest-agent"))
                return "codex"

        class Manifest(dict):
            def __getitem__(
                manifest_self,
                name: str,
            ) -> str:
                events.append(("manifest", name))
                return super().__getitem__(name)

        environment = Environment()
        manifest = Manifest(
            run_id="run-1",
            tmpdir="/run/tmp",
        )
        observed = self.enrich_environment(
            environment,
            profile=Profile(),
            role="resolver",
            manifest=manifest,
        )

        self.assertIs(observed, environment)
        self.assertEqual(
            events,
            [
                ("profile", "role-environment"),
                ("set", ("ROLE", "resolver")),
                ("manifest", "run_id"),
                ("profile", "run-id-environment"),
                ("set", ("RUN_ID", "run-1")),
                ("profile", "profile-environment"),
                ("profile", "profile-id"),
                ("profile", "profile-environment"),
                ("set", ("PROFILE_ID", "generic-v1")),
                ("profile", "agent-environment"),
                ("profile", "manifest-agent"),
                ("profile", "manifest-agent"),
                ("profile", "agent-environment"),
                ("set", ("AGENT_ID", "codex")),
                ("manifest", "tmpdir"),
                ("set", ("TMPDIR", "/run/tmp")),
                ("manifest", "tmpdir"),
                ("set", ("TMP", "/run/tmp")),
                ("manifest", "tmpdir"),
                ("set", ("TEMP", "/run/tmp")),
            ],
        )

    def test_environment_enrichment_preserves_optional_short_circuits(
        self,
    ) -> None:
        events: list[str] = []

        class MinimalProfile:
            @property
            def role_environment(profile_self) -> str:
                events.append("role-environment")
                return "ROLE"

            @property
            def run_id_environment(profile_self) -> str:
                raise AssertionError(
                    "pass-through must not resolve the run-ID marker"
                )

            @property
            def profile_environment(profile_self) -> None:
                events.append("profile-environment")
                return None

            @property
            def profile_id(profile_self) -> str:
                raise AssertionError(
                    "absent profile marker must short-circuit profile ID"
                )

            @property
            def agent_environment(profile_self) -> None:
                events.append("agent-environment")
                return None

            @property
            def manifest_agent(profile_self) -> str:
                raise AssertionError(
                    "absent agent marker must short-circuit agent identity"
                )

        environment: dict[str, str] = {}
        self.assertIs(
            self.enrich_environment(
                environment,
                profile=MinimalProfile(),
                manifest=None,
            ),
            environment,
        )
        self.assertEqual(environment, {"ROLE": "worker"})
        self.assertEqual(
            events,
            [
                "role-environment",
                "profile-environment",
                "agent-environment",
            ],
        )

        class NoAgentProfile(MinimalProfile):
            @property
            def agent_environment(profile_self) -> str:
                events.append("agent-environment-present")
                return "AGENT_ID"

            @property
            def manifest_agent(profile_self) -> None:
                events.append("manifest-agent-none")
                return None

        events.clear()
        environment = {}
        self.enrich_environment(
            environment,
            profile=NoAgentProfile(),
            manifest=None,
        )
        self.assertEqual(environment, {"ROLE": "worker"})
        self.assertEqual(
            events,
            [
                "role-environment",
                "profile-environment",
                "agent-environment-present",
                "manifest-agent-none",
            ],
        )

        environment = {}
        with self.assertRaises(KeyError) as caught:
            self.enrich_environment(
                environment,
                profile=SimpleNamespace(
                    role_environment="ROLE",
                    run_id_environment="RUN_ID",
                    profile_environment=None,
                    profile_id="unused",
                    agent_environment=None,
                    manifest_agent=None,
                ),
                manifest={},
            )
        self.assertEqual(caught.exception.args, ("run_id",))
        self.assertEqual(environment, {"ROLE": "worker"})

    def test_environment_enrichment_leaves_partial_mutation_on_failure(
        self,
    ) -> None:
        class DependencyFailure(RuntimeError):
            pass

        set_failure = DependencyFailure("profile marker")

        class BrokenEnvironment(dict):
            def __setitem__(
                environment_self,
                name: str,
                value: str,
            ) -> None:
                if name == "PROFILE_ID":
                    raise set_failure
                super().__setitem__(name, value)

        environment = BrokenEnvironment()
        with self.assertRaises(DependencyFailure) as caught:
            self.enrich_environment(
                environment,
                manifest={"run_id": "run-1", "tmpdir": "/run/tmp"},
            )
        self.assertIs(caught.exception, set_failure)
        self.assertIsNone(caught.exception.__cause__)
        self.assertEqual(
            environment,
            {"ROLE": "worker", "RUN_ID": "run-1"},
        )

        tmp_failure = DependencyFailure("second tmpdir read")

        class BrokenManifest(dict):
            temporary_reads = 0

            def __getitem__(
                manifest_self,
                name: str,
            ) -> str:
                if name == "tmpdir":
                    manifest_self.temporary_reads += 1
                    if manifest_self.temporary_reads == 2:
                        raise tmp_failure
                return super().__getitem__(name)

        environment = {}
        with self.assertRaises(DependencyFailure) as caught:
            self.enrich_environment(
                environment,
                manifest=BrokenManifest(
                    run_id="run-1",
                    tmpdir="/run/tmp",
                ),
            )
        self.assertIs(caught.exception, tmp_failure)
        self.assertIsNone(caught.exception.__cause__)
        self.assertEqual(
            environment,
            {
                "ROLE": "worker",
                "RUN_ID": "run-1",
                "PROFILE_ID": "generic-v1",
                "AGENT_ID": "codex",
                "TMPDIR": "/run/tmp",
            },
        )

    def test_managed_environment_wrappers_preserve_double_profile_lookup(
        self,
    ) -> None:
        real_codex = Path("/codex")
        manifest = {"run_id": "run-1", "tmpdir": "/run/tmp"}
        for wrapper_name, role in (
            ("child_environment", "worker"),
            ("resolver_environment", "resolver"),
        ):
            events: list[tuple[str, object]] = []
            outer_profile = object()
            base_profile = object()
            profiles = iter(
                (
                    ("outer", outer_profile),
                    ("base", base_profile),
                )
            )
            base_environment = {"base": "environment"}
            enriched_environment = {"enriched": "environment"}

            def active_profile() -> object:
                label, profile = next(profiles)
                events.append(("active-profile", label))
                return profile

            def enricher(
                environment: dict[str, str],
                *,
                profile: object,
                role: str,
                manifest: object,
            ) -> dict[str, str]:
                events.append(("enrich", role))
                self.assertIs(environment, base_environment)
                self.assertIs(profile, outer_profile)
                self.assertIs(manifest, manifest_argument)
                return enriched_environment

            def base_kernel(
                received_real: Path,
                **dependencies: object,
            ) -> dict[str, str]:
                events.append(("base-kernel", received_real))
                self.assertIs(
                    dependencies.pop("profile"),
                    base_profile,
                )
                self.assertEqual(
                    set(dependencies),
                    {
                        "sanitized_environment",
                        "control_environments",
                        "stringifier",
                        "executable_path",
                        "path_separator",
                    },
                )
                self.engine._enrich_codex_environment = enricher
                return base_environment

            manifest_argument = manifest
            with (
                self.subTest(wrapper=wrapper_name),
                mock.patch.object(
                    self.engine,
                    "active_profile",
                    side_effect=active_profile,
                ) as profile_lookup,
                mock.patch.object(
                    self.engine,
                    "_codex_environment",
                    side_effect=base_kernel,
                ),
                mock.patch.object(
                    self.engine,
                    "_enrich_codex_environment",
                    side_effect=AssertionError(
                        "enricher resolved before base environment"
                    ),
                ),
            ):
                observed = getattr(
                    self.engine,
                    wrapper_name,
                )(manifest_argument, real_codex)

            self.assertIs(observed, enriched_environment)
            self.assertEqual(
                events,
                [
                    ("active-profile", "outer"),
                    ("active-profile", "base"),
                    ("base-kernel", real_codex),
                    ("enrich", role),
                ],
            )
            self.assertEqual(profile_lookup.call_count, 2)

    def test_pass_through_enriches_after_checks_argv_and_base_environment(
        self,
    ) -> None:
        class ExecveReached(RuntimeError):
            pass

        events: list[tuple[str, object]] = []
        outer_profile = SimpleNamespace(
            role_environment="ROLE",
            profile_environment="PROFILE_ID",
            profile_id="generic-v1",
            agent_environment="AGENT_ID",
            manifest_agent="codex",
        )
        base_profile = object()
        profiles = iter(
            (
                ("outer", outer_profile),
                ("base", base_profile),
            )
        )
        repository = SimpleNamespace(
            root=Path("/repository"),
            relative_cwd=Path("subdirectory"),
        )
        real_codex = Path("/codex")
        arguments = ("prompt",)
        argv = ["argv"]
        base_environment = {"base": "environment"}
        enriched_environment = {"enriched": "environment"}
        reached = ExecveReached("execve")

        class Environment(dict):
            def get(
                environment_self,
                name: str,
                default: object = None,
            ) -> object:
                events.append(("environment-get", name))
                return super().get(name, default)

        inherited = Environment()

        def active_profile() -> object:
            label, profile = next(profiles)
            events.append(("active-profile", label))
            return profile

        def registered_record(
            received_repository: object,
            worktree: Path,
        ) -> None:
            events.append(("registered-record", worktree))
            self.assertIs(received_repository, repository)
            return None

        def git(
            cwd: Path,
            *received_arguments: str,
            **options: object,
        ) -> object:
            events.append(("git", (cwd, received_arguments, options)))
            return SimpleNamespace(stdout="")

        def build_argv(
            received_real: Path,
            workdir: Path,
            received_arguments: Sequence[str],
        ) -> list[str]:
            events.append(("argv", workdir))
            self.assertIs(received_real, real_codex)
            self.assertIs(received_arguments, arguments)
            return argv

        def enricher(
            environment: dict[str, str],
            *,
            profile: object,
            role: str,
            manifest: object | None,
        ) -> dict[str, str]:
            events.append(("enrich", manifest))
            self.assertIs(environment, base_environment)
            self.assertIs(profile, outer_profile)
            self.assertEqual(role, "worker")
            self.assertIsNone(manifest)
            return enriched_environment

        def base_kernel(
            received_real: Path,
            **dependencies: object,
        ) -> dict[str, str]:
            events.append(("base-kernel", received_real))
            self.assertIs(
                dependencies.pop("profile"),
                base_profile,
            )
            self.engine._enrich_codex_environment = enricher
            return base_environment

        def execve(
            received_real: Path,
            received_argv: list[str],
            environment: dict[str, str],
        ) -> None:
            events.append(("execve", None))
            self.assertIs(received_real, real_codex)
            self.assertIs(received_argv, argv)
            self.assertIs(environment, enriched_environment)
            raise reached

        fake_os = SimpleNamespace(
            environ=inherited,
            get_exec_path=object(),
            pathsep=object(),
            execve=execve,
        )
        with (
            mock.patch.object(
                self.engine,
                "active_profile",
                side_effect=active_profile,
            ),
            mock.patch.object(
                self.engine,
                "registered_record",
                side_effect=registered_record,
            ),
            mock.patch.object(
                self.engine,
                "git",
                side_effect=git,
            ),
            mock.patch.object(
                self.engine,
                "codex_argv",
                side_effect=build_argv,
            ),
            mock.patch.object(
                self.engine,
                "_codex_environment",
                side_effect=base_kernel,
            ),
            mock.patch.object(
                self.engine,
                "_enrich_codex_environment",
                side_effect=AssertionError(
                    "enricher resolved before base environment"
                ),
            ),
            mock.patch.object(
                self.engine,
                "MANAGED_CONTEXT_ENVIRONMENTS",
                ("MANAGED_ONE", "MANAGED_TWO"),
            ),
            mock.patch.object(self.engine, "os", fake_os),
        ):
            with self.assertRaises(ExecveReached) as caught:
                self.engine.pass_through_linked_worktree(
                    repository,
                    real_codex,
                    arguments,
                )

        self.assertIs(caught.exception, reached)
        self.assertEqual(
            events,
            [
                ("active-profile", "outer"),
                ("environment-get", "ROLE"),
                ("environment-get", "PROFILE_ID"),
                ("environment-get", "AGENT_ID"),
                ("registered-record", repository.root),
                (
                    "git",
                    (
                        repository.root,
                        (
                            "symbolic-ref",
                            "--quiet",
                            "--short",
                            "HEAD",
                        ),
                        {"check": False},
                    ),
                ),
                ("environment-get", "MANAGED_ONE"),
                ("environment-get", "MANAGED_TWO"),
                (
                    "argv",
                    repository.root / repository.relative_cwd,
                ),
                ("active-profile", "base"),
                ("base-kernel", real_codex),
                ("enrich", None),
                ("execve", None),
            ],
        )

    def test_real_filesystem_override_and_path_behavior(self) -> None:
        class SelectionError(RuntimeError):
            pass

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            launcher_path = root / "launcher"
            launcher_path.write_text("#!/bin/sh\nexit 0\n")
            launcher_path.chmod(0o755)
            launcher_metadata = launcher_path.stat()
            launcher = SimpleNamespace(
                device=launcher_metadata.st_dev,
                inode=launcher_metadata.st_ino,
            )

            executable = root / "real-codex"
            executable.write_text("#!/bin/sh\nexit 0\n")
            executable.chmod(0o755)
            observed = self.select(
                launcher=launcher,
                environment=lambda: {
                    ENVIRONMENT_NAME: str(executable)
                },
                error_type=lambda: SelectionError,
            )
            self.assertEqual(observed, executable.absolute())

            bin_directory = root / "bin"
            bin_directory.mkdir()
            path_executable = bin_directory / "codex"
            path_executable.write_text("#!/bin/sh\nexit 0\n")
            path_executable.chmod(0o755)
            observed = self.select(
                launcher=launcher,
                environment=lambda: {},
                executable_path=lambda: (
                    lambda: [str(bin_directory)]
                ),
                error_type=lambda: SelectionError,
            )
            self.assertEqual(observed, path_executable.absolute())

            hardlink = root / "hardlink"
            symlink = root / "symlink"
            os.link(launcher_path, hardlink)
            symlink.symlink_to(launcher_path)
            for candidate in (launcher_path, hardlink, symlink):
                with self.subTest(candidate=candidate.name):
                    with self.assertRaisesRegex(
                        SelectionError,
                        f"^{ENVIRONMENT_NAME} does not name a usable "
                        "non-launcher executable$",
                    ):
                        self.select(
                            launcher=launcher,
                            environment=lambda candidate=candidate: {
                                ENVIRONMENT_NAME: str(candidate)
                            },
                            error_type=lambda: SelectionError,
                        )


if __name__ == "__main__":
    unittest.main()
