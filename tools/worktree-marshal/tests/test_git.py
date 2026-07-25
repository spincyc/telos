#!/usr/bin/env python3
"""Direct parity tests for Git executable and invocation-policy seams."""

from __future__ import annotations

import importlib
import inspect
import os
import re
import shutil
import stat
import subprocess
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock


PACKAGE_ROOT = Path(__file__).resolve().parents[1]
SOURCE_ROOT = PACKAGE_ROOT / "src"
EXPECTED_UNSAFE_GIT_ENV = frozenset(
    {
        "GIT_ALTERNATE_OBJECT_DIRECTORIES",
        "GIT_ASKPASS",
        "GIT_ATTR_GLOBAL",
        "GIT_ATTR_SOURCE",
        "GIT_ATTR_SYSTEM",
        "GIT_CEILING_DIRECTORIES",
        "GIT_COMMON_DIR",
        "GIT_CONFIG",
        "GIT_CONFIG_COUNT",
        "GIT_CONFIG_GLOBAL",
        "GIT_CONFIG_NOSYSTEM",
        "GIT_CONFIG_PARAMETERS",
        "GIT_CONFIG_SYSTEM",
        "GIT_DIFF_OPTS",
        "GIT_DIR",
        "GIT_DISCOVERY_ACROSS_FILESYSTEM",
        "GIT_EDITOR",
        "GIT_EXEC_PATH",
        "GIT_EXTERNAL_DIFF",
        "GIT_EXTERNAL_DIFF_TRUST_EXIT_CODE",
        "GIT_GLOB_PATHSPECS",
        "GIT_GRAFT_FILE",
        "GIT_ICASE_PATHSPECS",
        "GIT_IMPLICIT_WORK_TREE",
        "GIT_INDEX_FILE",
        "GIT_LITERAL_PATHSPECS",
        "GIT_MERGE_AUTOEDIT",
        "GIT_NAMESPACE",
        "GIT_NOGLOB_PATHSPECS",
        "GIT_NO_REPLACE_OBJECTS",
        "GIT_OBJECT_DIRECTORY",
        "GIT_OPTIONAL_LOCKS",
        "GIT_PREFIX",
        "GIT_PROXY_COMMAND",
        "GIT_QUARANTINE_PATH",
        "GIT_REDIRECT_STDERR",
        "GIT_REDIRECT_STDIN",
        "GIT_REDIRECT_STDOUT",
        "GIT_REPLACE_REF_BASE",
        "GIT_SEQUENCE_EDITOR",
        "GIT_SHALLOW_FILE",
        "GIT_SHELL_PATH",
        "GIT_SSH",
        "GIT_SSH_COMMAND",
        "GIT_SSH_VARIANT",
        "GIT_TEMPLATE_DIR",
        "GIT_WORK_TREE",
    }
)


class GitPolicyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        sys.path.insert(0, str(SOURCE_ROOT))
        cls.policy = importlib.import_module("worktree_marshal.git")
        cls.engine = importlib.import_module("worktree_marshal.engine")

    @classmethod
    def tearDownClass(cls) -> None:
        try:
            sys.path.remove(str(SOURCE_ROOT))
        except ValueError:
            pass

    def validate_output(
        self,
        output: bytes,
        *,
        boolean_values: set[str] | None = None,
        command_config_pattern: re.Pattern[str] | None = None,
    ) -> None:
        class PolicyError(RuntimeError):
            pass

        self.policy.validate_effective_git_configuration(
            output,
            error_type=lambda: PolicyError,
            boolean_values=lambda: (
                self.policy.GIT_BOOLEAN_VALUES
                if boolean_values is None
                else boolean_values
            ),
            command_config_pattern=lambda: (
                self.policy.GIT_COMMAND_CONFIG_RE
                if command_config_pattern is None
                else command_config_pattern
            ),
        )

    def test_policy_import_does_not_load_the_lifecycle_engine(self) -> None:
        script = (
            "import os, sys; "
            "before = dict(os.environ); "
            f"sys.path.insert(0, {str(SOURCE_ROOT)!r}); "
            "import worktree_marshal.git; "
            "raise SystemExit("
            "'worktree_marshal.engine' in sys.modules or dict(os.environ) != before"
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

    def test_engine_preserves_the_existing_policy_surface(self) -> None:
        self.assertIs(
            self.engine.hardened_git_arguments,
            self.policy.hardened_git_arguments,
        )
        self.assertIs(self.engine.GIT_BASE_ARGUMENTS, self.policy.GIT_BASE_ARGUMENTS)
        self.assertIs(
            self.engine.GIT_BOOLEAN_VALUES,
            self.policy.GIT_BOOLEAN_VALUES,
        )
        self.assertIs(
            self.engine.GIT_COMMAND_CONFIG_RE,
            self.policy.GIT_COMMAND_CONFIG_RE,
        )
        self.assertIs(
            self.engine.GIT_INDEXED_CONFIG_ENV_RE,
            self.policy.GIT_INDEXED_CONFIG_ENV_RE,
        )
        self.assertIs(self.engine.GIT_UNSAFE_ENV, self.policy.GIT_UNSAFE_ENV)
        self.assertIsNot(
            self.engine.validate_effective_git_configuration,
            self.policy.validate_effective_git_configuration,
        )
        parameters = inspect.signature(
            self.engine.validate_effective_git_configuration
        ).parameters
        self.assertEqual(tuple(parameters), ("cwd",))
        self.assertIs(
            parameters["cwd"].kind,
            inspect.Parameter.POSITIONAL_OR_KEYWORD,
        )
        self.assertIs(parameters["cwd"].default, inspect.Parameter.empty)
        source = {"KEEP": "yes", "GIT_DIR": "/hostile"}
        self.assertEqual(
            self.engine.sanitized_git_environment(source),
            self.policy.sanitized_git_environment(source),
        )

    def test_git_executable_discovery_surface_is_exact(self) -> None:
        self.assertIs(
            self.engine._discover_git_executable,
            self.policy.discover_git_executable,
        )
        parameters = inspect.signature(
            self.policy.discover_git_executable
        ).parameters
        self.assertEqual(
            tuple(parameters),
            (
                "executable_locator",
                "path_factory",
                "os_error_type",
                "error_type",
                "regular_file_test",
                "access_check",
                "executable_mode",
            ),
        )
        for parameter in parameters.values():
            self.assertIs(parameter.kind, inspect.Parameter.KEYWORD_ONLY)
            self.assertIs(parameter.default, inspect.Parameter.empty)
        self.assertEqual(
            tuple(inspect.signature(self.engine.pin_git_executable).parameters),
            (),
        )

    def test_git_executable_discovery_success_order_is_exact(self) -> None:
        events: list[object] = []
        candidate = ""
        metadata_mode = object()
        executable_mode = object()

        class TruthValue:
            def __init__(truth_self, label: str) -> None:
                truth_self.label = label

            def __bool__(truth_self) -> bool:
                events.append(("truth", truth_self.label))
                return True

        class Metadata:
            @property
            def st_mode(metadata_self) -> object:
                events.append("metadata-mode")
                return metadata_mode

        class ResolvedPath:
            @property
            def stat(path_self) -> object:
                events.append("stat-attribute")

                def read_metadata() -> Metadata:
                    events.append("stat-call")
                    return Metadata()

                return read_metadata

        resolved = ResolvedPath()

        class CandidatePath:
            @property
            def resolve(path_self) -> object:
                events.append("resolve-attribute")

                def resolve_path(*, strict: bool) -> ResolvedPath:
                    events.append(("resolve-call", strict))
                    return resolved

                return resolve_path

        def executable_locator() -> object:
            events.append("locator-provider")

            def locate(name: str) -> str:
                events.append(("locator-call", name))
                return candidate

            return locate

        def path_factory() -> object:
            events.append("path-provider")

            def make_path(value: str) -> CandidatePath:
                events.append(("path-call", value))
                return CandidatePath()

            return make_path

        def regular_file_test() -> object:
            events.append("regular-provider")

            def is_regular(mode: object) -> object:
                events.append(("regular-call", mode))
                return TruthValue("regular")

            return is_regular

        def access_check() -> object:
            events.append("access-provider")

            def is_executable(path: object, mode: object) -> object:
                events.append(("access-call", path, mode))
                return TruthValue("executable")

            return is_executable

        def resolve_executable_mode() -> object:
            events.append("executable-mode-provider")
            return executable_mode

        blocked_os_error_type = mock.Mock(
            side_effect=AssertionError("resolved the OS error type on success")
        )
        blocked_error_type = mock.Mock(
            side_effect=AssertionError("resolved the launcher error on success")
        )

        observed = self.policy.discover_git_executable(
            executable_locator=executable_locator,
            path_factory=path_factory,
            os_error_type=blocked_os_error_type,
            error_type=blocked_error_type,
            regular_file_test=regular_file_test,
            access_check=access_check,
            executable_mode=resolve_executable_mode,
        )

        self.assertIs(observed, resolved)
        self.assertEqual(
            events,
            [
                "locator-provider",
                ("locator-call", "git"),
                "path-provider",
                ("path-call", candidate),
                "resolve-attribute",
                ("resolve-call", True),
                "stat-attribute",
                "stat-call",
                "regular-provider",
                "metadata-mode",
                ("regular-call", metadata_mode),
                ("truth", "regular"),
                "access-provider",
                "executable-mode-provider",
                ("access-call", resolved, executable_mode),
                ("truth", "executable"),
            ],
        )
        blocked_os_error_type.assert_not_called()
        blocked_error_type.assert_not_called()

    def test_git_executable_locator_boundaries_are_exact(self) -> None:
        class DiscoveryError(RuntimeError):
            pass

        path_factory = mock.Mock(
            side_effect=AssertionError("constructed a path without a candidate")
        )
        os_error_type = mock.Mock(
            side_effect=AssertionError("matched a locator failure")
        )
        error_type = mock.Mock(return_value=DiscoveryError)
        locator = mock.Mock(return_value=None)

        with self.assertRaises(DiscoveryError) as caught:
            self.policy.discover_git_executable(
                executable_locator=lambda: locator,
                path_factory=path_factory,
                os_error_type=os_error_type,
                error_type=error_type,
                regular_file_test=mock.Mock(),
                access_check=mock.Mock(),
                executable_mode=mock.Mock(),
            )

        self.assertEqual(str(caught.exception), "cannot find the Git executable")
        self.assertIsNone(caught.exception.__cause__)
        locator.assert_called_once_with("git")
        path_factory.assert_not_called()
        os_error_type.assert_not_called()
        error_type.assert_called_once_with()

        for phase in ("provider", "call"):
            with self.subTest(locator_failure=phase):
                failure = OSError(f"locator-{phase}")
                locator = mock.Mock(side_effect=failure)

                def executable_locator() -> object:
                    if phase == "provider":
                        raise failure
                    return locator

                blocked = mock.Mock(
                    side_effect=AssertionError("translated a locator failure")
                )
                with self.assertRaises(OSError) as locator_caught:
                    self.policy.discover_git_executable(
                        executable_locator=executable_locator,
                        path_factory=blocked,
                        os_error_type=blocked,
                        error_type=blocked,
                        regular_file_test=blocked,
                        access_check=blocked,
                        executable_mode=blocked,
                    )

                self.assertIs(locator_caught.exception, failure)
                if phase == "provider":
                    locator.assert_not_called()
                else:
                    locator.assert_called_once_with("git")

    def test_git_executable_resolution_catch_scope_and_cause_are_exact(
        self,
    ) -> None:
        class ResolutionOSError(OSError):
            pass

        class DiscoveryError(RuntimeError):
            pass

        expected_prefixes = {
            "path-provider": [
                "locator-provider",
                "locator-call",
                "path-provider",
            ],
            "path-call": [
                "locator-provider",
                "locator-call",
                "path-provider",
                "path-call",
            ],
            "resolve-attribute": [
                "locator-provider",
                "locator-call",
                "path-provider",
                "path-call",
                "resolve-attribute",
            ],
            "resolve-call": [
                "locator-provider",
                "locator-call",
                "path-provider",
                "path-call",
                "resolve-attribute",
                "resolve-call",
            ],
            "stat-attribute": [
                "locator-provider",
                "locator-call",
                "path-provider",
                "path-call",
                "resolve-attribute",
                "resolve-call",
                "stat-attribute",
            ],
            "stat-call": [
                "locator-provider",
                "locator-call",
                "path-provider",
                "path-call",
                "resolve-attribute",
                "resolve-call",
                "stat-attribute",
                "stat-call",
            ],
        }

        for phase, expected_prefix in expected_prefixes.items():
            with self.subTest(resolution_failure=phase):
                events: list[str] = []
                failure = ResolutionOSError(phase)

                def fail_at(observed: str) -> None:
                    events.append(observed)
                    if phase == observed:
                        raise failure

                class ResolvedPath:
                    @property
                    def stat(path_self) -> object:
                        fail_at("stat-attribute")

                        def read_metadata() -> object:
                            fail_at("stat-call")
                            return SimpleNamespace(st_mode=0)

                        return read_metadata

                class CandidatePath:
                    @property
                    def resolve(path_self) -> object:
                        fail_at("resolve-attribute")

                        def resolve_path(*, strict: bool) -> ResolvedPath:
                            self.assertTrue(strict)
                            fail_at("resolve-call")
                            return ResolvedPath()

                        return resolve_path

                def executable_locator() -> object:
                    events.append("locator-provider")

                    def locate(name: str) -> str:
                        self.assertEqual(name, "git")
                        events.append("locator-call")
                        return "candidate"

                    return locate

                def path_factory() -> object:
                    fail_at("path-provider")

                    def make_path(candidate: str) -> CandidatePath:
                        self.assertEqual(candidate, "candidate")
                        fail_at("path-call")
                        return CandidatePath()

                    return make_path

                def os_error_type() -> type[BaseException]:
                    events.append("os-error-type")
                    return ResolutionOSError

                def error_type() -> type[BaseException]:
                    events.append("error-type")
                    return DiscoveryError

                blocked = mock.Mock(
                    side_effect=AssertionError(
                        "validated a path after resolution failed"
                    )
                )
                with self.assertRaises(DiscoveryError) as caught:
                    self.policy.discover_git_executable(
                        executable_locator=executable_locator,
                        path_factory=path_factory,
                        os_error_type=os_error_type,
                        error_type=error_type,
                        regular_file_test=blocked,
                        access_check=blocked,
                        executable_mode=blocked,
                    )

                self.assertEqual(
                    str(caught.exception),
                    "cannot resolve the Git executable",
                )
                self.assertIs(caught.exception.__cause__, failure)
                self.assertIs(caught.exception.__context__, failure)
                self.assertEqual(
                    events,
                    expected_prefix + ["os-error-type", "error-type"],
                )

    def test_git_executable_resolution_only_catches_the_selected_error(
        self,
    ) -> None:
        class SelectedOSError(OSError):
            pass

        failure = RuntimeError("not selected")
        os_error_type = mock.Mock(return_value=SelectedOSError)
        blocked_error_type = mock.Mock(
            side_effect=AssertionError("translated a nonmatching error")
        )

        with self.assertRaises(RuntimeError) as caught:
            self.policy.discover_git_executable(
                executable_locator=lambda: lambda name: "candidate",
                path_factory=lambda: (_ for _ in ()).throw(failure),
                os_error_type=os_error_type,
                error_type=blocked_error_type,
                regular_file_test=mock.Mock(),
                access_check=mock.Mock(),
                executable_mode=mock.Mock(),
            )

        self.assertIs(caught.exception, failure)
        os_error_type.assert_called_once_with()
        blocked_error_type.assert_not_called()

        matching_failure = SelectedOSError("original")
        matcher_failure = LookupError("cannot resolve matcher")

        def broken_os_error_type() -> type[BaseException]:
            raise matcher_failure

        with self.assertRaises(LookupError) as matcher_caught:
            self.policy.discover_git_executable(
                executable_locator=lambda: lambda name: "candidate",
                path_factory=lambda: (
                    _ for _ in ()
                ).throw(matching_failure),
                os_error_type=broken_os_error_type,
                error_type=blocked_error_type,
                regular_file_test=mock.Mock(),
                access_check=mock.Mock(),
                executable_mode=mock.Mock(),
            )

        self.assertIs(matcher_caught.exception, matcher_failure)
        blocked_error_type.assert_not_called()

    def test_git_executable_validation_short_circuits_with_exact_error(
        self,
    ) -> None:
        class DiscoveryError(RuntimeError):
            pass

        resolved = SimpleNamespace()
        candidate_path = SimpleNamespace(
            resolve=lambda *, strict: resolved,
        )
        resolved.stat = lambda: SimpleNamespace(st_mode=17)

        regular_test = mock.Mock(return_value=False)
        blocked_access = mock.Mock(
            side_effect=AssertionError("checked access for a non-regular file")
        )
        blocked_mode = mock.Mock(
            side_effect=AssertionError(
                "resolved executable mode for a non-regular file"
            )
        )
        error_type = mock.Mock(return_value=DiscoveryError)
        os_error_type = mock.Mock(return_value=OSError)

        with self.assertRaises(DiscoveryError) as nonregular_caught:
            self.policy.discover_git_executable(
                executable_locator=lambda: lambda name: "candidate",
                path_factory=lambda: lambda candidate: candidate_path,
                os_error_type=os_error_type,
                error_type=error_type,
                regular_file_test=lambda: regular_test,
                access_check=blocked_access,
                executable_mode=blocked_mode,
            )

        self.assertEqual(
            str(nonregular_caught.exception),
            "the resolved Git executable is not a regular executable file",
        )
        self.assertIsNone(nonregular_caught.exception.__cause__)
        regular_test.assert_called_once_with(17)
        blocked_access.assert_not_called()
        blocked_mode.assert_not_called()
        os_error_type.assert_not_called()

        class ReboundDiscoveryError(RuntimeError):
            pass

        selected_error: list[type[RuntimeError]] = [DiscoveryError]

        class RebindingFalse:
            def __bool__(truth_self) -> bool:
                selected_error[0] = ReboundDiscoveryError
                return False

        executable_mode = object()
        regular_test = mock.Mock(return_value=True)
        access_test = mock.Mock(return_value=RebindingFalse())
        error_type = mock.Mock(side_effect=lambda: selected_error[0])

        with self.assertRaises(ReboundDiscoveryError) as inaccessible_caught:
            self.policy.discover_git_executable(
                executable_locator=lambda: lambda name: "candidate",
                path_factory=lambda: lambda candidate: candidate_path,
                os_error_type=os_error_type,
                error_type=error_type,
                regular_file_test=lambda: regular_test,
                access_check=lambda: access_test,
                executable_mode=lambda: executable_mode,
            )

        self.assertEqual(
            str(inaccessible_caught.exception),
            "the resolved Git executable is not a regular executable file",
        )
        self.assertIsNone(inaccessible_caught.exception.__cause__)
        regular_test.assert_called_once_with(17)
        access_test.assert_called_once_with(resolved, executable_mode)
        error_type.assert_called_once_with()
        os_error_type.assert_not_called()

    def test_git_executable_validation_errors_stay_outside_resolution_catch(
        self,
    ) -> None:
        phases = (
            "regular-provider",
            "metadata-mode",
            "regular-call",
            "regular-truth",
            "access-provider",
            "executable-mode-provider",
            "access-call",
            "access-truth",
        )

        for phase in phases:
            with self.subTest(validation_failure=phase):
                failure = OSError(phase)

                class ExplodingTruth:
                    def __bool__(truth_self) -> bool:
                        raise failure

                def fail_at(observed: str) -> None:
                    if phase == observed:
                        raise failure

                class Metadata:
                    @property
                    def st_mode(metadata_self) -> int:
                        fail_at("metadata-mode")
                        return 17

                resolved = SimpleNamespace(stat=lambda: Metadata())
                candidate_path = SimpleNamespace(
                    resolve=lambda *, strict: resolved,
                )

                def regular_file_test() -> object:
                    fail_at("regular-provider")

                    def is_regular(mode: int) -> bool:
                        fail_at("regular-call")
                        if phase == "regular-truth":
                            return ExplodingTruth()
                        return True

                    return is_regular

                def access_check() -> object:
                    fail_at("access-provider")

                    def is_executable(path: object, mode: object) -> bool:
                        fail_at("access-call")
                        if phase == "access-truth":
                            return ExplodingTruth()
                        return True

                    return is_executable

                def executable_mode() -> int:
                    fail_at("executable-mode-provider")
                    return 1

                os_error_type = mock.Mock(return_value=OSError)
                error_type = mock.Mock(
                    side_effect=AssertionError(
                        "translated a post-resolution failure"
                    )
                )

                with self.assertRaises(OSError) as caught:
                    self.policy.discover_git_executable(
                        executable_locator=lambda: lambda name: "candidate",
                        path_factory=lambda: lambda candidate: candidate_path,
                        os_error_type=os_error_type,
                        error_type=error_type,
                        regular_file_test=regular_file_test,
                        access_check=access_check,
                        executable_mode=executable_mode,
                    )

                self.assertIs(caught.exception, failure)
                os_error_type.assert_not_called()
                error_type.assert_not_called()

    def test_engine_git_pin_cache_is_exact_and_reentrant(self) -> None:
        class FalseyCachedPath:
            def __bool__(self) -> bool:
                return False

        falsey_cached = FalseyCachedPath()
        blocked_discovery = mock.Mock(
            side_effect=AssertionError("rediscovered a cached executable")
        )
        with (
            mock.patch.object(self.engine, "_PINNED_GIT", falsey_cached),
            mock.patch.object(
                self.engine,
                "_discover_git_executable",
                blocked_discovery,
            ),
        ):
            self.assertIs(self.engine.pin_git_executable(), falsey_cached)
            self.assertIs(self.engine._PINNED_GIT, falsey_cached)

        blocked_discovery.assert_not_called()

        reentrant_cached = Path("/reentrant-cache")
        discovered = Path("/discovered-git")

        def discover(**dependencies: object) -> Path:
            self.assertIsNone(self.engine._PINNED_GIT)
            self.engine._PINNED_GIT = reentrant_cached
            self.assertIs(
                self.engine.pin_git_executable(),
                reentrant_cached,
            )
            return discovered

        with (
            mock.patch.object(self.engine, "_PINNED_GIT", None),
            mock.patch.object(
                self.engine,
                "_discover_git_executable",
                side_effect=discover,
            ) as discovery,
        ):
            self.assertIs(self.engine.pin_git_executable(), discovered)
            self.assertIs(self.engine._PINNED_GIT, discovered)
            self.assertIs(self.engine.pin_git_executable(), discovered)

        discovery.assert_called_once()

    def test_engine_git_pin_failure_preserves_cache_mutation_timing(
        self,
    ) -> None:
        failure = RuntimeError("discovery failed")

        with (
            mock.patch.object(self.engine, "_PINNED_GIT", None),
            mock.patch.object(
                self.engine,
                "_discover_git_executable",
                side_effect=failure,
            ),
        ):
            with self.assertRaises(RuntimeError) as caught:
                self.engine.pin_git_executable()
            self.assertIs(caught.exception, failure)
            self.assertIsNone(self.engine._PINNED_GIT)

        reentrant_cached = Path("/partial-reentrant-cache")

        def mutate_then_fail(**dependencies: object) -> None:
            self.engine._PINNED_GIT = reentrant_cached
            raise failure

        with (
            mock.patch.object(self.engine, "_PINNED_GIT", None),
            mock.patch.object(
                self.engine,
                "_discover_git_executable",
                side_effect=mutate_then_fail,
            ),
        ):
            with self.assertRaises(RuntimeError) as caught:
                self.engine.pin_git_executable()
            self.assertIs(caught.exception, failure)
            self.assertIs(self.engine._PINNED_GIT, reentrant_cached)

    def test_engine_git_pin_wrapper_forwards_lazy_globals(self) -> None:
        class InitialOSError(OSError):
            pass

        class ReboundOSError(OSError):
            pass

        class InitialLauncherError(RuntimeError):
            pass

        class ReboundLauncherError(RuntimeError):
            pass

        initial_locator = mock.Mock(name="initial-locator")
        rebound_locator = mock.Mock(name="rebound-locator")
        initial_path_factory = mock.Mock(name="initial-path-factory")
        rebound_path_factory = mock.Mock(name="rebound-path-factory")
        initial_regular_test = mock.Mock(name="initial-regular-test")
        rebound_regular_test = mock.Mock(name="rebound-regular-test")
        initial_access = mock.Mock(name="initial-access")
        rebound_access = mock.Mock(name="rebound-access")
        initial_mode = object()
        rebound_mode = object()
        resolved = Path("/resolved-git")

        def discover(**dependencies: object) -> Path:
            self.assertEqual(
                tuple(dependencies),
                (
                    "executable_locator",
                    "path_factory",
                    "os_error_type",
                    "error_type",
                    "regular_file_test",
                    "access_check",
                    "executable_mode",
                ),
            )
            self.engine.shutil = SimpleNamespace(which=rebound_locator)
            self.assertIs(
                dependencies["executable_locator"](),
                rebound_locator,
            )
            self.engine.Path = rebound_path_factory
            self.assertIs(
                dependencies["path_factory"](),
                rebound_path_factory,
            )
            self.engine.OSError = ReboundOSError
            self.assertIs(
                dependencies["os_error_type"](),
                ReboundOSError,
            )
            self.engine.LauncherError = ReboundLauncherError
            self.assertIs(
                dependencies["error_type"](),
                ReboundLauncherError,
            )
            self.engine.stat = SimpleNamespace(S_ISREG=rebound_regular_test)
            self.assertIs(
                dependencies["regular_file_test"](),
                rebound_regular_test,
            )
            self.engine.os = SimpleNamespace(
                access=rebound_access,
                X_OK=initial_mode,
            )
            self.assertIs(
                dependencies["access_check"](),
                rebound_access,
            )
            self.engine.os = SimpleNamespace(
                access=initial_access,
                X_OK=rebound_mode,
            )
            self.assertIs(
                dependencies["executable_mode"](),
                rebound_mode,
            )
            return resolved

        with (
            mock.patch.object(self.engine, "_PINNED_GIT", None),
            mock.patch.object(
                self.engine,
                "_discover_git_executable",
                side_effect=discover,
            ) as discovery,
            mock.patch.object(
                self.engine,
                "shutil",
                SimpleNamespace(which=initial_locator),
            ),
            mock.patch.object(self.engine, "Path", initial_path_factory),
            mock.patch.object(
                self.engine,
                "OSError",
                InitialOSError,
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
                SimpleNamespace(S_ISREG=initial_regular_test),
            ),
            mock.patch.object(
                self.engine,
                "os",
                SimpleNamespace(access=initial_access, X_OK=initial_mode),
            ),
        ):
            self.assertIs(self.engine.pin_git_executable(), resolved)
            self.assertIs(self.engine._PINNED_GIT, resolved)

        discovery.assert_called_once()

    def test_engine_real_git_discovery_kernel_observes_rebound_globals(
        self,
    ) -> None:
        events: list[object] = []
        metadata_mode = object()
        executable_mode = object()

        class Metadata:
            @property
            def st_mode(metadata_self) -> object:
                events.append("metadata-mode")
                return metadata_mode

        class ResolvedPath:
            def stat(path_self) -> Metadata:
                events.append("stat")
                return Metadata()

        resolved = ResolvedPath()

        class ReboundStat:
            @property
            def S_ISREG(stat_self) -> object:
                events.append("regular-provider")

                def is_regular(mode: object) -> bool:
                    events.append(("regular", mode))
                    self.engine.os = AccessNamespace()
                    return True

                return is_regular

        class ModeNamespace:
            X_OK = executable_mode

        class AccessNamespace:
            @property
            def access(namespace_self) -> object:
                events.append("access-provider")
                self.engine.os = ModeNamespace()

                def is_executable(path: object, mode: object) -> bool:
                    events.append(("access", path, mode))
                    return True

                return is_executable

        class CandidatePath:
            def resolve(path_self, *, strict: bool) -> ResolvedPath:
                events.append(("resolve", strict))
                self.engine.stat = ReboundStat()
                return resolved

        def rebound_path_factory(candidate: str) -> CandidatePath:
            events.append(("path", candidate))
            return CandidatePath()

        def locate(name: str) -> str:
            events.append(("locate", name))
            self.engine.Path = rebound_path_factory
            return "candidate"

        stale_path_factory = mock.Mock(
            side_effect=AssertionError("used the Path binding too early")
        )
        stale_regular_test = mock.Mock(
            side_effect=AssertionError("used the stat binding too early")
        )
        stale_access = mock.Mock(
            side_effect=AssertionError("used the os.access binding too early")
        )

        with (
            mock.patch.object(self.engine, "_PINNED_GIT", None),
            mock.patch.object(
                self.engine,
                "_discover_git_executable",
                self.policy.discover_git_executable,
            ),
            mock.patch.object(
                self.engine,
                "shutil",
                SimpleNamespace(which=locate),
            ),
            mock.patch.object(self.engine, "Path", stale_path_factory),
            mock.patch.object(
                self.engine,
                "stat",
                SimpleNamespace(S_ISREG=stale_regular_test),
            ),
            mock.patch.object(
                self.engine,
                "os",
                SimpleNamespace(access=stale_access, X_OK=object()),
            ),
        ):
            observed = self.engine.pin_git_executable()
            self.assertIs(observed, resolved)
            self.assertIs(self.engine._PINNED_GIT, resolved)

        self.assertEqual(
            events,
            [
                ("locate", "git"),
                ("path", "candidate"),
                ("resolve", True),
                "stat",
                "regular-provider",
                "metadata-mode",
                ("regular", metadata_mode),
                "access-provider",
                ("access", resolved, executable_mode),
            ],
        )
        stale_path_factory.assert_not_called()
        stale_regular_test.assert_not_called()
        stale_access.assert_not_called()

    def test_engine_real_git_discovery_kernel_observes_rebound_error_types(
        self,
    ) -> None:
        class InitialOSError(OSError):
            pass

        class ReboundOSError(OSError):
            pass

        class InitialLauncherError(RuntimeError):
            pass

        class ReboundLauncherError(RuntimeError):
            pass

        failure = ReboundOSError("rebound failure")

        class FailingPath:
            def resolve(path_self, *, strict: bool) -> None:
                self.assertTrue(strict)
                self.engine.OSError = ReboundOSError
                self.engine.LauncherError = ReboundLauncherError
                raise failure

        with (
            mock.patch.object(self.engine, "_PINNED_GIT", None),
            mock.patch.object(
                self.engine,
                "_discover_git_executable",
                self.policy.discover_git_executable,
            ),
            mock.patch.object(
                self.engine,
                "shutil",
                SimpleNamespace(which=lambda name: "candidate"),
            ),
            mock.patch.object(
                self.engine,
                "Path",
                lambda candidate: FailingPath(),
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
                InitialLauncherError,
            ),
        ):
            with self.assertRaises(ReboundLauncherError) as caught:
                self.engine.pin_git_executable()
            self.assertEqual(
                str(caught.exception),
                "cannot resolve the Git executable",
            )
            self.assertIs(caught.exception.__cause__, failure)
            self.assertIsNone(self.engine._PINNED_GIT)

    def test_engine_pins_the_portable_real_git_executable(self) -> None:
        candidate = shutil.which("git")
        if candidate is None:
            self.skipTest("Git is not installed")
        expected = Path(candidate).resolve(strict=True)

        with (
            mock.patch.object(self.engine, "_PINNED_GIT", None),
            mock.patch.object(
                self.engine,
                "_discover_git_executable",
                self.policy.discover_git_executable,
            ),
        ):
            observed = self.engine.pin_git_executable()
            self.assertIs(self.engine._PINNED_GIT, observed)
            self.assertIs(self.engine.pin_git_executable(), observed)

        self.assertEqual(observed, expected)
        self.assertTrue(stat.S_ISREG(observed.stat().st_mode))
        self.assertTrue(os.access(observed, os.X_OK))

    def test_engine_wrapper_preserves_rebound_policy_globals(self) -> None:
        source = {
            "CUSTOM_UNSAFE": "remove",
            "CUSTOM_INDEXED": "remove",
            "GIT_CONFIG_KEY_0": "preserve",
            "GIT_DIR": "preserve",
        }
        with (
            mock.patch.object(
                self.engine,
                "GIT_UNSAFE_ENV",
                {"CUSTOM_UNSAFE"},
            ),
            mock.patch.object(
                self.engine,
                "GIT_INDEXED_CONFIG_ENV_RE",
                re.compile(r"^CUSTOM_INDEXED$"),
            ),
        ):
            observed = self.engine.sanitized_git_environment(source)

        self.assertNotIn("CUSTOM_UNSAFE", observed)
        self.assertNotIn("CUSTOM_INDEXED", observed)
        self.assertEqual(observed["GIT_CONFIG_KEY_0"], "preserve")
        self.assertEqual(observed["GIT_DIR"], "preserve")

    def test_sanitized_environment_is_a_repeatable_copy(self) -> None:
        forced = {
            "EDITOR": ":",
            "GIT_ATTR_GLOBAL": os.devnull,
            "GIT_ATTR_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_EDITOR": ":",
            "GIT_NO_REPLACE_OBJECTS": "1",
            "GIT_OPTIONAL_LOCKS": "1",
            "GIT_PAGER": "",
            "GIT_SEQUENCE_EDITOR": ":",
            "GIT_TERMINAL_PROMPT": "0",
            "VISUAL": ":",
        }
        self.assertIs(type(self.policy.GIT_UNSAFE_ENV), set)
        self.assertEqual(self.policy.GIT_UNSAFE_ENV, EXPECTED_UNSAFE_GIT_ENV)
        source = {name: "hostile" for name in EXPECTED_UNSAFE_GIT_ENV}
        source.update(
            {
                "CDPATH": "/hostile",
                "GIT_CONFIG_KEY_0": "core.fsmonitor",
                "GIT_CONFIG_VALUE_0": "/hostile",
                "GIT_CONFIG_KEY_27": "filter.hostile.process",
                "GIT_CONFIG_VALUE_27": "/hostile",
                "GIT_TEST_FAKE": "1",
                "GIT_TRACE": "1",
                "GIT_TRACE2_EVENT": "/hostile",
                "SSH_ASKPASS": "/hostile",
                "KEEP": "yes",
                "GIT_CONFIG_KEY_x": "preserved-near-miss",
                "GIT_TEST": "preserved-near-miss",
                "GIT_TRAC": "preserved-near-miss",
            }
        )
        original = source.copy()

        first = self.policy.sanitized_git_environment(source)
        second = self.policy.sanitized_git_environment(source)

        self.assertEqual(source, original)
        self.assertIsNot(first, source)
        self.assertEqual(first, second)
        self.assertEqual({name: first[name] for name in forced}, forced)
        self.assertEqual(first["KEEP"], "yes")
        self.assertEqual(first["GIT_CONFIG_KEY_x"], "preserved-near-miss")
        self.assertEqual(first["GIT_TEST"], "preserved-near-miss")
        self.assertEqual(first["GIT_TRAC"], "preserved-near-miss")
        removed = (
            (EXPECTED_UNSAFE_GIT_ENV - forced.keys())
            | {
                "CDPATH",
                "GIT_CONFIG_KEY_0",
                "GIT_CONFIG_VALUE_0",
                "GIT_CONFIG_KEY_27",
                "GIT_CONFIG_VALUE_27",
                "GIT_TEST_FAKE",
                "GIT_TRACE",
                "GIT_TRACE2_EVENT",
                "SSH_ASKPASS",
            }
        )
        self.assertTrue(removed.isdisjoint(first), removed.intersection(first))

    def test_engine_wrapper_preserves_default_environment_acquisition(self) -> None:
        source = {
            "KEEP": "yes",
            "GIT_DIR": "/hostile",
        }
        with mock.patch.dict(os.environ, source, clear=True):
            observed = self.engine.sanitized_git_environment()

        self.assertEqual(observed["KEEP"], "yes")
        self.assertNotIn("GIT_DIR", observed)
        self.assertEqual(observed["GIT_TERMINAL_PROMPT"], "0")

    def test_base_arguments_are_frozen(self) -> None:
        self.assertEqual(
            self.policy.GIT_BASE_ARGUMENTS,
            (
                "--no-replace-objects",
                "-c",
                "core.hooksPath=/dev/null",
                "-c",
                "commit.gpgSign=false",
                "-c",
                "tag.gpgSign=false",
                "-c",
                "core.editor=:",
                "-c",
                "sequence.editor=:",
            ),
        )

    def test_effective_configuration_policy_is_frozen(self) -> None:
        dangerous = (
            "filter.example.clean",
            "filter.example.smudge",
            "filter.example.process",
            "merge.example.driver",
            "diff.external",
            "diff.example.command",
            "diff.example.textconv",
            "FILTER.EXAMPLE.PROCESS",
        )
        benign = (
            "core.editor",
            "filter.example.required",
            "merge.example.name",
            "diff.example.binary",
        )

        for name in dangerous:
            with self.subTest(dangerous=name):
                self.assertIsNotNone(self.policy.GIT_COMMAND_CONFIG_RE.fullmatch(name))
        for name in benign:
            with self.subTest(benign=name):
                self.assertIsNone(self.policy.GIT_COMMAND_CONFIG_RE.fullmatch(name))
        self.assertEqual(
            self.policy.GIT_BOOLEAN_VALUES,
            {"", "0", "1", "false", "no", "off", "on", "true", "yes"},
        )

    def test_effective_configuration_accepts_boolean_and_benign_values(
        self,
    ) -> None:
        accepted = (
            "",
            " ",
            "0",
            "1",
            "false",
            "no",
            "off",
            "on",
            "true",
            "yes",
            " TRUE ",
            "\tNo\n",
        )
        for value in accepted:
            with self.subTest(fsmonitor=value):
                output = (
                    b"core.editor\nvim\0"
                    b"filter.example.required\ntrue\0"
                    b"filter.example.process\n \t\0"
                    b"core.fsmonitor\n"
                    + value.encode()
                    + b"\0"
                )
                self.validate_output(output)

        self.validate_output(b"\0\0")
        self.validate_output(b"benign.key\nfirst\nsecond\0")
        self.validate_output(b"benign.key\nvalue-without-trailing-nul")

    def test_effective_configuration_rejects_malformed_records(self) -> None:
        malformed = (
            b"missing-separator",
            b"\nmissing-key",
            b"valid.key\nvalue\0missing-separator",
        )
        for output in malformed:
            with self.subTest(output=output):
                with self.assertRaisesRegex(
                    RuntimeError,
                    "^Git returned malformed effective configuration$",
                ):
                    self.validate_output(output)

    def test_effective_configuration_rejects_command_bearing_values(
        self,
    ) -> None:
        cases = (
            (
                b"core.fsmonitor\n/bin/command\0",
                "unsafe command-bearing Git configuration 'core.fsmonitor'",
            ),
            (
                b"FILTER.EXAMPLE.CLEAN\n/bin/command\0",
                "unsafe command-bearing Git configuration 'filter.example.clean'",
            ),
            (
                b"filter.example.smudge\n/bin/command\0",
                "unsafe command-bearing Git configuration 'filter.example.smudge'",
            ),
            (
                b"filter.example.process\n/bin/command\0",
                "unsafe command-bearing Git configuration 'filter.example.process'",
            ),
            (
                b"merge.example.driver\n/bin/command\0",
                "unsafe command-bearing Git configuration 'merge.example.driver'",
            ),
            (
                b"diff.external\n/bin/command\0",
                "unsafe command-bearing Git configuration 'diff.external'",
            ),
            (
                b"diff.example.command\n/bin/command\0",
                "unsafe command-bearing Git configuration 'diff.example.command'",
            ),
            (
                b"diff.example.textconv\n/bin/command",
                "unsafe command-bearing Git configuration 'diff.example.textconv'",
            ),
        )
        for output, message in cases:
            with self.subTest(output=output):
                with self.assertRaisesRegex(RuntimeError, f"^{message}$"):
                    self.validate_output(output)

    def test_effective_configuration_uses_last_duplicate_and_surrogates(
        self,
    ) -> None:
        self.validate_output(
            b"core.fsmonitor\n/bin/command\0CORE.FSMONITOR\ntrue\0"
        )
        self.validate_output(
            b"filter.example.process\n/bin/command\0"
            b"FILTER.EXAMPLE.PROCESS\n \0"
        )
        self.validate_output(b"custom.\xff\nvalue-\xfe\0")

        with self.assertRaisesRegex(
            RuntimeError,
            "^unsafe command-bearing Git configuration 'core.fsmonitor'$",
        ):
            self.validate_output(
                b"core.fsmonitor\ntrue\0CORE.FSMONITOR\n/bin/command\0"
            )
        with self.assertRaisesRegex(
            RuntimeError,
            "^unsafe command-bearing Git configuration "
            "'filter.example.process'$",
        ):
            self.validate_output(
                b"filter.example.process\n \0"
                b"FILTER.EXAMPLE.PROCESS\n/bin/command\0"
            )

    def test_effective_configuration_preserves_validation_precedence(
        self,
    ) -> None:
        with self.assertRaisesRegex(
            RuntimeError,
            "^Git returned malformed effective configuration$",
        ):
            self.validate_output(
                b"core.fsmonitor\n/bin/command\0missing-separator"
            )

        class PolicyError(RuntimeError):
            pass

        pattern = mock.Mock(
            side_effect=AssertionError("matched patterns before fsmonitor")
        )
        with self.assertRaisesRegex(
            PolicyError,
            "^unsafe command-bearing Git configuration 'core.fsmonitor'$",
        ):
            self.policy.validate_effective_git_configuration(
                b"diff.external\n/bin/command\0"
                b"core.fsmonitor\n/bin/command",
                error_type=lambda: PolicyError,
                boolean_values=lambda: self.policy.GIT_BOOLEAN_VALUES,
                command_config_pattern=pattern,
            )
        pattern.assert_not_called()

        boolean_values = mock.Mock(
            side_effect=AssertionError("resolved booleans without fsmonitor")
        )
        self.policy.validate_effective_git_configuration(
            b"benign.key\nvalue",
            error_type=lambda: PolicyError,
            boolean_values=boolean_values,
            command_config_pattern=lambda: re.compile(r"(?!)"),
        )
        boolean_values.assert_not_called()

    def test_engine_effective_configuration_probe_is_exact_and_bounded(
        self,
    ) -> None:
        cwd = Path("/repository")
        successful = SimpleNamespace(
            returncode=0,
            stdout=b"core.fsmonitor\ntrue\0",
        )
        with mock.patch.object(
            self.engine,
            "raw_git",
            return_value=successful,
        ) as raw_git:
            self.engine.validate_effective_git_configuration(cwd)

        raw_git.assert_called_once_with(
            cwd,
            "config",
            "--null",
            "--list",
            text=False,
            check=False,
        )

        class ProbeError(RuntimeError):
            pass

        class FailedProbe:
            returncode = 17

            @property
            def stdout(self) -> bytes:
                raise AssertionError("read stdout after a failed probe")

        with (
            mock.patch.object(
                self.engine,
                "raw_git",
                return_value=FailedProbe(),
            ),
            mock.patch.object(self.engine, "LauncherError", ProbeError),
        ):
            with self.assertRaisesRegex(
                ProbeError,
                "^cannot inspect the repository's effective Git configuration$",
            ):
                self.engine.validate_effective_git_configuration(cwd)

    def test_engine_effective_configuration_resolves_policy_lazily(
        self,
    ) -> None:
        events: list[tuple[str, str]] = []

        class InitialError(RuntimeError):
            pass

        class ReboundError(RuntimeError):
            pass

        class FirstPattern:
            def fullmatch(pattern_self, key: str) -> None:
                events.append(("first-pattern", key))
                self.engine.GIT_COMMAND_CONFIG_RE = SecondPattern()
                return None

        class SecondPattern:
            def fullmatch(pattern_self, key: str) -> object | None:
                events.append(("second-pattern", key))
                if key == "danger.key":
                    self.engine.LauncherError = ReboundError
                    return object()
                return None

        result = SimpleNamespace(
            returncode=0,
            stdout=b"safe.key\nvalue\0danger.key\ncommand\0",
        )
        with (
            mock.patch.object(self.engine, "raw_git", return_value=result),
            mock.patch.object(
                self.engine,
                "GIT_COMMAND_CONFIG_RE",
                FirstPattern(),
            ),
            mock.patch.object(self.engine, "LauncherError", InitialError),
        ):
            with self.assertRaisesRegex(
                ReboundError,
                "^unsafe command-bearing Git configuration 'danger.key'$",
            ):
                self.engine.validate_effective_git_configuration(
                    Path("/repository")
                )

        self.assertEqual(
            events,
            [
                ("first-pattern", "safe.key"),
                ("second-pattern", "danger.key"),
            ],
        )

        class RebindingOutput:
            def split(output_self, separator: bytes) -> list[bytes]:
                self.assertEqual(separator, b"\0")
                self.engine.GIT_BOOLEAN_VALUES = {"custom"}
                return [b"core.fsmonitor\ncustom"]

        rebound_result = SimpleNamespace(
            returncode=0,
            stdout=RebindingOutput(),
        )
        with (
            mock.patch.object(
                self.engine,
                "raw_git",
                return_value=rebound_result,
            ),
            mock.patch.object(
                self.engine,
                "GIT_BOOLEAN_VALUES",
                {"initial"},
            ),
        ):
            self.engine.validate_effective_git_configuration(
                Path("/repository")
            )

    def test_git_resolves_the_effective_configuration_wrapper(self) -> None:
        cwd = Path("/repository")
        expected = SimpleNamespace(returncode=0)
        events: list[str] = []

        def authenticate_cwd(observed: Path) -> None:
            self.assertEqual(observed, cwd)
            events.append("authenticate")

        def validate_configuration(observed: Path) -> None:
            self.assertEqual(observed, cwd)
            events.append("validate")

        def run_git(*args: object, **kwargs: object) -> object:
            events.append("raw-git")
            return expected

        with (
            mock.patch.object(
                self.engine,
                "authenticate_git_cwd",
                side_effect=authenticate_cwd,
            ) as authenticate,
            mock.patch.object(
                self.engine,
                "validate_effective_git_configuration",
                side_effect=validate_configuration,
            ) as validate,
            mock.patch.object(
                self.engine,
                "raw_git",
                side_effect=run_git,
            ) as raw_git,
        ):
            observed = self.engine.git(cwd, "status", "--short")

        self.assertIs(observed, expected)
        self.assertEqual(events, ["authenticate", "validate", "raw-git"])
        authenticate.assert_called_once_with(cwd)
        validate.assert_called_once_with(cwd)
        raw_git.assert_called_once_with(
            cwd,
            "status",
            "--short",
            check=True,
            text=True,
            environment=None,
            input_data=None,
        )

        class ValidationError(RuntimeError):
            pass

        blocked_command = mock.Mock(
            side_effect=AssertionError("ran Git after validation failure")
        )
        with (
            mock.patch.object(self.engine, "authenticate_git_cwd"),
            mock.patch.object(
                self.engine,
                "validate_effective_git_configuration",
                side_effect=ValidationError("unsafe configuration"),
            ),
            mock.patch.object(self.engine, "raw_git", blocked_command),
        ):
            with self.assertRaisesRegex(
                ValidationError,
                "^unsafe configuration$",
            ):
                self.engine.git(cwd, "status", "--short")

        blocked_command.assert_not_called()

    def test_rebase_hardening_preserves_the_existing_argument_matrix(self) -> None:
        cases = (
            (("status", "--short"), ["status", "--short"]),
            (
                ("-C", "/repository", "rebase", "target"),
                ["-C", "/repository", "rebase", "--no-gpg-sign", "target"],
            ),
            (("rebase", "--abort"), ["rebase", "--abort"]),
            (("rebase", "--continue"), ["rebase", "--continue"]),
            (("rebase", "--edit-todo"), ["rebase", "--edit-todo"]),
            (("rebase", "--quit"), ["rebase", "--quit"]),
            (("rebase", "--skip"), ["rebase", "--skip"]),
            (
                ("rebase", "--no-gpg-sign", "target"),
                ["rebase", "--no-gpg-sign", "target"],
            ),
            (
                ("rebase", "--gpg-sign", "target"),
                ["rebase", "--gpg-sign", "target"],
            ),
            (
                ("rebase", "--gpg-sign=ABC123", "target"),
                ["rebase", "--gpg-sign=ABC123", "target"],
            ),
        )

        for supplied, expected in cases:
            with self.subTest(supplied=supplied):
                mutable = list(supplied)
                observed = self.policy.hardened_git_arguments(mutable)
                self.assertEqual(observed, expected)
                self.assertEqual(mutable, list(supplied))
                self.assertIsNot(observed, mutable)

    def test_absolute_git_path_kernel_and_wrapper_surfaces(self) -> None:
        self.assertEqual(
            str(inspect.signature(self.policy.absolute_git_path)),
            "(cwd: 'Path', selector: 'str', *, git_call: "
            "'Callable[[], Callable[..., object]]', path_factory: "
            "'Callable[[], Callable[[str], Path]]') -> 'Path'",
        )
        self.assertEqual(
            str(inspect.signature(self.engine.absolute_git_path)),
            "(cwd: 'Path', selector: 'str') -> 'Path'",
        )

    def test_git_invocation_kernel_surfaces_are_exact(self) -> None:
        self.assertEqual(
            tuple(inspect.signature(self.policy.raw_git).parameters),
            (
                "cwd",
                "args",
                "check",
                "text",
                "environment",
                "input_data",
                "executable",
                "base_arguments",
                "command_call",
            ),
        )
        self.assertEqual(
            tuple(
                inspect.signature(
                    self.policy.authenticated_git
                ).parameters
            ),
            (
                "cwd",
                "args",
                "check",
                "text",
                "environment",
                "input_data",
                "authenticate_cwd",
                "validate_configuration",
                "harden_arguments",
                "raw_git_call",
            ),
        )

    def test_absolute_git_path_preserves_call_and_resolution_order(self) -> None:
        cwd = Path("/repository")
        events: list[tuple[str, object]] = []

        class Candidate:
            def resolve(candidate_self) -> Path:
                events.append(("resolve", None))
                return Path("/repository/.git")

        def git_call(*args: object) -> object:
            events.append(("git", args))
            return SimpleNamespace(stdout="  /repository/.git  \n")

        def path_factory(value: str) -> object:
            events.append(("path", value))
            return Candidate()

        observed = self.policy.absolute_git_path(
            cwd,
            "--git-dir",
            git_call=lambda: git_call,
            path_factory=lambda: path_factory,
        )

        self.assertEqual(observed, Path("/repository/.git"))
        self.assertEqual(
            events,
            [
                (
                    "git",
                    (
                        cwd,
                        "rev-parse",
                        "--path-format=absolute",
                        "--git-dir",
                    ),
                ),
                ("path", "/repository/.git"),
                ("resolve", None),
            ],
        )

    def test_engine_absolute_git_path_wrapper_resolves_globals_lazily(
        self,
    ) -> None:
        sentinel = object()
        captured: dict[str, object] = {}

        def kernel(
            cwd: object,
            selector: object,
            **dependencies: object,
        ) -> object:
            captured.update(
                cwd=cwd,
                selector=selector,
                **dependencies,
            )
            return sentinel

        with mock.patch.object(
            self.engine,
            "_absolute_git_path",
            side_effect=kernel,
        ):
            observed = self.engine.absolute_git_path(
                Path("/repository"),
                "--git-common-dir",
            )

        self.assertIs(observed, sentinel)
        self.assertEqual(captured["cwd"], Path("/repository"))
        self.assertEqual(captured["selector"], "--git-common-dir")
        self.assertIs(captured["git_call"](), self.engine.git)
        self.assertIs(captured["path_factory"](), self.engine.Path)


if __name__ == "__main__":
    unittest.main()
