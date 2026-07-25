#!/usr/bin/env python3
"""Direct parity tests for run identity and lexical state paths."""

from __future__ import annotations

import importlib
import inspect
import re
import subprocess
import sys
import tempfile
import unittest
from contextlib import nullcontext
from pathlib import Path
from types import SimpleNamespace
from unittest import mock


PACKAGE_ROOT = Path(__file__).resolve().parents[1]
SOURCE_ROOT = PACKAGE_ROOT / "src"


class StatePolicyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        sys.path.insert(0, str(SOURCE_ROOT))
        cls.state_policy = importlib.import_module("worktree_marshal.state")
        cls.engine = importlib.import_module("worktree_marshal.engine")

    @classmethod
    def tearDownClass(cls) -> None:
        try:
            sys.path.remove(str(SOURCE_ROOT))
        except ValueError:
            pass

    def test_state_import_is_engine_free_and_environment_neutral(self) -> None:
        script = (
            "import os, sys; "
            "before = dict(os.environ); "
            f"sys.path.insert(0, {str(SOURCE_ROOT)!r}); "
            "import worktree_marshal.state; "
            "raise SystemExit("
            "'worktree_marshal.engine' in sys.modules "
            "or dict(os.environ) != before"
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

    def checkpoint_dependencies(self) -> dict[str, object]:
        return {
            "object_fields": ("object_field",),
            "retirement_object_fields": ("retirement_object",),
            "path_fields": ("path_field",),
            "hash_fields": ("hash_field",),
            "retirement_timestamp_fields": ("retirement_started_at",),
            "retirement_fields": (
                "retirement_object",
                "retirement_started_at",
                "retirement_anchor_created",
                "retirement_cleanup_target_head",
                "retirement_worktree_removed_at",
                "retirement_ref_cleanup_started_at",
                "retirement_ref_transaction_committed_at",
                "retirement_receipt_removed_at",
                "retirement_completed_at",
                "retirement_cleanup_warning",
            ),
            "retirement_core_fields": ("retirement_object",),
            "retirement_states": {
                "retirement-pending",
                "retirement-ref-cleanup-pending",
            },
            "object_id_pattern": re.compile(r"^[0-9a-f]{40}$"),
            "hash_match": re.compile(r"^[0-9a-f]{64}$").fullmatch,
            "error_type": self.engine.LauncherError,
        }

    def test_checkpoint_field_kernel_signature_is_explicit(self) -> None:
        parameters = inspect.signature(
            self.state_policy.validate_manifest_checkpoint_fields
        ).parameters
        self.assertEqual(
            tuple(parameters),
            (
                "manifest",
                "state",
                "object_fields",
                "retirement_object_fields",
                "path_fields",
                "hash_fields",
                "retirement_timestamp_fields",
                "retirement_fields",
                "retirement_core_fields",
                "retirement_states",
                "object_id_pattern",
                "hash_match",
                "error_type",
            ),
        )
        self.assertIs(
            parameters["manifest"].kind,
            inspect.Parameter.POSITIONAL_OR_KEYWORD,
        )
        self.assertIs(
            parameters["state"].kind,
            inspect.Parameter.POSITIONAL_OR_KEYWORD,
        )
        for parameter in tuple(parameters.values())[2:]:
            self.assertIs(parameter.kind, inspect.Parameter.KEYWORD_ONLY)
            self.assertIs(parameter.default, inspect.Parameter.empty)

    def test_checkpoint_field_kernel_validates_in_legacy_order(self) -> None:
        invalid = {
            "object_field": "bad-object",
            "retirement_object": "bad-retirement-object",
            "path_field": ["../bad"],
            "hash_field": "bad-hash",
            "integration_abort_mode": "bad-mode",
            "integration_manual_resolution": False,
            "integration_source_anchor_created": False,
            "retirement_anchor_created": False,
            "retirement_started_at": "",
            "retirement_cleanup_warning": "",
        }
        with self.assertRaisesRegex(
            self.engine.LauncherError,
            "^run manifest has an invalid object field$",
        ):
            self.state_policy.validate_manifest_checkpoint_fields(
                invalid,
                "preserved",
                **self.checkpoint_dependencies(),
            )

        valid = {
            "object_field": "a" * 40,
            "path_field": ["one/two"],
            "hash_field": "b" * 64,
            "integration_abort_mode": "candidate",
            "integration_manual_resolution": True,
            "integration_source_anchor_created": True,
        }
        self.assertIsNone(
            self.state_policy.validate_manifest_checkpoint_fields(
                valid,
                "preserved",
                **self.checkpoint_dependencies(),
            )
        )

    def test_checkpoint_field_kernel_enforces_retirement_lifecycle(self) -> None:
        dependencies = self.checkpoint_dependencies()
        with self.assertRaisesRegex(
            self.engine.LauncherError,
            "^run manifest has an incomplete retirement checkpoint$",
        ):
            self.state_policy.validate_manifest_checkpoint_fields(
                {},
                "retirement-pending",
                **dependencies,
            )

        pending = {
            "retirement_object": "a" * 40,
            "retirement_started_at": "now",
        }
        self.assertIsNone(
            self.state_policy.validate_manifest_checkpoint_fields(
                pending,
                "retirement-pending",
                **dependencies,
            )
        )

    def test_target_ref_kernel_signature_and_short_circuits(self) -> None:
        parameters = inspect.signature(
            self.state_policy.validate_manifest_target_ref
        ).parameters
        self.assertEqual(
            tuple(parameters),
            ("repository", "manifest", "check_ref_format", "error_type"),
        )
        self.assertIs(
            parameters["repository"].kind,
            inspect.Parameter.POSITIONAL_OR_KEYWORD,
        )
        self.assertIs(
            parameters["manifest"].kind,
            inspect.Parameter.POSITIONAL_OR_KEYWORD,
        )
        for parameter in tuple(parameters.values())[2:]:
            self.assertIs(parameter.kind, inspect.Parameter.KEYWORD_ONLY)
            self.assertIs(parameter.default, inspect.Parameter.empty)

        repository = SimpleNamespace(root=object())
        check_ref_format = mock.Mock()
        for target_ref in (None, 1, b"refs/heads/main", "main"):
            with self.subTest(target_ref=target_ref), self.assertRaisesRegex(
                self.engine.LauncherError,
                "^run manifest has an invalid target branch$",
            ):
                self.state_policy.validate_manifest_target_ref(
                    repository,
                    {"target_ref": target_ref},
                    check_ref_format=check_ref_format,
                    error_type=self.engine.LauncherError,
                )
        check_ref_format.assert_not_called()

    def test_target_ref_kernel_preserves_probe_and_result_behavior(self) -> None:
        root = object()
        repository = SimpleNamespace(root=root)
        target_ref = "refs/heads/topic"
        check_ref_format = mock.Mock(
            return_value=SimpleNamespace(returncode=0)
        )

        self.assertIsNone(
            self.state_policy.validate_manifest_target_ref(
                repository,
                {"target_ref": target_ref},
                check_ref_format=check_ref_format,
                error_type=self.engine.LauncherError,
            )
        )
        check_ref_format.assert_called_once_with(root, target_ref)

        check_ref_format.reset_mock(
            return_value=True,
        )
        check_ref_format.return_value = SimpleNamespace(returncode=1)
        with self.assertRaisesRegex(
            self.engine.LauncherError,
            "^run manifest has an invalid target branch$",
        ):
            self.state_policy.validate_manifest_target_ref(
                repository,
                {"target_ref": target_ref},
                check_ref_format=check_ref_format,
                error_type=self.engine.LauncherError,
            )

    def run_tmp_parent_dependencies(
        self,
        events: list[tuple[str, object]],
        root_metadata: object,
        opened_metadata: object,
    ) -> tuple[dict[str, object], object]:
        class TemporaryRoot:
            def lstat(root_self) -> object:
                events.append(("lstat", root_self))
                return root_metadata

        expected = SimpleNamespace(
            parent=TemporaryRoot(),
            name="20260723t010203z-0123456789ab",
        )

        def validate_exact_run_tmpdir(
            repository: object,
            manifest: object,
        ) -> object:
            events.append(("validate", (repository, manifest)))
            return expected

        def directory_test(mode: object) -> bool:
            events.append(("directory-test", mode))
            return True

        def file_open(path: object, flags: int) -> int:
            events.append(("open", (path, flags)))
            return 17

        def file_stat(descriptor: int) -> object:
            events.append(("fstat", descriptor))
            return opened_metadata

        def same_stat(first: object, second: object) -> bool:
            events.append(("samestat", (first, second)))
            return True

        def file_close(descriptor: int) -> None:
            events.append(("close", descriptor))

        dependencies = {
            "validate_exact_run_tmpdir": validate_exact_run_tmpdir,
            "directory_flag": 4,
            "nofollow_flag": 8,
            "cloexec_flag": 16,
            "read_only_flag": 1,
            "directory_test": directory_test,
            "file_open": file_open,
            "file_stat": file_stat,
            "same_stat": same_stat,
            "file_close": file_close,
            "error_type": self.engine.LauncherError,
        }
        return dependencies, expected

    def run_tmp_parent_filesystem_dependencies(self) -> dict[str, object]:
        return {
            "validate_exact_run_tmpdir": self.engine.validate_exact_run_tmpdir,
            "directory_flag": getattr(self.engine.os, "O_DIRECTORY", 0),
            "nofollow_flag": getattr(self.engine.os, "O_NOFOLLOW", 0),
            "cloexec_flag": getattr(self.engine.os, "O_CLOEXEC", 0),
            "read_only_flag": self.engine.os.O_RDONLY,
            "directory_test": self.engine.stat.S_ISDIR,
            "file_open": self.engine.os.open,
            "file_stat": self.engine.os.fstat,
            "same_stat": self.engine.os.path.samestat,
            "file_close": self.engine.os.close,
            "error_type": self.engine.LauncherError,
        }

    def test_run_tmp_parent_kernel_signatures_and_short_circuits(self) -> None:
        parameters = inspect.signature(
            self.state_policy.exact_run_tmp_parent
        ).parameters
        self.assertEqual(
            tuple(parameters),
            (
                "repository",
                "manifest",
                "validate_exact_run_tmpdir",
                "directory_flag",
                "nofollow_flag",
                "cloexec_flag",
                "read_only_flag",
                "directory_test",
                "file_open",
                "file_stat",
                "same_stat",
                "file_close",
                "error_type",
            ),
        )
        for name in ("repository", "manifest"):
            self.assertIs(
                parameters[name].kind,
                inspect.Parameter.POSITIONAL_OR_KEYWORD,
            )
        for parameter in tuple(parameters.values())[2:]:
            self.assertIs(parameter.kind, inspect.Parameter.KEYWORD_ONLY)
            self.assertIs(parameter.default, inspect.Parameter.empty)

        entry_parameters = inspect.signature(
            self.state_policy.run_tmp_entry
        ).parameters
        self.assertEqual(
            tuple(entry_parameters),
            ("parent_descriptor", "run_id", "entry_stat", "error_type"),
        )
        for name in ("parent_descriptor", "run_id"):
            self.assertIs(
                entry_parameters[name].kind,
                inspect.Parameter.POSITIONAL_OR_KEYWORD,
            )
        for parameter in tuple(entry_parameters.values())[2:]:
            self.assertIs(parameter.kind, inspect.Parameter.KEYWORD_ONLY)
            self.assertIs(parameter.default, inspect.Parameter.empty)

        repository = object()
        manifest = {"run_id": "opaque"}
        for missing_flag in ("directory_flag", "nofollow_flag"):
            with self.subTest(missing_flag=missing_flag):
                events: list[tuple[str, object]] = []
                dependencies, _ = self.run_tmp_parent_dependencies(
                    events,
                    SimpleNamespace(st_mode="root-mode"),
                    SimpleNamespace(st_mode="opened-mode"),
                )
                dependencies[missing_flag] = 0
                file_open = mock.Mock(
                    side_effect=AssertionError("opened without safe flags")
                )
                dependencies["file_open"] = file_open
                with self.assertRaisesRegex(
                    self.engine.LauncherError,
                    "^safe run temporary-path inspection is unavailable$",
                ):
                    with self.state_policy.exact_run_tmp_parent(
                        repository,
                        manifest,
                        **dependencies,
                    ):
                        raise AssertionError("entered without safe flags")
                file_open.assert_not_called()
                self.assertEqual(
                    events,
                    [("validate", (repository, manifest))],
                )

        events = []
        dependencies, _ = self.run_tmp_parent_dependencies(
            events,
            SimpleNamespace(st_mode="root-mode"),
            SimpleNamespace(st_mode="opened-mode"),
        )

        class BrokenRoot:
            def lstat(root_self) -> object:
                raise OSError("lstat failed")

        dependencies["validate_exact_run_tmpdir"] = lambda *_: SimpleNamespace(
            parent=BrokenRoot(),
            name="20260723t010203z-0123456789ab",
        )
        file_open = mock.Mock(
            side_effect=AssertionError("opened an uninspected root")
        )
        dependencies["file_open"] = file_open
        with self.assertRaisesRegex(
            self.engine.LauncherError,
            "^cannot inspect the run temporary root$",
        ):
            with self.state_policy.exact_run_tmp_parent(
                repository,
                manifest,
                **dependencies,
            ):
                raise AssertionError("entered an uninspected root")
        file_open.assert_not_called()

        events = []
        dependencies, _ = self.run_tmp_parent_dependencies(
            events,
            SimpleNamespace(st_mode="root-mode"),
            SimpleNamespace(st_mode="opened-mode"),
        )
        dependencies["directory_test"] = lambda mode: False
        file_open = mock.Mock(
            side_effect=AssertionError("opened a non-directory root")
        )
        dependencies["file_open"] = file_open
        with self.assertRaisesRegex(
            self.engine.LauncherError,
            "^the run temporary root is not a real directory$",
        ):
            with self.state_policy.exact_run_tmp_parent(
                repository,
                manifest,
                **dependencies,
            ):
                raise AssertionError("entered a non-directory root")
        file_open.assert_not_called()

        events = []
        dependencies, _ = self.run_tmp_parent_dependencies(
            events,
            SimpleNamespace(st_mode="root-mode"),
            SimpleNamespace(st_mode="opened-mode"),
        )
        dependencies["file_open"] = mock.Mock(side_effect=OSError("denied"))
        file_close = mock.Mock(
            side_effect=AssertionError("closed a never-opened descriptor")
        )
        dependencies["file_close"] = file_close
        with self.assertRaisesRegex(
            self.engine.LauncherError,
            "^cannot open the run temporary root safely$",
        ):
            with self.state_policy.exact_run_tmp_parent(
                repository,
                manifest,
                **dependencies,
            ):
                raise AssertionError("entered an unopened root")
        file_close.assert_not_called()

        events = []
        dependencies, _ = self.run_tmp_parent_dependencies(
            events,
            SimpleNamespace(st_mode="root-mode"),
            SimpleNamespace(st_mode="opened-mode"),
        )
        dependencies["file_stat"] = mock.Mock(side_effect=OSError("stat"))
        with self.assertRaisesRegex(
            self.engine.LauncherError,
            "^cannot authenticate the run temporary root$",
        ):
            with self.state_policy.exact_run_tmp_parent(
                repository,
                manifest,
                **dependencies,
            ):
                raise AssertionError("entered an unauthenticated root")
        self.assertEqual(events[-1], ("close", 17))

        for case, same_stat_result, opened_mode_directory in (
            ("replaced-mode", True, False),
            ("replaced-identity", False, True),
        ):
            with self.subTest(case=case):
                events = []
                root_metadata = SimpleNamespace(st_mode="root-mode")
                opened_metadata = SimpleNamespace(st_mode="opened-mode")
                dependencies, _ = self.run_tmp_parent_dependencies(
                    events,
                    root_metadata,
                    opened_metadata,
                )
                dependencies["directory_test"] = (
                    lambda mode: opened_mode_directory
                    if mode == "opened-mode"
                    else True
                )
                dependencies["same_stat"] = mock.Mock(
                    return_value=same_stat_result
                )
                with self.assertRaisesRegex(
                    self.engine.LauncherError,
                    "^the run temporary root changed during inspection$",
                ):
                    with self.state_policy.exact_run_tmp_parent(
                        repository,
                        manifest,
                        **dependencies,
                    ):
                        raise AssertionError("entered a replaced root")
                self.assertEqual(events[-1], ("close", 17))
                if not opened_mode_directory:
                    dependencies["same_stat"].assert_not_called()

        events = []
        dependencies, _ = self.run_tmp_parent_dependencies(
            events,
            SimpleNamespace(st_mode="root-mode"),
            SimpleNamespace(st_mode="opened-mode"),
        )
        dependencies["file_close"] = mock.Mock(side_effect=OSError("close"))
        with self.assertRaisesRegex(
            self.engine.LauncherError,
            "^cannot close the run temporary root$",
        ):
            with self.state_policy.exact_run_tmp_parent(
                repository,
                manifest,
                **dependencies,
            ):
                pass

        entry_stat = mock.Mock(side_effect=OSError("probe failed"))
        with self.assertRaisesRegex(
            self.engine.LauncherError,
            "^cannot inspect the run temporary path$",
        ):
            self.state_policy.run_tmp_entry(
                29,
                "20260723t010203z-0123456789ab",
                entry_stat=entry_stat,
                error_type=self.engine.LauncherError,
            )
        entry_stat.assert_called_once_with(
            "20260723t010203z-0123456789ab",
            dir_fd=29,
            follow_symlinks=False,
        )

    def test_run_tmp_parent_kernel_preserves_probe_order_and_close(
        self,
    ) -> None:
        events: list[tuple[str, object]] = []
        root_metadata = SimpleNamespace(st_mode="root-mode")
        opened_metadata = SimpleNamespace(st_mode="opened-mode")
        dependencies, expected = self.run_tmp_parent_dependencies(
            events,
            root_metadata,
            opened_metadata,
        )
        repository = object()
        manifest = {"run_id": "opaque"}

        with self.state_policy.exact_run_tmp_parent(
            repository,
            manifest,
            **dependencies,
        ) as parent:
            events.append(("body", parent))

        self.assertEqual(
            events,
            [
                ("validate", (repository, manifest)),
                ("lstat", expected.parent),
                ("directory-test", "root-mode"),
                ("open", (expected.parent, 1 | 4 | 8 | 16)),
                ("fstat", 17),
                ("directory-test", "opened-mode"),
                ("samestat", (root_metadata, opened_metadata)),
                ("body", (17, "20260723t010203z-0123456789ab")),
                ("close", 17),
            ],
        )

        class BodyFailure(RuntimeError):
            pass

        events.clear()
        with self.assertRaisesRegex(BodyFailure, "^body failed$"):
            with self.state_policy.exact_run_tmp_parent(
                repository,
                manifest,
                **dependencies,
            ):
                raise BodyFailure("body failed")
        self.assertEqual(events[-1], ("close", 17))

        entry_metadata = object()
        entry_stat = mock.Mock(return_value=entry_metadata)
        self.assertIs(
            self.state_policy.run_tmp_entry(
                31,
                "20260723t010203z-0123456789ab",
                entry_stat=entry_stat,
                error_type=self.engine.LauncherError,
            ),
            entry_metadata,
        )
        entry_stat.assert_called_once_with(
            "20260723t010203z-0123456789ab",
            dir_fd=31,
            follow_symlinks=False,
        )

        self.assertIsNone(
            self.state_policy.run_tmp_entry(
                31,
                "20260723t010203z-0123456789ab",
                entry_stat=mock.Mock(side_effect=FileNotFoundError("missing")),
                error_type=mock.Mock(
                    side_effect=AssertionError("raised for a missing entry")
                ),
            )
        )

    def test_run_tmp_parent_matches_real_filesystem_behavior(self) -> None:
        run_id = "20260723t010203z-0123456789ab"
        kernel_dependencies = self.run_tmp_parent_filesystem_dependencies()

        def kernel_entry(descriptor: int, name: str) -> object:
            return self.state_policy.run_tmp_entry(
                descriptor,
                name,
                entry_stat=self.engine.os.stat,
                error_type=self.engine.LauncherError,
            )

        surfaces = (
            (
                "engine",
                self.engine.exact_run_tmp_parent,
                self.engine.run_tmp_entry,
            ),
            (
                "kernel",
                lambda repository, manifest: (
                    self.state_policy.exact_run_tmp_parent(
                        repository,
                        manifest,
                        **kernel_dependencies,
                    )
                ),
                kernel_entry,
            ),
        )
        for label, parent_context, entry in surfaces:
            with self.subTest(surface=label):
                with tempfile.TemporaryDirectory() as temporary:
                    state_root = Path(temporary)
                    (state_root / "tmp" / run_id).mkdir(parents=True)
                    repository = SimpleNamespace(state_root=state_root)
                    manifest = {
                        "run_id": run_id,
                        "tmpdir": str(state_root / "tmp" / run_id),
                    }

                    with parent_context(repository, manifest) as (
                        descriptor,
                        observed_run_id,
                    ):
                        self.assertEqual(observed_run_id, run_id)
                        self.assertIsNotNone(entry(descriptor, run_id))
                        self.assertIsNone(entry(descriptor, "missing-entry"))

                    missing_root = SimpleNamespace(
                        state_root=state_root / "absent"
                    )
                    missing_manifest = {
                        "run_id": run_id,
                        "tmpdir": str(
                            state_root / "absent" / "tmp" / run_id
                        ),
                    }
                    with self.assertRaisesRegex(
                        self.engine.LauncherError,
                        "^cannot inspect the run temporary root$",
                    ):
                        with parent_context(missing_root, missing_manifest):
                            raise AssertionError("entered a missing root")

    def open_temporary_dependencies(
        self,
        events: list[tuple[str, object]],
        opened_metadata: object,
    ) -> dict[str, object]:
        def directory_test(mode: object) -> bool:
            events.append(("directory-test", mode))
            return True

        def file_open(name: object, flags: int, dir_fd: int) -> int:
            events.append(("open", (name, flags, dir_fd)))
            return 21

        def file_stat(descriptor: int) -> object:
            events.append(("fstat", descriptor))
            return opened_metadata

        def same_stat(first: object, second: object) -> bool:
            events.append(("samestat", (first, second)))
            return True

        def file_close(descriptor: int) -> None:
            events.append(("close", descriptor))

        return {
            "directory_flag": 4,
            "nofollow_flag": 8,
            "cloexec_flag": 16,
            "read_only_flag": 1,
            "directory_test": directory_test,
            "file_open": file_open,
            "file_stat": file_stat,
            "same_stat": same_stat,
            "file_close": file_close,
            "error_type": self.engine.LauncherError,
        }

    def temporary_removal_dependencies(
        self,
        events: list[tuple[str, object]],
        metadata_sequences: dict[str, object],
    ) -> dict[str, object]:
        def list_entries(descriptor: int) -> list[str]:
            events.append(("list", descriptor))
            return list(metadata_sequences)

        def entry_metadata(descriptor: int, name: str) -> object:
            events.append(("entry", (descriptor, name)))
            return next(metadata_sequences[name])

        def open_directory(
            descriptor: int,
            name: str,
            expected: object,
        ) -> int:
            events.append(("open-directory", (descriptor, name, expected)))
            return 23

        def remove_contents(descriptor: int) -> None:
            events.append(("remove-contents", descriptor))

        def directory_test(mode: object) -> bool:
            events.append(("directory-test", mode))
            return mode == "directory-mode"

        def same_stat(first: object, second: object) -> bool:
            events.append(("samestat", (first, second)))
            return True

        def remove_directory(name: str, *, dir_fd: int) -> None:
            events.append(("rmdir", (name, dir_fd)))

        def remove_entry(name: str, *, dir_fd: int) -> None:
            events.append(("unlink", (name, dir_fd)))

        def file_close(descriptor: int) -> None:
            events.append(("close", descriptor))

        return {
            "list_entries": list_entries,
            "entry_metadata": entry_metadata,
            "open_directory": open_directory,
            "remove_contents": remove_contents,
            "directory_test": directory_test,
            "same_stat": same_stat,
            "remove_directory": remove_directory,
            "remove_entry": remove_entry,
            "file_close": file_close,
            "error_type": self.engine.LauncherError,
        }

    def test_temporary_traversal_kernel_signatures_and_short_circuits(
        self,
    ) -> None:
        parameters = inspect.signature(
            self.state_policy.open_exact_temporary_directory
        ).parameters
        self.assertEqual(
            tuple(parameters),
            (
                "parent_descriptor",
                "name",
                "expected",
                "directory_flag",
                "nofollow_flag",
                "cloexec_flag",
                "read_only_flag",
                "directory_test",
                "file_open",
                "file_stat",
                "same_stat",
                "file_close",
                "error_type",
            ),
        )
        for name in ("parent_descriptor", "name", "expected"):
            self.assertIs(
                parameters[name].kind,
                inspect.Parameter.POSITIONAL_OR_KEYWORD,
            )
        for parameter in tuple(parameters.values())[3:]:
            self.assertIs(parameter.kind, inspect.Parameter.KEYWORD_ONLY)
            self.assertIs(parameter.default, inspect.Parameter.empty)

        removal_parameters = inspect.signature(
            self.state_policy.remove_open_temporary_contents
        ).parameters
        self.assertEqual(
            tuple(removal_parameters),
            (
                "directory_descriptor",
                "list_entries",
                "entry_metadata",
                "open_directory",
                "remove_contents",
                "directory_test",
                "same_stat",
                "remove_directory",
                "remove_entry",
                "file_close",
                "error_type",
            ),
        )
        self.assertIs(
            removal_parameters["directory_descriptor"].kind,
            inspect.Parameter.POSITIONAL_OR_KEYWORD,
        )
        for parameter in tuple(removal_parameters.values())[1:]:
            self.assertIs(parameter.kind, inspect.Parameter.KEYWORD_ONLY)
            self.assertIs(parameter.default, inspect.Parameter.empty)

        expected_metadata = SimpleNamespace(st_mode="expected-mode")
        for missing_flag in ("directory_flag", "nofollow_flag"):
            with self.subTest(missing_flag=missing_flag):
                events: list[tuple[str, object]] = []
                dependencies = self.open_temporary_dependencies(
                    events,
                    SimpleNamespace(st_mode="opened-mode"),
                )
                dependencies[missing_flag] = 0
                file_open = mock.Mock(
                    side_effect=AssertionError("opened without safe flags")
                )
                dependencies["file_open"] = file_open
                with self.assertRaisesRegex(
                    self.engine.LauncherError,
                    "^safe temporary-directory traversal is unavailable$",
                ):
                    self.state_policy.open_exact_temporary_directory(
                        9,
                        "entry",
                        expected_metadata,
                        **dependencies,
                    )
                file_open.assert_not_called()
                self.assertEqual(events, [])

        events = []
        dependencies = self.open_temporary_dependencies(
            events,
            SimpleNamespace(st_mode="opened-mode"),
        )
        dependencies["file_open"] = mock.Mock(side_effect=OSError("denied"))
        file_close = mock.Mock(
            side_effect=AssertionError("closed a never-opened descriptor")
        )
        dependencies["file_close"] = file_close
        with self.assertRaisesRegex(
            self.engine.LauncherError,
            "^cannot open an authenticated temporary directory$",
        ):
            self.state_policy.open_exact_temporary_directory(
                9,
                "entry",
                expected_metadata,
                **dependencies,
            )
        file_close.assert_not_called()

        events = []
        dependencies = self.open_temporary_dependencies(
            events,
            SimpleNamespace(st_mode="opened-mode"),
        )
        dependencies["file_stat"] = mock.Mock(side_effect=OSError("stat"))
        with self.assertRaisesRegex(
            self.engine.LauncherError,
            "^cannot authenticate a temporary directory$",
        ):
            self.state_policy.open_exact_temporary_directory(
                9,
                "entry",
                expected_metadata,
                **dependencies,
            )
        self.assertEqual(events[-1], ("close", 21))

        for case, same_stat_result, opened_directory in (
            ("replaced-mode", True, False),
            ("replaced-identity", False, True),
        ):
            with self.subTest(case=case):
                events = []
                dependencies = self.open_temporary_dependencies(
                    events,
                    SimpleNamespace(st_mode="opened-mode"),
                )
                dependencies["directory_test"] = lambda mode: opened_directory
                dependencies["same_stat"] = mock.Mock(
                    return_value=same_stat_result
                )
                with self.assertRaisesRegex(
                    self.engine.LauncherError,
                    "^a temporary directory changed before removal$",
                ):
                    self.state_policy.open_exact_temporary_directory(
                        9,
                        "entry",
                        expected_metadata,
                        **dependencies,
                    )
                self.assertEqual(events[-1], ("close", 21))
                if not opened_directory:
                    dependencies["same_stat"].assert_not_called()

        events = []
        dependencies = self.temporary_removal_dependencies(events, {})
        dependencies["list_entries"] = mock.Mock(side_effect=OSError("list"))
        entry_metadata = mock.Mock(
            side_effect=AssertionError("probed an unlisted directory")
        )
        dependencies["entry_metadata"] = entry_metadata
        with self.assertRaisesRegex(
            self.engine.LauncherError,
            "^cannot list an authenticated temporary directory$",
        ):
            self.state_policy.remove_open_temporary_contents(
                9,
                **dependencies,
            )
        entry_metadata.assert_not_called()

        events = []
        dependencies = self.temporary_removal_dependencies(
            events,
            {"vanished": iter((None,))},
        )
        open_directory = mock.Mock(
            side_effect=AssertionError("opened a vanished entry")
        )
        dependencies["open_directory"] = open_directory
        with self.assertRaisesRegex(
            self.engine.LauncherError,
            "^a temporary entry changed during removal$",
        ):
            self.state_policy.remove_open_temporary_contents(
                9,
                **dependencies,
            )
        open_directory.assert_not_called()

        before_file = SimpleNamespace(st_mode="file-mode")
        for case, sequence, same_stat_result in (
            ("vanished-current", (before_file, None), True),
            ("replaced-current", (before_file, before_file), False),
        ):
            with self.subTest(case=case):
                events = []
                dependencies = self.temporary_removal_dependencies(
                    events,
                    {"leaf": iter(sequence)},
                )
                dependencies["same_stat"] = lambda first, second: (
                    same_stat_result
                )
                remove_entry = mock.Mock(
                    side_effect=AssertionError("removed a changed entry")
                )
                dependencies["remove_entry"] = remove_entry
                with self.assertRaisesRegex(
                    self.engine.LauncherError,
                    "^a temporary entry changed during removal$",
                ):
                    self.state_policy.remove_open_temporary_contents(
                        9,
                        **dependencies,
                    )
                remove_entry.assert_not_called()

        events = []
        dependencies = self.temporary_removal_dependencies(
            events,
            {"leaf": iter((before_file, before_file))},
        )
        dependencies["remove_entry"] = mock.Mock(side_effect=OSError("unlink"))
        with self.assertRaisesRegex(
            self.engine.LauncherError,
            "^cannot remove an authenticated temporary entry$",
        ):
            self.state_policy.remove_open_temporary_contents(
                9,
                **dependencies,
            )

        events = []
        dependencies = self.temporary_removal_dependencies(
            events,
            {"leaf": iter((before_file, before_file, before_file))},
        )
        with self.assertRaisesRegex(
            self.engine.LauncherError,
            "^a temporary entry was replaced during removal$",
        ):
            self.state_policy.remove_open_temporary_contents(
                9,
                **dependencies,
            )

        before_directory = SimpleNamespace(st_mode="directory-mode")
        events = []
        dependencies = self.temporary_removal_dependencies(
            events,
            {"child": iter((before_directory, None))},
        )
        remove_directory = mock.Mock(
            side_effect=AssertionError("removed a changed directory")
        )
        dependencies["remove_directory"] = remove_directory
        with self.assertRaisesRegex(
            self.engine.LauncherError,
            "^a temporary directory changed during removal$",
        ):
            self.state_policy.remove_open_temporary_contents(
                9,
                **dependencies,
            )
        remove_directory.assert_not_called()
        self.assertEqual(events[-1], ("close", 23))

        events = []
        dependencies = self.temporary_removal_dependencies(
            events,
            {"child": iter((before_directory, before_directory))},
        )
        dependencies["remove_directory"] = mock.Mock(
            side_effect=OSError("rmdir")
        )
        with self.assertRaisesRegex(
            self.engine.LauncherError,
            "^cannot remove an authenticated temporary directory$",
        ):
            self.state_policy.remove_open_temporary_contents(
                9,
                **dependencies,
            )
        self.assertEqual(events[-1], ("close", 23))

    def test_temporary_traversal_kernel_preserves_probe_order(self) -> None:
        events: list[tuple[str, object]] = []
        expected_metadata = SimpleNamespace(st_mode="expected-mode")
        opened_metadata = SimpleNamespace(st_mode="opened-mode")
        dependencies = self.open_temporary_dependencies(
            events,
            opened_metadata,
        )
        dependencies["file_close"] = mock.Mock(
            side_effect=AssertionError("closed an authenticated descriptor")
        )

        observed = self.state_policy.open_exact_temporary_directory(
            9,
            "entry",
            expected_metadata,
            **dependencies,
        )

        self.assertEqual(observed, 21)
        self.assertEqual(
            events,
            [
                ("open", ("entry", 1 | 4 | 8 | 16, 9)),
                ("fstat", 21),
                ("directory-test", "opened-mode"),
                ("samestat", (expected_metadata, opened_metadata)),
            ],
        )
        dependencies["file_close"].assert_not_called()

        events = []
        before_directory = SimpleNamespace(st_mode="directory-mode")
        before_file = SimpleNamespace(st_mode="file-mode")
        metadata_sequences = {
            "child": iter((before_directory, before_directory, None)),
            "leaf": iter((before_file, before_file, None)),
        }
        removal_dependencies = self.temporary_removal_dependencies(
            events,
            metadata_sequences,
        )

        self.assertIsNone(
            self.state_policy.remove_open_temporary_contents(
                9,
                **removal_dependencies,
            )
        )
        self.assertEqual(
            events,
            [
                ("list", 9),
                ("entry", (9, "child")),
                ("directory-test", "directory-mode"),
                ("open-directory", (9, "child", before_directory)),
                ("remove-contents", 23),
                ("entry", (9, "child")),
                ("samestat", (before_directory, before_directory)),
                ("rmdir", ("child", 9)),
                ("close", 23),
                ("entry", (9, "child")),
                ("entry", (9, "leaf")),
                ("directory-test", "file-mode"),
                ("entry", (9, "leaf")),
                ("samestat", (before_file, before_file)),
                ("unlink", ("leaf", 9)),
                ("entry", (9, "leaf")),
            ],
        )

    def run_tmp_lifecycle_dependencies(
        self,
        events: list[tuple[str, object]],
        metadata_sequence: object,
    ) -> dict[str, object]:
        test_case = self

        def authenticate_parent(repository: object, manifest: object) -> object:
            events.append(("authenticate", (repository, manifest)))

            class Parent:
                def __enter__(parent_self) -> tuple[int, str]:
                    events.append(("enter", None))
                    return (9, "run-entry")

                def __exit__(parent_self, *exc_info: object) -> bool:
                    events.append(("exit", exc_info[0]))
                    return False

            return Parent()

        def entry_metadata(descriptor: int, name: str) -> object:
            events.append(("entry", (descriptor, name)))
            return next(metadata_sequence)

        def directory_test(mode: object) -> bool:
            events.append(("directory-test", mode))
            return mode == "directory-mode"

        def open_directory(
            descriptor: int,
            name: str,
            expected: object,
        ) -> int:
            events.append(("open-directory", (descriptor, name, expected)))
            return 23

        def remove_contents(descriptor: int) -> None:
            events.append(("remove-contents", descriptor))

        def same_stat(first: object, second: object) -> bool:
            events.append(("samestat", (first, second)))
            return True

        def remove_directory(name: str, *, dir_fd: int) -> None:
            events.append(("rmdir", (name, dir_fd)))

        def file_close(descriptor: int) -> None:
            events.append(("close", descriptor))

        return {
            "authenticate_parent": authenticate_parent,
            "entry_metadata": entry_metadata,
            "directory_test": directory_test,
            "open_directory": open_directory,
            "remove_contents": remove_contents,
            "same_stat": same_stat,
            "remove_directory": remove_directory,
            "file_close": file_close,
            "error_type": test_case.engine.LauncherError,
        }

    def test_run_tmp_lifecycle_kernel_signatures_and_short_circuits(
        self,
    ) -> None:
        expected_signatures = {
            "remove_run_tmpdir": (
                "repository",
                "manifest",
                "authenticate_parent",
                "entry_metadata",
                "directory_test",
                "open_directory",
                "remove_contents",
                "same_stat",
                "remove_directory",
                "file_close",
                "error_type",
            ),
            "require_run_tmp_absent": (
                "repository",
                "manifest",
                "authenticate_parent",
                "entry_metadata",
                "error_type",
            ),
            "require_run_tmp_directory": (
                "repository",
                "manifest",
                "authenticate_parent",
                "entry_metadata",
                "directory_test",
                "open_directory",
                "file_close",
                "error_type",
            ),
        }
        for kernel_name, expected in expected_signatures.items():
            with self.subTest(kernel=kernel_name):
                parameters = inspect.signature(
                    getattr(self.state_policy, kernel_name)
                ).parameters
                self.assertEqual(tuple(parameters), expected)
                for name in ("repository", "manifest"):
                    self.assertIs(
                        parameters[name].kind,
                        inspect.Parameter.POSITIONAL_OR_KEYWORD,
                    )
                for parameter in tuple(parameters.values())[2:]:
                    self.assertIs(
                        parameter.kind,
                        inspect.Parameter.KEYWORD_ONLY,
                    )
                    self.assertIs(
                        parameter.default,
                        inspect.Parameter.empty,
                    )

        repository = object()
        manifest = {"run_id": "opaque"}
        before_directory = SimpleNamespace(st_mode="directory-mode")
        before_file = SimpleNamespace(st_mode="file-mode")

        events: list[tuple[str, object]] = []
        dependencies = self.run_tmp_lifecycle_dependencies(
            events,
            iter((None,)),
        )
        open_directory = mock.Mock(
            side_effect=AssertionError("opened an absent temporary path")
        )
        dependencies["open_directory"] = open_directory
        self.assertIsNone(
            self.state_policy.remove_run_tmpdir(
                repository,
                manifest,
                **dependencies,
            )
        )
        open_directory.assert_not_called()
        self.assertEqual(events[-1], ("exit", None))

        events = []
        dependencies = self.run_tmp_lifecycle_dependencies(
            events,
            iter((before_file,)),
        )
        open_directory = mock.Mock(
            side_effect=AssertionError("opened a non-directory path")
        )
        dependencies["open_directory"] = open_directory
        with self.assertRaisesRegex(
            self.engine.LauncherError,
            "^the run temporary path is not an exact real directory$",
        ):
            self.state_policy.remove_run_tmpdir(
                repository,
                manifest,
                **dependencies,
            )
        open_directory.assert_not_called()

        events = []
        dependencies = self.run_tmp_lifecycle_dependencies(
            events,
            iter((before_directory, None)),
        )
        remove_directory = mock.Mock(
            side_effect=AssertionError("removed a moved path")
        )
        dependencies["remove_directory"] = remove_directory
        with self.assertRaisesRegex(
            self.engine.LauncherError,
            "^the run temporary path moved during removal$",
        ):
            self.state_policy.remove_run_tmpdir(
                repository,
                manifest,
                **dependencies,
            )
        remove_directory.assert_not_called()
        self.assertIn(("close", 23), events)

        events = []
        dependencies = self.run_tmp_lifecycle_dependencies(
            events,
            iter((before_directory, before_directory)),
        )
        dependencies["same_stat"] = lambda first, second: False
        remove_directory = mock.Mock(
            side_effect=AssertionError("removed a replaced path")
        )
        dependencies["remove_directory"] = remove_directory
        with self.assertRaisesRegex(
            self.engine.LauncherError,
            "^the run temporary path was replaced during removal$",
        ):
            self.state_policy.remove_run_tmpdir(
                repository,
                manifest,
                **dependencies,
            )
        remove_directory.assert_not_called()
        self.assertIn(("close", 23), events)

        events = []
        dependencies = self.run_tmp_lifecycle_dependencies(
            events,
            iter((before_directory, before_directory)),
        )
        dependencies["remove_directory"] = mock.Mock(
            side_effect=OSError("rmdir")
        )
        with self.assertRaisesRegex(
            self.engine.LauncherError,
            "^authenticated run temporary-directory removal failed$",
        ):
            self.state_policy.remove_run_tmpdir(
                repository,
                manifest,
                **dependencies,
            )
        self.assertIn(("close", 23), events)

        for case, after_same, expected_message in (
            ("retained", True, "the run temporary path was retained"),
            (
                "replaced",
                False,
                "the run temporary path was replaced during removal",
            ),
        ):
            with self.subTest(case=case):
                events = []
                dependencies = self.run_tmp_lifecycle_dependencies(
                    events,
                    iter(
                        (
                            before_directory,
                            before_directory,
                            before_directory,
                        )
                    ),
                )
                same_stat_results = iter((True, after_same))
                dependencies["same_stat"] = lambda first, second: next(
                    same_stat_results
                )
                with self.assertRaisesRegex(
                    self.engine.LauncherError,
                    f"^{expected_message}$",
                ):
                    self.state_policy.remove_run_tmpdir(
                        repository,
                        manifest,
                        **dependencies,
                    )

        events = []
        dependencies = self.run_tmp_lifecycle_dependencies(
            events,
            iter((before_directory,)),
        )
        absent_dependencies = {
            key: dependencies[key]
            for key in ("authenticate_parent", "entry_metadata", "error_type")
        }
        with self.assertRaisesRegex(
            self.engine.LauncherError,
            "^the cleaned run unexpectedly retains a temporary path$",
        ):
            self.state_policy.require_run_tmp_absent(
                repository,
                manifest,
                **absent_dependencies,
            )

        for case, sequence in (
            ("absent", (None,)),
            ("non-directory", (before_file,)),
        ):
            with self.subTest(case=case):
                events = []
                dependencies = self.run_tmp_lifecycle_dependencies(
                    events,
                    iter(sequence),
                )
                open_directory = mock.Mock(
                    side_effect=AssertionError("opened an invalid path")
                )
                dependencies["open_directory"] = open_directory
                directory_dependencies = {
                    key: dependencies[key]
                    for key in (
                        "authenticate_parent",
                        "entry_metadata",
                        "directory_test",
                        "open_directory",
                        "file_close",
                        "error_type",
                    )
                }
                with self.assertRaisesRegex(
                    self.engine.LauncherError,
                    "^the run temporary path is not an exact real directory$",
                ):
                    self.state_policy.require_run_tmp_directory(
                        repository,
                        manifest,
                        **directory_dependencies,
                    )
                open_directory.assert_not_called()

    def test_run_tmp_lifecycle_kernels_preserve_probe_order(self) -> None:
        repository = object()
        manifest = {"run_id": "opaque"}
        before_directory = SimpleNamespace(st_mode="directory-mode")

        events: list[tuple[str, object]] = []
        dependencies = self.run_tmp_lifecycle_dependencies(
            events,
            iter((before_directory, before_directory, None)),
        )
        self.assertIsNone(
            self.state_policy.remove_run_tmpdir(
                repository,
                manifest,
                **dependencies,
            )
        )
        self.assertEqual(
            events,
            [
                ("authenticate", (repository, manifest)),
                ("enter", None),
                ("entry", (9, "run-entry")),
                ("directory-test", "directory-mode"),
                ("open-directory", (9, "run-entry", before_directory)),
                ("remove-contents", 23),
                ("entry", (9, "run-entry")),
                ("samestat", (before_directory, before_directory)),
                ("rmdir", ("run-entry", 9)),
                ("close", 23),
                ("entry", (9, "run-entry")),
                ("exit", None),
            ],
        )

        events = []
        dependencies = self.run_tmp_lifecycle_dependencies(
            events,
            iter((None,)),
        )
        absent_dependencies = {
            key: dependencies[key]
            for key in ("authenticate_parent", "entry_metadata", "error_type")
        }
        self.assertIsNone(
            self.state_policy.require_run_tmp_absent(
                repository,
                manifest,
                **absent_dependencies,
            )
        )
        self.assertEqual(
            events,
            [
                ("authenticate", (repository, manifest)),
                ("enter", None),
                ("entry", (9, "run-entry")),
                ("exit", None),
            ],
        )

        events = []
        dependencies = self.run_tmp_lifecycle_dependencies(
            events,
            iter((before_directory,)),
        )
        directory_dependencies = {
            key: dependencies[key]
            for key in (
                "authenticate_parent",
                "entry_metadata",
                "directory_test",
                "open_directory",
                "file_close",
                "error_type",
            )
        }
        self.assertIsNone(
            self.state_policy.require_run_tmp_directory(
                repository,
                manifest,
                **directory_dependencies,
            )
        )
        self.assertEqual(
            events,
            [
                ("authenticate", (repository, manifest)),
                ("enter", None),
                ("entry", (9, "run-entry")),
                ("directory-test", "directory-mode"),
                ("open-directory", (9, "run-entry", before_directory)),
                ("close", 23),
                ("exit", None),
            ],
        )

    def test_run_tmp_lifecycle_matches_real_filesystem_behavior(self) -> None:
        run_id = "20260723t010203z-0123456789ab"
        remove_dependencies = {
            "authenticate_parent": self.engine.exact_run_tmp_parent,
            "entry_metadata": self.engine.run_tmp_entry,
            "directory_test": self.engine.stat.S_ISDIR,
            "open_directory": self.engine.open_exact_temporary_directory,
            "remove_contents": self.engine.remove_open_temporary_contents,
            "same_stat": self.engine.os.path.samestat,
            "remove_directory": self.engine.os.rmdir,
            "file_close": self.engine.os.close,
            "error_type": self.engine.LauncherError,
        }
        absent_dependencies = {
            key: remove_dependencies[key]
            for key in ("authenticate_parent", "entry_metadata", "error_type")
        }
        directory_dependencies = {
            key: remove_dependencies[key]
            for key in (
                "authenticate_parent",
                "entry_metadata",
                "directory_test",
                "open_directory",
                "file_close",
                "error_type",
            )
        }
        surfaces = (
            (
                "engine",
                self.engine.remove_run_tmpdir,
                self.engine.require_run_tmp_absent,
                self.engine.require_run_tmp_directory,
            ),
            (
                "kernel",
                lambda repository, manifest: (
                    self.state_policy.remove_run_tmpdir(
                        repository,
                        manifest,
                        **remove_dependencies,
                    )
                ),
                lambda repository, manifest: (
                    self.state_policy.require_run_tmp_absent(
                        repository,
                        manifest,
                        **absent_dependencies,
                    )
                ),
                lambda repository, manifest: (
                    self.state_policy.require_run_tmp_directory(
                        repository,
                        manifest,
                        **directory_dependencies,
                    )
                ),
            ),
        )
        for label, remove, require_absent, require_directory in surfaces:
            with self.subTest(surface=label):
                with tempfile.TemporaryDirectory() as temporary:
                    state_root = Path(temporary)
                    run_temporary = state_root / "tmp" / run_id
                    (run_temporary / "nested").mkdir(parents=True)
                    (run_temporary / "nested" / "inner.txt").write_text(
                        "inner\n",
                        encoding="utf-8",
                    )
                    (run_temporary / "outer.txt").write_text(
                        "outer\n",
                        encoding="utf-8",
                    )
                    repository = SimpleNamespace(state_root=state_root)
                    manifest = {
                        "run_id": run_id,
                        "tmpdir": str(run_temporary),
                    }

                    self.assertIsNone(
                        require_directory(repository, manifest)
                    )
                    self.assertIsNone(remove(repository, manifest))
                    self.assertFalse(run_temporary.exists())
                    self.assertTrue(run_temporary.parent.is_dir())
                    self.assertIsNone(require_absent(repository, manifest))
                    self.assertIsNone(remove(repository, manifest))
                    with self.assertRaisesRegex(
                        self.engine.LauncherError,
                        "^the run temporary path is not an exact"
                        " real directory$",
                    ):
                        require_directory(repository, manifest)

    def test_retirement_parameter_kernel_signatures_and_short_circuits(
        self,
    ) -> None:
        expected_signatures = {
            "retirement_parameters": (
                "manifest",
                "retirement_core_fields",
                "object_id_pattern",
                "error_type",
            ),
            "require_matching_retirement_arguments": (
                "manifest",
                "discard_head",
                "target_contains",
                "retirement_parameters",
                "error_type",
            ),
            "reject_conflicting_retirement_lifecycle": (
                "manifest",
                "error_type",
            ),
            "retirement_cleanup_target": (
                "manifest",
                "object_id_pattern",
                "error_type",
            ),
        }
        injected_counts = {
            "retirement_parameters": 1,
            "require_matching_retirement_arguments": 3,
            "reject_conflicting_retirement_lifecycle": 1,
            "retirement_cleanup_target": 1,
        }
        for kernel_name, expected in expected_signatures.items():
            with self.subTest(kernel=kernel_name):
                parameters = inspect.signature(
                    getattr(self.state_policy, kernel_name)
                ).parameters
                self.assertEqual(tuple(parameters), expected)
                data_count = injected_counts[kernel_name]
                for parameter in tuple(parameters.values())[:data_count]:
                    self.assertIs(
                        parameter.kind,
                        inspect.Parameter.POSITIONAL_OR_KEYWORD,
                    )
                for parameter in tuple(parameters.values())[data_count:]:
                    self.assertIs(
                        parameter.kind,
                        inspect.Parameter.KEYWORD_ONLY,
                    )
                    self.assertIs(
                        parameter.default,
                        inspect.Parameter.empty,
                    )

        pattern = mock.Mock()
        for manifest in ({}, {"first": 17}, {"first": None}):
            with self.subTest(manifest=manifest), self.assertRaisesRegex(
                self.engine.LauncherError,
                "^the retained run has an incomplete retirement checkpoint$",
            ):
                self.state_policy.retirement_parameters(
                    manifest,
                    retirement_core_fields=("first", "second", "third"),
                    object_id_pattern=pattern,
                    error_type=self.engine.LauncherError,
                )
        pattern.fullmatch.assert_not_called()

        pattern = mock.Mock()
        pattern.fullmatch.side_effect = lambda value: value == "a" * 40
        with self.assertRaisesRegex(
            self.engine.LauncherError,
            "^the retained run has an incomplete retirement checkpoint$",
        ):
            self.state_policy.retirement_parameters(
                {"first": "a" * 40, "second": "not-an-object", "third": 17},
                retirement_core_fields=("first", "second", "third"),
                object_id_pattern=pattern,
                error_type=self.engine.LauncherError,
            )
        self.assertEqual(
            pattern.fullmatch.call_args_list,
            [mock.call("a" * 40), mock.call("not-an-object")],
        )

        recorded = mock.Mock(return_value=("discard", "contains", "target"))
        for discard_head, target_contains in (
            ("other-discard", "contains"),
            ("discard", "other-contains"),
        ):
            recorded.reset_mock()
            with self.subTest(
                arguments=(discard_head, target_contains)
            ), self.assertRaisesRegex(
                self.engine.LauncherError,
                "^the retirement command's object arguments differ"
                " from the durable checkpoint$",
            ):
                self.state_policy.require_matching_retirement_arguments(
                    {"manifest": "opaque"},
                    discard_head,
                    target_contains,
                    retirement_parameters=recorded,
                    error_type=self.engine.LauncherError,
                )
            recorded.assert_called_once_with({"manifest": "opaque"})

        conflict_cases = (
            (
                {"background_process_active": True},
                "the quarantined run still records a background worker",
            ),
            (
                {"integrated_head": "a" * 40},
                "the quarantined run has a conflicting integration transaction",
            ),
            (
                {"integrated_at": "now"},
                "the quarantined run has a conflicting integration transaction",
            ),
            (
                {"integration_previous_state": "preserved"},
                "the quarantined run has a conflicting integration transaction",
            ),
            (
                {"cleanup_expected_head": "a" * 40},
                "the quarantined run has an unrelated cleanup transaction",
            ),
            (
                {"cleanup_warning": "warning"},
                "the quarantined run has an unrelated cleanup transaction",
            ),
            (
                {"cleaned_at": "now"},
                "the quarantined run has an unrelated cleanup transaction",
            ),
            (
                {"branch_cleaned_at": "now"},
                "the quarantined run has an unrelated cleanup transaction",
            ),
            (
                {
                    "background_process_active": True,
                    "integrated_head": "a" * 40,
                    "cleaned_at": "now",
                },
                "the quarantined run still records a background worker",
            ),
        )
        for manifest, expected_message in conflict_cases:
            with self.subTest(manifest=manifest), self.assertRaisesRegex(
                self.engine.LauncherError,
                f"^{re.escape(expected_message)}$",
            ):
                self.state_policy.reject_conflicting_retirement_lifecycle(
                    manifest,
                    error_type=self.engine.LauncherError,
                )

        pattern = mock.Mock()
        for manifest in (
            {},
            {"retirement_cleanup_target_head": 17},
            {"retirement_cleanup_target_head": None},
        ):
            with self.subTest(manifest=manifest), self.assertRaisesRegex(
                self.engine.LauncherError,
                "^the retirement ref cleanup has no exact target checkpoint$",
            ):
                self.state_policy.retirement_cleanup_target(
                    manifest,
                    object_id_pattern=pattern,
                    error_type=self.engine.LauncherError,
                )
        pattern.fullmatch.assert_not_called()

        for manifest in (
            {"retirement_cleanup_target_head": "not-an-object"},
            {"retirement_cleanup_target_head": "a" * 40},
        ):
            with self.subTest(manifest=manifest), self.assertRaisesRegex(
                self.engine.LauncherError,
                "^the retirement ref cleanup has no exact target checkpoint$",
            ):
                self.state_policy.retirement_cleanup_target(
                    manifest,
                    object_id_pattern=re.compile(r"^[0-9a-f]{40}$"),
                    error_type=self.engine.LauncherError,
                )

    def test_retirement_parameter_kernels_preserve_probe_behavior(
        self,
    ) -> None:
        events: list[tuple[str, object]] = []

        class Pattern:
            def fullmatch(pattern_self, value: str) -> bool:
                events.append(("fullmatch", value))
                return True

        observed = self.state_policy.retirement_parameters(
            {
                "first": "discard",
                "second": "contains",
                "third": "target",
                "unrelated": 17,
            },
            retirement_core_fields=("first", "second", "third"),
            object_id_pattern=Pattern(),
            error_type=self.engine.LauncherError,
        )
        self.assertEqual(observed, ("discard", "contains", "target"))
        self.assertEqual(
            events,
            [
                ("fullmatch", "discard"),
                ("fullmatch", "contains"),
                ("fullmatch", "target"),
            ],
        )

        recorded = mock.Mock(return_value=("discard", "contains", "target"))
        self.assertIsNone(
            self.state_policy.require_matching_retirement_arguments(
                {"manifest": "opaque"},
                "discard",
                "contains",
                retirement_parameters=recorded,
                error_type=mock.Mock(
                    side_effect=AssertionError("raised for exact arguments")
                ),
            )
        )
        recorded.assert_called_once_with({"manifest": "opaque"})

        self.assertIsNone(
            self.state_policy.reject_conflicting_retirement_lifecycle(
                {
                    "state": "retirement-pending",
                    "retirement_started_at": "now",
                    "background_process_active": False,
                    "integrated_head": None,
                },
                error_type=mock.Mock(
                    side_effect=AssertionError("raised for a clean lifecycle")
                ),
            )
        )

        events.clear()
        self.assertEqual(
            self.state_policy.retirement_cleanup_target(
                {
                    "retirement_cleanup_target_head": "cleanup-target",
                    "retirement_ref_cleanup_started_at": "now",
                },
                object_id_pattern=Pattern(),
                error_type=self.engine.LauncherError,
            ),
            "cleanup-target",
        )
        self.assertEqual(events, [("fullmatch", "cleanup-target")])

    def test_engine_preserves_run_identity_and_path_surfaces(self) -> None:
        self.assertIs(self.engine.RUN_ID_RE, self.state_policy.RUN_ID_RE)
        for helper_name in (
            "new_run_id",
            "repo_lock_path",
            "run_lock_path",
            "manifest_path",
            "exact_run_tmp_parent",
            "run_tmp_entry",
            "open_exact_temporary_directory",
            "remove_open_temporary_contents",
            "remove_run_tmpdir",
            "require_run_tmp_absent",
            "require_run_tmp_directory",
            "retirement_parameters",
            "require_matching_retirement_arguments",
            "reject_conflicting_retirement_lifecycle",
            "retirement_cleanup_target",
        ):
            with self.subTest(helper=helper_name):
                self.assertIsNot(
                    getattr(self.engine, helper_name),
                    getattr(self.state_policy, helper_name),
                )

        expected_parameters = {
            "new_run_id": (),
            "repo_lock_path": ("repository",),
            "run_lock_path": ("repository", "run_id"),
            "manifest_path": ("repository", "run_id"),
            "validate_run_id": ("run_id",),
            "exact_run_tmp_parent": ("repository", "manifest"),
            "run_tmp_entry": ("parent_descriptor", "run_id"),
            "open_exact_temporary_directory": (
                "parent_descriptor",
                "name",
                "expected",
            ),
            "remove_open_temporary_contents": ("directory_descriptor",),
            "remove_run_tmpdir": ("repository", "manifest"),
            "require_run_tmp_absent": ("repository", "manifest"),
            "require_run_tmp_directory": ("repository", "manifest"),
            "retirement_parameters": ("manifest",),
            "require_matching_retirement_arguments": (
                "manifest",
                "discard_head",
                "target_contains",
            ),
            "reject_conflicting_retirement_lifecycle": ("manifest",),
            "retirement_cleanup_target": ("manifest",),
        }
        for helper_name, expected in expected_parameters.items():
            with self.subTest(signature=helper_name):
                parameters = inspect.signature(
                    getattr(self.engine, helper_name)
                ).parameters
                self.assertEqual(tuple(parameters), expected)
                for parameter in parameters.values():
                    self.assertIs(
                        parameter.kind,
                        inspect.Parameter.POSITIONAL_OR_KEYWORD,
                    )
                    self.assertIs(parameter.default, inspect.Parameter.empty)

    def test_state_location_kernel_and_engine_wrapper_signatures(self) -> None:
        state_base_parameters = inspect.signature(
            self.state_policy.state_base
        ).parameters
        self.assertEqual(
            tuple(state_base_parameters),
            (
                "profile",
                "environment",
                "path_factory",
                "home",
                "error_type",
            ),
        )
        for parameter in state_base_parameters.values():
            self.assertIs(parameter.kind, inspect.Parameter.KEYWORD_ONLY)
            self.assertIs(parameter.default, inspect.Parameter.empty)

        repository_slug_parameters = inspect.signature(
            self.state_policy.repository_slug
        ).parameters
        self.assertEqual(
            tuple(repository_slug_parameters),
            ("root", "substitute"),
        )
        self.assertIs(
            repository_slug_parameters["root"].kind,
            inspect.Parameter.POSITIONAL_OR_KEYWORD,
        )
        self.assertIs(
            repository_slug_parameters["substitute"].kind,
            inspect.Parameter.KEYWORD_ONLY,
        )
        for parameter in repository_slug_parameters.values():
            self.assertIs(parameter.default, inspect.Parameter.empty)

        expected_engine_parameters = {
            "state_base": (),
            "repository_slug": ("root",),
        }
        for helper_name, expected in expected_engine_parameters.items():
            with self.subTest(engine_wrapper=helper_name):
                self.assertIsNot(
                    getattr(self.engine, helper_name),
                    getattr(self.state_policy, helper_name),
                )
                parameters = inspect.signature(
                    getattr(self.engine, helper_name)
                ).parameters
                self.assertEqual(tuple(parameters), expected)
                for parameter in parameters.values():
                    self.assertIs(
                        parameter.kind,
                        inspect.Parameter.POSITIONAL_OR_KEYWORD,
                    )
                    self.assertIs(parameter.default, inspect.Parameter.empty)

    def test_run_id_grammar_is_exact_and_syntactic(self) -> None:
        self.assertEqual(
            self.state_policy.RUN_ID_RE.pattern,
            r"^[0-9]{8}t[0-9]{6}z-[0-9a-f]{12}$",
        )
        self.assertEqual(self.state_policy.RUN_ID_RE.flags, re.UNICODE)

        valid = (
            "20260723t010203z-000000000000",
            "19991231t235959z-abcdef012345",
            "00000000t000000z-ffffffffffff",
            "99999999t999999z-deadbeefcafe",
        )
        invalid = (
            "",
            "20260723T010203z-000000000000",
            "20260723t010203Z-000000000000",
            "20260723t010203z-ABCDEF012345",
            "2026072t010203z-000000000000",
            "202607230t010203z-000000000000",
            "20260723t01020z-000000000000",
            "20260723t0102030z-000000000000",
            "20260723t010203z-00000000000",
            "20260723t010203z-0000000000000",
            "20260723-010203z-000000000000",
            "20260723t010203-000000000000",
            "20260723t010203z_000000000000",
            "x20260723t010203z-000000000000",
            "20260723t010203z-000000000000x",
            "20260723t010203z-000000000000\n",
            " 20260723t010203z-000000000000",
            "２０２６０７２３t010203z-000000000000",
            "../20260723t010203z-000000000000",
        )
        for run_id in valid:
            with self.subTest(valid=run_id):
                self.assertIsNotNone(
                    self.state_policy.RUN_ID_RE.fullmatch(run_id)
                )
        for run_id in invalid:
            with self.subTest(invalid=run_id):
                self.assertIsNone(
                    self.state_policy.RUN_ID_RE.fullmatch(run_id)
                )

        for value in (None, 17, b"20260723t010203z-000000000000"):
            with self.subTest(non_string=value):
                with self.assertRaises(TypeError):
                    self.state_policy.RUN_ID_RE.fullmatch(value)

    def test_validate_run_id_keeps_engine_regex_and_lazy_diagnostic(
        self,
    ) -> None:
        valid = "20260723t010203z-000000000000"
        with mock.patch.object(
            self.engine,
            "active_profile",
            side_effect=AssertionError("profile acquired for a valid run ID"),
        ) as active_profile:
            self.engine.validate_run_id(valid)
        active_profile.assert_not_called()

        events: list[tuple[str, object]] = []

        class InitialError(RuntimeError):
            pass

        class ExpectedError(RuntimeError):
            pass

        class TooLateError(RuntimeError):
            pass

        def rebound_profile() -> object:
            events.append(("profile", None))
            self.engine.LauncherError = TooLateError
            return SimpleNamespace(display_name="Rebound Marshal")

        class RebindingPattern:
            def fullmatch(pattern_self, run_id: str) -> None:
                events.append(("fullmatch", run_id))
                self.engine.LauncherError = ExpectedError
                self.engine.active_profile = rebound_profile
                return None

        with (
            mock.patch.object(
                self.engine,
                "RUN_ID_RE",
                RebindingPattern(),
            ),
            mock.patch.object(self.engine, "LauncherError", InitialError),
            mock.patch.object(
                self.engine,
                "active_profile",
                side_effect=AssertionError("captured the old profile resolver"),
            ),
        ):
            with self.assertRaisesRegex(
                ExpectedError,
                "^invalid Rebound Marshal run ID$",
            ):
                self.engine.validate_run_id("invalid")

        self.assertEqual(
            events,
            [
                ("fullmatch", "invalid"),
                ("profile", None),
            ],
        )

        for value in (None, 17, b"invalid"):
            with self.subTest(non_string=value):
                with mock.patch.object(
                    self.engine,
                    "active_profile",
                    side_effect=AssertionError(
                        "profile acquired after regex type failure"
                    ),
                ) as active_profile:
                    with self.assertRaises(TypeError):
                        self.engine.validate_run_id(value)
                active_profile.assert_not_called()

    def test_new_run_id_kernel_preserves_exact_operation_order(self) -> None:
        events: list[tuple[str, object]] = []

        class LoweredStamp:
            def __format__(stamp_self, specification: str) -> str:
                events.append(("format-stamp", specification))
                return "20260723t010203z"

        class FormattedStamp:
            def lower(stamp_self) -> object:
                events.append(("lower", None))
                return LoweredStamp()

        class Timestamp:
            def strftime(timestamp_self, format_string: str) -> object:
                events.append(("strftime", format_string))
                return FormattedStamp()

        class RandomSuffix:
            def __format__(suffix_self, specification: str) -> str:
                events.append(("format-suffix", specification))
                return "AbCdEf012345"

        def current_time() -> object:
            events.append(("current-time", None))
            return Timestamp()

        def random_suffix() -> object:
            events.append(("random-suffix", None))
            return RandomSuffix()

        observed = self.state_policy.new_run_id(
            current_time=current_time,
            random_suffix=random_suffix,
        )

        self.assertEqual(observed, "20260723t010203z-AbCdEf012345")
        self.assertEqual(
            events,
            [
                ("current-time", None),
                ("strftime", "%Y%m%dt%H%M%Sz"),
                ("lower", None),
                ("format-stamp", ""),
                ("random-suffix", None),
                ("format-suffix", ""),
            ],
        )

    def test_new_run_id_does_not_consume_entropy_after_stamp_failures(
        self,
    ) -> None:
        class ClockFailure(RuntimeError):
            pass

        class FormatFailure(RuntimeError):
            pass

        class LowerFailure(RuntimeError):
            pass

        class StampRenderFailure(RuntimeError):
            pass

        class BrokenTimestamp:
            def strftime(timestamp_self, format_string: str) -> object:
                raise FormatFailure("format failed")

        class BrokenFormattedStamp:
            def lower(stamp_self) -> object:
                raise LowerFailure("lower failed")

        class LoweringTimestamp:
            def strftime(timestamp_self, format_string: str) -> object:
                return BrokenFormattedStamp()

        class BrokenRenderedStamp:
            def __format__(stamp_self, specification: str) -> str:
                raise StampRenderFailure("stamp rendering failed")

        class RenderingFormattedStamp:
            def lower(stamp_self) -> object:
                return BrokenRenderedStamp()

        class RenderingTimestamp:
            def strftime(timestamp_self, format_string: str) -> object:
                return RenderingFormattedStamp()

        cases = (
            (
                "clock",
                mock.Mock(side_effect=ClockFailure("clock failed")),
                ClockFailure,
                "clock failed",
            ),
            (
                "strftime",
                mock.Mock(return_value=BrokenTimestamp()),
                FormatFailure,
                "format failed",
            ),
            (
                "lower",
                mock.Mock(return_value=LoweringTimestamp()),
                LowerFailure,
                "lower failed",
            ),
            (
                "stamp-render",
                mock.Mock(return_value=RenderingTimestamp()),
                StampRenderFailure,
                "stamp rendering failed",
            ),
        )
        for name, current_time, error_type, message in cases:
            with self.subTest(case=name):
                random_suffix = mock.Mock(
                    side_effect=AssertionError("consumed entropy")
                )
                with self.assertRaisesRegex(error_type, f"^{message}$"):
                    self.state_policy.new_run_id(
                        current_time=current_time,
                        random_suffix=random_suffix,
                    )
                random_suffix.assert_not_called()

    def test_new_run_id_propagates_suffix_failures_without_normalizing(
        self,
    ) -> None:
        class SuffixFailure(RuntimeError):
            pass

        class RenderFailure(RuntimeError):
            pass

        timestamp = SimpleNamespace(
            strftime=lambda format_string: "20260723T010203Z"
        )
        with self.assertRaisesRegex(SuffixFailure, "^suffix failed$"):
            self.state_policy.new_run_id(
                current_time=lambda: timestamp,
                random_suffix=lambda: (_ for _ in ()).throw(
                    SuffixFailure("suffix failed")
                ),
            )

        class BrokenSuffix:
            def __format__(suffix_self, specification: str) -> str:
                raise RenderFailure("suffix rendering failed")

        with self.assertRaisesRegex(
            RenderFailure,
            "^suffix rendering failed$",
        ):
            self.state_policy.new_run_id(
                current_time=lambda: timestamp,
                random_suffix=lambda: BrokenSuffix(),
            )

        observed = self.state_policy.new_run_id(
            current_time=lambda: timestamp,
            random_suffix=lambda: "UPPER/slashed suffix",
        )
        self.assertEqual(
            observed,
            "20260723t010203z-UPPER/slashed suffix",
        )

    def test_engine_new_run_id_resolves_clock_and_entropy_lazily(self) -> None:
        events: list[tuple[str, object]] = []

        class ReboundTimezone:
            @property
            def utc(timezone_self) -> str:
                events.append(("timezone.utc", None))
                return "rebound-utc"

        class InitialTimezone:
            @property
            def utc(timezone_self) -> str:
                raise AssertionError("captured timezone before datetime.now")

        class FormattedStamp:
            def lower(stamp_self) -> str:
                events.append(("lower", None))
                self.engine.secrets = rebound_secrets
                return "20260723t010203z"

        class Timestamp:
            def strftime(timestamp_self, format_string: str) -> object:
                events.append(("strftime", format_string))
                return FormattedStamp()

        def now(utc: object) -> object:
            events.append(("now", utc))
            return Timestamp()

        class DatetimeApi:
            @property
            def now(datetime_self) -> object:
                events.append(("datetime.now", None))
                self.engine.timezone = ReboundTimezone()
                return now

        class InitialSecrets:
            def token_hex(secrets_self, size: int) -> str:
                raise AssertionError("captured secrets before stamp formatting")

        class ReboundSecrets:
            def token_hex(secrets_self, size: int) -> str:
                events.append(("token-hex", size))
                return "ABCDEF012345"

        rebound_secrets = ReboundSecrets()
        with (
            mock.patch.object(self.engine, "datetime", DatetimeApi()),
            mock.patch.object(self.engine, "timezone", InitialTimezone()),
            mock.patch.object(self.engine, "secrets", InitialSecrets()),
        ):
            observed = self.engine.new_run_id()

        self.assertEqual(observed, "20260723t010203z-ABCDEF012345")
        self.assertEqual(
            events,
            [
                ("datetime.now", None),
                ("timezone.utc", None),
                ("now", "rebound-utc"),
                ("strftime", "%Y%m%dt%H%M%Sz"),
                ("lower", None),
                ("token-hex", 6),
            ],
        )

    def test_state_base_override_precedes_xdg_and_preserves_order(self) -> None:
        events: list[tuple[str, object]] = []
        result = object()

        class Profile:
            @property
            def state_environment(profile_self) -> str:
                events.append(("profile-state-environment", None))
                return "CUSTOM_STATE"

            @property
            def override_state_suffix(profile_self) -> tuple[str, ...]:
                events.append(("profile-override-suffix", None))
                return ("profiles", "selected")

            @property
            def default_state_parts(profile_self) -> tuple[str, ...]:
                raise AssertionError("read the default suffix after an override")

        class Environment:
            @property
            def get(environment_self) -> object:
                events.append(("resolve-get", None))

                def lookup(name: str) -> str:
                    events.append(("get", name))
                    values = {
                        "CUSTOM_STATE": "/override",
                        "XDG_STATE_HOME": "/xdg",
                    }
                    return values[name]

                return lookup

        class Candidate:
            def is_absolute(candidate_self) -> bool:
                events.append(("is-absolute", None))
                return True

            @property
            def joinpath(candidate_self) -> object:
                events.append(("bind-joinpath", None))

                def join(*parts: str) -> object:
                    events.append(("joinpath", parts))
                    return result

                return join

        def environment() -> object:
            events.append(("environment", None))
            return Environment()

        def path_factory(value: str) -> object:
            events.append(("path-factory", value))
            return Candidate()

        home = mock.Mock(side_effect=AssertionError("used home after override"))
        error_type = mock.Mock(
            side_effect=AssertionError("resolved error type for absolute path")
        )
        observed = self.state_policy.state_base(
            profile=Profile(),
            environment=environment,
            path_factory=path_factory,
            home=home,
            error_type=error_type,
        )

        self.assertIs(observed, result)
        self.assertEqual(
            events,
            [
                ("environment", None),
                ("resolve-get", None),
                ("profile-state-environment", None),
                ("get", "CUSTOM_STATE"),
                ("path-factory", "/override"),
                ("is-absolute", None),
                ("bind-joinpath", None),
                ("profile-override-suffix", None),
                ("joinpath", ("profiles", "selected")),
            ],
        )
        home.assert_not_called()
        error_type.assert_not_called()

    def test_state_base_reacquires_environment_for_xdg_branch(self) -> None:
        events: list[tuple[str, object]] = []
        result = object()

        class Profile:
            @property
            def state_environment(profile_self) -> str:
                events.append(("profile-state-environment", None))
                return "CUSTOM_STATE"

            @property
            def override_state_suffix(profile_self) -> tuple[str, ...]:
                raise AssertionError("read override suffix without an override")

            @property
            def default_state_parts(profile_self) -> tuple[str, ...]:
                events.append(("profile-default-parts", None))
                return ("marshal", "profile")

        class Environment:
            def __init__(
                environment_self,
                label: str,
                values: dict[str, str],
            ) -> None:
                environment_self.label = label
                environment_self.values = values

            def get(environment_self, name: str) -> str | None:
                events.append(
                    ("get", (environment_self.label, name))
                )
                return environment_self.values.get(name)

        environments = iter(
            (
                Environment("first", {"CUSTOM_STATE": ""}),
                Environment("second", {"XDG_STATE_HOME": "/xdg"}),
            )
        )

        def environment() -> object:
            events.append(("environment", None))
            return next(environments)

        class Candidate:
            def is_absolute(candidate_self) -> bool:
                events.append(("is-absolute", None))
                return True

            @property
            def joinpath(candidate_self) -> object:
                events.append(("bind-joinpath", None))

                def join(*parts: str) -> object:
                    events.append(("joinpath", parts))
                    return result

                return join

        def path_factory(value: str) -> object:
            events.append(("path-factory", value))
            return Candidate()

        home = mock.Mock(side_effect=AssertionError("used home after XDG"))
        error_type = mock.Mock(
            side_effect=AssertionError("resolved error type for absolute path")
        )
        observed = self.state_policy.state_base(
            profile=Profile(),
            environment=environment,
            path_factory=path_factory,
            home=home,
            error_type=error_type,
        )

        self.assertIs(observed, result)
        self.assertEqual(
            events,
            [
                ("environment", None),
                ("profile-state-environment", None),
                ("get", ("first", "CUSTOM_STATE")),
                ("environment", None),
                ("get", ("second", "XDG_STATE_HOME")),
                ("path-factory", "/xdg"),
                ("is-absolute", None),
                ("bind-joinpath", None),
                ("profile-default-parts", None),
                ("joinpath", ("marshal", "profile")),
            ],
        )
        home.assert_not_called()
        error_type.assert_not_called()

    def test_state_base_home_fallback_preserves_lexical_join_order(
        self,
    ) -> None:
        events: list[tuple[str, object]] = []
        result = object()

        class Profile:
            @property
            def state_environment(profile_self) -> str:
                events.append(("profile-state-environment", None))
                return "CUSTOM_STATE"

            @property
            def override_state_suffix(profile_self) -> tuple[str, ...]:
                raise AssertionError("read override suffix on home fallback")

            @property
            def default_state_parts(profile_self) -> tuple[str, ...]:
                events.append(("profile-default-parts", None))
                return ("marshal", "profile")

        class Environment:
            def get(environment_self, name: str) -> None:
                events.append(("get", name))
                return None

        def environment() -> object:
            events.append(("environment", None))
            return Environment()

        class TracingPath:
            def __init__(path_self, label: str) -> None:
                path_self.label = label

            def __truediv__(path_self, component: str) -> object:
                events.append(("divide", (path_self.label, component)))
                labels = {
                    ("home", ".local"): "local",
                    ("local", "state"): "state",
                }
                return TracingPath(labels[(path_self.label, component)])

            @property
            def joinpath(path_self) -> object:
                events.append(("bind-joinpath", path_self.label))

                def join(*parts: str) -> object:
                    events.append(
                        ("joinpath", (path_self.label, parts))
                    )
                    return result

                return join

        def home() -> object:
            events.append(("home", None))
            return TracingPath("home")

        path_factory = mock.Mock(
            side_effect=AssertionError("constructed an empty environment value")
        )
        error_type = mock.Mock(
            side_effect=AssertionError("resolved error type on home fallback")
        )
        observed = self.state_policy.state_base(
            profile=Profile(),
            environment=environment,
            path_factory=path_factory,
            home=home,
            error_type=error_type,
        )

        self.assertIs(observed, result)
        self.assertEqual(
            events,
            [
                ("environment", None),
                ("profile-state-environment", None),
                ("get", "CUSTOM_STATE"),
                ("environment", None),
                ("get", "XDG_STATE_HOME"),
                ("home", None),
                ("divide", ("home", ".local")),
                ("divide", ("local", "state")),
                ("bind-joinpath", "state"),
                ("profile-default-parts", None),
                ("joinpath", ("state", ("marshal", "profile"))),
            ],
        )
        path_factory.assert_not_called()
        error_type.assert_not_called()

    def test_state_base_relative_diagnostics_are_exact_and_lazy(self) -> None:
        class RelativeStateError(RuntimeError):
            pass

        cases = (
            (
                "override",
                {
                    "CUSTOM_STATE": "relative/override",
                    "XDG_STATE_HOME": "/unused",
                },
                "CUSTOM_STATE must be an absolute path",
            ),
            (
                "xdg",
                {
                    "CUSTOM_STATE": "",
                    "XDG_STATE_HOME": "relative/xdg",
                },
                "XDG_STATE_HOME must be an absolute path",
            ),
        )
        for name, values, expected_message in cases:
            with self.subTest(branch=name):
                events: list[tuple[str, object]] = []

                class Profile:
                    @property
                    def state_environment(profile_self) -> str:
                        events.append(
                            ("profile-state-environment", None)
                        )
                        return "CUSTOM_STATE"

                    @property
                    def override_state_suffix(
                        profile_self,
                    ) -> tuple[str, ...]:
                        raise AssertionError("read suffix for a relative path")

                    @property
                    def default_state_parts(
                        profile_self,
                    ) -> tuple[str, ...]:
                        raise AssertionError("read suffix for a relative path")

                class Candidate:
                    def is_absolute(candidate_self) -> bool:
                        events.append(("is-absolute", None))
                        return False

                    def joinpath(
                        candidate_self,
                        *parts: str,
                    ) -> object:
                        raise AssertionError("joined a relative state path")

                def environment() -> object:
                    events.append(("environment", None))
                    return values

                def path_factory(value: str) -> object:
                    events.append(("path-factory", value))
                    return Candidate()

                def error_type() -> type[Exception]:
                    events.append(("error-type", None))
                    return RelativeStateError

                home = mock.Mock(
                    side_effect=AssertionError(
                        "used home after a relative configured path"
                    )
                )
                with self.assertRaisesRegex(
                    RelativeStateError,
                    f"^{re.escape(expected_message)}$",
                ):
                    self.state_policy.state_base(
                        profile=Profile(),
                        environment=environment,
                        path_factory=path_factory,
                        home=home,
                        error_type=error_type,
                    )

                expected_environment_calls = 1 if name == "override" else 2
                self.assertEqual(
                    sum(
                        event == ("environment", None)
                        for event in events
                    ),
                    expected_environment_calls,
                )
                expected_profile_reads = 2 if name == "override" else 1
                self.assertEqual(
                    sum(
                        event == ("profile-state-environment", None)
                        for event in events
                    ),
                    expected_profile_reads,
                )
                expected_tail = [
                    ("is-absolute", None),
                    ("error-type", None),
                ]
                if name == "override":
                    expected_tail.append(
                        ("profile-state-environment", None)
                    )
                self.assertEqual(
                    events[-len(expected_tail) :],
                    expected_tail,
                )
                home.assert_not_called()

    def test_state_base_failures_short_circuit_later_providers(self) -> None:
        class ProviderFailure(RuntimeError):
            pass

        profile = SimpleNamespace(
            state_environment="CUSTOM_STATE",
            override_state_suffix=("override",),
            default_state_parts=("default",),
        )
        unused_path_factory = mock.Mock(
            side_effect=AssertionError("called path factory after failure")
        )
        unused_home = mock.Mock(
            side_effect=AssertionError("called home after failure")
        )
        unused_error_type = mock.Mock(
            side_effect=AssertionError("called error type after failure")
        )

        with self.assertRaisesRegex(
            ProviderFailure,
            "^environment failed$",
        ):
            self.state_policy.state_base(
                profile=profile,
                environment=mock.Mock(
                    side_effect=ProviderFailure("environment failed")
                ),
                path_factory=unused_path_factory,
                home=unused_home,
                error_type=unused_error_type,
            )
        unused_path_factory.assert_not_called()
        unused_home.assert_not_called()
        unused_error_type.assert_not_called()

        path_failure = mock.Mock(
            side_effect=ProviderFailure("path construction failed")
        )
        with self.assertRaisesRegex(
            ProviderFailure,
            "^path construction failed$",
        ):
            self.state_policy.state_base(
                profile=profile,
                environment=lambda: {"CUSTOM_STATE": "/override"},
                path_factory=path_failure,
                home=unused_home,
                error_type=unused_error_type,
            )
        path_failure.assert_called_once_with("/override")
        unused_home.assert_not_called()
        unused_error_type.assert_not_called()

        class AbsoluteFailure:
            def is_absolute(candidate_self) -> bool:
                raise ProviderFailure("absolute check failed")

        with self.assertRaisesRegex(
            ProviderFailure,
            "^absolute check failed$",
        ):
            self.state_policy.state_base(
                profile=profile,
                environment=lambda: {"CUSTOM_STATE": "/override"},
                path_factory=lambda value: AbsoluteFailure(),
                home=unused_home,
                error_type=unused_error_type,
            )
        unused_home.assert_not_called()
        unused_error_type.assert_not_called()

        environment_calls = 0

        def changing_environment() -> dict[str, str]:
            nonlocal environment_calls
            environment_calls += 1
            if environment_calls == 1:
                return {"CUSTOM_STATE": ""}
            raise ProviderFailure("second environment failed")

        with self.assertRaisesRegex(
            ProviderFailure,
            "^second environment failed$",
        ):
            self.state_policy.state_base(
                profile=profile,
                environment=changing_environment,
                path_factory=unused_path_factory,
                home=unused_home,
                error_type=unused_error_type,
            )
        self.assertEqual(environment_calls, 2)
        unused_home.assert_not_called()

        default_reads = 0

        class FallbackProfile:
            state_environment = "CUSTOM_STATE"

            @property
            def default_state_parts(
                profile_self,
            ) -> tuple[str, ...]:
                nonlocal default_reads
                default_reads += 1
                return ("default",)

        with self.assertRaisesRegex(ProviderFailure, "^home failed$"):
            self.state_policy.state_base(
                profile=FallbackProfile(),
                environment=lambda: {},
                path_factory=unused_path_factory,
                home=mock.Mock(
                    side_effect=ProviderFailure("home failed")
                ),
                error_type=unused_error_type,
            )
        self.assertEqual(default_reads, 0)

    def test_engine_state_base_defers_mutable_runtime_providers(self) -> None:
        events: list[tuple[str, object]] = []
        profile = object()
        result = object()

        class EnvironmentApi:
            def __init__(api_self, label: str) -> None:
                api_self.label = label

            @property
            def environ(api_self) -> object:
                events.append(("environment", api_self.label))
                return ("environment", api_self.label)

        class PathApi:
            def __init__(api_self, label: str) -> None:
                api_self.label = label

            def __call__(api_self, value: str) -> object:
                events.append(("path-factory", (api_self.label, value)))
                return ("path", api_self.label, value)

            def home(api_self) -> object:
                events.append(("home", api_self.label))
                return ("home", api_self.label)

        class InitialError(RuntimeError):
            pass

        class ReboundError(RuntimeError):
            pass

        initial_os = EnvironmentApi("initial")
        rebound_os = EnvironmentApi("rebound")
        initial_path = PathApi("initial")
        rebound_path = PathApi("rebound")

        def active_profile() -> object:
            events.append(("active-profile", None))
            self.engine.os = rebound_os
            self.engine.Path = rebound_path
            self.engine.LauncherError = ReboundError
            return profile

        def state_base_kernel(**providers: object) -> object:
            events.append(("kernel", tuple(providers)))
            self.assertIs(providers["profile"], profile)
            self.assertEqual(
                providers["environment"](),
                ("environment", "rebound"),
            )
            self.assertEqual(
                providers["path_factory"]("configured"),
                ("path", "rebound", "configured"),
            )
            self.assertEqual(
                providers["home"](),
                ("home", "rebound"),
            )
            self.assertIs(providers["error_type"](), ReboundError)
            return result

        with (
            mock.patch.object(self.engine, "os", initial_os),
            mock.patch.object(self.engine, "Path", initial_path),
            mock.patch.object(self.engine, "LauncherError", InitialError),
            mock.patch.object(
                self.engine,
                "active_profile",
                side_effect=active_profile,
            ),
            mock.patch.object(
                self.engine,
                "_state_base",
                side_effect=state_base_kernel,
            ),
        ):
            observed = self.engine.state_base()

        self.assertIs(observed, result)
        self.assertEqual(
            events,
            [
                ("active-profile", None),
                (
                    "kernel",
                    (
                        "profile",
                        "environment",
                        "path_factory",
                        "home",
                        "error_type",
                    ),
                ),
                ("environment", "rebound"),
                ("path-factory", ("rebound", "configured")),
                ("home", "rebound"),
            ],
        )

    def test_engine_state_base_real_kernel_resolves_providers_at_use(
        self,
    ) -> None:
        events: list[tuple[str, object]] = []

        class InitialError(RuntimeError):
            pass

        class ReboundError(RuntimeError):
            pass

        class Profile:
            @property
            def state_environment(profile_self) -> str:
                events.append(("profile-state-environment", None))
                return "CUSTOM_STATE"

            @property
            def override_state_suffix(
                profile_self,
            ) -> tuple[str, ...]:
                raise AssertionError("read override suffix for a falsey value")

            @property
            def default_state_parts(
                profile_self,
            ) -> tuple[str, ...]:
                raise AssertionError("read default suffix for a relative path")

        class ReboundEnvironment:
            def get(environment_self, name: str) -> object:
                events.append(("rebound-get", name))
                if name != "XDG_STATE_HOME":
                    raise AssertionError(f"unexpected rebound lookup: {name}")
                return xdg_value

        class ReboundOs:
            @property
            def environ(api_self) -> object:
                events.append(("rebound-environment", None))
                return ReboundEnvironment()

        class FalseyOverride:
            def __bool__(value_self) -> bool:
                events.append(("override-truthiness", None))
                self.engine.os = ReboundOs()
                return False

        class InitialEnvironment:
            def get(environment_self, name: str) -> object:
                events.append(("initial-get", name))
                if name != "CUSTOM_STATE":
                    raise AssertionError(f"reused initial environment: {name}")
                return FalseyOverride()

        class InitialOs:
            @property
            def environ(api_self) -> object:
                events.append(("initial-environment", None))
                return InitialEnvironment()

        class Candidate:
            def is_absolute(candidate_self) -> bool:
                events.append(("is-absolute", None))
                self.engine.LauncherError = ReboundError
                return False

        class ReboundPath:
            def __call__(path_self, value: object) -> object:
                events.append(("rebound-path", value))
                self.assertIs(value, xdg_value)
                return Candidate()

            def home(path_self) -> object:
                raise AssertionError("used home after a truthy XDG value")

        class InitialPath:
            def __call__(path_self, value: object) -> object:
                raise AssertionError("captured Path before XDG truthiness")

            def home(path_self) -> object:
                raise AssertionError("used home after a truthy XDG value")

        class TruthyXdg:
            def __bool__(value_self) -> bool:
                events.append(("xdg-truthiness", None))
                self.engine.Path = ReboundPath()
                return True

        xdg_value = TruthyXdg()

        def active_profile() -> object:
            events.append(("active-profile", None))
            return Profile()

        with (
            mock.patch.object(
                self.engine,
                "active_profile",
                side_effect=active_profile,
            ),
            mock.patch.object(self.engine, "os", InitialOs()),
            mock.patch.object(self.engine, "Path", InitialPath()),
            mock.patch.object(
                self.engine,
                "LauncherError",
                InitialError,
            ),
        ):
            with self.assertRaisesRegex(
                ReboundError,
                "^XDG_STATE_HOME must be an absolute path$",
            ):
                self.engine.state_base()

        self.assertEqual(
            events,
            [
                ("active-profile", None),
                ("initial-environment", None),
                ("profile-state-environment", None),
                ("initial-get", "CUSTOM_STATE"),
                ("override-truthiness", None),
                ("rebound-environment", None),
                ("rebound-get", "XDG_STATE_HOME"),
                ("xdg-truthiness", None),
                ("rebound-path", xdg_value),
                ("is-absolute", None),
            ],
        )

    def test_engine_override_error_is_captured_before_diagnostic_name(
        self,
    ) -> None:
        events: list[tuple[str, object]] = []

        class ExpectedError(RuntimeError):
            pass

        class TooLateError(RuntimeError):
            pass

        class Profile:
            reads = 0

            @property
            def state_environment(profile_self) -> str:
                profile_self.reads += 1
                events.append(
                    ("profile-state-environment", profile_self.reads)
                )
                if profile_self.reads == 2:
                    self.engine.LauncherError = TooLateError
                return "CUSTOM_STATE"

            @property
            def override_state_suffix(
                profile_self,
            ) -> tuple[str, ...]:
                raise AssertionError("read suffix for a relative override")

        class Candidate:
            def is_absolute(candidate_self) -> bool:
                events.append(("is-absolute", None))
                return False

        class PathApi:
            def __call__(path_self, value: str) -> object:
                events.append(("path", value))
                return Candidate()

        with (
            mock.patch.object(
                self.engine,
                "active_profile",
                return_value=Profile(),
            ),
            mock.patch.object(
                self.engine,
                "os",
                SimpleNamespace(
                    environ={"CUSTOM_STATE": "relative/path"}
                ),
            ),
            mock.patch.object(self.engine, "Path", PathApi()),
            mock.patch.object(
                self.engine,
                "LauncherError",
                ExpectedError,
            ),
        ):
            with self.assertRaisesRegex(
                ExpectedError,
                "^CUSTOM_STATE must be an absolute path$",
            ):
                self.engine.state_base()

        self.assertEqual(
            events,
            [
                ("profile-state-environment", 1),
                ("path", "relative/path"),
                ("is-absolute", None),
                ("profile-state-environment", 2),
            ],
        )

    def test_repository_slug_normalization_is_exactly_ascii(self) -> None:
        cases = (
            ("Triptych", "triptych"),
            ("Hello_World.git", "hello-world-git"),
            ("a..B__C", "a-b-c"),
            ("123 Project 456", "123-project-456"),
            ("Église Café", "glise-caf"),
            ("Straße", "stra-e"),
            ("Καλημέρα", "repository"),
            ("ＦＯＯ", "repository"),
            ("---", "repository"),
            ("", "repository"),
        )
        for name, expected in cases:
            with self.subTest(name=name):
                observed = self.state_policy.repository_slug(
                    SimpleNamespace(name=name),
                    substitute=re.sub,
                )
                self.assertEqual(observed, expected)

    def test_repository_slug_kernel_preserves_operation_order(self) -> None:
        events: list[tuple[str, object]] = []
        truthy_result = object()

        class Slug:
            def strip(slug_self, characters: str) -> object:
                events.append(("strip", characters))
                return truthy_result

        class LoweredName:
            def __format__(
                name_self,
                specification: str,
            ) -> str:
                raise AssertionError("formatted repository name")

        class Name:
            def lower(name_self) -> object:
                events.append(("lower", None))
                return LoweredName()

        class Root:
            @property
            def name(root_self) -> object:
                events.append(("root-name", None))
                return Name()

        def substitute(
            pattern: str,
            replacement: str,
            value: object,
        ) -> object:
            events.append(
                ("substitute", (pattern, replacement, value.__class__))
            )
            return Slug()

        observed = self.state_policy.repository_slug(
            Root(),
            substitute=substitute,
        )

        self.assertIs(observed, truthy_result)
        self.assertEqual(
            events,
            [
                ("root-name", None),
                ("lower", None),
                (
                    "substitute",
                    (r"[^a-z0-9]+", "-", LoweredName),
                ),
                ("strip", "-"),
            ],
        )

        self.assertEqual(
            self.state_policy.repository_slug(
                SimpleNamespace(name="---"),
                substitute=re.sub,
            ),
            "repository",
        )

    def test_repository_slug_failures_propagate_without_fallback(self) -> None:
        class SlugFailure(RuntimeError):
            pass

        class BrokenRoot:
            @property
            def name(root_self) -> str:
                raise SlugFailure("name failed")

        substitute = mock.Mock(
            side_effect=AssertionError("substituted after name failure")
        )
        with self.assertRaisesRegex(SlugFailure, "^name failed$"):
            self.state_policy.repository_slug(
                BrokenRoot(),
                substitute=substitute,
            )
        substitute.assert_not_called()

        class BrokenName:
            def lower(name_self) -> str:
                raise SlugFailure("lower failed")

        substitute.reset_mock()
        with self.assertRaisesRegex(SlugFailure, "^lower failed$"):
            self.state_policy.repository_slug(
                SimpleNamespace(name=BrokenName()),
                substitute=substitute,
            )
        substitute.assert_not_called()

        with self.assertRaisesRegex(SlugFailure, "^substitute failed$"):
            self.state_policy.repository_slug(
                SimpleNamespace(name="repository"),
                substitute=mock.Mock(
                    side_effect=SlugFailure("substitute failed")
                ),
            )

        class BrokenSlug:
            def strip(slug_self, characters: str) -> str:
                raise SlugFailure("strip failed")

        with self.assertRaisesRegex(SlugFailure, "^strip failed$"):
            self.state_policy.repository_slug(
                SimpleNamespace(name="repository"),
                substitute=lambda pattern, replacement, value: BrokenSlug(),
            )

    def test_engine_repository_slug_captures_substitute_before_root_name(
        self,
    ) -> None:
        events: list[tuple[str, object]] = []

        def initial_substitute(
            pattern: str,
            replacement: str,
            value: str,
        ) -> str:
            events.append(
                ("initial-substitute", (pattern, replacement, value))
            )
            return re.sub(pattern, replacement, value)

        class InitialRegexApi:
            @property
            def sub(api_self) -> object:
                events.append(("capture-substitute", None))
                return initial_substitute

        class ReboundRegexApi:
            @property
            def sub(api_self) -> object:
                raise AssertionError(
                    "resolved substitute after reading the repository name"
                )

        class Root:
            @property
            def name(root_self) -> str:
                events.append(("root-name", None))
                self.engine.re = ReboundRegexApi()
                return "Project Name"

        with mock.patch.object(self.engine, "re", InitialRegexApi()):
            observed = self.engine.repository_slug(Root())

        self.assertEqual(observed, "project-name")
        self.assertEqual(
            events,
            [
                ("capture-substitute", None),
                ("root-name", None),
                (
                    "initial-substitute",
                    (r"[^a-z0-9]+", "-", "project name"),
                ),
            ],
        )

    def test_discover_repository_keeps_state_outside_security_boundary(
        self,
    ) -> None:
        events: list[tuple[str, object]] = []
        start = Path("/repository/subdirectory")
        root = Path("/repository")
        git_dir = Path("/repository/.git")
        common_git_dir = Path("/repository/.git")

        def git(
            cwd: Path,
            *arguments: str,
            check: bool = True,
        ) -> object:
            events.append(("git", (cwd, arguments, check)))
            outputs = {
                ("rev-parse", "--is-inside-work-tree"): "true\n",
                ("rev-parse", "--show-toplevel"): f"{root}\n",
            }
            return SimpleNamespace(
                returncode=0,
                stdout=outputs[arguments],
            )

        def absolute_git_path(cwd: Path, selector: str) -> Path:
            events.append(("absolute-git-path", (cwd, selector)))
            paths = {
                "--git-dir": git_dir,
                "--git-common-dir": common_git_dir,
            }
            return paths[selector]

        class OperatingSystemApi:
            def fsencode(api_self, value: object) -> bytes:
                events.append(("fsencode", value))
                return b"common-git-directory"

        class Digest:
            def hexdigest(digest_self) -> str:
                events.append(("hexdigest", None))
                return "0123456789abcdef"

        class HashApi:
            def sha256(api_self, value: bytes) -> object:
                events.append(("sha256", value))
                return Digest()

        class Profile:
            @property
            def state_environment(profile_self) -> str:
                events.append(("profile-state-environment", None))
                return "CUSTOM_STATE"

        def state_base() -> Path:
            events.append(("state-base", None))
            return root / ".marshal-state"

        def repository_slug(discovered_root: Path) -> str:
            events.append(("repository-slug", discovered_root))
            return "project"

        def active_profile() -> object:
            events.append(("active-profile", None))
            return Profile()

        with (
            mock.patch.object(self.engine, "git", side_effect=git),
            mock.patch.object(
                self.engine,
                "absolute_git_path",
                side_effect=absolute_git_path,
            ),
            mock.patch.object(self.engine, "os", OperatingSystemApi()),
            mock.patch.object(self.engine, "hashlib", HashApi()),
            mock.patch.object(
                self.engine,
                "state_base",
                side_effect=state_base,
            ),
            mock.patch.object(
                self.engine,
                "repository_slug",
                side_effect=repository_slug,
            ),
            mock.patch.object(
                self.engine,
                "active_profile",
                side_effect=active_profile,
            ),
            mock.patch.object(
                self.engine,
                "Repository",
                side_effect=AssertionError(
                    "constructed a repository with state inside its worktree"
                ),
            ) as repository_type,
        ):
            with self.assertRaisesRegex(
                self.engine.LauncherError,
                "^CUSTOM_STATE must keep launcher state outside the worktree$",
            ):
                self.engine.discover_repository(start)

        repository_type.assert_not_called()
        self.assertEqual(
            events,
            [
                (
                    "git",
                    (
                        start,
                        ("rev-parse", "--is-inside-work-tree"),
                        False,
                    ),
                ),
                (
                    "git",
                    (
                        start,
                        ("rev-parse", "--show-toplevel"),
                        True,
                    ),
                ),
                ("absolute-git-path", (root, "--git-dir")),
                ("absolute-git-path", (root, "--git-common-dir")),
                ("fsencode", common_git_dir),
                ("sha256", b"common-git-directory"),
                ("hexdigest", None),
                ("state-base", None),
                ("repository-slug", root),
                ("active-profile", None),
                ("profile-state-environment", None),
            ],
        )

    def test_discover_repository_rejects_outside_cwd_before_state_policy(
        self,
    ) -> None:
        start = Path("/outside")
        root = Path("/repository")
        git_outputs = iter(
            (
                SimpleNamespace(returncode=0, stdout="true\n"),
                SimpleNamespace(returncode=0, stdout=f"{root}\n"),
            )
        )
        state_base = mock.Mock(
            side_effect=AssertionError(
                "selected state before authenticating the discovered root"
            )
        )
        repository_slug = mock.Mock(
            side_effect=AssertionError(
                "slugged a root before checking the current directory"
            )
        )
        with (
            mock.patch.object(
                self.engine,
                "git",
                side_effect=lambda *args, **kwargs: next(git_outputs),
            ),
            mock.patch.object(
                self.engine,
                "absolute_git_path",
                side_effect=(
                    Path("/repository/.git"),
                    Path("/repository/.git"),
                ),
            ),
            mock.patch.object(self.engine, "state_base", state_base),
            mock.patch.object(
                self.engine,
                "repository_slug",
                repository_slug,
            ),
            mock.patch.object(
                self.engine.hashlib,
                "sha256",
                side_effect=AssertionError(
                    "hashed state identity before relative-cwd validation"
                ),
            ),
        ):
            with self.assertRaisesRegex(
                self.engine.LauncherError,
                "^the current directory is outside the discovered worktree$",
            ):
                self.engine.discover_repository(start)

        state_base.assert_not_called()
        repository_slug.assert_not_called()

    def test_lexical_path_kernels_preserve_exact_opaque_joins(self) -> None:
        roots = (Path("/state/root"), Path("relative/state"))
        for state_root in roots:
            with self.subTest(root=state_root):
                self.assertEqual(
                    self.state_policy.repo_lock_path(state_root),
                    state_root / "repository.lock",
                )
                self.assertEqual(
                    self.state_policy.run_lock_path(state_root, "run.id"),
                    state_root / "runs" / "run.id.lock",
                )
                self.assertEqual(
                    self.state_policy.manifest_path(state_root, "run.id"),
                    state_root / "runs" / "run.id.json",
                )

        cases = (
            ("", Path("/state/runs/.lock"), Path("/state/runs/.json")),
            (
                "../escape",
                Path("/state/runs/../escape.lock"),
                Path("/state/runs/../escape.json"),
            ),
            (
                "nested/run",
                Path("/state/runs/nested/run.lock"),
                Path("/state/runs/nested/run.json"),
            ),
            (
                "/outside/run",
                Path("/outside/run.lock"),
                Path("/outside/run.json"),
            ),
            (
                " whitespace ",
                Path("/state/runs/ whitespace .lock"),
                Path("/state/runs/ whitespace .json"),
            ),
        )
        for run_id, lock_path, manifest_path in cases:
            with self.subTest(run_id=run_id):
                self.assertEqual(
                    self.state_policy.run_lock_path(Path("/state"), run_id),
                    lock_path,
                )
                self.assertEqual(
                    self.state_policy.manifest_path(
                        Path("/state"),
                        run_id,
                    ),
                    manifest_path,
                )

    def test_path_wrappers_preserve_get_format_and_division_order(
        self,
    ) -> None:
        events: list[tuple[str, object]] = []

        class TracingPath:
            def __init__(path_self, label: str) -> None:
                path_self.label = label

            def __truediv__(
                path_self,
                component: object,
            ) -> object:
                events.append(("divide", (path_self.label, component)))
                if component == "runs":
                    return TracingPath("runs")
                return ("result", path_self.label, component)

        class TracingRunId:
            def __format__(
                run_self,
                specification: str,
            ) -> str:
                events.append(("format-run-id", specification))
                return "opaque.id"

        class RepositoryStub:
            @property
            def state_root(repository_self) -> object:
                events.append(("get-state-root", None))
                return TracingPath("root")

        repository = RepositoryStub()
        run_id = TracingRunId()
        self.assertEqual(
            self.engine.run_lock_path(repository, run_id),
            ("result", "runs", "opaque.id.lock"),
        )
        self.assertEqual(
            events,
            [
                ("get-state-root", None),
                ("divide", ("root", "runs")),
                ("format-run-id", ""),
                ("divide", ("runs", "opaque.id.lock")),
            ],
        )

        events.clear()
        self.assertEqual(
            self.engine.manifest_path(repository, run_id),
            ("result", "runs", "opaque.id.json"),
        )
        self.assertEqual(
            events,
            [
                ("get-state-root", None),
                ("divide", ("root", "runs")),
                ("format-run-id", ""),
                ("divide", ("runs", "opaque.id.json")),
            ],
        )

        events.clear()
        self.assertEqual(
            self.engine.repo_lock_path(repository),
            ("result", "root", "repository.lock"),
        )
        self.assertEqual(
            events,
            [
                ("get-state-root", None),
                ("divide", ("root", "repository.lock")),
            ],
        )

    def test_path_kernel_failures_short_circuit_later_operations(self) -> None:
        class FirstDivisionFailure(RuntimeError):
            pass

        class FormatFailure(RuntimeError):
            pass

        class FinalDivisionFailure(RuntimeError):
            pass

        format_events: list[str] = []

        class UnexpectedFormat:
            def __format__(
                run_self,
                specification: str,
            ) -> str:
                format_events.append(specification)
                raise AssertionError("formatted after first division failed")

        class BrokenRoot:
            def __truediv__(root_self, component: object) -> object:
                raise FirstDivisionFailure("first division failed")

        with self.assertRaisesRegex(
            FirstDivisionFailure,
            "^first division failed$",
        ):
            self.state_policy.run_lock_path(BrokenRoot(), UnexpectedFormat())
        self.assertEqual(format_events, [])

        events: list[str] = []

        class Intermediate:
            def __truediv__(
                intermediate_self,
                component: object,
            ) -> object:
                events.append("final-division")
                raise FinalDivisionFailure("final division failed")

        class Root:
            def __truediv__(root_self, component: object) -> object:
                events.append("first-division")
                return Intermediate()

        class BrokenRunId:
            def __format__(
                run_self,
                specification: str,
            ) -> str:
                events.append("format")
                raise FormatFailure("format failed")

        with self.assertRaisesRegex(FormatFailure, "^format failed$"):
            self.state_policy.manifest_path(Root(), BrokenRunId())
        self.assertEqual(events, ["first-division", "format"])

        events.clear()
        with self.assertRaisesRegex(
            FinalDivisionFailure,
            "^final division failed$",
        ):
            self.state_policy.manifest_path(Root(), "run")
        self.assertEqual(events, ["first-division", "final-division"])

    def test_manifest_selection_retains_validation_boundaries(self) -> None:
        repository = SimpleNamespace(state_root=Path("/state"))
        with (
            mock.patch.object(
                self.engine,
                "active_profile",
                return_value=SimpleNamespace(display_name="Worktree Marshal"),
            ),
            mock.patch.object(
                self.engine,
                "manifest_path",
                side_effect=AssertionError("addressed an invalid run ID"),
            ) as manifest_path,
        ):
            with self.assertRaisesRegex(
                self.engine.LauncherError,
                "^invalid Worktree Marshal run ID$",
            ):
                self.engine.load_manifest(repository, "../escape")
        manifest_path.assert_not_called()

        with tempfile.TemporaryDirectory() as directory:
            state_root = Path(directory)
            runs = state_root / "runs"
            runs.mkdir()
            (runs / "first.json").touch()
            (runs / "second.json").touch()
            events: list[tuple[str, str]] = []

            class FirstPattern:
                def fullmatch(pattern_self, run_id: str) -> bool:
                    events.append(("first", run_id))
                    self.engine.RUN_ID_RE = SecondPattern()
                    return False

            class SecondPattern:
                def fullmatch(pattern_self, run_id: str) -> bool:
                    events.append(("second", run_id))
                    return run_id == "second"

            retained = {
                "run_id": "second",
                "state": "preserved",
            }
            status_repository = SimpleNamespace(
                linked_worktree=False,
                state_root=state_root,
            )
            with (
                mock.patch.object(self.engine, "RUN_ID_RE", FirstPattern()),
                mock.patch.object(self.engine, "initialize_state"),
                mock.patch.object(
                    self.engine,
                    "file_lock",
                    side_effect=lambda path: nullcontext(),
                ),
                mock.patch.object(
                    self.engine,
                    "load_manifest",
                    return_value=retained,
                ) as load_manifest,
                mock.patch.object(self.engine, "reconcile_stale_run"),
                mock.patch.object(
                    self.engine,
                    "run_is_active",
                    return_value=False,
                ),
                mock.patch("builtins.print"),
            ):
                observed = self.engine.show_status(
                    status_repository,
                    None,
                )

            self.assertEqual(observed, 0)
            self.assertEqual(
                events,
                [
                    ("first", "first"),
                    ("second", "second"),
                ],
            )
            load_manifest.assert_called_once_with(
                status_repository,
                "second",
            )

    def test_private_directory_kernel_and_wrapper_surfaces(self) -> None:
        self.assertEqual(
            tuple(
                inspect.signature(
                    self.state_policy.private_directory
                ).parameters
            ),
            (
                "path",
                "os_error_type",
                "error_type",
                "directory_test",
                "flag_lookup",
                "read_only_flag",
                "file_open",
                "file_stat",
                "same_stat",
                "file_chmod",
                "file_close",
            ),
        )
        self.assertEqual(
            str(inspect.signature(self.engine.private_directory)),
            "(path: 'Path') -> 'None'",
        )

    def test_manifest_writer_kernel_and_wrapper_surfaces(self) -> None:
        self.assertEqual(
            tuple(
                inspect.signature(
                    self.state_policy.write_manifest
                ).parameters
            )[:2],
            ("repository", "manifest"),
        )
        self.assertEqual(
            str(inspect.signature(self.engine.write_manifest)),
            "(repository: 'Repository', manifest: 'dict') -> 'None'",
        )

    def test_private_directory_matches_real_filesystem_behavior(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            engine_path = root / "engine" / "state"
            kernel_path = root / "kernel" / "state"

            self.engine.private_directory(engine_path)
            self.state_policy.private_directory(
                kernel_path,
                os_error_type=lambda: OSError,
                error_type=lambda: self.engine.LauncherError,
                directory_test=lambda: self.engine.stat.S_ISDIR,
                flag_lookup=lambda: (
                    lambda name, default: getattr(
                        self.engine.os,
                        name,
                        default,
                    )
                ),
                read_only_flag=lambda: self.engine.os.O_RDONLY,
                file_open=lambda: self.engine.os.open,
                file_stat=lambda: self.engine.os.fstat,
                same_stat=lambda: self.engine.os.path.samestat,
                file_chmod=lambda: self.engine.os.fchmod,
                file_close=lambda: self.engine.os.close,
            )

            self.assertTrue(engine_path.is_dir())
            self.assertTrue(kernel_path.is_dir())
            self.assertEqual(engine_path.stat().st_mode & 0o777, 0o700)
            self.assertEqual(kernel_path.stat().st_mode & 0o777, 0o700)

            regular_file = root / "not-a-directory"
            regular_file.write_text("content", encoding="utf-8")
            with self.assertRaisesRegex(
                self.engine.LauncherError,
                "^cannot create or inspect a private launcher directory$",
            ):
                self.engine.private_directory(regular_file)

    def test_engine_private_directory_wrapper_supplies_lazy_globals(
        self,
    ) -> None:
        sentinel_path = object()
        captured: dict[str, object] = {}

        def kernel(path: object, **dependencies: object) -> None:
            captured["path"] = path
            captured.update(dependencies)

        with mock.patch.object(
            self.engine,
            "_private_directory",
            side_effect=kernel,
        ):
            self.engine.private_directory(sentinel_path)

        self.assertIs(captured["path"], sentinel_path)
        self.assertIs(captured["os_error_type"](), OSError)
        self.assertIs(
            captured["error_type"](),
            self.engine.LauncherError,
        )
        self.assertIs(
            captured["directory_test"](),
            self.engine.stat.S_ISDIR,
        )
        self.assertEqual(
            captured["flag_lookup"]()("missing", 17),
            17,
        )
        self.assertEqual(
            captured["read_only_flag"](),
            self.engine.os.O_RDONLY,
        )
        self.assertIs(captured["file_open"](), self.engine.os.open)
        self.assertIs(captured["file_stat"](), self.engine.os.fstat)
        self.assertIs(
            captured["same_stat"](),
            self.engine.os.path.samestat,
        )
        self.assertIs(captured["file_chmod"](), self.engine.os.fchmod)
        self.assertIs(captured["file_close"](), self.engine.os.close)


if __name__ == "__main__":
    unittest.main()
