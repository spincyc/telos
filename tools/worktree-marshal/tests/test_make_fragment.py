#!/usr/bin/env python3
"""Focused black-box tests for the importable GNU Make fragment."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path


PACKAGE_ROOT = Path(__file__).resolve().parents[1]
MAKE_FRAGMENT = (
    PACKAGE_ROOT
    / "src"
    / "worktree_marshal"
    / "resources"
    / "worktree-marshal.mk"
)
RUN_ID = "20000101t000000z-abcdef012345"


class MakeFragmentTests(unittest.TestCase):
    def setUp(self) -> None:
        if shutil.which("make") is None:
            self.skipTest("GNU Make is unavailable")
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary_directory.name)
        self.log = self.root / "argv.jsonl"
        self.marker = self.root / "marker"
        self.fake = self.root / "fake worktree-marshal"
        self.fake.write_text(
            """#!/usr/bin/env python3
import json
import os
import sys

leaked = sorted(
    name
    for name in ("RUN", "MAKEFLAGS", "MFLAGS", "MAKELEVEL", "MAKEOVERRIDES")
    if name in os.environ
)
if leaked:
    print("leaked Make environment: " + ", ".join(leaked), file=sys.stderr)
    raise SystemExit(97)

with open(os.environ["WORKTREE_MARSHAL_TEST_LOG"], "a", encoding="utf-8") as log:
    log.write(json.dumps(sys.argv[1:]) + "\\n")
""",
            encoding="utf-8",
        )
        self.fake.chmod(0o755)
        self.environment = os.environ.copy()
        self.environment.pop("RUN", None)
        self.environment["WORKTREE_MARSHAL_TEST_LOG"] = str(self.log)
        self.write_makefile()

    def tearDown(self) -> None:
        self.temporary_directory.cleanup()

    @staticmethod
    def make_path(path: Path) -> str:
        return str(path).replace(" ", "\\ ")

    def write_makefile(self, configuration: str = "", suffix: str = "") -> None:
        self.makefile = self.root / "Makefile"
        self.makefile.write_text(
            f"WORKTREE_MARSHAL := {self.fake}\n"
            f"{configuration}"
            f"include {self.make_path(MAKE_FRAGMENT)}\n"
            f"{suffix}",
            encoding="utf-8",
        )

    def run_make(
        self,
        *arguments: str,
        environment: dict[str, str] | None = None,
    ) -> subprocess.CompletedProcess[str]:
        effective_environment = self.environment.copy()
        if environment:
            effective_environment.update(environment)
        return subprocess.run(
            ["make", "--no-print-directory", *arguments],
            cwd=self.root,
            env=effective_environment,
            text=True,
            capture_output=True,
            check=False,
            timeout=10,
        )

    def invocations(self) -> list[list[str]]:
        if not self.log.exists():
            return []
        return [
            json.loads(line)
            for line in self.log.read_text(encoding="utf-8").splitlines()
        ]

    def assert_rejected_without_invocation(
        self, *arguments: str, contains: str
    ) -> subprocess.CompletedProcess[str]:
        before = self.invocations()
        result = self.run_make(*arguments)
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertIn(contains, result.stderr)
        self.assertEqual(self.invocations(), before)
        return result

    def test_default_targets_delegate_exact_generic_argv(self) -> None:
        profile = ["--profile", "generic-v1"]
        cases = (
            (("codex",), [*profile, "run", "--agent", "codex"]),
            (("status",), [*profile, "status"]),
            (("reopen", f"RUN={RUN_ID}"), [*profile, "reopen", RUN_ID]),
            (("final-diff", f"RUN={RUN_ID}"), [*profile, "final-diff", RUN_ID]),
            (("integrate", f"RUN={RUN_ID}"), [*profile, "integrate", RUN_ID]),
            (("resolve", f"RUN={RUN_ID}"), [*profile, "resolve", RUN_ID]),
            (("continue", f"RUN={RUN_ID}"), [*profile, "continue", RUN_ID]),
            (("abort", f"RUN={RUN_ID}"), [*profile, "abort", RUN_ID]),
            (("clean-run", f"RUN={RUN_ID}"), [*profile, "clean", RUN_ID]),
        )

        for arguments, expected in cases:
            with self.subTest(target=arguments[0]):
                result = self.run_make(*arguments)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(self.invocations()[-1], expected)

    def test_status_accepts_only_an_optional_command_line_run_id(self) -> None:
        exact = self.run_make("status", f"RUN={RUN_ID}")
        self.assertEqual(exact.returncode, 0, exact.stderr)
        self.assertEqual(
            self.invocations(),
            [["--profile", "generic-v1", "status", RUN_ID]],
        )

        rejected = self.run_make("status", environment={"RUN": RUN_ID})
        self.assertEqual(rejected.returncode, 2, rejected.stderr)
        self.assertIn("RUN must be supplied on the Make command line", rejected.stderr)
        self.assertEqual(
            self.invocations(),
            [["--profile", "generic-v1", "status", RUN_ID]],
        )

    def test_missing_malformed_and_injected_run_ids_never_invoke_command(self) -> None:
        self.assert_rejected_without_invocation(
            "integrate",
            contains="Usage: make integrate RUN=<run-id>",
        )
        for malformed in (
            "not-a-run-id",
            "20000101T000000z-abcdef012345",
            "20000101t000000z-ABCDEF012345",
            "20000101t000000z-abcdef01234",
            "20000101t000000z-abcdef0123456",
        ):
            with self.subTest(run_id=malformed):
                self.assert_rejected_without_invocation(
                    "integrate",
                    f"RUN={malformed}",
                    contains="invalid Worktree Marshal run ID",
                )

        make_injection = f"RUN=$(shell touch {self.marker})"
        self.assert_rejected_without_invocation(
            "integrate",
            make_injection,
            contains="invalid Worktree Marshal run ID",
        )
        self.assertFalse(self.marker.exists())

        shell_injection = f"RUN={RUN_ID}'; touch {self.marker}; : '"
        self.assert_rejected_without_invocation(
            "integrate",
            shell_injection,
            contains="invalid Worktree Marshal run ID",
        )
        self.assertFalse(self.marker.exists())

    def test_multiple_and_indirect_targets_fail_before_any_recipe(self) -> None:
        self.write_makefile(
            suffix=(
                "alias: integrate\n"
                "ordinary:\n"
                f"\t@touch {self.make_path(self.marker)}\n"
            )
        )
        self.assert_rejected_without_invocation(
            "-k",
            "integrate",
            "ordinary",
            f"RUN={RUN_ID}",
            contains="targets must be invoked directly and alone",
        )
        self.assertFalse(self.marker.exists())

        self.assert_rejected_without_invocation(
            "alias",
            f"RUN={RUN_ID}",
            contains="targets must be invoked directly and alone",
        )

    def test_unknown_target_keeps_make_default_failure(self) -> None:
        result = self.run_make("definitely-unknown")
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertIn("No rule to make target", result.stderr)
        self.assertNotIn("Worktree Marshal targets", result.stderr)
        self.assertEqual(self.invocations(), [])

    def test_fragment_does_not_claim_an_unset_project_default_goal(self) -> None:
        self.write_makefile(
            suffix=(
                "ordinary:\n"
                f"\t@touch {self.make_path(self.marker)}\n"
            )
        )

        result = self.run_make()

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(self.marker.is_file())
        self.assertEqual(self.invocations(), [])

    def test_fragment_preserves_an_existing_project_default_goal(self) -> None:
        self.write_makefile(
            configuration=(
                "ordinary:\n"
                f"\t@touch {self.make_path(self.marker)}\n"
            )
        )

        result = self.run_make()

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(self.marker.is_file())
        self.assertEqual(self.invocations(), [])

    def test_target_names_reject_make_metacharacters_and_pattern_rules(self) -> None:
        for target in ("%", "x:y", "-hidden", "_hidden", ".hidden", "semi;colon"):
            with self.subTest(target=target):
                self.write_makefile(
                    configuration=f"WORKTREE_MARSHAL_STATUS_TARGET := {target}\n"
                )
                self.assert_rejected_without_invocation(
                    "definitely-unknown",
                    contains="target names must match",
                )

    def test_shell_configuration_cannot_come_from_invocation_or_environment(self) -> None:
        command_line = self.run_make(
            "status",
            "WORKTREE_MARSHAL_STATUS_ARGUMENTS=:; touch must-not-run",
        )
        self.assertEqual(command_line.returncode, 2, command_line.stderr)
        self.assertIn("must be configured in a Makefile", command_line.stderr)
        self.assertEqual(self.invocations(), [])

        environment = self.run_make(
            "status",
            environment={"WORKTREE_MARSHAL_STATUS_TARGET": "inspect"},
        )
        self.assertEqual(environment.returncode, 2, environment.stderr)
        self.assertIn("must be configured in a Makefile", environment.stderr)
        self.assertEqual(self.invocations(), [])

        global_command_line = self.run_make(
            "status",
            "WORKTREE_MARSHAL_GLOBAL_ARGUMENTS=:; touch must-not-run",
        )
        self.assertEqual(global_command_line.returncode, 2, global_command_line.stderr)
        self.assertIn("must be configured in a Makefile", global_command_line.stderr)
        self.assertEqual(self.invocations(), [])

        global_environment = self.run_make(
            "status",
            environment={"WORKTREE_MARSHAL_GLOBAL_ARGUMENTS": "--profile triptych"},
        )
        self.assertEqual(global_environment.returncode, 2, global_environment.stderr)
        self.assertIn("must be configured in a Makefile", global_environment.stderr)
        self.assertEqual(self.invocations(), [])

    def test_trusted_global_arguments_precede_every_command_argument(self) -> None:
        self.write_makefile(
            configuration="WORKTREE_MARSHAL_GLOBAL_ARGUMENTS := --profile triptych\n"
        )

        status = self.run_make("status", f"RUN={RUN_ID}")
        run = self.run_make("codex")

        self.assertEqual(status.returncode, 0, status.stderr)
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertEqual(
            self.invocations(),
            [
                ["--profile", "triptych", "status", RUN_ID],
                ["--profile", "triptych", "run", "--agent", "codex"],
            ],
        )

    def test_opt_in_positional_compatibility_delegates_the_same_run_id(self) -> None:
        self.write_makefile(
            configuration="WORKTREE_MARSHAL_POSITIONAL_RUN_ID_COMPAT := 1\n"
        )

        status = self.run_make("status", RUN_ID)
        integrate = self.run_make("integrate", RUN_ID)

        self.assertEqual(status.returncode, 0, status.stderr)
        self.assertEqual(integrate.returncode, 0, integrate.stderr)
        self.assertEqual(
            self.invocations(),
            [
                ["--profile", "generic-v1", "status", RUN_ID],
                ["--profile", "generic-v1", "integrate", RUN_ID],
            ],
        )

        malformed = self.run_make("integrate", "not-a-run-id")
        self.assertEqual(malformed.returncode, 2, malformed.stderr)
        self.assertIn("invalid Worktree Marshal run ID", malformed.stderr)
        self.assertEqual(len(self.invocations()), 2)

    def test_targets_display_name_and_legacy_argument_lists_are_configurable(self) -> None:
        configuration = """WORKTREE_MARSHAL_DISPLAY_NAME := Triptych Codex
WORKTREE_MARSHAL_GLOBAL_ARGUMENTS :=
WORKTREE_MARSHAL_RUN_TARGET := agent
WORKTREE_MARSHAL_STATUS_TARGET := agent-status
WORKTREE_MARSHAL_RUN_ARGUMENTS :=
WORKTREE_MARSHAL_STATUS_ARGUMENTS := --triptych-status
WORKTREE_MARSHAL_REOPEN_ARGUMENTS := --triptych-reopen
WORKTREE_MARSHAL_DIFF_ARGUMENTS := --triptych-final-diff
WORKTREE_MARSHAL_INTEGRATE_ARGUMENTS := --triptych-integrate
WORKTREE_MARSHAL_RESOLVE_ARGUMENTS := --triptych-resolve
WORKTREE_MARSHAL_CONTINUE_ARGUMENTS := --triptych-continue
WORKTREE_MARSHAL_ABORT_ARGUMENTS := --triptych-abort
WORKTREE_MARSHAL_CLEAN_ARGUMENTS := --triptych-clean
"""
        self.write_makefile(configuration=configuration)

        cases = (
            (("agent",), []),
            (("agent-status",), ["--triptych-status"]),
            (("agent-status", f"RUN={RUN_ID}"), ["--triptych-status", RUN_ID]),
            (("reopen", f"RUN={RUN_ID}"), ["--triptych-reopen", RUN_ID]),
            (("final-diff", f"RUN={RUN_ID}"), ["--triptych-final-diff", RUN_ID]),
            (("integrate", f"RUN={RUN_ID}"), ["--triptych-integrate", RUN_ID]),
            (("resolve", f"RUN={RUN_ID}"), ["--triptych-resolve", RUN_ID]),
            (("continue", f"RUN={RUN_ID}"), ["--triptych-continue", RUN_ID]),
            (("abort", f"RUN={RUN_ID}"), ["--triptych-abort", RUN_ID]),
            (("clean-run", f"RUN={RUN_ID}"), ["--triptych-clean", RUN_ID]),
        )
        for arguments, expected in cases:
            with self.subTest(target=arguments[0], expected=expected):
                result = self.run_make(*arguments)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(self.invocations()[-1], expected)

        malformed = self.run_make("integrate", "RUN=bad")
        self.assertEqual(malformed.returncode, 2, malformed.stderr)
        self.assertIn("invalid Triptych Codex run ID", malformed.stderr)

        old_name = self.run_make("status")
        self.assertEqual(old_name.returncode, 2, old_name.stderr)
        self.assertIn("No rule to make target", old_name.stderr)

    def test_duplicate_target_names_fail_during_parse(self) -> None:
        self.write_makefile(
            configuration=(
                "WORKTREE_MARSHAL_STATUS_TARGET := inspect\n"
                "WORKTREE_MARSHAL_REOPEN_TARGET := inspect\n"
            )
        )
        self.assert_rejected_without_invocation(
            "inspect",
            f"RUN={RUN_ID}",
            contains="target names must be distinct",
        )

    def test_fragment_include_guard_allows_a_repeated_include(self) -> None:
        self.write_makefile(
            suffix=f"include {self.make_path(MAKE_FRAGMENT)}\n",
        )
        result = self.run_make("status")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(
            self.invocations(),
            [["--profile", "generic-v1", "status"]],
        )


if __name__ == "__main__":
    unittest.main()
