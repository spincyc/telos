#!/usr/bin/env python3
"""Pure command-line grammar and engine-translation tests."""

from __future__ import annotations

import io
import sys
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest import mock


PACKAGE_ROOT = Path(__file__).resolve().parents[1]
SOURCE_ROOT = PACKAGE_ROOT / "src"
RUN_ID = "20000101t000000z-abcdef012345"
DISCARD_HEAD = "1" * 40
TARGET_CONTAINS = "2" * 40
EXPECTED_HELP = """usage: worktree-marshal --profile PROFILE COMMAND [ARGUMENTS...]
       worktree-marshal --help
       worktree-marshal --version

Profiles:
  generic-v1  Worktree Marshal's isolated generic lifecycle
  triptych    explicit compatibility access to Triptych schema 1

Commands:
  run --agent codex [-- CODEX_ARGUMENTS...]
  status [RUN_ID]
  reopen RUN_ID [-- CODEX_ARGUMENTS...]
  final-diff RUN_ID
  integrate RUN_ID
  resolve RUN_ID
  continue RUN_ID
  abort RUN_ID
  clean RUN_ID
  retire RUN_ID --discard-head FULL_OID --target-contains FULL_OID

Every stateful invocation requires exactly one case-sensitive --profile before
the command. The retire command is a destructive direct-only operation and has
no Make wrapper.
"""


class CliParsingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        sys.path.insert(0, str(SOURCE_ROOT))
        from worktree_marshal import cli

        cls.cli = cli

    @classmethod
    def tearDownClass(cls) -> None:
        try:
            sys.path.remove(str(SOURCE_ROOT))
        except ValueError:
            pass

    def invoke_pure(self, arguments: list[str]) -> tuple[int, str, str]:
        stdout = io.StringIO()
        stderr = io.StringIO()
        with (
            mock.patch.object(
                self.cli,
                "resolve_invocation_path",
                side_effect=AssertionError("pure parsing resolved an executable"),
            ) as resolve,
            mock.patch.object(
                self.cli,
                "dispatch",
                side_effect=AssertionError("pure parsing invoked the lifecycle engine"),
            ) as dispatch,
            redirect_stdout(stdout),
            redirect_stderr(stderr),
        ):
            result = self.cli.main(arguments)
        resolve.assert_not_called()
        dispatch.assert_not_called()
        return result, stdout.getvalue(), stderr.getvalue()

    def assert_usage(self, arguments: list[str], message: str) -> None:
        with self.assertRaises(self.cli.UsageError) as caught:
            self.cli.parse_arguments(arguments)
        self.assertEqual(str(caught.exception), message)

    def test_help_is_exact_and_has_no_lifecycle_side_effect(self) -> None:
        result, stdout, stderr = self.invoke_pure(["--help"])

        self.assertEqual(self.cli.HELP, EXPECTED_HELP)
        self.assertEqual(result, 0)
        self.assertEqual(stdout, EXPECTED_HELP)
        self.assertEqual(stderr, "")

    def test_version_is_exact_and_has_no_lifecycle_side_effect(self) -> None:
        result, stdout, stderr = self.invoke_pure(["--version"])

        self.assertEqual(result, 0)
        self.assertEqual(stdout, "worktree-marshal 0.0.0\n")
        self.assertEqual(stderr, "")

    def test_profile_failures_are_pure_and_exact(self) -> None:
        cases = (
            (
                [],
                "a stateful command requires --profile generic-v1 or --profile triptych",
            ),
            (
                ["status"],
                "a stateful command must begin with --profile generic-v1 or "
                "--profile triptych",
            ),
            (["--profile"], "--profile requires a value"),
            (
                ["--profile", "generic-v1"],
                "--profile must be followed by a command",
            ),
            (
                ["--profile", "unknown", "status"],
                "unknown profile 'unknown'",
            ),
            (
                ["--profile", "Generic-v1", "status"],
                "unknown profile 'Generic-v1'",
            ),
            (
                ["status", "--profile", "generic-v1"],
                "a stateful command must begin with --profile generic-v1 or "
                "--profile triptych",
            ),
            (
                ["--profile", "generic-v1", "--profile", "triptych", "status"],
                "unknown command '--profile'",
            ),
            (
                ["--profile", "generic-v1", "status", "--profile", "triptych"],
                "status accepts at most one run ID",
            ),
        )

        for arguments, message in cases:
            with self.subTest(arguments=arguments):
                self.assert_usage(arguments, message)
                result, stdout, stderr = self.invoke_pure(arguments)
                self.assertEqual(result, 2)
                self.assertEqual(stdout, "")
                self.assertEqual(stderr, f"worktree-marshal: {message}\n")

    def test_built_in_profiles_are_accepted_only_in_the_leading_slot(self) -> None:
        generic = self.cli.parse_arguments(
            ["--profile", "generic-v1", "status"]
        )
        compatibility = self.cli.parse_arguments(
            ["--profile", "triptych", "status", RUN_ID]
        )

        self.assertEqual(generic.profile_id, "generic-v1")
        self.assertIsNone(generic.run_id)
        self.assertEqual(compatibility.profile_id, "triptych")
        self.assertEqual(compatibility.run_id, RUN_ID)

    def test_run_arity_and_agent_selector_are_exact(self) -> None:
        self.assertEqual(
            self.cli.parse_arguments(
                ["--profile", "generic-v1", "run", "--agent", "codex"]
            ),
            self.cli.ParsedCommand(profile_id="generic-v1", command="run"),
        )
        for operands in (
            [],
            ["--agent"],
            ["--agent", "claude"],
            ["codex"],
            ["--agent", "codex", "--model", "gpt"],
        ):
            with self.subTest(operands=operands):
                self.assert_usage(
                    ["--profile", "generic-v1", "run", *operands],
                    (
                        "Codex arguments after run require a -- delimiter"
                        if operands[:2] == ["--agent", "codex"]
                        else "run requires exactly --agent codex before agent arguments"
                    ),
                )

    def test_status_and_reopen_arities_are_exact(self) -> None:
        status = self.cli.parse_arguments(
            ["--profile", "generic-v1", "status"]
        )
        selected = self.cli.parse_arguments(
            ["--profile", "generic-v1", "status", RUN_ID]
        )
        reopened = self.cli.parse_arguments(
            ["--profile", "generic-v1", "reopen", RUN_ID]
        )

        self.assertIsNone(status.run_id)
        self.assertEqual(selected.run_id, RUN_ID)
        self.assertEqual(reopened.run_id, RUN_ID)
        self.assert_usage(
            ["--profile", "generic-v1", "status", RUN_ID, "extra"],
            "status accepts at most one run ID",
        )
        self.assert_usage(
            ["--profile", "generic-v1", "reopen"],
            "reopen requires exactly one run ID",
        )
        self.assert_usage(
            ["--profile", "generic-v1", "reopen", RUN_ID, "--model", "gpt"],
            "Codex arguments after reopen require a -- delimiter",
        )

    def test_single_run_id_lifecycle_command_arities_are_exact(self) -> None:
        for command in (
            "abort",
            "clean",
            "continue",
            "final-diff",
            "integrate",
            "resolve",
        ):
            with self.subTest(command=command, arity="valid"):
                parsed = self.cli.parse_arguments(
                    ["--profile", "generic-v1", command, RUN_ID]
                )
                self.assertEqual(parsed.run_id, RUN_ID)
            for operands in ([], [RUN_ID, "extra"]):
                with self.subTest(command=command, operands=operands):
                    self.assert_usage(
                        ["--profile", "generic-v1", command, *operands],
                        f"{command} requires exactly one run ID",
                    )

    def test_retire_arity_and_option_order_are_exact(self) -> None:
        arguments = [
            "--profile",
            "generic-v1",
            "retire",
            RUN_ID,
            "--discard-head",
            DISCARD_HEAD,
            "--target-contains",
            TARGET_CONTAINS,
        ]
        parsed = self.cli.parse_arguments(arguments)

        self.assertEqual(parsed.run_id, RUN_ID)
        self.assertEqual(parsed.discard_head, DISCARD_HEAD)
        self.assertEqual(parsed.target_contains, TARGET_CONTAINS)
        invalid_operands = (
            [],
            [RUN_ID],
            [
                RUN_ID,
                "--target-contains",
                TARGET_CONTAINS,
                "--discard-head",
                DISCARD_HEAD,
            ],
            [
                RUN_ID,
                "--discard-head",
                DISCARD_HEAD,
                "--target-contains",
                TARGET_CONTAINS,
                "extra",
            ],
        )
        for operands in invalid_operands:
            with self.subTest(operands=operands):
                self.assert_usage(
                    ["--profile", "generic-v1", "retire", *operands],
                    (
                        "retire requires exactly RUN_ID --discard-head FULL_OID "
                        "--target-contains FULL_OID"
                    ),
                )

    def test_agent_delimiters_and_tokens_are_preserved_exactly(self) -> None:
        run = self.cli.parse_arguments(
            [
                "--profile",
                "generic-v1",
                "run",
                "--agent",
                "codex",
                "--",
                "--",
                "--literal-prompt",
            ]
        )
        reopen = self.cli.parse_arguments(
            [
                "--profile",
                "generic-v1",
                "reopen",
                RUN_ID,
                "--",
                "--",
                "--literal-prompt",
            ]
        )
        empty_reopen = self.cli.parse_arguments(
            ["--profile", "generic-v1", "reopen", RUN_ID, "--"]
        )

        self.assertTrue(run.agent_delimiter)
        self.assertEqual(run.agent_arguments, ("--", "--literal-prompt"))
        self.assertEqual(
            self.cli.engine_arguments(run),
            ["--", "--literal-prompt"],
        )
        self.assertTrue(reopen.agent_delimiter)
        self.assertEqual(reopen.agent_arguments, ("--", "--literal-prompt"))
        self.assertEqual(
            self.cli.engine_arguments(reopen),
            [
                "--triptych-reopen",
                RUN_ID,
                "--",
                "--",
                "--literal-prompt",
            ],
        )
        self.assertTrue(empty_reopen.agent_delimiter)
        self.assertEqual(empty_reopen.agent_arguments, ())
        self.assertEqual(
            self.cli.engine_arguments(empty_reopen),
            ["--triptych-reopen", RUN_ID, "--"],
        )

    def test_every_command_has_exact_engine_arguments(self) -> None:
        cases = (
            (
                [
                    "--profile",
                    "generic-v1",
                    "run",
                    "--agent",
                    "codex",
                    "--",
                    "--model",
                    "gpt",
                    "prompt",
                ],
                ["--model", "gpt", "prompt"],
            ),
            (["--profile", "generic-v1", "status"], ["--triptych-status"]),
            (
                ["--profile", "triptych", "status", RUN_ID],
                ["--triptych-status", RUN_ID],
            ),
            (
                ["--profile", "generic-v1", "reopen", RUN_ID],
                ["--triptych-reopen", RUN_ID],
            ),
            (
                ["--profile", "generic-v1", "final-diff", RUN_ID],
                ["--triptych-final-diff", RUN_ID],
            ),
            (
                ["--profile", "generic-v1", "integrate", RUN_ID],
                ["--triptych-integrate", RUN_ID],
            ),
            (
                ["--profile", "generic-v1", "resolve", RUN_ID],
                ["--triptych-resolve", RUN_ID],
            ),
            (
                ["--profile", "generic-v1", "continue", RUN_ID],
                ["--triptych-continue", RUN_ID],
            ),
            (
                ["--profile", "generic-v1", "abort", RUN_ID],
                ["--triptych-abort", RUN_ID],
            ),
            (
                ["--profile", "generic-v1", "clean", RUN_ID],
                ["--triptych-clean", RUN_ID],
            ),
            (
                [
                    "--profile",
                    "generic-v1",
                    "retire",
                    RUN_ID,
                    "--discard-head",
                    DISCARD_HEAD,
                    "--target-contains",
                    TARGET_CONTAINS,
                ],
                [
                    "--triptych-retire",
                    RUN_ID,
                    "--discard-head",
                    DISCARD_HEAD,
                    "--target-contains",
                    TARGET_CONTAINS,
                ],
            ),
        )

        for arguments, expected in cases:
            with self.subTest(command=arguments[2]):
                parsed = self.cli.parse_arguments(arguments)
                self.assertEqual(self.cli.engine_arguments(parsed), expected)


if __name__ == "__main__":
    unittest.main()
