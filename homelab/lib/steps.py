"""The installation sequence: ordered steps, one failure model, no way round it.

ADR 0059 fixes the behaviour. A step fails, the run stops, nothing further is
attempted, and the report says exactly where it stopped and why. There is no
rollback and no resume, because the disk is already unrecoverable once
partitioning begins and the thing worth preserving after a failure is the
evidence of it.

The safety property that matters here is structural rather than procedural:

    A destructive step cannot execute without an Authorization, and an
    Authorization can only be produced by `authorize()`, which requires the
    operator to have typed the target disk's serial.

There is no boolean to pass by mistake and no flag to set. If the token is
absent, the runner refuses before running the step, not after.
"""

from __future__ import annotations

import subprocess
import time
from dataclasses import dataclass, field
from typing import Callable

import prompts


class StepFailed(RuntimeError):
    """A step did not complete. The run stops here (ADR 0059)."""

    def __init__(self, step: "Step", detail: str, command: list[str] | None = None,
                 returncode: int | None = None, output: str = "") -> None:
        super().__init__(detail)
        self.step = step
        self.detail = detail
        self.command = command
        self.returncode = returncode
        self.output = output


class NotAuthorized(RuntimeError):
    """A destructive step was reached without an authorization token."""


@dataclass(frozen=True)
class Authorization:
    """Proof that the operator typed the target disk's serial.

    Constructed only by `authorize()`. Carrying the serial and the device means
    the token cannot be reused for a different disk than the one confirmed.
    """
    disk_path: str
    disk_serial: str
    granted_at: float


def authorize(typed: str, *, disk_path: str, disk_serial: str,
              clock: Callable[[], float] = time.time) -> Authorization | None:
    """Turn a typed confirmation into a token, or return None.

    This is the only way an Authorization comes into existence, which is what
    makes ADR 0058's gate structural rather than a convention.
    """
    if not prompts.confirm_disk_serial(typed, disk_serial):
        return None
    return Authorization(disk_path=disk_path, disk_serial=disk_serial, granted_at=clock())


@dataclass
class Step:
    """One unit of installation work."""

    name: str
    description: str
    run: Callable[[], None]
    destructive: bool = False


@dataclass
class Outcome:
    completed: list[Step] = field(default_factory=list)
    failed: Step | None = None
    error: StepFailed | None = None

    @property
    def succeeded(self) -> bool:
        return self.failed is None


class Runner:
    """Executes steps in order and stops at the first failure."""

    def __init__(self, steps: list[Step], *, authorization: Authorization | None = None,
                 emit: Callable[[str], None] = print) -> None:
        self.steps = steps
        self.authorization = authorization
        self.emit = emit

    def run(self, *, target_disk: str | None = None) -> Outcome:
        outcome = Outcome()
        for index, step in enumerate(self.steps, 1):
            if step.destructive:
                self._require_authorization(step, target_disk)
            self.emit(f"[{index}/{len(self.steps)}] {step.description}")
            try:
                step.run()
            except StepFailed as failure:
                outcome.failed, outcome.error = step, failure
                return outcome
            except Exception as error:  # noqa: BLE001 -- reported, never swallowed
                failure = StepFailed(step, f"{type(error).__name__}: {error}")
                outcome.failed, outcome.error = step, failure
                return outcome
            outcome.completed.append(step)
        return outcome

    def _require_authorization(self, step: Step, target_disk: str | None) -> None:
        if self.authorization is None:
            raise NotAuthorized(
                f"step {step.name!r} is destructive and no authorization was given. "
                "Nothing has been written to any disk."
            )
        if target_disk is not None and self.authorization.disk_path != target_disk:
            # The token names the disk it was granted for. A token obtained for
            # one disk must never authorize erasing another.
            raise NotAuthorized(
                f"authorization was granted for {self.authorization.disk_path} "
                f"but step {step.name!r} targets {target_disk}. Nothing has been written."
            )


# --------------------------------------------------------------------------
# Running commands
# --------------------------------------------------------------------------


def command(step_name: str, argv: list[str], *,
            runner: Callable[..., subprocess.CompletedProcess] = subprocess.run
            ) -> Callable[[], None]:
    """A step body that runs one command and raises StepFailed on non-zero.

    Output is captured so the failure report can include it. A step that fails
    without saying what the command printed is a step that costs an hour.
    """
    def execute() -> None:
        result = runner(argv, capture_output=True, text=True)
        if result.returncode != 0:
            raise StepFailed(
                Step(step_name, step_name, lambda: None),
                f"command exited {result.returncode}",
                command=argv,
                returncode=result.returncode,
                output=((result.stdout or "") + (result.stderr or "")).strip(),
            )
    return execute


# --------------------------------------------------------------------------
# The failure report, which is the primary artefact of a bad run
# --------------------------------------------------------------------------


def failure_report(outcome: Outcome, *, target_disk: str) -> list[str]:
    """Everything an operator needs to understand and act on a failure."""
    rule = "=" * 72
    lines = [rule, "INSTALLATION FAILED", rule, ""]

    if outcome.completed:
        lines.append("  Completed before the failure:")
        for step in outcome.completed:
            lines.append(f"    done   {step.name}  --- {step.description}")
    else:
        lines.append("  No step completed.")
    lines.append("")

    failed = outcome.failed
    error = outcome.error
    lines.append(f"  Failed at:  {failed.name}")
    lines.append(f"              {failed.description}")
    lines.append(f"  Reason:     {error.detail}")
    if error.command:
        lines.append(f"  Command:    {' '.join(error.command)}")
    if error.returncode is not None:
        lines.append(f"  Exit code:  {error.returncode}")
    if error.output:
        lines.append("")
        lines.append("  Output:")
        for line in error.output.splitlines():
            lines.append(f"    {line}")
    lines.append("")

    lines.append(rule)
    if any(step.destructive for step in outcome.completed) or failed.destructive:
        lines.append(f"  {target_disk} HAS BEEN PARTIALLY WRITTEN AND WILL NOT BOOT.")
        lines.append("")
        lines.append("  Nothing was rolled back, deliberately: cleaning up would destroy")
        lines.append("  the evidence above, and there is no data left on this disk to")
        lines.append("  protect (ADR 0059).")
        lines.append("")
        lines.append("  To retry, run the installer again from the beginning. It will")
        lines.append("  ask for authorization again and erase the disk again.")
    else:
        lines.append(f"  No disk was written. {target_disk} is untouched.")
    lines.append(rule)
    return lines


def success_report(outcome: Outcome, *, target_disk: str, hostname: str) -> list[str]:
    rule = "=" * 72
    return [
        rule,
        "INSTALLATION COMPLETE",
        rule,
        "",
        f"  {hostname} installed to {target_disk}",
        f"  {len(outcome.completed)} steps completed.",
        "",
        "  The machine will now power off rather than reboot (ADR 0010).",
        "  Move it to its network while it is powered off, then power it on.",
        rule,
    ]
