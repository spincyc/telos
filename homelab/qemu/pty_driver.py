"""Drive the real interactive installer through a pseudo-terminal.

ADR 0058: there is no unattended installation path, so the acceptance harness
answers the genuine prompts the way a person would. This module is that harness.

It works against two things without knowing the difference:

  * the installer running locally as a subprocess, for fast development; and
  * a serial console attached to a QEMU guest, once the matrix exists.

Both are a file descriptor that emits prompts and accepts typed lines.

The driver syncs on prompt *text taken from the registry the installer renders*,
so a reworded prompt cannot silently desynchronize the two. A prompt that
appears and is not in the script is an error, not something to guess at --
guessing is how a harness ends up confirming a disk erase nobody scripted.
"""

from __future__ import annotations

import os
import pty
import re
import select
import signal
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "lib"))

import prompts  # noqa: E402


class DriverError(RuntimeError):
    """The conversation did not go as scripted."""


@dataclass
class Transcript:
    """Everything the installer said, and everything the driver typed."""
    text: str = ""
    answered: list[tuple[str, str]] = field(default_factory=list)
    exit_status: int | None = None

    def saw(self, needle: str) -> bool:
        return needle in self.text

    def tail(self, lines: int = 40) -> str:
        return "\n".join(self.text.splitlines()[-lines:])


class Conversation:
    """A scripted set of answers, looked up by prompt identifier.

    An answer may be a list, in which case successive askings consume it in
    order. That is how a test exercises re-prompting: answer badly, watch the
    installer refuse, then answer correctly. Without it a bad answer would be
    repeated forever and the run would only end at the timeout.
    """

    def __init__(self, answers: dict[str, str | list[str]],
                 confirmation: str | list[str] | None = None) -> None:
        self.answers = {key: list(value) if isinstance(value, list) else value
                        for key, value in answers.items()}
        self.confirmation = confirmation

    def _take(self, identifier: str, value):
        """Consume one answer, holding the last one once a list runs out."""
        if isinstance(value, list):
            if not value:
                raise DriverError(
                    f"the script ran out of answers for {identifier!r}; the "
                    "installer is still asking")
            return value.pop(0)
        return value

    def reply_to(self, rendered: str) -> tuple[str, str]:
        """Return (identifier, answer) for a prompt the installer just printed.

        Matching is on the exact text from the shared registry, so this cannot
        drift from what the installer asks.
        """
        for prompt in prompts.PROMPTS:
            if prompt.render().rstrip() in rendered:
                if prompt.identifier not in self.answers:
                    raise DriverError(
                        f"the installer asked {prompt.identifier!r} but the script "
                        "has no answer for it")
                return prompt.identifier, self._take(
                    prompt.identifier, self.answers[prompt.identifier])

        if prompts.CONFIRMATION_TEXT in rendered:
            if self.confirmation is None:
                raise DriverError(
                    "the installer reached the authorization prompt but the script "
                    "has no confirmation. Refusing to invent one.")
            return "__confirmation__", self._take("__confirmation__", self.confirmation)

        raise DriverError(f"unrecognised prompt: {rendered.strip()!r}")


def _looks_like_a_prompt(buffer: str) -> str | None:
    """A prompt is a trailing line ending in ': ' with no newline after it."""
    if not buffer.endswith(": "):
        return None
    return buffer.rsplit("\n", 1)[-1]


def drive(argv: list[str], conversation: Conversation, *,
          timeout: float = 60.0, echo: bool = False) -> Transcript:
    """Run `argv` under a pty and answer its prompts. Returns the transcript."""
    transcript = Transcript()
    parent, child = pty.openpty()

    process = subprocess.Popen(
        argv, stdin=child, stdout=child, stderr=child,
        close_fds=True, preexec_fn=os.setsid)
    os.close(child)

    buffer = ""
    deadline = time.monotonic() + timeout
    try:
        while True:
            if time.monotonic() > deadline:
                raise DriverError(
                    f"timed out after {timeout:.0f}s. Last output:\n{transcript.tail()}")

            readable, _, _ = select.select([parent], [], [], 0.25)
            if readable:
                try:
                    chunk = os.read(parent, 4096).decode("utf-8", "replace")
                except OSError:
                    chunk = ""
                if not chunk:
                    break
                transcript.text += chunk
                buffer += chunk
                if echo:
                    sys.stdout.write(chunk)
                    sys.stdout.flush()

                pending = _looks_like_a_prompt(buffer)
                if pending:
                    identifier, answer = conversation.reply_to(pending)
                    os.write(parent, (answer + "\n").encode())
                    transcript.answered.append((identifier, answer))
                    buffer = ""
                    deadline = time.monotonic() + timeout
                elif "\n" in buffer:
                    buffer = buffer.rsplit("\n", 1)[-1]
            elif process.poll() is not None:
                # Drain anything still buffered after the process exited.
                while True:
                    readable, _, _ = select.select([parent], [], [], 0.1)
                    if not readable:
                        break
                    try:
                        chunk = os.read(parent, 4096).decode("utf-8", "replace")
                    except OSError:
                        break
                    if not chunk:
                        break
                    transcript.text += chunk
                break
    finally:
        os.close(parent)
        if process.poll() is None:
            os.killpg(os.getpgid(process.pid), signal.SIGTERM)
        transcript.exit_status = process.wait()

    return transcript


# --------------------------------------------------------------------------
# Assertions the acceptance matrix makes about a transcript
# --------------------------------------------------------------------------


def assert_authorization_was_required(transcript: Transcript) -> None:
    """The gate must have been reached and answered, not skipped."""
    if prompts.CONFIRMATION_TEXT not in transcript.text:
        raise DriverError(
            "the installer never asked for authorization. ADR 0058 requires the "
            "serial-typed confirmation before anything destructive.")


def assert_no_destruction(transcript: Transcript) -> None:
    """For runs that should have stopped before writing anything."""
    if "HAS BEEN PARTIALLY WRITTEN" in transcript.text:
        raise DriverError("a run that should have been refused wrote to a disk")
    if not re.search(r"[Nn]othing has been written", transcript.text):
        raise DriverError(
            "a refused run did not state that nothing was written. The operator "
            "is left not knowing whether the disk is intact.")


def manifest_from(transcript: Transcript) -> dict:
    import manifest as manifest_module
    return manifest_module.extract_from_console(transcript.text)
