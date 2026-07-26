# ADR 0058: Drive acceptance tests through the real interactive installer

- Status: Accepted
- Date: 2026-07-26

## Context

Two accepted decisions contradict each other.

ADR 0004 rejects a pre-staged deployment record and makes interactive
confirmation at the physical console *the* authorization boundary: nothing
destructive happens without an operator answering for it there and then.

ADR 0056 requires the QEMU acceptance matrix to install a virtual Controller
"unattended from the real installer using a recorded answer set". A recorded
answer set is exactly the pre-staged record ADR 0004 rejected, and running
unattended bypasses the confirmation that ADR 0004 defines as the boundary.

Resolving this by adding an `--unattended` flag guarded by a virtual-machine
check would leave one runtime check standing between a convenience flag and a
wiped disk. Checks like that get relaxed under deadline pressure, and the
consequence is unrecoverable.

## Decision

**No unattended installation code path exists.** The installer is interactive
and only interactive.

The acceptance matrix drives it by attaching to a pseudo-terminal and answering
prompts the way a person would, including the final confirmation.

- Prompt definitions live in one registry, `homelab/lib/prompts.py`: each prompt
  has a stable identifier, its human-facing text, its validator and its help
  text.
- The installer renders that registry. The test harness imports the same
  registry to know what to expect. There is one source of truth, so changing a
  prompt's wording cannot silently desynchronize the tests.
- The harness matches on prompt identity, supplies an answer, and asserts on
  what the installer prints back.
- There is no flag, environment variable or file that skips a prompt, and no
  code path that reaches a destructive operation without the confirmation
  having been answered.

The final confirmation requires the operator to **type the target disk's serial
number**, not to answer yes. A serial cannot be typed from muscle memory, cannot
be answered correctly by someone who has not read the summary, and cannot be
satisfied by a stray keystroke.

## Consequences

- ADR 0004 remains literally true on physical hardware: there is nothing to
  bypass because nothing exists to bypass.
- The artifact under test is byte-identical to the artifact that runs on metal,
  which is what ADR 0043 requires when it says to reprovision from the proven
  installer.
- The harness is more involved than reading an answers file, and acceptance runs
  are slower because they are driven through a terminal.
- A change to prompt wording is picked up by the harness automatically. A change
  to prompt *structure* -- adding, removing or reordering -- fails the matrix
  loudly, which is the correct outcome.
- ADR 0056's phrase "unattended from the real installer using a recorded answer
  set" is superseded on the mechanism. The intent, an automated end-to-end
  install with no human present, is unchanged.
- Nothing here weakens the ADR 0004 boundary for a person with physical console
  access, which that ADR already states it does not protect against.
