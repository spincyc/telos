# Telos repository guidance

These rules apply throughout this repository. Narrower `AGENTS.md` files may
add scope-specific requirements.

## Commits and pushes

- Commit coherent, independently verifiable units. Keep implementation
  commits free of `.journal/` changes and generated or ignored runtime state;
  record attributable journal checkpoints in adjacent journal-only commits.
- Before every terminal response or handoff, run
  `python3 .journal/bin/journal.py yield-check` as the immediately preceding
  action. Only exit zero with `YIELD PERMITTED` authorizes the response. On
  denial, discard the proposed final response, return to journal scheduling,
  and execute the highest-priority runnable task in the same turn. Any later
  tool call, commit, push, progress message, user question, or checkpoint
  invalidates a prior successful check. Status answers are commentary inside
  the loop; they never terminate active work.
- A bounded sub-agent reporting its completed result to the coordinating agent
  is an internal progress delivery, not a repository handoff or terminal
  response. It must deliver that result and finish even when the repository
  yield check is denied. The coordinating/root agent alone applies the
  repository yield gate before yielding control outside the active journal
  loop.
- Do not push without user authority. Before every authorized push, run
  `make verify-site` against the exact commit that will be pushed.
- After every push, find the `Publish GitHub Pages` workflow run whose
  `headSha` exactly equals the pushed commit, wait for it to finish, and
  require a successful conclusion before reporting the push complete or
  starting another push. A successful older run or a run for another SHA is
  not evidence.
- After every push to `main`, also verify that the successful
  `github-pages` deployment references the pushed SHA, inspect the deployment
  URL, and verify the affected public pages. Local site checks alone do not
  prove that GitHub Pages deployed correctly.
- If the exact-SHA workflow or deployment is missing or fails, investigate
  and repair it before another push. Preserve the failed run as evidence.
