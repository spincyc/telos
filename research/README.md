# Shared research library

Research belongs to the subject, not to the AI that first found it. Each
project directory is a small evidence exchange that another provider can read,
extend, challenge, and selectively use without copying publication prose.

## Required records

| File | Contract |
|---|---|
| `sources.md` | Stable source IDs, issuing authority, title, direct URL, retrieval date or checked date, intended use, and volatility or limits where relevant. |
| `claims.md` | Atomic reusable claims with stable IDs, supporting source IDs, scope, caveats, and a clear mark when the statement is inference or editorial policy. |
| `<provider>-selection.md` | The claims an edition selected, rejected, or bounded; why they were salient; and the publication documents that use them. |

Projects may add topic indexes, archived witnesses, datasets, or working notes.
They may split a large library into `*-sources.md` and `*-claims.md` topical
ledgers; the validator treats those files as part of the same project-wide ID
space. Projects do not have to share a source-file layout with one another.

## Identity rules

- IDs are permanent. Do not silently redefine an existing source or claim.
- When evidence changes, mark the old claim deprecated and add a new ID.
- Keep claims small enough that another edition can accept one without
  inheriting a paragraph of conclusions.
- Separate a source’s statement from an author’s inference.
- Mark volatile law, regulation, prices, schedules, and local conditions with
  an explicit re-check boundary.
- Link to the issuing authority or original paper, not a search result or an
  article that merely repeats it.

## Provider independence

A provider selection manifest is an editorial lens, not an ownership claim.
Claude, ChatGPT, or a future provider may:

1. reuse a supported claim;
2. reject it and explain why;
3. narrow its scope;
4. add a stronger or newer source;
5. publish a different structure and document count.

The `scripts/research-library` check verifies that every project has the three
record types, claim IDs are unique, selection manifests resolve known claims,
and source registers contain direct HTTPS references.

## Publication boundary

The library is evidence infrastructure. It is not automatically published as
reader guidance, and it never overrides a live authority. Each edition remains
responsible for selecting, explaining, and dating the evidence it uses.
