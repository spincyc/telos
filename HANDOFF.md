# Handoff

Durable task coordination lives in the local AIQ journal (`aiq status`); do
not reconstruct an active-agent snapshot from this file.

## Ground rules the owner has set

- **Commit and publish as sections complete.** Do not batch a day's work into one
  commit at the end.
- **Terse commit messages.** Subject line, blank line, two or three sentences of
  why. Clean up anything wordier.
- **One question at a time.** Use a single question with a recommended option
  first, minimal preamble. Do not stack three questions into one turn.
- **Publish when coherent.** `make check && make site` then push; the Pages
  workflow deploys on push to `main`.
- **Never run `sudo` unasked.** Hand privileged commands to the owner with the
  exact argv.

## What this repository is

Three subjects, each built to print well in black and white, published as PDFs
to GitHub Pages at <https://spincyc.github.io/telos/>. Each has explicit
Claude and ChatGPT editions.

| Project | State |
|---|---|
| `lake-country-fishing` | Complete. Pine Lake and North Lake: species sheets, rig sheets, lures, seasonal calendars, bathymetric maps, per-lake compendia, cooking and filleting sheets. |
| `electricity` | Lessons building to a spark-gap Tesla coil, with wiring diagrams. |
| `potato-launcher` | Deep treatment; combustion PVC launcher plus demonstrations. |

### Build system

    make            build every PDF into build/
    make install    promote reviewed builds into the tracked doc/ tree
    make site       regenerate site/ from site/pages/*.md and doc/
    make check      site/research checks, package-closure guard, and tests
    make list       every document id

A document is any directory under `src/` containing `main.tex`. `src/common/`
holds shared includes and never becomes a document. TEXINPUTS is built from the
leaf directory, so `\input{common/preamble.tex}` works from anywhere.

### Provider editions and shared research

Read `PROVIDER-EDITIONS.md` before adding a provider or reorganizing a
publication. Provider identity is explicit in source and artifact paths:

    src/<project>/<provider>/<document>/main.tex
    doc/<project>/<provider>/<document>.pdf

Provider editions do not need symmetric document trees or landing-page
layouts. Evidence is shared through `research/<project>/sources.md` and atomic
`claims.md`; each edition records its own selections and exclusions in
`<provider>-selection.md`. `scripts/research-library` enforces the exchange
contract.

The site header is intentionally limited to Home, Projects, and About. New
projects belong in the directory rather than global navigation. Every page
selects a validated template under `release/site/layouts/`; project-specific
layouts are expected.

`tools/worktree-marshal/` is still Codex-only. Multi-provider publication does
not authorize or imply a generic agent launcher.

## Publication teaching standard

`src/AGENTS.md` is the durable contract for every Telos publication. New and
revised material must teach the reader how to verify each important step:
questions before explanations, illustrations at meaningful state changes,
recorded observations and repeated measurements, worked examples with units,
safe fault isolation, reject or stop conditions, and a final acceptance proof.
Do not compress these away to preserve a one-page format. Project-local
contracts may tighten safety and evidence boundaries but may not weaken the
verification standard.

Review source and PDF together. Build every affected publication, inspect every
page at normal grayscale print scale, and promote the reviewed PDF in the same
change as its source.

## Traps that have already cost time

- **`git`/shell cwd resets between commands.** Return to the Telos checkout
  root before running repository commands. `make` in the wrong directory has
  wasted many cycles.
- **`tabularx` cannot span a macro boundary.** `telosfacts` is plain `tabular`
  with `\dimexpr` widths for this reason. Documents that need `tabularx` use it
  directly with the `L/R/C/B/N` column types from `src/common/preamble.tex`.
- **`siunitx` is unavailable** in this TeX Live split. Use `\qty` / `\qtyrange`
  from the shared preamble.

## Security

This repository is public. Never place credentials, private keys, tokens or
private addresses in Git, the site or command output; `make check` refuses
private address literals in published sources.
