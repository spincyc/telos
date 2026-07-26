# Provider editions

Telos treats an AI provider as publication provenance, not as a theme switch.
An edition may have its own document count, hierarchy, pedagogy, visual
language, and landing-page layout. The only shared contracts are evidence
traceability, safe publication, working links, and printable output.

## Repository shape

```text
research/<project>/
  sources.md
  claims.md
  <provider>-selection.md

src/<project>/<provider>/<document>/main.tex
doc/<project>/<provider>/<document>.pdf
site/pages/<project>/<provider>.md
```

Project chooser pages live at `site/pages/<project>/index.md`. Homelab remains
provider-neutral and keeps its existing source organization.

## What is shared

Research is the interchange surface. A provider can read another provider’s
sources and atomic claims, add evidence, or select different claims. It must
record those choices in its own selection manifest. Publication prose and TeX
includes are not shared across provider editions by default.

Run:

```sh
python scripts/research-library
```

The check requires a source register, claim ledger, and provider selection for
every researched project; verifies stable claim identity; rejects unresolved
claim selections; and requires direct HTTPS source references.

## Adding a provider edition

1. Read the project’s existing source register and claim ledger.
2. Re-check volatile sources and append stronger evidence where useful.
3. Add atomic claims without redefining existing IDs.
4. Write `<provider>-selection.md`, including exclusions and editorial reasons.
5. Create any document arrangement appropriate to the provider’s treatment.
6. Add a provider-specific landing source and select an appropriate layout in
   `site/site.json`.
7. Build and promote PDFs, then run `make check && make site && make verify-site`.

Do not create empty counterparts to make a matrix look complete. The manifest
lists real editions explicitly; a project can support one provider, several
providers, or none.

## Site architecture

The global header is intentionally bounded to Home, Projects, and About.
Individual projects are discovered through the searchable directory rather
than appended to global navigation.

Every manifest page selects a validated layout from
`release/site/layouts/<layout>.html`. Layout IDs cannot contain path
separators. Provider pages can therefore differ structurally without allowing
arbitrary template paths or forcing their content into a symmetric schema.

The site builder scans every declared page source for links and every published
PDF for reachability. Nested output paths are resolved as a browser would
resolve them. The homelab instance-data leak check remains recursive over all
site page sources.

## ChatGPT Projects

The ChatGPT publication set is canonical in Git. A ChatGPT Project is a useful
workspace for continuing an edition, but it does not automatically discover
repository files or enforce this structure.

For a working ChatGPT Project:

- choose project-only memory when creating it when isolation is desired;
- upload the project’s research register, claim ledger, ChatGPT selection
  manifest, and the small set of documents relevant to the task;
- put durable editorial constraints in Project Instructions;
- bring newly accepted evidence and decisions back into this repository.

Do not treat opaque chat memory or a saved response as the durable research
record. The repository remains the source of truth.

## Worktree Marshal boundary

`tools/worktree-marshal/` remains Codex-only. Supporting another coding-agent
runtime requires its own adapter, confinement model, credentials policy,
durable run identity, and security tests. Provider editions do not imply a
generic executable launcher, and this refactor deliberately does not create
one.
