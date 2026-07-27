# Handoff

Written 2026-07-26 at commit `b7f3bbe`. For an agent picking this up cold.

Read this, then `homelab/decisions/` for anything you are about to change in the
homelab. The decisions are the contract; the code is an implementation of them.

## Ground rules the owner has set

- **Commit and publish as sections complete.** Do not batch a day's work into one
  commit at the end.
- **Terse commit messages.** Subject line, blank line, two or three sentences of
  why. Clean up anything wordier.
- **One question at a time.** Use a single question with a recommended option
  first, minimal preamble. Do not stack three questions into one turn.
- **Publish when coherent.** `make check && make site` then push; the Pages
  workflow deploys on push to `main`.
- **Reach the test cycle first, harden after.** When a design choice trades
  speed-to-first-run against thoroughness, take the speed. ADR 0062 records this.
- **Never run `sudo` unasked.** Hand privileged commands to the owner with the
  exact argv.
- **Homelab is Markdown/HTML-first for now.** Homelab changes do not require
  new or rebuilt PDFs during the active implementation phase. Keep existing
  PDFs, but publish and review the human-readable GitHub Pages path.

## What this repository is

Four subjects, each built to print well in black and white, published as PDFs
to GitHub Pages at <https://spincyc.github.io/telos/>. Fishing, electricity,
and potato launcher now have explicit Claude and ChatGPT editions; homelab
remains provider-neutral.

| Project | State |
|---|---|
| `lake-country-fishing` | Complete. Pine Lake and North Lake: species sheets, rig sheets, lures, seasonal calendars, bathymetric maps, per-lake compendia, cooking and filleting sheets. |
| `electricity` | Lessons building to a spark-gap Tesla coil, with wiring diagrams. |
| `potato-launcher` | Deep treatment; combustion PVC launcher plus demonstrations. |
| `homelab` | **Active.** Provisioning system. See below. |

### Build system

    make            build every PDF into build/
    make install    promote reviewed builds into the tracked doc/ tree
    make site       regenerate site/ from site/pages/*.md and doc/
    make check      site/research checks, package-closure guard, 299 tests
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

## Homelab: where things stand

### Documentation queue

After implementation and the network design stabilize, make a complete
documentation pass in two linked layers:

- a terse human guide for purpose, ordinary use, maintenance, recovery, and
  knowing when to ask for help; and
- an exact operator runbook with prerequisites, commands, expected output,
  pass/fail gates, troubleshooting, rollback, rebuild, and final verification.

Cover Controller deployment and attachment, UniFi configuration, directory and
PXE operation, workstation minting, automatic updates, travel/offline use,
normal maintenance, fault recovery, and owner handoff. Keep the public layer
generic and secret-free; instance values belong in the private overlay.

The active deliverables are source Markdown and rendered GitHub Pages HTML.
Review the rendered pages for navigation, command wrapping, callouts, diagrams,
links, and small-screen use. Do not delete the existing homelab PDFs, and do
not let PDF work block the implementation cycle.

### The shape

A machine is installed by network booting it into an interactive environment,
answering questions at its console, and typing the target disk's **serial
number** to authorize the erase. There is no unattended path, no answer file,
and no flag that skips a prompt. Physical access plus that typed confirmation
*is* the authorization model (ADR 0058).

Install does only what cannot be done later. Everything else is Ansible
convergence from this repository (ADR 0053).

### What is built and tested

    homelab/lib/         netplan, dnsmasq, prompts, hardware, preflight, steps,
                         manifest, disks, artifacts, firstboot
    homelab/bin/         homelab-install, homelab-first-boot, homelab-render,
                         homelab-artifacts, homelab-image
    homelab/archiso/     the provisioning image profile
    homelab/ansible/     common, controller_network, services, identity_client
    homelab/qemu/        lab.py, pty_driver.py, matrix.py
    homelab/tests/       297 tests, all passing, no skips
    homelab/decisions/   63 ADRs

Key properties, each of which has a test:

- The destructive gate is **structural**: `steps.authorize()` mints an
  `Authorization` token carrying the disk it was granted for. Nothing else can
  construct one.
- A disk with no readable serial is never offered, because it could not be
  confirmed at the prompt. That rule fell out of the confirmation design.
- The acceptance harness drives the **genuine** installer through a
  pseudo-terminal. There is no test-only code path to abuse on real hardware.
- `bin/homelab-render` bridges Ansible to the same generators the installer
  uses, and tests assert byte equality. A template would be a second
  implementation that drifts silently while still passing `dnsmasq --test`.
- The site build fails closed if instance data (RFC 1918 literals, internal
  hostnames) reaches a published source (ADR 0046).
- `scripts/arch-packages --check` fails if the declared package closure would
  make pacman stop and ask which provider to use.

### Acceptance matrix

`make homelab-matrix`. Five stages; a stage that cannot run reports what it is
waiting for and the matrix does not call itself green.

| Stage | State |
|---|---|
| `firmware` | **passing** — a lab guest boots UEFI on its serial console, finds no boot disk, and attempts PXE over IPv4 on a segment with no route off it |
| `boot-chain` | pending — needs a built image |
| `install` | pending — needs a built image |
| `activation` | pending — needs a built image |
| `converge` | pending — needs a built image |

## The immediate next step

**Build the provisioning image.** Everything is staged and audited; the build
needs root and has not been run.

    make homelab-image      # stages into /tmp/homelab-image, audits, prints:
    sudo mkarchiso -v -w /tmp/homelab-image/work \
        -o /tmp/homelab-image/out /tmp/homelab-image/profile

Roughly 1–2 GiB of package downloads, 10–20 minutes. **Ask the owner before
running it** — they had not answered when this was written.

Optionally first: put an SSH **public** key at `homelab/instance/authorized_keys`
so the image runs sshd and an installation can be watched from another machine.
Without it the image is console-only, which is fine for the matrix, since the
matrix drives the serial console anyway. `bin/homelab-image` enables sshd only
when a key is present and refuses to stage a private key or an empty file.

Then implement matrix stages 2–5 in `homelab/qemu/matrix.py`. The scaffolding,
the pending-state reporting and the artifact detection are already there; each
stage needs its body written against `lab.Lab`, `matrix.boot_and_listen` and
`pty_driver.drive`.

`matrix.ARTIFACT_ROOT` defaults to `/tmp/homelab-image/out` and honours
`HOMELAB_ARTIFACT_ROOT`.

## Questions the owner has answered

- **Fixtures**: do not capture one machine's hardware. Capturing a box's state
  accomplishes nothing because production boxes differ; the installer must work
  against whatever it is actually installing on. Fixtures therefore describe
  hardware *shapes* — NVMe/SATA/eMMC partition naming, absent serials, removable
  media, several eligible disks, wireless-only. This is why
  `tests/test_hardware_shapes.py` exists.
- **Break-glass key**: a dedicated key pair used for nothing else, generated by
  the owner. Nothing in this repository handles the private half. Recorded as
  ADR 0063.

## Questions still open

Ask **one at a time**, recommended option first.

1. **The image build** — see above. This is the blocking one.
2. **The spare Controller machine's hostname.** Needed for the first real
   installation, not for the matrix.
3. **Windows dual-boot in the Workstation profile.** ADR 0055 has Windows Pro
   clients domain-joining and Windows Home keeping local accounts, but no
   decision records whether the Workstation *profile* installs alongside
   Windows or replaces it. Affects the disk layout in `lib/disks.py`, which
   currently claims the whole disk.

## Known gaps

- **No migration story for the existing Controller host.** There is no ADR
  covering how the current machine's data and services move onto a
  freshly-provisioned Controller. This is the gap that will bite on the day.
  It should be written before the first production installation, not after.
- **PXE build-and-install manual.** The design document exists; the procedural
  manual does not. `src/homelab/manual/controller-rebuild/` is the model to
  follow — commands paired with the observable evidence each one worked.
- **Matrix stages 2–5** are scaffolding only.
- **No second domain controller.** ADR 0055 requires one on separate physical
  hardware before the directory is production, deferred until the first works.

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
  root before running repository commands.
  first. `make` in the wrong directory has wasted many cycles.
- **`tabularx` cannot span a macro boundary.** `telosfacts` is plain `tabular`
  with `\dimexpr` widths for this reason. Documents that need `tabularx` use it
  directly with the `L/R/C/B/N` column types from `src/common/preamble.tex`.
- **`siunitx` is unavailable** in this TeX Live split. Use `\qty` / `\qtyrange`
  from the shared preamble.
- **A virtio disk reports no serial unless one is set.** This would have made
  the acceptance matrix fail with "no eligible disk" on its first real run, and
  the obvious diagnosis would have been that the installer was broken.
  `lab.py` sets one now; do not remove it.
- **Prompt order is deliberate**: subnet, pool start, pool end, Controller
  address *last*. The rule that the Controller must not sit inside the pool
  cannot be checked until the pool is known, so asking the address earlier
  reports the error on the wrong prompt.
- **`qemu-base`, never `qemu-desktop` or `qemu-full`.** The latter reach the
  virtual `jack` package, which stops pacman mid-transaction to ask for a
  provider. `make check` guards this.
- **`dnsmasq.refusals()` inspects directives only.** The generated file explains
  itself in comments and a comment must not read as a violation.

## Security constraints that remain in force

Do not place credentials, private keys, reusable bootstrap tokens, recovery keys
or unencrypted secrets in Git, logs, generated documentation, PXE roots, answer
files or command output.

- No plaintext secrets in Git. No private SSH keys in boot images. No reusable
  directory-administrator credentials in answer files.
- Real hostnames, addresses, MACs, disk serials and per-machine inventory live
  in the gitignored `homelab/instance/` overlay and are never published
  (ADR 0046). `homelab/instance-example/` is the tracked template; every value
  in it is a visible placeholder.
- The installation manifest is non-secret **by construction**, enforced in code
  (ADR 0060).
- There is no unattended installation path, and nothing may skip a prompt
  (ADR 0058).
