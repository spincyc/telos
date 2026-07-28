# Hands-on visual curriculum audit

This ledger applies the publication contract in [AGENTS.md](AGENTS.md) to the
repository's delivered hands-on curriculum. It tracks whether a reader can
recognize and verify progress, not how many image files a document contains.
A single finished-state image does not cover materially different setup,
action, checkpoint, result, and failure states.

Audit baseline: `a649b80`, 2026-07-28. Review the delivered PDF or HTML as well
as its source before changing a status.

## Status and teaching jobs

- **Pass** — all applicable teaching jobs are present, adjacent, legible, and
  verified in the delivered output.
- **Partial** — useful evidence exists, but one or more applicable jobs are
  missing or materially ambiguous.
- **Missing** — the publication lacks usable visual instruction for a central
  hands-on sequence.
- **Blocked—safety** — a visual would require unsupported or unsafe facts; fix
  the evidence/content contract before drawing it.
- **Not applicable** — the job does not apply, with a recorded reason.

The teaching jobs are:

1. orientation or system overview;
2. exact wiring, geometry, component order, or construction detail;
3. staged before/action/after states;
4. inspection or measurement checkpoints;
5. expected passing visible state;
6. targeted failure and troubleshooting states;
7. explicit prose reference and a caption that identifies evidence and the
   next action or decision;
8. legibility in ordinary grayscale print and, for active HTML, a narrow
   viewport.

Graphite is the default for people, hands, tools, materials, apparatus, food,
landscape, and observable physical state. Exact wiring, dimensions, maps,
graphs, safety boundaries, and state logic remain deterministic schematics.
Neither medium substitutes for the other.

## Inventory

The repository publishes four hands-on projects, 30 provider/type families,
148 PDFs, and 1,072 PDF pages at this baseline:

| Project | Families | Delivered PDFs | Pages | Current audit |
|---|---:|---:|---:|---|
| Potato Launcher | 5 | 18 | 56 | Detailed below; remediation first |
| Electricity & Magnetism | 10 | 36 | 139 | Family audit complete; leaf ledger pending |
| Lake Country Fishing | 12 | 86 | 800 | Family audit complete; leaf ledger pending |
| Homelab | 3 | 8 retained PDFs | 77 | Active Markdown/HTML family audit complete |

Research records, generated build intermediates, tooling, and site chooser
pages are supporting material rather than hands-on publication leaves. Site
pages still require audit when they deliver or navigate an operational
procedure. Homelab's active deliverables are Markdown and HTML; retained PDFs
do not create a new PDF requirement.

## Potato Launcher — first remediation gate

All 18 delivered PDFs were rendered and inspected. The project has five
external pencil PNGs and 35 instantiated TikZ figures. Every PDF has at least
one visual, but the project remains **partial** because visual count does not
cover the required states.

### Publication ledger

| Edition / publication | Existing useful evidence | Status | Material gap / next visual |
|---|---|---|---|
| ChatGPT `build-standard` | Three-state cut/dress/insertion plate; disposition flow | Partial | Add whole-system pressure-boundary overview, parts/marking PASS–REJECT plate, build-stage rail, cure-lock state, joint/penetration defect atlas, and evidence checkpoints. Exact ignition wiring is blocked pending sourced topology. |
| ChatGPT `field-guide` | COLD→FIRE state chain; graphite range scene | Partial | Replace/supplement the unlabeled scene with an annotated overhead range plan; add current-state proof marks, normal-shot log, and a three-panel 60-second misfire sequence. |
| ChatGPT `science-notebook` | Four coherent graphite model plates | Partial | Make each plate express its actual checkpoint: bounded number line, keyed material inspection, uncertainty legend/range boundary, and clipped-vs-true waveform plus range controls. Add a prediction→evidence→decision strip. |
| Claude `overview` | Labeled launcher identification section | Partial | Add causal energy strip, two-lane course/build map, and evidence-decision loop. Do not repeat the existing safety or launcher plates decoratively. |
| Claude `safety` | Range/firing-line safety plate | Partial | Add operator placement and exclusion zones, misfire timeline, pre-shot state, and anomaly→COLD→quarantine decision strip. Do not invent an obstruction-clearing method. |
| Claude `build` | Six construction/state schematics | Partial | Add parts-on-bench identification plate, launcher-specific electrode cutaway, joint PASS–REJECT evidence, defect atlas, and observational close-ups. Preserve distinct craft-sheet purposes. |
| Claude `build-log` | Opening technical illustration; chronological records | Missing | Add a repeated five-stage status rail, unambiguous NOT STARTED/PASS/HOLD/REMADE marks, cure timeline, and bounded observational sketch fields tied to evidence. |
| Claude craft 01–06 | Multiple local construction schematics | Partial | Audit each against the exact action and checkpoint; prioritize drilled-wall/electrode state, weld witness evidence, cure release, and inspection defect examples. Resolve empty/orphan page flow before adding art. |
| Claude lessons 01–04 | One conceptual plate per lesson | Partial | Concept visuals exist; add only state/checkpoint views required by learner actions. Do not turn conceptual safety material into construction instruction. |
| Claude Rubens-tube demo | Five diagrams | Partial | Retain the safety boundary; use the existing worksheet space only for purposeful setup/evidence/failure views. |

### Potato gap queue

| ID | Priority | Source / delivered area | Required visual or correction | Evidence constraint |
|---|---|---|---|---|
| PL-001 | Critical | Both editions, range safety | Plan view with firing line, people behind breech, muzzle cone, chamber-side exclusion, watcher, controlled access, and positive backstop | Show only sourced site-control geometry; labels remain vector |
| PL-002 | Critical | Field guide and safety | Misfire sequence: hands off, 60-second hold, adult breech-side vent outside muzzle line, disposition | Never show immediate approach, retry, added fuel, or looking into bore |
| PL-003 | Critical | Build documents | Whole-system and parts-identification plates with pressure-boundary locations and hold points | Markings screen material; they do not certify combustion use |
| PL-004 | Blocked—safety | Ignition build | Exact piezo terminal topology, lead routing, insulation, attachment, and strain relief | Current research does not support an exact external wiring design; do not infer one from overview art |
| PL-005 | Critical | Build and craft | Electrode/wall cutaway; penetration before/seal-after; intended vs external/no spark; crack/craze/oversize reject states | Verify dimensions and assembly claims against supported source/label before drawing |
| PL-006 | High | Build and build-log | Stage rail: qualify → prepare → join → cure → inspect/release, with NOT STARTED/PASS/HOLD/REMADE | Blank must never mean pass |
| PL-007 | High | Build and craft | Joint evidence pairs: bottomed/aligned/continuous bead vs backed-out/misaligned/dry gap; cure tag/timeline | Label-controlled process; no universal technique invented |
| PL-008 | High | Build/troubleshooting | Defect atlas: cellular/DWV or unreadable mark, crack/craze/whitening, bulge/deep score, moved witness, rocking cleanout, forbidden patch | Defect images are screening examples, not exhaustive diagnosis |
| PL-009 | High | Science notebook | Replace noun-like still lifes with bounded-mixture, material-inspection, trajectory-uncertainty, and protective-control checkpoint diagrams | Deterministic labels/limits over reviewed graphite |
| PL-010 | High | Site | Accessible figure previews and deep links; responsive figure styling; image-reference validation | Publish optimized reviewed derivatives, never raw multi-megabyte source art |
| PL-011 | High | Generated PDFs | Fix clipped Claude build headings pp. 3–5 and source/footer collisions in build-log p. 6 and projectile-motion p. 2 | Rebuild and inspect every affected page |
| PL-012 | Medium | Craft/page flow | Repair craft 03 sentence split and craft 06 orphan/mostly blank final page; assess purposeful visuals before compression | Intentional workspace must have a visible recording structure |

### Potato completion gate

Potato Launcher is not complete until:

- every row above is resolved, explicitly blocked with a safe dependency, or
  justified not applicable;
- the reader can trace each supported component and conductor without
  guessing;
- every build gate has an observable pass and reject/remake/retire branch;
- deliberately missing evidence and a visible defect both prevent release;
- each affected PDF is rebuilt and inspected page by page in grayscale at
  normal print scale; and
- site previews, captions, links, and narrow-screen rendering pass.

## Electricity & Magnetism — family baseline

Both editions provide many useful schematics, but exact wiring and physical
assembly frequently remain underdrawn. ChatGPT has 64 figure instances across
62 pages; Claude has 78 across 77 pages. Counts include tiny symbols and blank
graphs and therefore do not imply compliance.

| Family | Status | Highest-value next work |
|---|---|---|
| Overview / safety / build | Partial | Add persistent writable progress rails, physical meter/energizing states, simplified exact wiring, and observational winding/lead-routing plates. Fix existing overlapping labels. |
| Charge / fields | Partial | Add learner observation/sketch workspaces and apparatus geometry. Correct Claude field arrows that contradict its N–S magnet and inferred curves. |
| Ohm's law / electromagnet | Partial | Add breadboard/clip-lead mapping, meter jack/probe states, disconnected checkpoints, mechanical before/after views, and fault diagrams. Correct visually open/contradictory circuits. |
| Induction / transformers | Partial | Add start-center-finish and polarity conventions, full meter topology, retained primary drive, tap/coil reconfiguration, and measurement checkpoints. Correct ambiguous series/parallel meter drawings. |
| Capacitors / resonance / coupling | Partial | Add safe source-removal/discharge states, phase/timing/vane states, usable plots, explicit wiring, and physical core/rotation views. Use the currently orphaned coupling pencil asset or exempt/remove it. |
| Spark gap | Partial | Preserve paper-only boundary; clarify conceptual polarity/field/particle keys and ensure questions point to figures that actually contain the requested evidence. |
| Demos | Partial | Add larger observational apparatus plates and operational/fault states; correct Kelvin-dropper caption collisions and ChatGPT speaker voltmeter topology. |

Provider editions remain independently authored. Reuse teaching functions and
structural mechanisms, not another edition's finished art.

The electricity site is also stale: it advertises a spark-gap Tesla-coil
course while the current curriculum specifies a battery-powered coupled-coil
instrument and prohibits sparks and high voltage. Correct that boundary before
adding site previews.

## Lake Country Fishing — family baseline

The project has 69 referenced raster assets with no exact duplicate or orphan.
Rich portrait, cooking, and map art does not compensate for weak procedural
rig, knot, handling, and cooking sequences.

| Family | Status | Highest-value next work |
|---|---|---|
| Rigs, ChatGPT | Missing | Replace the generic straight-line/four-circle pseudo-sequence with 11 rig-specific component, staged assembly, finished-state, behavior, and fault plates. Quick-strike, tip-up, three-way, drop-shot, and Texas first. |
| Rigs, Claude | Partial | Replace the universal “sketch the cast” grid where the method is vertical, suspended, or through ice; add Texas threading, Palomar/tag direction, harness placement, trigger/depth, and O-ring states. |
| Knots | Missing | Add genuine hand/strand sequences, intermediate checkpoints, knot-specific PASS–FAIL finished states, and reproducible pull-test/troubleshooting views. Resolve fixed loop vs line-to-line surgeon's join. |
| Handling and release | Missing | Add staged net/support/unhook/measure/release and failure-correction plates; correct the existing hand-placement ambiguity and orphan page. |
| Cooking | Partial | ChatGPT has strong cleaning/filleting art and final measurement gates but lacks cook-along process states; Claude is predominantly timer/prose. Add setup, heat response, turn/probe, visible doneness, and correction views. |
| First trip / reading water / calendar / lures | Partial | Add field-facing milestone progress, staged/instrument views, and explicit labels/PASS–FAIL overlays. Correct ambiguous bait-water disposal imagery. |
| Lakes / maps | Partial | Core maps and pencil prompts are functional. Reduce repeated generic trees/sketches, add distinct worked examples, and enlarge maps embedded too small in compendia. |

All instructional raster art needs a visible teaching caption and textual
equivalent. A fixed Letter PDF alone is not a mobile-accessible equivalent.
Current fishing PDFs are untagged, essential overlay text reaches 5.5–6 pt in
places, and many raster assets remain color-profiled rather than verified
grayscale; these are delivery defects even when a drawing's content is sound.

## Homelab — active Markdown and HTML baseline

Homelab needs deterministic topology, state, terminal, and UI evidence more
than graphite. Use pencil only for physical device/cable/port orientation when
it teaches an observable action.

| Family | Status | Highest-value next work |
|---|---|---|
| Manuals / runbooks | Missing | Add Windows Setup and disk-layout states, Controller console/reboot states, network rollback topologies, expected command output, and symptom-led stop/correct/rollback branches. |
| Design | Partial | Add canonical network/DHCP authority topology, protocol/trust labels on boot-chain arrows, and provisioning-to-poweroff-to-activation swimlanes. |
| Site workflows | Missing | Reconcile the 12 procedure steps with the durable 14 gates, then render derived Proven/In progress/Pending/Blocked states, evidence links, semantic callouts, and responsive step navigation. |

## Verification backlog

Add a machine-readable inventory and static verifier only after the human
ledger stabilizes. The verifier should enforce stable IDs, applicable jobs or
reasoned N/A, existing source/delivered paths, unique evidence anchors,
referenced/orphaned assets, and source-to-promoted-output freshness. It must
not claim to judge visual adequacy by counting `tikzpicture` or image files.

For every affected publication:

1. build the exact PDF or site page;
2. inspect all affected pages in grayscale at normal delivered scale;
3. confirm caption/figure adjacency, deterministic labels, units, and minimum
   legibility;
4. test likely confusion pairs and failure states;
5. verify no clipped headings, footer collisions, unexplained large voids, or
   stale promoted output; and
6. record the delivered artifact and inspected pages in this ledger.
