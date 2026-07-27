# Telos instructional publication contract

This contract applies to every publication below `src/`. A provider- or
project-specific `AGENTS.md` may narrow it for safety, audience, evidence, or
editorial independence, but may not weaken the teaching and verification
requirements here.

## Teach through verification

Telos publications must teach the reader how to establish that each important
step, observation, inference, and finished result is sound. A direction such
as “assemble,” “measure,” “configure,” “cook,” or “inspect” is incomplete
unless the reader can tell what to observe, what to record, what acceptable
evidence looks like, and what to do when the evidence disagrees.

Every instructional sequence should include, where applicable:

1. the question or prediction being tested;
2. prerequisites, roles, hazards, tools, and units;
3. a de-energized, cold, dry, or otherwise safe setup check;
4. small numbered steps with an illustration at each meaningful state change;
5. intermediate questions before the answer is revealed;
6. direct observations and repeated measurements recorded in a table;
7. a worked example that keeps units visible;
8. controlled comparisons that change one important variable at a time;
9. uncertainty, limitations, and plausible alternative explanations;
10. symptom-to-cause troubleshooting with a safe next check;
11. an explicit stop, reject, remake, or escalate condition; and
12. a final acceptance proof stated as claim, evidence, and reasoning.

Conceptual and read-only material uses the same standard. It should provide
multiple representations, data or evidence to interpret, intermediate
questions, worked reasoning, boundary cases, and a prompt asking what result
would weaken or falsify the explanation. It must not invent a hands-on
procedure where the project safety contract forbids one.

## Illustration density and purpose

- Use ample original monochrome illustrations. One decorative overview image
  is not sufficient for a multi-stage process.
- Draw the before state, connection or action, expected evidence, measurement
  point, and important failure state when those differ materially.
- Keep labels, units, dimensions, arrows, and acceptance marks in TeX or
  another deterministic source format whenever practical.
- Pencil and graphite plates should remain high fidelity at ordinary grayscale
  print scale. Controlled schematics, maps, graphs, and overlays remain crisp
  vectors where precision matters more than texture.
- Every figure needs a teaching job: orient, predict, perform, compare,
  diagnose, or verify. Do not add decorative filler.

## Questions and records

- Ask questions throughout the sequence, not only at the beginning or end.
- Leave usable space for predictions, measurements, calculations, sketches,
  fault notes, and the final evidence claim.
- Prefer several short checks tied to the current figure or step over a single
  broad reflection prompt.
- State the expected pattern separately from fabricated sample data. Never
  imply that a reader obtained a measurement they did not take.

## Page flow and useful space

- Lay out each publication as a continuous professional book, not a stack of
  independently filled cards. Avoid orphan lines, stranded captions, nearly
  empty end pages, accidental blanks, and abrupt page breaks that leave a
  large white-only void.
- Treat an unexplained white void as a content warning as well as a layout
  defect. Before tightening spacing, ask whether the reader is missing an
  intermediate state, illustration, question, worked example, measurement
  record, diagnostic branch, or synthesis step.
- Do not manufacture density with decorative filler, oversized headings, or
  repeated prose. Add material only when it advances orientation, prediction,
  performance, comparison, diagnosis, or verification.
- Intentional working space must state its purpose at the point of use and be
  visibly usable: provide ruled lines, a grid, table cells, a sketch frame, or
  another clear recording structure. A heading above an otherwise blank half
  page is not a worksheet.
- As a review trigger, investigate any unlabeled white-only region approaching
  one third of the live page. Also inspect the preceding and following pages:
  a void often indicates a misplaced forced break or content that belongs in
  the surrounding sequence.
- Balance facing and consecutive pages when practical. Keep a figure with its
  setup, question, caption, and immediate interpretation; keep a table with
  the directions and acceptance criteria needed to complete it.

## Completeness and review

Page count is subordinate to clarity. Do not compress a real investigation or
procedure into a one-page card when the steps, figures, questions, and records
need more room.

Before publication:

- build every affected PDF;
- inspect every affected page in grayscale at normal print scale;
- check figure order, captions, labels, units, writing space, page breaks,
  orphaned fragments, and unexplained white-only regions;
- keep every tracked publication below 50,000,000 bytes. Composite binders
  must use a reproducible grayscale/downsampling stage rather than embedding
  every source raster at capture resolution. Never rely on Git LFS for
  published PDFs: the repository and Pages artifact must remain directly
  usable after an ordinary clone;
- confirm that safety and evidence boundaries survived the expansion;
- run repository validation; and
- promote the reviewed PDF together with its source.
