# Telos

**Useful work, independently made, built to leave the screen.**

Telos is a growing library of home projects worked out deeply enough to print,
carry, teach, and build from. Each AI provider publishes a distinct edition:
they share a research library, but choose their own evidence, structure, and
voice. Agreement is useful. Difference is useful too.

<div class="project-tools">
  <label>
    <span class="eyebrow">Find a project</span>
    <input type="search" placeholder="Try fishing, physics, workshop…" aria-label="Search projects" data-project-search>
  </label>
  <div class="filter-row" aria-label="Filter projects">
    <button type="button" data-project-filter="all" aria-pressed="true">All</button>
    <button type="button" data-project-filter="field">Field</button>
    <button type="button" data-project-filter="science">Science</button>
    <button type="button" data-project-filter="build">Build</button>
    <button type="button" data-project-filter="systems">Systems</button>
  </div>
</div>

<p class="project-status" data-project-status aria-live="polite">4 projects</p>

<div class="project-grid">
  <section class="project-card" data-project-card data-tags="field">
    <span class="eyebrow">Field · 2 editions</span>
    <h2><a href="projects/lake-country-fishing/index.md">Lake Country Fishing</a></h2>
    <p>Lake-specific field guides, fish, rigs, seasons, handling, and cooking for Pine and North Lakes in Waukesha County.</p>
    <p><a href="projects/lake-country-fishing/index.md">Choose an edition →</a></p>
  </section>
  <section class="project-card" data-project-card data-tags="science build">
    <span class="eyebrow">Science · 2 editions</span>
    <h2><a href="projects/electricity/index.md">Electricity &amp; Magnetism</a></h2>
    <p>Hands-on physics that starts with batteries and draws a hard adult-only boundary before dangerous voltage.</p>
    <p><a href="projects/electricity/index.md">Choose an edition →</a></p>
  </section>
  <section class="project-card" data-project-card data-tags="science build">
    <span class="eyebrow">Workshop · 2 editions</span>
    <h2><a href="projects/potato-launcher/index.md">Potato Launcher</a></h2>
    <p>Combustion, projectile motion, careful fabrication, and a safety-first supervised build.</p>
    <p><a href="projects/potato-launcher/index.md">Choose an edition →</a></p>
  </section>
  <section class="project-card" data-project-card data-tags="systems">
    <span class="eyebrow">Systems · provider-neutral</span>
    <h2><a href="projects/homelab/index.md">Homelab</a></h2>
    <p>A reproducible network-provisioning system with guarded installation, a Controller, and continuous convergence.</p>
    <p><a href="projects/homelab/index.md">Open project →</a></p>
  </section>
</div>

## One body of research, independent editions

Research is stored separately from publication prose. Each source is recorded
once; reusable claims keep their scope and caveats; every provider edition
declares which claims it selected and why. An edition can add evidence without
forcing another edition to adopt its conclusions.

The existing publications are the **Claude editions**. The new **ChatGPT
editions** are independently organized and written from the shared evidence,
not rewrites of Claude prose.

## Built for paper

Every publication is generated from source with `make` and reviewed as a PDF.
The website is a directory, not the product: the useful thing is the sheet in a
tackle box, the lesson on a workbench, or the checklist beside the tool.
Tracked PDFs stay below GitHub's 50 MB threshold. Large composite binders are
reproducibly reduced to print-resolution grayscale during the build instead of
requiring Git LFS or a separate download path.

Telos teaches through verification. A project does not merely tell the reader
what to do: it shows meaningful intermediate states, asks questions before
revealing the explanation, provides places to record measurements, and pairs
each important action with observable acceptance evidence. Troubleshooting,
stop conditions, and the final claim-evidence-reasoning proof are part of the
instruction rather than afterthoughts. Page count yields to clarity.

See [Projects](projects.md) for the full directory and [About](about.md) for the
research and edition model.
