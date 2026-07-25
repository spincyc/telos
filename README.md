# Telos

**Home projects, worked out properly and printed on paper.**

Each project here produces documents meant to be printed on an ordinary
black-and-white laser printer and then taken somewhere useful — into a boat,
onto a workbench, into a garage. Nothing depends on colour and nothing depends
on a screen. Where a sheet is called a one-pager, that is a hard contract: it
fits on one side of US Letter so it can live in a tackle box.

Everything is built from LaTeX source with `make`. The PDFs are tracked in the
repository, so what this site publishes is exactly what was reviewed locally.

## Projects

| Project | What it is | Sheets |
|---|---|---|
| **[Lake Country Fishing](lake-country-fishing.md)** | A field guide to Pine Lake and North Lake, Waukesha County, Wisconsin. Reconstructed depth maps with numbered spots keyed to a season-by-season table, a two-page sheet for every species (field card, then biology), a one-page sheet for every rig, a cooking and filleting sheet per species, and reference sheets for lures, bait, knots and the fishing year. | 44 |
| **[Potato Launcher](potato-launcher.md)** | A combustion-driven PVC launcher fired on open ground, with four lessons that make it a physics project rather than a stunt: air pressure, the fuel-air ratio, the gas law, and projectile motion. | 7 |
| **[Electricity & Magnetism](electricity.md)** | A hands-on course for teenagers that builds, lesson by lesson, to a working spark-gap Tesla coil. Charge, fields, Ohm's law, electromagnets, induction, transformers, capacitors, resonance, coupling, and the spark gap itself. | 18 |

## Start here

| If you want to | Take |
|---|---|
| One document with everything for a lake | [Pine Lake, complete](doc/lake-country-fishing/compendium/pine-lake.pdf) or [North Lake, complete](doc/lake-country-fishing/compendium/north-lake.pdf) |
| Just the lake and its depth map | [Pine Lake](doc/lake-country-fishing/lakes/pine-lake.pdf) · [North Lake](doc/lake-country-fishing/lakes/north-lake.pdf) |
| To identify a fish | [Species sheets](lake-country-fishing.md#species) |
| To tie a rig | [Rig sheets](lake-country-fishing.md#rigs) |
| To teach some physics | [Course map](doc/electricity/overview.pdf) |
| To build a Tesla coil safely | [Safety](doc/electricity/safety.pdf) — read this first |
| To launch a potato safely | [Safety](doc/potato-launcher/safety.pdf) — read this first |

## How it is built

| Command | What it does |
|---|---|
| `make` | Build every PDF into `build/` |
| `make list` | List document ids |
| `make doc DOC=<id>` | Build one document |
| `make install` | Promote reviewed builds into `doc/` |
| `make site` | Render the GitHub Pages artifact into `build/site` |
| `make site-preview` | Render it and serve it on localhost |
| `make check` | Validate the site manifest against the tree |
| `make help` | Everything else |

On Arch Linux, `make install-dependencies-arch` installs the toolchain and
`make dependencies-arch` prints the package list without touching anything.

## What is and is not authoritative

The fishing guide is a field reference, not a statement of law. Fishing
regulations change every year, and only the Wisconsin DNR's current publication
for a specific water body is authoritative. The depth maps are redrawn from
historical DNR survey sheets: they are generalized and **not for navigation**.

The electricity curriculum describes procedures involving mains-derived high
voltage. Lessons 1 through 9 are battery-powered and safe. From Lesson 10 the
apparatus can kill an adult, and the course is written on the assumption that
an adult owns the mains side of it permanently. Read the safety sheet before
building, not during.

Sources, plate provenance and licensing are set out in [Credits](credits.html)
and [Licensing](license.html).
