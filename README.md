# Telos

Home projects, worked out properly and printed on paper.

Each project here produces a set of PDFs that are meant to be printed on an
ordinary black-and-white laser printer and then taken somewhere useful — into a
boat, onto a workbench, into a garage. Nothing depends on colour, nothing
depends on a screen, and a species sheet or a rig sheet is a hard one-page
contract so it fits in a tackle box.

Everything is built from LaTeX source with `make`. The PDFs in `doc/` are
tracked, so what this site publishes is exactly what was reviewed locally.

## Projects

### [Lake Country Fishing](lake-country-fishing.md)

A field guide to **Pine Lake** and **North Lake** in Waukesha County,
Wisconsin — two deep lakes two miles apart that fish nothing alike. Reconstructed
depth maps with numbered spots keyed to a season-by-season table, a one-page
sheet for every species, a one-page sheet for every rig, and reference sheets for
lures, bait, knots and the fishing year.

### [Electricity & Magnetism](electricity.md)

A hands-on course for teenagers that builds, lesson by lesson, to a working
spark-gap Tesla coil. Charge, fields, Ohm's law, electromagnets, induction,
transformers, capacitors, resonance, coupling, and the spark gap itself — each
one built and measured rather than read about, because the machine at the end
does not work unless you understand all of them.

## Building it yourself

```sh
make                     # build every PDF into build/
make list                # list document ids
make doc DOC=<id>        # build one document
make install             # promote reviewed builds into doc/
make site                # render the GitHub Pages artifact into build/site
make site-preview        # render it and serve it on localhost
make help                # everything else
```

On Arch Linux, `make install-dependencies-arch` installs the toolchain;
`make dependencies-arch` prints the package list without touching anything.

## A note on what is and is not authoritative

The fishing guide is a field reference, not a statement of law. Fishing
regulations change every year and only the Wisconsin DNR's current publication
for a specific water body is authoritative — the sheets say so, and they mean
it.

The electricity curriculum describes procedures involving mains-derived high
voltage. Lessons 1 through 9 are battery-powered and safe. From Lesson 10
onward the apparatus can kill an adult, and the course is written on the
assumption that an adult owns the mains side of it. Read the safety sheet before
building, not during.
