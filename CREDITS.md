# Credits and sources

Telos incorporates public-domain material. This page records exactly what, from
where, and on what basis — so that the boundary between project-created content
(licensed CC BY 4.0) and incorporated material (not licensed by Telos at all)
is checkable rather than asserted.

## ChatGPT graphite portraits

The ChatGPT fishing edition uses eleven original, AI-assisted graphite
portraits generated with OpenAI image generation on 2026-07-27. They were
prompted and editorially reviewed species by species, converted to grayscale,
and are project-created content under the repository's CC BY 4.0 terms. Prompt
requirements, morphology criteria, processing, and file hashes are recorded in
`research/lake-country-fishing/portrait-provenance.md`.

## Fish plates

Every species plate in the fishing guide is a chromolithograph published in the
annual reports of the **New York Commissioners of Fisheries, Game and Forests**
between roughly 1896 and 1902. All but one are signed by **Sherman Foote Denton**
(1856–1937). All were published well before 1929 and are in the public domain in
the United States; Telos claims no rights in them.

Each was retrieved from Wikimedia Commons, converted to grayscale, cropped to
remove the engraved caption strip, and level-adjusted for laser printing. No
other alteration was made. The processing recipe is in
`src/lake-country-fishing/claude/shared/plates/` history.

| Sheet | Plate | Wikimedia Commons file |
|---|---|---|
| Largemouth Bass | The Large-Mouthed Black Bass | `Denton Largemouth Bass 1896.png` |
| Smallmouth Bass | The Small-Mouthed Black Bass | `Denton Smallmouth Bass 1896.png` |
| Walleye | The Pike Perch or Wall-Eyed Pike | `Denton Walleye 1896.png` |
| Northern Pike | The Pike | `Denton Pike 1896.png` |
| Muskellunge | The Mascalonge | `Denton Muskellunge 1896.png` |
| Yellow Perch | Yellow or Barred Perch | `Vintage illustrations by Denton from Game Birds and Fishes of North America digitally enhanced by rawpixel 06.jpg` |
| Bluegill | Blue Gill Sun Fish | `FMIB 41913 Blue Gill - Sun Fish (Lepomis pallidus).jpeg` |
| Black Crappie | Calico Bass; Strawberry Bass | `FMIB 41954 Calico Bass; Strawberry Bass (Pomoxys sparoides (Lac)).jpeg` |
| Rock Bass | Rock Bass | `FMIB 41915 Rock Bass (Ambloplites rupestrisi).jpeg` |
| Pumpkinseed | Sunfish (Eupomotis gibbosus) | `FMIB 43190 Sunfish (Eupomotis gibbosus).jpeg` |
| Cisco | Cisco from Hemlock Lake | `FMIB 43092 Cisco from Hemlock Lake (Argyrosomus artedi Le Sueur).jpeg` |

The plates prefixed `FMIB` were scanned by the **Freshwater and Marine Image
Bank**, University of Washington Libraries. The cisco plate carries no visible
signature and is credited to that collection rather than to Denton.

### A note on identification

Two Wikimedia files titled as walleye illustrations are in fact categorised as
*Sander canadensis* — sauger, a different species. Neither is used here. The
walleye plate is Denton's, captioned by him as the pike perch, and is
*Sander vitreus*.

## Lake bathymetry

The depth maps are **not reproductions**. They are redrawn from the soundings
and contours published on the Wisconsin DNR's historical lake survey sheets,
which state on their face: *"A Public Document — Please Identify the Source when
using it."* The source is identified on each map and here.

| Lake | Survey | WBIC |
|---|---|---|
| Pine Lake | Wisconsin Conservation Department lake survey, 6 June 1955 | 779200 |
| North Lake | Wisconsin Conservation Department lake survey sheet, data 1898, revised 21 October 1941 | 850800 |

The shoreline was traced from those sheets and the soundings read off them; the
contours were then reconstructed by interpolating a depth surface through those
soundings (`scripts/lake-map`). The result is **generalized and not for
navigation**. The North Lake survey in particular is very old and will not match
a modern sonar log in detail.

## Lake facts and regulations

Surface area, maximum and mean depth, bottom composition, clarity, species
lists, stocking notes, access, and every season, bag and length limit quoted in
the fishing guide come from the **Wisconsin Department of Natural Resources**:
its lake pages (`apps.dnr.wi.gov/lakes`) and its per-water regulation pages
(`apps.dnr.wi.gov/fisheriesmanagement`), read in July 2026 for the 2026–27
regulation year. Launch hours and fees come from the Village of Chenequa.

**Regulations change every year.** Only the DNR's current publication for a
specific water body is authoritative, and every sheet that quotes a limit says
so.

## AI-provider editions

The original fishing, electricity, and potato-launcher publications are
identified as the **Claude editions**. Their source and PDF paths now carry that
provider identity explicitly.

The **ChatGPT editions** are independent publications researched and written
for this repository in July 2026. They share no publication prose with the
Claude editions. Their authoritative witnesses, atomic reusable claims, and
editorial selections are recorded under `research/<project>/`; the source
registers there provide direct links, retrieval dates, scope, and caveats.

AI assistance does not transfer authority from an issuing agency to Telos.
Current law, regulation, safety requirements, and local conditions must still
be checked with the cited primary authority.

## Tooling

`tools/worktree-marshal/` is a vendored copy of a separate MIT-licensed project
and carries its own `LICENSE`. The Makefile, `scripts/`, `release/site/` and
`src/common/preamble.tex` derive from the build tooling of the author's
[Triptych](https://github.com/spincyc/triptych) project.

## Everything else

All text, tables, diagrams, curricula, maps and page designs in this repository
were created for it and are licensed [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/).
See `LICENSE`.
