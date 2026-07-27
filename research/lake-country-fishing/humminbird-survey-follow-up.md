# Humminbird bathymetry follow-up

Status: waiting for the exact control-head and transducer models.

## Goal

Use owner-collected GPS/depth evidence to refine Pine Lake and North Lake
bathymetry without treating an interpolated contour as a direct sounding.
Preserve the historical survey as a separately identified source layer.

## Preferred handoff

Provide one ZIP per lake. Copy the original memory-card contents without
renaming files or flattening directories. Include, when the unit supports
them:

1. AutoChart Live or AutoChart PC survey records;
2. raw sonar recordings;
3. exported GPX tracks, routes, and relevant waypoints;
4. a CSV containing latitude, longitude, and depth if the desktop workflow can
   export one; and
5. the survey note described below.

Screenshots are useful for orientation but are not a substitute for
georeferenced depth records.

Before sharing, remove unrelated home, travel, and private-property waypoints.
Keep an untouched private backup of the card.

## Survey note

Record:

- Humminbird control-head model and software version;
- transducer model, mounting location, and measured distance below the water
  surface;
- external or internal GPS source and any known antenna-to-transducer offset;
- displayed depth reference: surface, transducer, or keel;
- units, time zone, and datum when shown;
- lake, dates, start/end times, approximate water level, wind, wave height,
  boat load, and average survey speed;
- whether AutoChart vegetation, bottom hardness, Side Imaging, or only depth
  was recorded; and
- intervals affected by weeds, loss of bottom lock, planing, sharp turns,
  aeration, or manual depth correction.

## Collection pattern

1. Confirm lawful access, weather, fuel or battery reserve, PFDs, and safe
   operating depth.
2. Start GPS, sonar, and mapping records before entering the first survey
   line. Record the displayed time.
3. Run slow, parallel lines at a steady displacement speed. Space lines more
   closely where the bottom changes quickly and more widely over a uniform
   basin.
4. Run a second family of lines approximately perpendicular to the first.
   Crossings provide checks for GPS offset, water-level correction, latency,
   vegetation, and inconsistent bottom lock.
5. Add short confirmation loops around humps, saddles, points, holes, channel
   edges, and any contour that changes unexpectedly.
6. Do not survey water that is unsafe for the craft or transducer. Mark the
   unsurveyed boundary instead of extrapolating from a dangerous pass.
7. Stop the recordings after the final line. Note any clock, depth-reference,
   transducer, or water-level change made during the session.

## Acceptance checks

Before contouring:

- plot the raw tracks and reject impossible jumps;
- compare depths where tracks cross;
- separate vegetation top from bottom return;
- correct all sessions to one documented water-surface reference;
- retain original points and a rejection/reason column;
- show sounding density and unsurveyed regions;
- label interpolation method and contour interval; and
- compare the refined surface with the historical survey without silently
  forcing agreement.

The finished field map will keep observed soundings, inferred contours,
historical contours, shoreline imagery date, and uncertainty visually
distinct.

## Model-specific follow-up

Once the owner supplies the exact model, add:

- the precise recording menu path;
- supported card type and directory names;
- which raw/AutoChart files to retain;
- GPX export steps;
- software/firmware compatibility notes; and
- a short card-copy checklist tailored to that unit.

Official starting points:

- Humminbird AutoChart:
  <https://humminbird.johnsonoutdoors.com/us/learn/mapping/autochart>
- Humminbird AutoChart getting-started guide:
  <https://humminbird.johnsonoutdoors.com/sites/johnsonoutdoors-store/files/assets/misc/HU/H/HUM_productmanual_REF_AC_QSG_532260E/HUM_productmanual_REF_AC_QSG_532260E.pdf>
