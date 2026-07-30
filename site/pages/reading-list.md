# Reading tracker

This page shows only the actual reading list, grouped into three fixed tables:

- **Read** — completed books
- **Active** — books currently in progress
- **Queued** — books waiting to start

Each table uses a default sort order for that section:

- Read: newest completed first
- Active: newest started first
- Queued: by title

Data source: `site/data/reading-list.json` (generated from your ingestion pipeline).

<p id="reading-summary" data-reading-summary aria-live="polite"></p>
<div id="reading-sections" class="reading-sections" data-reading-sections></div>

<script src="assets/reading-list.js" defer></script>
