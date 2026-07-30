# Reading tracker

This page is driven by `site/data/reading-list.json`. Every state change is done
through deterministic tooling so humans and AI assistants use the same commands.
The tracker can now also classify every book with fiction/non-fiction plus coarse
and fine genre labels from `site/data/reading-genres.yaml`.

For AI or automation, call these commands first (no file editing required):

```sh
# Add a future book (required: title + author, optional: reader + notes + pages + words).
python3 scripts/reading-list.py --yaml site/data/reading-list.yaml --json site/data/reading-list.json \
  enqueue --title "Book title" --author "Book author"

# Add a future book and word count only when known.
python3 scripts/reading-list.py --yaml site/data/reading-list.yaml --json site/data/reading-list.json \
  enqueue --title "Book title" --author "Book author" --words 120000

# Start reading by title/author (use --id when available).
python3 scripts/reading-list.py --yaml site/data/reading-list.yaml --json site/data/reading-list.json \
  start --id "<entry-id>" --date 2026-07-30
# or:
python3 scripts/reading-list.py --yaml site/data/reading-list.yaml --json site/data/reading-list.json \
  start --title "Book title" --author "Book author" --date 2026-07-30

# Finish reading.
python3 scripts/reading-list.py --yaml site/data/reading-list.yaml --json site/data/reading-list.json \
  finish --id "<entry-id>" --date 2026-07-30

# Update counts.
python3 scripts/reading-list.py --yaml site/data/reading-list.yaml --json site/data/reading-list.json \
  update-pages --id "<entry-id>" --pages 432
python3 scripts/reading-list.py --yaml site/data/reading-list.yaml --json site/data/reading-list.json \
  update-words --id "<entry-id>" --words 120000

# Recompute fiction/non-fiction + coarse/fine genre labels for all entries.
python3 scripts/reading-list.py --yaml site/data/reading-list.yaml --json site/data/reading-list.json \
  scan --genres site/data/reading-genres.yaml

# Find IDs (title/author lookup is ambiguous-safe and will suggest IDs).
python3 scripts/reading-list.py --json site/data/reading-list.json \
  list --status pending --query "Book title"
```

`list` supports sort/filter/grouping in-page and is for viewing only.

Use the controls below to search, sort, and group by status, reader, genre category,
genre coarse label, or genre fine label.

<div class="reading-toolbar" data-reading-toolbar>
  <label class="reading-control">
    Search
    <input id="reading-search" type="search" placeholder="Title, author, note, reader, category, or genre">
  </label>
  <label class="reading-control">
    Status
    <select id="reading-status">
      <option value="all">All</option>
      <option value="complete">Complete</option>
      <option value="active">Active</option>
      <option value="pending">Pending</option>
    </select>
  </label>
  <label class="reading-control">
    Group by
    <select id="reading-group">
      <option value="status">Status</option>
      <option value="reader">Reader</option>
      <option value="genre_category">Fiction / Non-fiction</option>
      <option value="genre_coarse">Genre (coarse)</option>
      <option value="genre_fine">Genre (fine)</option>
      <option value="none">None</option>
    </select>
  </label>
  <label class="reading-control">
    Sort by
    <select id="reading-sort">
      <option value="title">Title</option>
      <option value="author">Author</option>
      <option value="reader">Reader</option>
      <option value="started">Started</option>
      <option value="completed">Completed</option>
      <option value="pages">Pages</option>
      <option value="words">Words</option>
      <option value="days">Days to read</option>
      <option value="genre_category">Genre category</option>
      <option value="genre_coarse">Genre (coarse)</option>
      <option value="genre_fine">Genre (fine)</option>
      <option value="pages_per_day">Pages / Day</option>
      <option value="words_per_day">Words / Day</option>
    </select>
  </label>
  <label class="reading-control">
    Direction
    <select id="reading-direction">
      <option value="asc">Ascending</option>
      <option value="desc">Descending</option>
    </select>
  </label>
  <button id="reading-reset" class="reading-reset" type="button">Reset filters</button>
</div>

<p id="reading-summary" data-reading-summary aria-live="polite"></p>
<div id="reading-sections" class="reading-sections" data-reading-sections></div>

<script src="assets/reading-list.js" defer></script>
