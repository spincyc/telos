(() => {
  const DATA_URL = "data/reading-list.json";
  const ROOT = document.querySelector("[data-reading-sections]");
  const STATUS_EL = document.getElementById("reading-status");
  const GROUP_EL = document.getElementById("reading-group");
  const SORT_EL = document.getElementById("reading-sort");
  const DIRECTION_EL = document.getElementById("reading-direction");
  const SEARCH_EL = document.getElementById("reading-search");
  const SUMMARY_EL = document.getElementById("reading-summary");
  const RESET_EL = document.getElementById("reading-reset");

  if (!ROOT || !STATUS_EL || !GROUP_EL || !SORT_EL || !DIRECTION_EL || !SEARCH_EL || !SUMMARY_EL || !RESET_EL) {
    return;
  }

  const statusOrder = {
    pending: 0,
    active: 1,
    complete: 2,
  };
  const statusLabel = {
    pending: "Pending",
    active: "Active",
    complete: "Complete",
  };
  const genreCategoryLabel = {
    fiction: "Fiction",
    "non-fiction": "Non-fiction",
    unclassified: "Unclassified",
    unknown: "Unclassified",
  };
  const statusStyle = {
    pending: "reading-status-pending",
    active: "reading-status-active",
    complete: "reading-status-complete",
  };

  const sortSpecs = {
    title: (entry) => (entry.title || "").toLowerCase(),
    author: (entry) => (entry.author || "").toLowerCase(),
    reader: (entry) => (entry.reader || "").toLowerCase(),
    pages: (entry) => (Number.isFinite(entry.pages) ? entry.pages : null),
    words: (entry) => (Number.isFinite(entry.words) ? entry.words : null),
    days: (entry) => (Number.isFinite(entry.days) ? entry.days : null),
    pages_per_day: (entry) => (Number.isFinite(entry.pages_per_day) ? entry.pages_per_day : null),
    words_per_day: (entry) => (Number.isFinite(entry.words_per_day) ? entry.words_per_day : null),
    genre_category: (entry) => safeText(entry.genre_category || ""),
    genre_coarse: (entry) => safeText(entry.genre_coarse || ""),
    genre_fine: (entry) => safeText(entry.genre_fine || ""),
    started: (entry) => parseDate(entry.started),
    completed: (entry) => parseDate(entry.completed),
  };

  function escapeText(value) {
    return (value || "")
      .replaceAll("&", "&amp;")
      .replaceAll("<", "&lt;")
      .replaceAll(">", "&gt;")
      .replaceAll('"', "&quot;")
      .replaceAll("'", "&#39;");
  }

  function parseDate(value) {
    if (!value) {
      return null;
    }
    const parsed = Date.parse(value);
    return Number.isFinite(parsed) ? parsed : null;
  }

  function compareSortValue(left, right, direction) {
    const leftMissing = left === null || left === undefined;
    const rightMissing = right === null || right === undefined;
    if (leftMissing && rightMissing) {
      return 0;
    }
    if (leftMissing) {
      return 1;
    }
    if (rightMissing) {
      return -1;
    }
    let comparison = 0;
    if (typeof left === "number" && typeof right === "number") {
      comparison = left - right;
    } else {
      comparison = safeText(left).localeCompare(safeText(right), "en", { sensitivity: "base" });
    }
    return comparison * direction;
  }

  function cell(value) {
    if (value === null || value === undefined || value === "") {
      return "—";
    }
    if (typeof value === "number") {
      return Number.isInteger(value) ? String(value) : value.toFixed(2);
    }
    return escapeText(String(value));
  }

  function genreCell(value) {
    if (value === null || value === undefined || value === "") {
      return "—";
    }
    return `<span class="reading-genre-badge">${escapeText(String(value))}</span>`;
  }

  function formatDate(value) {
    return cell(value);
  }

  function safeText(value) {
    return (value || "").toLowerCase();
  }

  function renderEntry(entry) {
    const status = entry.status || "pending";
    return `
      <tr>
        <td><span class="reading-status ${statusStyle[status] || ""}">${statusLabel[status] || status}</span></td>
        <td>${cell(entry.title)}</td>
        <td>${cell(entry.author)}</td>
        <td>${cell(entry.reader)}</td>
        <td>${genreCell(entry.genre_category || "unclassified")}</td>
        <td>${genreCell(entry.genre_coarse || "Unspecified")}</td>
        <td>${genreCell(entry.genre_fine || "Unspecified")}</td>
        <td>${formatDate(entry.started)}</td>
        <td>${formatDate(entry.completed)}</td>
        <td>${cell(entry.pages)}</td>
        <td>${cell(entry.words)}</td>
        <td>${cell(entry.days)}</td>
        <td>${cell(entry.pages_per_day)}</td>
        <td>${cell(entry.words_per_day)}</td>
        <td>${escapeText(entry.notes || "—")}</td>
      </tr>
    `;
  }

  function renderSection(name, rows, index) {
    if (!rows.length) {
      return "";
    }
    const sectionId = `reading-section-${index + 1}`;
    const heading = `${name} (${rows.length})`;
    return `
      <section class="reading-section" aria-labelledby="${sectionId}">
        <h2 id="${sectionId}">${heading}</h2>
        <div class="reading-table-wrap">
        <table class="reading-table">
          <thead>
            <tr>
              <th>Status</th>
              <th>Title</th>
              <th>Author</th>
              <th>Reader</th>
              <th>Category</th>
              <th>Genre</th>
              <th>Fine genre</th>
              <th>Started</th>
              <th>Completed</th>
              <th>Pages</th>
              <th>Words</th>
              <th>Days</th>
              <th>Pages/Day</th>
              <th>Words/Day</th>
              <th>Notes</th>
            </tr>
          </thead>
          <tbody>
            ${rows.map(renderEntry).join("")}
          </tbody>
        </table>
        </div>
      </section>
    `;
  }

  function buildGroups(entries) {
    const mode = GROUP_EL.value;
    if (mode === "none") {
      return [{ name: "All books", rows: entries }];
    }

    const grouped = new Map();
    for (const row of entries) {
      let key = "Unknown";
      if (mode === "status") {
        key = row.status || "pending";
      } else if (mode === "reader") {
        key = row.reader || "Unknown";
      } else if (mode === "genre_category") {
        key = row.genre_category || "unclassified";
      } else if (mode === "genre_coarse") {
        key = row.genre_coarse || "Unclassified";
      } else if (mode === "genre_fine") {
        key = row.genre_fine || "Unspecified";
      }
      const bucket = grouped.get(key);
      if (bucket) {
        bucket.push(row);
      } else {
        grouped.set(key, [row]);
      }
    }

    const order = mode === "status"
      ? ["complete", "active", "pending"]
      : mode === "genre_category"
      ? ["fiction", "non-fiction", "unclassified", "unknown"]
      : [...grouped.keys()].sort((a, b) => a.localeCompare(b));

    return order
      .filter((key) => grouped.has(key))
      .map((key) => ({
        name:
          mode === "status"
            ? statusLabel[key] || key
            : mode === "genre_category"
            ? genreCategoryLabel[key] || key
            : key,
        rows: grouped.get(key),
      }));
  }

  function compareEntries(sortBy, direction, a, b) {
    const extractor = sortSpecs[sortBy] || sortSpecs.title;
    const left = extractor(a);
    const right = extractor(b);
    const comparison = compareSortValue(left, right, direction);
    if (comparison) {
      return comparison;
    }
    const statusCompare = statusOrder[a.status || "pending"] - statusOrder[b.status || "pending"];
    return statusCompare || String(a.title || "").localeCompare(String(b.title || ""));
  }

  function renderSummary(filtered, total = false) {
    const visible = filtered.length;
    const counts = {
      complete: 0,
      active: 0,
      pending: 0,
    };
    const genres = {};
    for (const row of filtered) {
      counts[row.status || "pending"] += 1;
      const category = row.genre_category || "unclassified";
      genres[category] = (genres[category] || 0) + 1;
    }
    const base = total
      ? `Showing ${visible} matching entries`
      : `Showing ${visible} entries`;
    const genreSummary = Object.keys(genres)
      .sort()
      .map((key) => `${genreCategoryLabel[key] || key}: ${genres[key]}`)
      .join(" · ");
    const generatedAt = SUMMARY_EL.dataset.generatedAt || "unknown";
    const generatedText = generatedAt === "unknown"
      ? "updated unknown"
      : `updated ${generatedAt.replace("T", " ").replace("Z", "")}`;
    SUMMARY_EL.textContent = `${base} · Complete: ${counts.complete} · Active: ${counts.active} · Pending: ${counts.pending} · ${genreSummary} · ${generatedText}`;
  }

  function update(payload) {
    const rows = payload.entries || [];
    const query = SEARCH_EL.value.trim().toLowerCase();
    const targetStatus = STATUS_EL.value;

    const filtered = rows.filter((entry) => {
      if (targetStatus !== "all" && (entry.status || "pending") !== targetStatus) {
        return false;
      }
      if (!query) {
        return true;
      }
      return (
        safeText(entry.title).includes(query) ||
        safeText(entry.author).includes(query) ||
        safeText(entry.reader).includes(query) ||
        safeText(entry.id).includes(query) ||
        safeText(entry.notes).includes(query) ||
        safeText(entry.genre_category).includes(query) ||
        safeText(entry.genre_coarse).includes(query) ||
        safeText(entry.genre_fine).includes(query)
      );
    });

    const sortBy = SORT_EL.value;
    const direction = DIRECTION_EL.value === "desc" ? -1 : 1;
    const sorted = [...filtered].sort((a, b) => compareEntries(sortBy, direction, a, b));

    const groups = buildGroups(sorted);
    ROOT.innerHTML = groups.map(renderSection).join("\n");

    if (filtered.length === 0) {
      ROOT.innerHTML = '<p class="reading-empty">No entries match your filter.</p>';
      SUMMARY_EL.textContent = "No matching entries.";
      return;
    }

    renderSummary(filtered);
  }

  function renderLoading() {
    ROOT.innerHTML = '<p class="reading-empty">Loading your reading list…</p>';
    SUMMARY_EL.textContent = "Loading…";
  }

  function renderError(message) {
    ROOT.innerHTML = `<p class="reading-empty">${message}</p>`;
    SUMMARY_EL.textContent = message;
  }

  async function init() {
    renderLoading();
    try {
      const response = await fetch(DATA_URL);
      if (!response.ok) {
        throw new Error(`Failed to load data (${response.status})`);
      }
      const payload = await response.json();
      if (!Array.isArray(payload.entries)) {
        throw new Error("Invalid payload: missing entries array");
      }
      const generatedAt = payload.generated && payload.generated.at ? payload.generated.at : "unknown";
      SUMMARY_EL.dataset.generatedAt = generatedAt;

      const rerender = () => update(payload);
      const resetFilters = () => {
        SEARCH_EL.value = "";
        STATUS_EL.value = "all";
        GROUP_EL.value = "status";
        SORT_EL.value = "title";
        DIRECTION_EL.value = "asc";
        rerender();
      };
      RESET_EL.addEventListener("click", resetFilters);
      [STATUS_EL, GROUP_EL, SORT_EL, DIRECTION_EL].forEach((element) => {
        element.addEventListener("change", rerender);
      });
      SEARCH_EL.addEventListener("input", rerender);
      rerender();
    } catch (error) {
      renderError(String(error.message || error));
    }
  }

  init();
})();
