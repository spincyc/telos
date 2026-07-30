(() => {
  const DATA_URL = "data/reading-list.json";
  const ROOT = document.querySelector("[data-reading-sections]");
  const SUMMARY_EL = document.getElementById("reading-summary");

  if (!ROOT || !SUMMARY_EL) {
    return;
  }

  const statusLabel = {
    pending: "Queued",
    active: "Active",
    complete: "Read",
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

  const SORT_LABELS = {
    title: "Title",
    author: "Author",
    reader: "Reader",
    pages: "Pages",
    words: "Words",
    days: "Days",
    pages_per_day: "Pages / Day",
    words_per_day: "Words / Day",
    genre_category: "Category",
    genre_coarse: "Genre",
    genre_fine: "Fine genre",
    started: "Started",
    completed: "Completed",
  };

  const SORT_SPECS = {
    title: (entry) => safeText(entry.title),
    author: (entry) => safeText(entry.author),
    reader: (entry) => safeText(entry.reader),
    pages: (entry) => asNumber(entry.pages),
    words: (entry) => asNumber(entry.words),
    days: (entry) => asNumber(entry.days),
    pages_per_day: (entry) => asNumber(entry.pages_per_day),
    words_per_day: (entry) => asNumber(entry.words_per_day),
    genre_category: (entry) => safeText(entry.genre_category),
    genre_coarse: (entry) => safeText(entry.genre_coarse),
    genre_fine: (entry) => safeText(entry.genre_fine),
    started: (entry) => parseDate(entry.started),
    completed: (entry) => parseDate(entry.completed),
  };

  const TABLES = [
    {
      title: "Read",
      status: "complete",
      sort: { key: "completed", direction: -1 },
      columns: [
        { key: "title", label: "Title" },
        { key: "author", label: "Author" },
        { key: "reader", label: "Reader" },
        { key: "genre_category", label: "Category", badge: true },
        { key: "genre_coarse", label: "Genre", badge: true },
        { key: "genre_fine", label: "Fine genre", badge: true },
        { key: "started", label: "Started" },
        { key: "completed", label: "Completed" },
        { key: "days", label: "Days" },
        { key: "pages", label: "Pages" },
        { key: "words", label: "Words" },
        { key: "pages_per_day", label: "Pages / Day" },
        { key: "words_per_day", label: "Words / Day" },
        { key: "notes", label: "Notes" },
      ],
    },
    {
      title: "Active",
      status: "active",
      sort: { key: "started", direction: -1 },
      columns: [
        { key: "title", label: "Title" },
        { key: "author", label: "Author" },
        { key: "reader", label: "Reader" },
        { key: "genre_category", label: "Category", badge: true },
        { key: "genre_coarse", label: "Genre", badge: true },
        { key: "genre_fine", label: "Fine genre", badge: true },
        { key: "started", label: "Started" },
        { key: "days", label: "Days" },
        { key: "pages", label: "Pages" },
        { key: "words", label: "Words" },
        { key: "pages_per_day", label: "Pages / Day" },
        { key: "words_per_day", label: "Words / Day" },
        { key: "notes", label: "Notes" },
      ],
    },
    {
      title: "Queued",
      status: "pending",
      sort: { key: "title", direction: 1 },
      columns: [
        { key: "title", label: "Title" },
        { key: "author", label: "Author" },
        { key: "reader", label: "Reader" },
        { key: "genre_category", label: "Category", badge: true },
        { key: "genre_coarse", label: "Genre", badge: true },
        { key: "genre_fine", label: "Fine genre", badge: true },
        { key: "pages", label: "Pages" },
        { key: "words", label: "Words" },
        { key: "notes", label: "Notes" },
      ],
    },
  ];

  function escapeText(value) {
    return (value || "")
      .replaceAll("&", "&amp;")
      .replaceAll("<", "&lt;")
      .replaceAll(">", "&gt;")
      .replaceAll('"', "&quot;")
      .replaceAll("'", "&#39;");
  }

  function safeText(value) {
    return (value || "").toLowerCase();
  }

  function parseDate(value) {
    if (!value) {
      return null;
    }
    const parsed = Date.parse(value);
    return Number.isFinite(parsed) ? parsed : null;
  }

  function asNumber(value) {
    if (typeof value === "number") {
      return Number.isFinite(value) ? value : null;
    }
    if (typeof value !== "string") {
      return null;
    }
    const parsed = Number(value.trim().replace(/,/g, ""));
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
    if (typeof left === "number" && typeof right === "number") {
      return (left - right) * direction;
    }
    return safeText(left).localeCompare(safeText(right), "en", { sensitivity: "base" }) * direction;
  }

  function compareEntries(sortBy, direction, left, right) {
    const extractor = SORT_SPECS[sortBy] || SORT_SPECS.title;
    const first = extractor(left);
    const second = extractor(right);
    const base = compareSortValue(first, second, direction);
    if (base !== 0) {
      return base;
    }
    return safeText(left.title).localeCompare(safeText(right.title), "en", { sensitivity: "base" });
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
    return `<span class=\"reading-genre-badge\">${escapeText(String(value))}</span>`;
  }

  function formatDate(value) {
    return cell(value);
  }

  function renderCell(entry, column) {
    const value = entry[column.key];
    if (column.badge) {
      return genreCell(value);
    }
    if (column.key === "started" || column.key === "completed") {
      return formatDate(value);
    }
    if (column.key === "status") {
      return `<span class=\"reading-status ${statusStyle[entry.status || "pending"] || ""}\">` +
        `${escapeText(statusLabel[entry.status || "pending"] || "Queued")}</span>`;
    }
    return cell(value);
  }

  function renderEntry(entry, columns) {
    return `<tr>${columns.map((column) => `<td>${renderCell(entry, column)}</td>`).join("")}</tr>`;
  }

  function renderSection(config, rows) {
    const index = TABLES.indexOf(config);
    const sectionId = `reading-section-${index + 1}`;
    const heading = `${config.title} (${rows.length})`;
    const caption = `Sorted by ${SORT_LABELS[config.sort.key] || "Title"}`;
    const headers = config.columns
      .map((column) => {
        if (!SORT_SPECS[column.key]) {
          return `<th>${escapeText(column.label)}</th>`;
        }
        const active = config.sort.key === column.key;
        const direction = active ? config.sort.direction : 0;
        const orderClass = active ? (direction === -1 ? "desc" : "asc") : "neutral";
        const arrow = active ? (direction === 1 ? " ↑" : " ↓") : "";
        return `<th><button type=\"button\" class=\"reading-sort-control reading-sort-${orderClass}\" data-reading-section=\"${TABLES.indexOf(config)}\" data-reading-key=\"${escapeText(column.key)}\">${escapeText(column.label)}${arrow}</button></th>`;
      })
      .join("");
    const body = rows.map((entry) => renderEntry(entry, config.columns)).join("");
    if (rows.length === 0) {
      return `
        <section class=\"reading-section\" aria-labelledby=\"${sectionId}\">
          <h2 id=\"${sectionId}\">${heading}</h2>
          <p class=\"reading-empty\">No entries yet.</p>
        </section>
      `;
    }
    return `
      <section class=\"reading-section\" aria-labelledby=\"${sectionId}\">
        <h2 id=\"${sectionId}\">${heading}
          <span class=\"reading-sort-note\">${escapeText(caption)}</span>
        </h2>
        <div class=\"reading-table-wrap\">
          <table class=\"reading-table\">
            <thead>
              <tr>${headers}</tr>
            </thead>
            <tbody>${body}</tbody>
          </table>
        </div>
      </section>
    `;
  }

  function statusClass(status) {
    return statusStyle[status || "pending"] || "";
  }

  function countStatus(rows, status) {
    return rows.filter((row) => (row.status || "pending") === status).length;
  }

  function renderSummary(rows) {
    const counts = {
      complete: countStatus(rows, "complete"),
      active: countStatus(rows, "active"),
      pending: countStatus(rows, "pending"),
    };
    const genres = {};
    for (const row of rows) {
      const category = row.genre_category || "unclassified";
      genres[category] = (genres[category] || 0) + 1;
    }
    const genreSummary = Object.keys(genres)
      .sort()
      .map((key) => `${genreCategoryLabel[key] || key}: ${genres[key]}`)
      .join(" · ");
    SUMMARY_EL.textContent = `${rows.length} total · Read: ${counts.complete} · Active: ${counts.active} · Queued: ${counts.pending} · ${genreSummary}`;
  }

  function renderRows(rows) {
    const sections = TABLES.map((config) => {
      const bucket = rows.filter((row) => (row.status || "pending") === config.status);
      const sorted = [...bucket].sort((left, right) => {
        const result = compareEntries(config.sort.key, config.sort.direction, left, right);
        if (result === 0) {
          return statusClass(left.status).localeCompare(statusClass(right.status));
        }
        return result;
      });
      return renderSection(config, sorted);
    });
    ROOT.innerHTML = sections.join("\n");
    ROOT.querySelectorAll("[data-reading-key]").forEach((button) => {
      button.addEventListener("click", () => {
        const sectionIndex = Number(button.dataset.readingSection);
        const sortBy = button.dataset.readingKey;
        const config = TABLES[sectionIndex];
        if (!config) {
          return;
        }
        if (!SORT_SPECS[sortBy]) {
          return;
        }
        if (config.sort.key === sortBy) {
          config.sort.direction *= -1;
        } else {
          config.sort.key = sortBy;
          config.sort.direction = 1;
        }
        renderRows(rows);
      });
    });
    renderSummary(rows);
  }

  function renderLoading() {
    ROOT.innerHTML = '<p class=\"reading-empty\">Loading your reading list…</p>';
    SUMMARY_EL.textContent = "Loading…";
  }

  function renderError(message) {
    ROOT.innerHTML = `<p class=\"reading-empty\">${escapeText(String(message))}</p>`;
    SUMMARY_EL.textContent = String(message);
  }

  async function init() {
    renderLoading();
    try {
      const response = await fetch(DATA_URL);
      if (!response.ok) {
        throw new Error(`Failed to load data (${response.status})`);
      }
      const payload = await response.json();
      const rows = Array.isArray(payload.entries) ? payload.entries : null;
      if (!rows) {
        throw new Error("Invalid payload: missing entries array");
      }
      renderRows(rows);
    } catch (error) {
      renderError(error.message || String(error));
    }
  }

  init();
})();
