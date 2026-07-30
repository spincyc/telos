(() => {
  const DATA_URL = "data/reading-list.json";
  const ROOT = document.querySelector("[data-reading-sections]");
  const VERSION_EL = document.querySelector("[data-reading-version]");
  const BUILD_VERSION = "reading-list@2026-07-30-simple-layout-1";
  const TABLE_LAYOUTS = [
    {
      status: "complete",
      title: "Read",
      columns: [
        { key: "title", label: "Title" },
        { key: "author", label: "Author" },
        { key: "genre_category", label: "Category" },
        { key: "genre_coarse", label: "Genre" },
        { key: "genre_fine", label: "Fine Genre" },
        { key: "started", label: "Started" },
        { key: "completed", label: "Completed" },
        { key: "days", label: "Days" },
        { key: "pages", label: "Pages" },
        { key: "words", label: "Words" },
      ],
    },
    {
      status: "active",
      title: "Active",
      columns: [
        { key: "title", label: "Title" },
        { key: "author", label: "Author" },
        { key: "genre_category", label: "Category" },
        { key: "genre_coarse", label: "Genre" },
        { key: "genre_fine", label: "Fine Genre" },
        { key: "started", label: "Started" },
        { key: "days", label: "Days" },
        { key: "pages", label: "Pages" },
        { key: "words", label: "Words" },
      ],
    },
    {
      status: "pending",
      title: "Queued",
      columns: [
        { key: "title", label: "Title" },
        { key: "author", label: "Author" },
        { key: "genre_category", label: "Category" },
        { key: "genre_coarse", label: "Genre" },
        { key: "genre_fine", label: "Fine Genre" },
        { key: "pages", label: "Pages" },
        { key: "words", label: "Words" },
      ],
    },
  ];

  if (!ROOT) {
    return;
  }

  if (VERSION_EL) {
    VERSION_EL.textContent = `Version: ${BUILD_VERSION}`;
  }

  function safeText(value) {
    return String(value ?? "").trim();
  }

  function escapeText(value) {
    return safeText(value)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#39;");
  }

  function formatCell(value) {
    if (value === null || value === undefined || safeText(value) === "") {
      return "—";
    }
    if (typeof value === "number") {
      return Number.isFinite(value) ? String(value) : "—";
    }
    return escapeText(value);
  }

  function renderSection(entries, config, sectionIndex) {
    const title = config.title;
    const rows = entries
      .filter((row) => (row.status || "pending") === config.status)
      .sort((left, right) => escapeText(left.title).localeCompare(escapeText(right.title)));
    const headers = config.columns.map((column) => `<th>${escapeText(column.label)}</th>`).join("");
    const body = rows
      .map((entry) => {
        const cells = config.columns
          .map((column) => `<td>${formatCell(entry[column.key])}</td>`)
          .join("");
        return `<tr>${cells}</tr>`;
      })
      .join("");

    if (!rows.length) {
      return `
        <section aria-labelledby=\"reading-section-${sectionIndex + 1}\">
          <h2 id=\"reading-section-${sectionIndex + 1}\">${escapeText(title)} (0)</h2>
          <p>No entries.</p>
        </section>
      `;
    }

    return `
      <section aria-labelledby=\"reading-section-${sectionIndex + 1}\">
        <h2 id=\"reading-section-${sectionIndex + 1}\">${escapeText(title)} (${rows.length})</h2>
        <div style=\"overflow-x:auto;\">
          <table style=\"width:100%; border-collapse:collapse; margin:0 0 1rem; min-width: 56rem;\">
            <thead>
              <tr>${headers}</tr>
            </thead>
            <tbody>${body}</tbody>
          </table>
        </div>
      </section>
    `;
  }

  function renderError(message) {
    ROOT.innerHTML = `<p>${escapeText(message)}</p>`;
  }

  async function init() {
    try {
      const response = await fetch(DATA_URL);
      if (!response.ok) {
        throw new Error(`Failed to load data (${response.status})`);
      }
      const payload = await response.json();
      const entries = Array.isArray(payload.entries) ? payload.entries : null;
      if (!entries) {
        throw new Error("Invalid payload: missing entries");
      }
      ROOT.innerHTML = TABLE_LAYOUTS.map((layout, index) => renderSection(entries, layout, index)).join("");
    } catch (error) {
      renderError(`Unable to load reading list: ${String(error.message || error)}`);
    }
  }

  init();
})();
