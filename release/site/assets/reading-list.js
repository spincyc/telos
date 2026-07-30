(() => {
  const DATA_URL = "data/reading-list.json";
  const ROOT = document.querySelector("[data-reading-sections]");
  const VERSION_EL = document.querySelector("[data-reading-version]");
  const BUILD_VERSION = "reading-list@2026-07-30-simple-layout-6";
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
  const TABLE_SORTS = TABLE_LAYOUTS.map(() => ({ key: "title", direction: 1 }));
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

  function parseSortValue(value) {
    if (value === null || value === undefined) {
      return null;
    }
    if (typeof value === "number") {
      return Number.isFinite(value) ? value : null;
    }
    const text = safeText(value);
    if (text === "") {
      return null;
    }
    const parsedDate = Date.parse(text);
    if (!Number.isNaN(parsedDate)) {
      return parsedDate;
    }
    const parsedNumber = Number(text.replace(/,/g, ""));
    if (!Number.isNaN(parsedNumber)) {
      return parsedNumber;
    }
    return text.toLowerCase();
  }

  function compareValues(leftValue, rightValue) {
    if (leftValue === null && rightValue === null) {
      return 0;
    }
    if (leftValue === null) {
      return 1;
    }
    if (rightValue === null) {
      return -1;
    }
    if (typeof leftValue === "number" && typeof rightValue === "number") {
      return leftValue - rightValue;
    }
    return safeText(leftValue).localeCompare(safeText(rightValue), "en", { sensitivity: "base" });
  }

  function sortEntries(rows, sortState) {
    return [...rows].sort((left, right) => {
      const leftValue = parseSortValue(left[sortState.key]);
      const rightValue = parseSortValue(right[sortState.key]);
      const base = compareValues(leftValue, rightValue) * sortState.direction;
      if (base !== 0) {
        return base;
      }
      return safeText(left.title).localeCompare(safeText(right.title), "en", {
        sensitivity: "base",
      }) || safeText(left.author).localeCompare(safeText(right.author), "en", {
        sensitivity: "base",
      });
    });
  }

  function renderSection(entries, config, sectionIndex, sortState) {
    const title = config.title;
    const rows = sortEntries(
      entries.filter((row) => (row.status || "pending") === config.status),
      sortState,
    );
    const headers = config.columns
      .map((column) => {
        const active = sortState.key === column.key;
        const arrow = active ? (sortState.direction === 1 ? " ↑" : " ↓") : "";
        return `<th><button type="button" class="reading-sort-button" data-reading-section="${sectionIndex}" data-reading-sort="${escapeText(column.key)}">${escapeText(column.label)}${arrow}</button></th>`;
      })
      .join("");
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
        <section class=\"reading-section\" aria-labelledby=\"reading-section-${sectionIndex + 1}\">
          <h2 class="reading-section-title" id=\"reading-section-${sectionIndex + 1}\">${escapeText(title)} (0)</h2>
          <p>No entries.</p>
        </section>
      `;
    }

    return `
      <section class=\"reading-section\" aria-labelledby=\"reading-section-${sectionIndex + 1}\">
        <h2 class="reading-section-title" id=\"reading-section-${sectionIndex + 1}\">${escapeText(title)} (${rows.length})</h2>
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

  function renderError(message) {
    ROOT.innerHTML = `<p>${escapeText(message)}</p>`;
  }

  function bindSorting(entries) {
    ROOT.querySelectorAll("[data-reading-sort]").forEach((button) => {
      button.addEventListener("click", (event) => {
        const target = event.currentTarget;
        const sectionIndex = Number(target.dataset.readingSection);
        const sortBy = target.dataset.readingSort;
        if (!Number.isFinite(sectionIndex) || sectionIndex < 0 || sectionIndex >= TABLE_SORTS.length) {
          return;
        }
        if (!sortBy) {
          return;
        }
        const sortState = TABLE_SORTS[sectionIndex];
        if (sortState.key === sortBy) {
          sortState.direction *= -1;
        } else {
          sortState.key = sortBy;
          sortState.direction = 1;
        }
        renderRows(entries);
      });
    });
  }

  function renderRows(entries) {
    ROOT.innerHTML = TABLE_LAYOUTS.map(
      (layout, index) => renderSection(entries, layout, index, TABLE_SORTS[index]),
    ).join("");
    bindSorting(entries);
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
      TABLE_LAYOUTS.forEach((layout, index) => {
        const found = layout.columns.find((column) => column.key === TABLE_SORTS[index].key);
        if (!found) {
          TABLE_SORTS[index].key = "title";
          TABLE_SORTS[index].direction = 1;
        }
      });
      renderRows(entries);
    } catch (error) {
      renderError(`Unable to load reading list: ${String(error.message || error)}`);
    }
  }

  init();
})();
