(() => {
  const DATA_URL = "data/reading-list.json";
  const ROOT = document.querySelector("[data-reading-sections]");
  const SUMMARY_EL = document.getElementById("reading-summary");
  const HORIZONTAL_SCROLL_BAR = createHorizontalScrollBar();
  let activeHorizontalWrap = null;
  let isSyncingHorizontalBar = false;
  let horizontalWrappers = [];

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
        { key: "genre_category", label: "Category", badge: true },
        { key: "genre_coarse", label: "Genre", badge: true },
        { key: "genre_fine", label: "Fine genre", badge: true },
        { key: "pages", label: "Pages" },
        { key: "words", label: "Words" },
        { key: "notes", label: "Notes" },
      ],
    },
  ];

  function createHorizontalScrollBar() {
    const existingWrapper = document.querySelector("[data-reading-horizontal-scroll-wrapper]");
    if (existingWrapper) {
      const input = existingWrapper.querySelector("[data-reading-horizontal-scroll]");
      const value = existingWrapper.querySelector(".reading-horizontal-scrollbar-value");
      if (input && value) {
        if (document.body && existingWrapper.parentElement !== document.body) {
          document.body.appendChild(existingWrapper);
        }
        applyHorizontalBarLayout(existingWrapper);
        return {
          wrapper: existingWrapper,
          input,
          value,
        };
      }
      existingWrapper.remove();
    }
    if (!document.body) {
      return { wrapper: null, input: null, value: null };
    }
    const wrapper = document.createElement("div");
    wrapper.className = "reading-horizontal-scrollbar";
    wrapper.setAttribute("data-reading-horizontal-scroll-wrapper", "auto");
    wrapper.setAttribute("aria-live", "polite");
    wrapper.innerHTML = `
      <input
        type="range"
        min="0"
        max="0"
        step="1"
        value="0"
        class="reading-horizontal-scrollbar-input"
        data-reading-horizontal-scroll
        aria-label="Reading table horizontal scroll"
      />
      <span class="reading-horizontal-scrollbar-value">0%</span>
    `;
    document.body.appendChild(wrapper);
    return {
      wrapper,
      input: wrapper.querySelector("[data-reading-horizontal-scroll]"),
      value: wrapper.querySelector(".reading-horizontal-scrollbar-value"),
    };
  }

  function applyHorizontalBarLayout(wrapper) {
    if (!wrapper) {
      return;
    }
    wrapper.style.setProperty("position", "fixed", "important");
    wrapper.style.setProperty("left", "1rem", "important");
    wrapper.style.setProperty("right", "1rem", "important");
    wrapper.style.setProperty("bottom", "max(0.75rem, env(safe-area-inset-bottom))", "important");
    wrapper.style.setProperty("top", "auto", "important");
    wrapper.style.setProperty("z-index", "40", "important");
    wrapper.style.setProperty("display", "flex", "important");
    wrapper.style.setProperty("align-items", "center", "important");
    wrapper.style.setProperty("gap", ".65rem", "important");
    wrapper.style.setProperty("padding", ".7rem .82rem", "important");
    wrapper.style.setProperty("border-radius", "999px", "important");
    wrapper.style.setProperty("width", "calc(100% - 2rem)", "important");
    wrapper.style.setProperty("box-sizing", "border-box", "important");
    wrapper.style.setProperty("margin", "0", "important");
  }

  function pinHorizontalBarToViewport() {
    if (!HORIZONTAL_SCROLL_BAR.wrapper) {
      return;
    }
    applyHorizontalBarLayout(HORIZONTAL_SCROLL_BAR.wrapper);
  }

  function tableHasOverflow(wrapper) {
    return wrapper.scrollWidth > wrapper.clientWidth + 1;
  }

  function showHorizontalBarFor(wrapper) {
    if (!HORIZONTAL_SCROLL_BAR.wrapper || !HORIZONTAL_SCROLL_BAR.input || !HORIZONTAL_SCROLL_BAR.value || !wrapper) {
      return;
    }
    if (!tableHasOverflow(wrapper)) {
      hideHorizontalBar();
      return;
    }
    const max = wrapper.scrollWidth - wrapper.clientWidth;
    const maxValue = Math.max(1, Math.ceil(max));
    isSyncingHorizontalBar = true;
    HORIZONTAL_SCROLL_BAR.wrapper.hidden = false;
    HORIZONTAL_SCROLL_BAR.input.max = String(maxValue);
    const left = Math.min(max, wrapper.scrollLeft);
    HORIZONTAL_SCROLL_BAR.input.value = String(Math.round(left));
    const percent = Math.round(max > 0 ? (left / max) * 100 : 0);
    HORIZONTAL_SCROLL_BAR.value.textContent = `${percent}%`;
    isSyncingHorizontalBar = false;
  }

  function hideHorizontalBar() {
    if (!HORIZONTAL_SCROLL_BAR.wrapper || !HORIZONTAL_SCROLL_BAR.input || !HORIZONTAL_SCROLL_BAR.value) {
      return;
    }
    HORIZONTAL_SCROLL_BAR.wrapper.hidden = true;
    HORIZONTAL_SCROLL_BAR.input.value = "0";
    HORIZONTAL_SCROLL_BAR.value.textContent = "0%";
    activeHorizontalWrap = null;
  }

  function activateHorizontalWrap(wrapper) {
    if (!wrapper) {
      hideHorizontalBar();
      return;
    }
    if (activeHorizontalWrap === wrapper) {
      showHorizontalBarFor(wrapper);
      return;
    }
    activeHorizontalWrap = wrapper;
    showHorizontalBarFor(wrapper);
  }

  function onHorizontalWrapScroll(event) {
    const wrapper = event.currentTarget;
    activateHorizontalWrap(wrapper);
    showHorizontalBarFor(wrapper);
  }

  function onHorizontalWrapPointer(event) {
    activateHorizontalWrap(event.currentTarget);
  }

  function onHorizontalWrapFocus(event) {
    activateHorizontalWrap(event.currentTarget);
  }

  function nearestVisibleWrapper(wrappers) {
    const mid = window.innerHeight / 2;
    let best;
    let bestScore = Infinity;
    for (const wrapper of wrappers) {
      if (!tableHasOverflow(wrapper)) {
        continue;
      }
      const rect = wrapper.getBoundingClientRect();
      if (rect.bottom < 0 || rect.top > window.innerHeight) {
        continue;
      }
      const center = (rect.top + rect.bottom) / 2;
      const score = Math.abs(center - mid);
      if (score < bestScore) {
        bestScore = score;
        best = wrapper;
      }
    }
    return best || wrappers.find((wrapper) => tableHasOverflow(wrapper)) || null;
  }

  function refreshActiveHorizontalWrap() {
    if (horizontalWrappers.length === 0) {
      hideHorizontalBar();
      return;
    }
    const next = nearestVisibleWrapper(horizontalWrappers);
    if (next !== activeHorizontalWrap) {
      activateHorizontalWrap(next);
    } else if (next) {
      showHorizontalBarFor(next);
    }
  }

  function onInputHorizontalBar() {
    if (!HORIZONTAL_SCROLL_BAR.input || isSyncingHorizontalBar || !activeHorizontalWrap) {
      return;
    }
    if (!tableHasOverflow(activeHorizontalWrap)) {
      hideHorizontalBar();
      return;
    }
    const maxScroll = activeHorizontalWrap.scrollWidth - activeHorizontalWrap.clientWidth;
    const max = Number(HORIZONTAL_SCROLL_BAR.input.max) || 1;
    const sliderValue = Number(HORIZONTAL_SCROLL_BAR.input.value) || 0;
    const target = (sliderValue / max) * maxScroll;
    activeHorizontalWrap.scrollLeft = target;
    const percent = Math.round(maxScroll > 0 ? (target / maxScroll) * 100 : 0);
    HORIZONTAL_SCROLL_BAR.value.textContent = `${percent}%`;
  }

  function setupHorizontalScrollbar() {
    horizontalWrappers = Array.from(ROOT.querySelectorAll(".reading-table-wrap"));
    if (horizontalWrappers.length === 0) {
      hideHorizontalBar();
      return;
    }

    for (const [index, wrapper] of horizontalWrappers.entries()) {
      if (wrapper.dataset.readingScrollbarWireup === "1") {
        continue;
      }
      wrapper.dataset.readingSectionIndex = String(index);
      wrapper.addEventListener("scroll", onHorizontalWrapScroll, { passive: true });
      wrapper.addEventListener("pointerdown", onHorizontalWrapPointer, { passive: true });
      wrapper.addEventListener("focusin", onHorizontalWrapFocus);
      wrapper.dataset.readingScrollbarWireup = "1";
    }

    const firstOverflow = horizontalWrappers.find(tableHasOverflow);
    if (firstOverflow) {
      activeHorizontalWrap = firstOverflow;
      showHorizontalBarFor(firstOverflow);
    } else {
      const first = horizontalWrappers[0];
      activeHorizontalWrap = first;
      hideHorizontalBar();
    }
    refreshActiveHorizontalWrap();
  }

  if (HORIZONTAL_SCROLL_BAR.input) {
    HORIZONTAL_SCROLL_BAR.input.addEventListener("input", onInputHorizontalBar);
  }
  window.addEventListener("resize", () => {
    pinHorizontalBarToViewport();
    refreshActiveHorizontalWrap();
  });
  window.addEventListener("scroll", () => {
    pinHorizontalBarToViewport();
    requestAnimationFrame(refreshActiveHorizontalWrap);
  }, { passive: true });

  pinHorizontalBarToViewport();

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
    setupHorizontalScrollbar();
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
