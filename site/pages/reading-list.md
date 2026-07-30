<style>
  #reading-list-page {
    --heading-color: #111827;
    --body-color: #1f2937;
    --muted-color: #6b7280;
    --line-color: #e5e7eb;
    --accent-color: #2563eb;
    color: var(--body-color);
    font-family: "Inter", "Segoe UI", "Helvetica Neue", Arial, sans-serif;
  }

  #reading-list-page #reading-sections {
    display: grid;
    gap: 1rem;
  }

  #reading-list-page .reading-section {
    background: #fff;
    border: 1px solid var(--line-color);
    border-radius: 10px;
    padding: 0.75rem 1rem 1rem;
    box-shadow: 0 8px 24px rgba(2, 6, 23, 0.06);
  }

  #reading-list-page .reading-section-title {
    color: var(--heading-color);
    margin: 0 0 0.75rem;
    font-size: 1.2rem;
  }

  #reading-list-version {
    margin: 0 0 0.75rem;
    color: var(--muted-color);
    font-size: 0.9rem;
  }

  #reading-list-page .reading-table-wrap {
    overflow-x: auto;
  }

  #reading-list-page .reading-table {
    width: 100%;
    min-width: 56rem;
    border-collapse: collapse;
    margin-bottom: 0.75rem;
  }

  #reading-list-page .reading-table th {
    text-align: left;
    padding: 0.62rem 0.6rem;
    border-bottom: 1px solid var(--line-color);
    background: #f8fafc;
    color: #0f172a;
    font-size: 0.9rem;
    position: sticky;
    top: 0;
  }

  #reading-list-page .reading-table td {
    padding: 0.6rem;
    border-bottom: 1px solid #f1f5f9;
  }

  #reading-list-page .reading-table tbody tr:nth-child(even) {
    background: #f9fafb;
  }

  #reading-list-page .reading-table tbody tr:hover {
    background: #eff6ff;
  }

  #reading-list-page .reading-sort-button {
    border: 0;
    background: 0;
    padding: 0;
    color: inherit;
    cursor: pointer;
    font: inherit;
    width: 100%;
    text-align: left;
  }

  #reading-list-page .reading-sort-button:hover {
    color: var(--accent-color);
  }

  @media (max-width: 768px) {
    #reading-list-page .reading-section {
      padding: 0.5rem 0.65rem 0.75rem;
      border-radius: 8px;
    }

    #reading-list-page .reading-section-title {
      font-size: 1.05rem;
    }
  }
</style>

<p id="reading-list-version" data-reading-version aria-live="polite"></p>
<div id="reading-list-page">
  <div id="reading-sections" data-reading-sections>
    <p>Loading books…</p>
  </div>
</div>

<script src="assets/reading-list.js" defer></script>
