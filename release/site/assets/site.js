(() => {
  const input = document.querySelector("[data-project-search]");
  const filters = [...document.querySelectorAll("[data-project-filter]")];
  const cards = [...document.querySelectorAll("[data-project-card]")];
  if (!input || !cards.length) return;

  let active = "all";
  const refresh = () => {
    const query = input.value.trim().toLowerCase();
    let visible = 0;
    for (const card of cards) {
      const tags = (card.dataset.tags || "").split(/\s+/);
      const matchesFilter = active === "all" || tags.includes(active);
      const matchesQuery = !query || card.textContent.toLowerCase().includes(query);
      card.hidden = !(matchesFilter && matchesQuery);
      if (!card.hidden) visible += 1;
    }
    const status = document.querySelector("[data-project-status]");
    if (status) status.textContent = `${visible} project${visible === 1 ? "" : "s"}`;
  };

  input.addEventListener("input", refresh);
  for (const button of filters) {
    button.addEventListener("click", () => {
      active = button.dataset.projectFilter;
      for (const peer of filters) peer.setAttribute("aria-pressed", String(peer === button));
      refresh();
    });
  }
})();
