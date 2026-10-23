(() => {
    const grid = document.querySelector(".challenge-grid");
    const sortSelect = document.querySelector("#challenge-sort");
    const orderSelect = document.querySelector("#challenge-order");
    const statusSelect = document.querySelector("#challenge-status");
    const count = document.querySelector("#challenge-count");
    const empty = document.querySelector("#challenge-empty");
    if (!grid || !sortSelect || !orderSelect || !statusSelect || !count || !empty) return;

    const cards = Array.from(grid.querySelectorAll(".challenge-card"));
    const update = () => {
        const status = statusSelect.value;
        const visibleCards = cards.filter((card) => status === "all" || card.dataset.status === status);
        const key = sortSelect.value;
        const direction = orderSelect.value === "desc" ? -1 : 1;
        visibleCards.sort((a, b) => {
            const valueA = a.dataset[key] ?? "";
            const valueB = b.dataset[key] ?? "";
            return valueA.localeCompare(valueB, "ru", { numeric: true }) * direction;
        });
        cards.forEach((card) => {
            card.classList.toggle("is-filtered", status !== "all" && card.dataset.status !== status);
        });
        visibleCards.forEach((card) => grid.append(card));
        count.textContent = `Показано: ${visibleCards.length} из ${cards.length}`;
        empty.hidden = visibleCards.length !== 0;
    };

    [sortSelect, orderSelect, statusSelect].forEach((control) => control.addEventListener("change", update));
    update();
})();
