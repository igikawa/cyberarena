(() => {
    const form = document.querySelector("[data-lab-start-form]");
    if (!form) return;

    const button = form.querySelector("button[type='submit']");
    const status = form.querySelector("[role='status']");
    if (!button || !status) return;

    form.addEventListener("submit", () => {
        form.setAttribute("aria-busy", "true");
        button.disabled = true;
        button.textContent = "Создаём лабораторию…";
        status.hidden = false;
    });
})();
