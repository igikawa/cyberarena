const archiveInput = document.querySelector("#lab-archive");
const selectedFile = document.querySelector("[data-file-name]");
const buildForm = document.querySelector("[data-lab-build-form]");

archiveInput?.addEventListener("change", () => {
    selectedFile.textContent = archiveInput.files?.[0]?.name ?? "Архив не выбран";
});

buildForm?.addEventListener("submit", () => {
    const status = buildForm.querySelector("[data-build-status]");
    const button = buildForm.querySelector(".lab-build-button");
    const label = buildForm.querySelector("[data-submit-label]");
    status.hidden = false;
    button.disabled = true;
    button.setAttribute("aria-busy", "true");
    label.textContent = "Собираем и проверяем лабораторию…";
});
