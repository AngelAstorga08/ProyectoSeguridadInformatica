// Please see documentation at https://learn.microsoft.com/aspnet/core/client-side/bundling-and-minification
// for details on configuring this project to bundle and minify static web assets.

// Protege contra doble envío en formularios con botones data-throttle
document.addEventListener("submit", (event) => {
    const form = event.target.closest("form");
    if (!form) return;

    const throttledBtn = form.querySelector("[data-throttle]");
    if (!throttledBtn) return;

    const delay = parseInt(throttledBtn.dataset.throttle, 10) || 800;
    if (form.dataset.throttleLock === "1") {
        event.preventDefault();
        return;
    }

    form.dataset.throttleLock = "1";
    form.querySelectorAll("[data-throttle]").forEach(btn => btn.disabled = true);

    setTimeout(() => {
        form.dataset.throttleLock = "0";
        form.querySelectorAll("[data-throttle]").forEach(btn => btn.disabled = false);
    }, delay);
});
