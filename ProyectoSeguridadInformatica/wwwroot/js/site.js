// Please see documentation at https://learn.microsoft.com/aspnet/core/client-side/bundling-and-minification
// for details on configuring this project to bundle and minify static web assets.

// Protege contra doble click rápido en botones marcados con data-throttle
document.addEventListener("click", (event) => {
    const btn = event.target.closest("[data-throttle]");
    if (!btn) return;

    const delay = parseInt(btn.dataset.throttle, 10) || 800;
    if (btn.dataset.throttleLock === "1") {
        event.preventDefault();
        event.stopPropagation();
        return;
    }

    btn.dataset.throttleLock = "1";
    btn.disabled = true;

    setTimeout(() => {
        btn.disabled = false;
        btn.dataset.throttleLock = "0";
    }, delay);
});
