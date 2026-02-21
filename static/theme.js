(function () {
  function applyTheme(mode) {
    const dark = mode === 'dark';
    document.body.classList.toggle('dark', dark);
    localStorage.setItem('theme', dark ? 'dark' : 'light');

    document.querySelectorAll('#theme-toggle, #footer-theme-toggle').forEach((input) => {
      input.checked = dark;
    });
  }

  function initTheme() {
    const saved = localStorage.getItem('theme') || 'light';
    applyTheme(saved);

    document.querySelectorAll('#theme-toggle, #footer-theme-toggle').forEach((input) => {
      input.addEventListener('change', () => applyTheme(input.checked ? 'dark' : 'light'));
    });
  }

  window.EbookTheme = { initTheme, applyTheme };
})();
