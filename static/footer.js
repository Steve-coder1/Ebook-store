(function () {
  const toTopBtn = document.getElementById('scroll-top-btn');
  const footerThemeToggle = document.getElementById('footer-theme-toggle');

  function syncThemeControls() {
    const dark = document.body.classList.contains('dark');
    const headerToggle = document.getElementById('theme-toggle');
    if (headerToggle) headerToggle.checked = dark;
    if (footerThemeToggle) footerThemeToggle.checked = dark;
  }

  function applyTheme(dark) {
    document.body.classList.toggle('dark', dark);
    localStorage.setItem('theme', dark ? 'dark' : 'light');
    syncThemeControls();
  }

  footerThemeToggle?.addEventListener('change', () => applyTheme(footerThemeToggle.checked));

  if (toTopBtn) {
    const toggleTopButton = () => toTopBtn.classList.toggle('show', window.scrollY > 260);
    window.addEventListener('scroll', toggleTopButton, { passive: true });
    toggleTopButton();
    toTopBtn.addEventListener('click', () => window.scrollTo({ top: 0, behavior: 'smooth' }));
  }

  syncThemeControls();
})();
