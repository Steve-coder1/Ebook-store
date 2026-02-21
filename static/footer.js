(function () {
  const toTopBtn = document.getElementById('scroll-top-btn');

  window.EbookTheme?.initTheme();

  if (toTopBtn) {
    const toggleTopButton = () => toTopBtn.classList.toggle('show', window.scrollY > 260);
    window.addEventListener('scroll', toggleTopButton, { passive: true });
    toggleTopButton();
    toTopBtn.addEventListener('click', () => window.scrollTo({ top: 0, behavior: 'smooth' }));
  }
})();
