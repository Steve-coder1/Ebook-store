function initThemeAndMenu() {
  const body = document.body;
  const themeToggle = document.getElementById('theme-toggle');
  const savedTheme = localStorage.getItem('theme') || 'light';
  if (savedTheme === 'dark') {
    body.classList.add('dark');
    if (themeToggle) themeToggle.checked = true;
  }

  themeToggle?.addEventListener('change', () => {
    body.classList.toggle('dark', themeToggle.checked);
    localStorage.setItem('theme', themeToggle.checked ? 'dark' : 'light');
  });

  const menuBtn = document.getElementById('menu-toggle');
  const nav = document.getElementById('main-nav');
  menuBtn?.addEventListener('click', () => nav?.classList.toggle('open'));
}

function setupTabsAndCollapsibles() {
  const buttons = [...document.querySelectorAll('.tab-btn')];
  const panels = [...document.querySelectorAll('.tab-panel')];

  buttons.forEach((btn) => {
    btn.addEventListener('click', () => {
      buttons.forEach((b) => b.classList.toggle('active', b === btn));
      panels.forEach((panel) => panel.classList.toggle('active', panel.id === btn.dataset.tab));
    });
  });

  const compact = window.matchMedia('(max-width: 768px)').matches;
  document.querySelectorAll('[data-collapsible]').forEach((section) => {
    const toggle = section.querySelector('.collapse-toggle');
    const content = section.querySelector('.collapse-content');
    if (!toggle || !content) return;

    if (compact) {
      content.classList.remove('open');
      toggle.classList.add('collapsed');
    }

    toggle.addEventListener('click', () => {
      content.classList.toggle('open');
      toggle.classList.toggle('collapsed', !content.classList.contains('open'));
    });
  });
}

function renderPagination(targetId, page, totalPages, onPageChange) {
  const wrap = document.getElementById(targetId);
  wrap.innerHTML = '';
  if (totalPages <= 1) return;

  for (let i = 1; i <= totalPages; i += 1) {
    const btn = document.createElement('button');
    btn.type = 'button';
    btn.textContent = i;
    btn.classList.toggle('active', i === page);
    btn.addEventListener('click', () => onPageChange(i));
    wrap.appendChild(btn);
  }
}

function paginate(items, page, perPage = 6) {
  const totalPages = Math.max(1, Math.ceil((items?.length || 0) / perPage));
  const safePage = Math.min(page, totalPages);
  const start = (safePage - 1) * perPage;
  return {
    items: (items || []).slice(start, start + perPage),
    page: safePage,
    totalPages,
  };
}

function formatDate(value) {
  try {
    return new Date(value).toLocaleString();
  } catch (_) {
    return value || '';
  }
}

async function initProfileData() {
  const emailLabel = document.getElementById('profile-email');
  const settingsFeedback = document.getElementById('settings-feedback');

  let historyPage = 1;
  let favoritesPage = 1;
  let reviewsPage = 1;
  let historyRows = [];
  let favoritesRows = [];
  let reviewRows = [];

  async function loadMe() {
    const res = await fetch('/auth/me');
    const me = await res.json();
    emailLabel.textContent = me.email ? `Signed in as ${me.email}` : 'Unable to load profile.';
  }

  function renderHistory() {
    const wrap = document.getElementById('history-list');
    const pageData = paginate(historyRows, historyPage);

    wrap.innerHTML = pageData.items.map((row) => `
      <article class="profile-card ebook-hover-card">
        <h4>${row.ebook_title || 'Untitled ebook'}</h4>
        <p class="muted-text">Version: ${row.version_label || 'N/A'}</p>
        <p class="muted-text">Downloaded: ${formatDate(row.downloaded_at)}</p>
        <a class="hero-link" href="/ebook/${row.ebook_slug || row.ebook_id}/page">Open ebook</a>
      </article>
    `).join('') || '<p>No download history yet.</p>';

    renderPagination('history-pagination', pageData.page, pageData.totalPages, (next) => {
      historyPage = next;
      renderHistory();
    });
  }

  function renderFavorites() {
    const wrap = document.getElementById('favorites-list');
    const pageData = paginate(favoritesRows, favoritesPage);

    wrap.innerHTML = pageData.items.map((row) => `
      <article class="profile-card ebook-hover-card">
        <h4>${row.title || 'Untitled ebook'}</h4>
        <p class="muted-text">Author: ${row.author || 'Unknown author'}</p>
        <p class="muted-text">Rating: ${row.average_rating ?? 'N/A'} · Favorited: ${formatDate(row.favorited_at)}</p>
        <a class="hero-link" href="/ebook/${row.slug || row.id}/page">Open detail page</a>
      </article>
    `).join('') || '<p>No favorites added yet.</p>';

    renderPagination('favorites-pagination', pageData.page, pageData.totalPages, (next) => {
      favoritesPage = next;
      renderFavorites();
    });
  }

  function renderReviews() {
    const wrap = document.getElementById('reviews-list-profile');
    const pageData = paginate(reviewRows, reviewsPage);

    wrap.innerHTML = pageData.items.map((row) => `
      <article class="profile-card ebook-hover-card">
        <h4>${row.ebook_title || 'Ebook'} · ${'★'.repeat(row.rating || 0)}</h4>
        <p>${row.review_text || 'No review text provided.'}</p>
        <p class="muted-text">Updated: ${formatDate(row.updated_at)}</p>
        <div class="inline-actions">
          <button type="button" data-edit-review="${row.review_id}">Edit</button>
          <a class="hero-link" href="/ebook/${row.ebook_slug || row.ebook_id}/page">View ebook</a>
        </div>
      </article>
    `).join('') || '<p>You have not posted reviews yet.</p>';

    wrap.querySelectorAll('[data-edit-review]').forEach((btn) => {
      btn.addEventListener('click', async () => {
        const id = Number(btn.dataset.editReview);
        const row = reviewRows.find((r) => r.review_id === id);
        if (!row) return;

        const rating = prompt('Update rating (1-5):', String(row.rating));
        const reviewText = prompt('Update review text:', row.review_text || '');
        if (!rating) return;

        const fd = new FormData();
        fd.append('rating', rating);
        fd.append('review_text', reviewText || '');
        const res = await fetch(`/ebooks/${row.ebook_id}/reviews/${id}`, { method: 'PATCH', body: fd });
        const data = await res.json();
        settingsFeedback.textContent = data.message || data.error || 'Review update finished.';
        await loadReviews();
      });
    });

    renderPagination('reviews-pagination', pageData.page, pageData.totalPages, (next) => {
      reviewsPage = next;
      renderReviews();
    });
  }

  async function loadHistory() {
    const res = await fetch('/downloads/history');
    historyRows = res.ok ? await res.json() : [];
    historyPage = 1;
    renderHistory();
  }

  async function loadFavorites() {
    const sort = document.getElementById('favorite-sort').value;
    const res = await fetch(`/favorites?sort=${encodeURIComponent(sort)}`);
    favoritesRows = res.ok ? await res.json() : [];
    favoritesPage = 1;
    renderFavorites();
  }

  async function loadReviews() {
    const res = await fetch('/profile/reviews');
    reviewRows = res.ok ? await res.json() : [];
    reviewsPage = 1;
    renderReviews();
  }

  document.getElementById('favorite-sort')?.addEventListener('change', () => {
    loadFavorites();
  });

  document.getElementById('change-email-form')?.addEventListener('submit', async (e) => {
    e.preventDefault();
    const fd = new FormData(e.target);
    const res = await fetch('/auth/change-email', { method: 'POST', body: fd });
    const data = await res.json();
    settingsFeedback.textContent = data.message || data.error || '';
    if (res.ok) {
      e.target.reset();
      loadMe();
    }
  });

  document.getElementById('change-password-form')?.addEventListener('submit', async (e) => {
    e.preventDefault();
    const fd = new FormData(e.target);
    const res = await fetch('/auth/change-password', { method: 'POST', body: fd });
    const data = await res.json();
    settingsFeedback.textContent = data.message || data.error || '';
    if (res.ok) e.target.reset();
  });

  await Promise.all([loadMe(), loadHistory(), loadFavorites(), loadReviews()]);
}

initThemeAndMenu();
setupTabsAndCollapsibles();
initProfileData();
