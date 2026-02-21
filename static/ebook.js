function stars(rating) {
  const r = Math.max(0, Math.min(5, Math.round(Number(rating || 0))));
  return '★'.repeat(r) + '☆'.repeat(5 - r);
}

function applyThemeAndMenu() {
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

function setupCollapsibles() {
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

async function initEbookPage() {
  const root = document.querySelector('[data-ebook-slug]');
  if (!root) return;

  const slug = root.dataset.ebookSlug;
  const status = document.getElementById('ebook-status');
  const title = document.getElementById('ebook-title');
  const author = document.getElementById('ebook-author');
  const meta = document.getElementById('ebook-meta');
  const rating = document.getElementById('ebook-rating');
  const description = document.getElementById('ebook-description');
  const previewSummary = document.getElementById('preview-summary');
  const fileList = document.getElementById('file-list');
  const reviewsWrap = document.getElementById('reviews-list-page');
  const loadMoreBtn = document.getElementById('load-more-reviews');
  const feedback = document.getElementById('download-feedback');
  const linksWrap = document.getElementById('download-links');
  const favoriteBtn = document.getElementById('favorite-btn');
  const favoriteNote = document.getElementById('favorite-note');

  let ebook = null;
  let reviews = [];
  let shownReviews = 5;

  function renderReviews() {
    const visible = reviews.slice(0, shownReviews);
    reviewsWrap.innerHTML = visible.map((r) => `
      <article class="review-item">
        <strong>User #${r.user_id}</strong> · <small>${stars(r.rating)}</small>
        <p>${r.review_text || 'No review text provided.'}</p>
        <small>${new Date(r.created_at).toLocaleString()}</small>
      </article>
    `).join('') || '<p>No reviews yet.</p>';

    loadMoreBtn.style.display = shownReviews < reviews.length ? 'inline-block' : 'none';
  }

  try {
    const res = await fetch(`/ebook/${encodeURIComponent(slug)}`);
    if (!res.ok) throw new Error('Failed to load ebook');
    ebook = await res.json();

    title.textContent = ebook.title || 'Untitled ebook';
    author.textContent = `by ${ebook.author || 'Unknown author'}`;
    meta.textContent = `${ebook.category?.name || 'Uncategorized'} • ${ebook.slug || ''}`;
    rating.textContent = `${stars(ebook.average_rating)} (${ebook.review_count || 0} reviews)`;
    description.textContent = ebook.description || ebook.summary_text || 'No description available.';
    previewSummary.textContent = ebook.summary_text || 'No sample summary available.';
    status.textContent = 'Code validation required before download links are shown.';

    const files = ebook.files || [];
    fileList.innerHTML = files.map((f) => `
      <li title="Version: ${f.version_label || 'N/A'}">
        <strong>${f.file_name}</strong>
        <span>${f.version_label || 'v1'} • ${f.file_size || 0} bytes</span>
      </li>
    `).join('') || '<li>No files listed.</li>';

    const revRes = await fetch(`/ebooks/${ebook.id}/reviews`);
    reviews = revRes.ok ? await revRes.json() : [];
    renderReviews();
  } catch (err) {
    status.textContent = 'Unable to load ebook details right now.';
    return;
  }

  loadMoreBtn.addEventListener('click', () => {
    shownReviews += 5;
    renderReviews();
  });

  document.getElementById('review-form')?.addEventListener('submit', async (e) => {
    e.preventDefault();
    if (!ebook) return;
    const formData = new FormData(e.target);
    const res = await fetch(`/ebooks/${ebook.id}/reviews`, { method: 'POST', body: formData });
    const data = await res.json();
    if (!res.ok) {
      status.textContent = data.error || 'Unable to submit review. Sign in first.';
      return;
    }
    status.textContent = data.message || 'Review posted.';
    const r = await fetch(`/ebooks/${ebook.id}/reviews`);
    reviews = r.ok ? await r.json() : reviews;
    shownReviews = 5;
    renderReviews();
    e.target.reset();
  });

  favoriteBtn?.addEventListener('click', async () => {
    if (!ebook) return;
    let res = await fetch(`/favorites/${ebook.id}`, { method: 'POST' });
    let data = await res.json();
    if (!res.ok) {
      res = await fetch(`/favorites/${ebook.id}`, { method: 'DELETE' });
      data = await res.json();
      if (res.ok) {
        favoriteBtn.textContent = '♡ Add to favorites';
        favoriteBtn.classList.remove('active');
      }
    } else {
      favoriteBtn.textContent = '♥ Favorited';
      favoriteBtn.classList.add('active');
    }
    favoriteNote.textContent = data.message || data.error || '';
  });

  document.getElementById('code-unlock-form')?.addEventListener('submit', async (e) => {
    e.preventDefault();
    const formData = new FormData(e.target);
    const res = await fetch('/codes/validate', { method: 'POST', body: formData });
    const data = await res.json();

    if (!res.ok) {
      feedback.textContent = data.error || 'Code validation failed.';
      linksWrap.innerHTML = '';
      return;
    }

    feedback.textContent = data.confirmation || 'Code accepted.';
    const fileLinks = (data.files || []).map((f) => `<a class="download-link" href="${f.download_url}">${f.file_name}</a>`).join('');
    const bundle = data.bundle_download_url ? `<a class="download-link" href="${data.bundle_download_url}">Download bundle (zip)</a>` : '';
    linksWrap.innerHTML = `<div class="download-links-inner">${fileLinks}${bundle}</div>`;
  });
}

applyThemeAndMenu();
setupCollapsibles();
initEbookPage();


if (window.initSiteNotifications) window.initSiteNotifications();
