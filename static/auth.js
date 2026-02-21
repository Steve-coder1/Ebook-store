const output = document.getElementById('output');
const captchaLabel = document.getElementById('captcha-label');
let captchaToken = '';

function show(data) {
  output.textContent = JSON.stringify(data, null, 2);
  if (window.pushToast) window.pushToast(data?.message || data?.error || "Request completed", data?.error ? "error" : "info");
}

async function refreshCaptcha() {
  const res = await fetch('/auth/captcha');
  const data = await res.json();
  captchaToken = data.answer_token;
  captchaLabel.textContent = `Captcha: ${data.challenge}`;
}

function setupHeaderUX() {
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
  const utility = document.getElementById('utility-row');
  menuBtn?.addEventListener('click', () => {
    nav?.classList.toggle('open');
    utility?.classList.toggle('open');
  });

  const userBtn = document.getElementById('user-menu-btn');
  const userMenu = document.getElementById('user-menu');
  userBtn?.addEventListener('click', () => userMenu?.classList.toggle('open'));
  document.addEventListener('click', (e) => {
    if (!userMenu || !userBtn) return;
    if (!userMenu.contains(e.target) && !userBtn.contains(e.target)) userMenu.classList.remove('open');
  });

  document.getElementById('search-form')?.addEventListener('submit', async (e) => {
    e.preventDefault();
    const q = new FormData(e.target).get('q');
    const res = await fetch(`/ebooks?q=${encodeURIComponent(q || '')}&page=1&per_page=5`);
    show(await res.json());
  });

  document.getElementById('code-form')?.addEventListener('submit', async (e) => {
    e.preventDefault();
    const formData = new FormData(e.target);
    const res = await fetch('/codes/validate', { method: 'POST', body: formData });
    show(await res.json());
  });

  document.getElementById('logout-btn')?.addEventListener('click', async () => {
    const res = await fetch('/auth/logout', { method: 'POST' });
    show(await res.json());
  });
}

function setupHeroCarousel() {
  const slides = [...document.querySelectorAll('[data-slide]')];
  const dotsWrap = document.getElementById('hero-dots');
  if (!slides.length || !dotsWrap) return;

  let current = 0;
  function setSlide(index) {
    current = (index + slides.length) % slides.length;
    slides.forEach((slide, i) => slide.classList.toggle('active', i === current));
    [...dotsWrap.querySelectorAll('button')].forEach((dot, i) => dot.classList.toggle('active', i === current));
  }

  slides.forEach((_, i) => {
    const btn = document.createElement('button');
    btn.type = 'button';
    btn.addEventListener('click', () => setSlide(i));
    dotsWrap.appendChild(btn);
  });
  setSlide(0);
  setInterval(() => setSlide(current + 1), 5000);
}

function starString(rating) {
  const r = Math.max(0, Math.min(5, Math.round(Number(rating || 0))));
  return '★'.repeat(r) + '☆'.repeat(5 - r);
}

async function loadHomepageSections() {
  const featuredGrid = document.getElementById('featured-grid');
  const categoriesGrid = document.getElementById('categories-grid');
  const reviewsList = document.getElementById('reviews-list');

  try {
    const ebooksRes = await fetch('/ebooks?featured=true&per_page=6');
    const ebooksData = await ebooksRes.json();
    const items = ebooksData.items || [];

    featuredGrid.innerHTML = items.slice(0, 6).map((ebook) => `
      <article class="book-card">
        <div class="book-cover" loading="lazy">Featured</div>
        <div class="book-meta">
          <h3>${ebook.title || 'Untitled'}</h3>
          <p>${ebook.author || 'Unknown author'}</p>
          <div class="book-hover">
            <small>${starString(ebook.average_rating || 0)}</small>
            <a class="hero-link" href="/ebook/${ebook.slug || ebook.id}/page">Quick preview</a>
          </div>
        </div>
      </article>
    `).join('');

    const categoriesRes = await fetch('/categories');
    const categories = await categoriesRes.json();
    categoriesGrid.innerHTML = (categories || []).slice(0, 8).map((cat) => `
      <a class="category-card" href="/categories/${cat.slug}/ebooks">
        <strong>${cat.name}</strong>
        <small>Explore</small>
      </a>
    `).join('');

    const reviews = [];
    for (const ebook of items.slice(0, 3)) {
      const r = await fetch(`/ebooks/${ebook.id}/reviews`);
      const data = await r.json();
      if (Array.isArray(data)) reviews.push(...data.slice(0, 2).map((x) => ({ ...x, ebook_title: ebook.title })));
    }
    reviewsList.innerHTML = reviews.slice(0, 5).map((r) => `
      <article class="review-item">
        <strong>User #${r.user_id}</strong> · <small>${starString(r.rating)}</small>
        <p>${(r.review_text || 'Great read!').slice(0, 120)}</p>
        <small>${r.ebook_title || 'Ebook'} · <a class="hero-link" href="/ebooks/${r.ebook_id}/reviews">Read full review</a></small>
      </article>
    `).join('') || '<p>No reviews yet. Be the first to leave one.</p>';
  } catch (err) {
    featuredGrid.innerHTML = '<p>Featured ebooks unavailable.</p>';
    categoriesGrid.innerHTML = '<p>Categories unavailable.</p>';
    reviewsList.innerHTML = '<p>Reviews unavailable.</p>';
  }
}


function renderCatalog(items) {
  const grid = document.getElementById('catalog-grid');
  grid.innerHTML = (items || []).map((ebook) => `
    <article class="book-card">
      <div class="book-cover" loading="lazy">${ebook.is_featured ? 'Featured' : 'Ebook'}</div>
      <div class="book-meta">
        <h3>${ebook.title || 'Untitled'}</h3>
        <p>${ebook.author || 'Unknown author'}</p>
        <div class="book-hover">
          <small>${starString(ebook.average_rating || 0)}</small>
          <a class="hero-link" href="/ebook/${ebook.slug || ebook.id}/page">Open details</a>
        </div>
      </div>
    </article>
  `).join('') || '<p>No ebooks found with current filters.</p>';
}

function renderPagination(meta, onPage) {
  const wrap = document.getElementById('catalog-pagination');
  wrap.innerHTML = '';
  if (!meta || !meta.pages || meta.pages <= 1) return;
  for (let p = 1; p <= meta.pages; p += 1) {
    const btn = document.createElement('button');
    btn.type = 'button';
    btn.textContent = p;
    if (p === meta.page) btn.classList.add('active');
    btn.addEventListener('click', () => onPage(p));
    wrap.appendChild(btn);
  }
}

function setupCatalog() {
  const category = document.getElementById('filter-category');
  const author = document.getElementById('filter-author');
  const rating = document.getElementById('filter-rating');
  const featured = document.getElementById('filter-featured');
  const sort = document.getElementById('filter-sort');
  const searchInput = document.getElementById('catalog-search-input');
  const filtersWrap = document.getElementById('catalog-filters');
  const filterToggle = document.getElementById('filter-toggle');
  const listToggle = document.getElementById('list-view-toggle');
  const grid = document.getElementById('catalog-grid');

  if (!grid) return;

  let page = 1;

  async function loadCategoriesIntoFilter() {
    try {
      const res = await fetch('/categories');
      const items = await res.json();
      category.innerHTML = '<option value="">All categories</option>' + (items || []).map((c) => `<option value="${c.slug}">${c.name}</option>`).join('');
    } catch (_) {
      // ignore and keep default
    }
  }

  async function loadCatalog() {
    const params = new URLSearchParams();
    if (category.value) params.set('category', category.value);
    if (author.value) params.set('author', author.value);
    if (rating.value) params.set('min_rating', rating.value);
    if (featured.value) params.set('featured', featured.value);
    if (sort.value) params.set('sort', sort.value);
    if (searchInput.value) params.set('q', searchInput.value);
    params.set('page', String(page));
    params.set('per_page', '9');

    const res = await fetch(`/ebooks?${params.toString()}`);
    const data = await res.json();
    renderCatalog(data.items || []);
    renderPagination(data.pagination, (next) => {
      page = next;
      loadCatalog();
    });
  }

  document.getElementById('catalog-search-form')?.addEventListener('submit', (e) => {
    e.preventDefault();
    page = 1;
    loadCatalog();
  });

  [category, author, rating, featured, sort].forEach((el) => {
    el?.addEventListener('change', () => {
      page = 1;
      loadCatalog();
    });
  });

  filterToggle?.addEventListener('click', () => filtersWrap?.classList.toggle('open'));
  listToggle?.addEventListener('change', () => grid.classList.toggle('list', listToggle.checked));

  loadCategoriesIntoFilter();
  loadCatalog();
}

document.getElementById('register-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const formData = new FormData(e.target);
  const res = await fetch('/auth/register', { method: 'POST', body: formData });
  show(await res.json());
});

document.getElementById('login-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const formData = new FormData(e.target);
  formData.append('captcha_token', captchaToken);
  const res = await fetch('/auth/login', { method: 'POST', body: formData });
  show(await res.json());
  await refreshCaptcha();
});

setupHeaderUX();
setupHeroCarousel();
loadHomepageSections();
setupCatalog();
refreshCaptcha();


if (window.initSiteNotifications) window.initSiteNotifications();
