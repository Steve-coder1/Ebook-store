const output = document.getElementById('admin-output');

function show(data) {
  output.textContent = JSON.stringify(data, null, 2);
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
}

document.getElementById('admin-login-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const formData = new FormData(e.target);
  const res = await fetch('/admin/login', { method: 'POST', body: formData });
  show(await res.json());
});

setupHeaderUX();
