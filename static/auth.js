const output = document.getElementById('output');
const captchaLabel = document.getElementById('captcha-label');
let captchaToken = '';

function show(data) {
  output.textContent = JSON.stringify(data, null, 2);
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
refreshCaptcha();
