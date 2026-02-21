const output = document.getElementById('login-output');
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

window.EbookTheme?.initTheme();

document.getElementById('user-login-form')?.addEventListener('submit', async (e) => {
  e.preventDefault();
  const fd = new FormData(e.target);
  fd.append('captcha_token', captchaToken);
  const res = await fetch('/auth/login', { method: 'POST', body: fd });
  const data = await res.json();
  show(data);
  if (res.ok) window.location.href = '/';
  await refreshCaptcha();
});

document.getElementById('admin-login-form')?.addEventListener('submit', async (e) => {
  e.preventDefault();
  const fd = new FormData(e.target);
  const res = await fetch('/admin/login', { method: 'POST', body: fd });
  const data = await res.json();
  show(data);
  if (res.ok) window.location.href = '/admin';
});

refreshCaptcha();
