const output = document.getElementById('output');
const captchaLabel = document.getElementById('captcha-label');
let captchaToken = '';

async function refreshCaptcha() {
  const res = await fetch('/auth/captcha');
  const data = await res.json();
  captchaToken = data.answer_token;
  captchaLabel.textContent = `Captcha: ${data.challenge}`;
}

function show(data) {
  output.textContent = JSON.stringify(data, null, 2);
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

refreshCaptcha();
