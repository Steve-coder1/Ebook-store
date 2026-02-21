(function () {
  window.EbookTheme?.initTheme();
  if (window.initSiteNotifications) window.initSiteNotifications();

  const menuBtn = document.getElementById('menu-toggle');
  const nav = document.getElementById('main-nav');
  menuBtn?.addEventListener('click', () => nav?.classList.toggle('open'));

  const form = document.getElementById('access-code-form');
  const submitBtn = document.getElementById('code-submit-btn');
  const status = document.getElementById('code-status');
  const progress = document.getElementById('code-progress');
  const result = document.getElementById('download-result');
  const list = document.getElementById('download-file-list');
  const bundleWrap = document.getElementById('bundle-link-wrap');
  const captchaWrap = document.getElementById('captcha-wrap');
  const captchaLabel = document.getElementById('captcha-label');
  const captchaAnswer = document.getElementById('captcha-answer');
  const codeInput = document.getElementById('code-value');

  let captchaToken = '';
  let failedAttempts = 0;

  function setStatus(message, tone = 'info') {
    status.className = `code-status ${tone} fade-in`;
    status.textContent = message;
    if (window.pushToast && message) window.pushToast(message, tone === 'error' ? 'error' : 'info');
  }

  async function refreshCaptcha() {
    const res = await fetch('/codes/captcha');
    const data = await res.json();
    captchaToken = data.answer_token;
    captchaLabel.textContent = `Captcha: ${data.challenge}`;
  }

  function showCaptcha(show) {
    captchaWrap.classList.toggle('hidden', !show);
    captchaAnswer.required = !!show;
    if (!show) captchaAnswer.value = '';
  }

  codeInput?.addEventListener('input', () => {
    if (codeInput.value.trim().length >= 6) {
      setStatus('Ready to validate code.', 'info');
    }
  });

  form?.addEventListener('submit', async (e) => {
    e.preventDefault();
    submitBtn.disabled = true;
    progress.classList.add('active');
    result.classList.add('hidden');
    list.innerHTML = '';
    bundleWrap.innerHTML = '';

    const formData = new FormData(form);
    if (!captchaWrap.classList.contains('hidden')) {
      formData.append('captcha_token', captchaToken);
    }

    const res = await fetch('/codes/validate', { method: 'POST', body: formData });
    const data = await res.json();

    progress.classList.remove('active');
    submitBtn.disabled = false;

    if (!res.ok) {
      failedAttempts += 1;
      setStatus(data.error || 'Code validation failed.', 'error');
      if (res.status === 429 || failedAttempts >= 2 || String(data.error || '').toLowerCase().includes('captcha')) {
        showCaptcha(true);
        await refreshCaptcha();
      }
      return;
    }

    failedAttempts = 0;
    showCaptcha(false);
    setStatus(data.confirmation || data.message || 'Code accepted.', 'success');
    progress.classList.add('complete');
    setTimeout(() => progress.classList.remove('complete'), 800);

    const files = data.files || [];
    list.innerHTML = files.map((f) => `
      <li>
        <strong>${f.file_name}</strong>
        <span>${f.file_size || 0} bytes</span>
        <a class="download-link" href="${f.download_url}">Download</a>
      </li>
    `).join('');

    if (data.bundle_download_url) {
      bundleWrap.innerHTML = `<div class="download-links-inner"><a class="download-link" href="${data.bundle_download_url}">Download full bundle (ZIP)</a></div>`;
    }

    result.classList.remove('hidden');
    result.classList.add('fade-in');
  });
})();
