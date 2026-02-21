(function () {
  const DISMISS_KEY = 'dismissed_site_notifications_v1';

  function getDismissed() {
    try { return JSON.parse(localStorage.getItem(DISMISS_KEY) || '[]'); } catch (_) { return []; }
  }

  function setDismissed(ids) {
    localStorage.setItem(DISMISS_KEY, JSON.stringify(ids));
  }

  function dismiss(id, el) {
    const ids = new Set(getDismissed());
    ids.add(id);
    setDismissed([...ids]);
    if (el) {
      el.classList.add('is-hiding');
      setTimeout(() => el.remove(), 220);
    }
  }

  function bannerHtml(item) {
    const href = item.href ? `<a href="${item.href}" class="banner-link">${item.cta || 'Open'}</a>` : '';
    return `
      <article class="site-banner ${item.kind || 'info'}" data-notification-id="${item.id}">
        <div>
          <strong>${item.title || 'Notice'}</strong>
          <p>${item.message || ''}</p>
        </div>
        <div class="banner-actions">${href}<button type="button" class="icon-btn dismiss-banner" aria-label="Dismiss">✕</button></div>
      </article>
    `;
  }

  async function loadSiteBanners() {
    const wrap = document.getElementById('site-banner-stack');
    if (!wrap) return;

    try {
      const res = await fetch('/notifications/active');
      const data = await res.json();
      const dismissed = new Set(getDismissed());

      const notifications = [];
      if (data.maintenance?.enabled) {
        notifications.push({
          id: `maintenance-${data.maintenance.message}`,
          kind: 'warning',
          title: 'Maintenance mode',
          message: data.maintenance.message,
        });
      }

      (data.system || []).forEach((n) => notifications.push({
        id: `system-${n.id}`,
        kind: 'info',
        title: 'System message',
        message: n.message,
      }));

      (data.promotions || []).forEach((p) => notifications.push({
        id: `promo-${p.id}`,
        kind: 'promo',
        title: 'Featured ebook',
        message: `${p.title} by ${p.author || 'Unknown author'}`,
        href: `/ebook/${p.slug || p.id}/page`,
        cta: 'View ebook',
      }));

      const visible = notifications.filter((n) => !dismissed.has(n.id)).slice(0, 4);
      wrap.innerHTML = visible.map(bannerHtml).join('');

      wrap.querySelectorAll('.dismiss-banner').forEach((btn) => {
        btn.addEventListener('click', () => {
          const card = btn.closest('[data-notification-id]');
          dismiss(card?.dataset.notificationId, card);
        });
      });
    } catch (_) {
      wrap.innerHTML = '';
    }
  }

  function pushToast(message, kind = 'info') {
    const wrap = document.getElementById('toast-stack');
    if (!wrap || !message) return;
    const node = document.createElement('article');
    node.className = `toast ${kind}`;
    node.textContent = message;
    wrap.appendChild(node);
    requestAnimationFrame(() => node.classList.add('show'));
    setTimeout(() => {
      node.classList.remove('show');
      setTimeout(() => node.remove(), 220);
    }, 2600);
  }

  window.initSiteNotifications = loadSiteBanners;
  window.pushToast = pushToast;
})();
