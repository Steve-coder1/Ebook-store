const output = document.getElementById('admin-output');

function show(data) {
  if (output) output.textContent = JSON.stringify(data, null, 2);
  if (window.pushToast) window.pushToast(data?.message || data?.error || "Admin action completed", data?.error ? "error" : "info");
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
  const sidebar = document.getElementById('admin-sidebar');
  menuBtn?.addEventListener('click', () => {
    nav?.classList.toggle('open');
    sidebar?.classList.toggle('open');
  });
}

function setupAdminNav() {
  const links = [...document.querySelectorAll('.sidebar-link')];
  const panels = [...document.querySelectorAll('.admin-panel')];

  links.forEach((link) => {
    link.addEventListener('click', () => {
      links.forEach((item) => item.classList.toggle('active', item === link));
      panels.forEach((panel) => panel.classList.toggle('active', panel.id === link.dataset.panel));
    });
  });
}

function renderStatCards(overview) {
  const grid = document.getElementById('overview-stats');
  const cards = [
    ['Total ebooks', overview.total_ebooks || 0],
    ['Active codes', overview.total_active_codes || 0],
    ['Used codes', overview.used_codes || 0],
    ['All downloads', overview.downloads?.all_time || 0],
  ];
  grid.innerHTML = cards.map(([label, value]) => `<article class="stat-card"><small>${label}</small><strong>${value}</strong></article>`).join('');
}

function renderBars(targetId, labels = [], values = []) {
  const max = Math.max(1, ...values, 1);
  const wrap = document.getElementById(targetId);
  wrap.innerHTML = labels.map((label, i) => {
    const width = Math.round(((values[i] || 0) / max) * 100);
    return `<div class="chart-row"><span>${label}</span><div><i style="width:${width}%"></i></div><b>${values[i] || 0}</b></div>`;
  }).join('') || '<p>No data yet.</p>';
}

function renderPie(targetId, used, expired, active) {
  const total = Math.max(1, used + expired + active);
  const u = Math.round((used / total) * 100);
  const e = Math.round((expired / total) * 100);
  const a = 100 - u - e;
  const wrap = document.getElementById(targetId);
  wrap.innerHTML = `
    <div class="pie" style="background: conic-gradient(#3b82f6 0 ${u}%, #ef4444 ${u}% ${u + e}%, #10b981 ${u + e}% 100%);"></div>
    <p>Used ${u}% · Expired ${e}% · Active ${a}%</p>
  `;
}

async function loadOverview() {
  const res = await fetch('/admin/dashboard/overview');
  const data = await res.json();
  renderStatCards(data);

  const trend = data.downloads_over_time || [];
  renderBars('line-chart', trend.map((x) => x.date || x.label), trend.map((x) => x.count || 0));

  const tops = data.top_ebooks || [];
  renderBars('bar-chart', tops.map((x) => (x.title || 'Untitled').slice(0, 18)), tops.map((x) => x.download_count || 0));

  renderPie('pie-chart', data.used_codes || 0, data.expired_codes || 0, data.total_active_codes || 0);

  const activity = document.getElementById('recent-activity');
  const events = data.recent_activity || [];
  activity.innerHTML = events.map((item) => `<article class="list-item"><strong>${item.action || 'Action'}</strong><small>${item.timestamp || ''} · ${item.ip_address || 'n/a'}</small></article>`).join('') || '<p>No recent admin activity.</p>';
}

async function loadEbooks(params = new URLSearchParams()) {
  const res = await fetch(`/admin/ebooks?${params.toString()}`);
  const rows = await res.json();
  const wrap = document.getElementById('ebooks-list');
  wrap.innerHTML = (rows || []).map((e) => `
    <article class="list-item">
      <strong>${e.title || 'Untitled'}</strong>
      <small>${e.author || 'Unknown'} · ${e.is_featured ? 'Featured' : 'Standard'} · Downloads: ${e.download_count || 0}</small>
    </article>
  `).join('') || '<p>No ebooks found.</p>';
}

async function loadCodes() {
  const res = await fetch('/admin/codes?status=all');
  const rows = await res.json();
  const wrap = document.getElementById('codes-list');
  wrap.innerHTML = (rows || []).slice(0, 40).map((c) => `
    <article class="list-item">
      <strong>${c.code_value}</strong>
      <small>Ebook #${c.ebook_id} · ${c.is_used ? 'Used' : 'Unused'} · ${c.is_active ? 'Active' : 'Inactive'}</small>
    </article>
  `).join('') || '<p>No codes found.</p>';
}

async function loadUsers() {
  const res = await fetch('/admin/users');
  const rows = await res.json();
  const wrap = document.getElementById('users-list');
  wrap.innerHTML = (rows || []).map((u) => `
    <article class="list-item">
      <strong>${u.email}</strong>
      <small>Role: ${u.role} · Active: ${u.is_active ? 'Yes' : 'No'} · Joined: ${u.created_at}</small>
    </article>
  `).join('') || '<p>No users available.</p>';
}

async function loadSummaryAndAudit() {
  const summaryRes = await fetch('/admin/reports/summary');
  const summaryData = await summaryRes.json();
  document.getElementById('summary-output').textContent = JSON.stringify(summaryData, null, 2);

  const auditRes = await fetch('/admin/audit-logs?limit=40');
  const audits = await auditRes.json();
  const wrap = document.getElementById('audit-list');
  wrap.innerHTML = (audits || []).map((a) => `
    <article class="list-item">
      <strong>${a.action}</strong>
      <small>Admin #${a.admin_id} · ${a.timestamp} · ${a.ip_address}</small>
    </article>
  `).join('') || '<p>No audit events recorded.</p>';
}


async function loadNotifications() {
  const res = await fetch('/admin/notifications');
  const rows = await res.json();
  const wrap = document.getElementById('notification-list');
  if (!wrap) return;
  wrap.innerHTML = (rows || []).slice(0, 20).map((n) => `
    <article class="list-item">
      <strong>${n.message}</strong>
      <small>${n.created_at}</small>
    </article>
  `).join('') || '<p>No notifications published yet.</p>';
}

function setupForms() {
  document.getElementById('ebook-filter-form')?.addEventListener('submit', (e) => {
    e.preventDefault();
    const params = new URLSearchParams(new FormData(e.target));
    loadEbooks(params);
  });

  document.getElementById('generate-code-form')?.addEventListener('submit', async (e) => {
    e.preventDefault();
    const fd = new FormData(e.target);
    const res = await fetch('/admin/codes/generate', { method: 'POST', body: fd });
    show(await res.json());
    if (res.ok) {
      e.target.reset();
      loadCodes();
      loadOverview();
    }
  });

  document.getElementById('notification-form')?.addEventListener('submit', async (e) => {
    e.preventDefault();
    const fd = new FormData(e.target);
    const res = await fetch('/admin/notifications', { method: 'POST', body: fd });
    show(await res.json());
    if (res.ok) {
      e.target.reset();
      loadNotifications();
      if (window.initSiteNotifications) window.initSiteNotifications();
    }
  });

  document.getElementById('maintenance-form')?.addEventListener('submit', async (e) => {
    e.preventDefault();
    const fd = new FormData(e.target);
    fd.set('enabled', fd.get('enabled') ? 'true' : 'false');
    fd.set('disable_downloads', fd.get('disable_downloads') ? 'true' : 'false');
    fd.set('disable_code_entry', fd.get('disable_code_entry') ? 'true' : 'false');
    const res = await fetch('/admin/maintenance/toggle', { method: 'POST', body: fd });
    show(await res.json());
    if (window.initSiteNotifications) window.initSiteNotifications();
  });
}

async function boot() {
  setupHeaderUX();
  setupAdminNav();
  setupForms();

  try {
    await Promise.all([loadOverview(), loadEbooks(), loadCodes(), loadUsers(), loadSummaryAndAudit(), loadNotifications()]);
  } catch (err) {
    show({ error: 'Failed to load one or more admin sections.', details: String(err) });
  }
}

boot();


if (window.initSiteNotifications) window.initSiteNotifications();
