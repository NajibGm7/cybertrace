/**
 * CyberTrace – App Controller
 * Navigation, utilities, clock, toast notifications.
 */

// ── Navigation ────────────────────────────────────────────────────────────────

const PAGE_TITLES = {
  dashboard: 'Dashboard',
  upload:    'Upload Evidence',
  evidence:  'Evidence Files',
  network:   'Network Monitor',
  logs:      'Audit Logs',
  report:    'Reports',
};

const PAGE_RENDERERS = {
  dashboard: renderDashboard,
  upload:    renderUpload,
  evidence:  renderEvidence,
  network:   renderNetwork,
  logs:      renderLogs,
  report:    renderReport,
};

let currentPage = null;

function navigate(page) {
  // Stop network polling if leaving network page
  if (currentPage === 'network' && page !== 'network' && netInterval) {
    clearInterval(netInterval);
    netInterval = null;
  }

  // Hide all pages
  document.querySelectorAll('.page').forEach(p => p.classList.remove('active'));
  document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));

  // Show selected page
  const el = document.getElementById(`page-${page}`);
  if (el) el.classList.add('active');

  const nav = document.querySelector(`.nav-item[data-page="${page}"]`);
  if (nav) nav.classList.add('active');

  document.getElementById('page-title').textContent = PAGE_TITLES[page] || page;
  currentPage = page;

  // Close sidebar on mobile
  document.getElementById('sidebar').classList.remove('open');

  // Render page content
  if (PAGE_RENDERERS[page]) PAGE_RENDERERS[page]();
}

function toggleSidebar() {
  document.getElementById('sidebar').classList.toggle('open');
}

// ── Clock ─────────────────────────────────────────────────────────────────────

function updateClock() {
  const now = new Date();
  const ts  = now.toUTCString().replace(' GMT', ' UTC');
  const el  = document.getElementById('topbar-time');
  if (el) el.textContent = ts;
}
setInterval(updateClock, 1000);
updateClock();

// ── Toast ─────────────────────────────────────────────────────────────────────

let toastTimer = null;

function toast(message, type = 'ok') {
  const el = document.getElementById('toast');
  el.textContent = message;
  el.className = `toast toast-${type} show`;
  if (toastTimer) clearTimeout(toastTimer);
  toastTimer = setTimeout(() => el.classList.remove('show'), 3500);
}

// ── Utility helpers ───────────────────────────────────────────────────────────

function escHtml(str) {
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

function formatBytes(bytes) {
  if (!bytes) return '0 B';
  const units = ['B', 'KB', 'MB', 'GB'];
  let i = 0;
  let val = bytes;
  while (val >= 1024 && i < units.length - 1) { val /= 1024; i++; }
  return `${val.toFixed(i ? 1 : 0)} ${units[i]}`;
}

// ── Keyboard shortcuts ────────────────────────────────────────────────────────

document.addEventListener('keydown', e => {
  if (!document.getElementById('app') || document.getElementById('app').style.display === 'none') return;
  if (e.altKey) {
    const map = { '1': 'dashboard', '2': 'upload', '3': 'evidence',
                  '4': 'network',   '5': 'logs',   '6': 'report' };
    if (map[e.key]) { e.preventDefault(); navigate(map[e.key]); }
  }
});
