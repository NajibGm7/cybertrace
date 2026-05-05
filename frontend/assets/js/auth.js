/**
 * CyberTrace – Authentication Logic
 * Handles login, register, logout and session persistence.
 */

let currentUser = null;

// ── Show/hide form toggling ───────────────────────────────────────────────────

function showRegister() {
  document.getElementById('login-form').style.display    = 'none';
  document.getElementById('register-form').style.display = 'block';
  document.getElementById('register-error').textContent   = '';
  document.getElementById('register-success').textContent = '';
}

function showLogin() {
  document.getElementById('register-form').style.display = 'none';
  document.getElementById('login-form').style.display    = 'block';
  document.getElementById('login-error').textContent     = '';
}

// ── Login ─────────────────────────────────────────────────────────────────────

async function handleLogin() {
  const username = document.getElementById('login-username').value.trim();
  const password = document.getElementById('login-password').value;
  const errEl    = document.getElementById('login-error');
  errEl.textContent = '';

  if (!username || !password) {
    errEl.textContent = 'Please enter username and password.'; return;
  }

  try {
    const data = await Auth.login(username, password);
    localStorage.setItem('ct_token',    data.token);
    localStorage.setItem('ct_username', data.username);
    localStorage.setItem('ct_role',     data.role);
    currentUser = { username: data.username, role: data.role };
    enterApp();
  } catch (err) {
    errEl.textContent = err.message || 'Login failed.';
  }
}

// ── Register ──────────────────────────────────────────────────────────────────

async function handleRegister() {
  const username = document.getElementById('reg-username').value.trim();
  const email    = document.getElementById('reg-email').value.trim();
  const password = document.getElementById('reg-password').value;
  const errEl    = document.getElementById('register-error');
  const okEl     = document.getElementById('register-success');
  errEl.textContent = ''; okEl.textContent = '';

  if (!username || !email || !password) {
    errEl.textContent = 'All fields are required.'; return;
  }

  try {
    const data = await Auth.register(username, email, password);
    okEl.textContent = data.message + ' You can now log in.';
    setTimeout(showLogin, 2000);
  } catch (err) {
    errEl.textContent = err.message || 'Registration failed.';
  }
}

// ── Enter / Leave App ─────────────────────────────────────────────────────────

function enterApp() {
  document.getElementById('auth-overlay').style.display = 'none';
  document.getElementById('app').style.display          = 'flex';
  document.getElementById('sidebar-username').textContent =
    localStorage.getItem('ct_username') || 'analyst';
  document.getElementById('sidebar-role').textContent =
    localStorage.getItem('ct_role') || 'analyst';
  navigate('dashboard');
}

function logout() {
  localStorage.removeItem('ct_token');
  localStorage.removeItem('ct_username');
  localStorage.removeItem('ct_role');
  currentUser = null;
  document.getElementById('app').style.display          = 'none';
  document.getElementById('auth-overlay').style.display = 'flex';
  showLogin();
}

// ── Boot: check for existing session ─────────────────────────────────────────

(async function checkSession() {
  const token = localStorage.getItem('ct_token');
  if (!token) return; // Stay on auth screen

  try {
    const user = await Auth.me();
    currentUser = user;
    localStorage.setItem('ct_username', user.username);
    localStorage.setItem('ct_role',     user.role);
    enterApp();
  } catch {
    logout(); // Token expired or invalid
  }
})();

// Allow pressing Enter on login fields
document.addEventListener('keydown', e => {
  if (e.key !== 'Enter') return;
  if (document.getElementById('login-form').style.display !== 'none') handleLogin();
  else handleRegister();
});
