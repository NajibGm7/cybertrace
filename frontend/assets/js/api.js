/**
 * CyberTrace – API Client
 * Central wrapper for all HTTP calls to the Flask backend.
 */

const API_BASE = '/api';

/** Retrieve stored JWT token */
function getToken() {
  return localStorage.getItem('ct_token');
}

/** Default headers for authenticated requests */
function authHeaders(extra = {}) {
  return {
    'Content-Type': 'application/json',
    'Authorization': `Bearer ${getToken()}`,
    ...extra
  };
}

/** Generic request wrapper with error normalisation */
async function apiRequest(method, path, body = null, isFormData = false) {
  const opts = { method, headers: {} };

  if (isFormData) {
    // Let browser set multipart boundary automatically
    opts.headers['Authorization'] = `Bearer ${getToken()}`;
    opts.body = body;
  } else {
    opts.headers = authHeaders();
    if (body) opts.body = JSON.stringify(body);
  }

  try {
    const res = await fetch(`${API_BASE}${path}`, opts);
    const data = await res.json().catch(() => ({ error: 'Invalid JSON response' }));
    if (!res.ok) throw { status: res.status, message: data.error || 'Request failed', data };
    return data;
  } catch (err) {
    if (err.status) throw err;
    throw { status: 0, message: 'Network error – is the server running?', data: {} };
  }
}

// ── Auth ──────────────────────────────────────────────────────────────────────

const Auth = {
  register: (u, e, p) => apiRequest('POST', '/register', { username: u, email: e, password: p }),
  login:    (u, p)    => apiRequest('POST', '/login',    { username: u, password: p }),
  me:       ()        => apiRequest('GET',  '/me'),
};

// ── Files ─────────────────────────────────────────────────────────────────────

const Files = {
  list:     (caseId = '') => apiRequest('GET', `/files${caseId ? '?case_id=' + encodeURIComponent(caseId) : ''}`),
  detail:   (id)    => apiRequest('GET',    `/files/${id}`),
  scan:     (id)    => apiRequest('POST',   `/scan/${id}`),
  hash:     (id)    => apiRequest('POST',   `/hash/${id}`),
  metadata: (id)    => apiRequest('GET',    `/metadata/${id}`),
  remove:   (id)    => apiRequest('DELETE', `/files/${id}`),

  upload(file, caseId, onProgress) {
    return new Promise((resolve, reject) => {
      const fd = new FormData();
      fd.append('file', file);
      fd.append('case_id', caseId || 'CASE-001');

      const xhr = new XMLHttpRequest();
      xhr.open('POST', `${API_BASE}/upload`);
      xhr.setRequestHeader('Authorization', `Bearer ${getToken()}`);

      if (onProgress) {
        xhr.upload.onprogress = e => {
          if (e.lengthComputable) onProgress(Math.round(e.loaded / e.total * 100));
        };
      }

      xhr.onload = () => {
        try {
          const data = JSON.parse(xhr.responseText);
          if (xhr.status >= 200 && xhr.status < 300) resolve(data);
          else reject({ status: xhr.status, message: data.error || 'Upload failed', data });
        } catch { reject({ status: xhr.status, message: 'Invalid JSON', data: {} }); }
      };
      xhr.onerror = () => reject({ status: 0, message: 'Network error', data: {} });
      xhr.send(fd);
    });
  }
};

// ── Logs ──────────────────────────────────────────────────────────────────────

const Logs = {
  list: (params = {}) => {
    const qs = new URLSearchParams(params).toString();
    return apiRequest('GET', `/logs${qs ? '?' + qs : ''}`);
  }
};

// ── Network ───────────────────────────────────────────────────────────────────

const Network = {
  poll: () => apiRequest('GET', '/network')
};

// ── Reports ───────────────────────────────────────────────────────────────────

const Reports = {
  generate: (caseId) => apiRequest('POST', '/report', { case_id: caseId }),
  download: (filename) => `${API_BASE}/report/${encodeURIComponent(filename)}`
};

// ── Stats ─────────────────────────────────────────────────────────────────────

const Stats = {
  get: () => apiRequest('GET', '/stats')
};
