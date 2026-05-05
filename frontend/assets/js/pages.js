/**
 * CyberTrace – Page Renderers
 * Each function renders content into its respective #page-* div.
 */

// ═══════════════════════════════════════════════════════════════
//  DASHBOARD
// ═══════════════════════════════════════════════════════════════

async function renderDashboard() {
  const el = document.getElementById('page-dashboard');
  el.innerHTML = `
    <div class="page-header">
      <h1>DASHBOARD</h1>
      <p>Forensic operations overview</p>
    </div>
    <div class="stat-grid" id="stat-grid">
      ${[1,2,3,4,5].map(() => `<div class="stat-card"><div class="stat-label">Loading…</div><div class="stat-value">—</div></div>`).join('')}
    </div>
    <div class="grid-2">
      <div class="card">
        <div class="section-title">Recent Activity</div>
        <div id="dash-recent-logs">Loading…</div>
      </div>
      <div class="card">
        <div class="section-title">Action Breakdown</div>
        <div id="dash-action-chart"></div>
      </div>
    </div>`;

  try {
    const s = await Stats.get();
    const colours = { '--cyan': s.total_files, '--green': s.suspicious_files,
                      '--red': s.recent_uploads, '--yellow': s.total_logs, '--purple': s.total_users };

    document.getElementById('stat-grid').innerHTML = `
      <div class="stat-card" style="--accent:var(--cyan)">
        <div class="stat-label">Total Evidence</div>
        <div class="stat-value">${s.total_files}</div>
        <div class="stat-sub">files uploaded</div>
      </div>
      <div class="stat-card" style="--accent:var(--red)">
        <div class="stat-label">Suspicious</div>
        <div class="stat-value">${s.suspicious_files}</div>
        <div class="stat-sub">flagged files</div>
      </div>
      <div class="stat-card" style="--accent:var(--yellow)">
        <div class="stat-label">24h Uploads</div>
        <div class="stat-value">${s.recent_uploads}</div>
        <div class="stat-sub">recent evidence</div>
      </div>
      <div class="stat-card" style="--accent:var(--green)">
        <div class="stat-label">Audit Logs</div>
        <div class="stat-value">${s.total_logs}</div>
        <div class="stat-sub">total entries</div>
      </div>
      <div class="stat-card" style="--accent:var(--purple)">
        <div class="stat-label">Analysts</div>
        <div class="stat-value">${s.total_users}</div>
        <div class="stat-sub">registered users</div>
      </div>`;

    // Action bar chart
    let chartHTML = '';
    const maxCount = Math.max(...s.action_breakdown.map(a => a.cnt), 1);
    const chartColours = { upload: 'var(--cyan)', scan: 'var(--yellow)',
      hash: 'var(--purple)', login: 'var(--green)', report: '#00bfff',
      delete: 'var(--red)', network: '#a0c8ff' };
    for (const a of s.action_breakdown) {
      const pct = Math.round(a.cnt / maxCount * 100);
      const col = chartColours[a.action] || 'var(--text-muted)';
      chartHTML += `
        <div style="margin:.4rem 0">
          <div style="display:flex;justify-content:space-between;font-size:.75rem;margin-bottom:.2rem">
            <span style="color:${col};text-transform:uppercase;letter-spacing:1px;font-family:var(--font-head);font-size:.65rem">${a.action}</span>
            <span style="color:var(--text-muted)">${a.cnt}</span>
          </div>
          <div style="height:6px;background:var(--border);border-radius:3px;overflow:hidden">
            <div style="height:100%;width:${pct}%;background:${col};border-radius:3px;
              box-shadow:0 0 8px ${col};transition:width .5s ease"></div>
          </div>
        </div>`;
    }
    document.getElementById('dash-action-chart').innerHTML = chartHTML || '<p style="color:var(--text-muted);font-size:.85rem">No actions recorded yet.</p>';

  } catch (err) {
    document.getElementById('stat-grid').innerHTML = `<div class="stat-card"><div class="stat-label" style="color:var(--red)">${err.message}</div></div>`;
  }

  // Recent logs
  try {
    const logsData = await Logs.list({ per_page: 6 });
    let html = '';
    for (const lg of logsData.logs) {
      const cls = `log-${lg.action}` || 'log-default';
      html += `<div style="display:flex;gap:.75rem;padding:.45rem 0;border-bottom:1px solid var(--border);font-size:.82rem;align-items:center">
        <span class="${cls}" style="font-family:var(--font-head);font-size:.65rem;letter-spacing:1px;min-width:4.5rem">${lg.action.toUpperCase()}</span>
        <span style="flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${lg.detail || lg.target || '—'}</span>
        <span style="color:var(--text-muted);font-family:var(--font-mono);font-size:.7rem;flex-shrink:0">${lg.created_at.slice(11,19)}</span>
      </div>`;
    }
    document.getElementById('dash-recent-logs').innerHTML = html || '<p style="color:var(--text-muted);font-size:.85rem;padding:.5rem 0">No logs yet.</p>';
  } catch { document.getElementById('dash-recent-logs').innerHTML = '<p style="color:var(--red)">Failed to load logs.</p>'; }
}


// ═══════════════════════════════════════════════════════════════
//  UPLOAD EVIDENCE
// ═══════════════════════════════════════════════════════════════

function renderUpload() {
  const el = document.getElementById('page-upload');
  el.innerHTML = `
    <div class="page-header">
      <h1>UPLOAD EVIDENCE</h1>
      <p>Add files to the forensic evidence store</p>
    </div>
    <div class="card" style="max-width:640px">
      <div class="field-group">
        <label>Case ID</label>
        <input class="field-input" id="up-case-id" placeholder="CASE-2024-001" value="CASE-001">
      </div>

      <div class="upload-zone" id="upload-zone" onclick="document.getElementById('file-input').click()">
        <input type="file" id="file-input" multiple onchange="handleFileSelect(this.files)">
        <div class="upload-icon">⬆</div>
        <div class="upload-text">Click to select or drag &amp; drop files</div>
        <div class="upload-sub">Max 50 MB · Any file type accepted (forensic toolkit)</div>
      </div>

      <div id="upload-queue" style="margin-top:1rem"></div>
    </div>`;

  // Drag and drop
  const zone = document.getElementById('upload-zone');
  zone.addEventListener('dragover', e => { e.preventDefault(); zone.classList.add('drag-over'); });
  zone.addEventListener('dragleave', () => zone.classList.remove('drag-over'));
  zone.addEventListener('drop', e => {
    e.preventDefault(); zone.classList.remove('drag-over');
    handleFileSelect(e.dataTransfer.files);
  });
}

async function handleFileSelect(fileList) {
  const files  = Array.from(fileList);
  const caseId = document.getElementById('up-case-id').value.trim() || 'CASE-001';
  const queue  = document.getElementById('upload-queue');

  for (const file of files) {
    const id = 'upl-' + Math.random().toString(36).slice(2);
    queue.insertAdjacentHTML('beforeend', `
      <div id="${id}" class="card" style="margin-bottom:.75rem;padding:.75rem">
        <div style="display:flex;justify-content:space-between;margin-bottom:.35rem">
          <span style="font-weight:600">${escHtml(file.name)}</span>
          <span style="color:var(--text-muted);font-size:.8rem">${formatBytes(file.size)}</span>
        </div>
        <div class="progress-bar"><div class="progress-fill" id="${id}-bar" style="width:0%"></div></div>
        <div id="${id}-status" style="font-size:.75rem;color:var(--text-muted)">Uploading…</div>
      </div>`);

    try {
      const result = await Files.upload(file, caseId, pct => {
        document.getElementById(`${id}-bar`).style.width = pct + '%';
      });
      document.getElementById(`${id}-bar`).style.width = '100%';
      document.getElementById(`${id}-status`).innerHTML =
        `<span style="color:var(--green)">✓ Uploaded</span> · ID: ${result.file_id} · ` +
        `<a href="#" onclick="navigate('evidence')" style="color:var(--cyan)">View evidence</a>`;
      toast('Uploaded: ' + file.name, 'ok');
    } catch (err) {
      document.getElementById(`${id}-bar`).style.background = 'var(--red)';
      document.getElementById(`${id}-status`).innerHTML = `<span style="color:var(--red)">✗ ${err.message}</span>`;
      toast('Upload failed: ' + err.message, 'err');
    }
  }
}


// ═══════════════════════════════════════════════════════════════
//  EVIDENCE FILES
// ═══════════════════════════════════════════════════════════════

async function renderEvidence() {
  const el = document.getElementById('page-evidence');
  el.innerHTML = `
    <div class="page-header">
      <h1>EVIDENCE FILES</h1>
      <p>Manage and analyse uploaded files</p>
    </div>
    <div style="display:flex;gap:.75rem;margin-bottom:1rem;flex-wrap:wrap">
      <input class="field-input" id="ev-filter-case" placeholder="Filter by Case ID" style="max-width:200px">
      <button class="btn-secondary" onclick="loadEvidence()">⟳ Refresh</button>
    </div>
    <div id="evidence-table-wrap">
      <div class="empty-state"><div class="empty-icon">◉</div>Loading evidence…</div>
    </div>
    <!-- Detail Panel -->
    <div id="evidence-detail-panel" style="display:none;margin-top:1.5rem"></div>`;

  await loadEvidence();
}

async function loadEvidence() {
  const caseId = (document.getElementById('ev-filter-case') || {}).value || '';
  const wrap   = document.getElementById('evidence-table-wrap');
  wrap.innerHTML = '<div class="empty-state">Loading…</div>';

  try {
    const files = await Files.list(caseId);
    if (!files.length) {
      wrap.innerHTML = '<div class="empty-state"><div class="empty-icon">◉</div>No evidence files found. Upload some first.</div>';
      return;
    }

    let rows = '';
    for (const f of files) {
      let analysis = {};
      try { analysis = JSON.parse(f.analysis_result || '{}'); } catch {}
      const risk = analysis.risk_level || (f.is_suspicious ? 'high' : 'unknown');
      rows += `
        <tr>
          <td>${f.id}</td>
          <td><span style="color:var(--cyan)">${escHtml(f.original_name)}</span></td>
          <td style="color:var(--text-muted)">${escHtml(f.case_id)}</td>
          <td>${f.file_type || '—'}</td>
          <td>${formatBytes(f.file_size || 0)}</td>
          <td><span class="badge badge-${risk}">${risk.toUpperCase()}</span></td>
          <td class="mono">${(f.md5_hash || '—').slice(0,16)}…</td>
          <td style="white-space:nowrap">
            <button class="btn-secondary" onclick="actionScan(${f.id})"    style="margin-right:.3rem">Scan</button>
            <button class="btn-secondary" onclick="actionHash(${f.id})"    style="margin-right:.3rem">Hash</button>
            <button class="btn-secondary" onclick="showDetail(${f.id})"   style="margin-right:.3rem">Detail</button>
            <button class="btn-danger"    onclick="actionDelete(${f.id})">Delete</button>
          </td>
        </tr>`;
    }

    wrap.innerHTML = `
      <div class="table-wrap">
        <table>
          <thead><tr>
            <th>#</th><th>Filename</th><th>Case</th><th>Type</th>
            <th>Size</th><th>Risk</th><th>MD5</th><th>Actions</th>
          </tr></thead>
          <tbody>${rows}</tbody>
        </table>
      </div>`;
  } catch (err) {
    wrap.innerHTML = `<div class="empty-state" style="color:var(--red)">Error: ${err.message}</div>`;
  }
}

async function actionScan(id) {
  toast('Scanning file…', 'ok');
  try {
    const r = await Files.scan(id);
    toast(`Risk: ${r.scan_result.risk_level.toUpperCase()} · ${r.scan_result.findings.length} findings`, r.scan_result.is_suspicious ? 'warn' : 'ok');
    loadEvidence();
  } catch (err) { toast(err.message, 'err'); }
}

async function actionHash(id) {
  toast('Computing hashes…', 'ok');
  try {
    const r = await Files.hash(id);
    toast('Hashes computed. Check file details.', 'ok');
    loadEvidence();
    showDetail(id);
  } catch (err) { toast(err.message, 'err'); }
}

async function actionDelete(id) {
  if (!confirm('Delete this evidence file? This cannot be undone.')) return;
  try {
    await Files.remove(id);
    toast('File deleted.', 'warn');
    loadEvidence();
  } catch (err) { toast(err.message, 'err'); }
}

async function showDetail(id) {
  const panel = document.getElementById('evidence-detail-panel');
  panel.style.display = 'block';
  panel.innerHTML = `<div class="card"><div style="color:var(--text-muted)">Loading detail…</div></div>`;

  try {
    const [f, meta] = await Promise.all([Files.detail(id), Files.metadata(id).catch(() => null)]);
    let analysis = {};
    try { analysis = JSON.parse(f.analysis_result || '{}'); } catch {}

    const findings = (analysis.findings || []).concat(
      (analysis.signature_matches || []).map(s => '⚠ Sig: ' + s)
    );

    panel.innerHTML = `
      <div class="card">
        <div class="section-title">File Detail – #${f.id} · ${escHtml(f.original_name)}</div>
        <div class="grid-2" style="gap:1.5rem">
          <div>
            <div class="section-title" style="font-size:.7rem;margin-top:0">Hashes</div>
            ${f.md5_hash    ? `<div class="hash-block"><div class="hash-label">MD5</div><div class="hash-value">${f.md5_hash}</div></div>` : '<p style="color:var(--text-muted);font-size:.8rem">No hashes yet – click Hash button.</p>'}
            ${f.sha1_hash   ? `<div class="hash-block"><div class="hash-label">SHA-1</div><div class="hash-value">${f.sha1_hash}</div></div>` : ''}
            ${f.sha256_hash ? `<div class="hash-block"><div class="hash-label">SHA-256</div><div class="hash-value">${f.sha256_hash}</div></div>` : ''}

            <div class="section-title" style="font-size:.7rem">Scan Findings</div>
            ${findings.length ? findings.map(f => `<div style="padding:.3rem 0;border-bottom:1px solid var(--border);font-size:.82rem;color:var(--yellow)">⚠ ${escHtml(f)}</div>`).join('') : '<div style="color:var(--green);font-size:.82rem">✓ No suspicious findings</div>'}
          </div>
          <div>
            <div class="section-title" style="font-size:.7rem;margin-top:0">Metadata</div>
            ${meta ? Object.entries(meta).slice(0,12).map(([k,v]) => `
              <div style="display:flex;gap:.5rem;padding:.3rem 0;border-bottom:1px solid var(--border);font-size:.8rem">
                <span style="color:var(--text-muted);min-width:120px;flex-shrink:0">${escHtml(k)}</span>
                <span style="word-break:break-all">${escHtml(String(typeof v === 'object' ? JSON.stringify(v) : v).slice(0, 120))}</span>
              </div>`).join('') : '<p style="color:var(--text-muted);font-size:.8rem">Metadata unavailable.</p>'}
          </div>
        </div>
        <button class="btn-secondary" onclick="document.getElementById('evidence-detail-panel').style.display='none'" style="margin-top:1rem">Close</button>
      </div>`;
  } catch (err) {
    panel.innerHTML = `<div class="card" style="color:var(--red)">Error: ${err.message}</div>`;
  }
}


// ═══════════════════════════════════════════════════════════════
//  NETWORK MONITOR
// ═══════════════════════════════════════════════════════════════

let netInterval = null;

function renderNetwork() {
  const el = document.getElementById('page-network');
  el.innerHTML = `
    <div class="page-header">
      <h1>NETWORK MONITOR</h1>
      <p>Active connections – auto-refreshes every 8 seconds</p>
    </div>
    <div style="display:flex;gap:.75rem;margin-bottom:1rem">
      <button class="btn-secondary" onclick="pollNetwork()">⟳ Refresh now</button>
      <div id="net-timestamp" style="color:var(--text-muted);font-family:var(--font-mono);font-size:.75rem;align-self:center"></div>
    </div>
    <div id="net-alert" style="display:none;margin-bottom:1rem;padding:.75rem 1rem;background:var(--red-dim);border:1px solid var(--red);border-radius:4px;color:var(--red);font-weight:700"></div>
    <div class="table-wrap">
      <table id="net-table">
        <thead><tr><th>PID</th><th>Protocol</th><th>Local Address</th><th>Remote Address</th><th>State</th><th>Process</th><th>Alert</th></tr></thead>
        <tbody id="net-tbody"><tr><td colspan="7" class="empty-state">Loading…</td></tr></tbody>
      </table>
    </div>`;

  pollNetwork();
  if (netInterval) clearInterval(netInterval);
  netInterval = setInterval(pollNetwork, 8000);
}

async function pollNetwork() {
  try {
    const data = await Network.poll();
    document.getElementById('net-timestamp').textContent = 'Last polled: ' + data.timestamp.replace('T', ' ').slice(0, 19) + ' UTC';

    let rows = '';
    let hasSuspicious = false;
    const suspiciousAlerts = [];

    for (const c of data.connections) {
      const stateClass = {
        ESTABLISHED: 'conn-established', LISTEN: 'conn-listen',
        TIME_WAIT: 'conn-time_wait'
      }[c.state] || '';

      const isSusp = !!c.ALERT;
      if (isSusp) { hasSuspicious = true; suspiciousAlerts.push(c.ALERT); }

      rows += `
        <tr style="${isSusp ? 'background:rgba(255,34,68,.06)' : ''}">
          <td>${c.pid}</td>
          <td><span style="color:var(--cyan)">${c.protocol}</span></td>
          <td class="mono">${c.local}</td>
          <td class="mono ${isSusp ? 'conn-suspicious' : ''}">${c.remote}</td>
          <td class="${stateClass || (isSusp ? 'conn-suspicious' : '')}">${c.state}</td>
          <td>${escHtml(c.process)}</td>
          <td>${isSusp ? `<span style="color:var(--red);font-weight:700">⚠ ${escHtml(c.ALERT)}</span>` : '—'}</td>
        </tr>`;
    }

    document.getElementById('net-tbody').innerHTML = rows;

    const alertEl = document.getElementById('net-alert');
    if (hasSuspicious) {
      alertEl.style.display = 'block';
      alertEl.textContent = '⚠ SUSPICIOUS CONNECTIONS DETECTED: ' + suspiciousAlerts.join(' | ');
    } else {
      alertEl.style.display = 'none';
    }
  } catch (err) {
    document.getElementById('net-tbody').innerHTML = `<tr><td colspan="7" style="color:var(--red)">${err.message}</td></tr>`;
  }
}


// ═══════════════════════════════════════════════════════════════
//  AUDIT LOGS
// ═══════════════════════════════════════════════════════════════

async function renderLogs() {
  const el = document.getElementById('page-logs');
  el.innerHTML = `
    <div class="page-header">
      <h1>AUDIT LOGS</h1>
      <p>Complete forensic audit trail</p>
    </div>
    <!-- Filters -->
    <div style="display:flex;gap:.75rem;flex-wrap:wrap;margin-bottom:1rem">
      <input  class="field-input" id="log-search"   placeholder="Search detail / target…" style="max-width:220px">
      <select class="field-select" id="log-action" style="max-width:140px">
        <option value="">All Actions</option>
        <option>upload</option><option>scan</option><option>hash</option>
        <option>login</option><option>register</option><option>report</option>
        <option>delete</option><option>network</option><option>metadata</option>
      </select>
      <select class="field-select" id="log-status" style="max-width:130px">
        <option value="">All Status</option>
        <option>success</option><option>warning</option><option>error</option>
      </select>
      <button class="btn-secondary" onclick="loadLogs(1)">Filter</button>
      <button class="btn-secondary" onclick="clearLogFilters()">Clear</button>
    </div>
    <div id="logs-wrap"><div class="empty-state">Loading…</div></div>
    <div id="logs-pagination" style="display:flex;gap:.5rem;margin-top:1rem;flex-wrap:wrap"></div>`;

  await loadLogs(1);
}

async function loadLogs(page = 1) {
  const params = {
    page, per_page: 20,
    search: (document.getElementById('log-search') || {}).value || '',
    action: (document.getElementById('log-action') || {}).value || '',
    status: (document.getElementById('log-status') || {}).value || '',
  };
  // Remove empty params
  Object.keys(params).forEach(k => params[k] === '' && delete params[k]);

  const wrap = document.getElementById('logs-wrap');
  wrap.innerHTML = '<div class="empty-state">Loading…</div>';

  try {
    const data  = await Logs.list(params);
    if (!data.logs.length) {
      wrap.innerHTML = '<div class="empty-state"><div class="empty-icon">≡</div>No logs match the current filter.</div>';
      return;
    }

    let rows = '';
    for (const lg of data.logs) {
      const cls = `log-${lg.action}`;
      rows += `
        <tr>
          <td class="mono" style="white-space:nowrap">${lg.created_at}</td>
          <td>${escHtml(lg.username || '—')}</td>
          <td><span class="${cls}" style="font-family:var(--font-head);font-size:.65rem;letter-spacing:1px">${lg.action.toUpperCase()}</span></td>
          <td>${escHtml(lg.target || '—')}</td>
          <td>${escHtml(lg.detail || '—')}</td>
          <td>${escHtml(lg.ip_address || '—')}</td>
          <td><span class="badge badge-${lg.status}">${lg.status.toUpperCase()}</span></td>
        </tr>`;
    }

    wrap.innerHTML = `
      <div class="table-wrap">
        <table>
          <thead><tr><th>Timestamp</th><th>User</th><th>Action</th><th>Target</th><th>Detail</th><th>IP</th><th>Status</th></tr></thead>
          <tbody>${rows}</tbody>
        </table>
      </div>
      <div style="color:var(--text-muted);font-size:.75rem;margin-top:.5rem">Showing ${data.logs.length} of ${data.total} entries</div>`;

    // Pagination
    const pagEl = document.getElementById('logs-pagination');
    pagEl.innerHTML = '';
    for (let p = 1; p <= data.pages; p++) {
      pagEl.insertAdjacentHTML('beforeend',
        `<button class="${p === page ? 'btn-green' : 'btn-secondary'}" onclick="loadLogs(${p})">${p}</button>`);
    }
  } catch (err) {
    wrap.innerHTML = `<div class="empty-state" style="color:var(--red)">Error: ${err.message}</div>`;
  }
}

function clearLogFilters() {
  ['log-search','log-action','log-status'].forEach(id => {
    const el = document.getElementById(id);
    if (el) el.value = '';
  });
  loadLogs(1);
}


// ═══════════════════════════════════════════════════════════════
//  REPORT GENERATOR
// ═══════════════════════════════════════════════════════════════

function renderReport() {
  const el = document.getElementById('page-report');
  el.innerHTML = `
    <div class="page-header">
      <h1>FORENSIC REPORTS</h1>
      <p>Generate downloadable HTML forensic reports</p>
    </div>
    <div class="card" style="max-width:540px">
      <div class="section-title" style="margin-top:0">Generate New Report</div>
      <div class="field-group">
        <label>Case ID</label>
        <input class="field-input" id="rpt-case-id" placeholder="CASE-001" value="CASE-001">
      </div>
      <p style="font-size:.8rem;color:var(--text-muted);margin-bottom:1rem">
        The report will include all evidence files for this case, their hashes, scan findings, and a full audit log export.
      </p>
      <button class="btn-primary" onclick="generateReport()">
        <span>GENERATE REPORT</span><span class="btn-arrow">→</span>
      </button>
      <div id="rpt-result" style="margin-top:1rem"></div>
    </div>

    <div class="card" style="max-width:540px;margin-top:1.5rem">
      <div class="section-title" style="margin-top:0">Instructions</div>
      <ul style="color:var(--text-muted);font-size:.85rem;padding-left:1.25rem;line-height:2">
        <li>Upload evidence files and assign a Case ID</li>
        <li>Run Scan and Hash on each file</li>
        <li>Enter the same Case ID above and click Generate</li>
        <li>Download the HTML report and open in browser</li>
        <li>Use browser Print → Save as PDF for a PDF copy</li>
      </ul>
    </div>`;
}

async function generateReport() {
  const caseId = document.getElementById('rpt-case-id').value.trim() || 'CASE-001';
  const res    = document.getElementById('rpt-result');
  res.innerHTML = '<span style="color:var(--text-muted)">Generating…</span>';

  try {
    const data = await Reports.generate(caseId);
    const url  = Reports.download(data.filename);
    res.innerHTML = `
      <div style="padding:.75rem;background:var(--green-dim);border:1px solid var(--green);border-radius:4px">
        <div style="color:var(--green);font-weight:700;margin-bottom:.35rem">✓ Report generated</div>
        <div style="font-size:.8rem;margin-bottom:.5rem">${escHtml(data.filename)}</div>
        <a href="${url}" target="_blank" class="btn-green" style="display:inline-block;padding:.4rem .85rem;text-decoration:none;border-radius:4px;border:1px solid var(--green);color:var(--green)">
          ⬇ Download Report
        </a>
      </div>`;
    toast('Report ready: ' + data.filename, 'ok');
  } catch (err) {
    res.innerHTML = `<span style="color:var(--red)">Error: ${err.message}</span>`;
    toast(err.message, 'err');
  }
}
