"""
CyberTrace - Report Generator
Produces a professional forensic HTML report (downloadable / printable).
PDF export can be done via browser Print → Save as PDF.
"""

import os
import json
from datetime import datetime


REPORTS_DIR = os.path.join(os.path.dirname(__file__), '../../reports')


def generate_html_report(case_id: str, analyst: str, files: list, logs: list) -> str:
    """
    Build an HTML forensic report and save it to /reports/.
    Returns the absolute path to the saved file.
    """
    os.makedirs(REPORTS_DIR, exist_ok=True)
    timestamp  = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
    filename   = f'report_{case_id}_{timestamp}.html'
    filepath   = os.path.join(REPORTS_DIR, filename)

    # ── File rows ──────────────────────────────────────────────────────────
    file_rows = ''
    for f in files:
        analysis = {}
        if f['analysis_result']:
            try:
                analysis = json.loads(f['analysis_result'])
            except Exception:
                pass

        risk        = analysis.get('risk_level', 'unknown')
        risk_colour = {'clean': '#00ff88', 'low': '#ffd700',
                       'medium': '#ff8c00', 'high': '#ff2244',
                       'unknown': '#aaa'}.get(risk, '#aaa')

        findings_html = ''
        for finding in analysis.get('findings', []):
            findings_html += f'<li>{finding}</li>'
        for sig in analysis.get('signature_matches', []):
            findings_html += f'<li>⚠ Signature: {sig}</li>'
        if not findings_html:
            findings_html = '<li>No suspicious findings</li>'

        file_rows += f"""
        <tr>
          <td>{f['id']}</td>
          <td>{f['original_name']}</td>
          <td>{f['file_type'] or 'Unknown'}</td>
          <td>{f['file_size']:,} bytes</td>
          <td style="color:{risk_colour};font-weight:700">{risk.upper()}</td>
          <td><code>{f['md5_hash'] or '—'}</code></td>
          <td><code>{f['sha256_hash'] or '—'}</code></td>
          <td><ul style="margin:0;padding-left:1rem">{findings_html}</ul></td>
        </tr>"""

    # ── Log rows ──────────────────────────────────────────────────────────
    log_rows = ''
    for lg in logs[-50:]:   # Last 50 log entries
        status_colour = {'success': '#00ff88', 'warning': '#ffd700',
                         'error': '#ff2244'}.get(lg['status'], '#aaa')
        log_rows += f"""
        <tr>
          <td>{lg['created_at']}</td>
          <td>{lg['username'] or '—'}</td>
          <td><span style="color:#00d4ff">{lg['action'].upper()}</span></td>
          <td>{lg['target'] or '—'}</td>
          <td>{lg['detail'] or '—'}</td>
          <td style="color:{status_colour}">{lg['status'].upper()}</td>
        </tr>"""

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>CyberTrace Forensic Report – {case_id}</title>
<style>
  @import url('https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Exo+2:wght@300;600;800&display=swap');
  :root {{
    --bg: #050a0f; --surface: #0d1b2a; --border: #1e3a5f;
    --cyan: #00d4ff; --green: #00ff88; --red: #ff2244;
    --text: #c8d8e8; --muted: #5a7a9a;
  }}
  * {{ box-sizing:border-box; margin:0; padding:0 }}
  body {{ background:var(--bg); color:var(--text); font-family:'Exo 2',sans-serif;
         font-size:14px; line-height:1.6; padding:2rem }}
  h1 {{ font-size:2rem; color:var(--cyan); font-weight:800; letter-spacing:4px;
        text-transform:uppercase; border-bottom:2px solid var(--border); padding-bottom:1rem }}
  h2 {{ font-size:1.1rem; color:var(--cyan); text-transform:uppercase;
        letter-spacing:2px; margin:2rem 0 1rem; border-left:3px solid var(--cyan);
        padding-left:.75rem }}
  .meta-grid {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(200px,1fr));
                gap:1rem; margin:1rem 0 }}
  .meta-card {{ background:var(--surface); border:1px solid var(--border);
                padding:1rem; border-radius:4px }}
  .meta-card .label {{ color:var(--muted); font-size:.75rem; text-transform:uppercase;
                       letter-spacing:1px }}
  .meta-card .value {{ color:var(--green); font-family:'Share Tech Mono',monospace;
                       font-size:1rem; margin-top:.25rem }}
  table {{ width:100%; border-collapse:collapse; font-size:.8rem; margin-top:.5rem }}
  th {{ background:var(--border); color:var(--cyan); text-align:left;
        padding:.5rem .75rem; text-transform:uppercase; letter-spacing:1px; font-size:.7rem }}
  td {{ padding:.5rem .75rem; border-bottom:1px solid #0d1b2a; vertical-align:top }}
  tr:hover td {{ background:rgba(0,212,255,.04) }}
  code {{ font-family:'Share Tech Mono',monospace; font-size:.75rem;
          word-break:break-all; color:#7ec8e3 }}
  .badge {{ display:inline-block; padding:.15rem .5rem; border-radius:3px;
            font-size:.7rem; font-weight:700; letter-spacing:1px }}
  .footer {{ margin-top:3rem; padding-top:1rem; border-top:1px solid var(--border);
             color:var(--muted); font-size:.75rem; text-align:center }}
  @media print {{
    body {{ background:#fff; color:#000 }}
    h1,h2 {{ color:#003366 }}
    td,th {{ color:#000; border-color:#ccc }}
    code {{ color:#003366 }}
    .meta-card {{ border:1px solid #ccc }}
    .meta-card .value {{ color:#003366 }}
  }}
</style>
</head>
<body>

<h1>🔍 CyberTrace Digital Forensics Report</h1>

<div class="meta-grid">
  <div class="meta-card">
    <div class="label">Case ID</div>
    <div class="value">{case_id}</div>
  </div>
  <div class="meta-card">
    <div class="label">Lead Analyst</div>
    <div class="value">{analyst}</div>
  </div>
  <div class="meta-card">
    <div class="label">Report Generated</div>
    <div class="value">{datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}</div>
  </div>
  <div class="meta-card">
    <div class="label">Evidence Items</div>
    <div class="value">{len(files)}</div>
  </div>
  <div class="meta-card">
    <div class="label">Log Entries</div>
    <div class="value">{len(logs)}</div>
  </div>
  <div class="meta-card">
    <div class="label">Tool</div>
    <div class="value">CyberTrace v1.0</div>
  </div>
</div>

<h2>Evidence Files</h2>
<table>
  <thead>
    <tr>
      <th>#</th><th>Filename</th><th>Type</th><th>Size</th>
      <th>Risk</th><th>MD5</th><th>SHA-256</th><th>Findings</th>
    </tr>
  </thead>
  <tbody>{file_rows or '<tr><td colspan="8">No files recorded.</td></tr>'}</tbody>
</table>

<h2>Audit Log (Last 50 Entries)</h2>
<table>
  <thead>
    <tr><th>Timestamp</th><th>User</th><th>Action</th><th>Target</th><th>Detail</th><th>Status</th></tr>
  </thead>
  <tbody>{log_rows or '<tr><td colspan="6">No logs available.</td></tr>'}</tbody>
</table>

<div class="footer">
  <p>This report was generated automatically by CyberTrace Digital Forensics Toolkit.</p>
  <p>CONFIDENTIAL – For authorised personnel only. Handle in accordance with your organisation's evidence policy.</p>
</div>
</body>
</html>"""

    with open(filepath, 'w', encoding='utf-8') as fh:
        fh.write(html)

    return filepath, filename
