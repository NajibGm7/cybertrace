"""
CyberTrace - Logs, Network Monitor & Report Routes

GET  /api/logs           – paginated audit log with optional filters
GET  /api/network        – simulated active network connections
POST /api/report         – generate HTML forensic report
GET  /api/report/<name>  – download a previously generated report
GET  /api/stats          – dashboard summary statistics
"""

import os
import json
import random
import time
from datetime import datetime, timedelta
from flask import Blueprint, request, jsonify, send_from_directory

from ..models.database import get_db, log_action
from ..utils.auth import token_required
from ..utils.reporter import generate_html_report

extra_bp = Blueprint('extra', __name__)

REPORTS_DIR = os.path.abspath(
    os.path.join(os.path.dirname(__file__), '../../reports')
)


# ── Audit Logs ────────────────────────────────────────────────────────────────

@extra_bp.route('/logs', methods=['GET'])
@token_required
def get_logs(current_user):
    """
    Return paginated audit logs.
    Query params: page, per_page, action, username, status, search
    """
    page     = max(1, int(request.args.get('page', 1)))
    per_page = min(100, max(1, int(request.args.get('per_page', 25))))
    action   = request.args.get('action', '').strip()
    username = request.args.get('username', '').strip()
    status   = request.args.get('status', '').strip()
    search   = request.args.get('search', '').strip()

    conn     = get_db()
    clauses  = []
    params   = []

    if action:
        clauses.append("action = ?");   params.append(action)
    if username:
        clauses.append("username LIKE ?"); params.append(f'%{username}%')
    if status:
        clauses.append("status = ?");   params.append(status)
    if search:
        clauses.append("(detail LIKE ? OR target LIKE ?)");
        params += [f'%{search}%', f'%{search}%']

    where = ("WHERE " + " AND ".join(clauses)) if clauses else ""

    total = conn.execute(f"SELECT COUNT(*) FROM logs {where}", params).fetchone()[0]
    rows  = conn.execute(
        f"SELECT * FROM logs {where} ORDER BY created_at DESC LIMIT ? OFFSET ?",
        params + [per_page, (page - 1) * per_page]
    ).fetchall()
    conn.close()

    return jsonify({
        'total':    total,
        'page':     page,
        'per_page': per_page,
        'pages':    (total + per_page - 1) // per_page,
        'logs':     [dict(r) for r in rows],
    })


# ── Simulated Network Monitor ─────────────────────────────────────────────────

# Static base list – augmented with random "live" noise each request
_BASE_CONNECTIONS = [
    {'pid': 412,  'protocol': 'TCP', 'local': '0.0.0.0:80',    'remote': '0.0.0.0:0',          'state': 'LISTEN',       'process': 'nginx'},
    {'pid': 412,  'protocol': 'TCP', 'local': '0.0.0.0:443',   'remote': '0.0.0.0:0',          'state': 'LISTEN',       'process': 'nginx'},
    {'pid': 5001, 'protocol': 'TCP', 'local': '127.0.0.1:5000','remote': '0.0.0.0:0',          'state': 'LISTEN',       'process': 'python (Flask)'},
    {'pid': 1,    'protocol': 'TCP', 'local': '127.0.0.1:631', 'remote': '0.0.0.0:0',          'state': 'LISTEN',       'process': 'cupsd'},
    {'pid': 888,  'protocol': 'UDP', 'local': '0.0.0.0:5353',  'remote': '0.0.0.0:0',          'state': '—',            'process': 'mDNS'},
    {'pid': 302,  'protocol': 'TCP', 'local': '10.0.0.5:52134','remote': '142.250.80.46:443',   'state': 'ESTABLISHED',  'process': 'chrome'},
    {'pid': 302,  'protocol': 'TCP', 'local': '10.0.0.5:52140','remote': '13.107.42.14:443',    'state': 'ESTABLISHED',  'process': 'chrome'},
    {'pid': 718,  'protocol': 'TCP', 'local': '10.0.0.5:48822','remote': '52.95.121.75:443',    'state': 'ESTABLISHED',  'process': 'aws-cli'},
    {'pid': 214,  'protocol': 'TCP', 'local': '10.0.0.5:60001','remote': '185.199.108.133:443', 'state': 'TIME_WAIT',    'process': 'curl'},
]

_SUSPICIOUS_PORTS = [4444, 1337, 31337, 12345, 6666, 9001]


@extra_bp.route('/network', methods=['GET'])
@token_required
def network_monitor(current_user):
    """Return simulated network connections with optional randomised noise."""
    connections = list(_BASE_CONNECTIONS)

    # Randomly inject a suspicious connection ~30 % of the time
    if random.random() < 0.30:
        port = random.choice(_SUSPICIOUS_PORTS)
        connections.append({
            'pid':      random.randint(2000, 9999),
            'protocol': 'TCP',
            'local':    f'10.0.0.5:{random.randint(50000,65000)}',
            'remote':   f'{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}:{port}',
            'state':    'ESTABLISHED',
            'process':  '??? (UNKNOWN)',
            'ALERT':    f'Suspicious port {port} detected!',
        })

    log_action(current_user['sub'], current_user['username'],
               'network', 'monitor',
               'Network monitor polled', request.remote_addr)

    return jsonify({
        'timestamp':   datetime.utcnow().isoformat(),
        'connections': connections,
        'total':       len(connections),
    })


# ── Report Generator ──────────────────────────────────────────────────────────

@extra_bp.route('/report', methods=['POST'])
@token_required
def create_report(current_user):
    """Generate a full forensic HTML report for a given case."""
    data    = request.get_json(silent=True) or {}
    case_id = (data.get('case_id') or 'CASE-UNASSIGNED').strip()

    conn  = get_db()
    files = conn.execute(
        "SELECT * FROM files WHERE case_id=? ORDER BY uploaded_at", (case_id,)
    ).fetchall()
    logs  = conn.execute(
        "SELECT * FROM logs ORDER BY created_at"
    ).fetchall()
    conn.close()

    filepath, filename = generate_html_report(
        case_id   = case_id,
        analyst   = current_user['username'],
        files     = [dict(f) for f in files],
        logs      = [dict(l) for l in logs],
    )

    log_action(current_user['sub'], current_user['username'],
               'report', case_id,
               f'Report generated: {filename}', request.remote_addr)

    return jsonify({
        'message':  'Report generated',
        'filename': filename,
        'download': f'/api/report/{filename}',
    })


@extra_bp.route('/report/<filename>', methods=['GET'])
def download_report(filename):
    """Serve a previously generated report file."""
    # Sanitise – reject path traversal
    if '..' in filename or '/' in filename:
        return jsonify({'error': 'Invalid filename'}), 400
    return send_from_directory(REPORTS_DIR, filename, as_attachment=True)


# ── Dashboard Statistics ──────────────────────────────────────────────────────

@extra_bp.route('/stats', methods=['GET'])
@token_required
def stats(current_user):
    """Return counts for the dashboard overview cards."""
    conn = get_db()
    total_files      = conn.execute("SELECT COUNT(*) FROM files").fetchone()[0]
    suspicious_files = conn.execute("SELECT COUNT(*) FROM files WHERE is_suspicious=1").fetchone()[0]
    total_logs       = conn.execute("SELECT COUNT(*) FROM logs").fetchone()[0]
    total_users      = conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]
    recent_uploads   = conn.execute(
        "SELECT COUNT(*) FROM files WHERE uploaded_at >= datetime('now','-24 hours')"
    ).fetchone()[0]

    # Action breakdown for mini chart
    action_counts = conn.execute("""
        SELECT action, COUNT(*) as cnt FROM logs GROUP BY action ORDER BY cnt DESC
    """).fetchall()

    conn.close()

    return jsonify({
        'total_files':      total_files,
        'suspicious_files': suspicious_files,
        'total_logs':       total_logs,
        'total_users':      total_users,
        'recent_uploads':   recent_uploads,
        'action_breakdown': [dict(r) for r in action_counts],
    })
