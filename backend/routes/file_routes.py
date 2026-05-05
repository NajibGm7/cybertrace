"""
CyberTrace - File / Evidence Routes
POST /api/upload        – upload an evidence file
GET  /api/files         – list all uploaded files
GET  /api/files/<id>    – get file details
POST /api/scan/<id>     – run forensic scan on a file
POST /api/hash/<id>     – (re)generate hashes for a file
DELETE /api/files/<id>  – remove an evidence file
"""

import os
import uuid
import json
from flask import Blueprint, request, jsonify, send_from_directory
from ..models.database import get_db, log_action
from ..utils.auth import token_required
from ..utils.forensics import generate_hashes, scan_file, extract_metadata, detect_mime

files_bp = Blueprint('files', __name__)

UPLOADS_DIR = os.path.join(os.path.dirname(__file__), '../../uploads')
MAX_FILE_MB = 50

# Allowed MIME types – extend as needed
ALLOWED_MIMES = {
    'image/jpeg', 'image/png', 'image/gif', 'image/bmp', 'image/tiff',
    'application/pdf', 'text/plain', 'text/csv',
    'application/msword',
    'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
    'application/vnd.ms-excel',
    'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
    'application/zip', 'application/x-zip-compressed',
    'application/octet-stream',        # allow generic binary for forensics
    'application/x-executable',
    'application/x-dosexec',
}


def _safe_filename(original: str) -> str:
    """Return a UUID-based filename preserving the extension."""
    ext = os.path.splitext(original)[1][:10]  # cap extension length
    return f'{uuid.uuid4().hex}{ext}'


# ── Upload ────────────────────────────────────────────────────────────────────

@files_bp.route('/upload', methods=['POST'])
@token_required
def upload_file(current_user):
    """Receive and store an evidence file."""
    if 'file' not in request.files:
        return jsonify({'error': 'No file part in request'}), 400

    f        = request.files['file']
    case_id  = (request.form.get('case_id') or 'CASE-UNASSIGNED').strip()

    if f.filename == '':
        return jsonify({'error': 'No file selected'}), 400

    # Size check
    f.seek(0, 2)
    size = f.tell()
    f.seek(0)
    if size > MAX_FILE_MB * 1024 * 1024:
        return jsonify({'error': f'File exceeds {MAX_FILE_MB} MB limit'}), 413

    original_name = f.filename
    stored_name   = _safe_filename(original_name)

    os.makedirs(UPLOADS_DIR, exist_ok=True)
    save_path = os.path.join(UPLOADS_DIR, stored_name)
    f.save(save_path)

    # Basic metadata
    mime     = detect_mime(save_path, original_name)
    ext      = os.path.splitext(original_name)[1].lower()

    conn = get_db()
    conn.execute("""
        INSERT INTO files
            (case_id, original_name, stored_name, file_size, file_type, mime_type, uploaded_by)
        VALUES (?,?,?,?,?,?,?)
    """, (case_id, original_name, stored_name, size, ext, mime, current_user['sub']))
    conn.commit()
    file_id = conn.execute(
        "SELECT id FROM files WHERE stored_name=?", (stored_name,)
    ).fetchone()['id']
    conn.close()

    log_action(current_user['sub'], current_user['username'],
               'upload', original_name,
               f'Uploaded {original_name} ({size:,} bytes) to case {case_id}',
               request.remote_addr)

    return jsonify({
        'message':  'File uploaded successfully',
        'file_id':  file_id,
        'case_id':  case_id,
        'filename': original_name,
        'size':     size,
        'mime':     mime,
    }), 201


# ── List Files ────────────────────────────────────────────────────────────────

@files_bp.route('/files', methods=['GET'])
@token_required
def list_files(current_user):
    """Return all evidence files (optionally filtered by case_id)."""
    case_id = request.args.get('case_id')
    conn    = get_db()
    if case_id:
        rows = conn.execute(
            "SELECT * FROM files WHERE case_id=? ORDER BY uploaded_at DESC", (case_id,)
        ).fetchall()
    else:
        rows = conn.execute(
            "SELECT * FROM files ORDER BY uploaded_at DESC"
        ).fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])


# ── File Detail ───────────────────────────────────────────────────────────────

@files_bp.route('/files/<int:file_id>', methods=['GET'])
@token_required
def file_detail(current_user, file_id):
    """Return full details for a single file."""
    conn = get_db()
    row  = conn.execute("SELECT * FROM files WHERE id=?", (file_id,)).fetchone()
    conn.close()
    if not row:
        return jsonify({'error': 'File not found'}), 404
    return jsonify(dict(row))


# ── Scan ──────────────────────────────────────────────────────────────────────

@files_bp.route('/scan/<int:file_id>', methods=['POST'])
@token_required
def scan(current_user, file_id):
    """Run rule-based forensic scan on an uploaded file."""
    conn = get_db()
    row  = conn.execute("SELECT * FROM files WHERE id=?", (file_id,)).fetchone()
    if not row:
        conn.close()
        return jsonify({'error': 'File not found'}), 404

    filepath = os.path.join(UPLOADS_DIR, row['stored_name'])
    if not os.path.exists(filepath):
        conn.close()
        return jsonify({'error': 'Physical file missing from storage'}), 404

    result = scan_file(filepath, row['original_name'])

    conn.execute("""
        UPDATE files SET is_suspicious=?, analysis_result=? WHERE id=?
    """, (1 if result['is_suspicious'] else 0, json.dumps(result), file_id))
    conn.commit()
    conn.close()

    log_action(current_user['sub'], current_user['username'],
               'scan', row['original_name'],
               f"Scan complete – risk: {result['risk_level']}",
               request.remote_addr,
               'warning' if result['is_suspicious'] else 'success')

    return jsonify({'file_id': file_id, 'scan_result': result})


# ── Hash ──────────────────────────────────────────────────────────────────────

@files_bp.route('/hash/<int:file_id>', methods=['POST'])
@token_required
def compute_hash(current_user, file_id):
    """Compute / refresh cryptographic hashes for a file."""
    conn = get_db()
    row  = conn.execute("SELECT * FROM files WHERE id=?", (file_id,)).fetchone()
    if not row:
        conn.close()
        return jsonify({'error': 'File not found'}), 404

    filepath = os.path.join(UPLOADS_DIR, row['stored_name'])
    if not os.path.exists(filepath):
        conn.close()
        return jsonify({'error': 'Physical file missing from storage'}), 404

    hashes = generate_hashes(filepath)

    conn.execute("""
        UPDATE files SET md5_hash=?, sha1_hash=?, sha256_hash=? WHERE id=?
    """, (hashes['md5'], hashes['sha1'], hashes['sha256'], file_id))
    conn.commit()
    conn.close()

    log_action(current_user['sub'], current_user['username'],
               'hash', row['original_name'],
               f"Hashes computed: MD5={hashes['md5'][:12]}…",
               request.remote_addr)

    return jsonify({'file_id': file_id, 'hashes': hashes})


# ── Metadata ──────────────────────────────────────────────────────────────────

@files_bp.route('/metadata/<int:file_id>', methods=['GET'])
@token_required
def metadata(current_user, file_id):
    """Extract and return file metadata."""
    conn = get_db()
    row  = conn.execute("SELECT * FROM files WHERE id=?", (file_id,)).fetchone()
    conn.close()
    if not row:
        return jsonify({'error': 'File not found'}), 404

    filepath = os.path.join(UPLOADS_DIR, row['stored_name'])
    if not os.path.exists(filepath):
        return jsonify({'error': 'Physical file missing'}), 404

    meta = extract_metadata(filepath, row['original_name'])
    log_action(current_user['sub'], current_user['username'],
               'metadata', row['original_name'],
               'Metadata extracted', request.remote_addr)
    return jsonify(meta)


# ── Delete ────────────────────────────────────────────────────────────────────

@files_bp.route('/files/<int:file_id>', methods=['DELETE'])
@token_required
def delete_file(current_user, file_id):
    """Remove an evidence file."""
    conn = get_db()
    row  = conn.execute("SELECT * FROM files WHERE id=?", (file_id,)).fetchone()
    if not row:
        conn.close()
        return jsonify({'error': 'File not found'}), 404

    filepath = os.path.join(UPLOADS_DIR, row['stored_name'])
    if os.path.exists(filepath):
        os.remove(filepath)

    conn.execute("DELETE FROM files WHERE id=?", (file_id,))
    conn.commit()
    conn.close()

    log_action(current_user['sub'], current_user['username'],
               'delete', row['original_name'],
               f"Evidence file deleted: {row['original_name']}",
               request.remote_addr, 'warning')

    return jsonify({'message': f"File {row['original_name']} deleted"})
