"""
CyberTrace – Seed Data Script
==============================
Run this ONCE after first launch to populate the database with
sample users, files, and log entries for demonstration purposes.

Usage:
    python seed_data.py
"""

import os
import sys
import json
import hashlib
import sqlite3
from datetime import datetime, timedelta

# Make sure we can import from the project root
sys.path.insert(0, os.path.dirname(__file__))

from backend.models.database import init_db, get_db, log_action
from backend.utils.auth import hash_password

UPLOADS_DIR = os.path.join(os.path.dirname(__file__), 'uploads')
os.makedirs(UPLOADS_DIR, exist_ok=True)


def create_dummy_file(filename: str, content: bytes) -> str:
    """Write a dummy file to /uploads and return its stored name."""
    stored = filename  # Use readable name for demo
    path   = os.path.join(UPLOADS_DIR, stored)
    with open(path, 'wb') as f:
        f.write(content)
    return stored


def md5(data: bytes) -> str:
    return hashlib.md5(data).hexdigest()

def sha1(data: bytes) -> str:
    return hashlib.sha1(data).hexdigest()

def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def seed():
    print("[CyberTrace Seed] Initialising database…")
    init_db()

    conn = get_db()

    # ── Users ─────────────────────────────────────────────────────────────────
    users = [
        ('admin',      'admin@cybertrace.lab',    'Admin@1234',    'admin'),
        ('analyst01',  'analyst01@cybertrace.lab', 'Password123',  'analyst'),
        ('investigator','inv@cybertrace.lab',      'Secure#2024',  'analyst'),
    ]

    user_ids = {}
    for uname, email, pw, role in users:
        existing = conn.execute("SELECT id FROM users WHERE username=?", (uname,)).fetchone()
        if existing:
            user_ids[uname] = existing['id']
            print(f"  [skip] User '{uname}' already exists.")
            continue
        conn.execute(
            "INSERT INTO users (username, email, password, role) VALUES (?,?,?,?)",
            (uname, email, hash_password(pw), role)
        )
        conn.commit()
        row = conn.execute("SELECT id FROM users WHERE username=?", (uname,)).fetchone()
        user_ids[uname] = row['id']
        print(f"  [+] User created: {uname} / {pw}  (role: {role})")

    # ── Dummy evidence files ──────────────────────────────────────────────────
    files_data = [
        {
            'stored':   'sample_report.pdf',
            'original': 'financial_report_Q3.pdf',
            'content':  b'%PDF-1.4 Dummy PDF content for CyberTrace demo. Author: John Doe. Case: CASE-001.',
            'case_id':  'CASE-001',
            'type':     '.pdf',
            'mime':     'application/pdf',
            'suspicion': False,
            'findings': [],
            'risk':     'clean',
        },
        {
            'stored':   'suspect_script.bat',
            'original': 'update.bat',
            'content':  b'@echo off\ncmd.exe /c powershell -ExecutionPolicy Bypass -EncodedCommand base64_decode\nREG ADD HKEY_LOCAL_MACHINE\\SOFTWARE\\evil\n',
            'case_id':  'CASE-001',
            'type':     '.bat',
            'mime':     'application/octet-stream',
            'suspicion': True,
            'findings': [
                'Suspicious extension detected: .bat',
                'Suspicious string found: cmd.exe',
                'Suspicious string found: powershell',
                'Suspicious string found: base64_decode',
                'Suspicious string found: HKEY_LOCAL_MACHINE',
            ],
            'risk':     'high',
        },
        {
            'stored':   'evidence_photo.jpg',
            'original': 'crime_scene_photo_01.jpg',
            'content':  bytes([0xFF, 0xD8, 0xFF, 0xE0]) + b'\x00\x10JFIF\x00\x01' + b'\x00' * 100 + b'Dummy JPEG content',
            'case_id':  'CASE-001',
            'type':     '.jpg',
            'mime':     'image/jpeg',
            'suspicion': False,
            'findings': [],
            'risk':     'clean',
        },
        {
            'stored':   'malware_sample.exe',
            'original': 'svchost32.exe',
            'content':  b'MZ\x90\x00\x03\x00\x00\x00' + b'\x00' * 50 + b'WScript.Shell\x00CreateObject\x00socket.connect',
            'case_id':  'CASE-002',
            'type':     '.exe',
            'mime':     'application/x-dosexec',
            'suspicion': True,
            'findings': [
                'Suspicious extension detected: .exe',
                'Suspicious string found: WScript.Shell',
                'Suspicious string found: CreateObject',
                'Suspicious string found: socket.connect',
            ],
            'risk':     'high',
        },
        {
            'stored':   'witness_statement.docx',
            'original': 'witness_statement_2024.docx',
            'content':  b'PK\x03\x04' + b'\x00' * 20 + b'[Content_Types].xml' + b'Dummy DOCX content - witness statement for case CASE-002.',
            'case_id':  'CASE-002',
            'type':     '.docx',
            'mime':     'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
            'suspicion': False,
            'findings': [],
            'risk':     'low',
        },
        {
            'stored':   'network_capture.bin',
            'original': 'capture_2024_11_01.bin',
            'content':  b'\x7fELF\x02\x01\x01\x00' + b'\x00' * 56 + b'socket.connect\x00urllib.request',
            'case_id':  'CASE-002',
            'type':     '.bin',
            'mime':     'application/octet-stream',
            'suspicion': True,
            'findings': [
                'Suspicious extension detected: .bin',
                'Suspicious string found: socket.connect',
                'Suspicious string found: urllib.request',
            ],
            'risk':     'medium',
        },
    ]

    analyst_id = user_ids.get('analyst01', 1)
    inv_id     = user_ids.get('investigator', 1)

    for i, fd in enumerate(files_data):
        existing = conn.execute("SELECT id FROM files WHERE stored_name=?", (fd['stored'],)).fetchone()
        if existing:
            print(f"  [skip] File '{fd['original']}' already seeded.")
            continue

        content = fd['content']
        create_dummy_file(fd['stored'], content)

        analysis = json.dumps({
            'is_suspicious':     fd['suspicion'],
            'risk_level':        fd['risk'],
            'findings':          fd['findings'],
            'signature_matches': [],
            'scanned_at':        datetime.utcnow().isoformat(),
        })

        uploader = analyst_id if i % 2 == 0 else inv_id

        conn.execute("""
            INSERT INTO files
              (case_id, original_name, stored_name, file_size, file_type, mime_type,
               md5_hash, sha1_hash, sha256_hash, is_suspicious, analysis_result, uploaded_by)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?)
        """, (
            fd['case_id'], fd['original'], fd['stored'], len(content),
            fd['type'], fd['mime'],
            md5(content), sha1(content), sha256(content),
            1 if fd['suspicion'] else 0,
            analysis, uploader
        ))
        conn.commit()
        print(f"  [+] Evidence: {fd['original']}  [{fd['risk'].upper()}]")

    # ── Log entries ───────────────────────────────────────────────────────────
    sample_logs = [
        (user_ids.get('admin',1),       'admin',        'login',    'admin',                    'Successful login',                        '192.168.1.10', 'success'),
        (user_ids.get('analyst01',1),   'analyst01',    'login',    'analyst01',                'Successful login',                        '192.168.1.42', 'success'),
        (user_ids.get('analyst01',1),   'analyst01',    'upload',   'financial_report_Q3.pdf',  'Uploaded financial_report_Q3.pdf to CASE-001', '192.168.1.42', 'success'),
        (user_ids.get('analyst01',1),   'analyst01',    'scan',     'financial_report_Q3.pdf',  'Scan complete – risk: clean',             '192.168.1.42', 'success'),
        (user_ids.get('analyst01',1),   'analyst01',    'hash',     'financial_report_Q3.pdf',  'Hashes computed: MD5=a1b2c3…',            '192.168.1.42', 'success'),
        (user_ids.get('analyst01',1),   'analyst01',    'upload',   'update.bat',               'Uploaded update.bat to CASE-001',         '192.168.1.42', 'success'),
        (user_ids.get('analyst01',1),   'analyst01',    'scan',     'update.bat',               'Scan complete – risk: high',              '192.168.1.42', 'warning'),
        (user_ids.get('investigator',1),'investigator', 'login',    'investigator',             'Successful login',                        '10.0.0.55',    'success'),
        (user_ids.get('investigator',1),'investigator', 'upload',   'svchost32.exe',            'Uploaded svchost32.exe to CASE-002',      '10.0.0.55',    'success'),
        (user_ids.get('investigator',1),'investigator', 'scan',     'svchost32.exe',            'Scan complete – risk: high',              '10.0.0.55',    'warning'),
        (user_ids.get('investigator',1),'investigator', 'hash',     'svchost32.exe',            'Hashes computed: MD5=deadbeef…',          '10.0.0.55',    'success'),
        (user_ids.get('admin',1),       'admin',        'report',   'CASE-001',                 'Report generated: report_CASE-001.html',  '192.168.1.10', 'success'),
        (user_ids.get('analyst01',1),   'analyst01',    'network',  'monitor',                  'Network monitor polled',                  '192.168.1.42', 'success'),
        (user_ids.get('analyst01',1),   'analyst01',    'login',    'analyst01',                'Failed login attempt',                    '203.0.113.5',  'error'),
        (user_ids.get('admin',1),       'admin',        'metadata', 'crime_scene_photo_01.jpg', 'Metadata extracted',                      '192.168.1.10', 'success'),
    ]

    existing_log_count = conn.execute("SELECT COUNT(*) FROM logs").fetchone()[0]
    if existing_log_count > 0:
        print(f"  [skip] {existing_log_count} log entries already exist.")
    else:
        for lg in sample_logs:
            conn.execute("""
                INSERT INTO logs (user_id, username, action, target, detail, ip_address, status)
                VALUES (?,?,?,?,?,?,?)
            """, lg)
        conn.commit()
        print(f"  [+] {len(sample_logs)} log entries inserted.")

    conn.close()

    print("""
╔══════════════════════════════════════════════════════════╗
║         CyberTrace Seed Data – Complete!                 ║
╠══════════════════════════════════════════════════════════╣
║  Test Accounts:                                          ║
║    admin        / Admin@1234    (admin role)             ║
║    analyst01    / Password123   (analyst role)           ║
║    investigator / Secure#2024   (analyst role)           ║
║                                                          ║
║  Sample Cases:                                           ║
║    CASE-001: 3 files (1 high risk)                       ║
║    CASE-002: 3 files (2 suspicious)                      ║
║                                                          ║
║  Run:  python app.py  then open http://localhost:5000    ║
╚══════════════════════════════════════════════════════════╝
""")


if __name__ == '__main__':
    seed()
