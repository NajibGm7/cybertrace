"""
CyberTrace - Database Models
Handles SQLite database setup and schema for Users, Files, and Logs.
"""

import sqlite3
import os

# Path to the SQLite database file
DB_PATH = os.path.join(os.path.dirname(__file__), '../../database/cybertrace.db')


def get_db():
    """Open a new database connection."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row  # Return rows as dict-like objects
    conn.execute("PRAGMA journal_mode=WAL")  # Better concurrency
    return conn


def init_db():
    """
    Initialize the database and create tables if they don't exist.
    Called on app startup.
    """
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = get_db()
    cursor = conn.cursor()

    # ── Users Table ──────────────────────────────────────────────
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            username    TEXT    NOT NULL UNIQUE,
            email       TEXT    NOT NULL UNIQUE,
            password    TEXT    NOT NULL,          -- bcrypt hash
            role        TEXT    DEFAULT 'analyst', -- analyst | admin
            created_at  TEXT    DEFAULT (datetime('now'))
        )
    """)

    # ── Files (Evidence) Table ───────────────────────────────────
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS files (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            case_id         TEXT    NOT NULL,
            original_name   TEXT    NOT NULL,
            stored_name     TEXT    NOT NULL,      -- UUID-based safe filename
            file_size       INTEGER,
            file_type       TEXT,
            mime_type       TEXT,
            md5_hash        TEXT,
            sha1_hash       TEXT,
            sha256_hash     TEXT,
            is_suspicious   INTEGER DEFAULT 0,     -- Boolean flag
            analysis_result TEXT,                  -- JSON blob of findings
            uploaded_by     INTEGER REFERENCES users(id),
            uploaded_at     TEXT    DEFAULT (datetime('now'))
        )
    """)

    # ── Logs (Audit Trail) Table ─────────────────────────────────
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS logs (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id     INTEGER REFERENCES users(id),
            username    TEXT,
            action      TEXT    NOT NULL,          -- upload | scan | hash | login | report
            target      TEXT,                      -- filename or resource affected
            detail      TEXT,                      -- human-readable description
            ip_address  TEXT,
            status      TEXT    DEFAULT 'success', -- success | warning | error
            created_at  TEXT    DEFAULT (datetime('now'))
        )
    """)

    conn.commit()
    conn.close()
    print("[CyberTrace] Database initialised.")


def log_action(user_id, username, action, target, detail, ip_address="unknown", status="success"):
    """
    Convenience function to insert a log entry from anywhere in the app.
    """
    conn = get_db()
    conn.execute("""
        INSERT INTO logs (user_id, username, action, target, detail, ip_address, status)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (user_id, username, action, target, detail, ip_address, status))
    conn.commit()
    conn.close()
