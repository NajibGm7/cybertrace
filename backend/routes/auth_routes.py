"""
CyberTrace - Authentication Routes
POST /api/register  – create a new analyst account
POST /api/login     – authenticate and receive JWT
GET  /api/me        – return current user profile (protected)
"""

from flask import Blueprint, request, jsonify
from ..models.database import get_db, log_action
from ..utils.auth import hash_password, verify_password, create_token, token_required
import re

auth_bp = Blueprint('auth', __name__)


def _valid_email(email: str) -> bool:
    return bool(re.match(r'^[^@]+@[^@]+\.[^@]+$', email))


# ── Register ─────────────────────────────────────────────────────────────────

@auth_bp.route('/register', methods=['POST'])
def register():
    """Register a new user account."""
    data = request.get_json(silent=True) or {}
    username = (data.get('username') or '').strip()
    email    = (data.get('email')    or '').strip().lower()
    password = (data.get('password') or '').strip()

    # Input validation
    if not username or not email or not password:
        return jsonify({'error': 'username, email and password are required'}), 400
    if len(username) < 3:
        return jsonify({'error': 'Username must be at least 3 characters'}), 400
    if not _valid_email(email):
        return jsonify({'error': 'Invalid email address'}), 400
    if len(password) < 8:
        return jsonify({'error': 'Password must be at least 8 characters'}), 400

    hashed = hash_password(password)

    conn = get_db()
    try:
        conn.execute(
            "INSERT INTO users (username, email, password) VALUES (?,?,?)",
            (username, email, hashed)
        )
        conn.commit()
        user_id = conn.execute(
            "SELECT id FROM users WHERE username=?", (username,)
        ).fetchone()['id']
    except Exception as e:
        conn.close()
        if 'UNIQUE' in str(e):
            return jsonify({'error': 'Username or email already exists'}), 409
        return jsonify({'error': 'Registration failed'}), 500
    finally:
        conn.close()

    log_action(user_id, username, 'register', username,
               f'New account created: {username}',
               request.remote_addr)

    return jsonify({'message': f'Account created for {username}. Please log in.'}), 201


# ── Login ─────────────────────────────────────────────────────────────────────

@auth_bp.route('/login', methods=['POST'])
def login():
    """Authenticate user and return JWT."""
    data     = request.get_json(silent=True) or {}
    username = (data.get('username') or '').strip()
    password = (data.get('password') or '').strip()

    if not username or not password:
        return jsonify({'error': 'username and password are required'}), 400

    conn = get_db()
    row  = conn.execute(
        "SELECT id, username, email, password, role FROM users WHERE username=?",
        (username,)
    ).fetchone()
    conn.close()

    if not row or not verify_password(password, row['password']):
        log_action(None, username, 'login', username,
                   'Failed login attempt', request.remote_addr, 'error')
        return jsonify({'error': 'Invalid credentials'}), 401

    token = create_token(row['id'], row['username'], row['role'])
    log_action(row['id'], username, 'login', username,
               'Successful login', request.remote_addr)

    return jsonify({
        'token':    token,
        'username': row['username'],
        'email':    row['email'],
        'role':     row['role'],
    })


# ── Profile ───────────────────────────────────────────────────────────────────

@auth_bp.route('/me', methods=['GET'])
@token_required
def me(current_user):
    """Return the current user's profile."""
    conn = get_db()
    row  = conn.execute(
        "SELECT id, username, email, role, created_at FROM users WHERE id=?",
        (current_user['sub'],)
    ).fetchone()
    conn.close()

    if not row:
        return jsonify({'error': 'User not found'}), 404

    return jsonify(dict(row))
