"""
CyberTrace - Authentication Utilities
JWT token creation, verification, and password hashing via bcrypt.
"""

import jwt
import bcrypt
import os
from datetime import datetime, timedelta, timezone
from functools import wraps
from flask import request, jsonify

# Secret key – in production, load from environment variable
SECRET_KEY = os.environ.get('CYBERTRACE_SECRET', 'CT-dev-secret-change-in-prod-2024')
TOKEN_EXPIRY_HOURS = 8


# ── Password Hashing ─────────────────────────────────────────────────────────

def hash_password(plain_text: str) -> str:
    """Return bcrypt hash of the given password."""
    return bcrypt.hashpw(plain_text.encode('utf-8'), bcrypt.gensalt(rounds=12)).decode('utf-8')


def verify_password(plain_text: str, hashed: str) -> bool:
    """Compare a plain password against a stored bcrypt hash."""
    return bcrypt.checkpw(plain_text.encode('utf-8'), hashed.encode('utf-8'))


# ── JWT Tokens ───────────────────────────────────────────────────────────────

def create_token(user_id: int, username: str, role: str) -> str:
    """Generate a signed JWT that expires in TOKEN_EXPIRY_HOURS hours."""
    payload = {
        'sub': user_id,
        'username': username,
        'role': role,
        'iat': datetime.now(timezone.utc),
        'exp': datetime.now(timezone.utc) + timedelta(hours=TOKEN_EXPIRY_HOURS)
    }
    return jwt.encode(payload, SECRET_KEY, algorithm='HS256')


def decode_token(token: str) -> dict:
    """
    Decode and validate a JWT.
    Raises jwt.ExpiredSignatureError or jwt.InvalidTokenError on failure.
    """
    return jwt.decode(token, SECRET_KEY, algorithms=['HS256'])


# ── Route Decorator ──────────────────────────────────────────────────────────

def token_required(f):
    """
    Decorator for protected routes.
    Expects:  Authorization: Bearer <token>
    Injects `current_user` dict into the wrapped function.
    """
    @wraps(f)
    def decorated(*args, **kwargs):
        auth_header = request.headers.get('Authorization', '')
        if not auth_header.startswith('Bearer '):
            return jsonify({'error': 'Missing or malformed Authorization header'}), 401

        token = auth_header.split(' ', 1)[1]
        try:
            current_user = decode_token(token)
        except jwt.ExpiredSignatureError:
            return jsonify({'error': 'Token has expired – please log in again'}), 401
        except jwt.InvalidTokenError as e:
            return jsonify({'error': f'Invalid token: {e}'}), 401

        return f(current_user, *args, **kwargs)
    return decorated
