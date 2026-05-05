"""
CyberTrace Digital Forensics Toolkit
=====================================
Flask application factory and entry point.

Run:  python app.py          (development)
      gunicorn app:app       (production)
"""

import os
from flask import Flask, jsonify, send_from_directory
from flask_cors import CORS

# Local imports
from backend.models.database import init_db
from backend.routes.auth_routes import auth_bp
from backend.routes.file_routes import files_bp
from backend.routes.extra_routes import extra_bp


def create_app() -> Flask:
    """Application factory."""
    app = Flask(__name__, static_folder='frontend', static_url_path='')

    # ── CORS (allow all origins in dev; tighten in production) ─────────────
    CORS(app, resources={r'/api/*': {'origins': '*'}},
         supports_credentials=True)

    # ── Register Blueprints (all under /api) ────────────────────────────────
    app.register_blueprint(auth_bp,  url_prefix='/api')
    app.register_blueprint(files_bp, url_prefix='/api')
    app.register_blueprint(extra_bp, url_prefix='/api')

    # ── Serve frontend SPA ──────────────────────────────────────────────────
    @app.route('/', defaults={'path': ''})
    @app.route('/<path:path>')
    def serve_frontend(path):
        """Serve the React-free HTML frontend."""
        # If path points to a real static file, serve it
        full = os.path.join(app.static_folder, path)
        if path and os.path.exists(full):
            return send_from_directory(app.static_folder, path)
        # Otherwise fall back to index.html (SPA routing)
        return send_from_directory(app.static_folder, 'index.html')

    # ── Health check ────────────────────────────────────────────────────────
    @app.route('/api/health')
    def health():
        return jsonify({'status': 'ok', 'app': 'CyberTrace v1.0'})

    # ── Global error handlers ───────────────────────────────────────────────
    @app.errorhandler(404)
    def not_found(e):
        return jsonify({'error': 'Endpoint not found'}), 404

    @app.errorhandler(413)
    def too_large(e):
        return jsonify({'error': 'File too large'}), 413

    @app.errorhandler(500)
    def server_error(e):
        return jsonify({'error': 'Internal server error', 'detail': str(e)}), 500

    return app


# ── Bootstrap ────────────────────────────────────────────────────────────────

app = create_app()

if __name__ == '__main__':
    # Initialise SQLite tables on first run
    init_db()

    port = int(os.environ.get('PORT', 5000))
    debug = os.environ.get('FLASK_DEBUG', 'true').lower() == 'true'

    print(f"""
╔══════════════════════════════════════════════╗
║   CyberTrace Digital Forensics Toolkit       ║
║   http://localhost:{port}                      ║
╚══════════════════════════════════════════════╝
    """)

    app.run(host='0.0.0.0', port=port, debug=debug)
