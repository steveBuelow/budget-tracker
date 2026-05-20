"""
app.py — Flask application factory
Security checklist:
  ✓ SECRET_KEY loaded from env; raises in production if missing
  ✓ SESSION_COOKIE_HTTPONLY  — JS cannot read the session cookie
  ✓ SESSION_COOKIE_SECURE    — HTTPS-only in production
  ✓ SESSION_COOKIE_SAMESITE  — blocks cross-site request forgery vectors
  ✓ debug=False in production (never expose Werkzeug debugger publicly)
  ✓ No credentials in source code
"""

import os
from datetime import timedelta

from dotenv import load_dotenv
from flask import Flask, jsonify

from routes import register_routes

load_dotenv()  # reads .env into os.environ; safe no-op when .env is absent


def create_app():
    app = Flask(__name__)

    # ── SECRET KEY ──────────────────────────────────────────────────────────
    # Used to sign session cookies.  A guessable key lets anyone forge a
    # session.  We fail loudly in production if it is not set.
    is_prod = os.getenv("FLASK_ENV") == "production"
    secret_key = os.getenv("SECRET_KEY")

    if is_prod and not secret_key:
        raise RuntimeError(
            "SECRET_KEY must be set in production. "
            "Generate one with: python -c \"import secrets; print(secrets.token_hex(32))\""
        )
    # Fall back to a random per-process key in dev so sessions reset on restart
    # (better than a hardcoded string that leaks into git history)
    app.config["SECRET_KEY"] = secret_key or os.urandom(32)

    # ── SESSION / COOKIE CONFIG ──────────────────────────────────────────────
    app.config["SESSION_PERMANENT"] = True
    app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(days=7)
    app.config.update(
        SESSION_COOKIE_HTTPONLY=True,   # JS cannot steal the cookie via XSS
        SESSION_COOKIE_SECURE=is_prod,  # Only send over HTTPS in production
        SESSION_COOKIE_SAMESITE="Lax",  # Blocks most CSRF vectors
    )

    # ── ERROR HANDLERS ───────────────────────────────────────────────────────
    @app.errorhandler(404)
    def not_found(_e):
        return jsonify({"error": "Route not found"}), 404

    @app.errorhandler(405)
    def method_not_allowed(_e):
        return jsonify({"error": "Method not allowed"}), 405

    @app.errorhandler(500)
    def server_error(_e):
        # Never expose internal tracebacks to the client
        return jsonify({"error": "Internal server error"}), 500

    register_routes(app)
    return app


app = create_app()

if __name__ == "__main__":
    # debug=True enables the Werkzeug reloader + interactive debugger.
    # That debugger allows arbitrary code execution — NEVER run with debug=True
    # on a public server.
    debug_mode = os.getenv("FLASK_ENV") != "production"
    app.run(debug=debug_mode)