"""
routes.py — All Flask route handlers
Security / validation checklist:
  ✓ All string inputs stripped of leading/trailing whitespace
  ✓ HTML tags removed from free-text fields (prevents stored XSS)
  ✓ Field length limits enforced server-side (can't be bypassed like JS checks)
  ✓ Category validated against an explicit allowlist
  ✓ Month format validated with a regex (prevents path traversal in DELETE /net-worth/<month>)
  ✓ Numeric fields validated and bounded
  ✓ All DB writes use parameterised queries (in models.py) — no SQL injection
  ✓ Every mutating route requires an authenticated session
  ✓ Error messages never reveal internal state to the client
"""

import re

import psycopg2
from flask import jsonify, render_template, request, session

from models import (
    create_expense,
    create_net_worth_entry,
    create_user,
    delete_expense,
    delete_net_worth_entry,
    find_user,
    get_expenses,
    get_net_worth_history,
    get_user_by_id,
    update_expense,
)

# ── CONSTANTS / ALLOWLISTS ──────────────────────────────────────────────────

ALLOWED_CATEGORIES = {
    "Food", "Housing", "Transport", "Health",
    "Entertainment", "Shopping", "Utilities",
    "Education", "Travel", "Other",
}

# Regex: exactly YYYY-MM, e.g. "2025-04"
MONTH_RE = re.compile(r"^\d{4}-(0[1-9]|1[0-2])$")

# Conservative upper bound — prevents absurd values slipping into the DB
MAX_AMOUNT = 1_000_000_000  # $1 billion

# Field length limits
MAX_USERNAME_LEN = 30
MIN_USERNAME_LEN = 3
MAX_PASSWORD_LEN = 128
MIN_PASSWORD_LEN = 8
MAX_NAME_LEN     = 100
MAX_NOTES_LEN    = 500

# ── HELPERS ─────────────────────────────────────────────────────────────────

_DANGEROUS_BLOCK_RE = re.compile(
    r"<(script|style|iframe|object|embed)[^>]*>.*?</\1>",
    re.IGNORECASE | re.DOTALL,
)
_TAG_RE = re.compile(r"<[^>]+>")


def strip_tags(value: str) -> str:
    """
    Remove HTML from a string to prevent stored XSS.
    Two-pass approach:
      1. Remove dangerous block elements *and their contents* (script, style, …)
      2. Strip any remaining HTML tags
    """
    value = _DANGEROUS_BLOCK_RE.sub("", value)  # remove <script>…</script> etc.
    return _TAG_RE.sub("", value)               # strip remaining tags


def clean_str(value, max_len: int) -> str:
    """Strip whitespace + HTML tags, then enforce length cap."""
    value = str(value or "").strip()
    value = strip_tags(value)
    return value[:max_len]


def auth_required():
    """Return (user_id, None) if authenticated, else (None, error_response)."""
    user_id = session.get("user_id")
    if not user_id:
        return None, (jsonify({"error": "Not authenticated"}), 401)
    return user_id, None


# ── ROUTE REGISTRATION ───────────────────────────────────────────────────────

def register_routes(app):

    # ── INDEX ────────────────────────────────────────────────────────────────
    @app.route("/")
    def index():
        return render_template("index.html")

    # ── AUTH ─────────────────────────────────────────────────────────────────

    @app.route("/signup", methods=["POST"])
    def signup():
        data = request.get_json(silent=True) or {}

        username = clean_str(data.get("username"), MAX_USERNAME_LEN)
        password = str(data.get("password") or "")

        # --- Validate username ---
        if len(username) < MIN_USERNAME_LEN:
            return jsonify({"error": f"Username must be at least {MIN_USERNAME_LEN} characters"}), 400
        if not re.match(r"^[A-Za-z0-9_]+$", username):
            return jsonify({"error": "Username may only contain letters, numbers, and underscores"}), 400

        # --- Validate password ---
        if len(password) < MIN_PASSWORD_LEN:
            return jsonify({"error": f"Password must be at least {MIN_PASSWORD_LEN} characters"}), 400
        if len(password) > MAX_PASSWORD_LEN:
            return jsonify({"error": "Password is too long"}), 400

        try:
            create_user(username, password)
            return jsonify({"message": "Account created successfully!"}), 201
        except psycopg2.IntegrityError:
            return jsonify({"error": "That username is already taken"}), 409
        except Exception:
            return jsonify({"error": "Could not create account"}), 500

    @app.route("/login", methods=["POST"])
    def login():
        data = request.get_json(silent=True)
        if not data:
            return jsonify({"error": "Request must be JSON"}), 400

        username = clean_str(data.get("username"), MAX_USERNAME_LEN)
        password = str(data.get("password") or "")

        if not username or not password:
            return jsonify({"error": "Username and password are required"}), 400

        result = find_user(username, password)
        if result:
            session.permanent = True
            session["user_id"]  = result["id"]
            session["username"] = result["username"]
            return jsonify({"status": "Logged in successfully!"}), 200

        # Intentionally vague — don't reveal which field was wrong
        return jsonify({"error": "Invalid credentials"}), 401

    @app.route("/logout", methods=["POST"])
    def logout():
        session.clear()
        return jsonify({"status": "Logged out"}), 200

    @app.route("/me")
    def me():
        user_id, err = auth_required()
        if err:
            return err
        user = get_user_by_id(user_id)
        if not user:
            return jsonify({"error": "User not found"}), 404
        return jsonify({"id": user["id"], "username": user["username"]}), 200

    # ── EXPENSES ─────────────────────────────────────────────────────────────

    @app.route("/expenses", methods=["GET"])
    def list_expenses():
        user_id, err = auth_required()
        if err:
            return err
        rows = get_expenses(user_id)
        return jsonify(rows), 200

    @app.route("/expenses", methods=["POST"])
    def add_expense():
        user_id, err = auth_required()
        if err:
            return err

        data     = request.get_json(silent=True) or {}
        name, amount, category, notes = _parse_expense(data)

        # name is empty string on validation failure (we set it to "" sentinel)
        err_resp = _validate_expense(name, amount, category)
        if err_resp:
            return err_resp

        new_id = create_expense(name, amount, category, notes, user_id)
        return jsonify({"id": new_id, "message": "Expense created"}), 201

    @app.route("/expenses/<int:expense_id>", methods=["PUT"])
    def edit_expense(expense_id):
        user_id, err = auth_required()
        if err:
            return err

        data     = request.get_json(silent=True) or {}
        name, amount, category, notes = _parse_expense(data)

        err_resp = _validate_expense(name, amount, category)
        if err_resp:
            return err_resp

        updated = update_expense(expense_id, user_id, name, amount, category, notes)
        if not updated:
            return jsonify({"error": "Expense not found or access denied"}), 404
        return jsonify({"message": "Expense updated"}), 200

    @app.route("/expenses/<int:expense_id>", methods=["DELETE"])
    def remove_expense(expense_id):
        user_id, err = auth_required()
        if err:
            return err
        deleted = delete_expense(expense_id, user_id)
        if not deleted:
            return jsonify({"error": "Expense not found or access denied"}), 404
        return jsonify({"message": "Expense deleted"}), 200

    # ── NET WORTH ────────────────────────────────────────────────────────────

    @app.route("/net-worth", methods=["GET"])
    def list_net_worth():
        user_id, err = auth_required()
        if err:
            return err
        rows = get_net_worth_history(user_id)
        return jsonify(rows), 200

    @app.route("/net-worth", methods=["POST"])
    def save_net_worth():
        user_id, err = auth_required()
        if err:
            return err

        data = request.get_json(silent=True) or {}
        month = str(data.get("month") or "").strip()
        assets = data.get("assets")
        liab   = data.get("liabilities")

        # --- Validate month ---
        if not MONTH_RE.match(month):
            return jsonify({"error": "month must be in YYYY-MM format (e.g. 2025-04)"}), 400

        # --- Validate numbers ---
        try:
            assets = float(assets)
            liab   = float(liab)
        except (TypeError, ValueError):
            return jsonify({"error": "assets and liabilities must be numbers"}), 400

        if assets < 0 or liab < 0:
            return jsonify({"error": "assets and liabilities must be non-negative"}), 400
        if assets > MAX_AMOUNT or liab > MAX_AMOUNT:
            return jsonify({"error": "Value exceeds maximum allowed amount"}), 400

        create_net_worth_entry(user_id, month, assets, liab)
        return jsonify({"message": "Net worth entry saved"}), 201

    @app.route("/net-worth/<month>", methods=["DELETE"])
    def remove_net_worth(month):
        """
        month is YYYY-MM, e.g. /net-worth/2025-04
        We validate the format before it ever reaches the DB to prevent
        path-traversal or unexpected query behaviour.
        """
        user_id, err = auth_required()
        if err:
            return err

        if not MONTH_RE.match(month):
            return jsonify({"error": "Invalid month format"}), 400

        delete_net_worth_entry(user_id, month)
        return jsonify({"message": "Entry removed"}), 200


# ── PRIVATE HELPERS ──────────────────────────────────────────────────────────

def _parse_expense(data: dict):
    """Extract and sanitize expense fields from a request payload."""
    name     = clean_str(data.get("expense_name"), MAX_NAME_LEN)
    amount   = data.get("amount")
    category = clean_str(data.get("category", "Other"), 50)
    notes    = clean_str(data.get("notes", ""), MAX_NOTES_LEN)
    return name, amount, category, notes


def _validate_expense(name, amount, category):
    """Return a JSON error response tuple, or None if everything is valid."""
    if not name:
        return jsonify({"error": "expense_name is required"}), 400
    if len(name) < 1:
        return jsonify({"error": "expense_name cannot be empty"}), 400

    if amount is None:
        return jsonify({"error": "amount is required"}), 400
    try:
        amount = float(amount)
    except (TypeError, ValueError):
        return jsonify({"error": "amount must be a number"}), 400
    if amount <= 0:
        return jsonify({"error": "amount must be greater than zero"}), 400
    if amount > MAX_AMOUNT:
        return jsonify({"error": "amount exceeds maximum allowed value"}), 400

    if category not in ALLOWED_CATEGORIES:
        return jsonify({"error": f"category must be one of: {', '.join(sorted(ALLOWED_CATEGORIES))}"}), 400

    return None  # All good