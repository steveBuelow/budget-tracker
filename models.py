"""
models.py — Database model functions.
All SQL uses parameterised queries (%s placeholders) — psycopg2 handles
escaping, so no manual quoting is ever needed. This is the correct defence
against SQL injection.
"""

from decimal import Decimal

from werkzeug.security import check_password_hash, generate_password_hash

from db import get_db


def _jsonify_row(row: dict) -> dict:
    """Convert Decimal / datetime values returned by psycopg2 into JSON-safe types."""
    out = dict(row)
    for k, v in list(out.items()):
        if isinstance(v, Decimal):
            out[k] = float(v)
        elif hasattr(v, "isoformat"):
            out[k] = v.isoformat()
    return out


# ── USERS ─────────────────────────────────────────────────────────────────────

def create_user(username, password):
    hashed_pw = generate_password_hash(password)
    conn = get_db()
    try:
        with conn.cursor() as cur:
            cur.execute(
                "INSERT INTO users (username, password) VALUES (%s, %s)",
                (username, hashed_pw),
            )
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def find_user(username, password):
    conn = get_db()
    try:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT id, username, password FROM users WHERE username = %s",
                (username,),
            )
            user = cur.fetchone()
    finally:
        conn.close()

    if user and check_password_hash(user["password"], password):
        return {"id": user["id"], "username": user["username"]}
    return None


def get_user_by_id(user_id):
    conn = get_db()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT id, username FROM users WHERE id = %s", (user_id,))
            row = cur.fetchone()
            return dict(row) if row else None
    finally:
        conn.close()


# ── EXPENSES ──────────────────────────────────────────────────────────────────

def get_expenses(user_id):
    conn = get_db()
    try:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT id, expense_name, amount, category, notes, created_at
                FROM expenses
                WHERE user_id = %s
                ORDER BY created_at DESC
                """,
                (user_id,),
            )
            rows = cur.fetchall()
    finally:
        conn.close()
    return [_jsonify_row(r) for r in rows]


def create_expense(expense_name, amount, category, notes, user_id):
    conn = get_db()
    try:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO expenses (expense_name, amount, category, notes, user_id)
                VALUES (%s, %s, %s, %s, %s)
                RETURNING id
                """,
                (expense_name, amount, category, notes, user_id),
            )
            new_id = cur.fetchone()["id"]
        conn.commit()
        return new_id
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def delete_expense(expense_id, user_id):
    conn = get_db()
    try:
        with conn.cursor() as cur:
            cur.execute(
                "DELETE FROM expenses WHERE id = %s AND user_id = %s",
                (expense_id, user_id),
            )
            deleted = cur.rowcount > 0
        conn.commit()
        return deleted
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def update_expense(expense_id, user_id, expense_name, amount, category, notes):
    conn = get_db()
    try:
        with conn.cursor() as cur:
            cur.execute(
                """
                UPDATE expenses
                SET expense_name = %s,
                    amount       = %s,
                    category     = %s,
                    notes        = %s
                WHERE id = %s AND user_id = %s
                """,
                (expense_name, amount, category, notes, expense_id, user_id),
            )
            updated = cur.rowcount > 0
        conn.commit()
        return updated
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


# ── NET WORTH ─────────────────────────────────────────────────────────────────

def get_net_worth_history(user_id):
    conn = get_db()
    try:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT month, assets, liabilities
                FROM net_worth
                WHERE user_id = %s
                ORDER BY month ASC
                """,
                (user_id,),
            )
            rows = cur.fetchall()
        return [_jsonify_row(r) for r in rows]
    finally:
        conn.close()


def create_net_worth_entry(user_id, month, assets, liabilities):
    conn = get_db()
    try:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO net_worth (user_id, month, assets, liabilities)
                VALUES (%s, %s, %s, %s)
                ON CONFLICT (user_id, month)
                DO UPDATE SET assets      = EXCLUDED.assets,
                              liabilities = EXCLUDED.liabilities
                """,
                (user_id, month, assets, liabilities),
            )
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def delete_net_worth_entry(user_id, month):
    conn = get_db()
    try:
        with conn.cursor() as cur:
            cur.execute(
                "DELETE FROM net_worth WHERE user_id = %s AND month = %s",
                (user_id, month),
            )
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()