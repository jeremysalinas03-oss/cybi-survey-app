from __future__ import annotations

import csv
import html as html_lib
import os
import secrets
from functools import wraps
from io import StringIO
from typing import Any, Callable, Optional

import psycopg2
from flask import (
    Flask,
    Response,
    abort,
    redirect,
    render_template_string,
    request,
    send_from_directory,
    session,
)

# Optional dependency (enabled via requirements.txt). If missing, app still runs without rate limits.
try:
    from flask_limiter import Limiter
    from flask_limiter.util import get_remote_address
except Exception:  # pragma: no cover
    Limiter = None  # type: ignore
    get_remote_address = None  # type: ignore

app = Flask(__name__)

# -----------------------------
# Configuration (Render-friendly)
# -----------------------------
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# Secret key is required for sessions + CSRF. Set SECRET_KEY in Render env vars.
app.secret_key = os.environ.get("SECRET_KEY", secrets.token_hex(32))

# Cookie security: on Render (HTTPS) set COOKIE_SECURE=1. For local HTTP testing, leave it unset/0.
cookie_secure = os.environ.get("COOKIE_SECURE", "0") == "1"
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=cookie_secure,
    MAX_CONTENT_LENGTH=64 * 1024,  # 64KB max request body
)

# Admin password for /results, /export_csv, and admin delete endpoints
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD")

# Max responses (global cap). Defaults to 500; can be overridden via env var MAX_RESPONSES.
MAX_RESPONSES = int(os.environ.get("MAX_RESPONSES", "500"))


# -----------------------------
# Database (PostgreSQL on Render)
# -----------------------------
def get_conn():
    """Connect using Render's DATABASE_URL."""
    db_url = os.environ.get("DATABASE_URL")
    if not db_url:
        raise RuntimeError("DATABASE_URL is not set (Render env var).")
    # connect_timeout prevents the app from hanging during cold starts
    return psycopg2.connect(db_url, connect_timeout=5)


def init_db() -> None:
    """Create the responses table if it doesn't exist."""
    conn = get_conn()
    cur = conn.cursor()
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS responses (
            id BIGSERIAL PRIMARY KEY,
            q1 TEXT,
            q2 TEXT,
            q3 TEXT,
            q4 TEXT,
            q5 TEXT,
            q6 TEXT,
            q7 TEXT,
            q8 TEXT,
            q9 TEXT,
            q10 TEXT,
            q11 TEXT,
            submitted_at TIMESTAMPTZ DEFAULT NOW()
        );
        """
    )
    conn.commit()
    conn.close()


# Ensure DB/table exists after the server is up (avoids boot hangs)
@app.before_request
def ensure_db_once():
    if getattr(app, "_db_initialized", False):
        return
    try:
        init_db()
        app._db_initialized = True
    except Exception as e:
        # Let the request fail later with a clearer /health error if DB is unavailable
        print(f"[WARN] DB init failed: {e}")


# -----------------------------
# Helpers
# -----------------------------
def clamp(value: Optional[str], max_len: int) -> str:
    return (value or "")[:max_len]


def require_admin(f: Callable[..., Any]) -> Callable[..., Any]:
    """Basic-Auth protect an endpoint using ADMIN_PASSWORD env var."""

    @wraps(f)
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        if not ADMIN_PASSWORD:
            return "ADMIN_PASSWORD is not set", 500

        auth = request.authorization
        # Username can be anything; we validate only the password.
        if not auth or auth.password != ADMIN_PASSWORD:
            return Response(
                "Authentication required",
                401,
                {"WWW-Authenticate": 'Basic realm="Survey Admin"'},
            )
        return f(*args, **kwargs)

    return wrapper


def get_or_create_csrf_token() -> str:
    token = session.get("csrf_token")
    if not token:
        token = secrets.token_urlsafe(32)
        session["csrf_token"] = token
    return token


def verify_csrf() -> None:
    form_token = request.form.get("csrf_token")
    sess_token = session.get("csrf_token")
    if not form_token or not sess_token or form_token != sess_token:
        abort(403)


# -----------------------------
# Rate limiting (optional)
# -----------------------------
limiter = None
if Limiter and get_remote_address:
    limiter = Limiter(
        get_remote_address,
        app=app,
        default_limits=["200 per day", "50 per hour"],
        storage_uri=os.environ.get("LIMITER_STORAGE_URI", "memory://"),
    )


# -----------------------------
# Security headers
# -----------------------------
@app.after_request
def add_security_headers(resp: Response) -> Response:
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Referrer-Policy"] = "no-referrer"
    resp.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
    resp.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "img-src 'self' data:; "
        "style-src 'self' 'unsafe-inline';"
    )
    return resp


# -----------------------------
# Routes
# -----------------------------
@app.route("/health")
def health() -> str:
    try:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute("SELECT 1;")
        conn.close()
        return "ok"
    except Exception as e:
        return f"db_error: {e}", 500


@app.route("/")
def serve_index() -> str:
    csrf = get_or_create_csrf_token()
    with open(os.path.join(BASE_DIR, "index.html"), "r", encoding="utf-8") as f:
        html_text = f.read()
    return render_template_string(html_text, csrf_token=csrf)


@app.route("/images/<path:filename>")
def images(filename: str):
    # Your repo must have an images/ folder at the root: images/cyber.png, etc.
    return send_from_directory(os.path.join(BASE_DIR, "images"), filename)


@app.route("/submit_survey", methods=["POST"])
def submit_survey():
    verify_csrf()

    # One submission per browser session (basic duplicate submit protection)
    if session.get("submitted") is True:
        return (
            "<h1>Already submitted</h1>"
            "<p>This browser session already submitted the survey.</p>"
            "<a href='/'>Return to Survey</a>"
        )
    session["submitted"] = True

    q1 = clamp(request.form.get("q1"), 50)
    q2 = clamp(request.form.get("q2"), 50)
    q3 = clamp(request.form.get("q3"), 50)
    q4 = clamp(", ".join(request.form.getlist("q4[]")), 500)
    q5 = clamp(request.form.get("q5"), 1000)
    q6 = clamp(request.form.get("q6"), 1000)
    q7 = clamp(request.form.get("q7"), 50)
    q8 = clamp(", ".join(request.form.getlist("q8[]")), 500)
    q9 = clamp(request.form.get("q9"), 1000)
    q10 = clamp(request.form.get("q10"), 2000)
    q11 = clamp(request.form.get("q11"), 50)

    conn = get_conn()
    cur = conn.cursor()

    # Global cap (default 500)
    cur.execute("SELECT count(*) FROM responses;")
    total = cur.fetchone()[0]
    if total >= MAX_RESPONSES:
        conn.close()
        return (
            "<h1>Survey Closed</h1>"
            f"<p>The maximum number of responses ({MAX_RESPONSES}) has been reached.</p>"
            "<a href='/'>Back</a>"
        )

    cur.execute(
        """
        INSERT INTO responses (q1, q2, q3, q4, q5, q6, q7, q8, q9, q10, q11)
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        """,
        (q1, q2, q3, q4, q5, q6, q7, q8, q9, q10, q11),
    )
    conn.commit()
    conn.close()

    return (
        "<h1>Thank You!</h1>"
        "<p>Your response has been recorded.</p>"
        "<a href='/'>Return to Survey</a>"
    )


# Apply rate limit decorator only if limiter exists
if limiter:
    submit_survey = limiter.limit("5 per minute")(submit_survey)  # type: ignore


@app.route("/results")
@require_admin
def view_results():
    conn = get_conn()
    cur = conn.cursor()
    cur.execute(
        "SELECT id,q1,q2,q3,q4,q5,q6,q7,q8,q9,q10,q11,submitted_at "
        "FROM responses ORDER BY id DESC"
    )
    rows = cur.fetchall()
    conn.close()

    out = [
        "<h1>Survey Responses</h1>",
        "<p><a href='/export_csv'>Download CSV</a></p>",
        "<table border='1' cellpadding='6'>",
        "<tr>"
        "<th>ID</th><th>Q1</th><th>Q2</th><th>Q3</th><th>Q4</th><th>Q5</th><th>Q6</th>"
        "<th>Q7</th><th>Q8</th><th>Q9</th><th>Q10</th><th>Q11</th><th>Submitted</th><th>Delete</th>"
        "</tr>",
    ]

    for row in rows:
        response_id = row[0]
        cells = "".join([f"<td>{html_lib.escape(str(col))}</td>" for col in row])

        delete_form = (
            f"<td>"
            f"<form method='POST' action='/admin/delete/{response_id}' "
            f"onsubmit=\"return confirm('Delete submission ID {response_id}?');\">"
            f"<button type='submit'>Delete</button>"
            f"</form>"
            f"</td>"
        )

        out.append(f"<tr>{cells}{delete_form}</tr>")

    out.append("</table><br><a href='/'>Back to Survey</a>")
    return "".join(out)


@app.route("/admin/delete/<int:response_id>", methods=["POST"])
@require_admin
def delete_response(response_id: int):
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("DELETE FROM responses WHERE id = %s", (response_id,))
    conn.commit()
    conn.close()
    return redirect("/results")


@app.route("/export_csv")
@require_admin
def export_csv():
    conn = get_conn()
    cur = conn.cursor()
    cur.execute(
        """
        SELECT q1,q2,q3,q4,q5,q6,q7,q8,q9,q10,q11,submitted_at
        FROM responses
        ORDER BY id DESC
        """
    )
    rows = cur.fetchall()
    conn.close()

    sio = StringIO()
    writer = csv.writer(sio)
    writer.writerow(["q1","q2","q3","q4","q5","q6","q7","q8","q9","q10","q11","submitted_at"])
    writer.writerows(rows)

    return Response(
        sio.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment; filename=survey_results.csv"},
    )


if __name__ == "__main__":
    port = int(os.environ.get("PORT", "5000"))
    app.run(host="0.0.0.0", port=port, debug=False)




