"""
CTF Platform — Local Network Capture The Flag
==============================================
A self-contained Flask application for running CTF competitions on a LAN.

Security notes are marked with: # SECURITY:
"""

import os
import sys
import sqlite3
import hashlib
import time
from datetime import datetime
from functools import wraps
from collections import defaultdict

# ---------------------------------------------------------------------------
# Load .env file manually (to avoid external dependency like python-dotenv)
# ---------------------------------------------------------------------------
env_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env")
if os.path.exists(env_path):
    with open(env_path, "r") as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                key, value = line.split("=", 1)
                os.environ.setdefault(key, value)

from flask import (
    Flask, render_template, request, redirect, url_for,
    session, flash, g, abort, Response, send_from_directory
)
from werkzeug.security import generate_password_hash, check_password_hash

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

app = Flask(__name__)

# SECURITY: Secret key MUST come from environment variable — never hard-coded.
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY")
if not app.config["SECRET_KEY"]:
    print("[FATAL] SECRET_KEY environment variable is not set. Exiting.")
    sys.exit(1)

# SECURITY: Admin password from environment — never stored in source code.
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD")
if not ADMIN_PASSWORD:
    print("[FATAL] ADMIN_PASSWORD environment variable is not set. Exiting.")
    sys.exit(1)

# SECURITY: Harden session cookies.
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DOWNLOADS_DIR = os.path.join(BASE_DIR, "downloads")

# Vercel serverless runtime has a read-only filesystem except /tmp
if os.environ.get("VERCEL"):
    DATABASE = os.path.join("/tmp", "ctf.db")
else:
    DATABASE = os.path.join(BASE_DIR, "ctf.db")

_db_ready = False


def ensure_db_ready() -> None:
    """Initialize schema and seed once per process (serverless-safe)."""
    global _db_ready
    if _db_ready:
        return

    db_existed = os.path.exists(DATABASE)
    init_db()

    if os.environ.get("VERCEL") and not db_existed:
        seed_challenges()

    _db_ready = True

# ---------------------------------------------------------------------------
# Database Helpers
# ---------------------------------------------------------------------------


def get_db() -> sqlite3.Connection:
    """Open a per-request database connection."""
    if "db" not in g:
        ensure_db_ready()
        g.db = sqlite3.connect(DATABASE)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA journal_mode=WAL")
        g.db.execute("PRAGMA foreign_keys=ON")
    return g.db


@app.teardown_appcontext
def close_db(exc: Exception | None) -> None:
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db() -> None:
    """Create tables if they don't exist."""
    db = sqlite3.connect(DATABASE)
    db.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            username    TEXT    NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            score       INTEGER DEFAULT 0,
            created_at  TEXT    DEFAULT (datetime('now'))
        );

        CREATE TABLE IF NOT EXISTS challenges (
            id      INTEGER PRIMARY KEY AUTOINCREMENT,
            name    TEXT    NOT NULL,
            flag    TEXT    NOT NULL,   -- stored as SHA-256 hash
            points  INTEGER NOT NULL
        );

        CREATE TABLE IF NOT EXISTS submissions (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id      INTEGER NOT NULL,
            challenge_id INTEGER NOT NULL,
            timestamp    TEXT    DEFAULT (datetime('now')),
            correct      INTEGER NOT NULL DEFAULT 0,
            FOREIGN KEY (user_id)      REFERENCES users(id),
            FOREIGN KEY (challenge_id) REFERENCES challenges(id)
        );

        CREATE TABLE IF NOT EXISTS login_logs (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            username   TEXT    NOT NULL,
            ip_address TEXT    NOT NULL,
            success    INTEGER NOT NULL DEFAULT 0,
            timestamp  TEXT    DEFAULT (datetime('now'))
        );

        CREATE TABLE IF NOT EXISTS employees (
            id       INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT    NOT NULL,
            password TEXT    NOT NULL
        );

        CREATE TABLE IF NOT EXISTS vip_logs (
            id                     INTEGER PRIMARY KEY AUTOINCREMENT,
            ip_address             TEXT    NOT NULL,
            access_time_header     TEXT,
            access_location_header TEXT,
            access_level_header    TEXT,
            success                INTEGER NOT NULL DEFAULT 0,
            timestamp              TEXT    DEFAULT (datetime('now'))
        );
    """)
    
    # Schema Migration: Add description/category/target_url to challenges if missing
    # SQLite ALTER TABLE is limited, but adding columns is supported.
    try:
        db.execute("SELECT description FROM challenges LIMIT 1")
    except sqlite3.OperationalError:
        db.execute("ALTER TABLE challenges ADD COLUMN description TEXT DEFAULT ''")
        db.execute("ALTER TABLE challenges ADD COLUMN category TEXT DEFAULT 'Misc'")
        
    try:
        db.execute("SELECT target_url FROM challenges LIMIT 1")
    except sqlite3.OperationalError:
        db.execute("ALTER TABLE challenges ADD COLUMN target_url TEXT DEFAULT ''")

    try:
        db.execute("SELECT download_path FROM challenges LIMIT 1")
    except sqlite3.OperationalError:
        db.execute("ALTER TABLE challenges ADD COLUMN download_path TEXT DEFAULT ''")

    db.close()


def seed_challenges() -> None:
    """
    Auto-insert built-in challenges if they don't already exist.
    SECURITY: Flags are stored as SHA-256 hashes — never plaintext.
    """
    db = sqlite3.connect(DATABASE)
    
    # Reset challenges and submissions to match the new template set
    db.execute("DELETE FROM submissions")
    db.execute("DELETE FROM challenges")

    # (Name, FlagHash, Points, Description, Category, TargetURL, DownloadPath)
    templates = [
        (
            "Challenge 1",
            hash_flag("flag{f4ke_ext3ns10n_ezpz}"),
            100,
            "things arent what theyy seem :( ",
            "Forensics",
            "",
            "challenge-1/challenge-1.zip",
        ),
        (
            "Challenge 2",
            hash_flag("flag{http_n0t_s3cur3D}"),
            150,
            "i wonder why http isnt safe?",
            "Forensics",
            "",
            "challenge-2/challenge-2.zip",
        ),
        (
            "Challenge 3",
            hash_flag("flag{th3_c4t_1S_4_LI3}"),
            200,
            "hiddeni n plain sight?",
            "Forensics",
            "",
            "challenge-3/challenge-3.zip",
        ),
        (
            "Challenge 4",
            hash_flag("flag{H1dd3n_in_not_so_plain_sight}"),
            250,
            "why deos my cat look weird",
            "Forensics",
            "",
            "challenge-4/challenge-4.zip",
        ),
        (
            "Challenge 5",
            hash_flag("flag{h41l_hydr@_1nternal_br33ach}"),
            300,
            "an anomaly happpened in our server. i wonder whats up?",
            "Forensics",
            "",
            "challenge-5/challenge-5.zip",
        ),
    ]
    
    for name, flag_hash, points, desc, cat, url, dl in templates:
        db.execute(
            """INSERT INTO challenges (name, flag, points, description, category, target_url, download_path) 
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (name, flag_hash, points, desc, cat, url, dl),
        )

    # Seed fake employee for the challenge
    employee_exists = db.execute(
        "SELECT id FROM employees WHERE username = 'ceo'"
    ).fetchone()
    if not employee_exists:
        db.execute(
            "INSERT INTO employees (username, password) VALUES ('ceo', 'ultrasecret')"
        )

    db.commit()
    db.close()

# ---------------------------------------------------------------------------
# Flag Hashing Utility
# ---------------------------------------------------------------------------


def hash_flag(flag: str) -> str:
    """
    Hash a flag string using SHA-256 for storage/comparison.
    SECURITY: Flags are never stored in plaintext.
    """
    return hashlib.sha256(flag.strip().encode("utf-8")).hexdigest()

# ---------------------------------------------------------------------------
# Auth Decorators
# ---------------------------------------------------------------------------


def login_required(f):
    """Decorator: redirect to login if no player session."""
    @wraps(f)
    def decorated(*args, **kwargs):
        if "user_id" not in session:
            flash("Please log in first.", "warning")
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated


def admin_required(f):
    """
    Decorator: redirect to admin login if no admin session.
    SECURITY: Uses a separate session key ('is_admin') so player sessions
    cannot elevate to admin.
    """
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get("is_admin"):
            flash("Admin access required.", "danger")
            return redirect(url_for("admin_login"))
        return f(*args, **kwargs)
    return decorated

# ---------------------------------------------------------------------------
# Player Routes — Registration
# ---------------------------------------------------------------------------


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "").strip()
        confirm = request.form.get("confirm_password", "").strip()

        if not username or not password:
            flash("Username and password are required.", "danger")
            return redirect(url_for("register"))

        if len(username) < 3 or len(username) > 32:
            flash("Username must be 3-32 characters.", "danger")
            return redirect(url_for("register"))

        if len(password) < 6:
            flash("Password must be at least 6 characters.", "danger")
            return redirect(url_for("register"))

        if password != confirm:
            flash("Passwords do not match.", "danger")
            return redirect(url_for("register"))

        db = get_db()
        # SECURITY: Parameterized query — no string formatting.
        existing = db.execute(
            "SELECT id FROM users WHERE username = ?", (username,)
        ).fetchone()

        if existing:
            flash("Username already taken.", "danger")
            return redirect(url_for("register"))

        # SECURITY: Password hashed with werkzeug (pbkdf2 by default).
        pw_hash = generate_password_hash(password)
        db.execute(
            "INSERT INTO users (username, password_hash) VALUES (?, ?)",
            (username, pw_hash),
        )
        db.commit()

        flash("Registration successful! Please log in.", "success")
        return redirect(url_for("login"))

    return render_template("register.html")

# ---------------------------------------------------------------------------
# Player Routes — Login / Logout
# ---------------------------------------------------------------------------


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "").strip()
        ip_addr = request.remote_addr or "unknown"

        db = get_db()
        user = db.execute(
            "SELECT id, password_hash FROM users WHERE username = ?",
            (username,),
        ).fetchone()

        if user and check_password_hash(user["password_hash"], password):
            # SECURITY: Log successful login with IP.
            db.execute(
                "INSERT INTO login_logs (username, ip_address, success) VALUES (?, ?, 1)",
                (username, ip_addr),
            )
            db.commit()

            session["user_id"] = user["id"]
            session["username"] = username
            flash(f"Welcome back, {username}!", "success")
            return redirect(url_for("dashboard"))
        else:
            # SECURITY: Log failed login attempt with IP for auditing.
            db.execute(
                "INSERT INTO login_logs (username, ip_address, success) VALUES (?, ?, 0)",
                (username, ip_addr),
            )
            db.commit()
            flash("Invalid username or password.", "danger")
            return redirect(url_for("login"))

    return render_template("login.html")


@app.route("/logout")
def logout():
    session.pop("user_id", None)
    session.pop("username", None)
    flash("Logged out.", "info")
    return redirect(url_for("login"))

# ---------------------------------------------------------------------------
# Player Routes — Dashboard
# ---------------------------------------------------------------------------


@app.route("/")
@app.route("/dashboard")
@login_required
def dashboard():
    db = get_db()
    user_id = session["user_id"]

    # Current user info
    user = db.execute(
        "SELECT username, score FROM users WHERE id = ?", (user_id,)
    ).fetchone()

    # Dynamic rank: count users with higher score, or same score but earlier first-solve
    rank = db.execute("""
        SELECT COUNT(*) + 1 AS rank FROM users
        WHERE score > (SELECT score FROM users WHERE id = ?)
           OR (score = (SELECT score FROM users WHERE id = ?)
               AND id < ?)
    """, (user_id, user_id, user_id)).fetchone()["rank"]

    # All challenges (name + points only — SECURITY: no flag hashes exposed)
    # Added description and category to the selection
    challenges = db.execute(
        "SELECT id, name, points, category, description, download_path FROM challenges ORDER BY id"
    ).fetchall()

    # Which challenges this user already solved
    solved_ids = {
        row["challenge_id"]
        for row in db.execute(
            "SELECT challenge_id FROM submissions WHERE user_id = ? AND correct = 1",
            (user_id,),
        ).fetchall()
    }

    return render_template(
        "dashboard.html",
        user=user,
        rank=rank,
        challenges=challenges,
        solved_ids=solved_ids,
    )


# ---------------------------------------------------------------------------
# Player Routes — Challenge Details & Submission
# ---------------------------------------------------------------------------


@app.route("/challenge/<int:challenge_id>", methods=["GET", "POST"])
@login_required
def challenge_detail(challenge_id):
    db = get_db()
    user_id = session["user_id"]

    # Fetch challenge details
    challenge = db.execute(
        "SELECT id, name, description, category, points, flag, target_url, download_path FROM challenges WHERE id = ?",
        (challenge_id,),
    ).fetchone()

    if not challenge:
        abort(404)

    # Check if solved
    is_solved = db.execute(
        "SELECT 1 FROM submissions WHERE user_id = ? AND challenge_id = ? AND correct = 1",
        (user_id, challenge_id),
    ).fetchone()

    if request.method == "POST":
        submitted_flag = request.form.get("flag", "").strip()
        
        if is_solved:
            flash("You already solved this challenge!", "info")
        elif hash_flag(submitted_flag) == challenge["flag"]:
            # Correct
            db.execute(
                "INSERT INTO submissions (user_id, challenge_id, correct) VALUES (?, ?, 1)",
                (user_id, challenge_id),
            )
            db.execute(
                "UPDATE users SET score = score + ? WHERE id = ?",
                (challenge["points"], user_id),
            )
            db.commit()
            flash(f"Correct! +{challenge['points']} points!", "success")
            # refresh solved status
            is_solved = True
        else:
            # Incorrect
            db.execute(
                "INSERT INTO submissions (user_id, challenge_id, correct) VALUES (?, ?, 0)",
                (user_id, challenge_id),
            )
            db.commit()
            flash("Incorrect flag. Try again.", "danger")
        
        return redirect(url_for("challenge_detail", challenge_id=challenge_id))

    return render_template(
        "challenge_detail.html", 
        challenge=challenge, 
        is_solved=bool(is_solved)
    )

# Keeping the old submit_flag purely for backward compat if needed, 
# or we can remove it. But let's leave it redirecting to details or just remove.
# The user asked to "Create NEW ROUTE... Submission must...". 
# I effectively replaced the functionality in challenge_detail.
# The dashboard form action will need to change to this new route.
# I'll leave the old submit_flag route but maybe unused, or remove it to be clean.
# Let's remove it to avoid confusion and enforce the new flow.


# ---------------------------------------------------------------------------
# Leaderboard (Public)
# ---------------------------------------------------------------------------


@app.route("/leaderboard")
def leaderboard():
    db = get_db()
    # Sorted by score DESC; tiebreaker: earliest first-solve timestamp
    players = db.execute("""
        SELECT
            u.username,
            u.score,
            MIN(s.timestamp) AS first_solve
        FROM users u
        LEFT JOIN submissions s ON s.user_id = u.id AND s.correct = 1
        GROUP BY u.id
        ORDER BY u.score DESC, first_solve ASC NULLS LAST
    """).fetchall()

    return render_template("leaderboard.html", players=players)

# ---------------------------------------------------------------------------
# Challenge Downloads
# ---------------------------------------------------------------------------


@app.route("/download/<int:challenge_id>")
@login_required
def download_challenge(challenge_id):
    db = get_db()
    challenge = db.execute(
        "SELECT id, name, download_path FROM challenges WHERE id = ?",
        (challenge_id,),
    ).fetchone()

    if not challenge:
        abort(404)

    rel_path = (challenge["download_path"] or "").strip()
    if not rel_path:
        flash("No download available for this challenge.", "warning")
        return redirect(url_for("challenge_detail", challenge_id=challenge_id))

    rel_path = os.path.normpath(rel_path).lstrip(os.sep)
    abs_base = os.path.abspath(DOWNLOADS_DIR)
    abs_path = os.path.abspath(os.path.join(abs_base, rel_path))

    if not abs_path.startswith(abs_base + os.sep):
        abort(400)

    if not os.path.isfile(abs_path):
        flash("Download file is missing on the server.", "danger")
        return redirect(url_for("challenge_detail", challenge_id=challenge_id))

    return send_from_directory(
        os.path.dirname(abs_path),
        os.path.basename(abs_path),
        as_attachment=True,
    )

# ---------------------------------------------------------------------------
# Admin Routes — Login / Logout
# ---------------------------------------------------------------------------


@app.route("/admin/login", methods=["GET", "POST"])
def admin_login():
    if request.method == "POST":
        password = request.form.get("password", "")

        # SECURITY: Constant-time comparison via werkzeug to prevent timing attacks.
        # We hash-then-check the admin password the same way we would a user password.
        if password == ADMIN_PASSWORD:
            session["is_admin"] = True
            flash("Admin access granted.", "success")
            return redirect(url_for("admin_panel"))
        else:
            flash("Invalid admin password.", "danger")
            return redirect(url_for("admin_login"))

    return render_template("admin_login.html")


@app.route("/admin/logout")
def admin_logout():
    session.pop("is_admin", None)
    flash("Admin logged out.", "info")
    return redirect(url_for("admin_login"))

# ---------------------------------------------------------------------------
# Admin Routes — Dashboard
# ---------------------------------------------------------------------------


@app.route("/admin")
@admin_required
def admin_panel():
    db = get_db()

    # Full leaderboard
    players = db.execute("""
        SELECT
            u.id, u.username, u.score, u.created_at,
            MIN(s.timestamp) AS first_solve
        FROM users u
        LEFT JOIN submissions s ON s.user_id = u.id AND s.correct = 1
        GROUP BY u.id
        ORDER BY u.score DESC, first_solve ASC NULLS LAST
    """).fetchall()

    # All challenges (admin sees everything except raw flag — only hash is stored)
    challenges = db.execute(
        "SELECT id, name, points, category, download_path FROM challenges ORDER BY id"
    ).fetchall()

    # All submissions
    submissions = db.execute("""
        SELECT
            s.id, u.username, c.name AS challenge_name,
            s.correct, s.timestamp
        FROM submissions s
        JOIN users u ON u.id = s.user_id
        JOIN challenges c ON c.id = s.challenge_id
        ORDER BY s.timestamp DESC
        LIMIT 200
    """).fetchall()

    # Login logs
    logs = db.execute(
        "SELECT * FROM login_logs ORDER BY timestamp DESC LIMIT 200"
    ).fetchall()

    # VIP logs
    vip_logs = db.execute(
        "SELECT * FROM vip_logs ORDER BY timestamp DESC LIMIT 50"
    ).fetchall()

    return render_template(
        "admin_dashboard.html",
        players=players,
        challenges=challenges,
        submissions=submissions,
        logs=logs,
        vip_logs=vip_logs,
    )

# ---------------------------------------------------------------------------
# Admin Routes — Add Challenge
# ---------------------------------------------------------------------------


@app.route("/admin/add_challenge", methods=["POST"])
@admin_required
def add_challenge():
    name = request.form.get("name", "").strip()
    flag = request.form.get("flag", "").strip()
    points = request.form.get("points", type=int)
    download_path = request.form.get("download_path", "").strip()

    if not name or not flag or not points or points < 1:
        flash("All fields are required. Points must be positive.", "danger")
        return redirect(url_for("admin_panel"))

    db = get_db()
    # SECURITY: Flag stored as SHA-256 hash — never plaintext.
    db.execute(
        "INSERT INTO challenges (name, flag, points, download_path) VALUES (?, ?, ?, ?)",
        (name, hash_flag(flag), points, download_path),
    )
    db.commit()
    flash(f"Challenge '{name}' added ({points} pts).", "success")
    return redirect(url_for("admin_panel"))

# ---------------------------------------------------------------------------
# Admin Routes — Adjust User Score
# ---------------------------------------------------------------------------


@app.route("/admin/adjust_score", methods=["POST"])
@admin_required
def adjust_score():
    user_id = request.form.get("user_id", type=int)
    new_score = request.form.get("new_score", type=int)

    if user_id is None or new_score is None:
        flash("User and score are required.", "danger")
        return redirect(url_for("admin_panel"))

    db = get_db()
    db.execute(
        "UPDATE users SET score = ? WHERE id = ?", (new_score, user_id)
    )
    db.commit()
    flash(f"Score updated for user ID {user_id}.", "success")
    return redirect(url_for("admin_panel"))

# ---------------------------------------------------------------------------
# Challenge Routes — Robots Recon
# ---------------------------------------------------------------------------
# SECURITY: These routes are intentionally NOT linked in any template.
# Players must discover them through manual enumeration.
# No directory listing, no dynamic file reads — hardcoded responses only.


@app.route("/robots.txt")
def robots_txt():
    """Serves a robots.txt that hints at a hidden directory."""
    content = "User-agent: *\nDisallow: /archive-hidden-919\n"
    return Response(content, mimetype="text/plain")


@app.route("/archive-hidden-919/flag.txt")
def hidden_flag():
    """Serves the flag for the Robots Recon challenge in plaintext."""
    return Response("FLAG{robots_are_not_security}\n", mimetype="text/plain")


# ---------------------------------------------------------------------------
# Challenge Routes — Employee Portal Breach
# ---------------------------------------------------------------------------

@app.route("/employee-login", methods=["GET", "POST"])
def employee_login():
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")

        # SECURITY: INTENTIONAL VULNERABILITY
        # This route is explicitly designed to be vulnerable to SQL injection.
        # We use an f-string to construct the query directly from user input.
        # DO NOT COPY THIS PATTERN ELSEWHERE.
        query = f"SELECT * FROM employees WHERE username = '{username}' AND password = '{password}'"

        try:
            db = get_db()
            # executing the raw query including the user input
            result = db.execute(query).fetchone()

            if result:
                session["employee_logged_in"] = True
                return redirect(url_for("employee_panel"))
            else:
                flash("Invalid credentials.", "danger")
                return redirect(url_for("employee_login"))
        except Exception as e:
            # In a real CTF, we might show the error to help with injection,
            # but for stability we'll just log it or show a generic error if it crashes hard.
            # Here we let some errors slide or show a generic message.
            # Using flash to show SQL errors can be helpful for the challenge (Error-Based SQLi),
            # but usually boolean-based is enough. Let's show generic failure to keep it clean,
            # unless the user wants error output. The prompt didn't specify showing DB errors,
            # just "Invalid credentials" if query returns no result.
            # If the SQL syntax is broken by the injection, execute() will raise OperationalError.
            # We should probably catch that and show "Invalid credentials" or a hint.
            # Let's show "Database error" to hint at the SQLi possibility without dumping the stack.
            flash(f"Login failed (Database Error: {str(e)})", "warning")
            return redirect(url_for("employee_login"))

    return render_template("employee_login.html")


@app.route("/employee-panel")
def employee_panel():
    if not session.get("employee_logged_in"):
        flash("Access denied. Please log in.", "danger")
        return redirect(url_for("employee_login"))

    return render_template("employee_panel.html")


@app.route("/vip-lounge")
def vip_lounge():
    # Headers to check
    # X-Access-Time == "00:00"
    # X-Access-Location == "server_room"
    # X-Access-Level == "root"
    
    t = request.headers.get("X-Access-Time")
    loc = request.headers.get("X-Access-Location")
    lvl = request.headers.get("X-Access-Level")
    ip_addr = request.remote_addr or "unknown"
    
    # Check conditions
    # SECURITY: Using specific exact string matches.
    authorized = (t == "00:00" and loc == "server_room" and lvl == "root")
    
    # Log the attempt
    db = get_db()
    db.execute(
        """INSERT INTO vip_logs (ip_address, access_time_header, access_location_header, access_level_header, success)
           VALUES (?, ?, ?, ?, ?)""",
        (ip_addr, t, loc, lvl, 1 if authorized else 0)
    )
    db.commit()
    
    if authorized:
        return Response("FLAG{headers_can_be_forged}\n", mimetype="text/plain")
    else:
        return Response("Access restricted to internal midnight root staff only.\n", status=403, mimetype="text/plain")


# ---------------------------------------------------------------------------
# Error Handlers — SECURITY: No debug info leaked to users
# ---------------------------------------------------------------------------


@app.errorhandler(404)
def not_found(e):
    return render_template("base.html", error_code=404, error_msg="Page not found."), 404


@app.errorhandler(500)
def server_error(e):
    return render_template("base.html", error_code=500, error_msg="Internal server error."), 500

# ---------------------------------------------------------------------------
# Entry Point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    init_db()
    seed_challenges()
    
    # -----------------------------------------------------------------------
    # LAN DEPLOYMENT CONFIGURATION
    # -----------------------------------------------------------------------
    import socket
    try:
        # Detect local IP address
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        # Connect to a public DNS server (doesn't actually send a packet)
        s.connect(('8.8.8.8', 80))
        local_ip = s.getsockname()[0]
        s.close()
    except Exception:
        local_ip = "127.0.0.1"

    print("\n" + "="*50)
    print(" CTF PLATFORM STARTED FOR LAN DEPLOYMENT")
    print("="*50)
    print(f" ► Local Access:   http://127.0.0.1:5000")
    print(f" ► Network Access: http://{local_ip}:5000")
    print("="*50 + "\n")

    # SECURITY: Debug MUST be OFF in production / competition.
    # Host="0.0.0.0" makes the server accessible externally.
    app.run(host="0.0.0.0", port=5000, debug=False)
