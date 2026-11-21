"""
Remediated version of vulnerable_app/app.py (Task 3: Secure Coding Review).
Every fix is marked FIX and mirrors a finding in secure_coding_review_report.md.
"""
import ast
import json
import os
import re
import sqlite3
import subprocess

from flask import Flask, request, escape

app = Flask(__name__)

# FIX (F1): secret key comes from the environment, never hardcoded
app.secret_key = os.environ["APP_SECRET_KEY"]

DB_PATH = "users.db"

# FIX (F2): credentials are read from environment variables, not source code
ADMIN_USER = os.environ.get("ADMIN_USER", "")
ADMIN_PASS = os.environ.get("ADMIN_PASS", "")


def get_db():
    return sqlite3.connect(DB_PATH)


@app.route("/login", methods=["POST"])
def login():
    username = request.form.get("username", "")
    password = request.form.get("password", "")
    db = get_db()
    # FIX (F3): parameterized query prevents SQL injection
    cur = db.execute(
        "SELECT * FROM users WHERE username = ? AND password = ?",
        (username, password),
    )
    user = cur.fetchone()
    if user:
        # FIX (F4): output escaped, preventing reflected XSS
        return "Welcome " + escape(username)
    return "Login failed", 401


@app.route("/ping")
def ping():
    host = request.args.get("host", "127.0.0.1")
    # FIX (F5): strict allow-list validation, no shell, argument list form
    if not re.fullmatch(r"[a-zA-Z0-9.\-]{1,253}", host):
        return "Invalid host", 400
    result = subprocess.run(
        ["ping", "-c", "1", host],
        capture_output=True, timeout=5, check=False,
    )
    return "<pre>" + escape(result.stdout.decode(errors="replace")) + "</pre>"


@app.route("/profile", methods=["POST"])
def profile():
    data = request.get_data()
    # FIX (F6): JSON replaces pickle; pickle must never touch untrusted data
    try:
        profile = json.loads(data)
    except json.JSONDecodeError:
        return "Bad profile", 400
    if not isinstance(profile, dict):
        return "Bad profile", 400
    return "Loaded profile for " + escape(str(profile.get("name", "?")))


ALLOWED_DIR = "/var/data"


@app.route("/read")
def read_file():
    filename = request.args.get("name", "")
    # FIX (F7): canonicalize and confine the path to the allowed directory
    safe_name = os.path.basename(filename)
    path = os.path.realpath(os.path.join(ALLOWED_DIR, safe_name))
    if not path.startswith(os.path.realpath(ALLOWED_DIR) + os.sep):
        return "Forbidden", 403
    with open(path) as f:
        return escape(f.read())


@app.route("/run_diag")
def run_diag():
    expr = request.args.get("expr", "1+1")
    # FIX (F8): ast.literal_eval only evaluates literals, never code
    try:
        return str(ast.literal_eval(expr))
    except (ValueError, SyntaxError):
        return "Invalid expression", 400


if __name__ == "__main__":
    # FIX (F9, F10): debug off, bind to localhost only
    app.run(host="127.0.0.1", port=5000, debug=False)
