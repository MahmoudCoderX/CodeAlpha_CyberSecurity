"""
Deliberately vulnerable demo Flask application.
Used as the audit target for Task 3: Secure Coding Review.
DO NOT DEPLOY - this code intentionally contains security flaws.
"""
import os
import pickle
import sqlite3
import subprocess

from flask import Flask, request, redirect

app = Flask(__name__)

# VULN: hardcoded secret key committed to source control
app.secret_key = "supersecret123"

DB_PATH = "users.db"
# VULN: hardcoded credentials
ADMIN_USER = "admin"
ADMIN_PASS = "admin123"


def get_db():
    return sqlite3.connect(DB_PATH)


@app.route("/login", methods=["POST"])
def login():
    username = request.form.get("username", "")
    password = request.form.get("password", "")
    db = get_db()
    # VULN: SQL injection - user input concatenated into the query
    query = "SELECT * FROM users WHERE username = '" + username + \
            "' AND password = '" + password + "'"
    cur = db.execute(query)
    user = cur.fetchone()
    if user:
        return "Welcome " + username  # VULN: reflected XSS, no escaping
    return "Login failed", 401


@app.route("/ping")
def ping():
    host = request.args.get("host", "127.0.0.1")
    # VULN: OS command injection - shell=True with user input
    result = subprocess.check_output("ping -c 1 " + host, shell=True)
    return "<pre>" + result.decode() + "</pre>"


@app.route("/profile", methods=["POST"])
def profile():
    data = request.get_data()
    # VULN: insecure deserialization of attacker-controlled data
    profile = pickle.loads(data)
    return "Loaded profile for " + str(profile.get("name", "?"))


@app.route("/read")
def read_file():
    filename = request.args.get("name", "")
    # VULN: path traversal - no validation of the file path
    with open("/var/data/" + filename) as f:
        return f.read()


@app.route("/run_diag")
def run_diag():
    # VULN: use of eval on request data
    expr = request.args.get("expr", "1+1")
    return str(eval(expr))


if __name__ == "__main__":
    # VULN: debug mode on and listening on all interfaces
    app.run(host="0.0.0.0", port=5000, debug=True)
