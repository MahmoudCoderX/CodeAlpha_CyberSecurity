# Task 3: Secure Coding Review - Report
CodeAlpha Cyber Security Internship | Mahmoud Mohamed Sayed

## 1. Scope and method

- **Audit target:** `vulnerable_app/app.py`, a small Flask web application
  (login, ping utility, profile upload, file read, diagnostics endpoint).
- **Language / framework:** Python 3 with Flask and SQLite.
- **Method:** automated static analysis with **Bandit 1.x** (Python SAST tool),
  followed by manual line-by-line inspection to confirm each finding, remove
  false positives, and assess real-world exploitability.
- **Verification:** the remediated version (`fixed_app.py`) was re-scanned with
  the same tool to confirm the fixes.

## 2. Summary of findings

| ID | Vulnerability | Location | Bandit severity | Exploitability |
|----|---------------|----------|-----------------|----------------|
| F1 | Hardcoded Flask secret key | app.py:16 | Low | High |
| F2 | Hardcoded admin credentials | app.py:21 | Low | High |
| F3 | SQL injection in /login | app.py:34 | Medium | Critical |
| F4 | Reflected XSS in /login response | app.py:37 | (manual) | High |
| F5 | OS command injection in /ping | app.py:47 | High | Critical |
| F6 | Insecure deserialization (pickle) in /profile | app.py:55 | Medium | Critical |
| F7 | Path traversal in /read | app.py:63 | (manual) | High |
| F8 | eval() on user input in /run_diag | app.py:71 | Medium | Critical |
| F9 | Flask debug=True in production | app.py:76 | High | Critical |
| F10 | Binding to 0.0.0.0 (all interfaces) | app.py:76 | Medium | Medium |

Manual review added F4 and F7, which the static tool did not flag: automated
tools are a starting point, not a complete audit.

## 3. Detailed findings and remediation

### F3 - SQL injection (Critical)
The login query concatenates `username` and `password` directly into SQL:
```python
query = "SELECT * FROM users WHERE username = '" + username + "' AND ..."
```
An input such as `' OR '1'='1` bypasses authentication entirely.
**Fix:** parameterized queries (`db.execute("... WHERE username = ?", (username,))`).

### F5 - OS command injection (Critical)
`/ping` runs `subprocess.check_output("ping -c 1 " + host, shell=True)`.
A host value like `127.0.0.1; cat /etc/passwd` executes arbitrary commands.
**Fix:** validate the host against a strict allow-list regex, drop `shell=True`,
and pass arguments as a list.

### F6 - Insecure deserialization (Critical)
`pickle.loads(request.get_data())` deserializes attacker-controlled bytes.
A crafted pickle payload executes arbitrary code on the server.
**Fix:** never unpickle untrusted data; use JSON with type checking.

### F8 - eval() on user input (Critical)
`/run_diag` passes the `expr` parameter straight to `eval()`, giving callers a
full Python interpreter on the server.
**Fix:** `ast.literal_eval`, which only evaluates literals, plus error handling.

### F9 - Debug mode enabled (Critical)
`app.run(debug=True)` exposes the Werkzeug debugger, which allows remote code
execution when reachable.
**Fix:** `debug=False` in any deployed environment; bind to 127.0.0.1 unless
the service must be public (F10).

### F7 - Path traversal (High)
`/read` opens `/var/data/<filename>` with no validation; `../../etc/passwd`
reads arbitrary files.
**Fix:** strip directory components (`os.path.basename`), canonicalize with
`os.path.realpath`, and verify the result stays inside the allowed directory.

### F4 - Reflected XSS (High)
The login success message returns the username unescaped; a username like
`<script>...</script>` runs in the victim's browser.
**Fix:** escape all user-controlled output (`flask.escape` / template
auto-escaping).

### F1 / F2 - Hardcoded secrets (Low severity, high impact)
The Flask secret key and admin credentials are committed to source control.
Anyone with repo access can forge sessions or log in as admin.
**Fix:** load secrets from environment variables or a secrets manager; rotate
any secret that was ever committed.

## 4. Secure coding best practices (checklist)

1. Never build SQL by string concatenation - always use parameterized queries.
2. Never pass user input to a shell; validate with allow-lists and use
   argument arrays.
3. Never deserialize untrusted data with pickle; use JSON.
4. Never call `eval`/`exec` on input; use `ast.literal_eval` for literals.
5. Escape all user-controlled output to prevent XSS.
6. Keep secrets out of source code; use environment variables or a vault.
7. Run with `debug=False` and minimal network exposure in production.
8. Canonicalize and confine file paths to an allowed directory.
9. Add SAST (e.g. Bandit) to CI so these classes of bug are caught on commit.

## 5. Verification

| Scan | Issues |
|------|--------|
| Bandit on `vulnerable_app/app.py` | 10 findings (see `bandit_report_raw.txt`) |
| Bandit on `fixed_app.py` | 3 informational notes about legitimate subprocess use; every exploitable finding resolved |

## 6. Conclusion

The review found 10 vulnerabilities, 5 of them directly exploitable for remote
code execution or authentication bypass. All were remediated in
`fixed_app.py` and the fixes were verified by re-scanning. Combining a static
analyzer with manual review proved essential: the tool caught the dangerous
sinks quickly, while manual inspection added the XSS and path traversal
issues the tool missed.
