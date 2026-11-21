# Task 3: Secure Coding Review
CodeAlpha Cyber Security Internship | Mahmoud Mohamed Sayed

A security audit of a small Python/Flask web application, combining automated
static analysis (Bandit) with manual review.

## Contents
- `vulnerable_app/app.py` - the audit target (deliberately vulnerable demo app)
- `bandit_report_raw.txt` - raw output of the Bandit static analysis scan
- `secure_coding_review_report.md` - full findings, severity, and remediation
- `fixed_app.py` - remediated version; every fix is marked FIX and cross-referenced

## Reproduce the scan
```bash
pip install bandit
bandit -r vulnerable_app -f txt -o bandit_report_raw.txt
bandit fixed_app.py
```
