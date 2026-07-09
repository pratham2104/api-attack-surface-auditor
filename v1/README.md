# v1.0 — Single-file scanner

Original version. One file, 5 test categories, ran against Move More and found 2 vulnerabilities.

## Run
```bash
python3 fuzz_movmore.py
```

## Findings
- Missing rate limiting on /api/auth/login
- /api/health publicly accessible

Replaced by v2.0 which introduced a modular architecture, 3 new test categories, and found 5 vulnerabilities including a critical SQL injection.
