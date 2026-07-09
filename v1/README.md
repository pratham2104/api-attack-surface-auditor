# API Attack Surface Auditor — v1.0

Original single-file version of the scanner. Replaced by v2.0 which introduced a modular architecture, 3 new test categories, and found 5 vulnerabilities including a critical SQL injection. See the main README for the full project.

---

## What this version has

One file — `fuzz_movmore.py` — that runs 5 security tests against a REST API:

- Missing authentication — hits every endpoint with no token
- BOLA/IDOR — low-privilege user requesting high-privilege resources by ID
- JWT attacks — alg:none and role tampering
- Mass assignment — injects admin fields into POST/PUT bodies
- Rate limiting — 50 rapid login requests, flags if no 429

---

## Findings from v1 scan (2026-07-05)

```
=================================================================
  MOVE MORE — SECURITY SCAN REPORT
  2026-07-05 15:40:18   http://localhost:3001
=================================================================

  [VULNERABLE]  Missing Rate Limiting
  Detail   : 50 rapid login attempts — no 429 returned

  [INFO]        /api/health public — accepted risk

  [SAFE]        BOLA/IDOR
  [SAFE]        JWT Attacks
  [SAFE]        Mass Assignment

=================================================================
  Vulnerabilities found : 2
  Checks passed         : 3
=================================================================
```

---

## How to run

```bash
pip3 install httpx
```

Paste tokens into `fuzz_movmore.py` at the top:

```python
BASE_URL        = "http://localhost:3001"
TOKEN_EMPLOYEE  = "paste_token_here"
TOKEN_ADMIN     = "paste_token_here"
```

```bash
python3 fuzz_movmore.py
```
