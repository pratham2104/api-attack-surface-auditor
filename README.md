# API Attack Surface Auditor

During my internship at Calculus Cloud Solutions, I worked across SOC analysis, network security, and vendor evaluation — but I kept running into a gap: most security tooling I used was either enterprise-grade and opaque, or too generic to be educational. After the internship wrapped up, I wanted to build something from scratch that I actually understood end to end. Move More is a corporate wellness platform I had worked on during a separate engagement with Tetherify — and since I owned the codebase, it was the perfect real target. This scanner is a personal project built entirely post-internship, independently, to deepen my understanding of API security and give myself a structured way to audit an application I had written myself.

---

## What it tests

| Test | OWASP API Category | Description |
|---|---|---|
| Missing authentication | API2:2023 | Hits every endpoint with no token — flags any 200 response |
| BOLA / IDOR | API1:2023 | Authenticates as low-privilege user, requests high-privilege resources by ID |
| JWT alg:none | API2:2023 | Strips signature, sets alg to none — checks if server accepts unsigned token |
| JWT role tampering | API5:2023 | Modifies role claim without re-signing — checks if server enforces signature |
| Mass assignment | API6:2023 | Injects admin fields into POST/PUT bodies — checks if reflected in response |
| Rate limiting | API4:2023 | Fires 50 rapid login requests — flags if no 429 is returned |
| Security headers | API8:2023 | Checks responses for missing CSP, HSTS, X-Frame-Options, and more |
| CORS misconfiguration | API8:2023 | Sends evil origin header — checks if server reflects it |
| SQL injection | API10:2023 | Fuzzes query params and body fields with SQLi payloads |

---

## Real findings on a live app

Scanned against **Move More** — a production corporate wellness platform with JWT-based RBAC, PostgreSQL backend, and endpoints across auth, users, activities, challenges, leaderboard, and admin.

```
=================================================================
  API ATTACK SURFACE AUDITOR — SCAN REPORT
  2026-07-09 17:24:36   http://localhost:3001
=================================================================

  [CRITICAL]  SQL Injection
  OWASP    : API10:2023 — Unsafe Consumption of APIs
  Detail   : 500 error on GET /api/activities with payload in field
             'limit' — possible unhandled SQL error
  Request  : GET http://localhost:3001/api/activities  limit="' OR '1'='1"
  Response : HTTP 500: {"error":"server_error","message":"Failed to fetch activities."}

  [HIGH]  Missing Header: Content-Security-Policy
  OWASP    : API8:2023 — Security Misconfiguration
  Detail   : 'Content-Security-Policy' absent on: /api/health, /api/activities.
             Prevents XSS by controlling which scripts the browser can load.

  [MEDIUM]  Missing Rate Limiting
  OWASP    : API4:2023 — Unrestricted Resource Consumption
  Detail   : 50 rapid login attempts completed with no 429 returned

  [LOW]  Missing Header: Permissions-Policy
  OWASP    : API8:2023 — Security Misconfiguration

  [INFO]  Missing Auth — /api/health
  OWASP    : API2:2023 — Broken Authentication
  Status   : Accepted risk, intentionally public

  [SAFE]    BOLA/IDOR
  [SAFE]    JWT Attacks
  [SAFE]    Mass Assignment
  [SAFE]    CORS

=================================================================
  Vulnerabilities : 5
  Passed          : 4
  Total checks    : 9
=================================================================
```

---

### Finding 1: SQL injection on `/api/activities` (Critical)

**Severity:** Critical  
**OWASP:** API10:2023 — Unsafe Consumption of APIs

The `limit` query parameter on the activities endpoint was passed unsanitized into a database query. Injecting `' OR '1'='1` caused the server to return HTTP 500 — meaning the payload reached the database layer and caused an unhandled exception.

**Attack scenario:** An attacker can manipulate query logic, extract data from other tables using UNION-based injection, or crash the application by passing malformed SQL through any unvalidated parameter.

**Remediation applied:**

```javascript
const limit = parseInt(req.query.limit) || 10
if (isNaN(limit) || limit < 1 || limit > 100) {
  return res.status(400).json({ error: "Invalid limit parameter" })
}
```

---

### Finding 2: Missing rate limit on login endpoint (Medium)

**Severity:** Medium  
**OWASP:** API4:2023 — Unrestricted Resource Consumption  
**CVSS v3 Score:** 5.3

The login endpoint accepted 50 consecutive authentication attempts with wrong credentials and returned no `429 Too Many Requests`. `express-rate-limit` was installed as a dependency but never wired into the application middleware.

**Remediation applied:**

```javascript
const rateLimit = require('express-rate-limit')

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  message: { error: 'Too many login attempts. Try again in 15 minutes.' }
})

app.use('/api/auth/login', loginLimiter)
```

---

### Finding 3: Missing Content-Security-Policy header (High)

**Severity:** High  
**OWASP:** API8:2023 — Security Misconfiguration

No `Content-Security-Policy` header was present on any endpoint response. Without CSP, the browser has no restrictions on which scripts, stylesheets, or resources can execute — leaving the app open to XSS attacks if any user input ever reaches the DOM unsanitized.

**Remediation:**

```javascript
app.use((req, res, next) => {
  res.setHeader("Content-Security-Policy", "default-src 'self'")
  next()
})
```

---

## How the JWT attack module works

Two forged tokens are constructed entirely in Python — no server secret required.

**alg:none attack** — The JWT header specifies the signing algorithm. If a server blindly trusts the `alg` field without enforcing its own expected algorithm, an attacker can set `alg: none`, strip the signature entirely, and the server accepts it as valid.

```
Original:  eyJhbGciOiJIUzI1NiJ9.eyJ1c2VyIjoiZW1wbG95ZWUifQ.SIGNATURE
Forged:    eyJhbGciOiJub25lIn0.eyJ1c2VyIjoiZW1wbG95ZWUifQ.
```

**Role tampering** — JWT payloads are base64 encoded, not encrypted. Anyone can decode, modify, and re-encode the payload. The only thing preventing tampering is the signature — which the server must verify against its own secret.

```python
payload = base64.urlsafe_b64decode(token.split('.')[1] + '==')
payload['role'] = 'admin'
forged = f"{header}.{new_payload}."
```

Move More correctly rejected both attacks — signature verification enforced on every protected route.

---

## How the mass assignment module works

The scanner injects privileged fields alongside every legitimate POST/PUT request body and checks if the server reflects or applies them:

```python
injected = {
    "role": "admin",
    "isAdmin": True,
    "credits": 99999,
    "is_first_login": False,
    "permissions": ["all"]
}
```

If any injected field name or value appears in the response, the server accepted a field it should have ignored. Move More correctly rejected all injected fields.

---

## How the CORS module works

Sends every request with `Origin: https://evil.com` and checks the `Access-Control-Allow-Origin` response header. Three failure modes:

- Evil origin reflected AND credentials allowed — Critical
- Evil origin reflected, no credentials — Medium
- Wildcard origin with credentials — Medium

Move More correctly scoped its CORS policy to its own origin.

---

## BOLA testing methodology

Broken Object Level Authorization is the #1 vulnerability in the OWASP API Top 10. The scanner authenticates as a low-privilege user (id=3, role=employee) and requests resources belonging to a high-privilege user (id=1, role=admin):

```
GET /api/users/1          (as employee)   → expected 403
GET /api/users/1/badges   (as employee)   → expected 403
GET /api/admin/users/1    (as employee)   → expected 403
```

Move More returned `403 Forbidden` on all cross-user resource requests.

---

## Running it yourself

**Install dependencies**

```bash
pip3 install -r requirements.txt
```

**Get fresh JWT tokens** (expire in 15 minutes)

```bash
curl -X POST http://localhost:3001/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"employee_id":"EMP-001","password":"yourpassword"}'
```

**Configure**

Open `main.py` and set at the top:

```python
BASE_URL  = "http://localhost:3001"
TOKEN_A   = "paste_low_privilege_token"
TOKEN_B   = "paste_high_privilege_token"
```

**Run**

```bash
python3 main.py
```

Report prints to terminal and saves to `scan_report.txt`.

---

## Project structure

```
api-attack-surface-auditor/
├── main.py                 # entry point — orchestrates all modules
├── requirements.txt
├── scan_report.txt         # latest scan output
├── scanner/
│   ├── auth.py             # missing authentication
│   ├── bola.py             # BOLA / IDOR
│   ├── jwt_attacks.py      # alg:none + role tampering
│   ├── mass_assign.py      # mass assignment
│   ├── rate_limit.py       # rate limiting
│   ├── headers.py          # security headers audit
│   ├── cors.py             # CORS misconfiguration
│   └── sqli.py             # SQL injection fuzzer
└── v1/
    ├── fuzz_movmore.py     # original single-file version
    └── fuzzer_report.txt   # original 2-finding report
```

---

## Adapting to your own API

1. Update `BASE_URL` and `KNOWN_ROUTES` in `main.py`
2. Set two tokens representing different privilege levels
3. Set user IDs that correspond to those accounts
4. Update BOLA target paths to match your resource endpoints

---

## Changelog

### v2.0
- Refactored into modular package — 8 independent scanner modules
- Added security headers audit, CORS misconfiguration, SQL injection fuzzer
- Found 5 vulnerabilities including critical SQL injection on live app
- Standardized finding format with OWASP category and severity per module
- Patched all findings in Move More and verified with re-scan

### v1.0
- Single-file scanner (`v1/fuzz_movmore.py`)
- 5 test categories: missing auth, BOLA, JWT attacks, mass assignment, rate limiting
- Found 2 vulnerabilities on first run against Move More

---

## Tech stack

Python 3 · httpx · base64 · OWASP API Security Top 10 · JWT (RFC 7519) · Express.js target

---

## Author

Pratham Agarwal — Computer Science & Data Science, Central Michigan University  
[GitHub](https://github.com/pratham2104) · [Cybersecurity Portfolio](https://github.com/pratham2104/Pratham-Cybersecurity-Portfolio)
