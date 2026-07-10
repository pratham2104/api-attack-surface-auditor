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
  API ATTACK SURFACE AUDITOR v4.0 — SCAN REPORT
  2026-07-09 20:17:16   http://localhost:3001
=================================================================

  [CRITICAL]  SQL Injection
  OWASP    : API10:2023 — Unsafe Consumption of APIs
  Detail   : 500 error on GET /api/activities with payload in field 'limit'
  Request  : GET http://localhost:3001/api/activities  limit="' OR '1'='1"
  Response : HTTP 500: {"error":"server_error","message":"Failed to fetch activities."}

  [HIGH]  Missing Header: Content-Security-Policy
  OWASP    : API8:2023 — Security Misconfiguration
  Detail   : 'Content-Security-Policy' absent on sampled endpoints.

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
**MITRE ATT&CK:** T1190 — Exploit Public-Facing Application

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
**MITRE ATT&CK:** T1110 — Brute Force  
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
**MITRE ATT&CK:** T1059.007 — JavaScript (XSS enablement)

No `Content-Security-Policy` header was present on any endpoint response. Without CSP, the browser has no restrictions on which scripts, stylesheets, or resources can execute.

**Remediation:**

```javascript
app.use((req, res, next) => {
  res.setHeader("Content-Security-Policy", "default-src 'self'")
  next()
})
```

---

## How to run

**Install dependencies**

```bash
pip3 install -r requirements.txt
```

**Run with CLI flags — no file editing needed**

```bash
python3 main.py --url http://localhost:3001 \
  --token-a "EMPLOYEE_JWT" \
  --token-b "ADMIN_JWT"
```

**Get fresh tokens** (expire in 15 minutes)

```bash
curl -X POST http://localhost:3001/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"employee_id":"EMP-001","password":"yourpassword"}'
```

**All available flags**

```
--url        Base URL of the target API  (default: http://localhost:3001)
--token-a    Low-privilege JWT token
--token-b    High-privilege JWT token
--output     Path for HTML report        (default: ~/Desktop/lab/scan_report.html)
--user-a     User ID for token-a         (default: 3)
--user-b     User ID for token-b         (default: 1)
```

**Two outputs generated per scan:**
- `scan_report.txt` — plain text terminal summary
- `scan_report.html` — full HTML report with MITRE ATT&CK mapping, open in any browser

---

## What v4.0 added over v3.0

**Async parallel scanning** — all 8 modules now run simultaneously using `asyncio.gather()` instead of sequentially. Scan time dropped from ~30 seconds to ~5 seconds.

**CLI argument support** — no more editing the file before each run. Pass everything as flags. Works with environment variables too — `TOKEN_A` and `TOKEN_B` are read automatically if set, making the tool CI/CD friendly.

**GitHub Actions pipeline** — `.github/workflows/scan.yml` runs the full scan automatically every Monday against a staging URL and uploads the HTML report as a downloadable artifact in the Actions tab.

---

## Project structure

```
api-attack-surface-auditor/
├── main.py                  # async entry point with argparse CLI
├── requirements.txt
├── .github/
│   └── workflows/
│       └── scan.yml         # automated weekly scan pipeline
├── scanner/
│   ├── auth.py              # missing authentication
│   ├── bola.py              # BOLA / IDOR
│   ├── jwt_attacks.py       # alg:none + role tampering
│   ├── mass_assign.py       # mass assignment
│   ├── rate_limit.py        # rate limiting
│   ├── headers.py           # security headers audit
│   ├── cors.py              # CORS misconfiguration
│   └── sqli.py              # SQL injection fuzzer
├── reporter/
│   ├── html_report.py       # HTML report with MITRE ATT&CK mapping
│   └── mitre_map.py         # MITRE ATT&CK technique mappings
└── v1/
    ├── fuzz_movmore.py      # original single-file version
    └── fuzzer_report.txt    # original 2-finding report
```

---

## Adapting to your own API

1. Update `--url` to point at your target
2. Pass two tokens representing different privilege levels via `--token-a` and `--token-b`
3. Update `KNOWN_ROUTES` in `scanner/auth.py` and BOLA targets in `scanner/bola.py`
4. Everything else runs automatically

---

## Changelog

### v4.0
- Rewrote all 8 scanner modules as async — parallel execution via asyncio.gather()
- Added argparse CLI — run with flags, no file editing required
- Added environment variable support for TOKEN_A and TOKEN_B
- Added GitHub Actions workflow — automated weekly scan with artifact upload

### v3.0
- Added HTML report generator with severity color coding and expandable finding cards
- Added MITRE ATT&CK technique mapping for every finding category
- Two outputs per scan: plain text summary + self-contained HTML report

### v2.0
- Refactored into modular package — 8 independent scanner modules
- Added security headers audit, CORS misconfiguration, SQL injection fuzzer
- Found 5 vulnerabilities including critical SQL injection on live app
- Patched all findings in Move More and verified with re-scan

### v1.0
- Single-file scanner (v1/fuzz_movmore.py)
- 5 test categories: missing auth, BOLA, JWT attacks, mass assignment, rate limiting
- Found 2 vulnerabilities on first run against Move More

---

## Tech stack

Python 3 · asyncio · httpx · argparse · base64 · OWASP API Security Top 10 · MITRE ATT&CK · JWT (RFC 7519) · GitHub Actions · Express.js target

---

## Author

Pratham Agarwal — Computer Science & Data Science, Central Michigan University  
[GitHub](https://github.com/pratham2104) · [Cybersecurity Portfolio](https://github.com/pratham2104/Pratham-Cybersecurity-Portfolio)
