# API Attack Surface Auditor

During my internship at Calculus Cloud Solutions, I worked across SOC analysis, network security, and vendor evaluation — but I kept running into a gap: most security tooling I used was either enterprise-grade and opaque, or too generic to be educational. After the internship wrapped up, I wanted to build something from scratch that I actually understood end to end. Move More is a corporate wellness platform I had worked on during a separate engagement with Tetherify — and since I owned the codebase, it was the perfect real target. This scanner is a personal project built entirely post-internship, independently, to deepen my understanding of API security and give myself a structured way to audit an application I had written myself.

---

## What it tests

| Test | OWASP API Category | MITRE ATT&CK | Description |
|---|---|---|---|
| Missing authentication | API2:2023 | T1078 | Hits every endpoint with no token — flags any 200 response |
| BOLA / IDOR | API1:2023 | T1083 | Authenticates as low-privilege user, requests high-privilege resources by ID |
| JWT alg:none | API2:2023 | T1528 | Strips signature, sets alg to none — checks if server accepts unsigned token |
| JWT role tampering | API5:2023 | T1134.001 | Modifies role claim without re-signing — checks if server enforces signature |
| Mass assignment | API6:2023 | T1548 | Injects admin fields into POST/PUT bodies — checks if reflected in response |
| Rate limiting | API4:2023 | T1110 | Fires 50 rapid login requests — flags if no 429 is returned |
| Security headers | API8:2023 | T1059.007 | Checks responses for missing CSP, HSTS, X-Frame-Options, and more |
| CORS misconfiguration | API8:2023 | T1185 | Sends evil origin header — checks if server reflects it |
| SQL injection | API10:2023 | T1190 | Fuzzes query params and body fields with SQLi payloads |
| SSRF | API7:2023 | T1090 | Injects internal URLs into params — flags response anomalies vs baseline |

---

## Real findings on a live app

Scanned against **Move More** — a production corporate wellness platform with JWT-based RBAC, PostgreSQL backend, and endpoints across auth, users, activities, challenges, leaderboard, and admin.

```
======================================================================
  API ATTACK SURFACE AUDITOR v5.0 — SCAN REPORT
  2026-07-10 16:00:22   http://localhost:3001
======================================================================

  [CRITICAL]  SQL Injection
  OWASP    : API10:2023 — Unsafe Consumption of APIs
  MITRE    : T1190 — Exploit Public-Facing Application
  CVSS     : 9.8  AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
  Detail   : 500 error on GET /api/activities with payload in field 'limit'
  Request  : GET http://localhost:3001/api/activities  limit="' OR '1'='1"
  Response : HTTP 500: {"error":"server_error","message":"Failed to fetch activities."}

  [HIGH]  Missing Header: Content-Security-Policy
  OWASP    : API8:2023 — Security Misconfiguration
  MITRE    : T1059.007 — JavaScript (XSS enablement)
  CVSS     : 4.7  AV:N/AC:H/PR:N/UI:R/S:C/C:L/I:L/A:N

  [MEDIUM]  Missing Rate Limiting
  OWASP    : API4:2023 — Unrestricted Resource Consumption
  MITRE    : T1110 — Brute Force
  CVSS     : 5.3  AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N

  [LOW]  Missing Header: Permissions-Policy
  OWASP    : API8:2023 — Security Misconfiguration
  MITRE    : T1185 — Browser Session Hijacking
  CVSS     : 3.1  AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N

  [INFO]  Missing Auth — /api/health
  Status   : Accepted risk, intentionally public

  [SAFE]    BOLA/IDOR · JWT Attacks · Mass Assignment · CORS · SSRF

======================================================================
  Vulnerabilities : 5
  Passed          : 5
  Total checks    : 10
======================================================================
```

---

### Finding 1: SQL injection on `/api/activities` (Critical — CVSS 9.8)

**OWASP:** API10:2023 — Unsafe Consumption of APIs  
**MITRE ATT&CK:** T1190 — Exploit Public-Facing Application  
**CVSS v3.1:** `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` → 9.8

The `limit` query parameter on the activities endpoint was passed unsanitized into a database query. Injecting `' OR '1'='1` caused the server to return HTTP 500 — the payload reached the database layer and triggered an unhandled exception.

**Attack scenario:** An attacker can manipulate query logic, extract data using UNION-based injection, or crash the service entirely through malformed SQL in any unvalidated parameter.

**Remediation applied:**

```javascript
const limit = parseInt(req.query.limit) || 10
if (isNaN(limit) || limit < 1 || limit > 100) {
  return res.status(400).json({ error: "Invalid limit parameter" })
}
```

---

### Finding 2: Missing Content-Security-Policy header (High — CVSS 4.7)

**OWASP:** API8:2023 — Security Misconfiguration  
**MITRE ATT&CK:** T1059.007 — JavaScript  
**CVSS v3.1:** `AV:N/AC:H/PR:N/UI:R/S:C/C:L/I:L/A:N` → 4.7

No CSP header present on any response. Without it the browser cannot restrict which scripts and resources execute — leaving the app open to XSS if any user input reaches the DOM unsanitized.

**Remediation:**

```javascript
app.use((req, res, next) => {
  res.setHeader("Content-Security-Policy", "default-src 'self'")
  next()
})
```

---

### Finding 3: Missing rate limit on login endpoint (Medium — CVSS 5.3)

**OWASP:** API4:2023 — Unrestricted Resource Consumption  
**MITRE ATT&CK:** T1110 — Brute Force  
**CVSS v3.1:** `AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N` → 5.3

50 consecutive login attempts with wrong credentials returned no 429. `express-rate-limit` was installed but never wired up.

**Remediation applied:**

```javascript
const loginLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 10 })
app.use('/api/auth/login', loginLimiter)
```

---

## How to run

**Install dependencies**

```bash
pip3 install -r requirements.txt
```

**Auto-login — no manual token management needed**

```bash
python3 main.py --url http://localhost:3001 \
  --cred-a "EMP-001 yourpassword" \
  --cred-b "EMP-HR-001 Password1"
```

**All output formats at once**

```bash
python3 main.py --url http://localhost:3001 \
  --cred-a "EMP-001 yourpassword" \
  --cred-b "EMP-HR-001 Password1" \
  --format all
```

**Compare against a previous scan**

```bash
python3 main.py ... --diff ~/Desktop/lab/previous_scan.json
```

**All available flags**

```
--url         Target API base URL
--cred-a      Auto-login: "employee_id password" for low-privilege user
--cred-b      Auto-login: "employee_id password" for high-privilege user
--token-a     Manual JWT token (alternative to --cred-a)
--token-b     Manual JWT token (alternative to --cred-b)
--format      Output format: html | json | all  (default: html)
--output      HTML report path
--diff        Path to previous scan JSON for delta report
--user-a      User ID for token-a (default: 3)
--user-b      User ID for token-b (default: 1)
```

**Three outputs generated per scan:**
- `scan_report.txt` — plain text terminal summary with CVSS vectors
- `scan_report.html` — full HTML report with MITRE ATT&CK links, expandable cards, severity colors
- `scan_report.json` — structured JSON for SIEM ingestion (Splunk, Microsoft Sentinel)

**Delta report** (when `--diff` is used):
- `diff_report.html` — shows new findings, fixed findings, and unchanged findings side by side

---

## CVSS v3.1 scoring

Every finding includes a full CVSS v3.1 vector string and numeric score, not just a severity label. The vector encodes the exploitability and impact metrics that feed into the score:

```
AV:N  — Attack Vector: Network (exploitable remotely)
AC:L  — Attack Complexity: Low (no special conditions)
PR:N  — Privileges Required: None
UI:N  — User Interaction: None
S:U   — Scope: Unchanged
C:H   — Confidentiality Impact: High
I:H   — Integrity Impact: High
A:H   — Availability Impact: High
      → Score: 9.8 Critical
```

---

## JSON output for SIEM ingestion

Every scan produces a `scan_report.json` with full structured data per finding:

```json
{
  "scan_metadata": {
    "tool": "API Attack Surface Auditor v5.0",
    "timestamp": "2026-07-10T20:00:22Z",
    "target": "http://localhost:3001",
    "vulnerable": 5,
    "safe": 5
  },
  "findings": [
    {
      "status": "VULNERABLE",
      "category": "SQL Injection",
      "severity": "Critical",
      "mitre": { "technique_id": "T1190", "tactic": "Initial Access" },
      "cvss": { "vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "score": 9.8 }
    }
  ]
}
```

This format is compatible with Splunk HEC and Microsoft Sentinel Analytics ingestion pipelines.

---

## SSRF detection methodology

The SSRF module takes a baseline response for each endpoint first, then compares injected responses against it. A server that ignores unknown params returns the same response every time — flagging those would be a false positive. The scanner only flags when:

- Internal content strings appear in the response (AWS metadata keys, Redis version, PostgreSQL banner)
- Response length changes by more than 20% — indicating the server processed the injected URL
- A 500 error is triggered by an internal URL that the clean request didn't produce

---

## How the JWT attack module works

Two forged tokens are constructed entirely in Python — no server secret required.

**alg:none** — sets `alg` to `none` and strips the signature entirely. If the server trusts the header's algorithm field without enforcing its own expected value, the unsigned token is accepted.

**Role tampering** — decodes the base64 payload, changes `role` from `employee` to `admin`, re-encodes without re-signing. If signature verification is skipped, the tampered role takes effect.

Move More correctly rejected both — signature verification enforced on every protected route.

---

## Project structure

```
api-attack-surface-auditor/
├── main.py                    # async entry point, argparse CLI, auto token refresh
├── requirements.txt
├── .github/
│   └── workflows/
│       └── scan.yml           # automated weekly scan, artifact upload
├── scanner/
│   ├── auth.py                # missing authentication
│   ├── bola.py                # BOLA / IDOR
│   ├── jwt_attacks.py         # alg:none + role tampering
│   ├── mass_assign.py         # mass assignment
│   ├── rate_limit.py          # rate limiting
│   ├── headers.py             # security headers audit
│   ├── cors.py                # CORS misconfiguration
│   ├── sqli.py                # SQL injection fuzzer
│   └── ssrf.py                # SSRF with baseline comparison
├── reporter/
│   ├── html_report.py         # HTML report with MITRE + CVSS
│   ├── mitre_map.py           # MITRE ATT&CK mappings + CVSS v3.1 vectors
│   ├── json_report.py         # SIEM-compatible JSON output
│   └── diff_report.py         # delta report between two scans
└── v1/
    ├── fuzz_movmore.py        # original single-file version
    └── fuzzer_report.txt      # original 2-finding report
```

---

## Changelog

### v5.0
- Auto token refresh via `--cred-a` / `--cred-b` — no more manual curl before each run
- CVSS v3.1 vector strings and numeric scores on every finding in all output formats
- JSON output (`--format json` or `--format all`) for Splunk / Sentinel ingestion
- Scan diff / delta report (`--diff`) — shows new, fixed, and unchanged findings
- SSRF module (9th test category) with baseline comparison to eliminate false positives
- MITRE ATT&CK mappings expanded to cover all 10 test categories

### v4.0
- Rewrote all scanner modules as async — parallel execution via asyncio.gather()
- Added argparse CLI — run with flags, no file editing required
- Added GitHub Actions workflow — automated weekly scan with artifact upload

### v3.0
- Added HTML report generator with severity color coding and expandable finding cards
- Added MITRE ATT&CK technique mapping for every finding category

### v2.0
- Refactored into modular package — 8 independent scanner modules
- Added security headers audit, CORS misconfiguration, SQL injection fuzzer
- Found 5 vulnerabilities including critical SQL injection on live app
- Patched findings in Move More and verified with re-scan

### v1.0
- Single-file scanner (v1/fuzz_movmore.py)
- 5 test categories — found 2 vulnerabilities on first run

---

## Tech stack

Python 3 · asyncio · httpx · argparse · base64 · OWASP API Security Top 10 · MITRE ATT&CK · CVSS v3.1 · JWT (RFC 7519) · GitHub Actions · Express.js target

---

## Author

Pratham Agarwal — Computer Science & Data Science, Central Michigan University  
[GitHub](https://github.com/pratham2104) · [Cybersecurity Portfolio](https://github.com/pratham2104/Pratham-Cybersecurity-Portfolio)
