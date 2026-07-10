# API Attack Surface Auditor

During my internship at Calculus Cloud Solutions, I worked across SOC analysis, network security, and vendor evaluation — but I kept running into a gap: most security tooling I used was either enterprise-grade and opaque, or too generic to be educational. After the internship wrapped up, I wanted to build something from scratch that I actually understood end to end. Move More is a corporate wellness platform I had worked on during a separate engagement with Tetherify — and since I owned the codebase, it was the perfect real target. This scanner is a personal project built entirely post-internship, independently, to deepen my understanding of API security and give myself a structured way to audit an application I had written myself.

---

## What it tests

| Test | OWASP | MITRE ATT&CK | Description |
|---|---|---|---|
| OpenAPI discovery | API8:2023 | T1592 | Auto-discovers all endpoints from spec — no hardcoded routes |
| Missing authentication | API2:2023 | T1078 | Hits every discovered endpoint with no token |
| BOLA / IDOR | API1:2023 | T1083 | Low-privilege user requests high-privilege resources by ID |
| JWT alg:none | API2:2023 | T1528 | Strips signature, sets alg to none — checks if accepted |
| JWT role tampering | API5:2023 | T1134.001 | Modifies role claim without re-signing |
| Mass assignment | API6:2023 | T1548 | Injects admin fields into POST/PUT bodies |
| Rate limiting | API4:2023 | T1110 | 50 rapid login requests — flags if no 429 returned |
| Security headers | API8:2023 | T1059.007 | Checks for missing CSP, HSTS, X-Frame-Options, and more |
| CORS misconfiguration | API8:2023 | T1185 | Sends evil origin — checks if server reflects it |
| SQL injection | API10:2023 | T1190 | Fuzzes discovered parameters with SQLi payloads |
| SSRF | API7:2023 | T1090 | Injects internal URLs — baseline comparison to eliminate false positives |
| OAuth 2.0 / SSO | API2:2023 | T1550.001 | Redirect URI manipulation, state CSRF, token in URL |
| API versioning | API9:2023 | T1190 | Probes deprecated version prefixes for unprotected endpoints |
| Timing attack | API2:2023 | T1110.003 | Measures response time delta between valid/invalid usernames |
| TLS / SSL audit | API8:2023 | T1557 | Checks TLS version, certificate expiry, HSTS, HTTPS enforcement |
| Business logic | API3:2023 | T1565 | Negative values, integer overflow, race conditions, future timestamps |

---

## What changed in v6 — the architectural shift

Every version before v6 hardcoded the list of routes to test. You had to know the API before you could scan it.

v6 runs OpenAPI auto-discovery first. It probes 12 common spec locations (`/swagger.json`, `/openapi.json`, `/api-docs`, etc.), parses the spec if found, and builds an `api_map` — a structured representation of every endpoint, method, and parameter the API exposes. Every scanner module then reads from `api_map` instead of a hardcoded list.

```
Target API
    ↓
OpenAPI discovery → api_map (routes, params, auth schemes, OAuth flows)
    ↓
All 15 modules run in parallel using the discovered surface
    ↓
scan_report.txt  ·  scan_report.html  ·  scan_report.json
    ↓
generate_dashboard.py → dashboard.html
```

If no spec is found the scanner falls back to a curated route list and injects common parameter names. Either way it runs without configuration.

---

## Real findings on a live app

Scanned against **Move More** — a production corporate wellness platform with JWT-based RBAC, PostgreSQL backend, and endpoints across auth, users, activities, challenges, leaderboard, and admin.

```
======================================================================
  API ATTACK SURFACE AUDITOR v6.0 — SCAN REPORT
  2026-07-10 16:33:36   http://localhost:3001
======================================================================

  [CRITICAL]  SQL Injection
  MITRE    : T1190 — Exploit Public-Facing Application
  CVSS     : 9.8  AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
  Detail   : 500 error on GET /api/activities — 'limit' param unsanitized

  [HIGH]  Missing Header: Content-Security-Policy
  MITRE    : T1059.007 — JavaScript (XSS enablement)
  CVSS     : 4.7  AV:N/AC:H/PR:N/UI:R/S:C/C:L/I:L/A:N

  [MEDIUM]  Missing Rate Limiting
  MITRE    : T1110 — Brute Force
  CVSS     : 5.3  AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N

  [LOW]  API Discovery — no OpenAPI spec found
  [LOW]  Missing Header: Permissions-Policy
  [INFO]  Missing Auth — /api/health (accepted risk)
  [INFO]  TLS — HTTP Only (localhost, expected for dev)

  [SAFE]  BOLA/IDOR · JWT Attacks · Mass Assignment · CORS
  [SAFE]  SSRF · OAuth/SSO · API Versioning · Timing Attack
  [SAFE]  Business Logic

======================================================================
  Vulnerabilities : 8      Passed : 9      Total checks : 17
======================================================================
```

---

### Finding 1: SQL injection on `/api/activities` (Critical — CVSS 9.8)

**OWASP:** API10:2023  
**MITRE ATT&CK:** T1190 — Exploit Public-Facing Application  
**CVSS v3.1:** `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` → 9.8

The `limit` query parameter was passed unsanitized into the database query. Injecting `' OR '1'='1` caused HTTP 500 — the payload reached the database layer.

**Remediation applied:**
```javascript
const limit = parseInt(req.query.limit) || 10
if (isNaN(limit) || limit < 1 || limit > 100) {
  return res.status(400).json({ error: "Invalid limit parameter" })
}
```

---

### Finding 2: Missing rate limit on login endpoint (Medium — CVSS 5.3)

**OWASP:** API4:2023  
**MITRE ATT&CK:** T1110 — Brute Force  
**CVSS v3.1:** `AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N` → 5.3

50 consecutive login attempts with wrong credentials, no 429 returned. `express-rate-limit` was installed but never wired up.

**Remediation applied:**
```javascript
const loginLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 10 })
app.use('/api/auth/login', loginLimiter)
```

---

## New in v6 — module deep dives

### OpenAPI auto-discovery

Probes 12 common spec paths in order, parses Swagger 2.x and OpenAPI 3.x formats, extracts every endpoint, method, parameter, auth scheme, and OAuth flow. The resulting `api_map` is passed to every other module so they test the real discovered surface instead of a hardcoded list.

If no spec exists (like Move More), flags it as a low-severity misconfiguration — undocumented APIs are harder to audit and harder to secure.

### OAuth 2.0 / SSO testing

Three attack vectors:

**Redirect URI manipulation** — Sends authorization requests with `redirect_uri` set to `https://evil.com`. If the server redirects there, an attacker can intercept authorization codes.

**State parameter CSRF** — Omits the `state` parameter. If the server processes the request without it, OAuth flows can be initiated on behalf of victims.

**Token in URL** — Sends the JWT as a query parameter instead of a header. Tokens in URLs appear in server logs, proxy logs, and browser history.

### API versioning attacks

Takes every discovered route, strips the version prefix, and re-probes under `/v1/`, `/v2/`, `/api/beta/`, `/api/legacy/`, and 8 other prefixes — both with and without auth. Old versions routinely bypass security controls that were added to the current version. One unauthenticated 200 from a deprecated endpoint is a full auth bypass.

### Timing attack — username enumeration

Sends 20 requests with a known-valid username and 20 with an invalid username, both using wrong passwords. Measures mean response time for each group. A server that validates username existence before hashing takes longer for valid usernames — that delta leaks which accounts exist. Flags if the difference exceeds 50ms.

### TLS / SSL audit

Checks TLS version (flags TLS 1.0/1.1 as deprecated per RFC 8996), certificate expiry (flags within 30 days), HSTS header presence and `max-age` value, and HTTP-to-HTTPS redirect behavior. For localhost targets, flags as informational and notes production requirements.

### Business logic testing

Move More specific tests that no generic scanner would catch:

- Negative duration and step count submissions
- Integer overflow (2,147,483,648+ values in numeric fields)
- Zero-duration activities that may award points
- Future timestamps on activity logs
- Race condition: 5 simultaneous identical submissions to detect duplicate point earning

---

## How to run

**Install**
```bash
pip3 install -r requirements.txt
```

**Recommended — auto-login, all outputs, dashboard**
```bash
python3 main.py --url http://localhost:3001 \
  --cred-a "EMP-001 yourpassword" \
  --cred-b "EMP-HR-001 Password1" \
  --format all
```

**Generate security dashboard**
```bash
python3 generate_dashboard.py
```
Opens `dashboard.html` in any browser — severity breakdown, MITRE tactic heatmap, OWASP coverage, CVSS scatter plot, full findings table.

**All available flags**
```
--url            Target API base URL
--cred-a         Auto-login: "employee_id password" (low-privilege)
--cred-b         Auto-login: "employee_id password" (high-privilege)
--token-a        Manual JWT token (alternative to --cred-a)
--token-b        Manual JWT token (alternative to --cred-b)
--format         html | json | all  (default: html)
--output         HTML report output path
--diff           Path to previous scan JSON for delta report
--no-discovery   Skip OpenAPI probing, use fallback route list
--user-a         User ID for token-a (default: 3)
--user-b         User ID for token-b (default: 1)
```

**Four outputs per scan**
```
scan_report.txt    plain text with CVSS vectors and MITRE IDs
scan_report.html   interactive HTML with expandable finding cards
scan_report.json   structured JSON for SIEM ingestion
dashboard.html     security dashboard (run generate_dashboard.py)
```

**Diff against a previous scan**
```bash
python3 main.py ... --diff ~/Desktop/lab/previous_scan.json
```
Generates `diff_report.html` — new findings, fixed findings, unchanged.

---

## Project structure

```
api-attack-surface-auditor/
├── main.py                    # async entry point, argparse CLI, auto token refresh
├── generate_dashboard.py      # reads scan_report.json → dashboard.html
├── requirements.txt
├── .github/
│   └── workflows/
│       └── scan.yml           # automated weekly scan, artifact upload
├── scanner/
│   ├── openapi_discovery.py   # auto-discovers endpoints from OpenAPI spec
│   ├── auth.py                # missing authentication
│   ├── bola.py                # BOLA / IDOR
│   ├── jwt_attacks.py         # alg:none + role tampering
│   ├── mass_assign.py         # mass assignment
│   ├── rate_limit.py          # rate limiting
│   ├── headers.py             # security headers audit
│   ├── cors.py                # CORS misconfiguration
│   ├── sqli.py                # SQL injection fuzzer
│   ├── ssrf.py                # SSRF with baseline comparison
│   ├── oauth.py               # OAuth 2.0 / SSO vulnerability testing
│   ├── versioning.py          # deprecated API version probing
│   ├── timing.py              # timing attack username enumeration
│   ├── tls.py                 # TLS/SSL audit
│   └── business_logic.py      # Move More specific logic tests
├── reporter/
│   ├── html_report.py         # HTML report with MITRE + CVSS v3.1
│   ├── mitre_map.py           # ATT&CK mappings + CVSS vectors for all 16 categories
│   ├── json_report.py         # SIEM-compatible JSON output
│   └── diff_report.py         # delta report between two scans
└── v1/
    ├── fuzz_movmore.py        # original single-file version
    └── fuzzer_report.txt      # original 2-finding report
```

---

## Adapting to any API

Point it at any REST API with an OpenAPI spec and it configures itself:

```bash
python3 main.py --url https://your-api.com \
  --token-a "your_jwt_here" \
  --token-b "admin_jwt_here"
```

Discovery finds the spec, maps the endpoints, and every module tests the actual surface. For APIs without a spec, update `FALLBACK_ROUTES` in `scanner/auth.py` and `FALLBACK_TARGETS` in `scanner/sqli.py`.

---

## Changelog

### v6.0
- OpenAPI auto-discovery — scanner finds endpoints itself, no hardcoded routes
- All modules updated to consume `api_map` from discovery
- 6 new scanner modules: OAuth 2.0, API versioning, timing attack, TLS/SSL, business logic
- Total test categories: 16 (up from 10 in v5)
- `generate_dashboard.py` — standalone security dashboard from scan JSON
- MITRE ATT&CK mappings expanded to cover all 16 categories

### v5.0
- Auto token refresh via `--cred-a` / `--cred-b`
- CVSS v3.1 vector strings and scores on every finding
- JSON output for SIEM ingestion
- Scan diff / delta report
- SSRF module with baseline comparison

### v4.0
- Async parallel scanning — all modules run simultaneously
- argparse CLI — run with flags, no file editing
- GitHub Actions automated weekly scan

### v3.0
- HTML report with MITRE ATT&CK mapping
- Severity color coding, expandable finding cards

### v2.0
- Modular refactor — 8 independent scanner modules
- Security headers, CORS, SQL injection added
- Found 5 vulnerabilities including critical SQLi on live app

### v1.0
- Single-file scanner — 5 test categories, 2 findings

---

## Tech stack

Python 3 · asyncio · httpx · argparse · ssl · base64 · Chart.js · OWASP API Security Top 10 · MITRE ATT&CK · CVSS v3.1 · JWT (RFC 7519) · GitHub Actions · Express.js target

---

## Author

Pratham Agarwal — Computer Science & Data Science, Central Michigan University  
[GitHub](https://github.com/pratham2104) · [Cybersecurity Portfolio](https://github.com/pratham2104/Pratham-Cybersecurity-Portfolio)
