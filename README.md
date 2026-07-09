# API Attack Surface Auditor

Automated REST API security scanner that tests production applications against the OWASP API Security Top 10. Built and deployed against a live Node.js/Express application — found real vulnerabilities, filed findings, and patched them.

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

---

## Real findings on a live app

Scanned against **Move More** — a production wellness platform with JWT-based RBAC, a PostgreSQL backend, and endpoints across auth, users, activities, challenges, leaderboard, and admin.

```
=================================================================
  MOVE MORE — SECURITY SCAN REPORT
  2026-07-05 15:40:18   http://localhost:3001
=================================================================

  [VULNERABLE]  Missing Auth
  Detail   : /api/health returns 200 with no token
  Request  : GET http://localhost:3001/api/health (no Authorization header)
  Response : HTTP 200: {"status":"ok","timestamp":"2026-07-05T19:40:17.843Z",
             "uptime":3801,"checks":{"database":"ok","jwt":"ok"}}

  [VULNERABLE]  Missing Rate Limiting
  Detail   : 50 rapid login attempts completed — no 429 returned
  Request  : POST /api/auth/login x50, wrong credentials, no delay
  Response : No 429 Too Many Requests received across 50 requests

  [SAFE]        BOLA/IDOR
  [SAFE]        JWT Attacks
  [SAFE]        Mass Assignment
=================================================================
  Vulnerabilities found : 2
  Checks passed         : 3
=================================================================
```

### Finding 1: Unauthenticated access to `/api/health`

**Severity:** Informational  
**OWASP:** API2:2023 — Broken Authentication  
**Status:** Accepted risk — intentional by design

The health endpoint returned `200 OK` with no Authorization header. The response exposes internal service state including database connectivity status, JWT configuration status, and server uptime.

```json
{
  "status": "ok",
  "timestamp": "2026-07-05T19:40:17.843Z",
  "uptime": 3801,
  "checks": { "database": "ok", "jwt": "ok" }
}
```

Health endpoints are commonly left public for infrastructure monitoring (load balancers, uptime tools). However the response here leaks internal architecture details — specifically that the app uses JWT and the database connection state — which gives an attacker useful reconnaissance. **Recommendation:** Strip the `checks` object from the public response or gate it behind an internal network check.

---

### Finding 2: Missing rate limit on login endpoint

**Severity:** Medium  
**OWASP:** API4:2023 — Unrestricted Resource Consumption  
**CVSS v3 Score:** 5.3 (Medium)

The login endpoint accepted 50 consecutive authentication attempts with wrong credentials and returned no `429 Too Many Requests` response. `express-rate-limit` was installed as a dependency but never wired into the application middleware — meaning the protection existed in the package list but provided zero actual defense.

**Attack scenario:** An attacker with a credential list could run an automated brute-force against the login endpoint with no server-side friction. Combined with a weak or reused password, this leads to account takeover.

**Remediation applied:**

```javascript
const rateLimit = require('express-rate-limit')

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,  // 15 minute window
  max: 10,                     // 10 attempts per window per IP
  message: { error: 'Too many login attempts. Try again in 15 minutes.' }
})

app.use('/api/auth/login', loginLimiter)
```

After patching, re-running the scanner returned `[SAFE] Rate Limiting` — rate limit triggered at request 10 with a proper `429` response.

---

## How the JWT attack module works

Two forged tokens are constructed entirely in Python — no server secret required.

**alg:none attack** — The JWT header specifies the signing algorithm. If a server blindly trusts the `alg` field without enforcing its own expected algorithm, an attacker can set `alg: none`, strip the signature entirely, and the server accepts it as valid.

```
Original:  eyJhbGciOiJIUzI1NiJ9.eyJ1c2VyIjoiZW1wbG95ZWUifQ.SIGNATURE
Forged:    eyJhbGciOiJub25lIn0.eyJ1c2VyIjoiZW1wbG95ZWUifQ.
```

**Role tampering** — JWT payloads are base64 encoded, not encrypted. Anyone can decode, modify, and re-encode the payload. The only thing preventing tampering is the signature — which the server must verify against its own secret. If verification is skipped or misconfigured, a user can escalate their own role.

```python
# Decode payload
payload = base64.urlsafe_b64decode(token.split('.')[1] + '==')

# Tamper
payload['role'] = 'admin'

# Re-encode without valid signature
forged = f"{header}.{new_payload}."
```

Move More correctly rejected both attacks — signature verification was enforced on every protected route.

---

## How the mass assignment module works

Modern frameworks often automatically bind incoming request body fields to internal data model properties. If the server doesn't explicitly whitelist which fields are allowed, an attacker can inject privileged fields directly into a POST or PUT request body and have them applied silently.

The scanner injects a set of escalation fields alongside every legitimate POST/PUT request:

```python
injected = {
    "role": "admin",
    "isAdmin": True,
    "credits": 99999,
    "is_first_login": False,
    "permissions": ["all"]
}
```

It then checks if any of these fields appear in the response — if they do, the server accepted and reflected them, which means they may have been written to the database with elevated values.

**Example attack scenario:** A user updates their profile via `PUT /api/users/profile` with a normal body like `{"name": "John"}`. If the server uses something like `Object.assign(user, req.body)` without stripping privileged keys, adding `"role": "admin"` to the body silently upgrades the account.

Move More returned no injected fields in any response — the API correctly ignores unrecognized or unauthorized fields on write operations.

---

## BOLA testing methodology

Broken Object Level Authorization (BOLA) is the #1 vulnerability in the OWASP API Top 10. It occurs when an API accepts a user-supplied resource ID without verifying the requesting user owns or has access to that resource.

The scanner authenticates as a low-privilege user (id=3, role=employee) and then requests resources belonging to a high-privilege user (id=1, role=admin) by substituting their ID in the path:

```
GET /api/users/1          (as employee)   → expected 403
GET /api/users/1/badges   (as employee)   → expected 403
GET /api/admin/users/1    (as employee)   → expected 403
```

Move More returned `403 Forbidden` on all cross-user resource requests — authorization checks were correctly scoped to the authenticated user's own ID.

---

## Running it yourself

**Requirements**

```bash
pip3 install httpx
```

**Get fresh JWT tokens** (they expire in 15 minutes)

```bash
curl -X POST http://localhost:3001/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"user@example.com","password":"yourpassword"}'
```

**Configure and run**

Open `fuzz_movmore.py` and set your values at the top:

```python
BASE_URL       = "http://localhost:3001"
TOKEN_EMPLOYEE = "paste_token_here"
TOKEN_ADMIN    = "paste_token_here"
```

```bash
python3 fuzz_movmore.py
```

Report is printed to terminal and saved to `fuzzer_report.txt`.

---

## Adapting to your own API

The scanner is not Move More specific. To run it against any Express/Node REST API:

1. Update `BASE_URL` and `KNOWN_ROUTES` at the top of the file
2. Set two tokens representing different privilege levels
3. Set the user IDs that correspond to those accounts
4. Update the BOLA target paths to match your resource endpoints

The JWT attack and rate limit modules require no configuration changes.

---

## Tech stack

Python 3 · httpx · base64 · OWASP API Security Top 10 · JWT (RFC 7519) · Express.js target

---

## Author

Pratham Agarwal — Computer Science & Data Science, Central Michigan University  
[GitHub](https://github.com/pratham2104) · [Cybersecurity Portfolio](https://github.com/pratham2104/Pratham-Cybersecurity-Portfolio)
