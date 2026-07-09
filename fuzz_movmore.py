"""
fuzz_movmore.py — API security scanner for Move More (your own app)
Tests: missing auth, BOLA/IDOR, JWT attacks, mass assignment, rate limiting
Run: python3 fuzz_movmore.py

BEFORE RUNNING:
  1. Start Move More locally (port 3001)
  2. Paste fresh tokens below (they expire in 15 min)
  3. Run the curl commands printed at startup to get new tokens
"""

import os
import json
import base64
import time
import httpx
from datetime import datetime

# ─────────────────────────────────────────────────────────────────────────────
# CONFIG — paste fresh tokens here before each run
# ─────────────────────────────────────────────────────────────────────────────
BASE_URL        = "http://localhost:3001"
TOKEN_EMPLOYEE  = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6Mywicm9sZSI6ImVtcGxveWVlIiwiZW1haWwiOiJ0ZXN0QHRldGhlcmZpLmNvbSIsImlhdCI6MTc4MzI4MDMyNiwiZXhwIjoxNzgzMjgxMjI2fQ.Q3fzS2g-UzSEmiA6tg5c5_yOA4grOMC5equXc7B8bLY"   # id=3, role=employee
TOKEN_ADMIN     = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6MSwicm9sZSI6ImFkbWluIiwiZW1haWwiOiJockB0ZXRoZXJmaS5jb20iLCJpYXQiOjE3ODMyODAyNzQsImV4cCI6MTc4MzI4MTE3NH0.4SO87MPnOKtMumhtp2zWBAd9TgvGuv2HDiX5VIWFp00"       # id=1, role=admin

USER_EMPLOYEE_ID = 3
USER_ADMIN_ID    = 1

KNOWN_ROUTES = [
    "/api/health",
    "/api/activities",
    "/api/notifications",
    "/api/challenges",
    "/api/leaderboard",
    "/api/badges",
    "/api/squads",
    "/api/admin",
    "/api/users",
    "/api/feed",
]

findings = []

# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def log(msg: str):
    print(msg)

def record_vuln(category, detail, request_info, response_info):
    findings.append({
        "status": "VULNERABLE",
        "category": category,
        "detail": detail,
        "request": request_info,
        "response": response_info,
    })
    log(f"  ⚠  VULNERABLE: {detail}")

def record_safe(category):
    findings.append({"status": "SAFE", "category": category})

def auth(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}

def decode_payload(token: str) -> dict:
    try:
        part = token.split(".")[1]
        part += "=" * (-len(part) % 4)
        return json.loads(base64.urlsafe_b64decode(part))
    except Exception:
        return {}

def forge_none_alg(token: str) -> str:
    parts = token.split(".")
    header = json.loads(base64.urlsafe_b64decode(parts[0] + "=="))
    header["alg"] = "none"
    new_h = base64.urlsafe_b64encode(
        json.dumps(header, separators=(",", ":")).encode()
    ).rstrip(b"=").decode()
    return f"{new_h}.{parts[1]}."

def forge_role(token: str, role: str = "admin") -> str:
    parts = token.split(".")
    payload = decode_payload(token)
    payload["role"] = role
    new_p = base64.urlsafe_b64encode(
        json.dumps(payload, separators=(",", ":")).encode()
    ).rstrip(b"=").decode()
    return f"{parts[0]}.{new_p}."

# ─────────────────────────────────────────────────────────────────────────────
# Test 1 — Missing authentication
# ─────────────────────────────────────────────────────────────────────────────

def test_missing_auth():
    log("\n[1/5] Missing authentication")
    log("      Hitting every endpoint with NO token — expecting 401/403\n")
    vuln = False
    with httpx.Client(timeout=8) as c:
        for route in KNOWN_ROUTES:
            try:
                r = c.get(f"{BASE_URL}{route}")
                log(f"  GET {route:<35} → {r.status_code}")
                if r.status_code == 200:
                    record_vuln(
                        "Missing Auth",
                        f"{route} returns 200 with no token",
                        f"GET {BASE_URL}{route}  (no Authorization header)",
                        f"HTTP {r.status_code}: {r.text[:200]}"
                    )
                    vuln = True
            except Exception as e:
                log(f"  GET {route:<35} → ERROR: {e}")
    if not vuln:
        record_safe("Missing Auth")
        log("\n  ✓ All endpoints protected — none returned 200 without a token")

# ─────────────────────────────────────────────────────────────────────────────
# Test 2 — BOLA / IDOR
# ─────────────────────────────────────────────────────────────────────────────

def test_bola():
    log("\n[2/5] BOLA / IDOR  (employee accessing admin-owned resources)")
    log("      Authenticated as employee (id=3), requesting admin (id=1) data\n")
    targets = [
        f"/api/users/{USER_ADMIN_ID}",
        f"/api/users/{USER_ADMIN_ID}/activities",
        f"/api/users/{USER_ADMIN_ID}/badges",
        f"/api/activities/{USER_ADMIN_ID}",
        f"/api/admin/users/{USER_ADMIN_ID}",
    ]
    vuln = False
    with httpx.Client(timeout=8) as c:
        for route in targets:
            try:
                r = c.get(f"{BASE_URL}{route}", headers=auth(TOKEN_EMPLOYEE))
                log(f"  GET {route:<40} → {r.status_code}")
                if r.status_code == 200:
                    record_vuln(
                        "BOLA/IDOR",
                        f"Employee can read admin resource: {route}",
                        f"GET {BASE_URL}{route} with TOKEN_EMPLOYEE",
                        f"HTTP {r.status_code}: {r.text[:200]}"
                    )
                    vuln = True
            except Exception as e:
                log(f"  GET {route:<40} → ERROR: {e}")
    if not vuln:
        record_safe("BOLA/IDOR")
        log("\n  ✓ No cross-user resource access detected")

# ─────────────────────────────────────────────────────────────────────────────
# Test 3 — JWT attacks
# ─────────────────────────────────────────────────────────────────────────────

def test_jwt():
    log("\n[3/5] JWT attacks  (alg:none + role tampering)")
    log("      Forging tokens without the server's signing secret\n")
    vuln = False
    with httpx.Client(timeout=8) as c:

        # alg:none
        forged = forge_none_alg(TOKEN_EMPLOYEE)
        log(f"  alg:none token: {forged[:60]}...")
        try:
            r = c.get(f"{BASE_URL}/api/users", headers=auth(forged))
            log(f"  GET /api/users (alg:none) → {r.status_code}")
            if r.status_code == 200:
                record_vuln(
                    "JWT alg:none",
                    "Server accepts unsigned token (alg:none)",
                    f"GET /api/users with forged token (alg:none, no signature)",
                    f"HTTP {r.status_code}: {r.text[:200]}"
                )
                vuln = True
        except Exception as e:
            log(f"  alg:none → ERROR: {e}")

        # Role tamper: employee → admin
        tampered = forge_role(TOKEN_EMPLOYEE, "admin")
        log(f"\n  Role-tampered token (employee→admin): {tampered[:60]}...")
        try:
            r = c.get(f"{BASE_URL}/api/admin", headers=auth(tampered))
            log(f"  GET /api/admin (tampered role) → {r.status_code}")
            if r.status_code == 200:
                record_vuln(
                    "JWT Role Tampering",
                    "Server accepts role-tampered token without re-signing",
                    f"GET /api/admin with payload role changed to 'admin' (no valid sig)",
                    f"HTTP {r.status_code}: {r.text[:200]}"
                )
                vuln = True
        except Exception as e:
            log(f"  Role tamper → ERROR: {e}")

    if not vuln:
        record_safe("JWT Attacks")
        log("\n  ✓ Server correctly rejects unsigned / tampered tokens")

# ─────────────────────────────────────────────────────────────────────────────
# Test 4 — Mass assignment
# ─────────────────────────────────────────────────────────────────────────────

def test_mass_assignment():
    log("\n[4/5] Mass assignment  (injecting privileged fields into POST/PUT bodies)")
    log("      Checking if server reflects or applies injected fields\n")
    injected = {
        "role": "admin",
        "isAdmin": True,
        "credits": 99999,
        "is_first_login": False,
        "permissions": ["all"],
    }
    targets = [
        ("/api/activities", "POST", {"title": "test", "type": "walk", "duration": 10}),
        ("/api/challenges", "POST", {"name": "test challenge"}),
        ("/api/users/profile", "PUT", {"name": "Test User"}),
    ]
    vuln = False
    with httpx.Client(timeout=8) as c:
        for route, method, base_body in targets:
            payload = {**base_body, **injected}
            try:
                r = c.request(
                    method,
                    f"{BASE_URL}{route}",
                    json=payload,
                    headers={**auth(TOKEN_EMPLOYEE), "Content-Type": "application/json"}
                )
                log(f"  {method} {route:<35} → {r.status_code}")
                body = r.text.lower()
                for field, val in injected.items():
                    if field in body or str(val).lower() in body:
                        record_vuln(
                            "Mass Assignment",
                            f"Field '{field}' reflected in response at {route}",
                            f"{method} {BASE_URL}{route}  body: {json.dumps(payload)[:200]}",
                            f"HTTP {r.status_code}: {r.text[:300]}"
                        )
                        vuln = True
                        break
            except Exception as e:
                log(f"  {method} {route:<35} → ERROR: {e}")
    if not vuln:
        record_safe("Mass Assignment")
        log("\n  ✓ No injected fields reflected in responses")

# ─────────────────────────────────────────────────────────────────────────────
# Test 5 — Rate limiting
# ─────────────────────────────────────────────────────────────────────────────

def test_rate_limit():
    log("\n[5/5] Rate limiting  (50 rapid requests to /api/auth/login)")
    log("      Expecting a 429 before 50 requests complete\n")
    hit_limit = False
    with httpx.Client(timeout=8) as c:
        for i in range(1, 51):
            try:
                r = c.post(
                    f"{BASE_URL}/api/auth/login",
                    json={"email": f"brute{i}@test.com", "password": "wrongpassword"},
                    headers={"Content-Type": "application/json"}
                )
                log(f"  Request {i:02d}/50 → {r.status_code}")
                if r.status_code == 429:
                    log(f"\n  ✓ Rate limit hit at request {i}")
                    record_safe("Rate Limiting")
                    hit_limit = True
                    break
            except Exception as e:
                log(f"  Request {i:02d} → ERROR: {e}")
                break
    if not hit_limit:
        record_vuln(
            "Missing Rate Limiting",
            "50 rapid login attempts completed — no 429 returned",
            "POST /api/auth/login x50, wrong credentials, no delay",
            "No 429 Too Many Requests received across 50 requests"
        )

# ─────────────────────────────────────────────────────────────────────────────
# Report
# ─────────────────────────────────────────────────────────────────────────────

def print_report():
    lines = []
    lines.append("\n" + "=" * 65)
    lines.append("  MOVE MORE — SECURITY SCAN REPORT")
    lines.append(f"  {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}   {BASE_URL}")
    lines.append("=" * 65)

    vulns = [f for f in findings if f["status"] == "VULNERABLE"]
    safes = [f for f in findings if f["status"] == "SAFE"]

    for f in vulns:
        lines.append(f"\n  [VULNERABLE]  {f['category']}")
        lines.append(f"  Detail   : {f['detail']}")
        lines.append(f"  Request  : {f['request']}")
        lines.append(f"  Response : {f['response']}")

    for f in safes:
        lines.append(f"\n  [SAFE]        {f['category']}")

    lines.append("\n" + "=" * 65)
    lines.append(f"  Vulnerabilities found : {len(vulns)}")
    lines.append(f"  Checks passed         : {len(safes)}")
    lines.append("=" * 65 + "\n")

    report = "\n".join(lines)
    print(report)

    out = os.path.expanduser("~/Desktop/lab/fuzzer_report.txt")
    with open(out, "w") as f:
        f.write(report)
    log(f"  Report saved → {out}")

# ─────────────────────────────────────────────────────────────────────────────
# Entry point
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("=" * 65)
    print("  MOVE MORE — API SECURITY SCANNER")
    print("=" * 65)

    print("""
  Tokens expire every 15 min. Get fresh ones with:

  curl -X POST http://localhost:3001/api/auth/login \\
    -H "Content-Type: application/json" \\
    -d '{"email":"test@tetherfi.com","password":"<YOUR_PASSWORD>"}'

  curl -X POST http://localhost:3001/api/auth/login \\
    -H "Content-Type: application/json" \\
    -d '{"email":"hr@tetherfi.com","password":"Password1"}'

  Then paste them into TOKEN_EMPLOYEE and TOKEN_ADMIN at the top of this file.
""")

    tokens_set = (
        "PASTE_FRESH" not in TOKEN_EMPLOYEE and
        "PASTE_FRESH" not in TOKEN_ADMIN
    )
    if not tokens_set:
        print("  ⚠  Tokens not set — JWT and BOLA tests will be skipped or inaccurate.")
        print("  Paste fresh tokens at the top of this file and re-run.\n")

    test_missing_auth()
    test_bola()
    test_jwt()
    test_mass_assignment()
    test_rate_limit()
    print_report()
