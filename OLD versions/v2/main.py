"""
main.py — API Attack Surface Auditor
Entry point. Imports all scanner modules, runs every test,
collects findings, prints a structured report, and saves to txt.

Usage:
  1. Paste fresh JWT tokens into TOKEN_A and TOKEN_B below
  2. Make sure Move More is running on port 3001
  3. python3 main.py

Get fresh tokens:
  curl -X POST http://localhost:3001/api/auth/login \
    -H "Content-Type: application/json" \
    -d '{"email":"test@tetherfi.com","password":"YOUR_PASSWORD"}'

  curl -X POST http://localhost:3001/api/auth/login \
    -H "Content-Type: application/json" \
    -d '{"email":"hr@tetherfi.com","password":"Password1"}'
"""

import os
import httpx
from datetime import datetime

# ─────────────────────────────────────────────────────────────────────────────
# CONFIG — paste fresh tokens here before each run (they expire in 15 min)
# ─────────────────────────────────────────────────────────────────────────────
BASE_URL        = "http://localhost:3001"
TOKEN_A = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6Mywicm9sZSI6ImVtcGxveWVlIiwiZW1haWwiOiJ0ZXN0QHRldGhlcmZpLmNvbSIsImlhdCI6MTc4MzYzMTkwOSwiZXhwIjoxNzgzNjMyODA5fQ.xRxIivDnSwk3Le7zJrg4QA_PJ6l6i2Fm0axnWhAyeVc"
TOKEN_B = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6MSwicm9sZSI6ImFkbWluIiwiZW1haWwiOiJockB0ZXRoZXJmaS5jb20iLCJpYXQiOjE3ODM2MzE5MzIsImV4cCI6MTc4MzYzMjgzMn0.m1eb8kmkNa8KpE5u35OxJeUlTSXdACoimcQDc48aKVw"
USER_A_ID       = 3
USER_B_ID       = 1
REPORT_PATH     = os.path.expanduser("~/Desktop/lab/scan_report.txt")

# ─────────────────────────────────────────────────────────────────────────────
# Import all scanner modules
# ─────────────────────────────────────────────────────────────────────────────
from scanner import auth, bola, jwt_attacks, mass_assign, rate_limit, headers, cors, sqli

MODULES = [
    auth,
    bola,
    jwt_attacks,
    mass_assign,
    rate_limit,
    headers,
    cors,
    sqli,
]

# ─────────────────────────────────────────────────────────────────────────────
# Report printer
# ─────────────────────────────────────────────────────────────────────────────

def print_report(all_findings):
    lines = []
    lines.append("\n" + "=" * 65)
    lines.append("  API ATTACK SURFACE AUDITOR — SCAN REPORT")
    lines.append(f"  {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}   {BASE_URL}")
    lines.append("=" * 65)

    vulns = [f for f in all_findings if f["status"] == "VULNERABLE"]
    safes = [f for f in all_findings if f["status"] == "SAFE"]

    # Group by severity for the summary block
    severity_order = ["Critical", "High", "Medium", "Low", "Info"]
    for sev in severity_order:
        sev_vulns = [f for f in vulns if f.get("severity") == sev]
        for f in sev_vulns:
            lines.append(f"\n  [{sev.upper()}]  {f['category']}")
            lines.append(f"  OWASP    : {f.get('owasp', 'N/A')}")
            lines.append(f"  Detail   : {f['detail']}")
            lines.append(f"  Request  : {f['request']}")
            lines.append(f"  Response : {f['response']}")

    for f in safes:
        lines.append(f"\n  [SAFE]    {f['category']}")
        lines.append(f"  OWASP    : {f.get('owasp', 'N/A')}")

    lines.append("\n" + "=" * 65)
    lines.append(f"  Vulnerabilities : {len(vulns)}")
    lines.append(f"  Passed          : {len(safes)}")
    lines.append(f"  Total checks    : {len(all_findings)}")
    lines.append("=" * 65 + "\n")

    report = "\n".join(lines)
    print(report)

    os.makedirs(os.path.dirname(REPORT_PATH), exist_ok=True)
    with open(REPORT_PATH, "w") as f:
        f.write(report)
    print(f"  Report saved → {REPORT_PATH}\n")

# ─────────────────────────────────────────────────────────────────────────────
# Entry point
# ─────────────────────────────────────────────────────────────────────────────

def main():
    print("=" * 65)
    print("  API ATTACK SURFACE AUDITOR")
    print(f"  Target: {BASE_URL}")
    print("=" * 65)

    # Warn if tokens are still placeholders
    if "PASTE" in TOKEN_A or "PASTE" in TOKEN_B:
        print("\n  ⚠  Tokens not set — JWT and BOLA tests will be inaccurate.")
        print("  Paste fresh tokens into TOKEN_A and TOKEN_B at the top of main.py\n")

    # Shared context passed to every module
    ctx = {
        "base_url":  BASE_URL,
        "token_a":   TOKEN_A,
        "token_b":   TOKEN_B,
        "user_a_id": USER_A_ID,
        "user_b_id": USER_B_ID,
    }

    all_findings = []

    # Run all modules against a shared httpx client (connection pooling)
    with httpx.Client(timeout=10) as client:
        for module in MODULES:
            try:
                results = module.run(client=client, **ctx)
                all_findings.extend(results)
            except Exception as e:
                print(f"\n  ERROR in {module.__name__}: {e}")

    print_report(all_findings)


if __name__ == "__main__":
    main()
