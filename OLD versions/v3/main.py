"""
main.py — API Attack Surface Auditor
Entry point. Imports all scanner modules, runs every test,
collects findings, prints a structured terminal report,
and generates a color-coded HTML report with MITRE ATT&CK mapping.

Usage:
  1. Paste fresh JWT tokens into TOKEN_A and TOKEN_B below
  2. Make sure Move More is running on port 3001
  3. python3 main.py

Get fresh tokens:
  curl -X POST http://localhost:3001/api/auth/login \
    -H "Content-Type: application/json" \
    -d '{"employee_id":"EMP-001","password":"YOUR_PASSWORD"}'

  curl -X POST http://localhost:3001/api/auth/login \
    -H "Content-Type: application/json" \
    -d '{"employee_id":"EMP-HR-001","password":"Password1"}'
"""

import os
import httpx
from datetime import datetime

# ─────────────────────────────────────────────────────────────────────────────
# CONFIG — paste fresh tokens here before each run (they expire in 15 min)
# ─────────────────────────────────────────────────────────────────────────────
BASE_URL        = "http://localhost:3001"
BASE_URL = "http://localhost:3001"
TOKEN_A  = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6Mywicm9sZSI6ImVtcGxveWVlIiwiZW1haWwiOiJ0ZXN0QHRldGhlcmZpLmNvbSIsImlhdCI6MTc4MzYzOTIzOCwiZXhwIjoxNzgzNjQwMTM4fQ.wAroRwv5e6AKq3WxuOxTCUEpjcoFgOh4am3iSBuTGhQ"
TOKEN_B  = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6MSwicm9sZSI6ImFkbWluIiwiZW1haWwiOiJockB0ZXRoZXJmaS5jb20iLCJpYXQiOjE3ODM2MzkyNDMsImV4cCI6MTc4MzY0MDE0M30.7uwQFNb2B_fpvzO2fZsWY9BbTZ65hIDNQAxyVW0NeWI"
USER_A_ID       = 3
USER_B_ID       = 1
REPORT_TXT      = os.path.expanduser("~/Desktop/lab/scan_report.txt")
REPORT_HTML     = os.path.expanduser("~/Desktop/lab/scan_report.html")

# ─────────────────────────────────────────────────────────────────────────────
# Import all scanner modules
# ─────────────────────────────────────────────────────────────────────────────
from scanner import auth, bola, jwt_attacks, mass_assign, rate_limit, headers, cors, sqli

# Import reporter modules (Phase 2)
from reporter import html_report

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
# Terminal report printer
# ─────────────────────────────────────────────────────────────────────────────

def print_report(all_findings):
    lines = []
    lines.append("\n" + "=" * 65)
    lines.append("  API ATTACK SURFACE AUDITOR — SCAN REPORT")
    lines.append(f"  {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}   {BASE_URL}")
    lines.append("=" * 65)

    vulns = [f for f in all_findings if f["status"] == "VULNERABLE"]
    safes = [f for f in all_findings if f["status"] == "SAFE"]

    severity_order = ["Critical", "High", "Medium", "Low", "Info"]
    for sev in severity_order:
        for f in [x for x in vulns if x.get("severity") == sev]:
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

    os.makedirs(os.path.dirname(REPORT_TXT), exist_ok=True)
    with open(REPORT_TXT, "w") as f:
        f.write(report)
    print(f"  Text report saved → {REPORT_TXT}")

# ─────────────────────────────────────────────────────────────────────────────
# Entry point
# ─────────────────────────────────────────────────────────────────────────────

def main():
    print("=" * 65)
    print("  API ATTACK SURFACE AUDITOR  v3.0")
    print(f"  Target: {BASE_URL}")
    print("=" * 65)

    if "PASTE" in TOKEN_A or "PASTE" in TOKEN_B:
        print("\n  ⚠  Tokens not set — JWT and BOLA tests will be inaccurate.")
        print("  Paste fresh tokens into TOKEN_A and TOKEN_B at the top of main.py\n")

    ctx = {
        "base_url":  BASE_URL,
        "token_a":   TOKEN_A,
        "token_b":   TOKEN_B,
        "user_a_id": USER_A_ID,
        "user_b_id": USER_B_ID,
    }

    all_findings = []

    with httpx.Client(timeout=10) as client:
        for module in MODULES:
            try:
                results = module.run(client=client, **ctx)
                all_findings.extend(results)
            except Exception as e:
                print(f"\n  ERROR in {module.__name__}: {e}")

    # Terminal + text report
    print_report(all_findings)

    # HTML report with MITRE ATT&CK mapping (Phase 2)
    html_report.generate(all_findings, base_url=BASE_URL, output_path=REPORT_HTML)


if __name__ == "__main__":
    main()
