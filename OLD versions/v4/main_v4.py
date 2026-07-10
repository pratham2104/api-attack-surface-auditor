"""
main.py — API Attack Surface Auditor v4.0
Async entry point with CLI argument support.
All 8 scanner modules run in parallel via asyncio.gather().

Usage:
  python3 main.py --url http://localhost:3001 --token-a JWT --token-b JWT

  Or still works with hardcoded values if you prefer:
  python3 main.py

Get fresh tokens:
  curl -X POST http://localhost:3001/api/auth/login \
    -H "Content-Type: application/json" \
    -d '{"employee_id":"EMP-001","password":"YOUR_PASSWORD"}'

  curl -X POST http://localhost:3001/api/auth/login \
    -H "Content-Type: application/json" \
    -d '{"employee_id":"EMP-HR-001","password":"Password1"}'
"""

import os
import asyncio
import argparse
import httpx
from datetime import datetime

# ─────────────────────────────────────────────────────────────────────────────
# Defaults — overridden by CLI args or environment variables
# ─────────────────────────────────────────────────────────────────────────────
DEFAULT_URL      = "http://localhost:3001"
DEFAULT_TOKEN_A  = os.environ.get("TOKEN_A", "PASTE_EMPLOYEE_TOKEN_HERE")
DEFAULT_TOKEN_B  = os.environ.get("TOKEN_B", "PASTE_ADMIN_TOKEN_HERE")
DEFAULT_OUTPUT   = os.path.expanduser("~/Desktop/lab/scan_report.html")
DEFAULT_TXT      = os.path.expanduser("~/Desktop/lab/scan_report.txt")
USER_A_ID        = 3
USER_B_ID        = 1

# ─────────────────────────────────────────────────────────────────────────────
# CLI argument parser
# ─────────────────────────────────────────────────────────────────────────────

def parse_args():
    parser = argparse.ArgumentParser(
        description="API Attack Surface Auditor — OWASP API Top 10 scanner"
    )
    parser.add_argument("--url",      default=DEFAULT_URL,     help="Base URL of the target API")
    parser.add_argument("--token-a",  default=DEFAULT_TOKEN_A, help="Low-privilege JWT token")
    parser.add_argument("--token-b",  default=DEFAULT_TOKEN_B, help="High-privilege JWT token")
    parser.add_argument("--output",   default=DEFAULT_OUTPUT,  help="Path for HTML report output")
    parser.add_argument("--user-a",   default=USER_A_ID, type=int, help="User ID for token-a")
    parser.add_argument("--user-b",   default=USER_B_ID, type=int, help="User ID for token-b")
    return parser.parse_args()

# ─────────────────────────────────────────────────────────────────────────────
# Import all scanner modules (async versions)
# ─────────────────────────────────────────────────────────────────────────────
from scanner import auth, bola, jwt_attacks, mass_assign, rate_limit, headers, cors, sqli
from reporter import html_report

MODULES = [auth, bola, jwt_attacks, mass_assign, rate_limit, headers, cors, sqli]

# ─────────────────────────────────────────────────────────────────────────────
# Terminal report printer
# ─────────────────────────────────────────────────────────────────────────────

def print_report(all_findings, base_url, txt_path):
    lines = []
    lines.append("\n" + "=" * 65)
    lines.append("  API ATTACK SURFACE AUDITOR v4.0 — SCAN REPORT")
    lines.append(f"  {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}   {base_url}")
    lines.append("=" * 65)

    vulns = [f for f in all_findings if f["status"] == "VULNERABLE"]
    safes = [f for f in all_findings if f["status"] == "SAFE"]

    for sev in ["Critical", "High", "Medium", "Low", "Info"]:
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

    os.makedirs(os.path.dirname(txt_path), exist_ok=True)
    with open(txt_path, "w") as f:
        f.write(report)
    print(f"  Text report saved → {txt_path}")

# ─────────────────────────────────────────────────────────────────────────────
# Async main — all modules run in parallel
# ─────────────────────────────────────────────────────────────────────────────

async def run_scan(args):
    print("=" * 65)
    print("  API ATTACK SURFACE AUDITOR  v4.0")
    print(f"  Target  : {args.url}")
    print(f"  Modules : {len(MODULES)} running in parallel")
    print("=" * 65)

    if "PASTE" in args.token_a or "PASTE" in args.token_b:
        print("\n  ⚠  Tokens not set — JWT and BOLA tests will be inaccurate.")
        print("  Use --token-a and --token-b flags or paste into DEFAULT_TOKEN vars\n")

    ctx = {
        "base_url":  args.url,
        "token_a":   args.token_a,
        "token_b":   args.token_b,
        "user_a_id": args.user_a,
        "user_b_id": args.user_b,
    }

    print("\n  Running all modules in parallel...\n")
    start = asyncio.get_event_loop().time()

    async with httpx.AsyncClient(timeout=10) as client:
        tasks   = [module.run(client=client, **ctx) for module in MODULES]
        results = await asyncio.gather(*tasks, return_exceptions=True)

    elapsed = asyncio.get_event_loop().time() - start
    print(f"\n  Scan completed in {elapsed:.1f}s\n")

    all_findings = []
    for i, result in enumerate(results):
        if isinstance(result, Exception):
            print(f"  ERROR in {MODULES[i].__name__}: {result}")
        else:
            all_findings.extend(result)

    print_report(all_findings, args.url, DEFAULT_TXT)
    html_report.generate(all_findings, base_url=args.url, output_path=args.output)


def main():
    args = parse_args()
    asyncio.run(run_scan(args))


if __name__ == "__main__":
    main()
