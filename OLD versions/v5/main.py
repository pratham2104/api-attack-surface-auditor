"""
main.py — API Attack Surface Auditor v5.0
New in v5:
  --cred-a / --cred-b   auto token refresh (no manual curl needed)
  --format json         exports findings as SIEM-ingestible JSON
  --diff <path>         compares against previous scan, generates delta report
  SSRF module           9th scanner module (scanner/ssrf.py)
  CVSS v3.1 vectors     every finding now has a vector string + numeric score

Usage examples:
  # Auto login — no manual token needed
  python3 main.py --url http://localhost:3001 \
    --cred-a "EMP-001 newpass1" \
    --cred-b "EMP-HR-001 Password1"

  # Manual tokens (still works)
  python3 main.py --url http://localhost:3001 \
    --token-a JWT --token-b JWT

  # JSON output for SIEM
  python3 main.py ... --format json

  # Diff against previous scan
  python3 main.py ... --diff ~/Desktop/lab/previous_scan.json
"""

import os
import asyncio
import argparse
import httpx
import json
from datetime import datetime, timezone

# ─────────────────────────────────────────────────────────────────────────────
# Defaults
# ─────────────────────────────────────────────────────────────────────────────
DEFAULT_URL     = "http://localhost:3001"
DEFAULT_TOKEN_A = os.environ.get("TOKEN_A", "")
DEFAULT_TOKEN_B = os.environ.get("TOKEN_B", "")
DEFAULT_HTML    = os.path.expanduser("~/Desktop/lab/scan_report.html")
DEFAULT_JSON    = os.path.expanduser("~/Desktop/lab/scan_report.json")
DEFAULT_TXT     = os.path.expanduser("~/Desktop/lab/scan_report.txt")
USER_A_ID       = 3
USER_B_ID       = 1

# ─────────────────────────────────────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────────────────────────────────────

def parse_args():
    p = argparse.ArgumentParser(
        description="API Attack Surface Auditor v5.0 — OWASP API Top 10 scanner"
    )
    p.add_argument("--url",      default=DEFAULT_URL,  help="Target API base URL")
    p.add_argument("--token-a",  default=DEFAULT_TOKEN_A, help="Low-privilege JWT token")
    p.add_argument("--token-b",  default=DEFAULT_TOKEN_B, help="High-privilege JWT token")
    p.add_argument("--cred-a",   default="", help='Auto-login: "employee_id password"')
    p.add_argument("--cred-b",   default="", help='Auto-login: "employee_id password"')
    p.add_argument("--output",   default=DEFAULT_HTML, help="HTML report output path")
    p.add_argument("--format",   default="html", choices=["html", "json", "all"],
                   help="Output format: html | json | all")
    p.add_argument("--diff",     default="", help="Path to previous scan JSON for delta report")
    p.add_argument("--user-a",   default=USER_A_ID, type=int)
    p.add_argument("--user-b",   default=USER_B_ID, type=int)
    return p.parse_args()

# ─────────────────────────────────────────────────────────────────────────────
# Auto token refresh
# ─────────────────────────────────────────────────────────────────────────────

async def login(client, base_url, employee_id, password):
    """Login and return (access_token, expiry_timestamp)."""
    try:
        r = await client.post(
            f"{base_url}/api/auth/login",
            json={"employee_id": employee_id, "password": password},
            headers={"Content-Type": "application/json"}
        )
        data  = r.json()
        token = data.get("access_token", "")
        if not token:
            print(f"  ⚠  Login failed for {employee_id}: {data}")
            return "", None

        # Decode expiry from JWT payload
        import base64 as b64
        payload_part = token.split(".")[1]
        payload_part += "=" * (-len(payload_part) % 4)
        payload = json.loads(b64.urlsafe_b64decode(payload_part))
        expiry  = payload.get("exp")
        print(f"  ✓ Logged in as {employee_id}")
        return token, expiry

    except Exception as e:
        print(f"  ⚠  Login error for {employee_id}: {e}")
        return "", None


def is_token_expired(expiry_ts):
    """Return True if token expires in less than 60 seconds."""
    if not expiry_ts:
        return False
    now = datetime.now(timezone.utc).timestamp()
    return (expiry_ts - now) < 60

# ─────────────────────────────────────────────────────────────────────────────
# Scanner modules
# ─────────────────────────────────────────────────────────────────────────────
from scanner import auth, bola, jwt_attacks, mass_assign, rate_limit, headers, cors, sqli, ssrf
from reporter import html_report, json_report, diff_report

MODULES = [auth, bola, jwt_attacks, mass_assign, rate_limit, headers, cors, sqli, ssrf]

# ─────────────────────────────────────────────────────────────────────────────
# Terminal report
# ─────────────────────────────────────────────────────────────────────────────

def print_report(all_findings, base_url, txt_path):
    from reporter import mitre_map
    lines = []
    lines.append("\n" + "=" * 70)
    lines.append("  API ATTACK SURFACE AUDITOR v5.0 — SCAN REPORT")
    lines.append(f"  {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}   {base_url}")
    lines.append("=" * 70)

    vulns = [f for f in all_findings if f["status"] == "VULNERABLE"]
    safes = [f for f in all_findings if f["status"] == "SAFE"]

    for sev in ["Critical", "High", "Medium", "Low", "Info"]:
        for f in [x for x in vulns if x.get("severity") == sev]:
            mitre = mitre_map.get(f["category"])
            lines.append(f"\n  [{sev.upper()}]  {f['category']}")
            lines.append(f"  OWASP    : {f.get('owasp', 'N/A')}")
            lines.append(f"  MITRE    : {mitre['id']} — {mitre['name']}")
            lines.append(f"  CVSS     : {mitre.get('cvss_score', 'N/A')}  {mitre.get('cvss_vector', '')}")
            lines.append(f"  Detail   : {f['detail']}")
            lines.append(f"  Request  : {f['request']}")
            lines.append(f"  Response : {f['response']}")

    for f in safes:
        lines.append(f"\n  [SAFE]    {f['category']}")

    lines.append("\n" + "=" * 70)
    lines.append(f"  Vulnerabilities : {len(vulns)}")
    lines.append(f"  Passed          : {len(safes)}")
    lines.append(f"  Total checks    : {len(all_findings)}")
    lines.append("=" * 70 + "\n")

    report = "\n".join(lines)
    print(report)

    os.makedirs(os.path.dirname(txt_path), exist_ok=True)
    with open(txt_path, "w") as f:
        f.write(report)
    print(f"  Text report → {txt_path}")

# ─────────────────────────────────────────────────────────────────────────────
# Async main
# ─────────────────────────────────────────────────────────────────────────────

async def run_scan(args):
    print("=" * 70)
    print("  API ATTACK SURFACE AUDITOR  v5.0")
    print(f"  Target  : {args.url}")
    print(f"  Modules : {len(MODULES)} running in parallel")
    print("=" * 70)

    async with httpx.AsyncClient(timeout=10) as client:

        # ── Auto token refresh ────────────────────────────────────────────
        token_a   = args.token_a
        token_b   = args.token_b
        expiry_a  = None
        expiry_b  = None
        cred_a    = args.cred_a.split() if args.cred_a else []
        cred_b    = args.cred_b.split() if args.cred_b else []

        if cred_a and len(cred_a) == 2:
            print("\n  Auto-login enabled")
            token_a, expiry_a = await login(client, args.url, cred_a[0], cred_a[1])
        if cred_b and len(cred_b) == 2:
            token_b, expiry_b = await login(client, args.url, cred_b[0], cred_b[1])

        if not token_a and not token_b:
            print("\n  ⚠  No tokens provided. Use --cred-a/--cred-b or --token-a/--token-b\n")

        ctx = {
            "base_url":  args.url,
            "token_a":   token_a,
            "token_b":   token_b,
            "user_a_id": args.user_a,
            "user_b_id": args.user_b,
        }

        print("\n  Running all modules in parallel...\n")
        start = asyncio.get_event_loop().time()

        # Refresh tokens mid-scan if expired
        if is_token_expired(expiry_a) and cred_a:
            print("  Refreshing token A...")
            token_a, expiry_a = await login(client, args.url, cred_a[0], cred_a[1])
            ctx["token_a"] = token_a

        if is_token_expired(expiry_b) and cred_b:
            print("  Refreshing token B...")
            token_b, expiry_b = await login(client, args.url, cred_b[0], cred_b[1])
            ctx["token_b"] = token_b

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

    # ── Outputs ───────────────────────────────────────────────────────────
    print_report(all_findings, args.url, DEFAULT_TXT)

    if args.format in ("html", "all"):
        html_report.generate(all_findings, base_url=args.url, output_path=args.output)

    if args.format in ("json", "all"):
        json_report.generate(all_findings, base_url=args.url, output_path=DEFAULT_JSON)
        # Always save JSON for future diff comparisons
    else:
        # Save JSON silently even when not requested — needed for --diff next time
        json_report.generate(all_findings, base_url=args.url, output_path=DEFAULT_JSON)

    if args.diff and os.path.exists(args.diff):
        print(f"\n  Running diff against {args.diff}...")
        diff_report.generate(all_findings, previous_path=args.diff)
    elif args.diff:
        print(f"  ⚠  Diff file not found: {args.diff}")


def main():
    args = parse_args()
    asyncio.run(run_scan(args))


if __name__ == "__main__":
    main()
