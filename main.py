"""
main.py — API Attack Surface Auditor v6.0
The biggest update yet. New in v6:
  - OpenAPI auto-discovery — discovers all endpoints automatically
  - All scanner modules use discovered routes/params instead of hardcoded lists
  - 6 new scanner modules: OAuth, versioning, timing, TLS, business logic
  - Splunk dashboard + CSV lookup output
  - --splunk flag to generate Splunk outputs
  - --no-discovery flag to skip spec probing and use fallback routes

Usage:
  # Auto-login + full discovery (recommended)
  python3 main.py --url http://localhost:3001 \
    --cred-a "EMP-001 newpass1" \
    --cred-b "EMP-HR-001 Password1"

  # All outputs including Splunk dashboard
  python3 main.py --url http://localhost:3001 \
    --cred-a "EMP-001 newpass1" \
    --cred-b "EMP-HR-001 Password1" \
    --format all --splunk

  # Skip discovery, use fallback routes
  python3 main.py --url http://localhost:3001 \
    --cred-a "EMP-001 newpass1" \
    --no-discovery

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
DEFAULT_URL  = "http://localhost:3001"
DEFAULT_HTML = os.path.expanduser("~/Desktop/lab/scan_report.html")
DEFAULT_JSON = os.path.expanduser("~/Desktop/lab/scan_report.json")
DEFAULT_TXT  = os.path.expanduser("~/Desktop/lab/scan_report.txt")
USER_A_ID    = 3
USER_B_ID    = 1

# ─────────────────────────────────────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────────────────────────────────────

def parse_args():
    p = argparse.ArgumentParser(
        description="API Attack Surface Auditor v6.0"
    )
    p.add_argument("--url",           default=DEFAULT_URL)
    p.add_argument("--token-a",       default=os.environ.get("TOKEN_A", ""))
    p.add_argument("--token-b",       default=os.environ.get("TOKEN_B", ""))
    p.add_argument("--cred-a",        default="", help='Auto-login: "employee_id password"')
    p.add_argument("--cred-b",        default="", help='Auto-login: "employee_id password"')
    p.add_argument("--output",        default=DEFAULT_HTML)
    p.add_argument("--format",        default="html", choices=["html", "json", "all"])
    p.add_argument("--diff",          default="")
    p.add_argument("--splunk",        action="store_true",
                   help="Generate Splunk dashboard XML and CSV lookup")
    p.add_argument("--no-discovery",  action="store_true",
                   help="Skip OpenAPI discovery, use hardcoded fallback routes")
    p.add_argument("--user-a",        default=USER_A_ID, type=int)
    p.add_argument("--user-b",        default=USER_B_ID, type=int)
    return p.parse_args()

# ─────────────────────────────────────────────────────────────────────────────
# Auto token refresh
# ─────────────────────────────────────────────────────────────────────────────

async def login(client, base_url, employee_id, password):
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
        import base64 as b64
        part = token.split(".")[1]
        part += "=" * (-len(part) % 4)
        payload = json.loads(b64.urlsafe_b64decode(part))
        print(f"  ✓ Logged in as {employee_id} (role: {payload.get('role', 'unknown')})")
        return token, payload.get("exp")
    except Exception as e:
        print(f"  ⚠  Login error for {employee_id}: {e}")
        return "", None


def is_expired(expiry_ts):
    if not expiry_ts:
        return False
    return (expiry_ts - datetime.now(timezone.utc).timestamp()) < 60

# ─────────────────────────────────────────────────────────────────────────────
# Scanner modules
# ─────────────────────────────────────────────────────────────────────────────
from scanner import (
    openapi_discovery,
    auth, bola, jwt_attacks, mass_assign, rate_limit,
    headers, cors, sqli, ssrf,
    oauth, versioning, timing, tls, business_logic
)
from reporter import html_report, json_report, diff_report, splunk_dashboard

# Modules that run in parallel after discovery
PARALLEL_MODULES = [
    auth, bola, jwt_attacks, mass_assign, rate_limit,
    headers, cors, sqli, ssrf,
    oauth, versioning, timing, tls, business_logic,
]

# ─────────────────────────────────────────────────────────────────────────────
# Terminal report
# ─────────────────────────────────────────────────────────────────────────────

def print_report(all_findings, base_url, txt_path):
    from reporter import mitre_map
    lines = []
    lines.append("\n" + "=" * 70)
    lines.append("  API ATTACK SURFACE AUDITOR v6.0 — SCAN REPORT")
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
            lines.append(f"  Detail   : {f.get('detail', '')}")
            lines.append(f"  Request  : {f.get('request', '')}")
            lines.append(f"  Response : {f.get('response', '')}")

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
    print(f"  Text report      → {txt_path}")

# ─────────────────────────────────────────────────────────────────────────────
# Async main
# ─────────────────────────────────────────────────────────────────────────────

async def run_scan(args):
    print("=" * 70)
    print("  API ATTACK SURFACE AUDITOR  v6.0")
    print(f"  Target   : {args.url}")
    print(f"  Modules  : {len(PARALLEL_MODULES)} parallel + discovery")
    print("=" * 70)

    async with httpx.AsyncClient(timeout=15) as client:

        # ── Auto login ────────────────────────────────────────────────────
        token_a, expiry_a = args.token_a, None
        token_b, expiry_b = args.token_b, None
        cred_a = args.cred_a.split() if args.cred_a else []
        cred_b = args.cred_b.split() if args.cred_b else []

        if cred_a and len(cred_a) == 2:
            print("\n  Auto-login:")
            token_a, expiry_a = await login(client, args.url, cred_a[0], cred_a[1])
        if cred_b and len(cred_b) == 2:
            token_b, expiry_b = await login(client, args.url, cred_b[0], cred_b[1])

        # ── OpenAPI discovery (runs first, serially) ──────────────────────
        api_map = None
        discovery_findings = []

        if not args.no_discovery:
            print()
            disc_results, api_map = await openapi_discovery.run(
                client=client, base_url=args.url
            )
            discovery_findings = disc_results
        else:
            print("\n  Discovery skipped (--no-discovery)")
            from scanner.openapi_discovery import _empty_map
            api_map = _empty_map()

        # Refresh tokens if needed
        if is_expired(expiry_a) and cred_a:
            token_a, expiry_a = await login(client, args.url, cred_a[0], cred_a[1])
        if is_expired(expiry_b) and cred_b:
            token_b, expiry_b = await login(client, args.url, cred_b[0], cred_b[1])

        ctx = {
            "base_url":  args.url,
            "token_a":   token_a,
            "token_b":   token_b,
            "user_a_id": args.user_a,
            "user_b_id": args.user_b,
            "api_map":   api_map,
        }

        print(f"\n  Running {len(PARALLEL_MODULES)} modules in parallel...\n")
        start = asyncio.get_event_loop().time()

        tasks   = [m.run(client=client, **ctx) for m in PARALLEL_MODULES]
        results = await asyncio.gather(*tasks, return_exceptions=True)

    elapsed = asyncio.get_event_loop().time() - start
    print(f"\n  Scan completed in {elapsed:.1f}s\n")

    all_findings = list(discovery_findings)
    for i, result in enumerate(results):
        if isinstance(result, Exception):
            print(f"  ERROR in {PARALLEL_MODULES[i].__name__}: {result}")
        else:
            all_findings.extend(result)

    # ── Outputs ───────────────────────────────────────────────────────────
    print_report(all_findings, args.url, DEFAULT_TXT)

    if args.format in ("html", "all"):
        html_report.generate(all_findings, base_url=args.url, output_path=args.output)

    # Always save JSON for diff
    json_report.generate(all_findings, base_url=args.url, output_path=DEFAULT_JSON)
    if args.format in ("json", "all"):
        print(f"  JSON report      → {DEFAULT_JSON}")

    if args.diff and os.path.exists(args.diff):
        print(f"\n  Running diff against {args.diff}...")
        diff_report.generate(all_findings, previous_path=args.diff)
    elif args.diff:
        print(f"  ⚠  Diff file not found: {args.diff}")

    if args.splunk:
        print(f"\n  Generating Splunk outputs...")
        splunk_dashboard.generate(all_findings, base_url=args.url)


def main():
    args = parse_args()
    asyncio.run(run_scan(args))


if __name__ == "__main__":
    main()
