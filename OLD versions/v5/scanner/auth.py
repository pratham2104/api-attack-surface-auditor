"""
scanner/auth.py
Tests every known endpoint with no Authorization header.
Flags any endpoint that returns 200 — it should require a token.
Async version — uses httpx.AsyncClient passed in from main.
"""

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

PUBLIC_BY_DESIGN = {"/api/health"}


async def run(client, base_url, **kwargs):
    print("\n[1/8] Missing authentication")
    print("      No token — expecting 401/403 on all protected routes\n")

    findings  = []
    vuln_found = False

    for route in KNOWN_ROUTES:
        try:
            r = await client.get(f"{base_url}{route}")
            print(f"  GET {route:<35} → {r.status_code}")

            if r.status_code == 200:
                accepted_risk = route in PUBLIC_BY_DESIGN
                findings.append({
                    "status":   "VULNERABLE",
                    "category": "Missing Auth",
                    "severity": "Info" if accepted_risk else "High",
                    "owasp":    "API2:2023 — Broken Authentication",
                    "detail":   (
                        f"{route} returns 200 with no token"
                        + (" (intentionally public — accepted risk)" if accepted_risk else "")
                    ),
                    "request":  f"GET {base_url}{route}  (no Authorization header)",
                    "response": f"HTTP {r.status_code}: {r.text[:200]}",
                })
                vuln_found = True

        except Exception as e:
            print(f"  GET {route:<35} → ERROR: {e}")

    if not vuln_found:
        print("\n  ✓ All endpoints returned non-200 without a token")
        findings.append({
            "status":   "SAFE",
            "category": "Missing Auth",
            "severity": None,
            "owasp":    "API2:2023 — Broken Authentication",
        })

    return findings
