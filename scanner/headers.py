"""
scanner/headers.py
Security headers audit — async version.
"""

EXPECTED_HEADERS = {
    "Content-Security-Policy":    ("High",   "Prevents XSS by controlling which scripts the browser can load"),
    "Strict-Transport-Security":  ("High",   "Forces HTTPS — prevents protocol downgrade and cookie hijacking"),
    "X-Frame-Options":            ("Medium", "Blocks clickjacking — prevents iframe embedding on malicious sites"),
    "X-Content-Type-Options":     ("Medium", "Stops MIME sniffing — prevents type-confusion attacks on uploads"),
    "Referrer-Policy":            ("Low",    "Controls URL info leaking in the Referer header"),
    "Permissions-Policy":         ("Low",    "Restricts browser features (camera, mic, geolocation)"),
}

PROBE_ROUTES = ["/api/health", "/api/leaderboard", "/api/activities"]


async def run(client, base_url, token_a, **kwargs):
    print("\n[6/8] Security headers audit")
    print("      Checking response headers across sampled endpoints\n")

    findings       = []
    missing_headers = {}

    for route in PROBE_ROUTES:
        try:
            r = await client.get(
                f"{base_url}{route}",
                headers={"Authorization": f"Bearer {token_a}"}
            )
            print(f"  GET {route:<35} → {r.status_code}")

            for header in EXPECTED_HEADERS:
                if header.lower() not in {k.lower() for k in r.headers}:
                    missing_headers.setdefault(header, []).append(route)

        except Exception as e:
            print(f"  GET {route:<35} → ERROR: {e}")

    for header, routes in missing_headers.items():
        severity, reason = EXPECTED_HEADERS[header]
        findings.append({
            "status":   "VULNERABLE",
            "category": f"Missing Header: {header}",
            "severity": severity,
            "owasp":    "API8:2023 — Security Misconfiguration",
            "detail":   f"'{header}' absent on: {', '.join(routes)}. {reason}.",
            "request":  f"GET {base_url}{routes[0]}  (checking response headers)",
            "response": f"Header '{header}' not present in response",
        })
        print(f"  ⚠  Missing: {header} ({severity})")

    if not missing_headers:
        print("\n  ✓ All expected security headers present")
        findings.append({
            "status":   "SAFE",
            "category": "Security Headers",
            "severity": None,
            "owasp":    "API8:2023 — Security Misconfiguration",
        })

    return findings
