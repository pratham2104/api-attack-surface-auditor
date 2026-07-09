"""
scanner/headers.py
Security headers audit — NEW in Phase 1.
Checks every endpoint response for missing or misconfigured HTTP security headers.
These headers are the first line of browser-side defense and are checked
in every real penetration test as standard practice.
"""

# Headers we expect, with a plain-English reason why each matters
EXPECTED_HEADERS = {
    "Content-Security-Policy": (
        "High",
        "Prevents XSS by controlling which scripts, styles, and resources the browser can load"
    ),
    "Strict-Transport-Security": (
        "High",
        "Forces HTTPS — prevents protocol downgrade attacks and cookie hijacking over HTTP"
    ),
    "X-Frame-Options": (
        "Medium",
        "Blocks clickjacking — prevents the page being embedded in an iframe on a malicious site"
    ),
    "X-Content-Type-Options": (
        "Medium",
        "Stops browsers from MIME-sniffing — prevents type-confusion attacks on file uploads"
    ),
    "Referrer-Policy": (
        "Low",
        "Controls how much URL info leaks in the Referer header when following links"
    ),
    "Permissions-Policy": (
        "Low",
        "Restricts browser features (camera, mic, geolocation) from being used by the page"
    ),
}

# Probe these routes — we pick ones likely to return actual responses
PROBE_ROUTES = ["/api/health", "/api/leaderboard", "/api/activities"]


def run(client, base_url, token_a, **kwargs):
    print("\n[6/8] Security headers audit")
    print("      Checking response headers across sampled endpoints\n")

    findings = []
    missing_headers = {}   # header → list of routes where it was absent

    for route in PROBE_ROUTES:
        try:
            r = client.get(
                f"{base_url}{route}",
                headers={"Authorization": f"Bearer {token_a}"}
            )
            print(f"  GET {route:<35} → {r.status_code}")

            for header in EXPECTED_HEADERS:
                if header.lower() not in {k.lower() for k in r.headers}:
                    missing_headers.setdefault(header, []).append(route)

        except Exception as e:
            print(f"  GET {route:<35} → ERROR: {e}")

    # One finding per missing header (not per route)
    for header, routes in missing_headers.items():
        severity, reason = EXPECTED_HEADERS[header]
        findings.append({
            "status": "VULNERABLE",
            "category": f"Missing Header: {header}",
            "severity": severity,
            "owasp": "API8:2023 — Security Misconfiguration",
            "detail": f"'{header}' absent on: {', '.join(routes)}. {reason}.",
            "request": f"GET {base_url}{routes[0]}  (checking response headers)",
            "response": f"Header '{header}' not present in response",
        })
        print(f"  ⚠  Missing: {header} ({severity})")

    if not missing_headers:
        print("\n  ✓ All expected security headers present")
        findings.append({
            "status": "SAFE",
            "category": "Security Headers",
            "severity": None,
            "owasp": "API8:2023 — Security Misconfiguration",
        })

    return findings
