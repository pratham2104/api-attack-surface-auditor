"""
scanner/versioning.py
API versioning attack — new in v6.
Old API versions are routinely left without auth, rate limiting,
or input validation because they were "deprecated" but never removed.

Strategy:
  1. Take all known routes from api_map
  2. Strip the /api/ prefix from each route
  3. Probe the route under multiple version prefixes
  4. Compare auth behavior — if the old version accepts requests
     that the current version rejects, flag it
"""

# Version prefixes to probe
VERSION_PREFIXES = [
    "/v1",
    "/v2",
    "/api/v1",
    "/api/v2",
    "/api/v3",
    "/api/beta",
    "/api/dev",
    "/api/internal",
    "/api/v1.0",
    "/api/v2.0",
    "/api/old",
    "/api/legacy",
]

# Suffixes that indicate an old version endpoint
OLD_VERSION_SIGNALS = ["v1", "v2", "beta", "dev", "internal", "old", "legacy"]


def _strip_prefix(route):
    """Strip /api/ or /api/vN/ prefix from a route to get the resource name."""
    import re
    # Remove /api/vN/ or /api/ prefix
    cleaned = re.sub(r"^/api(/v\d+)?", "", route)
    return cleaned or route


async def run(client, base_url, token_a, api_map, **kwargs):
    print("\n[NEW] API versioning attacks")
    print("      Probing old/deprecated version prefixes for unprotected endpoints\n")

    findings  = []
    vuln_found = False
    tested     = set()

    known_routes = api_map.get("routes", [])

    for route in known_routes[:8]:   # cap at 8 routes to keep scan fast
        resource = _strip_prefix(route)
        if not resource or resource in tested:
            continue
        tested.add(resource)

        # Get baseline — how the current version responds
        try:
            baseline = await client.get(
                f"{base_url}{route}",
                headers={"Authorization": f"Bearer {token_a}"}
            )
            baseline_auth_status = baseline.status_code
        except Exception:
            baseline_auth_status = None

        for prefix in VERSION_PREFIXES:
            versioned_route = prefix + resource
            if versioned_route == route:
                continue

            try:
                # Test without auth — old versions often skip auth entirely
                r_no_auth = await client.get(f"{base_url}{versioned_route}")

                if r_no_auth.status_code == 200:
                    findings.append({
                        "status":   "VULNERABLE",
                        "category": "API Versioning — Unprotected Old Version",
                        "severity": "High",
                        "owasp":    "API9:2023 — Improper Inventory Management",
                        "detail":   (
                            f"Old version endpoint {versioned_route} returns 200 with no auth. "
                            f"Current version {route} requires authentication. "
                            "Deprecated versions bypass security controls."
                        ),
                        "request":  f"GET {base_url}{versioned_route}  (no Authorization header)",
                        "response": f"HTTP {r_no_auth.status_code}: {r_no_auth.text[:200]}",
                    })
                    vuln_found = True
                    print(f"  ⚠  UNPROTECTED: {versioned_route} → {r_no_auth.status_code}")

                elif r_no_auth.status_code not in (404, 410):
                    # Endpoint exists but returns something other than 404
                    # Could be auth bypass or different behavior
                    print(f"  Found: {versioned_route} → {r_no_auth.status_code}")

                    # Test with auth to compare behavior
                    r_auth = await client.get(
                        f"{base_url}{versioned_route}",
                        headers={"Authorization": f"Bearer {token_a}"}
                    )

                    if r_auth.status_code == 200 and baseline_auth_status != 200:
                        findings.append({
                            "status":   "VULNERABLE",
                            "category": "API Versioning — Different Auth Behavior",
                            "severity": "Medium",
                            "owasp":    "API9:2023 — Improper Inventory Management",
                            "detail":   (
                                f"Old version {versioned_route} responds differently than "
                                f"current version {route}. May have weaker security controls."
                            ),
                            "request":  f"GET {base_url}{versioned_route}",
                            "response": f"HTTP {r_auth.status_code}: {r_auth.text[:200]}",
                        })
                        vuln_found = True

            except Exception:
                pass

    if not vuln_found:
        print("  ✓ No unprotected versioned endpoints found")
        findings.append({
            "status":   "SAFE",
            "category": "API Versioning",
            "severity": None,
            "owasp":    "API9:2023 — Improper Inventory Management",
        })

    return findings
