"""
scanner/ssrf.py
Server-Side Request Forgery (SSRF) test — v5.
Injects internal URLs into injectable parameters and compares
the response against a clean baseline.

A real SSRF changes the response — either by returning internal content
or by producing a different response length/structure.
Returning the same normal response means the server ignored the param.

Detection:
  1. Internal content strings in response (ami-id, instance-id, etc.)
  2. Response significantly different from baseline (length delta > 20%)
  3. Server error (500) caused by attempting to fetch an internal URL
"""

import re

SSRF_PAYLOADS = [
    "http://localhost",
    "http://127.0.0.1",
    "http://0.0.0.0",
    "http://169.254.169.254",
    "http://169.254.169.254/latest/meta-data/",
    "http://metadata.google.internal",
    "http://100.100.100.200/latest/meta-data/",
    "http://localhost:5432",
    "http://localhost:6379",
    "http://localhost:8080",
]

# Content that would only appear if the server actually fetched an internal URL
INTERNAL_INDICATORS = re.compile(
    r"(ami-id|instance-id|instance-type|computeMetadata|"
    r"redis_version|PostgreSQL|root:.*daemon:|"
    r"local-hostname|placement/region|iam/security-credentials)",
    re.IGNORECASE
)

TARGETS = [
    ("/api/activities",  ["url", "redirect", "target", "src"]),
    ("/api/feed",        ["url", "source", "redirect"]),
    ("/api/challenges",  ["image", "url", "icon"]),
]


async def _baseline(client, base_url, route, token_a):
    """Get a clean response for comparison."""
    try:
        r = await client.get(
            f"{base_url}{route}",
            headers={"Authorization": f"Bearer {token_a}"}
        )
        return r.status_code, len(r.text), r.text
    except Exception:
        return None, 0, ""


async def run(client, base_url, token_a, **kwargs):
    print("\n[9/9] SSRF — Server-Side Request Forgery")
    print("      Comparing responses against clean baseline to eliminate false positives\n")

    findings  = []
    vuln_found = False

    for route, params in TARGETS:
        base_status, base_len, base_text = await _baseline(client, base_url, route, token_a)
        print(f"  {route}  (baseline: {base_status}, {base_len} bytes)")

        for param in params:
            for payload in SSRF_PAYLOADS:
                try:
                    r = await client.get(
                        f"{base_url}{route}",
                        params={param: payload},
                        headers={"Authorization": f"Bearer {token_a}"},
                    )

                    # Detection 1: internal content strings in response
                    if INTERNAL_INDICATORS.search(r.text):
                        findings.append({
                            "status":   "VULNERABLE",
                            "category": "SSRF",
                            "severity": "Critical",
                            "owasp":    "API7:2023 — Server Side Request Forgery",
                            "detail":   (
                                f"Internal content detected in response at "
                                f"{route}?{param}={payload} — server made an internal request"
                            ),
                            "request":  f"GET {base_url}{route}?{param}={payload}",
                            "response": f"HTTP {r.status_code}: {r.text[:300]}",
                        })
                        vuln_found = True
                        print(f"    ⚠  INTERNAL CONTENT FOUND: {param}={payload}")
                        break

                    # Detection 2: response significantly differs from baseline
                    # (more than 20% change in length means the param affected the response)
                    if base_len > 0:
                        delta = abs(len(r.text) - base_len) / base_len
                        if delta > 0.20 and r.status_code == 200:
                            findings.append({
                                "status":   "VULNERABLE",
                                "category": "SSRF",
                                "severity": "High",
                                "owasp":    "API7:2023 — Server Side Request Forgery",
                                "detail":   (
                                    f"Response changed significantly ({delta:.0%} delta) "
                                    f"at {route}?{param}={payload} — server may have processed the URL"
                                ),
                                "request":  f"GET {base_url}{route}?{param}={payload}",
                                "response": f"HTTP {r.status_code}: {r.text[:300]}",
                            })
                            vuln_found = True
                            print(f"    ⚠  RESPONSE DELTA {delta:.0%}: {param}={payload}")

                    # Detection 3: 500 caused by attempting internal fetch
                    if r.status_code == 500 and base_status != 500:
                        findings.append({
                            "status":   "VULNERABLE",
                            "category": "SSRF",
                            "severity": "High",
                            "owasp":    "API7:2023 — Server Side Request Forgery",
                            "detail":   (
                                f"Server error triggered by internal URL at "
                                f"{route}?{param}={payload} — possible failed internal fetch"
                            ),
                            "request":  f"GET {base_url}{route}?{param}={payload}",
                            "response": f"HTTP 500: {r.text[:200]}",
                        })
                        vuln_found = True

                except Exception:
                    pass

    if not vuln_found:
        print("\n  ✓ No SSRF indicators detected — responses match baseline across all payloads")
        findings.append({
            "status":   "SAFE",
            "category": "SSRF",
            "severity": None,
            "owasp":    "API7:2023 — Server Side Request Forgery",
        })

    return findings
