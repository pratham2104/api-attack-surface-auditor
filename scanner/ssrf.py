"""
scanner/ssrf.py
SSRF — v6 update. Uses discovered endpoints and URL-like params from api_map.
Same baseline-comparison detection logic as v5 fix.
"""

import re

SSRF_PAYLOADS = [
    "http://localhost",
    "http://127.0.0.1",
    "http://0.0.0.0",
    "http://169.254.169.254",
    "http://169.254.169.254/latest/meta-data/",
    "http://metadata.google.internal",
    "http://localhost:5432",
    "http://localhost:6379",
    "http://localhost:8080",
]

URL_PARAM_NAMES = {"url", "redirect", "target", "src", "href",
                   "link", "image", "icon", "callback", "next",
                   "return", "goto", "uri", "path", "source"}

INTERNAL_INDICATORS = re.compile(
    r"(ami-id|instance-id|instance-type|computeMetadata|"
    r"redis_version|PostgreSQL|root:.*daemon:|"
    r"local-hostname|placement/region|iam/security-credentials)",
    re.IGNORECASE
)

FALLBACK_TARGETS = [
    ("/api/activities",  ["url", "redirect", "target", "src"]),
    ("/api/feed",        ["url", "source", "redirect"]),
    ("/api/challenges",  ["image", "url", "icon"]),
]


def _build_targets_from_api_map(api_map):
    targets = []
    for path, methods in api_map.get("endpoints", {}).items():
        url_params = []
        for method, op in methods.items():
            for p in op.get("parameters", []):
                if p["name"].lower() in URL_PARAM_NAMES:
                    url_params.append(p["name"])
        if url_params:
            targets.append((path, list(set(url_params))))
    return targets[:4] if targets else None


async def _baseline(client, base_url, route, token_a):
    try:
        r = await client.get(
            f"{base_url}{route}",
            headers={"Authorization": f"Bearer {token_a}"}
        )
        return r.status_code, len(r.text)
    except Exception:
        return None, 0


async def run(client, base_url, token_a, api_map, **kwargs):
    targets = _build_targets_from_api_map(api_map)
    if not targets:
        targets = FALLBACK_TARGETS
        print("\n[9/15] SSRF  (fallback route list)")
    else:
        print(f"\n[9/15] SSRF  ({len(targets)} endpoints with URL-like params from spec)")

    print("       Baseline comparison to eliminate false positives\n")

    findings  = []
    vuln_found = False

    for route, params in targets:
        base_status, base_len = await _baseline(client, base_url, route, token_a)
        print(f"  {route}  baseline: {base_status}, {base_len}B")

        for param in params:
            for payload in SSRF_PAYLOADS:
                try:
                    r = await client.get(
                        f"{base_url}{route}",
                        params={param: payload},
                        headers={"Authorization": f"Bearer {token_a}"},
                    )

                    if INTERNAL_INDICATORS.search(r.text):
                        findings.append({
                            "status":   "VULNERABLE",
                            "category": "SSRF",
                            "severity": "Critical",
                            "owasp":    "API7:2023 — Server Side Request Forgery",
                            "detail":   f"Internal content in response at {route}?{param}={payload}",
                            "request":  f"GET {base_url}{route}?{param}={payload}",
                            "response": f"HTTP {r.status_code}: {r.text[:300]}",
                        })
                        vuln_found = True
                        break

                    if base_len > 0 and abs(len(r.text) - base_len) / base_len > 0.20:
                        findings.append({
                            "status":   "VULNERABLE",
                            "category": "SSRF",
                            "severity": "High",
                            "owasp":    "API7:2023 — Server Side Request Forgery",
                            "detail":   f"Response delta >20% at {route}?{param}={payload}",
                            "request":  f"GET {base_url}{route}?{param}={payload}",
                            "response": f"HTTP {r.status_code}: {r.text[:300]}",
                        })
                        vuln_found = True

                    if r.status_code == 500 and base_status != 500:
                        findings.append({
                            "status":   "VULNERABLE",
                            "category": "SSRF",
                            "severity": "High",
                            "owasp":    "API7:2023 — Server Side Request Forgery",
                            "detail":   f"500 triggered by internal URL at {route}?{param}={payload}",
                            "request":  f"GET {base_url}{route}?{param}={payload}",
                            "response": f"HTTP 500: {r.text[:200]}",
                        })
                        vuln_found = True

                except Exception:
                    pass

    if not vuln_found:
        print("\n  ✓ No SSRF indicators — responses match baseline")
        findings.append({
            "status":   "SAFE",
            "category": "SSRF",
            "severity": None,
            "owasp":    "API7:2023 — Server Side Request Forgery",
        })

    return findings
