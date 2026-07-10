"""
scanner/mass_assign.py
Mass assignment test — async version.
Injects privileged fields into POST/PUT bodies and checks if reflected.
"""

import json

INJECTED_FIELDS = {
    "role":          "admin",
    "isAdmin":       True,
    "credits":       99999,
    "is_first_login": False,
    "permissions":   ["all"],
}

TARGETS = [
    ("/api/activities",    "POST", {"title": "test", "type": "walk", "duration": 10}),
    ("/api/challenges",    "POST", {"name": "test challenge"}),
    ("/api/users/profile", "PUT",  {"name": "Test User"}),
]


async def run(client, base_url, token_a, **kwargs):
    print("\n[4/8] Mass assignment")
    print("      Injecting privileged fields into POST/PUT bodies\n")

    findings  = []
    vuln_found = False

    for route, method, base_body in TARGETS:
        payload = {**base_body, **INJECTED_FIELDS}
        try:
            r = await client.request(
                method,
                f"{base_url}{route}",
                json=payload,
                headers={
                    "Authorization":  f"Bearer {token_a}",
                    "Content-Type":   "application/json",
                }
            )
            print(f"  {method} {route:<35} → {r.status_code}")

            response_text = r.text.lower()
            for field, val in INJECTED_FIELDS.items():
                if field.lower() in response_text or str(val).lower() in response_text:
                    findings.append({
                        "status":   "VULNERABLE",
                        "category": "Mass Assignment",
                        "severity": "High",
                        "owasp":    "API6:2023 — Unrestricted Access to Sensitive Business Flows",
                        "detail":   f"Field '{field}' reflected in response at {route}",
                        "request":  f"{method} {base_url}{route}  body: {json.dumps(payload)[:200]}",
                        "response": f"HTTP {r.status_code}: {r.text[:300]}",
                    })
                    vuln_found = True
                    break

        except Exception as e:
            print(f"  {method} {route:<35} → ERROR: {e}")

    if not vuln_found:
        print("\n  ✓ No injected fields reflected in any response")
        findings.append({
            "status":   "SAFE",
            "category": "Mass Assignment",
            "severity": None,
            "owasp":    "API6:2023 — Unrestricted Access to Sensitive Business Flows",
        })

    return findings
