"""
scanner/mass_assign.py
Mass assignment test.
Injects privileged fields into POST/PUT request bodies.
Flags any response that reflects one of the injected field names or values,
which means the server accepted and processed a field it should have ignored.
"""

import json

# Fields an attacker would try to inject to escalate privileges
INJECTED_FIELDS = {
    "role": "admin",
    "isAdmin": True,
    "credits": 99999,
    "is_first_login": False,
    "permissions": ["all"],
}

# Endpoints to test with their method and a minimal valid base body
TARGETS = [
    ("/api/activities", "POST", {"title": "test", "type": "walk", "duration": 10}),
    ("/api/challenges", "POST", {"name": "test challenge"}),
    ("/api/users/profile", "PUT",  {"name": "Test User"}),
]


def run(client, base_url, token_a, **kwargs):
    """
    token_a = low-privilege token — we inject fields to try to escalate
    """
    print("\n[4/8] Mass assignment")
    print("      Injecting privileged fields into POST/PUT bodies\n")

    findings = []
    vuln_found = False

    for route, method, base_body in TARGETS:
        # Merge the legitimate body with the injected privileged fields
        payload = {**base_body, **INJECTED_FIELDS}

        try:
            r = client.request(
                method,
                f"{base_url}{route}",
                json=payload,
                headers={
                    "Authorization": f"Bearer {token_a}",
                    "Content-Type": "application/json",
                }
            )
            print(f"  {method} {route:<35} → {r.status_code}")

            # Check if any injected field name or value appears in the response
            response_text = r.text.lower()
            for field, val in INJECTED_FIELDS.items():
                if field.lower() in response_text or str(val).lower() in response_text:
                    findings.append({
                        "status": "VULNERABLE",
                        "category": "Mass Assignment",
                        "severity": "High",
                        "owasp": "API6:2023 — Unrestricted Access to Sensitive Business Flows",
                        "detail": f"Field '{field}' reflected in response at {route} — server may have applied it",
                        "request": f"{method} {base_url}{route}  body: {json.dumps(payload)[:200]}",
                        "response": f"HTTP {r.status_code}: {r.text[:300]}",
                    })
                    vuln_found = True
                    break

        except Exception as e:
            print(f"  {method} {route:<35} → ERROR: {e}")

    if not vuln_found:
        print("\n  ✓ No injected fields reflected in any response")
        findings.append({
            "status": "SAFE",
            "category": "Mass Assignment",
            "severity": None,
            "owasp": "API6:2023 — Unrestricted Access to Sensitive Business Flows",
        })

    return findings
