"""
scanner/bola.py
Broken Object Level Authorization (BOLA / IDOR) test.
Authenticates as the low-privilege user and requests resources
belonging to the high-privilege user by substituting their ID.
Flags any 200 response — should be 403.
"""


def run(client, base_url, token_a, user_a_id, user_b_id, **kwargs):
    """
    token_a     = low-privilege token (employee)
    user_a_id   = their ID
    user_b_id   = the high-privilege user's ID we try to access
    """
    print("\n[2/8] BOLA / IDOR")
    print(f"      Authenticated as user {user_a_id}, requesting user {user_b_id} resources\n")

    # Build target paths using the other user's ID
    targets = [
        f"/api/users/{user_b_id}",
        f"/api/users/{user_b_id}/activities",
        f"/api/users/{user_b_id}/badges",
        f"/api/activities/{user_b_id}",
        f"/api/admin/users/{user_b_id}",
    ]

    findings = []
    vuln_found = False

    for route in targets:
        try:
            r = client.get(
                f"{base_url}{route}",
                headers={"Authorization": f"Bearer {token_a}"}
            )
            print(f"  GET {route:<45} → {r.status_code}")

            if r.status_code == 200:
                findings.append({
                    "status": "VULNERABLE",
                    "category": "BOLA/IDOR",
                    "severity": "High",
                    "owasp": "API1:2023 — Broken Object Level Authorization",
                    "detail": f"User {user_a_id} can read user {user_b_id} resource at {route}",
                    "request": f"GET {base_url}{route} with token for user {user_a_id}",
                    "response": f"HTTP {r.status_code}: {r.text[:200]}",
                })
                vuln_found = True

        except Exception as e:
            print(f"  GET {route:<45} → ERROR: {e}")

    if not vuln_found:
        print("\n  ✓ No cross-user resource access detected")
        findings.append({
            "status": "SAFE",
            "category": "BOLA/IDOR",
            "severity": None,
            "owasp": "API1:2023 — Broken Object Level Authorization",
        })

    return findings
