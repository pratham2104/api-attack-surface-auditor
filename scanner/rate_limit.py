"""
scanner/rate_limit.py
Rate limiting test.
Fires 50 rapid POST requests at the login endpoint with wrong credentials.
Flags if no 429 Too Many Requests is returned — means brute-force is possible.
"""


def run(client, base_url, **kwargs):
    print("\n[5/8] Rate limiting")
    print("      50 rapid login requests — expecting a 429 before request 50\n")

    findings = []
    hit_limit = False

    for i in range(1, 51):
        try:
            r = client.post(
                f"{base_url}/api/auth/login",
                json={"employee_id": f"EMP-{i:03d}", "password": "wrongpassword"},
                headers={"Content-Type": "application/json"}
            )
            print(f"  Request {i:02d}/50 → {r.status_code}")

            if r.status_code == 429:
                print(f"\n  ✓ Rate limit triggered at request {i}")
                findings.append({
                    "status": "SAFE",
                    "category": "Rate Limiting",
                    "severity": None,
                    "owasp": "API4:2023 — Unrestricted Resource Consumption",
                })
                hit_limit = True
                break

        except Exception as e:
            print(f"  Request {i:02d} → ERROR: {e}")
            break

    if not hit_limit:
        findings.append({
            "status": "VULNERABLE",
            "category": "Missing Rate Limiting",
            "severity": "Medium",
            "owasp": "API4:2023 — Unrestricted Resource Consumption",
            "detail": "50 rapid login attempts completed with no 429 — brute-force is unrestricted",
            "request": "POST /api/auth/login x50, wrong credentials, no delay between requests",
            "response": "No 429 Too Many Requests received across all 50 requests",
        })

    return findings
