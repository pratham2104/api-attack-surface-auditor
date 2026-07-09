"""
scanner/sqli.py
SQL injection fuzzer — NEW in Phase 1.
Injects classic SQLi payloads into query params and request body fields.
Detection logic: flags HTTP 500 errors, SQL error strings leaking in
responses, and unusual response length changes vs the baseline.
Note: this is a black-box heuristic — it detects probable SQLi, not confirmed.
"""

import re

# Classic payloads — covers error-based, boolean-based, and comment tricks
PAYLOADS = [
    "' OR '1'='1",
    "' OR '1'='1'--",
    "' OR 1=1--",
    "'; DROP TABLE users--",
    "1' ORDER BY 1--",
    "' UNION SELECT null--",
    "admin'--",
    "' AND SLEEP(0)--",       # time-based (0s so it doesn't actually slow tests)
]

# SQL error strings that leak in responses — sign of unhandled exceptions
SQL_ERROR_PATTERNS = re.compile(
    r"(sql|syntax error|pg_query|pg::|pgsql|postgresql|"
    r"mysql|sqlite|ora-|odbc|jdbc|invalid query|unrecognized|"
    r"column .* does not exist|relation .* does not exist)",
    re.IGNORECASE
)

# Endpoints to probe with their method and injectable fields
TARGETS = [
    ("/api/auth/login",    "POST",  {"email": None,   "password": None}),
    ("/api/activities",    "GET",   {"type": None,    "limit": None}),
    ("/api/users",         "GET",   {"search": None,  "id": None}),
    ("/api/leaderboard",   "GET",   {"limit": None,   "offset": None}),
]


def _get_baseline(client, base_url, route, method, token_a):
    """Get a clean response length to compare against injected requests."""
    try:
        if method == "GET":
            r = client.get(
                f"{base_url}{route}",
                headers={"Authorization": f"Bearer {token_a}"}
            )
        else:
            r = client.post(
                f"{base_url}{route}",
                json={"email": "baseline@test.com", "password": "baseline"},
                headers={"Authorization": f"Bearer {token_a}", "Content-Type": "application/json"}
            )
        return len(r.text)
    except Exception:
        return None


def run(client, base_url, token_a, **kwargs):
    print("\n[8/8] SQL injection")
    print("      Fuzzing query params and body fields with SQLi payloads\n")

    findings = []
    vuln_found = False

    for route, method, fields in TARGETS:
        baseline_len = _get_baseline(client, base_url, route, method, token_a)
        print(f"  {method} {route}")

        for field in fields:
            for payload in PAYLOADS:
                try:
                    if method == "GET":
                        # Inject as a query parameter
                        r = client.get(
                            f"{base_url}{route}",
                            params={field: payload},
                            headers={"Authorization": f"Bearer {token_a}"}
                        )
                    else:
                        # Inject into the request body
                        body = {f: (payload if f == field else "test") for f in fields}
                        r = client.request(
                            method,
                            f"{base_url}{route}",
                            json=body,
                            headers={
                                "Authorization": f"Bearer {token_a}",
                                "Content-Type": "application/json"
                            }
                        )

                    # Detection: 500 error
                    if r.status_code == 500:
                        findings.append({
                            "status": "VULNERABLE",
                            "category": "SQL Injection",
                            "severity": "Critical",
                            "owasp": "API10:2023 — Unsafe Consumption of APIs",
                            "detail": (
                                f"500 error on {method} {route} "
                                f"with payload in field '{field}' — possible unhandled SQL error"
                            ),
                            "request": f"{method} {base_url}{route}  {field}={payload!r}",
                            "response": f"HTTP 500: {r.text[:200]}",
                        })
                        vuln_found = True
                        break

                    # Detection: SQL error string in response body
                    if SQL_ERROR_PATTERNS.search(r.text):
                        findings.append({
                            "status": "VULNERABLE",
                            "category": "SQL Injection — Error Leak",
                            "severity": "High",
                            "owasp": "API10:2023 — Unsafe Consumption of APIs",
                            "detail": (
                                f"SQL error string detected in response body at {route} "
                                f"with payload in '{field}' — database errors are leaking"
                            ),
                            "request": f"{method} {base_url}{route}  {field}={payload!r}",
                            "response": f"HTTP {r.status_code}: {r.text[:300]}",
                        })
                        vuln_found = True
                        break

                    # Detection: response length changed significantly (boolean-based indicator)
                    if baseline_len and abs(len(r.text) - baseline_len) > 500:
                        print(
                            f"    ⚠  Length anomaly: field={field!r} "
                            f"payload={payload!r}  Δlen={len(r.text) - baseline_len}"
                        )

                except Exception as e:
                    print(f"    ERROR: {e}")

        print(f"    Payloads sent — {r.status_code if 'r' in dir() else 'N/A'}")

    if not vuln_found:
        print("\n  ✓ No SQL injection indicators detected")
        findings.append({
            "status": "SAFE",
            "category": "SQL Injection",
            "severity": None,
            "owasp": "API10:2023 — Unsafe Consumption of APIs",
        })

    return findings
