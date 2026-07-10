"""
scanner/sqli.py
SQL injection fuzzer — async version.
"""

import re

PAYLOADS = [
    "' OR '1'='1",
    "' OR '1'='1'--",
    "' OR 1=1--",
    "'; DROP TABLE users--",
    "1' ORDER BY 1--",
    "' UNION SELECT null--",
    "admin'--",
    "' AND SLEEP(0)--",
]

SQL_ERROR_PATTERNS = re.compile(
    r"(sql|syntax error|pg_query|pg::|pgsql|postgresql|"
    r"mysql|sqlite|ora-|odbc|jdbc|invalid query|unrecognized|"
    r"column .* does not exist|relation .* does not exist)",
    re.IGNORECASE
)

TARGETS = [
    ("/api/auth/login",  "POST", {"employee_id": None, "password": None}),
    ("/api/activities",  "GET",  {"type": None, "limit": None}),
    ("/api/users",       "GET",  {"search": None, "id": None}),
    ("/api/leaderboard", "GET",  {"limit": None, "offset": None}),
]


async def _get_baseline(client, base_url, route, method, token_a):
    try:
        if method == "GET":
            r = await client.get(
                f"{base_url}{route}",
                headers={"Authorization": f"Bearer {token_a}"}
            )
        else:
            r = await client.post(
                f"{base_url}{route}",
                json={"employee_id": "baseline", "password": "baseline"},
                headers={"Authorization": f"Bearer {token_a}", "Content-Type": "application/json"}
            )
        return len(r.text)
    except Exception:
        return None


async def run(client, base_url, token_a, **kwargs):
    print("\n[8/8] SQL injection")
    print("      Fuzzing query params and body fields with SQLi payloads\n")

    findings  = []
    vuln_found = False
    last_r     = None

    for route, method, fields in TARGETS:
        baseline_len = await _get_baseline(client, base_url, route, method, token_a)
        print(f"  {method} {route}")

        for field in fields:
            for payload in PAYLOADS:
                try:
                    if method == "GET":
                        r = await client.get(
                            f"{base_url}{route}",
                            params={field: payload},
                            headers={"Authorization": f"Bearer {token_a}"}
                        )
                    else:
                        body = {f: (payload if f == field else "test") for f in fields}
                        r = await client.request(
                            method,
                            f"{base_url}{route}",
                            json=body,
                            headers={
                                "Authorization": f"Bearer {token_a}",
                                "Content-Type":  "application/json"
                            }
                        )
                    last_r = r

                    if r.status_code == 500:
                        findings.append({
                            "status":   "VULNERABLE",
                            "category": "SQL Injection",
                            "severity": "Critical",
                            "owasp":    "API10:2023 — Unsafe Consumption of APIs",
                            "detail":   f"500 error on {method} {route} with payload in field '{field}'",
                            "request":  f"{method} {base_url}{route}  {field}={payload!r}",
                            "response": f"HTTP 500: {r.text[:200]}",
                        })
                        vuln_found = True
                        break

                    if SQL_ERROR_PATTERNS.search(r.text):
                        findings.append({
                            "status":   "VULNERABLE",
                            "category": "SQL Injection — Error Leak",
                            "severity": "High",
                            "owasp":    "API10:2023 — Unsafe Consumption of APIs",
                            "detail":   f"SQL error string in response at {route} field '{field}'",
                            "request":  f"{method} {base_url}{route}  {field}={payload!r}",
                            "response": f"HTTP {r.status_code}: {r.text[:300]}",
                        })
                        vuln_found = True
                        break

                    if baseline_len and abs(len(r.text) - baseline_len) > 500:
                        print(f"    ⚠  Length anomaly: field={field!r} Δlen={len(r.text) - baseline_len}")

                except Exception as e:
                    print(f"    ERROR: {e}")

        status = last_r.status_code if last_r else "N/A"
        print(f"    Payloads sent — {status}")

    if not vuln_found:
        print("\n  ✓ No SQL injection indicators detected")
        findings.append({
            "status":   "SAFE",
            "category": "SQL Injection",
            "severity": None,
            "owasp":    "API10:2023 — Unsafe Consumption of APIs",
        })

    return findings
