"""
scanner/cors.py
CORS misconfiguration test — async version.
"""

EVIL_ORIGIN  = "https://evil.com"
PROBE_ROUTES = ["/api/users", "/api/activities", "/api/admin"]


async def run(client, base_url, token_a, **kwargs):
    print("\n[7/8] CORS misconfiguration")
    print(f"      Sending Origin: {EVIL_ORIGIN} — checking if server reflects it\n")

    findings  = []
    vuln_found = False

    for route in PROBE_ROUTES:
        try:
            r = await client.get(
                f"{base_url}{route}",
                headers={
                    "Authorization": f"Bearer {token_a}",
                    "Origin":        EVIL_ORIGIN,
                }
            )
            print(f"  GET {route:<35} → {r.status_code}")

            acao = r.headers.get("Access-Control-Allow-Origin", "")
            acac = r.headers.get("Access-Control-Allow-Credentials", "")

            if EVIL_ORIGIN in acao and acac.lower() == "true":
                findings.append({
                    "status":   "VULNERABLE",
                    "category": "CORS — Evil Origin + Credentials",
                    "severity": "Critical",
                    "owasp":    "API8:2023 — Security Misconfiguration",
                    "detail":   f"Server reflects evil origin AND allows credentials at {route}",
                    "request":  f"GET {base_url}{route}  Origin: {EVIL_ORIGIN}",
                    "response": f"ACAO: {acao}  |  ACAC: {acac}",
                })
                vuln_found = True

            elif EVIL_ORIGIN in acao:
                findings.append({
                    "status":   "VULNERABLE",
                    "category": "CORS — Evil Origin Reflected",
                    "severity": "Medium",
                    "owasp":    "API8:2023 — Security Misconfiguration",
                    "detail":   f"Server reflects evil origin at {route}",
                    "request":  f"GET {base_url}{route}  Origin: {EVIL_ORIGIN}",
                    "response": f"Access-Control-Allow-Origin: {acao}",
                })
                vuln_found = True

            elif acao == "*" and acac.lower() == "true":
                findings.append({
                    "status":   "VULNERABLE",
                    "category": "CORS — Wildcard + Credentials",
                    "severity": "Medium",
                    "owasp":    "API8:2023 — Security Misconfiguration",
                    "detail":   f"Wildcard origin with credentials at {route}",
                    "request":  f"GET {base_url}{route}  Origin: {EVIL_ORIGIN}",
                    "response": f"ACAO: *  |  ACAC: {acac}",
                })
                vuln_found = True
            else:
                print(f"    ACAO: '{acao or 'not set'}'  ACAC: '{acac or 'not set'}'")

        except Exception as e:
            print(f"  GET {route:<35} → ERROR: {e}")

    if not vuln_found:
        print("\n  ✓ No CORS misconfigurations detected")
        findings.append({
            "status":   "SAFE",
            "category": "CORS",
            "severity": None,
            "owasp":    "API8:2023 — Security Misconfiguration",
        })

    return findings
