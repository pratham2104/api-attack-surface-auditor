"""
scanner/cors.py
CORS misconfiguration test — NEW in Phase 1.
A misconfigured CORS policy lets malicious websites make authenticated
requests to the API on behalf of a logged-in user and read the response.
Two vectors tested:
  1. Evil origin reflection — does the server echo back a fake origin?
  2. Wildcard + credentials — does the server allow credentials with a wildcard?
"""

EVIL_ORIGIN = "https://evil.com"
PROBE_ROUTES = ["/api/users", "/api/activities", "/api/admin"]


def run(client, base_url, token_a, **kwargs):
    print("\n[7/8] CORS misconfiguration")
    print(f"      Sending Origin: {EVIL_ORIGIN} — checking if server reflects it\n")

    findings = []
    vuln_found = False

    for route in PROBE_ROUTES:
        try:
            r = client.get(
                f"{base_url}{route}",
                headers={
                    "Authorization": f"Bearer {token_a}",
                    "Origin": EVIL_ORIGIN,
                }
            )
            print(f"  GET {route:<35} → {r.status_code}")

            acao = r.headers.get("Access-Control-Allow-Origin", "")
            acac = r.headers.get("Access-Control-Allow-Credentials", "")

            # Worst case: evil origin reflected AND credentials allowed
            if EVIL_ORIGIN in acao and acac.lower() == "true":
                findings.append({
                    "status": "VULNERABLE",
                    "category": "CORS — Evil Origin + Credentials",
                    "severity": "Critical",
                    "owasp": "API8:2023 — Security Misconfiguration",
                    "detail": (
                        f"Server reflects evil origin AND allows credentials at {route}. "
                        "A malicious site can make authenticated requests on behalf of any user."
                    ),
                    "request": f"GET {base_url}{route}  Origin: {EVIL_ORIGIN}",
                    "response": (
                        f"Access-Control-Allow-Origin: {acao}  |  "
                        f"Access-Control-Allow-Credentials: {acac}"
                    ),
                })
                vuln_found = True

            # Medium: evil origin reflected but no credentials
            elif EVIL_ORIGIN in acao:
                findings.append({
                    "status": "VULNERABLE",
                    "category": "CORS — Evil Origin Reflected",
                    "severity": "Medium",
                    "owasp": "API8:2023 — Security Misconfiguration",
                    "detail": (
                        f"Server reflects evil origin at {route} — "
                        "cross-origin reads are possible without credential theft."
                    ),
                    "request": f"GET {base_url}{route}  Origin: {EVIL_ORIGIN}",
                    "response": f"Access-Control-Allow-Origin: {acao}",
                })
                vuln_found = True

            # Medium: wildcard with credentials (spec-invalid but some servers do it)
            elif acao == "*" and acac.lower() == "true":
                findings.append({
                    "status": "VULNERABLE",
                    "category": "CORS — Wildcard + Credentials",
                    "severity": "Medium",
                    "owasp": "API8:2023 — Security Misconfiguration",
                    "detail": (
                        f"Wildcard origin with credentials allowed at {route}. "
                        "Browsers block this per-spec, but some clients do not."
                    ),
                    "request": f"GET {base_url}{route}  Origin: {EVIL_ORIGIN}",
                    "response": (
                        f"Access-Control-Allow-Origin: *  |  "
                        f"Access-Control-Allow-Credentials: {acac}"
                    ),
                })
                vuln_found = True

            else:
                print(f"    ACAO: '{acao or 'not set'}'  ACAC: '{acac or 'not set'}'")

        except Exception as e:
            print(f"  GET {route:<35} → ERROR: {e}")

    if not vuln_found:
        print("\n  ✓ No CORS misconfigurations detected")
        findings.append({
            "status": "SAFE",
            "category": "CORS",
            "severity": None,
            "owasp": "API8:2023 — Security Misconfiguration",
        })

    return findings
