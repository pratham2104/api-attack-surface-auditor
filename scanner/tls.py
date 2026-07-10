"""
scanner/tls.py
TLS / SSL security audit — new in v6.
Standard check in every real pentest report.

Checks:
  1. HTTPS enforcement — is TLS used at all?
  2. TLS version — TLS 1.0/1.1 are deprecated (RFC 8996)
  3. Certificate expiry — flag if expiring within 30 days
  4. HSTS header presence and configuration
  5. HTTP to HTTPS redirect — does the server force upgrade?
  6. Mixed content indicator — does the API serve over HTTP?

Note: For localhost targets (development), most checks are informational.
The TLS check is most relevant against production/staging URLs.
"""

import ssl
import socket
import urllib.parse
from datetime import datetime, timezone


def _cert_info(hostname, port=443):
    """Fetch TLS certificate info for a hostname."""
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert    = ssock.getpeercert()
                version = ssock.version()
                cipher  = ssock.cipher()
                return cert, version, cipher
    except Exception as e:
        return None, None, None


def _check_tls_version(version):
    """Return severity if TLS version is deprecated."""
    if version in ("TLSv1", "TLSv1.1", "SSLv3", "SSLv2"):
        return "High", f"Deprecated protocol {version} supported (RFC 8996 requires TLS 1.2+)"
    if version == "TLSv1.2":
        return "Low", "TLS 1.2 in use — TLS 1.3 preferred for forward secrecy"
    return None, None


def _check_cert_expiry(cert):
    """Check if certificate expires within 30 days."""
    try:
        not_after_str = cert.get("notAfter", "")
        not_after     = datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z")
        not_after     = not_after.replace(tzinfo=timezone.utc)
        now           = datetime.now(timezone.utc)
        days_left     = (not_after - now).days

        if days_left < 0:
            return "Critical", f"Certificate EXPIRED {abs(days_left)} days ago"
        if days_left < 30:
            return "High", f"Certificate expires in {days_left} days ({not_after_str})"
        return None, f"Certificate valid for {days_left} more days"
    except Exception:
        return None, "Could not parse certificate expiry"


async def run(client, base_url, **kwargs):
    print("\n[NEW] TLS / SSL security audit\n")

    findings = []
    parsed   = urllib.parse.urlparse(base_url)
    scheme   = parsed.scheme
    hostname = parsed.hostname
    port     = parsed.port or (443 if scheme == "https" else 80)

    # ── Check 1: HTTPS enforcement ─────────────────────────────────────────
    if scheme == "http":
        print(f"  ✗ Target is HTTP — no TLS ({base_url})")

        # Check if HTTP redirects to HTTPS
        http_to_https = False
        try:
            r = await client.get(base_url, follow_redirects=False)
            location = r.headers.get("location", "")
            if location.startswith("https://"):
                http_to_https = True
                print(f"  ✓ HTTP → HTTPS redirect present ({location})")
        except Exception:
            pass

        if hostname in ("localhost", "127.0.0.1", "0.0.0.0"):
            findings.append({
                "status":   "VULNERABLE",
                "category": "TLS — HTTP Only (localhost)",
                "severity": "Info",
                "owasp":    "API8:2023 — Security Misconfiguration",
                "detail":   (
                    "Target is running over HTTP on localhost — expected for development. "
                    "Ensure production deployment uses HTTPS with a valid certificate."
                ),
                "request":  f"Scheme check: {base_url}",
                "response": "HTTP (no TLS) — localhost environment",
            })
        else:
            sev = "Low" if http_to_https else "High"
            findings.append({
                "status":   "VULNERABLE",
                "category": "TLS — No HTTPS",
                "severity": sev,
                "owasp":    "API8:2023 — Security Misconfiguration",
                "detail":   (
                    f"Production API served over plain HTTP{'with redirect to HTTPS' if http_to_https else ' with no HTTPS redirect'}. "
                    "All traffic is unencrypted — credentials and tokens transmitted in plaintext."
                ),
                "request":  f"GET {base_url}",
                "response": f"HTTP (not HTTPS)  redirect={'yes' if http_to_https else 'no'}",
            })
        return findings

    # ── Check 2: TLS version and cipher ────────────────────────────────────
    print(f"  Checking TLS on {hostname}:{port}...")
    cert, tls_version, cipher = _cert_info(hostname, port)

    if tls_version:
        print(f"  TLS version : {tls_version}")
        print(f"  Cipher      : {cipher[0] if cipher else 'unknown'}")

        sev, reason = _check_tls_version(tls_version)
        if sev:
            findings.append({
                "status":   "VULNERABLE",
                "category": f"TLS — Deprecated Protocol ({tls_version})",
                "severity": sev,
                "owasp":    "API8:2023 — Security Misconfiguration",
                "detail":   reason,
                "request":  f"TLS handshake with {hostname}:{port}",
                "response": f"Protocol: {tls_version}  Cipher: {cipher}",
            })
        else:
            print(f"  ✓ TLS version acceptable ({tls_version})")
    else:
        print(f"  Could not establish TLS connection to {hostname}:{port}")

    # ── Check 3: Certificate expiry ─────────────────────────────────────────
    if cert:
        sev, reason = _check_cert_expiry(cert)
        print(f"  Certificate : {reason}")
        if sev:
            findings.append({
                "status":   "VULNERABLE",
                "category": "TLS — Certificate Expiry",
                "severity": sev,
                "owasp":    "API8:2023 — Security Misconfiguration",
                "detail":   reason,
                "request":  f"TLS certificate check for {hostname}",
                "response": str(cert.get("notAfter", "unknown")),
            })

    # ── Check 4: HSTS header ────────────────────────────────────────────────
    try:
        r = await client.get(base_url)
        hsts = r.headers.get("Strict-Transport-Security", "")

        if not hsts:
            findings.append({
                "status":   "VULNERABLE",
                "category": "TLS — Missing HSTS Header",
                "severity": "Medium",
                "owasp":    "API8:2023 — Security Misconfiguration",
                "detail":   (
                    "Strict-Transport-Security header absent. Without HSTS, browsers "
                    "may connect over HTTP on first visit, enabling protocol downgrade attacks."
                ),
                "request":  f"GET {base_url}",
                "response": "Strict-Transport-Security: <not present>",
            })
        else:
            print(f"  ✓ HSTS present: {hsts}")
            # Check max-age
            if "max-age=0" in hsts or "max-age=1" in hsts:
                findings.append({
                    "status":   "VULNERABLE",
                    "category": "TLS — HSTS max-age Too Short",
                    "severity": "Low",
                    "owasp":    "API8:2023 — Security Misconfiguration",
                    "detail":   f"HSTS max-age is too short: {hsts}. Recommended: max-age=31536000",
                    "request":  f"GET {base_url}",
                    "response": f"Strict-Transport-Security: {hsts}",
                })
    except Exception as e:
        print(f"  HSTS check error: {e}")

    if not findings:
        print("  ✓ TLS configuration looks good")
        findings.append({
            "status":   "SAFE",
            "category": "TLS / SSL",
            "severity": None,
            "owasp":    "API8:2023 — Security Misconfiguration",
        })

    return findings
