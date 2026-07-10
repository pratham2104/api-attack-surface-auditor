"""
scanner/oauth.py
OAuth 2.0 / SSO vulnerability testing — new in v6.
Tests for the most common OAuth implementation flaws:
  1. Redirect URI manipulation — can the redirect_uri be changed to an attacker domain?
  2. State parameter CSRF — is the state param present and validated?
  3. Token in URL — does the app return tokens in URL fragments / query params?
  4. Open redirect via redirect_uri — does the auth endpoint follow arbitrary redirects?
  5. Authorization endpoint discovery — are OAuth endpoints exposed?

Note: Most apps using JWT (like Move More) don't implement OAuth 2.0 flows
directly — this module checks for OAuth endpoints and tests them if found,
or flags their absence as informational.
"""

import urllib.parse

# Common OAuth / SSO endpoint paths to probe
OAUTH_PATHS = [
    "/oauth/authorize",
    "/oauth/token",
    "/auth/oauth/authorize",
    "/api/oauth/authorize",
    "/oauth2/authorize",
    "/oauth2/token",
    "/connect/authorize",
    "/connect/token",
    "/.well-known/openid-configuration",
    "/api/auth/oauth",
    "/auth/sso",
    "/saml/login",
]

EVIL_REDIRECT = "https://evil.com/callback"
EVIL_ORIGINS  = ["https://evil.com", "null", "https://attacker.example.com"]


async def _check_openid_config(client, base_url):
    """Fetch OpenID Connect discovery document if present."""
    try:
        r = await client.get(f"{base_url}/.well-known/openid-configuration")
        if r.status_code == 200:
            return r.json()
    except Exception:
        pass
    return None


async def _test_redirect_uri_manipulation(client, base_url, auth_endpoint):
    """Test if redirect_uri can be set to an arbitrary attacker domain."""
    findings = []
    payloads = [
        EVIL_REDIRECT,
        "https://evil.com",
        "https://evil.com/callback?legit=true",
        f"{base_url.rstrip('/')}/callback/../../../evil.com",
    ]

    for payload in payloads:
        params = {
            "response_type": "code",
            "client_id":     "test",
            "redirect_uri":  payload,
            "scope":         "openid profile",
            "state":         "test123",
        }
        try:
            r = await client.get(
                f"{base_url}{auth_endpoint}",
                params=params,
                follow_redirects=False
            )
            location = r.headers.get("location", "")

            # If the server redirects to our evil URL — critical finding
            if "evil.com" in location:
                findings.append({
                    "status":   "VULNERABLE",
                    "category": "OAuth — Redirect URI Manipulation",
                    "severity": "Critical",
                    "owasp":    "API2:2023 — Broken Authentication",
                    "detail":   (
                        f"Authorization endpoint redirected to attacker-controlled URI: {location}. "
                        "An attacker can steal authorization codes by replacing redirect_uri."
                    ),
                    "request":  f"GET {base_url}{auth_endpoint}?redirect_uri={payload}",
                    "response": f"HTTP {r.status_code}  Location: {location}",
                })
                break

        except Exception:
            pass

    return findings


async def _test_state_csrf(client, base_url, auth_endpoint):
    """Test if state parameter is required — missing state enables CSRF."""
    findings = []
    params = {
        "response_type": "code",
        "client_id":     "test",
        "redirect_uri":  f"{base_url}/callback",
        "scope":         "openid",
        # Intentionally omitting 'state'
    }
    try:
        r = await client.get(
            f"{base_url}{auth_endpoint}",
            params=params,
            follow_redirects=False
        )
        # If server accepts request without state and returns 302 → CSRF possible
        if r.status_code in (200, 302) and "error" not in r.text.lower():
            findings.append({
                "status":   "VULNERABLE",
                "category": "OAuth — Missing State Parameter (CSRF)",
                "severity": "High",
                "owasp":    "API2:2023 — Broken Authentication",
                "detail":   (
                    "Authorization request accepted without a state parameter. "
                    "An attacker can perform CSRF attacks to initiate OAuth flows "
                    "on behalf of a victim, leading to account linking attacks."
                ),
                "request":  f"GET {base_url}{auth_endpoint} (no state param)",
                "response": f"HTTP {r.status_code}: {r.text[:200]}",
            })
    except Exception:
        pass

    return findings


async def _test_token_in_url(client, base_url, token_a):
    """
    Check if tokens appear in URL parameters or referrer headers.
    Test by hitting endpoints with the token in the URL instead of header.
    """
    findings = []
    try:
        r = await client.get(
            f"{base_url}/api/activities",
            params={"access_token": token_a, "token": token_a},
        )
        if r.status_code == 200:
            findings.append({
                "status":   "VULNERABLE",
                "category": "OAuth — Token Accepted in URL Parameter",
                "severity": "Medium",
                "owasp":    "API2:2023 — Broken Authentication",
                "detail":   (
                    "API accepted access token as a URL query parameter instead of "
                    "requiring it in the Authorization header. Tokens in URLs are "
                    "logged by servers, proxies, and browser history — high leakage risk."
                ),
                "request":  f"GET {base_url}/api/activities?access_token=<token>",
                "response": f"HTTP {r.status_code}: {r.text[:200]}",
            })
    except Exception:
        pass

    return findings


async def run(client, base_url, token_a, api_map, **kwargs):
    print("\n[NEW] OAuth 2.0 / SSO vulnerability testing")
    print("      Probing for OAuth endpoints and testing common flaws\n")

    findings  = []
    vuln_found = False

    # Check for OpenID configuration
    oidc_config = await _check_openid_config(client, base_url)
    if oidc_config:
        print(f"  ✓ OpenID Connect config found — issuer: {oidc_config.get('issuer', 'unknown')}")
        auth_endpoint = urllib.parse.urlparse(
            oidc_config.get("authorization_endpoint", "")
        ).path

        if auth_endpoint:
            redirect_findings = await _test_redirect_uri_manipulation(
                client, base_url, auth_endpoint
            )
            state_findings = await _test_state_csrf(client, base_url, auth_endpoint)
            findings.extend(redirect_findings + state_findings)
            if redirect_findings or state_findings:
                vuln_found = True

    else:
        # Probe common OAuth paths
        found_endpoints = []
        for path in OAUTH_PATHS:
            try:
                r = await client.get(f"{base_url}{path}", follow_redirects=False)
                if r.status_code not in (404, 405):
                    found_endpoints.append(path)
                    print(f"  Found OAuth endpoint: {path} → {r.status_code}")
            except Exception:
                pass

        if found_endpoints:
            auth_ep = next((p for p in found_endpoints if "authoriz" in p), found_endpoints[0])
            redirect_findings = await _test_redirect_uri_manipulation(
                client, base_url, auth_ep
            )
            state_findings = await _test_state_csrf(client, base_url, auth_ep)
            findings.extend(redirect_findings + state_findings)
            if redirect_findings or state_findings:
                vuln_found = True
        else:
            print("  No OAuth / SSO endpoints found on this target")

    # Token in URL test — applies regardless of OAuth presence
    token_url_findings = await _test_token_in_url(client, base_url, token_a)
    if token_url_findings:
        findings.extend(token_url_findings)
        vuln_found = True

    if not vuln_found and not findings:
        print("  ✓ No OAuth vulnerabilities detected")
        findings.append({
            "status":   "SAFE",
            "category": "OAuth / SSO",
            "severity": None,
            "owasp":    "API2:2023 — Broken Authentication",
        })

    return findings
