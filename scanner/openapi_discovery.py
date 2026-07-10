"""
scanner/openapi_discovery.py
The core architectural change in v6.

Auto-discovers API endpoints by fetching the OpenAPI / Swagger spec.
Parses both OpenAPI 3.x and Swagger 2.x formats.
Produces an api_map that all other scanner modules use instead of
hardcoded route lists. This makes the scanner work against any API
with zero configuration.

If no spec is found, falls back to probing common route patterns
and returns a best-guess api_map.

Returns:
    api_map dict consumed by ctx in main.py
"""

import json

# Common spec locations to try in order
SPEC_PATHS = [
    "/swagger.json",
    "/swagger/v1/swagger.json",
    "/api-docs",
    "/api-docs/swagger.json",
    "/openapi.json",
    "/openapi/v3/api-docs",
    "/v1/api-docs",
    "/api/swagger.json",
    "/.well-known/openapi.json",
    "/docs/openapi.json",
    "/api/openapi.json",
    "/api/v1/swagger.json",
]

# Fallback routes when no spec is found
FALLBACK_ROUTES = [
    "/api/health",
    "/api/activities",
    "/api/notifications",
    "/api/challenges",
    "/api/leaderboard",
    "/api/badges",
    "/api/squads",
    "/api/admin",
    "/api/users",
    "/api/feed",
    "/api/auth/login",
    "/api/auth/register",
]

# Common injectable parameter names by category
INJECTABLE_QUERY_PARAMS = ["id", "limit", "offset", "page", "search",
                            "filter", "sort", "type", "status", "q"]
URL_LIKE_PARAMS          = ["url", "redirect", "target", "src", "href",
                            "link", "image", "icon", "callback", "next"]


def _empty_map():
    return {
        "spec_found":     False,
        "spec_url":       None,
        "spec_version":   None,
        "routes":         FALLBACK_ROUTES,
        "endpoints":      {},
        "auth_schemes":   [],
        "oauth_flows":    {},
        "login_endpoint": "/api/auth/login",
        "login_field":    "employee_id",
        "servers":        [],
    }


def _parse_swagger2(spec):
    """Parse Swagger 2.x spec and return endpoint map."""
    endpoints = {}
    base_path = spec.get("basePath", "")

    for path, methods in spec.get("paths", {}).items():
        full_path = base_path.rstrip("/") + "/" + path.lstrip("/")
        endpoints[full_path] = {}

        for method, operation in methods.items():
            if method.lower() in ("get", "post", "put", "patch", "delete"):
                params = []
                for p in operation.get("parameters", []):
                    params.append({
                        "name":     p.get("name", ""),
                        "in":       p.get("in", "query"),
                        "type":     p.get("type", "string"),
                        "required": p.get("required", False),
                    })
                auth_required = bool(operation.get("security", spec.get("security")))
                endpoints[full_path][method.upper()] = {
                    "parameters":    params,
                    "auth_required": auth_required,
                }

    # Auth schemes
    auth_schemes = list(spec.get("securityDefinitions", {}).keys())

    return endpoints, auth_schemes, {}


def _parse_openapi3(spec):
    """Parse OpenAPI 3.x spec and return endpoint map."""
    endpoints = {}
    servers   = [s.get("url", "") for s in spec.get("servers", [])]

    for path, methods in spec.get("paths", {}).items():
        endpoints[path] = {}
        for method, operation in methods.items():
            if method.lower() in ("get", "post", "put", "patch", "delete"):
                params = []
                for p in operation.get("parameters", []):
                    params.append({
                        "name":     p.get("name", ""),
                        "in":       p.get("in", "query"),
                        "type":     p.get("schema", {}).get("type", "string"),
                        "required": p.get("required", False),
                    })
                auth_required = bool(operation.get("security", spec.get("security")))
                endpoints[path][method.upper()] = {
                    "parameters":    params,
                    "auth_required": auth_required,
                }

    # Auth schemes and OAuth flows
    auth_schemes = []
    oauth_flows  = {}
    for scheme_name, scheme in spec.get("components", {}).get("securitySchemes", {}).items():
        auth_schemes.append(scheme_name)
        if scheme.get("type") == "oauth2":
            oauth_flows[scheme_name] = scheme.get("flows", {})

    return endpoints, auth_schemes, oauth_flows, servers


def _enrich_endpoints(endpoints):
    """
    For any endpoint that has no documented parameters,
    inject a best-guess set of common parameter names.
    This ensures the scanner still fuzzes undocumented params.
    """
    for path, methods in endpoints.items():
        for method, op in methods.items():
            if not op.get("parameters"):
                guessed = []
                if method == "GET":
                    for p in INJECTABLE_QUERY_PARAMS:
                        guessed.append({"name": p, "in": "query",
                                        "type": "string", "required": False})
                op["parameters"] = guessed
    return endpoints


async def run(client, base_url, **kwargs):
    """
    Try to fetch and parse an OpenAPI spec from the target.
    Returns api_map dict — not a findings list.
    Called separately from other modules before the parallel scan.
    """
    print("\n[DISCOVERY] OpenAPI auto-discovery")
    print(f"            Probing {len(SPEC_PATHS)} common spec locations...\n")

    api_map = _empty_map()

    for spec_path in SPEC_PATHS:
        try:
            r = await client.get(
                f"{base_url}{spec_path}",
                headers={"Accept": "application/json"},
            )

            if r.status_code == 200 and "json" in r.headers.get("content-type", ""):
                spec = r.json()

                # Swagger 2.x
                if spec.get("swagger", "").startswith("2"):
                    endpoints, auth_schemes, oauth_flows = _parse_swagger2(spec)
                    endpoints = _enrich_endpoints(endpoints)
                    api_map.update({
                        "spec_found":   True,
                        "spec_url":     spec_path,
                        "spec_version": "2.x (Swagger)",
                        "routes":       list(endpoints.keys()),
                        "endpoints":    endpoints,
                        "auth_schemes": auth_schemes,
                        "oauth_flows":  oauth_flows,
                    })
                    print(f"  ✓ Swagger 2.x spec found at {spec_path}")
                    print(f"    Discovered {len(endpoints)} endpoints")
                    break

                # OpenAPI 3.x
                elif spec.get("openapi", "").startswith("3"):
                    endpoints, auth_schemes, oauth_flows, servers = _parse_openapi3(spec)
                    endpoints = _enrich_endpoints(endpoints)
                    api_map.update({
                        "spec_found":   True,
                        "spec_url":     spec_path,
                        "spec_version": "3.x (OpenAPI)",
                        "routes":       list(endpoints.keys()),
                        "endpoints":    endpoints,
                        "auth_schemes": auth_schemes,
                        "oauth_flows":  oauth_flows,
                        "servers":      servers,
                    })
                    print(f"  ✓ OpenAPI 3.x spec found at {spec_path}")
                    print(f"    Discovered {len(endpoints)} endpoints")
                    if oauth_flows:
                        print(f"    OAuth flows detected: {list(oauth_flows.keys())}")
                    break

        except Exception:
            pass

    if not api_map["spec_found"]:
        print("  ✗ No spec found — falling back to hardcoded route list")
        print(f"    Using {len(FALLBACK_ROUTES)} known routes")

        # Enrich fallback routes with guessed params
        for route in FALLBACK_ROUTES:
            api_map["endpoints"][route] = {
                "GET": {
                    "parameters":    [{"name": p, "in": "query", "type": "string", "required": False}
                                      for p in INJECTABLE_QUERY_PARAMS + URL_LIKE_PARAMS],
                    "auth_required": True,
                }
            }

    # Always return a finding so main.py can include it in the report
    discovery_finding = {
        "status":   "VULNERABLE" if not api_map["spec_found"] else "SAFE",
        "category": "API Discovery",
        "severity": "Low" if not api_map["spec_found"] else None,
        "owasp":    "API8:2023 — Security Misconfiguration",
        "detail":   (
            f"No OpenAPI spec found at any of {len(SPEC_PATHS)} common paths — "
            "API surface is undocumented, making security review harder."
        ) if not api_map["spec_found"] else (
            f"OpenAPI spec found at {api_map['spec_url']} "
            f"({api_map['spec_version']}, {len(api_map['routes'])} endpoints)"
        ),
        "request":  f"GET {base_url}/swagger.json (and {len(SPEC_PATHS)-1} other paths)",
        "response":  "No valid spec returned" if not api_map["spec_found"] else "Spec parsed successfully",
    }

    return [discovery_finding], api_map
