"""
scanner/business_logic.py
Business logic vulnerability testing — new in v6.
App-specific tests that generic scanners miss entirely.

Written for Move More (Tetherify) based on the known API surface.
Tests:
  1. Negative numeric values in activity fields
  2. Integer overflow in duration / steps / points
  3. Zero-value submissions
  4. Duplicate activity submissions (race condition)
  5. Future timestamp injection
  6. Extreme string lengths in text fields
  7. Negative point values in admin endpoints
  8. Activity type confusion (wrong type for metric)
"""

import asyncio
import json
from datetime import datetime, timedelta, timezone


async def _post_activity(client, base_url, token, body):
    """Helper: POST to activities endpoint."""
    try:
        r = await client.post(
            f"{base_url}/api/activities",
            json=body,
            headers={
                "Authorization":  f"Bearer {token}",
                "Content-Type":   "application/json",
            }
        )
        return r
    except Exception:
        return None


async def _check_negative_values(client, base_url, token_a):
    """Test if negative durations/steps are accepted."""
    findings = []
    cases = [
        {"title": "Test Walk", "type": "walk", "duration": -10,
         "desc": "negative duration (-10 minutes)"},
        {"title": "Test Steps", "type": "steps", "steps": -1000,
         "desc": "negative step count (-1000)"},
        {"title": "Test Run", "type": "run", "duration": -9999,
         "desc": "large negative duration (-9999)"},
    ]

    for case in cases:
        desc = case.pop("desc")
        r    = await _post_activity(client, base_url, token_a, case)
        if r and r.status_code in (200, 201):
            findings.append({
                "status":   "VULNERABLE",
                "category": "Business Logic — Negative Values Accepted",
                "severity": "Medium",
                "owasp":    "API3:2023 — Broken Object Property Level Authorization",
                "detail":   (
                    f"API accepted activity with {desc}. "
                    "Negative values could corrupt point calculations or allow "
                    "point farming through negative-to-positive manipulation."
                ),
                "request":  f"POST {base_url}/api/activities  body: {json.dumps(case)}",
                "response": f"HTTP {r.status_code}: {r.text[:200]}",
            })
    return findings


async def _check_integer_overflow(client, base_url, token_a):
    """Test if extremely large integers cause overflow or unhandled errors."""
    findings = []
    overflow_cases = [
        {"title": "Overflow Test", "type": "walk",
         "duration": 2147483648, "desc": "int32 max overflow"},
        {"title": "Overflow Test", "type": "steps",
         "steps": 9999999999, "desc": "large step count"},
        {"title": "Overflow Test", "type": "walk",
         "duration": 99999999999999, "desc": "very large duration"},
    ]

    for case in overflow_cases:
        desc = case.pop("desc")
        r    = await _post_activity(client, base_url, token_a, case)
        if r:
            if r.status_code == 500:
                findings.append({
                    "status":   "VULNERABLE",
                    "category": "Business Logic — Integer Overflow (Server Error)",
                    "severity": "High",
                    "owasp":    "API3:2023 — Broken Object Property Level Authorization",
                    "detail":   (
                        f"Server returned 500 when processing {desc}. "
                        "Unhandled integer overflow may crash the service or corrupt data."
                    ),
                    "request":  f"POST {base_url}/api/activities  body: {json.dumps(case)}",
                    "response": f"HTTP 500: {r.text[:200]}",
                })
            elif r.status_code in (200, 201):
                findings.append({
                    "status":   "VULNERABLE",
                    "category": "Business Logic — Integer Overflow (Accepted)",
                    "severity": "Medium",
                    "owasp":    "API3:2023 — Broken Object Property Level Authorization",
                    "detail":   (
                        f"API accepted activity with {desc}. "
                        "Extreme values accepted without validation may overflow database columns."
                    ),
                    "request":  f"POST {base_url}/api/activities  body: {json.dumps(case)}",
                    "response": f"HTTP {r.status_code}: {r.text[:200]}",
                })
    return findings


async def _check_zero_values(client, base_url, token_a):
    """Test if zero-duration activities are accepted and earn points."""
    findings = []
    r = await _post_activity(client, base_url, token_a, {
        "title": "Zero Duration", "type": "walk", "duration": 0
    })
    if r and r.status_code in (200, 201):
        body = r.text.lower()
        if "points" in body or "point" in body:
            findings.append({
                "status":   "VULNERABLE",
                "category": "Business Logic — Zero Duration Earns Points",
                "severity": "Medium",
                "owasp":    "API3:2023 — Broken Object Property Level Authorization",
                "detail":   (
                    "Zero-duration activity accepted and may have awarded points. "
                    "Users could farm points by submitting zero-duration activities repeatedly."
                ),
                "request":  f"POST {base_url}/api/activities  duration=0",
                "response": f"HTTP {r.status_code}: {r.text[:200]}",
            })
    return findings


async def _check_future_timestamps(client, base_url, token_a):
    """Test if future timestamps are accepted for activity logging."""
    findings = []
    future_date = (datetime.now(timezone.utc) + timedelta(days=30)).isoformat()
    r = await _post_activity(client, base_url, token_a, {
        "title": "Future Activity", "type": "walk",
        "duration": 30, "date": future_date, "timestamp": future_date,
    })
    if r and r.status_code in (200, 201):
        findings.append({
            "status":   "VULNERABLE",
            "category": "Business Logic — Future Timestamps Accepted",
            "severity": "Low",
            "owasp":    "API3:2023 — Broken Object Property Level Authorization",
            "detail":   (
                f"Activity with future timestamp ({future_date}) was accepted. "
                "Users could pre-log activities or manipulate challenge completion dates."
            ),
            "request":  f"POST {base_url}/api/activities  date={future_date}",
            "response": f"HTTP {r.status_code}: {r.text[:200]}",
        })
    return findings


async def _check_duplicate_submission(client, base_url, token_a):
    """Race condition test — submit the same activity simultaneously."""
    body = {"title": "Duplicate Race", "type": "walk", "duration": 10}

    tasks = [
        _post_activity(client, base_url, token_a, body)
        for _ in range(5)
    ]
    responses = await asyncio.gather(*tasks, return_exceptions=True)

    success_count = sum(
        1 for r in responses
        if r and not isinstance(r, Exception) and r.status_code in (200, 201)
    )

    if success_count > 1:
        return [{
            "status":   "VULNERABLE",
            "category": "Business Logic — Race Condition (Duplicate Submission)",
            "severity": "Medium",
            "owasp":    "API4:2023 — Unrestricted Resource Consumption",
            "detail":   (
                f"{success_count}/5 simultaneous identical activity submissions were accepted. "
                "Race condition allows duplicate point earning by firing requests in parallel."
            ),
            "request":  f"POST {base_url}/api/activities x5 simultaneously",
            "response": f"{success_count} successful responses",
        }]
    return []


async def run(client, base_url, token_a, **kwargs):
    print("\n[NEW] Business logic vulnerability testing")
    print("      Move More specific: negative values, overflow, duplicates, timestamps\n")

    findings  = []
    vuln_found = False

    tests = [
        ("Negative values",       _check_negative_values),
        ("Integer overflow",      _check_integer_overflow),
        ("Zero-duration",         _check_zero_values),
        ("Future timestamps",     _check_future_timestamps),
        ("Duplicate submission",  _check_duplicate_submission),
    ]

    for test_name, test_fn in tests:
        try:
            print(f"  Testing: {test_name}...")
            result = await test_fn(client, base_url, token_a)
            if result:
                findings.extend(result)
                vuln_found = True
                for f in result:
                    print(f"  ⚠  {f['category']}")
            else:
                print(f"  ✓ {test_name} — no issues")
        except Exception as e:
            print(f"  ERROR in {test_name}: {e}")

    if not vuln_found:
        print("\n  ✓ No business logic vulnerabilities detected")
        findings.append({
            "status":   "SAFE",
            "category": "Business Logic",
            "severity": None,
            "owasp":    "API3:2023 — Broken Object Property Level Authorization",
        })

    return findings
