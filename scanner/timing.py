"""
scanner/timing.py
Timing attack / username enumeration — new in v6.

A server that validates username existence before checking the password
takes measurably longer to respond for valid usernames than invalid ones.
This leaks which usernames exist — username enumeration via timing side-channel.

Method:
  1. Send N requests with a known-valid username + wrong password
  2. Send N requests with a random invalid username + wrong password
  3. Compare mean response times
  4. Flag if valid username consistently slower by more than THRESHOLD_MS

This is a classic Security+ side-channel attack concept.
"""

import asyncio
import time
import statistics

SAMPLE_SIZE   = 20       # requests per group — larger = more accurate
THRESHOLD_MS  = 50       # minimum mean difference to flag (milliseconds)
VALID_USER    = "EMP-001"
INVALID_USERS = [
    "NOTAUSER001",
    "FAKEEMP999",
    "INVALID_USER_XYZ",
    "DOESNOTEXIST001",
]


async def _timed_request(client, url, body, headers):
    """Send one login request and return elapsed time in milliseconds."""
    start = time.monotonic()
    try:
        await client.post(url, json=body, headers=headers)
    except Exception:
        pass
    return (time.monotonic() - start) * 1000


async def run(client, base_url, api_map, **kwargs):
    print("\n[NEW] Timing attack — username enumeration")
    print(f"      Sending {SAMPLE_SIZE} requests per group, measuring response time delta\n")

    login_url = f"{base_url}{api_map.get('login_endpoint', '/api/auth/login')}"
    headers   = {"Content-Type": "application/json"}

    # Warmup — prime connection pool
    for _ in range(3):
        await _timed_request(
            client, login_url,
            {"employee_id": VALID_USER, "password": "warmup"},
            headers
        )

    # Group A: valid username + wrong password
    print(f"  Timing {SAMPLE_SIZE} requests with valid username ({VALID_USER})...")
    valid_times = []
    for _ in range(SAMPLE_SIZE):
        t = await _timed_request(
            client, login_url,
            {"employee_id": VALID_USER, "password": "WRONGPASSWORD_XYZ"},
            headers
        )
        valid_times.append(t)
        await asyncio.sleep(0.05)   # small delay between requests

    # Group B: invalid username + wrong password
    print(f"  Timing {SAMPLE_SIZE} requests with invalid usernames...")
    invalid_times = []
    for i in range(SAMPLE_SIZE):
        fake_user = INVALID_USERS[i % len(INVALID_USERS)]
        t = await _timed_request(
            client, login_url,
            {"employee_id": fake_user, "password": "WRONGPASSWORD_XYZ"},
            headers
        )
        invalid_times.append(t)
        await asyncio.sleep(0.05)

    # Statistics
    valid_mean    = statistics.mean(valid_times)
    invalid_mean  = statistics.mean(invalid_times)
    valid_stdev   = statistics.stdev(valid_times)   if len(valid_times) > 1   else 0
    invalid_stdev = statistics.stdev(invalid_times) if len(invalid_times) > 1 else 0
    delta         = valid_mean - invalid_mean

    print(f"\n  Valid username   : mean={valid_mean:.1f}ms  stdev={valid_stdev:.1f}ms")
    print(f"  Invalid username : mean={invalid_mean:.1f}ms  stdev={invalid_stdev:.1f}ms")
    print(f"  Delta            : {delta:+.1f}ms  (threshold: >{THRESHOLD_MS}ms to flag)")

    if delta > THRESHOLD_MS:
        return [{
            "status":   "VULNERABLE",
            "category": "Timing Attack — Username Enumeration",
            "severity": "Medium",
            "owasp":    "API2:2023 — Broken Authentication",
            "detail":   (
                f"Valid username responses averaged {valid_mean:.1f}ms vs "
                f"{invalid_mean:.1f}ms for invalid — {delta:.1f}ms delta exceeds "
                f"{THRESHOLD_MS}ms threshold. The server validates username existence "
                "before password hashing, leaking valid usernames via response timing."
            ),
            "request":  (
                f"POST {login_url} x{SAMPLE_SIZE} (valid) "
                f"vs x{SAMPLE_SIZE} (invalid)"
            ),
            "response": (
                f"Valid mean: {valid_mean:.1f}ms  |  "
                f"Invalid mean: {invalid_mean:.1f}ms  |  "
                f"Delta: {delta:.1f}ms"
            ),
        }]

    print("  ✓ No significant timing difference detected")
    return [{
        "status":   "SAFE",
        "category": "Timing Attack — Username Enumeration",
        "severity": None,
        "owasp":    "API2:2023 — Broken Authentication",
    }]
