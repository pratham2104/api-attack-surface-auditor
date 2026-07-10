"""
reporter/mitre_map.py
Maps each scanner finding category to a MITRE ATT&CK technique.
Data is hardcoded — no external API needed.
Reference: https://attack.mitre.org
"""

MITRE_MAP = {
    "SQL Injection": {
        "id":      "T1190",
        "name":    "Exploit Public-Facing Application",
        "tactic":  "Initial Access",
        "url":     "https://attack.mitre.org/techniques/T1190/",
        "summary": "Adversaries exploit weaknesses in internet-facing software to gain access."
    },
    "SQL Injection — Error Leak": {
        "id":      "T1190",
        "name":    "Exploit Public-Facing Application",
        "tactic":  "Initial Access",
        "url":     "https://attack.mitre.org/techniques/T1190/",
        "summary": "Database error strings leaking in responses aid adversary reconnaissance."
    },
    "Missing Auth": {
        "id":      "T1078",
        "name":    "Valid Accounts",
        "tactic":  "Defense Evasion / Persistence",
        "url":     "https://attack.mitre.org/techniques/T1078/",
        "summary": "Unauthenticated endpoints allow adversaries to access resources without credentials."
    },
    "Missing Rate Limiting": {
        "id":      "T1110",
        "name":    "Brute Force",
        "tactic":  "Credential Access",
        "url":     "https://attack.mitre.org/techniques/T1110/",
        "summary": "No request throttling allows automated credential guessing at scale."
    },
    "JWT alg:none": {
        "id":      "T1528",
        "name":    "Steal Application Access Token",
        "tactic":  "Credential Access",
        "url":     "https://attack.mitre.org/techniques/T1528/",
        "summary": "Forged unsigned tokens bypass authentication entirely."
    },
    "JWT Role Tampering": {
        "id":      "T1134.001",
        "name":    "Token Impersonation/Theft",
        "tactic":  "Defense Evasion / Privilege Escalation",
        "url":     "https://attack.mitre.org/techniques/T1134/001/",
        "summary": "Tampered token claims escalate attacker privileges without valid credentials."
    },
    "JWT Attacks": {
        "id":      "T1528",
        "name":    "Steal Application Access Token",
        "tactic":  "Credential Access",
        "url":     "https://attack.mitre.org/techniques/T1528/",
        "summary": "Token forgery allows impersonation of any user or role."
    },
    "BOLA/IDOR": {
        "id":      "T1083",
        "name":    "File and Directory Discovery",
        "tactic":  "Discovery",
        "url":     "https://attack.mitre.org/techniques/T1083/",
        "summary": "Enumerating resource IDs exposes data belonging to other users."
    },
    "Mass Assignment": {
        "id":      "T1548",
        "name":    "Abuse Elevation Control Mechanism",
        "tactic":  "Privilege Escalation",
        "url":     "https://attack.mitre.org/techniques/T1548/",
        "summary": "Injecting privileged fields into API bodies silently escalates account permissions."
    },
    "CORS — Evil Origin + Credentials": {
        "id":      "T1185",
        "name":    "Browser Session Hijacking",
        "tactic":  "Collection",
        "url":     "https://attack.mitre.org/techniques/T1185/",
        "summary": "Misconfigured CORS allows malicious sites to make authenticated requests on behalf of victims."
    },
    "CORS — Evil Origin Reflected": {
        "id":      "T1185",
        "name":    "Browser Session Hijacking",
        "tactic":  "Collection",
        "url":     "https://attack.mitre.org/techniques/T1185/",
        "summary": "Reflected origin enables cross-origin data reads from malicious sites."
    },
    "CORS — Wildcard + Credentials": {
        "id":      "T1185",
        "name":    "Browser Session Hijacking",
        "tactic":  "Collection",
        "url":     "https://attack.mitre.org/techniques/T1185/",
        "summary": "Wildcard CORS with credentials undermines same-origin security policy."
    },
    "Missing Header: Content-Security-Policy": {
        "id":      "T1059.007",
        "name":    "JavaScript (XSS enablement)",
        "tactic":  "Execution",
        "url":     "https://attack.mitre.org/techniques/T1059/007/",
        "summary": "Absent CSP allows injected scripts to execute without browser-level restriction."
    },
    "Missing Header: Strict-Transport-Security": {
        "id":      "T1557",
        "name":    "Adversary-in-the-Middle",
        "tactic":  "Collection",
        "url":     "https://attack.mitre.org/techniques/T1557/",
        "summary": "Missing HSTS enables protocol downgrade attacks intercepting plaintext traffic."
    },
    "Missing Header: X-Frame-Options": {
        "id":      "T1185",
        "name":    "Browser Session Hijacking",
        "tactic":  "Collection",
        "url":     "https://attack.mitre.org/techniques/T1185/",
        "summary": "Missing framing protection enables clickjacking attacks on authenticated users."
    },
    "Missing Header: X-Content-Type-Options": {
        "id":      "T1059",
        "name":    "Command and Scripting Interpreter",
        "tactic":  "Execution",
        "url":     "https://attack.mitre.org/techniques/T1059/",
        "summary": "MIME sniffing can cause browsers to execute non-script responses as scripts."
    },
    "Missing Header: Permissions-Policy": {
        "id":      "T1185",
        "name":    "Browser Session Hijacking",
        "tactic":  "Collection",
        "url":     "https://attack.mitre.org/techniques/T1185/",
        "summary": "Unrestricted browser features expose users to surveillance via camera, mic, or location."
    },
    "Missing Header: Referrer-Policy": {
        "id":      "T1040",
        "name":    "Network Sniffing",
        "tactic":  "Discovery",
        "url":     "https://attack.mitre.org/techniques/T1040/",
        "summary": "Sensitive URL fragments leak via Referer header to third-party resources."
    },
}


def get(category):
    """
    Return the MITRE entry for a given finding category.
    Falls back to a generic entry if not found.
    """
    return MITRE_MAP.get(category, {
        "id":      "N/A",
        "name":    "Not mapped",
        "tactic":  "N/A",
        "url":     "https://attack.mitre.org",
        "summary": ""
    })
