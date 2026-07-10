"""
reporter/json_report.py
Exports scan findings as structured JSON compatible with
Splunk, Microsoft Sentinel, and other SIEM ingestion pipelines.
New in v5.
"""

import os
import json
from datetime import datetime
from reporter import mitre_map

OUTPUT_PATH = os.path.expanduser("~/Desktop/lab/scan_report.json")


def generate(findings, base_url="http://localhost:3001", output_path=OUTPUT_PATH):
    """
    Serialize all findings to JSON with full MITRE and CVSS metadata.
    Format is compatible with Splunk HEC and Sentinel Analytics ingestion.
    """
    timestamp = datetime.utcnow().isoformat() + "Z"

    output = {
        "scan_metadata": {
            "tool":       "API Attack Surface Auditor v5.0",
            "timestamp":  timestamp,
            "target":     base_url,
            "total":      len(findings),
            "vulnerable": sum(1 for f in findings if f["status"] == "VULNERABLE"),
            "safe":       sum(1 for f in findings if f["status"] == "SAFE"),
        },
        "findings": []
    }

    severity_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4, None: 5}
    sorted_findings = sorted(findings, key=lambda f: severity_order.get(f.get("severity"), 5))

    for f in sorted_findings:
        mitre = mitre_map.get(f["category"])

        record = {
            "status":   f["status"],
            "category": f["category"],
            "severity": f.get("severity"),
            "owasp":    f.get("owasp", "N/A"),
            "mitre": {
                "technique_id":   mitre["id"],
                "technique_name": mitre["name"],
                "tactic":         mitre["tactic"],
                "url":            mitre["url"],
            },
            "cvss": {
                "vector": mitre.get("cvss_vector", "N/A"),
                "score":  mitre.get("cvss_score", 0.0),
            },
            "timestamp": timestamp,
        }

        if f["status"] == "VULNERABLE":
            record["detail"]   = f.get("detail", "")
            record["request"]  = f.get("request", "")
            record["response"] = f.get("response", "")

        output["findings"].append(record)

    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, "w") as fh:
        json.dump(output, fh, indent=2)

    print(f"  JSON report saved → {output_path}")
    return output_path
