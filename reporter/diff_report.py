"""
reporter/diff_report.py
Compares two scan JSON outputs and generates a delta report.
Shows: new findings, fixed findings, unchanged findings.
Mirrors what a SOC analyst does after a patch cycle.
New in v5.

Usage (from main.py):
  python3 main.py --diff ~/Desktop/lab/previous_scan.json
"""

import os
import json
from datetime import datetime

OUTPUT_PATH = os.path.expanduser("~/Desktop/lab/diff_report.html")

SEVERITY_COLORS = {
    "Critical": "#ff4444",
    "High":     "#ff8800",
    "Medium":   "#ffcc00",
    "Low":      "#00cc66",
    "Info":     "#4488ff",
    None:       "#888888",
}


def load_scan(path):
    """Load a previous scan JSON file and return its findings list."""
    with open(path, "r") as f:
        data = json.load(f)
    return data.get("findings", [])


def _finding_key(finding):
    """Unique key per finding for comparison."""
    return (finding["category"], finding["status"])


def compare(current_findings, previous_path):
    """
    Compare current findings against a previous scan JSON.
    Returns three lists: new, fixed, unchanged.
    """
    try:
        previous_findings = load_scan(previous_path)
    except Exception as e:
        print(f"  Could not load previous scan: {e}")
        return [], [], current_findings

    current_keys  = {_finding_key(f) for f in current_findings}
    previous_keys = {_finding_key(f) for f in previous_findings}

    new_keys     = current_keys  - previous_keys
    fixed_keys   = previous_keys - current_keys
    shared_keys  = current_keys  & previous_keys

    new_findings     = [f for f in current_findings  if _finding_key(f) in new_keys]
    fixed_findings   = [f for f in previous_findings if _finding_key(f) in fixed_keys]
    unchanged_findings = [f for f in current_findings if _finding_key(f) in shared_keys]

    return new_findings, fixed_findings, unchanged_findings


def _finding_row(f, row_class):
    sev   = f.get("severity", "")
    color = SEVERITY_COLORS.get(sev, "#888")
    detail = f.get("detail", "")

    return f"""
    <tr class="{row_class}">
        <td><span class="sev-badge" style="background:{color};color:#000;">{sev or "SAFE"}</span></td>
        <td>{f['category']}</td>
        <td>{f.get('owasp','N/A')}</td>
        <td class="detail">{detail}</td>
    </tr>"""


def generate(current_findings, previous_path, output_path=OUTPUT_PATH):
    new_f, fixed_f, unchanged_f = compare(current_findings, previous_path)
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    new_rows       = "".join(_finding_row(f, "new-row")       for f in new_f)
    fixed_rows     = "".join(_finding_row(f, "fixed-row")     for f in fixed_f)
    unchanged_rows = "".join(_finding_row(f, "unchanged-row") for f in unchanged_f)

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Scan Delta Report</title>
<style>
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', monospace;
          background: #0d0d0d; color: #c9c9c9; padding: 2rem; }}
  h1 {{ font-size: 20px; color: #fff; margin-bottom: 4px; }}
  .meta {{ font-size: 13px; color: #555; margin-bottom: 2rem; }}
  .summary {{ display: flex; gap: 16px; margin-bottom: 2rem; }}
  .summary-card {{ border-radius: 8px; padding: 14px 20px; text-align: center; min-width: 100px; }}
  .summary-card .num {{ font-size: 28px; font-weight: 700; }}
  .summary-card .lbl {{ font-size: 11px; color: #888; text-transform: uppercase; margin-top: 4px; }}
  .new-card     {{ background: #2a0a0a; border: 1px solid #ff4444; }}
  .fixed-card   {{ background: #0a2a0a; border: 1px solid #00cc66; }}
  .unchanged-card {{ background: #111; border: 1px solid #333; }}
  .section-title {{ font-size: 13px; font-weight: 600; color: #888; text-transform: uppercase;
                    letter-spacing: 0.08em; margin: 1.5rem 0 0.75rem; }}
  table {{ width: 100%; border-collapse: collapse; font-size: 13px; }}
  th {{ text-align: left; padding: 8px 12px; color: #555; font-size: 11px;
        text-transform: uppercase; letter-spacing: 0.05em; border-bottom: 1px solid #222; }}
  td {{ padding: 10px 12px; border-bottom: 1px solid #1a1a1a; vertical-align: top; }}
  .new-row td {{ background: #1a0505; }}
  .fixed-row td {{ background: #051a05; }}
  .unchanged-row td {{ background: #0d0d0d; }}
  .sev-badge {{ font-size: 11px; font-weight: 700; padding: 2px 8px; border-radius: 4px; white-space: nowrap; }}
  .detail {{ color: #888; font-size: 12px; }}
  .empty {{ color: #555; font-size: 13px; padding: 12px 0; }}
  .footer {{ margin-top: 3rem; font-size: 12px; color: #333; border-top: 1px solid #1a1a1a; padding-top: 1rem; }}
</style>
</head>
<body>

<h1>Scan Delta Report</h1>
<div class="meta">Generated: {timestamp} · Compared against: {os.path.basename(previous_path)}</div>

<div class="summary">
  <div class="summary-card new-card">
    <div class="num" style="color:#ff4444;">{len(new_f)}</div>
    <div class="lbl">New</div>
  </div>
  <div class="summary-card fixed-card">
    <div class="num" style="color:#00cc66;">{len(fixed_f)}</div>
    <div class="lbl">Fixed</div>
  </div>
  <div class="summary-card unchanged-card">
    <div class="num" style="color:#888;">{len(unchanged_f)}</div>
    <div class="lbl">Unchanged</div>
  </div>
</div>

<div class="section-title">New findings ({len(new_f)})</div>
{"<table><tr><th>Severity</th><th>Category</th><th>OWASP</th><th>Detail</th></tr>" + new_rows + "</table>" if new_f else '<div class="empty">No new findings.</div>'}

<div class="section-title">Fixed findings ({len(fixed_f)})</div>
{"<table><tr><th>Severity</th><th>Category</th><th>OWASP</th><th>Detail</th></tr>" + fixed_rows + "</table>" if fixed_f else '<div class="empty">No findings were fixed.</div>'}

<div class="section-title">Unchanged ({len(unchanged_f)})</div>
{"<table><tr><th>Severity</th><th>Category</th><th>OWASP</th><th>Detail</th></tr>" + unchanged_rows + "</table>" if unchanged_f else '<div class="empty">No unchanged findings.</div>'}

<div class="footer">
  Generated by API Attack Surface Auditor v5.0 ·
  github.com/pratham2104/api-attack-surface-auditor
</div>
</body>
</html>"""

    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, "w") as f:
        f.write(html)

    print(f"  Diff report saved → {output_path}")
    print(f"  New: {len(new_f)}  Fixed: {len(fixed_f)}  Unchanged: {len(unchanged_f)}")
    return output_path
