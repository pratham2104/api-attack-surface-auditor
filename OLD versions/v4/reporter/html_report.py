"""
reporter/html_report.py
Generates a self-contained HTML security report from scanner findings.
Styled like a real pentest deliverable — severity color coding, MITRE ATT&CK
technique IDs, CVSS-style severity badges, OWASP categories, remediation notes.
Output is a single .html file with no external dependencies.
"""

import os
from datetime import datetime
from reporter import mitre_map

SEVERITY_COLORS = {
    "Critical": {"bg": "#4a0000", "border": "#ff4444", "badge": "#ff4444", "text": "#ff9999"},
    "High":     {"bg": "#3d1a00", "border": "#ff8800", "badge": "#ff8800", "text": "#ffcc88"},
    "Medium":   {"bg": "#3d3100", "border": "#ffcc00", "badge": "#ffcc00", "text": "#ffe566"},
    "Low":      {"bg": "#003d1a", "border": "#00cc66", "badge": "#00cc66", "text": "#66ffaa"},
    "Info":     {"bg": "#001a3d", "border": "#4488ff", "badge": "#4488ff", "text": "#88bbff"},
}

CVSS_SCORES = {
    "Critical": "9.0 — 10.0",
    "High":     "7.0 — 8.9",
    "Medium":   "4.0 — 6.9",
    "Low":      "0.1 — 3.9",
    "Info":     "0.0",
}

OUTPUT_PATH = os.path.expanduser("~/Desktop/lab/scan_report.html")


def _severity_order(finding):
    order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4, None: 5}
    return order.get(finding.get("severity"), 5)


def _finding_card(finding, index):
    if finding["status"] == "SAFE":
        return f"""
        <div class="card safe">
            <div class="card-header">
                <span class="badge safe-badge">SAFE</span>
                <span class="card-title">{finding['category']}</span>
                <span class="owasp-tag">{finding.get('owasp', '')}</span>
            </div>
        </div>"""

    sev = finding.get("severity", "Info")
    colors = SEVERITY_COLORS.get(sev, SEVERITY_COLORS["Info"])
    mitre = mitre_map.get(finding["category"])

    return f"""
    <div class="card vuln" style="border-color:{colors['border']};background:{colors['bg']};">
        <div class="card-header" onclick="toggleCard({index})">
            <span class="badge" style="background:{colors['badge']};color:#000;">{sev.upper()}</span>
            <span class="card-title" style="color:{colors['text']};">{finding['category']}</span>
            <span class="cvss-score">CVSS {CVSS_SCORES.get(sev, 'N/A')}</span>
            <span class="chevron" id="chev-{index}">▼</span>
        </div>
        <div class="card-body" id="body-{index}">
            <div class="meta-row">
                <div class="meta-item">
                    <span class="meta-label">OWASP</span>
                    <span class="meta-value">{finding.get('owasp', 'N/A')}</span>
                </div>
                <div class="meta-item">
                    <span class="meta-label">MITRE ATT&CK</span>
                    <a class="meta-value mitre-link" href="{mitre['url']}" target="_blank">
                        {mitre['id']} — {mitre['name']}
                    </a>
                </div>
                <div class="meta-item">
                    <span class="meta-label">Tactic</span>
                    <span class="meta-value">{mitre['tactic']}</span>
                </div>
            </div>
            <div class="detail-section">
                <div class="detail-label">Detail</div>
                <div class="detail-value">{finding.get('detail', '')}</div>
            </div>
            <div class="detail-section">
                <div class="detail-label">Request</div>
                <pre class="code-block">{finding.get('request', '')}</pre>
            </div>
            <div class="detail-section">
                <div class="detail-label">Response</div>
                <pre class="code-block">{finding.get('response', '')}</pre>
            </div>
            <div class="detail-section mitre-summary">
                <div class="detail-label">ATT&CK context</div>
                <div class="detail-value">{mitre['summary']}</div>
            </div>
        </div>
    </div>"""


def generate(findings, base_url="http://localhost:3001", output_path=OUTPUT_PATH):
    vulns  = sorted([f for f in findings if f["status"] == "VULNERABLE"], key=_severity_order)
    safes  = [f for f in findings if f["status"] == "SAFE"]
    total  = len(findings)
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    counts = {sev: 0 for sev in SEVERITY_COLORS}
    for f in vulns:
        sev = f.get("severity", "Info")
        if sev in counts:
            counts[sev] += 1

    summary_cards = "".join([
        f"""<div class="summary-card" style="border-color:{SEVERITY_COLORS[sev]['border']};">
                <div class="summary-count" style="color:{SEVERITY_COLORS[sev]['badge']};">{counts[sev]}</div>
                <div class="summary-label">{sev}</div>
            </div>"""
        for sev in ["Critical", "High", "Medium", "Low", "Info"]
    ])

    finding_cards = "\n".join([_finding_card(f, i) for i, f in enumerate(vulns)])
    safe_cards    = "\n".join([_finding_card(f, i + len(vulns)) for i, f in enumerate(safes)])

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>API Attack Surface Auditor — Scan Report</title>
<style>
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', monospace; background: #0d0d0d; color: #c9c9c9; padding: 2rem; }}
  a {{ color: inherit; }}

  .report-header {{ border-bottom: 1px solid #333; padding-bottom: 1.5rem; margin-bottom: 2rem; }}
  .report-title {{ font-size: 22px; font-weight: 600; color: #fff; margin-bottom: 4px; }}
  .report-meta {{ font-size: 13px; color: #666; }}
  .report-meta span {{ margin-right: 24px; }}

  .summary-row {{ display: flex; gap: 12px; margin-bottom: 2rem; flex-wrap: wrap; }}
  .summary-card {{ flex: 1; min-width: 80px; border: 1px solid; border-radius: 8px; padding: 14px; text-align: center; background: #111; }}
  .summary-count {{ font-size: 28px; font-weight: 700; }}
  .summary-label {{ font-size: 11px; color: #888; margin-top: 4px; text-transform: uppercase; letter-spacing: 0.05em; }}

  .section-title {{ font-size: 13px; font-weight: 600; color: #888; text-transform: uppercase; letter-spacing: 0.08em; margin-bottom: 12px; margin-top: 2rem; }}

  .card {{ border: 1px solid #333; border-radius: 10px; margin-bottom: 10px; overflow: hidden; }}
  .card-header {{ display: flex; align-items: center; gap: 12px; padding: 14px 16px; cursor: pointer; flex-wrap: wrap; }}
  .card-title {{ font-size: 15px; font-weight: 500; color: #fff; flex: 1; }}
  .badge {{ font-size: 11px; font-weight: 700; padding: 3px 10px; border-radius: 4px; letter-spacing: 0.05em; flex-shrink: 0; }}
  .safe-badge {{ background: #1a3d1a; color: #66ff88; border: 1px solid #00cc44; }}
  .owasp-tag {{ font-size: 11px; color: #555; }}
  .cvss-score {{ font-size: 11px; color: #888; flex-shrink: 0; }}
  .chevron {{ font-size: 12px; color: #666; transition: transform 0.2s; flex-shrink: 0; }}
  .chevron.open {{ transform: rotate(180deg); }}

  .card-body {{ display: none; padding: 0 16px 16px; border-top: 1px solid #222; }}
  .card-body.open {{ display: block; }}

  .meta-row {{ display: flex; gap: 24px; flex-wrap: wrap; padding: 14px 0 10px; border-bottom: 1px solid #1a1a1a; margin-bottom: 14px; }}
  .meta-item {{ display: flex; flex-direction: column; gap: 3px; }}
  .meta-label {{ font-size: 10px; color: #555; text-transform: uppercase; letter-spacing: 0.06em; }}
  .meta-value {{ font-size: 13px; color: #ccc; }}
  .mitre-link {{ color: #4488ff; text-decoration: none; }}
  .mitre-link:hover {{ text-decoration: underline; }}

  .detail-section {{ margin-bottom: 12px; }}
  .detail-label {{ font-size: 10px; color: #555; text-transform: uppercase; letter-spacing: 0.06em; margin-bottom: 6px; }}
  .detail-value {{ font-size: 13px; color: #bbb; line-height: 1.6; }}
  .code-block {{ font-family: monospace; font-size: 12px; background: #0a0a0a; border: 1px solid #222; border-radius: 6px; padding: 10px 12px; color: #aaa; white-space: pre-wrap; word-break: break-all; line-height: 1.5; }}
  .mitre-summary {{ background: #111; border-left: 3px solid #333; border-radius: 0 6px 6px 0; padding: 10px 14px; }}

  .safe.card {{ background: #0a0f0a; border-color: #1a3d1a; }}
  .safe .card-header {{ cursor: default; }}

  .footer {{ margin-top: 3rem; padding-top: 1rem; border-top: 1px solid #222; font-size: 12px; color: #444; }}
</style>
</head>
<body>

<div class="report-header">
  <div class="report-title">API Attack Surface Auditor — Scan Report</div>
  <div class="report-meta">
    <span>Target: {base_url}</span>
    <span>Generated: {timestamp}</span>
    <span>Vulnerabilities: {len(vulns)}</span>
    <span>Passed: {len(safes)}</span>
    <span>Total checks: {total}</span>
  </div>
</div>

<div class="summary-row">
  {summary_cards}
</div>

<div class="section-title">Vulnerabilities</div>
{finding_cards if finding_cards else '<div style="color:#555;font-size:13px;padding:12px 0;">No vulnerabilities found.</div>'}

<div class="section-title">Passed checks</div>
{safe_cards}

<div class="footer">
  Generated by API Attack Surface Auditor · github.com/pratham2104/api-attack-surface-auditor ·
  Pratham Agarwal — Computer Science & Data Science, Central Michigan University
</div>

<script>
function toggleCard(i) {{
  const body = document.getElementById('body-' + i);
  const chev = document.getElementById('chev-' + i);
  body.classList.toggle('open');
  chev.classList.toggle('open');
}}
</script>
</body>
</html>"""

    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, "w") as f:
        f.write(html)

    print(f"\n  HTML report saved → {output_path}")
    print("  Open in any browser to view.\n")
    return output_path
