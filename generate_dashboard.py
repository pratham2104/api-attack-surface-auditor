"""
generate_dashboard.py
Reads scan_report.json and generates a standalone dashboard.html
that looks like a Splunk security dashboard — charts, tables, heatmaps.
No Splunk account needed. Opens in any browser.

Run: python3 generate_dashboard.py
     (scan_report.json must be in ~/Desktop/lab/)
"""

import os
import json
from datetime import datetime

JSON_PATH      = os.path.expanduser("~/Desktop/lab/scan_report.json")
DASHBOARD_PATH = os.path.expanduser("~/Desktop/lab/dashboard.html")

SEVERITY_COLORS = {
    "Critical": "#ff4444",
    "High":     "#ff8800",
    "Medium":   "#ffcc00",
    "Low":      "#00cc66",
    "Info":     "#4488ff",
}

OWASP_SHORT = {
    "API1:2023 — Broken Object Level Authorization":          "API1 — BOLA",
    "API2:2023 — Broken Authentication":                      "API2 — Auth",
    "API3:2023 — Broken Object Property Level Authorization": "API3 — Property",
    "API4:2023 — Unrestricted Resource Consumption":          "API4 — Rate Limit",
    "API5:2023 — Broken Function Level Authorization":        "API5 — Func Auth",
    "API6:2023 — Unrestricted Access to Sensitive Business Flows": "API6 — Business",
    "API7:2023 — Server Side Request Forgery":                "API7 — SSRF",
    "API8:2023 — Security Misconfiguration":                  "API8 — Misconfig",
    "API9:2023 — Improper Inventory Management":              "API9 — Inventory",
    "API10:2023 — Unsafe Consumption of APIs":                "API10 — SQLi/Injection",
}


def load_json(path):
    with open(path) as f:
        return json.load(f)


def build_dashboard(data):
    meta     = data["scan_metadata"]
    findings = data["findings"]
    vulns    = [f for f in findings if f["status"] == "VULNERABLE"]
    safes    = [f for f in findings if f["status"] == "SAFE"]

    # Severity counts
    sev_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
    for f in vulns:
        sev = f.get("severity", "Info")
        if sev in sev_counts:
            sev_counts[sev] += 1

    # OWASP breakdown
    owasp_vuln = {}
    owasp_safe = set()
    for f in findings:
        owasp = f.get("owasp", "Unknown")
        short = OWASP_SHORT.get(owasp, owasp)
        if f["status"] == "VULNERABLE":
            owasp_vuln[short] = owasp_vuln.get(short, 0) + 1
        else:
            owasp_safe.add(short)

    # MITRE tactic breakdown
    tactic_counts = {}
    for f in vulns:
        tactic = f.get("mitre", {}).get("tactic", "Unknown")
        tactic_counts[tactic] = tactic_counts.get(tactic, 0) + 1

    # Finding rows
    sev_order = ["Critical", "High", "Medium", "Low", "Info"]
    sorted_vulns = sorted(
        vulns,
        key=lambda x: sev_order.index(x.get("severity", "Info"))
        if x.get("severity") in sev_order else 99
    )

    finding_rows = ""
    for f in sorted_vulns:
        sev   = f.get("severity", "Info")
        color = SEVERITY_COLORS.get(sev, "#888")
        mitre = f.get("mitre", {})
        cvss  = f.get("cvss", {})
        finding_rows += f"""
        <tr>
          <td><span class="sev-badge" style="background:{color};color:#000;">{sev}</span></td>
          <td class="cat">{f['category']}</td>
          <td class="mono">{mitre.get('technique_id','N/A')}</td>
          <td>{mitre.get('technique_name','N/A')}</td>
          <td class="mono">{cvss.get('score','N/A')}</td>
          <td class="detail-cell">{f.get('detail','')[:120]}...</td>
        </tr>"""

    # Chart data as JS
    sev_labels  = list(sev_counts.keys())
    sev_values  = list(sev_counts.values())
    sev_colors  = [SEVERITY_COLORS[s] for s in sev_labels]

    owasp_all_keys = list(set(list(owasp_vuln.keys()) + list(owasp_safe)))
    owasp_values   = [owasp_vuln.get(k, 0) for k in owasp_all_keys]
    owasp_colors   = ["#ff4444" if owasp_vuln.get(k, 0) > 0 else "#1a3d1a"
                      for k in owasp_all_keys]

    tactic_labels = list(tactic_counts.keys())
    tactic_values = list(tactic_counts.values())

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>API Attack Surface Auditor — Security Dashboard</title>
<script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/4.4.1/chart.umd.min.js"></script>
<style>
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
          background: #0a0a0a; color: #c9c9c9; padding: 0; }}

  /* Header */
  .dash-header {{ background: #111; border-bottom: 1px solid #222;
                  padding: 20px 28px; display: flex; align-items: center;
                  justify-content: space-between; flex-wrap: wrap; gap: 12px; }}
  .dash-title {{ font-size: 18px; font-weight: 600; color: #fff; }}
  .dash-title span {{ color: #e67e00; }}
  .dash-meta {{ font-size: 12px; color: #555; line-height: 1.8; }}

  /* Grid */
  .grid {{ display: grid; gap: 14px; padding: 20px 28px; }}
  .row-4 {{ grid-template-columns: repeat(4, 1fr); }}
  .row-3 {{ grid-template-columns: repeat(3, 1fr); }}
  .row-2 {{ grid-template-columns: repeat(2, 1fr); }}
  .row-1 {{ grid-template-columns: 1fr; }}

  /* Panels */
  .panel {{ background: #111; border: 1px solid #1e1e1e; border-radius: 8px;
             padding: 16px; }}
  .panel-title {{ font-size: 11px; font-weight: 600; color: #666; text-transform: uppercase;
                  letter-spacing: 0.08em; margin-bottom: 12px; }}

  /* KPI cards */
  .kpi {{ text-align: center; padding: 20px 16px; }}
  .kpi-num {{ font-size: 40px; font-weight: 700; line-height: 1; }}
  .kpi-label {{ font-size: 11px; color: #555; text-transform: uppercase;
                letter-spacing: 0.06em; margin-top: 6px; }}

  /* Charts */
  .chart-wrap {{ position: relative; height: 220px; }}

  /* OWASP table */
  .owasp-table {{ width: 100%; border-collapse: collapse; font-size: 12px; }}
  .owasp-table th {{ color: #555; font-size: 10px; text-transform: uppercase;
                     letter-spacing: 0.05em; padding: 6px 8px; text-align: left;
                     border-bottom: 1px solid #222; }}
  .owasp-table td {{ padding: 7px 8px; border-bottom: 1px solid #1a1a1a; }}
  .owasp-table tr:last-child td {{ border-bottom: none; }}
  .status-vuln {{ color: #ff4444; font-weight: 600; font-size: 11px; }}
  .status-safe {{ color: #00cc66; font-size: 11px; }}

  /* Findings table */
  .findings-table {{ width: 100%; border-collapse: collapse; font-size: 12px; }}
  .findings-table th {{ color: #555; font-size: 10px; text-transform: uppercase;
                        letter-spacing: 0.05em; padding: 8px 10px; text-align: left;
                        border-bottom: 1px solid #222; white-space: nowrap; }}
  .findings-table td {{ padding: 9px 10px; border-bottom: 1px solid #1a1a1a;
                        vertical-align: top; }}
  .findings-table tr:last-child td {{ border-bottom: none; }}
  .sev-badge {{ font-size: 10px; font-weight: 700; padding: 2px 8px;
                border-radius: 3px; white-space: nowrap; }}
  .cat {{ font-weight: 500; color: #ddd; }}
  .mono {{ font-family: monospace; color: #aaa; }}
  .detail-cell {{ color: #777; font-size: 11px; max-width: 300px; }}

  /* Timeline */
  .timeline {{ display: flex; flex-direction: column; gap: 8px; }}
  .tl-item {{ display: flex; align-items: center; gap: 10px; font-size: 12px; }}
  .tl-dot {{ width: 8px; height: 8px; border-radius: 50%; flex-shrink: 0; }}
  .tl-text {{ color: #aaa; }}

  /* Footer */
  .footer {{ padding: 16px 28px; font-size: 11px; color: #333;
             border-top: 1px solid #1a1a1a; margin-top: 8px; }}
</style>
</head>
<body>

<div class="dash-header">
  <div>
    <div class="dash-title">API Attack Surface Auditor <span>v6.0</span> — Security Dashboard</div>
    <div class="dash-meta" style="margin-top:6px;">
      Target: {meta['target']} &nbsp;·&nbsp;
      Scan: {datetime.fromisoformat(meta['timestamp'].replace('Z','+00:00')).strftime('%Y-%m-%d %H:%M UTC')} &nbsp;·&nbsp;
      {meta['total']} checks run
    </div>
  </div>
  <div style="font-size:11px;color:#444;text-align:right;">
    github.com/pratham2104/api-attack-surface-auditor<br>
    Pratham Agarwal — CS &amp; Data Science, CMU
  </div>
</div>

<!-- Row 1: KPI cards -->
<div class="grid row-4">
  <div class="panel kpi">
    <div class="kpi-num" style="color:#ff4444;">{meta['vulnerable']}</div>
    <div class="kpi-label">Vulnerabilities</div>
  </div>
  <div class="panel kpi">
    <div class="kpi-num" style="color:#ff4444;">{sev_counts['Critical']}</div>
    <div class="kpi-label">Critical</div>
  </div>
  <div class="panel kpi">
    <div class="kpi-num" style="color:#00cc66;">{meta['safe']}</div>
    <div class="kpi-label">Passed</div>
  </div>
  <div class="panel kpi">
    <div class="kpi-num" style="color:#888;">{meta['total']}</div>
    <div class="kpi-label">Total Checks</div>
  </div>
</div>

<!-- Row 2: Charts -->
<div class="grid row-3">
  <div class="panel">
    <div class="panel-title">Findings by severity</div>
    <div class="chart-wrap">
      <canvas id="sevChart"></canvas>
    </div>
  </div>
  <div class="panel">
    <div class="panel-title">MITRE ATT&amp;CK tactics</div>
    <div class="chart-wrap">
      <canvas id="tacticChart"></canvas>
    </div>
  </div>
  <div class="panel">
    <div class="panel-title">OWASP API Top 10 coverage</div>
    <table class="owasp-table">
      <tr><th>Category</th><th>Status</th></tr>
      {"".join(f'<tr><td>{k}</td><td class="{"status-vuln" if owasp_vuln.get(k,0) > 0 else "status-safe"}">{"VULN ("+str(owasp_vuln[k])+")" if owasp_vuln.get(k,0) > 0 else "PASS"}</td></tr>' for k in sorted(set(list(owasp_vuln.keys()) + list(owasp_safe))))}
    </table>
  </div>
</div>

<!-- Row 3: Severity bar + Timeline -->
<div class="grid row-2">
  <div class="panel">
    <div class="panel-title">OWASP coverage — vulnerability count</div>
    <div class="chart-wrap">
      <canvas id="owaspChart"></canvas>
    </div>
  </div>
  <div class="panel">
    <div class="panel-title">Findings timeline</div>
    <div class="timeline">
      {"".join(f'<div class="tl-item"><div class="tl-dot" style="background:{SEVERITY_COLORS.get(f.get("severity","Info"), "#888")};"></div><div class="tl-text"><strong style="color:{SEVERITY_COLORS.get(f.get("severity","Info"), "#888")};">[{f.get("severity","?")}]</strong> {f["category"]}</div></div>' for f in sorted_vulns)}
    </div>
  </div>
</div>

<!-- Row 4: Full findings table -->
<div class="grid row-1">
  <div class="panel">
    <div class="panel-title">Vulnerability details ({len(vulns)} findings)</div>
    <table class="findings-table">
      <tr>
        <th>Severity</th>
        <th>Category</th>
        <th>MITRE ID</th>
        <th>Technique</th>
        <th>CVSS</th>
        <th>Detail</th>
      </tr>
      {finding_rows}
    </table>
  </div>
</div>

<div class="footer">
  Generated by API Attack Surface Auditor v6.0 &nbsp;·&nbsp;
  github.com/pratham2104/api-attack-surface-auditor &nbsp;·&nbsp;
  Pratham Agarwal — Computer Science &amp; Data Science, Central Michigan University
</div>

<script>
const chartDefaults = {{
  plugins: {{ legend: {{ labels: {{ color: '#888', font: {{ size: 11 }} }} }} }},
  scales: {{ x: {{ ticks: {{ color: '#666' }}, grid: {{ color: '#1a1a1a' }} }},
             y: {{ ticks: {{ color: '#666' }}, grid: {{ color: '#1a1a1a' }} }} }}
}};

// Severity pie
new Chart(document.getElementById('sevChart'), {{
  type: 'doughnut',
  data: {{
    labels: {json.dumps(sev_labels)},
    datasets: [{{
      data: {json.dumps(sev_values)},
      backgroundColor: {json.dumps(sev_colors)},
      borderWidth: 0,
    }}]
  }},
  options: {{
    plugins: {{ legend: {{ position: 'right', labels: {{ color: '#888', font: {{ size: 11 }} }} }} }},
    cutout: '65%',
  }}
}});

// Tactic bar
new Chart(document.getElementById('tacticChart'), {{
  type: 'bar',
  data: {{
    labels: {json.dumps(tactic_labels)},
    datasets: [{{
      label: 'Findings',
      data: {json.dumps(tactic_values)},
      backgroundColor: '#e67e00',
      borderRadius: 4,
    }}]
  }},
  options: {{
    indexAxis: 'y',
    plugins: {{ legend: {{ display: false }} }},
    scales: {{
      x: {{ ticks: {{ color: '#666' }}, grid: {{ color: '#1a1a1a' }} }},
      y: {{ ticks: {{ color: '#888', font: {{ size: 11 }} }}, grid: {{ color: '#1a1a1a' }} }}
    }}
  }}
}});

// OWASP bar
new Chart(document.getElementById('owaspChart'), {{
  type: 'bar',
  data: {{
    labels: {json.dumps(owasp_all_keys)},
    datasets: [{{
      label: 'Vulnerabilities',
      data: {json.dumps(owasp_values)},
      backgroundColor: {json.dumps(owasp_colors)},
      borderRadius: 4,
    }}]
  }},
  options: {{
    plugins: {{ legend: {{ display: false }} }},
    scales: {{
      x: {{ ticks: {{ color: '#666', font: {{ size: 10 }} }}, grid: {{ color: '#1a1a1a' }} }},
      y: {{ ticks: {{ color: '#666' }}, grid: {{ color: '#1a1a1a' }} }}
    }}
  }}
}});
</script>
</body>
</html>"""

    with open(DASHBOARD_PATH, "w") as f:
        f.write(html)

    print(f"Dashboard saved → {DASHBOARD_PATH}")
    print("Open in any browser.")


if __name__ == "__main__":
    if not os.path.exists(JSON_PATH):
        print(f"scan_report.json not found at {JSON_PATH}")
        print("Run the scanner first: python3 main.py --format all")
        exit(1)

    data = load_json(JSON_PATH)
    build_dashboard(data)
