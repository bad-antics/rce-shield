"""
Multi-format report generator for RCE Shield findings.
"""

import csv
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from jinja2 import Template

from rce_shield.core.scanner import Finding, Severity


class ReportGenerator:
    """Generate security reports in multiple formats."""

    def __init__(self, findings: list[Finding]):
        self.findings = sorted(findings, key=lambda f: f.severity.sort_key())
        self.generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    def _severity_counts(self) -> dict[str, int]:
        counts = {s.value: 0 for s in Severity}
        for f in self.findings:
            counts[f.severity.value] += 1
        return counts

    def _risk_score(self) -> int:
        c = self._severity_counts()
        return (
            c["CRITICAL"] * 40
            + c["HIGH"] * 25
            + c["MEDIUM"] * 10
            + c["LOW"] * 3
        )

    def _risk_rating(self) -> str:
        score = self._risk_score()
        if score > 150:
            return "CRITICAL"
        if score > 80:
            return "HIGH"
        if score > 30:
            return "MEDIUM"
        return "LOW"

    # ── JSON ───────────────────────────────────────────────────────────
    def generate_json(self, path: str) -> None:
        data = {
            "meta": {
                "tool": "RCE Shield",
                "version": "1.0.0",
                "generated_at": self.generated_at,
                "total_findings": len(self.findings),
                "risk_score": self._risk_score(),
                "risk_rating": self._risk_rating(),
                "severity_counts": self._severity_counts(),
            },
            "findings": [f.to_dict() for f in self.findings],
        }
        Path(path).write_text(json.dumps(data, indent=2))

    # ── CSV ────────────────────────────────────────────────────────────
    def generate_csv(self, path: str) -> None:
        with open(path, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow([
                "Severity", "Category", "Target", "Description",
                "Evidence", "Remediation", "CVE", "CVSS",
            ])
            for finding in self.findings:
                writer.writerow([
                    finding.severity.value,
                    finding.category,
                    finding.target,
                    finding.description,
                    finding.evidence,
                    finding.remediation,
                    finding.cve or "",
                    finding.cvss or "",
                ])

    # ── HTML ───────────────────────────────────────────────────────────
    def generate_html(self, path: str) -> None:
        counts = self._severity_counts()
        risk_rating = self._risk_rating()
        risk_score = self._risk_score()

        risk_colors = {
            "CRITICAL": "#ef4444",
            "HIGH": "#f97316",
            "MEDIUM": "#eab308",
            "LOW": "#22c55e",
        }

        html = HTML_TEMPLATE.render(
            generated_at=self.generated_at,
            findings=self.findings,
            counts=counts,
            total=len(self.findings),
            risk_rating=risk_rating,
            risk_score=risk_score,
            risk_color=risk_colors.get(risk_rating, "#22c55e"),
        )
        Path(path).write_text(html)


HTML_TEMPLATE = Template("""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>RCE Shield — Security Report</title>
<style>
:root {
    --bg: #0a0e17; --card: #111827; --accent: #8b5cf6;
    --red: #ef4444; --org: #f97316; --yel: #eab308; --grn: #22c55e;
    --txt: #e0e0e0;
}
* { margin: 0; padding: 0; box-sizing: border-box; }
body { background: var(--bg); color: var(--txt); font-family: 'Segoe UI', system-ui, sans-serif; padding: 24px; }
h1 { color: var(--accent); font-size: 28px; margin-bottom: 4px; }
h2 { color: var(--accent); font-size: 20px; margin: 32px 0 12px; }
.meta { color: #888; margin-bottom: 24px; font-size: 14px; }
.risk-box { background: var(--card); border-radius: 12px; padding: 24px; text-align: center;
    margin-bottom: 32px; border: 2px solid {{ risk_color }}; }
.risk-label { font-size: 48px; font-weight: 800; color: {{ risk_color }}; }
.risk-sub { color: #888; font-size: 14px; margin-top: 4px; }
.grid { display: grid; grid-template-columns: repeat(5, 1fr); gap: 12px; margin-bottom: 32px; }
.card { background: var(--card); border-radius: 12px; padding: 18px; text-align: center; border: 1px solid #222; }
.card .n { font-size: 36px; font-weight: 700; }
.card .l { font-size: 12px; color: #888; margin-top: 4px; }
.c-crit .n { color: var(--red); } .c-high .n { color: var(--org); }
.c-med .n { color: var(--yel); } .c-low .n { color: var(--grn); }
.c-info .n { color: #888; }
table { width: 100%; border-collapse: collapse; background: var(--card);
    border-radius: 12px; overflow: hidden; margin-bottom: 24px; }
th { background: #1a2332; color: var(--accent); padding: 12px 16px;
    text-align: left; font-size: 12px; text-transform: uppercase; }
td { padding: 10px 16px; border-bottom: 1px solid #1a1a2e; font-size: 13px; }
.sev-CRITICAL { color: var(--red); font-weight: bold; }
.sev-HIGH { color: var(--org); font-weight: bold; }
.sev-MEDIUM { color: var(--yel); }
.sev-LOW { color: var(--grn); }
.sev-INFO { color: #888; }
.footer { margin-top: 32px; text-align: center; color: #555; font-size: 12px; }
</style>
</head>
<body>

<h1>🛡️ RCE Shield — Security Report</h1>
<div class="meta">Generated: {{ generated_at }} | Total Findings: {{ total }}</div>

<div class="risk-box">
    <div class="risk-label">{{ risk_rating }}</div>
    <div class="risk-sub">Overall Risk Assessment (Score: {{ risk_score }})</div>
</div>

<div class="grid">
    <div class="card c-crit"><div class="n">{{ counts.CRITICAL }}</div><div class="l">Critical</div></div>
    <div class="card c-high"><div class="n">{{ counts.HIGH }}</div><div class="l">High</div></div>
    <div class="card c-med"><div class="n">{{ counts.MEDIUM }}</div><div class="l">Medium</div></div>
    <div class="card c-low"><div class="n">{{ counts.LOW }}</div><div class="l">Low</div></div>
    <div class="card c-info"><div class="n">{{ counts.INFO }}</div><div class="l">Info</div></div>
</div>

<h2>🔍 Detailed Findings</h2>
<table>
<thead>
<tr><th>#</th><th>Severity</th><th>Category</th><th>Target</th><th>Finding</th><th>CVE</th><th>Remediation</th></tr>
</thead>
<tbody>
{% for f in findings %}
<tr>
    <td>{{ loop.index }}</td>
    <td class="sev-{{ f.severity.value }}">{{ f.severity.value }}</td>
    <td>{{ f.category }}</td>
    <td>{{ f.target }}</td>
    <td>{{ f.description }}</td>
    <td>{{ f.cve or '' }}</td>
    <td>{{ f.remediation }}</td>
</tr>
{% endfor %}
</tbody>
</table>

<div class="footer">RCE Shield v1.0.0 — NullSec — For authorized use only</div>
</body>
</html>""")
