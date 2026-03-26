"""
Reporting Agent — PDF/Executive Report Generation

Capabilities:
  - Executive summary reports (PDF-ready HTML)
  - Per-account vulnerability reports
  - Compliance posture reports (NIST, CIS)
  - Remediation activity reports
  - Trend analysis over time
  - Board-level risk dashboards
"""

import json
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


@dataclass
class ReportConfig:
    company_name: str = "Enterprise Corp"
    report_title: str = "Windows Vulnerability Management Report"
    logo_url: str = ""
    include_executive_summary: bool = True
    include_vulnerability_details: bool = True
    include_compliance_section: bool = True
    include_remediation_history: bool = True
    include_trend_analysis: bool = True
    include_recommendations: bool = True


class ReportingAgent:
    """
    Agent 9: Executive and technical report generation.

    Produces HTML reports that can be converted to PDF via browser print
    or wkhtmltopdf. Designed for board presentations and audit submissions.
    """

    def __init__(self, config: ReportConfig = None):
        self.config = config or ReportConfig()

    def generate_executive_report(
        self,
        accounts: list,
        servers: list,
        decisions: list,
        pipeline_summary: Dict,
        compliance_data: Dict = None,
    ) -> str:
        """Generate full executive report as HTML."""

        total_servers = len(servers)
        total_accounts = len(accounts)
        total_critical = sum(getattr(s, 'critical_vulns', 0) for s in servers)
        total_high = sum(getattr(s, 'high_vulns', 0) for s in servers)
        avg_compliance = round(sum(getattr(s, 'patch_compliance', 0) for s in servers) / max(total_servers, 1) * 100, 1)

        auto_count = pipeline_summary.get('auto_remediated', 0)
        pending_count = pipeline_summary.get('pending_approval', 0)
        chg_count = pipeline_summary.get('chg_tickets', 0)
        total_decisions = pipeline_summary.get('total', 0)
        avg_confidence = pipeline_summary.get('avg_confidence', 0)

        now = datetime.now()

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>{self.config.report_title}</title>
<style>
    @page {{ margin: 1in; size: A4; }}
    body {{ font-family: 'Segoe UI', Tahoma, sans-serif; color: #1a1a2e; margin: 0; padding: 2rem; background: white; }}
    .header {{ background: linear-gradient(135deg, #0a0a23, #0f3460); color: white; padding: 2rem; border-radius: 12px; margin-bottom: 2rem; }}
    .header h1 {{ margin: 0; font-size: 1.8rem; }}
    .header p {{ margin: 0.3rem 0 0; color: #a8b2d1; }}
    .meta {{ display: flex; gap: 2rem; margin-top: 1rem; font-size: 0.85rem; color: #ccc; }}
    .section {{ margin: 2rem 0; }}
    .section h2 {{ color: #0f3460; border-bottom: 2px solid #0f3460; padding-bottom: 0.5rem; }}
    .metrics {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 1rem; margin: 1rem 0; }}
    .metric-card {{ background: #f8f9fa; border-radius: 8px; padding: 1.2rem; text-align: center; border-left: 4px solid #0f3460; }}
    .metric-card .value {{ font-size: 2rem; font-weight: 700; color: #0f3460; }}
    .metric-card .label {{ font-size: 0.8rem; color: #666; text-transform: uppercase; letter-spacing: 1px; }}
    .metric-critical {{ border-left-color: #dc3545; }}
    .metric-critical .value {{ color: #dc3545; }}
    .metric-success {{ border-left-color: #28a745; }}
    .metric-success .value {{ color: #28a745; }}
    .metric-warning {{ border-left-color: #ffc107; }}
    .metric-warning .value {{ color: #856404; }}
    table {{ width: 100%; border-collapse: collapse; margin: 1rem 0; font-size: 0.85rem; }}
    th {{ background: #0f3460; color: white; padding: 0.7rem; text-align: left; }}
    td {{ padding: 0.6rem 0.7rem; border-bottom: 1px solid #e0e0e0; }}
    tr:nth-child(even) {{ background: #f8f9fa; }}
    .risk-critical {{ color: #dc3545; font-weight: 700; }}
    .risk-high {{ color: #fd7e14; font-weight: 700; }}
    .risk-medium {{ color: #ffc107; font-weight: 600; }}
    .pipeline-flow {{ background: #f0f4ff; padding: 1.5rem; border-radius: 8px; font-family: monospace; font-size: 0.85rem; }}
    .footer {{ margin-top: 3rem; padding-top: 1rem; border-top: 1px solid #ddd; font-size: 0.75rem; color: #999; text-align: center; }}
    .recommendation {{ background: #fff3cd; border-left: 4px solid #ffc107; padding: 1rem; margin: 0.5rem 0; border-radius: 0 8px 8px 0; }}
    .recommendation.critical {{ background: #f8d7da; border-left-color: #dc3545; }}
</style>
</head>
<body>

<div class="header">
    <h1>{self.config.report_title}</h1>
    <p>{self.config.company_name} — Agentic AI Security Platform</p>
    <div class="meta">
        <span>Generated: {now.strftime('%B %d, %Y %H:%M')}</span>
        <span>Period: {(now - timedelta(days=7)).strftime('%b %d')} — {now.strftime('%b %d, %Y')}</span>
        <span>Classification: CONFIDENTIAL</span>
    </div>
</div>

<div class="section">
    <h2>Executive Summary</h2>
    <p>This report provides an overview of the Windows Server vulnerability posture across
    <strong>{total_accounts} AWS accounts</strong> managing <strong>{total_servers} Windows servers</strong>.
    The Agentic AI pipeline processed <strong>{total_decisions} vulnerabilities</strong> with an average
    confidence score of <strong>{avg_confidence:.0%}</strong>.</p>

    <div class="metrics">
        <div class="metric-card">
            <div class="value">{total_accounts}</div>
            <div class="label">AWS Accounts</div>
        </div>
        <div class="metric-card">
            <div class="value">{total_servers}</div>
            <div class="label">Windows Servers</div>
        </div>
        <div class="metric-card metric-critical">
            <div class="value">{total_critical}</div>
            <div class="label">Critical Vulns</div>
        </div>
        <div class="metric-card metric-warning">
            <div class="value">{total_high}</div>
            <div class="label">High Vulns</div>
        </div>
    </div>

    <div class="metrics">
        <div class="metric-card metric-success">
            <div class="value">{auto_count}</div>
            <div class="label">Auto-Remediated</div>
        </div>
        <div class="metric-card metric-warning">
            <div class="value">{pending_count}</div>
            <div class="label">Pending Approval</div>
        </div>
        <div class="metric-card">
            <div class="value">{chg_count}</div>
            <div class="label">CHG Tickets</div>
        </div>
        <div class="metric-card metric-success">
            <div class="value">{avg_compliance}%</div>
            <div class="label">Avg Compliance</div>
        </div>
    </div>
</div>

<div class="section">
    <h2>AI Pipeline Performance</h2>
    <div class="pipeline-flow">
Discovery → Analysis → Decision Engine → [Auto-Remediate | Human Approve | CHG Ticket] → Verification

Auto-Remediate:  {auto_count} vulnerabilities (confidence >= 90%)
Human Approve:   {pending_count} vulnerabilities (confidence 70-89%)
CHG Tickets:     {chg_count} vulnerabilities (confidence &lt; 70%)
Average Confidence: {avg_confidence:.0%}
    </div>
</div>

<div class="section">
    <h2>Account Vulnerability Posture</h2>
    <table>
        <tr><th>Account</th><th>ID</th><th>OU</th><th>Servers</th><th>Critical</th><th>High</th><th>Last Scan</th></tr>
"""

        for a in accounts:
            html += f"""        <tr>
            <td>{getattr(a, 'account_name', 'N/A')}</td>
            <td>{getattr(a, 'account_id', 'N/A')}</td>
            <td>{getattr(a, 'ou_path', 'N/A')}</td>
            <td>{getattr(a, 'server_count', 0)}</td>
            <td class="risk-critical">{getattr(a, 'critical_vulns', 0)}</td>
            <td class="risk-high">{getattr(a, 'high_vulns', 0)}</td>
            <td>{getattr(a, 'last_scan', 'Never')}</td>
        </tr>
"""

        html += """    </table>
</div>

<div class="section">
    <h2>Pipeline Decisions</h2>
    <table>
        <tr><th>CVE</th><th>Action</th><th>Confidence</th><th>Risk</th><th>NIST</th><th>ITSM Ticket</th></tr>
"""

        for d in decisions:
            action_class = ""
            if d.action == "AUTO_REMEDIATE":
                action_class = "risk-medium"
            elif d.action == "HUMAN_APPROVE":
                action_class = "risk-high"
            elif d.action == "RAISE_CHG":
                action_class = "risk-critical"

            html += f"""        <tr>
            <td>{d.vulnerability_id}</td>
            <td class="{action_class}">{d.action.replace('_', ' ').title()}</td>
            <td>{d.confidence_score:.0%}</td>
            <td>{d.risk_score:.0%}</td>
            <td>{', '.join(d.nist_controls)}</td>
            <td>{d.itsm_ticket_id or '—'}</td>
        </tr>
"""

        html += """    </table>
</div>

<div class="section">
    <h2>Recommendations</h2>
    <div class="recommendation critical">
        <strong>Priority 1:</strong> Address all CRITICAL vulnerabilities within 24 hours.
        Ensure auto-remediation pipeline has SSM connectivity to all production servers.
    </div>
    <div class="recommendation">
        <strong>Priority 2:</strong> Review and approve pending items in the Human Approval Queue
        within 48 hours to prevent SLA breaches.
    </div>
    <div class="recommendation">
        <strong>Priority 3:</strong> Ensure ServiceNow CHG tickets are assigned and scheduled
        within the next maintenance window.
    </div>
</div>

<div class="footer">
    <p>Generated by VulnShield AI — Agentic Windows Vulnerability Management Platform</p>
    <p>CONFIDENTIAL — For authorized personnel only</p>
</div>

</body>
</html>"""

        return html

    def generate_compliance_report(self, nist_data: Dict, cis_data: Dict, servers: list) -> str:
        """Generate NIST/CIS compliance-focused report."""
        compliant = sum(1 for s in servers if getattr(s, 'patch_compliance', 0) >= 0.9)
        total = len(servers)

        html = f"""<div class="section">
<h2>Compliance Status Report</h2>
<p>Compliant Servers (>=90%): <strong>{compliant}/{total}</strong></p>

<h3>NIST SP 800-53 Controls</h3>
<table>
<tr><th>Control</th><th>Name</th><th>Registry Fixes</th><th>Confidence</th><th>Auto-Fix</th></tr>
"""
        for cid, info in nist_data.items():
            html += f"""<tr>
<td>{cid}</td><td>{info['name']}</td>
<td>{len(info.get('registry_fixes', []))}</td>
<td>{info.get('confidence', 0):.0%}</td>
<td>{'Yes' if info.get('auto_remediate') else 'No'}</td>
</tr>"""

        html += "</table></div>"
        return html
