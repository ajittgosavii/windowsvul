"""
Notification Agent — Slack, Microsoft Teams, Email alerts

Capabilities:
  - Send real-time alerts for critical vulnerabilities
  - Pipeline status notifications (auto-remediated, pending approval, CHG created)
  - Rollback alerts
  - Daily/weekly summary digests
  - Configurable channels per severity level
"""

import json
import logging
from datetime import datetime
from typing import Dict, List, Optional
from dataclasses import dataclass, field
from enum import Enum

logger = logging.getLogger(__name__)


class NotificationChannel(Enum):
    SLACK = "slack"
    TEAMS = "teams"
    EMAIL = "email"


class NotificationPriority(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class NotificationConfig:
    """Configuration for notification channels."""
    # Slack
    slack_webhook_url: str = ""
    slack_channel: str = "#security-alerts"
    slack_enabled: bool = False

    # Microsoft Teams
    teams_webhook_url: str = ""
    teams_enabled: bool = False

    # Email (SMTP)
    smtp_server: str = ""
    smtp_port: int = 587
    smtp_username: str = ""
    smtp_password: str = ""
    smtp_from: str = "vulnshield@enterprise.com"
    email_recipients: List[str] = field(default_factory=lambda: ["security-team@enterprise.com"])
    email_enabled: bool = False

    # Routing rules: severity → channels
    routing: Dict[str, List[str]] = field(default_factory=lambda: {
        "critical": ["slack", "teams", "email"],
        "high": ["slack", "teams"],
        "medium": ["slack"],
        "low": [],
        "info": [],
    })


@dataclass
class NotificationRecord:
    notification_id: str
    channel: str
    priority: str
    subject: str
    message: str
    status: str = "SENT"
    timestamp: str = ""
    metadata: Dict = field(default_factory=dict)

    def __post_init__(self):
        if not self.timestamp:
            self.timestamp = datetime.now().isoformat()


class NotificationAgent:
    """
    Agent 8: Multi-channel notification delivery.

    Sends alerts via Slack, Microsoft Teams, and Email based on
    severity routing rules.
    """

    def __init__(self, config: NotificationConfig = None):
        self.config = config or NotificationConfig()
        self.history: List[NotificationRecord] = []

    def notify_vulnerability_found(self, vulnerability: Dict, server_context: Dict) -> List[NotificationRecord]:
        """Send notifications for a newly discovered vulnerability."""
        severity = vulnerability.get("severity", "MEDIUM").lower()
        cve = vulnerability.get("cve_id", "Unknown")
        title = vulnerability.get("title", "Unknown Vulnerability")
        cvss = vulnerability.get("cvss_score", "N/A")

        subject = f"[{severity.upper()}] New Vulnerability: {cve}"
        message = (
            f"**Vulnerability Detected**\n\n"
            f"**CVE:** {cve}\n"
            f"**Title:** {title}\n"
            f"**Severity:** {severity.upper()} (CVSS: {cvss})\n"
            f"**Server:** {server_context.get('hostname', 'N/A')} ({server_context.get('instance_id', 'N/A')})\n"
            f"**Account:** {server_context.get('account_name', 'N/A')} ({server_context.get('account_id', 'N/A')})\n"
            f"**Component:** {vulnerability.get('packageName', 'N/A')}\n"
            f"**KB Fix:** {vulnerability.get('kb_number', 'N/A')}\n\n"
            f"Review in VulnShield AI Dashboard."
        )

        return self._send_by_severity(severity, subject, message, {"type": "vulnerability", "cve": cve})

    def notify_pipeline_decision(self, decision) -> List[NotificationRecord]:
        """Send notification for a pipeline decision."""
        action_labels = {
            "AUTO_REMEDIATE": ("Auto-Remediated", "info"),
            "HUMAN_APPROVE": ("Pending Approval", "high"),
            "RAISE_CHG": ("CHG Ticket Created", "medium"),
        }
        label, priority = action_labels.get(decision.action, ("Unknown", "info"))

        subject = f"[Pipeline] {decision.vulnerability_id} → {label}"
        message = (
            f"**Pipeline Decision**\n\n"
            f"**CVE:** {decision.vulnerability_id}\n"
            f"**Action:** {label}\n"
            f"**Confidence:** {decision.confidence_score:.0%}\n"
            f"**Risk Score:** {decision.risk_score:.0%}\n"
            f"**NIST Controls:** {', '.join(decision.nist_controls)}\n"
        )

        if decision.itsm_ticket_id:
            message += f"**ITSM Ticket:** {decision.itsm_ticket_id}\n"

        if decision.action == "HUMAN_APPROVE":
            message += "\n**Action Required:** Approve or reject in the Approval Queue."

        return self._send_by_severity(priority, subject, message, {"type": "decision", "action": decision.action})

    def notify_rollback(self, rollback_record) -> List[NotificationRecord]:
        """Send critical alert for rollback events."""
        subject = f"[ROLLBACK] {rollback_record.get('vulnerability_id', 'Unknown')} — Remediation Failed"
        message = (
            f"**Rollback Triggered**\n\n"
            f"**CVE:** {rollback_record.get('vulnerability_id', 'Unknown')}\n"
            f"**Instance:** {rollback_record.get('instance_id', 'N/A')}\n"
            f"**Reason:** {rollback_record.get('trigger_reason', 'Unknown')}\n"
            f"**Rollback Type:** {rollback_record.get('rollback_type', 'full')}\n"
            f"**Status:** {rollback_record.get('status', 'UNKNOWN')}\n\n"
            f"**Immediate action required.**"
        )

        return self._send_by_severity("critical", subject, message, {"type": "rollback"})

    def notify_approval_needed(self, decisions: list) -> List[NotificationRecord]:
        """Send summary of items pending approval."""
        count = len(decisions)
        subject = f"[Approval Required] {count} vulnerabilities pending review"

        lines = [f"**{count} items require human approval:**\n"]
        for d in decisions[:10]:
            lines.append(f"- **{d.vulnerability_id}** — Confidence: {d.confidence_score:.0%} | Risk: {d.risk_score:.0%}")
        if count > 10:
            lines.append(f"\n_...and {count - 10} more_")
        lines.append("\nReview in VulnShield AI → Approval Queue tab.")

        return self._send_by_severity("high", subject, "\n".join(lines), {"type": "approval_summary", "count": count})

    def send_daily_digest(self, summary: Dict) -> List[NotificationRecord]:
        """Send daily vulnerability management digest."""
        subject = f"[Daily Digest] VulnShield AI — {datetime.now().strftime('%Y-%m-%d')}"
        message = (
            f"**Daily Vulnerability Digest**\n\n"
            f"**Total Vulnerabilities:** {summary.get('total', 0)}\n"
            f"**Auto-Remediated:** {summary.get('auto_remediated', 0)}\n"
            f"**Pending Approval:** {summary.get('pending_approval', 0)}\n"
            f"**CHG Tickets:** {summary.get('chg_tickets', 0)}\n"
            f"**Avg Confidence:** {summary.get('avg_confidence', 0):.0%}\n"
            f"**Rollbacks:** {summary.get('rollbacks', 0)}\n"
        )

        return self._send_by_severity("info", subject, message, {"type": "daily_digest"})

    # ==================== CHANNEL SENDERS ====================

    def _send_by_severity(
        self, severity: str, subject: str, message: str, metadata: Dict
    ) -> List[NotificationRecord]:
        """Route notification to channels based on severity."""
        channels = self.config.routing.get(severity, [])
        records = []

        for channel in channels:
            record = self._send(channel, severity, subject, message, metadata)
            records.append(record)

        # Always log even if no channels configured
        if not channels:
            record = NotificationRecord(
                notification_id=f"NOTIF-{datetime.now().strftime('%Y%m%d%H%M%S')}",
                channel="log_only",
                priority=severity,
                subject=subject,
                message=message[:200],
                status="LOGGED",
                metadata=metadata,
            )
            self.history.append(record)
            records.append(record)

        return records

    def _send(self, channel: str, priority: str, subject: str, message: str, metadata: Dict) -> NotificationRecord:
        """Send to a specific channel."""
        record = NotificationRecord(
            notification_id=f"NOTIF-{channel.upper()}-{datetime.now().strftime('%Y%m%d%H%M%S')}",
            channel=channel,
            priority=priority,
            subject=subject,
            message=message[:500],
            metadata=metadata,
        )

        try:
            if channel == "slack" and self.config.slack_enabled:
                self._send_slack(subject, message)
                record.status = "SENT"
            elif channel == "teams" and self.config.teams_enabled:
                self._send_teams(subject, message)
                record.status = "SENT"
            elif channel == "email" and self.config.email_enabled:
                self._send_email(subject, message)
                record.status = "SENT"
            else:
                record.status = "SIMULATED"
        except Exception as e:
            record.status = f"FAILED: {e}"
            logger.error(f"Notification failed ({channel}): {e}")

        self.history.append(record)
        return record

    def _send_slack(self, subject: str, message: str):
        """Send Slack notification via webhook."""
        import requests

        payload = {
            "channel": self.config.slack_channel,
            "username": "VulnShield AI",
            "icon_emoji": ":shield:",
            "blocks": [
                {"type": "header", "text": {"type": "plain_text", "text": subject[:150]}},
                {"type": "section", "text": {"type": "mrkdwn", "text": message[:3000]}},
                {"type": "context", "elements": [
                    {"type": "mrkdwn", "text": f"VulnShield AI | {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"}
                ]},
            ],
        }
        requests.post(self.config.slack_webhook_url, json=payload, timeout=10)

    def _send_teams(self, subject: str, message: str):
        """Send Microsoft Teams notification via webhook."""
        import requests

        # Convert markdown bold to Teams format
        teams_msg = message.replace("**", "**")

        payload = {
            "@type": "MessageCard",
            "@context": "http://schema.org/extensions",
            "themeColor": "0076D7",
            "summary": subject,
            "sections": [
                {
                    "activityTitle": subject,
                    "activitySubtitle": f"VulnShield AI | {datetime.now().strftime('%Y-%m-%d %H:%M')}",
                    "text": teams_msg,
                    "markdown": True,
                }
            ],
        }
        requests.post(self.config.teams_webhook_url, json=payload, timeout=10)

    def _send_email(self, subject: str, message: str):
        """Send email notification via SMTP."""
        import smtplib
        from email.mime.text import MIMEText
        from email.mime.multipart import MIMEMultipart

        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"] = self.config.smtp_from
        msg["To"] = ", ".join(self.config.email_recipients)

        # Plain text
        msg.attach(MIMEText(message, "plain"))

        # HTML version
        html = f"<html><body><pre style='font-family: monospace;'>{message}</pre></body></html>"
        msg.attach(MIMEText(html, "html"))

        with smtplib.SMTP(self.config.smtp_server, self.config.smtp_port) as server:
            server.starttls()
            server.login(self.config.smtp_username, self.config.smtp_password)
            server.sendmail(self.config.smtp_from, self.config.email_recipients, msg.as_string())

    def get_history(self, last_n: int = 50) -> List[Dict]:
        from dataclasses import asdict
        return [asdict(r) for r in self.history[-last_n:]]
