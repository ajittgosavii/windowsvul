"""
Agentic AI Pipeline — Autonomous Vulnerability Management

Architecture:
  ┌─────────────┐    ┌──────────────┐    ┌────────────────┐
  │  Discovery   │───▶│  AI Analysis │───▶│ Decision Engine│
  │  Agent       │    │  Agent       │    │                │
  └─────────────┘    └──────────────┘    └───────┬────────┘
                                                  │
                              ┌────────────────────┼────────────────────┐
                              │                    │                    │
                         confidence ≥ 0.90    0.70–0.89           confidence < 0.70
                              │                    │                    │
                    ┌─────────▼──────┐  ┌──────────▼─────┐  ┌─────────▼──────┐
                    │ Auto-Remediate │  │  Human-in-Loop │  │  Raise CHG /   │
                    │ via SSM        │  │  Approval Gate │  │  ITSM Ticket   │
                    └────────────────┘  └────────────────┘  └────────────────┘
                              │                    │                    │
                              └────────────────────┼────────────────────┘
                                                   │
                                         ┌─────────▼──────┐
                                         │  Verification  │
                                         │  Agent         │
                                         └────────────────┘

Confidence Thresholds (configurable):
  - AUTO_REMEDIATE:  ≥ 0.90 — Execute immediately via SSM
  - HUMAN_APPROVE:   0.70–0.89 — Queue for human approval in dashboard
  - RAISE_CHG:       < 0.70 — Create ServiceNow CHG ticket, assign to team

Agent Types:
  1. Discovery Agent — Scans AWS accounts, inventories servers
  2. Analysis Agent — CVE analysis, NIST mapping, risk scoring
  3. Decision Agent — Confidence routing, action selection
  4. Remediation Agent — Script generation, SSM execution
  5. Verification Agent — Post-remediation validation
  6. ITSM Agent — ServiceNow ticket management
"""

import json
import logging
from datetime import datetime
from typing import Dict, List, Optional, Callable
from dataclasses import dataclass, field, asdict
from enum import Enum

logger = logging.getLogger(__name__)


# ==================== ENUMS & MODELS ====================

class AgentAction(Enum):
    AUTO_REMEDIATE = "AUTO_REMEDIATE"
    HUMAN_APPROVE = "HUMAN_APPROVE"
    RAISE_CHG = "RAISE_CHG"
    ESCALATE = "ESCALATE"
    SKIP = "SKIP"


class PipelineStage(Enum):
    DISCOVERY = "Discovery"
    ANALYSIS = "Analysis"
    DECISION = "Decision"
    APPROVAL = "Approval"
    REMEDIATION = "Remediation"
    VERIFICATION = "Verification"
    CLOSED = "Closed"


class ApprovalStatus(Enum):
    PENDING = "Pending"
    APPROVED = "Approved"
    REJECTED = "Rejected"
    EXPIRED = "Expired"


@dataclass
class AgentDecision:
    """A decision made by the AI agent for a specific vulnerability."""
    decision_id: str
    vulnerability_id: str
    instance_id: str
    account_id: str
    action: str  # AgentAction value
    confidence_score: float
    risk_score: float
    reasoning: str
    nist_controls: List[str] = field(default_factory=list)
    remediation_script: str = ""
    estimated_duration: str = ""
    reboot_required: bool = False
    stage: str = PipelineStage.DECISION.value
    approval_status: str = ApprovalStatus.PENDING.value
    itsm_ticket_id: Optional[str] = None
    created_at: str = ""
    updated_at: str = ""
    executed_at: Optional[str] = None
    executed_by: str = "AI_AGENT"
    verification_result: Optional[Dict] = None

    def __post_init__(self):
        now = datetime.now().isoformat()
        if not self.created_at:
            self.created_at = now
        if not self.updated_at:
            self.updated_at = now


@dataclass
class PipelineConfig:
    """Configuration for the agentic pipeline."""
    # Confidence thresholds
    auto_remediate_threshold: float = 0.90
    human_approve_threshold: float = 0.70
    # Below human_approve_threshold → RAISE_CHG

    # Risk weights
    severity_weights: Dict = field(default_factory=lambda: {
        "CRITICAL": 1.0,
        "HIGH": 0.75,
        "MEDIUM": 0.5,
        "LOW": 0.25,
    })

    # Guardrails
    max_auto_remediations_per_hour: int = 50
    require_restore_point: bool = True
    dry_run_first: bool = True
    blackout_windows: List[Dict] = field(default_factory=list)

    # ITSM
    itsm_enabled: bool = True
    itsm_assignment_group: str = "Windows Server Team"
    itsm_change_category: str = "Security Patch"
    itsm_urgency: str = "2"  # 1=Critical, 2=High, 3=Medium, 4=Low

    # Approval
    approval_timeout_hours: int = 24
    approval_escalation_hours: int = 48
    auto_approve_low_risk: bool = False


# ==================== AGENT: ANALYSIS ====================

class AnalysisAgent:
    """AI agent that analyzes vulnerabilities and calculates risk scores."""

    def __init__(self, remediator, claude_client=None, openai_client=None):
        self.remediator = remediator
        self.claude_client = claude_client
        self.openai_client = openai_client

    def analyze_vulnerability(
        self, vulnerability: Dict, server_context: Dict
    ) -> Dict:
        """Comprehensive vulnerability analysis with risk scoring."""

        # NIST control mapping
        nist_controls = self.remediator.map_cve_to_nist(vulnerability)

        # Build remediation plan for confidence scoring
        from windows_server_remediation_MERGED_ENHANCED import NIST_REMEDIATION_MAP
        registry_fixes = []
        reboot_required = False
        for ctrl in nist_controls:
            if ctrl in NIST_REMEDIATION_MAP:
                ctrl_data = NIST_REMEDIATION_MAP[ctrl]
                registry_fixes.extend(ctrl_data.get("registry_fixes", []))
                if ctrl_data.get("reboot_required"):
                    reboot_required = True

        plan = {
            "registry_fixes": registry_fixes,
            "reboot_required": reboot_required,
        }

        # Confidence score from remediator
        confidence = self.remediator.calculate_confidence_score(vulnerability, plan)

        # Risk score calculation
        risk_score = self._calculate_risk_score(vulnerability, server_context)

        # AI-enhanced analysis: Claude → OpenAI → rule-based
        ai_reasoning = ""
        if self.claude_client:
            ai_reasoning = self._ai_analyze_claude(vulnerability, server_context, nist_controls)
        if not ai_reasoning and self.openai_client:
            ai_reasoning = self._ai_analyze_openai(vulnerability, server_context, nist_controls)
        if not ai_reasoning:
            ai_reasoning = self._rule_based_reasoning(
                vulnerability, server_context, nist_controls, confidence, risk_score
            )

        return {
            "nist_controls": nist_controls,
            "confidence_score": confidence,
            "risk_score": risk_score,
            "registry_fixes": registry_fixes,
            "reboot_required": reboot_required,
            "reasoning": ai_reasoning,
        }

    def _calculate_risk_score(self, vulnerability: Dict, server_context: Dict) -> float:
        """
        Calculate composite risk score (0.0 - 1.0).

        Factors:
        - CVSS score (40% weight)
        - Exploitability (20% weight)
        - Server criticality / environment (20% weight)
        - Attack vector (10% weight)
        - Exposure duration (10% weight)
        """
        # CVSS contribution (0-10 scale → 0-1)
        cvss = vulnerability.get("cvss_score", vulnerability.get("cvss", 7.0))
        cvss_factor = min(cvss / 10.0, 1.0)

        # Exploitability
        exploit_map = {"High": 1.0, "Medium": 0.6, "Low": 0.3, "None": 0.1}
        exploit_factor = exploit_map.get(
            vulnerability.get("exploitability", "Medium"), 0.5
        )

        # Server environment criticality
        env = server_context.get("environment", "Production")
        env_map = {"Production": 1.0, "Staging": 0.6, "Development": 0.3}
        env_factor = env_map.get(env, 0.5)

        # Attack vector
        vector_map = {"Network": 1.0, "Adjacent": 0.7, "Local": 0.4, "Physical": 0.1}
        vector_factor = vector_map.get(
            vulnerability.get("attack_vector", "Network"), 0.5
        )

        # Exposure duration (days since vulnerability published)
        exposure_factor = 0.5  # Default mid-range

        # Weighted composite
        risk = (
            cvss_factor * 0.40
            + exploit_factor * 0.20
            + env_factor * 0.20
            + vector_factor * 0.10
            + exposure_factor * 0.10
        )

        return round(min(risk, 1.0), 3)

    def _build_analysis_prompt(
        self, vulnerability: Dict, server_context: Dict, nist_controls: List[str]
    ) -> str:
        return f"""Analyze this Windows Server vulnerability concisely:

CVE: {vulnerability.get('cve_id', 'Unknown')}
Title: {vulnerability.get('title', 'Unknown')}
Severity: {vulnerability.get('severity', 'Unknown')}
CVSS: {vulnerability.get('cvss_score', 'N/A')}
Component: {vulnerability.get('packageName', 'Unknown')}
Description: {vulnerability.get('description', '')}

Server Context:
- OS: {server_context.get('os_version', 'Unknown')}
- Environment: {server_context.get('environment', 'Production')}
- Application: {server_context.get('application', 'Unknown')}

NIST Controls: {', '.join(nist_controls)}

Provide in 3-4 sentences: risk assessment, remediation recommendation, and whether auto-remediation is safe."""

    def _ai_analyze_claude(
        self, vulnerability: Dict, server_context: Dict, nist_controls: List[str]
    ) -> str:
        """Try Claude AI analysis."""
        try:
            prompt = self._build_analysis_prompt(vulnerability, server_context, nist_controls)
            response = self.claude_client.messages.create(
                model="claude-sonnet-4-20250514",
                max_tokens=300,
                messages=[{"role": "user", "content": prompt}],
            )
            return response.content[0].text
        except Exception:
            return ""  # Fall through to OpenAI

    def _ai_analyze_openai(
        self, vulnerability: Dict, server_context: Dict, nist_controls: List[str]
    ) -> str:
        """Try OpenAI GPT-4o analysis."""
        try:
            prompt = self._build_analysis_prompt(vulnerability, server_context, nist_controls)
            response = self.openai_client.chat.completions.create(
                model="gpt-4o",
                max_tokens=300,
                messages=[
                    {"role": "system", "content": "You are an expert Windows Server security analyst. Be concise."},
                    {"role": "user", "content": prompt},
                ],
            )
            return response.choices[0].message.content
        except Exception:
            return ""  # Fall through to rule-based

    def _rule_based_reasoning(
        self,
        vulnerability: Dict,
        server_context: Dict,
        nist_controls: List[str],
        confidence: float,
        risk_score: float,
    ) -> str:
        """Rule-based reasoning when AI is unavailable."""
        severity = vulnerability.get("severity", "MEDIUM")
        cve = vulnerability.get("cve_id", "Unknown")
        component = vulnerability.get("packageName", "Unknown")
        env = server_context.get("environment", "Production")

        lines = [
            f"**{cve}** — {severity} severity vulnerability in {component}.",
            f"Risk Score: {risk_score:.1%} | Confidence: {confidence:.1%}",
            f"NIST Controls: {', '.join(nist_controls) if nist_controls else 'None mapped'}",
            "",
        ]

        if confidence >= 0.90:
            lines.append(f"**Recommendation:** Auto-remediate. High confidence ({confidence:.0%}) "
                         f"with well-tested remediation path.")
        elif confidence >= 0.70:
            lines.append(f"**Recommendation:** Queue for human approval. Moderate confidence ({confidence:.0%}). "
                         f"Review remediation script before execution.")
        else:
            lines.append(f"**Recommendation:** Raise CHG ticket. Low confidence ({confidence:.0%}). "
                         f"Requires manual investigation and testing.")

        if env == "Production":
            lines.append(f"**Note:** Target is a {env} server — extra caution advised.")

        return "\n".join(lines)


# ==================== AGENT: DECISION ====================

class DecisionAgent:
    """Routes vulnerabilities to the correct action based on confidence and risk."""

    def __init__(self, config: PipelineConfig):
        self.config = config
        self.auto_count_this_hour = 0
        self.hour_start = datetime.now()

    def decide(self, analysis: Dict, vulnerability: Dict, server_context: Dict) -> AgentDecision:
        """Make a routing decision for a vulnerability."""

        confidence = analysis["confidence_score"]
        risk_score = analysis["risk_score"]
        severity = vulnerability.get("severity", "MEDIUM")

        # Reset hourly counter
        if (datetime.now() - self.hour_start).total_seconds() > 3600:
            self.auto_count_this_hour = 0
            self.hour_start = datetime.now()

        # Determine action
        action = self._determine_action(confidence, risk_score, severity)

        decision = AgentDecision(
            decision_id=f"DEC-{datetime.now().strftime('%Y%m%d%H%M%S')}-{vulnerability.get('cve_id', 'UNK')}",
            vulnerability_id=vulnerability.get("cve_id", "Unknown"),
            instance_id=server_context.get("instance_id", "Unknown"),
            account_id=server_context.get("account_id", "Unknown"),
            action=action.value,
            confidence_score=confidence,
            risk_score=risk_score,
            reasoning=analysis["reasoning"],
            nist_controls=analysis.get("nist_controls", []),
            reboot_required=analysis.get("reboot_required", False),
            stage=PipelineStage.DECISION.value,
        )

        if action == AgentAction.AUTO_REMEDIATE:
            self.auto_count_this_hour += 1

        return decision

    def _determine_action(
        self, confidence: float, risk_score: float, severity: str
    ) -> AgentAction:
        """Core routing logic."""

        # Guardrail: rate limit auto-remediations
        if self.auto_count_this_hour >= self.config.max_auto_remediations_per_hour:
            return AgentAction.HUMAN_APPROVE

        # High confidence → auto-remediate
        if confidence >= self.config.auto_remediate_threshold:
            return AgentAction.AUTO_REMEDIATE

        # Medium confidence → human approval
        if confidence >= self.config.human_approve_threshold:
            return AgentAction.HUMAN_APPROVE

        # Low confidence → raise ITSM change ticket
        return AgentAction.RAISE_CHG


# ==================== AGENT: REMEDIATION ====================

class RemediationAgent:
    """Executes remediation actions based on decisions."""

    def __init__(self, remediator, aws_connector=None):
        self.remediator = remediator
        self.aws_connector = aws_connector

    def generate_script(
        self, vulnerability: Dict, server_version: str
    ) -> Dict:
        """Generate remediation script using the backend engine."""
        return self.remediator.generate_remediation_script(
            vulnerability=vulnerability,
            server_version=server_version,
            include_nist_controls=True,
        )

    def execute(self, decision: AgentDecision, server=None, dry_run: bool = False) -> Dict:
        """Execute remediation on a remote server."""
        if not self.aws_connector or not server:
            decision.executed_at = datetime.now().isoformat()
            decision.stage = PipelineStage.REMEDIATION.value
            return {
                "status": "SIMULATED",
                "message": "Remediation simulated (no live server target)",
                "decision_id": decision.decision_id,
                "timestamp": datetime.now().isoformat(),
            }

        try:
            result = self.aws_connector.execute_remediation(
                server=server,
                remediation_script=decision.remediation_script,
                dry_run=dry_run,
            )
            decision.executed_at = datetime.now().isoformat()
            decision.stage = PipelineStage.REMEDIATION.value
            return result
        except Exception as e:
            decision.stage = PipelineStage.REMEDIATION.value
            return {"status": "FAILED", "error": str(e), "timestamp": datetime.now().isoformat()}


# ==================== AGENT: VERIFICATION ====================

class VerificationAgent:
    """Post-remediation verification agent."""

    VERIFICATION_SCRIPT = """
$ErrorActionPreference = 'SilentlyContinue'

$verification = @{
    Timestamp = (Get-Date -Format 'yyyy-MM-ddTHH:mm:ss')
    Hostname = $env:COMPUTERNAME
    Checks = @()
}

# Check if specific KB is installed
param([string]$KBNumber)
$kb = Get-HotFix -Id $KBNumber -ErrorAction SilentlyContinue
$verification.Checks += @{
    Check = "KB Installation"
    KB = $KBNumber
    Installed = ($null -ne $kb)
    InstalledOn = $kb.InstalledOn
}

# Check Windows Defender
$defender = Get-MpComputerStatus -ErrorAction SilentlyContinue
$verification.Checks += @{
    Check = "Windows Defender"
    RealTimeProtection = $defender.RealTimeProtectionEnabled
    SignatureAge = $defender.AntivirusSignatureAge
}

# Check pending reboots
$rebootPending = Test-Path "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Component Based Servicing\\RebootPending"
$verification.Checks += @{
    Check = "Reboot Status"
    RebootPending = $rebootPending
}

$verification | ConvertTo-Json -Depth 3
"""

    def verify(self, decision: AgentDecision, aws_connector=None, server=None) -> Dict:
        """Run post-remediation verification."""
        if aws_connector and server:
            result = aws_connector.execute_remediation(
                server=server,
                remediation_script=self.VERIFICATION_SCRIPT,
                dry_run=False,
            )
            decision.verification_result = result
        else:
            # Simulation
            decision.verification_result = {
                "status": "SIMULATED_PASS",
                "checks": {
                    "kb_installed": True,
                    "defender_active": True,
                    "reboot_pending": False,
                },
            }

        decision.stage = PipelineStage.VERIFICATION.value
        return decision.verification_result


# ==================== ORCHESTRATOR ====================

class AgenticPipeline:
    """
    Main orchestrator that coordinates all agents through the pipeline.

    Flow:
    1. Discovery → Find servers across accounts
    2. Scan → Run vulnerability scans
    3. Analyze → AI analyzes each vulnerability
    4. Decide → Route to auto/human/CHG based on confidence
    5. Execute → Remediate (auto) or queue (human/CHG)
    6. Verify → Post-remediation checks
    """

    def __init__(
        self,
        remediator,
        aws_connector=None,
        itsm_client=None,
        claude_client=None,
        openai_client=None,
        config: PipelineConfig = None,
    ):
        self.config = config or PipelineConfig()
        self.remediator = remediator
        self.aws_connector = aws_connector
        self.itsm_client = itsm_client

        # Initialize agents with both AI clients for fallback
        self.analysis_agent = AnalysisAgent(remediator, claude_client, openai_client)
        self.decision_agent = DecisionAgent(self.config)
        self.remediation_agent = RemediationAgent(remediator, aws_connector)
        self.verification_agent = VerificationAgent()

        # Pipeline state
        self.decisions: List[AgentDecision] = []
        self.pipeline_log: List[Dict] = []

    def _log(self, stage: str, message: str, level: str = "INFO"):
        entry = {
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "stage": stage,
            "level": level,
            "message": message,
        }
        self.pipeline_log.append(entry)
        logger.info(f"[{stage}] {message}")

    def process_vulnerability(
        self,
        vulnerability: Dict,
        server_context: Dict,
        server=None,
    ) -> AgentDecision:
        """Process a single vulnerability through the full pipeline."""

        cve = vulnerability.get("cve_id", "Unknown")
        self._log("ANALYSIS", f"Analyzing {cve}...")

        # Step 1: Analysis
        analysis = self.analysis_agent.analyze_vulnerability(
            vulnerability, server_context
        )

        # Step 2: Decision
        decision = self.decision_agent.decide(
            analysis, vulnerability, server_context
        )
        self._log(
            "DECISION",
            f"{cve} → {decision.action} (confidence={decision.confidence_score:.0%}, risk={decision.risk_score:.0%})",
        )

        # Step 3: Generate remediation script
        server_version = server_context.get("os_version", "Windows Server 2022")
        script_result = self.remediation_agent.generate_script(
            vulnerability, server_version
        )
        decision.remediation_script = script_result.get("script", "")
        decision.estimated_duration = script_result.get("estimated_duration", "Unknown")

        # Step 4: Execute based on action
        if decision.action == AgentAction.AUTO_REMEDIATE.value:
            self._handle_auto_remediate(decision, server)

        elif decision.action == AgentAction.HUMAN_APPROVE.value:
            self._handle_human_approve(decision)

        elif decision.action == AgentAction.RAISE_CHG.value:
            self._handle_raise_chg(decision, vulnerability, server_context)

        self.decisions.append(decision)
        return decision

    def process_batch(
        self,
        vulnerabilities: List[Dict],
        server_context: Dict,
        server=None,
        progress_callback: Callable = None,
    ) -> List[AgentDecision]:
        """Process a batch of vulnerabilities."""
        decisions = []

        for i, vuln in enumerate(vulnerabilities):
            decision = self.process_vulnerability(vuln, server_context, server)
            decisions.append(decision)

            if progress_callback:
                progress_callback(i + 1, len(vulnerabilities), decision)

        self._log(
            "SUMMARY",
            f"Processed {len(decisions)} vulnerabilities: "
            f"{sum(1 for d in decisions if d.action == AgentAction.AUTO_REMEDIATE.value)} auto, "
            f"{sum(1 for d in decisions if d.action == AgentAction.HUMAN_APPROVE.value)} human, "
            f"{sum(1 for d in decisions if d.action == AgentAction.RAISE_CHG.value)} CHG",
        )

        return decisions

    def _handle_auto_remediate(self, decision: AgentDecision, server=None):
        """Auto-remediate with dry-run-first if configured."""
        self._log("REMEDIATION", f"Auto-remediating {decision.vulnerability_id}")

        if self.config.dry_run_first:
            self._log("REMEDIATION", f"Running dry-run for {decision.vulnerability_id}")
            dry_result = self.remediation_agent.execute(decision, server, dry_run=True)
            self._log("REMEDIATION", f"Dry-run result: {dry_result.get('status')}")

        # Actual execution
        result = self.remediation_agent.execute(decision, server, dry_run=False)
        decision.stage = PipelineStage.REMEDIATION.value
        self._log("REMEDIATION", f"Execution result: {result.get('status')}")

        # Verification
        self._log("VERIFICATION", f"Verifying {decision.vulnerability_id}")
        self.verification_agent.verify(decision, self.aws_connector, server)

    def _handle_human_approve(self, decision: AgentDecision):
        """Queue for human approval."""
        decision.stage = PipelineStage.APPROVAL.value
        decision.approval_status = ApprovalStatus.PENDING.value
        self._log(
            "APPROVAL",
            f"{decision.vulnerability_id} queued for human approval "
            f"(confidence={decision.confidence_score:.0%})",
        )

    def _handle_raise_chg(
        self, decision: AgentDecision, vulnerability: Dict, server_context: Dict
    ):
        """Create ITSM change ticket."""
        decision.stage = PipelineStage.APPROVAL.value

        if self.itsm_client and self.config.itsm_enabled:
            try:
                ticket = self.itsm_client.create_change_request(
                    vulnerability=vulnerability,
                    server_context=server_context,
                    decision=decision,
                )
                decision.itsm_ticket_id = ticket.get("number", ticket.get("sys_id"))
                self._log(
                    "ITSM",
                    f"CHG ticket created: {decision.itsm_ticket_id} for {decision.vulnerability_id}",
                )
            except Exception as e:
                self._log("ITSM", f"Failed to create ticket: {e}", level="ERROR")
        else:
            decision.itsm_ticket_id = f"CHG-SIM-{datetime.now().strftime('%Y%m%d%H%M%S')}"
            self._log(
                "ITSM",
                f"Simulated CHG ticket: {decision.itsm_ticket_id} for {decision.vulnerability_id}",
            )

    # ===================== APPROVAL MANAGEMENT =====================

    def approve_decision(self, decision_id: str, approved_by: str = "admin") -> bool:
        """Approve a pending decision and trigger remediation."""
        for decision in self.decisions:
            if decision.decision_id == decision_id:
                if decision.approval_status != ApprovalStatus.PENDING.value:
                    return False

                decision.approval_status = ApprovalStatus.APPROVED.value
                decision.executed_by = approved_by
                decision.stage = PipelineStage.REMEDIATION.value
                self._log(
                    "APPROVAL",
                    f"{decision.vulnerability_id} approved by {approved_by}",
                )

                # Execute remediation
                result = self.remediation_agent.execute(decision, server=None, dry_run=False)
                self._log("REMEDIATION", f"Post-approval execution: {result.get('status')}")
                return True

        return False

    def reject_decision(self, decision_id: str, rejected_by: str = "admin", reason: str = "") -> bool:
        """Reject a pending decision."""
        for decision in self.decisions:
            if decision.decision_id == decision_id:
                decision.approval_status = ApprovalStatus.REJECTED.value
                decision.stage = PipelineStage.CLOSED.value
                self._log(
                    "APPROVAL",
                    f"{decision.vulnerability_id} rejected by {rejected_by}: {reason}",
                )
                return True
        return False

    # ===================== REPORTING =====================

    def get_pipeline_summary(self) -> Dict:
        """Get summary of pipeline execution."""
        if not self.decisions:
            return {"total": 0}

        return {
            "total": len(self.decisions),
            "auto_remediated": sum(
                1 for d in self.decisions
                if d.action == AgentAction.AUTO_REMEDIATE.value
            ),
            "pending_approval": sum(
                1 for d in self.decisions
                if d.approval_status == ApprovalStatus.PENDING.value
            ),
            "chg_tickets": sum(
                1 for d in self.decisions
                if d.action == AgentAction.RAISE_CHG.value
            ),
            "approved": sum(
                1 for d in self.decisions
                if d.approval_status == ApprovalStatus.APPROVED.value
            ),
            "rejected": sum(
                1 for d in self.decisions
                if d.approval_status == ApprovalStatus.REJECTED.value
            ),
            "avg_confidence": round(
                sum(d.confidence_score for d in self.decisions) / len(self.decisions), 3
            ),
            "avg_risk": round(
                sum(d.risk_score for d in self.decisions) / len(self.decisions), 3
            ),
        }

    def get_decisions_by_action(self, action: AgentAction) -> List[AgentDecision]:
        """Filter decisions by action type."""
        return [d for d in self.decisions if d.action == action.value]

    def get_pending_approvals(self) -> List[AgentDecision]:
        """Get all decisions pending human approval."""
        return [
            d for d in self.decisions
            if d.approval_status == ApprovalStatus.PENDING.value
        ]

    def get_log(self, last_n: int = 50) -> List[Dict]:
        """Get recent pipeline log entries."""
        return self.pipeline_log[-last_n:]
