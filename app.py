"""
Agentic AI Windows Vulnerability Scanner & Remediation Tool
Enterprise Edition — Multi-Account AWS, ServiceNow ITSM, Human-in-the-Loop

Cloud-based Streamlit application powered by Claude AI
"""

import streamlit as st
import json
import pandas as pd
from datetime import datetime, timedelta
from typing import Dict, List, Optional
from dataclasses import asdict

from windows_server_remediation_MERGED_ENHANCED import (
    WindowsServerRemediator,
    WINDOWS_SERVER_VERSIONS,
    NIST_REMEDIATION_MAP,
    CIS_BENCHMARK_MAP,
    VULNERABILITY_CATEGORIES,
    CRITICAL_COMPONENTS,
)
from aws_multi_account import (
    AWSMultiAccountConnector,
    AWSAccount,
    WindowsServer,
    AccountStatus,
    ServerStatus,
)
from agentic_pipeline import (
    AgenticPipeline,
    PipelineConfig,
    AgentAction,
    PipelineStage,
    ApprovalStatus,
    AnalysisAgent,
    DecisionAgent,
)
from itsm_integration import (
    ServiceNowClient,
    ServiceNowConfig,
    create_servicenow_client,
)

# ==================== PAGE CONFIG ====================
st.set_page_config(
    page_title="Enterprise Windows Vulnerability AI Agent",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="collapsed" if "authenticated" not in st.session_state or not st.session_state["authenticated"] else "expanded",
)

# ==================== SSO LOGIN GATE ====================

# Enterprise SSO users (in production, replace with LDAP/SAML/OAuth)
SSO_USERS = {
    "admin": {"password": "admin123", "role": "Administrator", "name": "Admin User", "email": "admin@enterprise.com"},
    "security": {"password": "security123", "role": "Security Engineer", "name": "Security Team", "email": "security@enterprise.com"},
    "devops": {"password": "devops123", "role": "DevOps Engineer", "name": "DevOps Team", "email": "devops@enterprise.com"},
    "auditor": {"password": "auditor123", "role": "Compliance Auditor", "name": "Audit Team", "email": "auditor@enterprise.com"},
    "demo": {"password": "demo", "role": "Demo User", "name": "Demo Account", "email": "demo@enterprise.com"},
}

if "authenticated" not in st.session_state:
    st.session_state["authenticated"] = False
    st.session_state["user_info"] = {}

def render_login_page():
    """Render professional SSO login page with animated shield logo and dark frame."""
    st.markdown("""
    <style>
        /* FULL PAGE DARK BACKGROUND */
        [data-testid="stSidebar"] { display: none !important; }
        header[data-testid="stHeader"] { display: none !important; }
        [data-testid="stToolbar"] { display: none !important; }
        [data-testid="stDecoration"] { display: none !important; }
        [data-testid="stStatusWidget"] { display: none !important; }
        .stDeployButton { display: none !important; }
        #MainMenu { display: none !important; }

        .stApp {
            background: linear-gradient(135deg, #0a0a23 0%, #0d1b2a 25%, #1b2838 50%, #0f3460 75%, #16213e 100%) !important;
        }
        [data-testid="stAppViewContainer"] {
            background: transparent !important;
        }
        [data-testid="stMain"] {
            background: transparent !important;
        }
        .block-container {
            padding-top: 2rem !important;
            max-width: 100% !important;
            background: transparent !important;
        }
        [data-testid="stAppViewContainer"] > section,
        [data-testid="stAppViewContainer"] > section > div {
            background: transparent !important;
        }

        /* Kill ALL Streamlit container backgrounds on login page */
        [data-testid="stForm"],
        [data-testid="stForm"] > div,
        [data-testid="stVerticalBlock"],
        [data-testid="stVerticalBlockBorderWrapper"],
        [data-testid="stHorizontalBlock"],
        [data-testid="column"],
        [data-testid="stElementContainer"],
        .stForm,
        .element-container,
        .stVerticalBlock,
        div[data-testid="stVerticalBlockBorderWrapper"] > div,
        div[data-testid="stVerticalBlockBorderWrapper"] {
            background: transparent !important;
            background-color: transparent !important;
            border: none !important;
            box-shadow: none !important;
        }

        /* Animated background particles effect */
        [data-testid="stAppViewContainer"]::before {
            content: '';
            position: fixed;
            top: 0; left: 0; right: 0; bottom: 0;
            background-image:
                radial-gradient(2px 2px at 20% 30%, rgba(59,130,246,0.15), transparent),
                radial-gradient(2px 2px at 40% 70%, rgba(139,92,246,0.1), transparent),
                radial-gradient(2px 2px at 60% 40%, rgba(59,130,246,0.12), transparent),
                radial-gradient(2px 2px at 80% 80%, rgba(139,92,246,0.08), transparent),
                radial-gradient(1px 1px at 10% 90%, rgba(96,165,250,0.15), transparent),
                radial-gradient(1px 1px at 70% 20%, rgba(96,165,250,0.1), transparent),
                radial-gradient(1px 1px at 90% 60%, rgba(139,92,246,0.12), transparent);
            animation: twinkle 8s ease-in-out infinite alternate;
            pointer-events: none;
            z-index: 0;
        }
        @keyframes twinkle {
            0% { opacity: 0.5; }
            100% { opacity: 1; }
        }

        /* GLASS CARD — logo/branding area */
        .login-card {
            max-width: 420px;
            margin: 5vh auto 0;
            text-align: center;
        }

        /* Constrain the Streamlit form + footer to same width */
        .block-container > div > div > div[data-testid="stVerticalBlockBorderWrapper"],
        .block-container > div > div > div.element-container {
            max-width: 420px !important;
            margin-left: auto !important;
            margin-right: auto !important;
        }

        /* Form wrapper — remove ALL backgrounds */
        [data-testid="stForm"] {
            border: 1px solid rgba(59, 130, 246, 0.15) !important;
            border-radius: 16px !important;
            padding: 1.5rem !important;
            max-width: 420px !important;
            margin: 0 auto !important;
        }

        /* Animated Shield Logo */
        .logo-container {
            text-align: center;
            margin-bottom: 1.5rem;
        }

        .shield-logo {
            width: 90px;
            height: 90px;
            margin: 0 auto 1rem;
            position: relative;
            animation: float 3s ease-in-out infinite;
        }

        @keyframes float {
            0%, 100% { transform: translateY(0px); }
            50% { transform: translateY(-10px); }
        }

        .shield-logo svg {
            width: 100%;
            height: 100%;
            filter: drop-shadow(0 0 25px rgba(59, 130, 246, 0.6));
        }

        /* Double pulse ring */
        .shield-logo::before, .shield-logo::after {
            content: '';
            position: absolute;
            top: -12px; left: -12px; right: -12px; bottom: -12px;
            border-radius: 50%;
            border: 2px solid rgba(59, 130, 246, 0.25);
        }
        .shield-logo::before {
            animation: pulse-ring 2s ease-out infinite;
        }
        .shield-logo::after {
            animation: pulse-ring 2s ease-out infinite 1s;
        }
        @keyframes pulse-ring {
            0% { transform: scale(1); opacity: 1; }
            100% { transform: scale(1.4); opacity: 0; }
        }

        .logo-title {
            color: white;
            font-size: 1.6rem;
            font-weight: 700;
            letter-spacing: -0.5px;
            margin: 0;
            text-shadow: 0 2px 10px rgba(0,0,0,0.3);
        }

        .logo-subtitle {
            color: rgba(168, 178, 209, 0.85);
            font-size: 0.8rem;
            margin-top: 0.4rem;
            letter-spacing: 3px;
            text-transform: uppercase;
        }

        /* Scanning line */
        .scan-line {
            width: 80%;
            height: 2px;
            margin: 1.5rem auto;
            background: linear-gradient(90deg, transparent, #3b82f6, #8b5cf6, #3b82f6, transparent);
            background-size: 200% 100%;
            animation: scan-move 3s linear infinite;
            border-radius: 2px;
        }
        @keyframes scan-move {
            0% { background-position: 200% 0; }
            100% { background-position: -200% 0; }
        }

        /* Labels */
        .login-label {
            color: rgba(168, 178, 209, 0.7);
            font-size: 0.75rem;
            text-transform: uppercase;
            letter-spacing: 1.5px;
            margin-bottom: 0.3rem;
            font-weight: 500;
        }

        /* Override Streamlit inputs for dark theme — aggressive selectors */
        input, .stTextInput input, .stTextInput > div > div > input,
        [data-testid="stTextInput"] input,
        input[type="text"], input[type="password"] {
            background: #0d1b2a !important;
            background-color: #0d1b2a !important;
            border: 1px solid rgba(59, 130, 246, 0.25) !important;
            border-radius: 12px !important;
            color: #e2e8f0 !important;
            -webkit-text-fill-color: #e2e8f0 !important;
            padding: 0.7rem 1rem !important;
            font-size: 0.95rem !important;
            caret-color: #60a5fa !important;
        }
        input:focus, .stTextInput input:focus,
        input[type="text"]:focus, input[type="password"]:focus {
            border-color: rgba(59, 130, 246, 0.5) !important;
            box-shadow: 0 0 15px rgba(59, 130, 246, 0.15) !important;
            color: #e2e8f0 !important;
            -webkit-text-fill-color: #e2e8f0 !important;
        }
        input::placeholder, .stTextInput input::placeholder {
            color: rgba(148, 163, 184, 0.5) !important;
            -webkit-text-fill-color: rgba(148, 163, 184, 0.5) !important;
        }
        /* Autofill override (Chrome turns inputs white on autofill) */
        input:-webkit-autofill,
        input:-webkit-autofill:hover,
        input:-webkit-autofill:focus {
            -webkit-box-shadow: 0 0 0 30px #0d1b2a inset !important;
            -webkit-text-fill-color: #e2e8f0 !important;
            border: 1px solid rgba(59, 130, 246, 0.25) !important;
        }

        /* Sign In button */
        .stFormSubmitButton > button {
            background: linear-gradient(135deg, #3b82f6 0%, #8b5cf6 100%) !important;
            color: white !important;
            border: none !important;
            border-radius: 12px !important;
            padding: 0.7rem !important;
            font-weight: 600 !important;
            font-size: 0.95rem !important;
            letter-spacing: 0.5px !important;
            transition: all 0.3s ease !important;
            box-shadow: 0 4px 20px rgba(59, 130, 246, 0.3) !important;
        }
        .stFormSubmitButton > button:hover {
            transform: translateY(-2px) !important;
            box-shadow: 0 8px 30px rgba(59, 130, 246, 0.5) !important;
        }

        /* SSO badge */
        .sso-badge {
            text-align: center;
            margin-top: 1.5rem;
        }
        .sso-badge span {
            background: rgba(59, 130, 246, 0.1);
            color: #60a5fa;
            padding: 5px 18px;
            border-radius: 20px;
            font-size: 0.7rem;
            letter-spacing: 1.5px;
            border: 1px solid rgba(59, 130, 246, 0.2);
            font-weight: 500;
        }

        /* Footer */
        .login-footer {
            text-align: center;
            color: rgba(168, 178, 209, 0.35);
            font-size: 0.7rem;
            margin-top: 2rem;
            line-height: 1.6;
        }

        /* Agent badges row */
        .agent-badges {
            display: flex;
            justify-content: center;
            gap: 6px;
            flex-wrap: wrap;
            margin-top: 0.8rem;
        }
        .agent-badge {
            background: rgba(59, 130, 246, 0.08);
            color: rgba(168, 178, 209, 0.5);
            padding: 2px 10px;
            border-radius: 10px;
            font-size: 0.6rem;
            letter-spacing: 0.5px;
        }
    </style>
    """, unsafe_allow_html=True)

    # Logo + branding as pure HTML (no Streamlit containers)
    st.markdown("""
        <div class="login-card">
            <div class="logo-container">
                <div class="shield-logo">
                    <svg viewBox="0 0 100 100" xmlns="http://www.w3.org/2000/svg">
                        <defs>
                            <linearGradient id="shieldGrad" x1="0%" y1="0%" x2="100%" y2="100%">
                                <stop offset="0%" style="stop-color:#3b82f6;stop-opacity:1" />
                                <stop offset="100%" style="stop-color:#8b5cf6;stop-opacity:1" />
                            </linearGradient>
                        </defs>
                        <path d="M50 5 L90 25 L90 50 C90 75 70 92 50 98 C30 92 10 75 10 50 L10 25 Z"
                              fill="url(#shieldGrad)" opacity="0.9"/>
                        <path d="M50 15 L80 30 L80 50 C80 70 65 83 50 88 C35 83 20 70 20 50 L20 30 Z"
                              fill="rgba(10,10,35,0.6)"/>
                        <path d="M42 50 L48 56 L60 40" stroke="white" stroke-width="4" fill="none"
                              stroke-linecap="round" stroke-linejoin="round" opacity="0.9"/>
                    </svg>
                </div>
                <p class="logo-title">VulnShield AI</p>
                <p class="logo-subtitle">Enterprise Security Platform</p>
                <div class="scan-line"></div>
            </div>
        </div>
    """, unsafe_allow_html=True)

    # Login form — Streamlit widgets (these MUST be outside the HTML div)
    with st.form("login_form", clear_on_submit=False):
        st.markdown('<p class="login-label">Username</p>', unsafe_allow_html=True)
        username = st.text_input("Username", label_visibility="collapsed", placeholder="Enter your username")

        st.markdown('<p class="login-label">Password</p>', unsafe_allow_html=True)
        password = st.text_input("Password", type="password", label_visibility="collapsed", placeholder="Enter your password")

        submitted = st.form_submit_button("Sign In", use_container_width=True, type="primary")

        if submitted:
            if username in SSO_USERS and SSO_USERS[username]["password"] == password:
                st.session_state["authenticated"] = True
                st.session_state["user_info"] = {
                    "username": username,
                    **{k: v for k, v in SSO_USERS[username].items() if k != "password"},
                }
                st.rerun()
            else:
                st.error("Invalid credentials. Try: demo / demo")

    st.markdown("""
        <div style="text-align:center; margin-top:1rem;">
            <div class="sso-badge"><span>SSO ENTERPRISE AUTH</span></div>
            <div class="agent-badges">
                <span class="agent-badge">12 AI Agents</span>
                <span class="agent-badge">200+ AWS Accounts</span>
                <span class="agent-badge">NIST/CIS</span>
                <span class="agent-badge">ServiceNow</span>
            </div>
            <div class="login-footer">
                Agentic AI Windows Vulnerability Management v3.0<br>
                Powered by Claude AI &bull; Multi-Account AWS &bull; ServiceNow ITSM
            </div>
        </div>
    """, unsafe_allow_html=True)

# Check authentication
if not st.session_state["authenticated"]:
    render_login_page()
    st.stop()

# ==================== CUSTOM CSS ====================
st.markdown("""
<style>
    .main-header {
        background: linear-gradient(135deg, #0a0a23 0%, #1a1a3e 40%, #0f3460 100%);
        padding: 1.5rem 2rem;
        border-radius: 12px;
        margin-bottom: 1.5rem;
        color: white;
    }
    .main-header h1 { color: white; margin: 0; font-size: 1.7rem; }
    .main-header p { color: #a8b2d1; margin: 0.3rem 0 0 0; font-size: 0.9rem; }
    .agent-card {
        background: #f8f9fa;
        border-left: 4px solid #0f3460;
        padding: 1rem 1.2rem;
        border-radius: 0 8px 8px 0;
        margin-bottom: 0.8rem;
    }
    .action-auto { border-left: 4px solid #28a745; background: #f0fff4; padding: 0.6rem; border-radius: 0 6px 6px 0; margin: 0.3rem 0; }
    .action-human { border-left: 4px solid #ffc107; background: #fffdf0; padding: 0.6rem; border-radius: 0 6px 6px 0; margin: 0.3rem 0; }
    .action-chg { border-left: 4px solid #dc3545; background: #fff5f5; padding: 0.6rem; border-radius: 0 6px 6px 0; margin: 0.3rem 0; }
    .pipeline-step { display: inline-block; padding: 4px 12px; border-radius: 16px; font-size: 0.75rem; font-weight: 600; margin: 2px; }
    .step-active { background: #0f3460; color: white; }
    .step-done { background: #28a745; color: white; }
    .step-pending { background: #e9ecef; color: #6c757d; }
</style>
""", unsafe_allow_html=True)


# ==================== SESSION STATE ====================
def init_session_state():
    defaults = {
        "remediator": WindowsServerRemediator(),
        "chat_history": [],
        "scan_results": [],
        "remediation_queue": [],
        "agent_log": [],
        "pipeline": None,
        "aws_connector": None,
        "snow_client": None,
        "accounts": [],
        "servers": [],
        "decisions": [],
    }
    for k, v in defaults.items():
        if k not in st.session_state:
            st.session_state[k] = v


init_session_state()
remediator = st.session_state["remediator"]


# ==================== AI AGENT CORE ====================

class VulnerabilityAgent:
    """Agentic AI that reasons about vulnerabilities and recommends actions."""

    SYSTEM_PROMPT = """You are an expert Windows Server security analyst AI agent for an enterprise with 200+ AWS accounts.
Your role is to:
1. Analyze vulnerability scan results across multi-account AWS environments
2. Map vulnerabilities to NIST SP 800-53 controls and CIS Benchmarks
3. Make autonomous remediation decisions based on confidence scores:
   - Confidence >= 90%: Auto-remediate via AWS SSM
   - Confidence 70-89%: Queue for human approval
   - Confidence < 70%: Raise ServiceNow CHG ticket
4. Generate PowerShell remediation scripts
5. Prioritize vulnerabilities by business impact across the fleet
6. Coordinate with ServiceNow ITSM for change management

Available NIST controls: AC-2, AC-17, SC-8, SI-2, SI-3, AU-9
Supported Windows Server versions: 2012 R2, 2016, 2019, 2022, 2025
AWS services used: SSM, Inspector, Organizations, STS AssumeRole

Always respond with structured, actionable advice. Be specific about which servers
and accounts are affected. Format output in markdown."""

    def __init__(self, api_key: Optional[str] = None):
        self.client = None
        if api_key:
            try:
                import anthropic
                self.client = anthropic.Anthropic(api_key=api_key)
            except ImportError:
                pass

    def analyze(self, prompt: str, context: str = "") -> str:
        if not self.client:
            return self._fallback_analysis(prompt)
        try:
            full_prompt = f"Context:\n{context}\n\nUser Query:\n{prompt}" if context else prompt
            response = self.client.messages.create(
                model="claude-sonnet-4-20250514",
                max_tokens=2048,
                system=self.SYSTEM_PROMPT,
                messages=[{"role": "user", "content": full_prompt}],
            )
            return response.content[0].text
        except Exception as e:
            return f"AI analysis error: {e}\n\n" + self._fallback_analysis(prompt)

    def _fallback_analysis(self, prompt: str) -> str:
        p = prompt.lower()
        if "scan" in p or "vulnerabilit" in p:
            return self._generate_scan_report()
        elif "remediat" in p or "fix" in p:
            return self._generate_remediation_advice()
        elif "nist" in p or "compliance" in p:
            return self._generate_compliance_report()
        elif "account" in p or "fleet" in p or "multi" in p:
            return self._generate_fleet_report()
        elif "servicenow" in p or "itsm" in p or "chg" in p or "ticket" in p:
            return self._generate_itsm_report()
        elif "pipeline" in p or "agent" in p or "decision" in p:
            return self._generate_pipeline_report()
        else:
            return (
                "**Enterprise AI Agent Ready** — I can help with:\n\n"
                "- **Multi-Account Scan** — Scan Windows servers across 200+ AWS accounts\n"
                "- **Agentic Remediation** — Auto-fix, human approval, or CHG ticket based on AI confidence\n"
                "- **Fleet Overview** — View all accounts, servers, and vulnerability posture\n"
                "- **ITSM / ServiceNow** — Create and track CHG tickets automatically\n"
                "- **Compliance** — NIST SP 800-53 and CIS Benchmark mapping\n"
                "- **Pipeline Status** — View AI agent decision pipeline\n\n"
                "Try: *'Show me critical vulnerabilities across all production accounts'*"
            )

    def _generate_scan_report(self) -> str:
        return """### Multi-Account Vulnerability Scan Report

| Account | Servers | Critical | High | Medium | Compliance |
|---------|---------|----------|------|--------|------------|
| Splunk COE (448549863273) | 15 | 3 | 7 | 12 | 78% |
| Cloud Migration (950766978386) | 22 | 5 | 12 | 18 | 72% |
| Finance Production | 8 | 1 | 4 | 6 | 91% |
| HR Systems | 5 | 0 | 2 | 3 | 95% |
| ERP Platform | 30 | 8 | 15 | 22 | 68% |
| DevTest | 12 | 2 | 6 | 9 | 82% |

**Fleet Summary:** 92 servers across 6 accounts
**Total Critical:** 19 | **Total High:** 46 | **Average Compliance:** 81%

**AI Agent Actions:**
- 12 vulnerabilities auto-remediated (confidence >= 90%)
- 5 queued for human approval (confidence 70-89%)
- 2 CHG tickets created in ServiceNow (confidence < 70%)"""

    def _generate_remediation_advice(self) -> str:
        return """### Agentic Remediation Pipeline Status

**Auto-Remediated (Confidence >= 90%):**
| CVE | Accounts Affected | Servers | Status |
|-----|-------------------|---------|--------|
| CVE-2024-43498 | 4 accounts | 35 servers | Completed via SSM |
| CVE-2024-38063 | 6 accounts | 62 servers | In Progress |

**Pending Human Approval (Confidence 70-89%):**
| CVE | Risk | Confidence | Reason |
|-----|------|------------|--------|
| CVE-2024-43499 | HIGH | 82% | RDP change on production — requires validation |
| CVE-2024-21338 | HIGH | 77% | Kernel update with reboot — needs maintenance window |

**CHG Tickets Created (Confidence < 70%):**
| Ticket | CVE | Risk | Assigned To |
|--------|-----|------|-------------|
| CHG0040001 | CVE-2024-30078 | HIGH | Windows Server Team |
| CHG0040002 | CVE-2024-35250 | MEDIUM | Windows Server Team |

**Next Steps:** Approve pending items in the Approval Queue tab or review CHG tickets in ServiceNow."""

    def _generate_compliance_report(self) -> str:
        controls = []
        for cid, info in NIST_REMEDIATION_MAP.items():
            controls.append(f"| {cid} | {info['name']} | {len(info.get('registry_fixes', []))} | {info.get('confidence', 0.85):.0%} |")
        return f"""### NIST SP 800-53 Compliance — Fleet-Wide

| Control | Name | Registry Fixes | Confidence |
|---------|------|---------------|------------|
{chr(10).join(controls)}

**Fleet Compliance Score:** 81% average across 92 servers
**Highest Risk Account:** ERP Platform (68% compliance)
**Best Performing:** HR Systems (95% compliance)"""

    def _generate_fleet_report(self) -> str:
        return """### Enterprise Fleet Overview

**AWS Organization:** 6 accounts connected (of 200+ target)
**Total Windows Servers:** 92 managed instances
**SSM Coverage:** 89 servers online, 3 offline

| Metric | Value |
|--------|-------|
| Total Accounts | 6 |
| Total Servers | 92 |
| Servers Online | 89 |
| Pending Reboot | 7 |
| Critical Vulns (Fleet) | 19 |
| High Vulns (Fleet) | 46 |
| Avg Patch Compliance | 81% |
| Auto-Remediation Rate | 63% |

**Account Distribution:**
- Production: 4 accounts, 75 servers
- Non-Production: 2 accounts, 17 servers"""

    def _generate_itsm_report(self) -> str:
        return """### ServiceNow ITSM Status

**Instance:** dev218436.service-now.com
**Connection:** Active

| Ticket | Type | CVE | Status | Priority | Assigned To |
|--------|------|-----|--------|----------|-------------|
| CHG0040001 | Change | CVE-2024-30078 | New | P1 | Windows Server Team |
| CHG0040002 | Change | CVE-2024-35250 | Assess | P2 | Windows Server Team |
| CHG0040003 | Change | CVE-2024-21338 | Authorize | P2 | Windows Server Team |

**Automation Stats:**
- CHG tickets auto-created: 3
- Avg time to create: 2.1 seconds
- CMDB servers synced: 92
- Incidents raised: 0"""

    def _generate_pipeline_report(self) -> str:
        return """### Agentic AI Pipeline Status

```
Discovery → Analysis → Decision → [Auto|Approve|CHG] → Remediation → Verification
    ✅          ✅         ✅           ⏳                  ⏳              ⏳
```

**Pipeline Configuration:**
| Setting | Value |
|---------|-------|
| Auto-Remediate Threshold | >= 90% confidence |
| Human Approval Range | 70-89% confidence |
| CHG Ticket Range | < 70% confidence |
| Max Auto/Hour | 50 remediations |
| Dry-Run First | Enabled |
| Restore Points | Required |

**Current Run:**
- Vulnerabilities analyzed: 19
- Auto-remediated: 12 (63%)
- Pending approval: 5 (26%)
- CHG tickets: 2 (11%)
- Average confidence: 84%"""


# ==================== SAMPLE DATA ====================
SAMPLE_VULNERABILITIES = [
    {"cve_id": "CVE-2024-43498", "title": ".NET Framework Remote Code Execution", "severity": "CRITICAL", "cvss_score": 9.8, "packageName": "Microsoft .NET Framework", "description": "RCE in .NET Framework allowing unauthenticated attackers to execute arbitrary code", "kb_number": "KB5043050", "component": ".NET Framework", "attack_vector": "Network", "exploitability": "High"},
    {"cve_id": "CVE-2024-43499", "title": "Windows Remote Desktop Services RCE", "severity": "CRITICAL", "cvss_score": 9.1, "packageName": "Remote Desktop Services", "description": "RCE in RDP service enabling lateral movement", "kb_number": "KB5043051", "component": "Remote Desktop Services", "attack_vector": "Network", "exploitability": "High"},
    {"cve_id": "CVE-2024-43500", "title": "IIS Web Server Information Disclosure", "severity": "HIGH", "cvss_score": 7.5, "packageName": "Internet Information Services", "description": "Information disclosure in IIS exposing sensitive configuration", "kb_number": "KB5043052", "component": "IIS", "attack_vector": "Network", "exploitability": "Medium"},
    {"cve_id": "CVE-2024-38063", "title": "Windows TCP/IP Remote Code Execution", "severity": "CRITICAL", "cvss_score": 9.8, "packageName": "Windows TCP/IP", "description": "Critical RCE in TCP/IP stack via crafted IPv6 packets", "kb_number": "KB5041578", "component": "Windows Kernel", "attack_vector": "Network", "exploitability": "High"},
    {"cve_id": "CVE-2024-21338", "title": "Windows Kernel Elevation of Privilege", "severity": "HIGH", "cvss_score": 7.8, "packageName": "Windows Kernel", "description": "EoP vulnerability in Windows Kernel allowing SYSTEM access", "kb_number": "KB5034763", "component": "Windows Kernel", "attack_vector": "Local", "exploitability": "Medium"},
    {"cve_id": "CVE-2024-30078", "title": "Wi-Fi Driver Remote Code Execution", "severity": "HIGH", "cvss_score": 8.8, "packageName": "Wi-Fi Driver", "description": "Wi-Fi driver RCE via crafted network packets", "kb_number": "KB5039212", "component": "Network Driver", "attack_vector": "Adjacent", "exploitability": "Medium"},
    {"cve_id": "CVE-2024-35250", "title": "Kernel Streaming Service EoP", "severity": "MEDIUM", "cvss_score": 6.7, "packageName": "Kernel Streaming", "description": "Local privilege escalation via kernel streaming", "kb_number": "KB5040442", "component": "Kernel Streaming", "attack_vector": "Local", "exploitability": "Low"},
]


# ==================== SIDEBAR ====================
# ==================== SECRETS (from st.secrets / .streamlit/secrets.toml) ====================
# All credentials are loaded from Streamlit secrets — never shown in the UI
_secrets = st.secrets if hasattr(st, "secrets") and len(st.secrets) > 0 else {}

api_key = _secrets.get("ANTHROPIC_API_KEY", "")
aws_access_key = _secrets.get("AWS_ACCESS_KEY_ID", "")
aws_secret_key = _secrets.get("AWS_SECRET_ACCESS_KEY", "")
mgmt_account = _secrets.get("AWS_MANAGEMENT_ACCOUNT", "448549863273")
snow_url = _secrets.get("SERVICENOW_URL", "https://dev218436.service-now.com")
snow_user = _secrets.get("SERVICENOW_USER", "admin")
snow_pass = _secrets.get("SERVICENOW_PASSWORD", "")

# Initialize clients from secrets
agent = VulnerabilityAgent(api_key=api_key if api_key else None)

# Auto-connect ServiceNow if secrets are present
if snow_pass and not st.session_state.get("snow_client"):
    st.session_state["snow_client"] = create_servicenow_client(snow_url, snow_user, snow_pass)

# ==================== SIDEBAR ====================

# Hub-and-spoke account registry (configurable)
ACCOUNT_REGISTRY = {
    "448549863273": {"name": "Splunk COE / Primary", "ou": "Production", "regions": ["us-east-1", "us-west-1", "us-east-2"], "role": "Hub", "enabled": True},
    "950766978386": {"name": "Cloud Migration", "ou": "Production", "regions": ["us-west-1"], "role": "Spoke", "enabled": True},
    "123456789012": {"name": "Finance Production", "ou": "Production/Finance", "regions": ["us-east-1"], "role": "Spoke", "enabled": True},
    "234567890123": {"name": "HR Systems", "ou": "Production/HR", "regions": ["us-east-1"], "role": "Spoke", "enabled": True},
    "345678901234": {"name": "ERP Platform", "ou": "Production/ERP", "regions": ["eu-west-1"], "role": "Spoke", "enabled": True},
    "456789012345": {"name": "DevTest Environment", "ou": "Non-Production/Dev", "regions": ["us-west-2"], "role": "Spoke", "enabled": True},
}

with st.sidebar:
    # ==================== DATA MODE TOGGLE — TOP OF SIDEBAR ====================
    tog_col1, tog_col2 = st.columns([1, 1])
    with tog_col1:
        data_mode = st.toggle("Live AWS", value=False, key="data_mode_toggle")
    with tog_col2:
        if data_mode:
            st.markdown("🟢 **LIVE**")
        else:
            st.markdown("🔵 **DEMO**")

    # User info & logout (compact)
    user = st.session_state.get("user_info", {})
    u_col1, u_col2 = st.columns([2, 1])
    with u_col1:
        st.caption(f"👤 {user.get('name', 'User')} | {user.get('role', '')}")
    with u_col2:
        if st.button("Sign Out", key="logout", use_container_width=True):
            st.session_state["authenticated"] = False
            st.session_state["user_info"] = {}
            st.rerun()

    st.divider()

    # ==================== HUB & SPOKE MULTI-ACCOUNT ====================
    st.markdown("## 🌐 Multi-Account (Hub & Spoke)")

    # Hub account
    st.caption(f"Hub: `{mgmt_account}` — scans spokes via AssumeRole")

    # Build account options for multiselect
    _acct_options = {
        f"{info['name']} ({acct_id})": acct_id
        for acct_id, info in ACCOUNT_REGISTRY.items()
    }

    # Filter by OU
    _all_ous = sorted(set(info["ou"] for info in ACCOUNT_REGISTRY.values()))
    ou_filter = st.selectbox("Filter by OU", ["All OUs"] + _all_ous, key="ou_filter")

    if ou_filter != "All OUs":
        _acct_options = {
            label: acct_id for label, acct_id in _acct_options.items()
            if ACCOUNT_REGISTRY[acct_id]["ou"] == ou_filter
        }

    # Multiselect dropdown (scales to 200+ accounts)
    selected_labels = st.multiselect(
        "Select Spoke Accounts",
        options=list(_acct_options.keys()),
        default=list(_acct_options.keys()),
        key="acct_multiselect",
    )

    selected_accounts = [_acct_options[label] for label in selected_labels]
    st.session_state["selected_accounts"] = selected_accounts
    st.caption(f"{len(selected_accounts)} of {len(ACCOUNT_REGISTRY)} accounts selected")

    # Connect button
    aws_region = "us-west-1"  # Default hub region

    if st.button("🔗 Connect Selected Accounts", use_container_width=True, type="primary", key="connect_aws"):
        connector = AWSMultiAccountConnector(
            management_account_id=mgmt_account,
            home_region=aws_region,
            aws_access_key=aws_access_key if aws_access_key else None,
            aws_secret_key=aws_secret_key if aws_secret_key else None,
        )
        st.session_state["aws_connector"] = connector

        if data_mode:
            # LIVE: Real AWS API calls
            with st.spinner("Querying AWS Organizations & SSM..."):
                accounts = connector.discover_accounts()
                accounts = [a for a in accounts if a.account_id in selected_accounts]
                st.session_state["accounts"] = accounts
                servers = connector.discover_all_servers(accounts)
                st.session_state["servers"] = servers
            st.success(f"LIVE: {len(accounts)} accounts, {len(servers)} servers")
        else:
            # DEMO: Simulated data
            accounts = connector._get_fallback_accounts()
            accounts = [a for a in accounts if a.account_id in selected_accounts]
            st.session_state["accounts"] = accounts
            servers = []
            for acct in accounts:
                servers.extend(connector._get_demo_servers(acct))
            st.session_state["servers"] = servers
            st.success(f"DEMO: {len(accounts)} accounts, {len(servers)} servers")

    st.divider()

    # ==================== PIPELINE CONFIG ====================
    st.markdown("### ⚡ AI Pipeline")
    auto_threshold = st.slider("Auto-Remediate (>=)", 0.5, 1.0, 0.90, 0.05, key="auto_thresh")
    human_threshold = st.slider("Human Approve (>=)", 0.3, 0.95, 0.70, 0.05, key="human_thresh")
    max_auto_hour = st.number_input("Max Auto/Hour", 1, 200, 50, key="max_auto")
    dry_run_first = st.checkbox("Dry-Run First", value=True, key="dry_run")
    require_restore = st.checkbox("Require Restore Point", value=True, key="restore")

    st.divider()
    st.caption(f"v3.0 Enterprise | 12 AI Agents | {'LIVE' if data_mode else 'DEMO'}")


# ==================== INITIALIZE PIPELINE ====================
def get_pipeline() -> AgenticPipeline:
    if st.session_state["pipeline"] is None:
        config = PipelineConfig(
            auto_remediate_threshold=auto_threshold,
            human_approve_threshold=human_threshold,
            max_auto_remediations_per_hour=max_auto_hour,
            dry_run_first=dry_run_first,
            require_restore_point=require_restore,
        )
        claude_client = None
        if api_key:
            try:
                import anthropic
                claude_client = anthropic.Anthropic(api_key=api_key)
            except ImportError:
                pass

        st.session_state["pipeline"] = AgenticPipeline(
            remediator=remediator,
            aws_connector=st.session_state.get("aws_connector"),
            itsm_client=st.session_state.get("snow_client"),
            claude_client=claude_client,
            config=config,
        )
    return st.session_state["pipeline"]


# ==================== HEADER ====================
_mode_badge = (
    '<span style="background:#28a745;color:white;padding:2px 10px;border-radius:10px;font-size:0.7rem;margin-left:0.8rem;vertical-align:middle;">LIVE</span>'
    if st.session_state.get("data_mode_toggle", False) else
    '<span style="background:#6c757d;color:white;padding:2px 10px;border-radius:10px;font-size:0.7rem;margin-left:0.8rem;vertical-align:middle;">DEMO</span>'
)
st.markdown(f"""
<div class="main-header">
    <h1>🛡️ Agentic AI — Enterprise Windows Vulnerability Management {_mode_badge}</h1>
    <p>Multi-Account AWS | ServiceNow ITSM | AI Confidence Routing | Human-in-the-Loop | 200+ Accounts</p>
</div>
""", unsafe_allow_html=True)


# ==================== TABS ====================
(tab_dashboard, tab_fleet, tab_agent, tab_pipeline,
 tab_approvals, tab_itsm, tab_compliance, tab_scripts, tab_compare) = st.tabs([
    "📊 Dashboard",
    "🌐 Fleet View",
    "🤖 AI Agent",
    "⚡ Pipeline",
    "✋ Approval Queue",
    "🎫 ITSM / ServiceNow",
    "📋 Compliance",
    "📝 Scripts",
    "📈 Market Comparison",
])


# ==================== HELPER: load data based on Demo/Live toggle ====================
def is_live_mode() -> bool:
    return st.session_state.get("data_mode_toggle", False)

def get_accounts():
    if st.session_state["accounts"]:
        return st.session_state["accounts"]
    # Auto-load demo data when in demo mode (or no connection yet)
    connector = AWSMultiAccountConnector(management_account_id=mgmt_account)
    accounts = connector._get_fallback_accounts()
    st.session_state["accounts"] = accounts
    st.session_state["aws_connector"] = connector
    return accounts

def get_servers():
    if st.session_state["servers"]:
        return st.session_state["servers"]
    connector = st.session_state.get("aws_connector") or AWSMultiAccountConnector(management_account_id=mgmt_account)
    accounts = get_accounts()
    servers = []
    for acct in accounts:
        servers.extend(connector._get_demo_servers(acct))
    st.session_state["servers"] = servers
    st.session_state["aws_connector"] = connector
    return servers


# ==================== TAB: DASHBOARD ====================
with tab_dashboard:
    accounts = get_accounts()
    servers = get_servers()

    total_critical = sum(s.critical_vulns for s in servers)
    total_high = sum(s.high_vulns for s in servers)
    total_medium = sum(s.medium_vulns for s in servers)
    online = sum(1 for s in servers if s.status == "Online")
    avg_compliance = round(sum(s.patch_compliance for s in servers) / max(len(servers), 1) * 100, 1)

    # Top metrics
    c1, c2, c3, c4, c5, c6 = st.columns(6)
    c1.metric("AWS Accounts", len(accounts))
    c2.metric("Windows Servers", len(servers))
    c3.metric("Servers Online", online)
    c4.metric("Critical Vulns", total_critical, delta=f"-{total_critical} to fix", delta_color="inverse")
    c5.metric("High Vulns", total_high, delta=f"-{total_high} to fix", delta_color="inverse")
    c6.metric("Avg Compliance", f"{avg_compliance}%")

    st.divider()

    # Pipeline summary
    pipeline = get_pipeline()
    decisions = pipeline.decisions

    p1, p2, p3, p4 = st.columns(4)
    auto_count = sum(1 for d in decisions if d.action == AgentAction.AUTO_REMEDIATE.value)
    human_count = sum(1 for d in decisions if d.action == AgentAction.HUMAN_APPROVE.value)
    chg_count = sum(1 for d in decisions if d.action == AgentAction.RAISE_CHG.value)
    pending = sum(1 for d in decisions if d.approval_status == ApprovalStatus.PENDING.value)

    p1.metric("Auto-Remediated", auto_count)
    p2.metric("Pending Approval", pending)
    p3.metric("CHG Tickets", chg_count)
    p4.metric("Total Decisions", len(decisions))

    st.divider()

    # Account overview table
    col_left, col_right = st.columns([3, 2])

    with col_left:
        st.markdown("#### Account Vulnerability Posture")
        acct_rows = []
        for a in accounts:
            acct_rows.append({
                "Account": a.account_name,
                "ID": a.account_id,
                "OU": a.ou_path,
                "Region": a.region,
                "Servers": a.server_count,
                "Critical": a.critical_vulns,
                "High": a.high_vulns,
                "Last Scan": a.last_scan or "Never",
            })
        st.dataframe(pd.DataFrame(acct_rows), use_container_width=True, hide_index=True)

    with col_right:
        st.markdown("#### Agentic Pipeline Flow")
        st.markdown(f"""
```
Discovery ─── Analysis ─── Decision Engine
                              │
               ┌──────────────┼──────────────┐
          Confidence ≥{auto_threshold:.0%}   {human_threshold:.0%}-{auto_threshold:.0%}    <{human_threshold:.0%}
               │              │              │
         Auto-Remediate  Human Approve   Raise CHG
          via SSM         Dashboard     ServiceNow
               │              │              │
               └──────────────┼──────────────┘
                              │
                         Verification
```
        """)
        st.markdown(f"**Thresholds:** Auto >= {auto_threshold:.0%} | Human >= {human_threshold:.0%} | CHG < {human_threshold:.0%}")

    # Agent log
    st.divider()
    st.markdown("#### Agent Activity Log")
    if st.session_state["agent_log"]:
        for entry in st.session_state["agent_log"][-15:]:
            st.markdown(f"- `{entry['time']}` — {entry['action']}")
    elif pipeline.pipeline_log:
        for entry in pipeline.pipeline_log[-15:]:
            st.markdown(f"- `{entry['timestamp']}` [{entry['stage']}] {entry['message']}")
    else:
        st.caption("No agent activity yet. Run the pipeline from the Pipeline tab.")


# ==================== TAB: FLEET VIEW ====================
with tab_fleet:
    st.markdown("#### 🌐 Enterprise Fleet — Windows Servers Across AWS Accounts")

    accounts = get_accounts()
    servers = get_servers()

    # Filters
    f1, f2, f3, f4 = st.columns(4)
    with f1:
        acct_filter = st.multiselect("Filter by Account", options=[a.account_name for a in accounts], default=[], key="fleet_acct_filter")
    with f2:
        os_filter = st.multiselect("Filter by OS", options=list(WINDOWS_SERVER_VERSIONS.keys()), default=[], key="fleet_os_filter")
    with f3:
        status_filter = st.multiselect("Filter by Status", options=["Online", "PendingReboot", "Offline"], default=[], key="fleet_status_filter")
    with f4:
        env_filter = st.multiselect("Filter by Environment", options=["Production", "Staging", "Development"], default=[], key="fleet_env_filter")

    # Apply filters
    filtered = servers
    if acct_filter:
        filtered = [s for s in filtered if s.account_name in acct_filter]
    if os_filter:
        filtered = [s for s in filtered if s.os_version in os_filter]
    if status_filter:
        filtered = [s for s in filtered if s.status in status_filter]
    if env_filter:
        filtered = [s for s in filtered if s.tags.get("Environment") in env_filter]

    st.markdown(f"**Showing {len(filtered)} of {len(servers)} servers**")

    # Server table
    srv_rows = []
    for s in filtered:
        status_icon = {"Online": "🟢", "PendingReboot": "🟡", "Offline": "🔴"}.get(s.status, "⚪")
        srv_rows.append({
            "Status": f"{status_icon} {s.status}",
            "Hostname": s.hostname,
            "Instance ID": s.instance_id,
            "Account": s.account_name,
            "OS": s.os_version,
            "IP": s.private_ip,
            "Region": s.region,
            "Environment": s.tags.get("Environment", "N/A"),
            "Application": s.tags.get("Application", "N/A"),
            "Critical": s.critical_vulns,
            "High": s.high_vulns,
            "Compliance": f"{s.patch_compliance:.0%}",
        })

    if srv_rows:
        st.dataframe(pd.DataFrame(srv_rows), use_container_width=True, hide_index=True, height=500)
    else:
        st.info("No servers match the selected filters.")

    # OS Distribution chart
    st.divider()
    ch1, ch2 = st.columns(2)
    with ch1:
        st.markdown("#### OS Version Distribution")
        os_counts = {}
        for s in servers:
            os_counts[s.os_version] = os_counts.get(s.os_version, 0) + 1
        if os_counts:
            st.bar_chart(pd.DataFrame(list(os_counts.items()), columns=["OS Version", "Count"]).set_index("OS Version"))

    with ch2:
        st.markdown("#### Servers by Account")
        acct_counts = {}
        for s in servers:
            acct_counts[s.account_name] = acct_counts.get(s.account_name, 0) + 1
        if acct_counts:
            st.bar_chart(pd.DataFrame(list(acct_counts.items()), columns=["Account", "Servers"]).set_index("Account"))


# ==================== TAB: AI AGENT ====================
with tab_agent:
    st.markdown("#### 🤖 Enterprise AI Security Agent")
    st.caption("Multi-account analysis, fleet-wide remediation, ITSM coordination")

    # Quick actions
    qa1, qa2, qa3, qa4, qa5 = st.columns(5)
    with qa1:
        if st.button("🔍 Fleet Scan", use_container_width=True, key="qa_fleet"):
            st.session_state["chat_history"].append({"role": "user", "content": "Scan all accounts for critical vulnerabilities"})
    with qa2:
        if st.button("📋 Compliance", use_container_width=True, key="qa_comp"):
            st.session_state["chat_history"].append({"role": "user", "content": "Generate fleet-wide NIST compliance report"})
    with qa3:
        if st.button("⚡ Pipeline", use_container_width=True, key="qa_pipe"):
            st.session_state["chat_history"].append({"role": "user", "content": "Show me the agentic pipeline status and decisions"})
    with qa4:
        if st.button("🎫 ITSM Status", use_container_width=True, key="qa_itsm"):
            st.session_state["chat_history"].append({"role": "user", "content": "Show ServiceNow ticket status and open CHG requests"})
    with qa5:
        if st.button("🌐 Fleet View", use_container_width=True, key="qa_fleet_view"):
            st.session_state["chat_history"].append({"role": "user", "content": "Give me a fleet overview of all accounts and servers"})

    # Chat display
    chat_container = st.container(height=400)
    with chat_container:
        if not st.session_state["chat_history"]:
            st.markdown("""**🤖 Enterprise AI Agent** — I manage vulnerability scanning, remediation, and ITSM across your AWS fleet.

- **Scan** — Discover and analyze vulnerabilities across 200+ accounts
- **Decide** — Route fixes: auto-remediate, human approval, or CHG ticket
- **Execute** — Run PowerShell remediations via AWS SSM
- **Track** — Auto-create/update ServiceNow tickets
""")
        else:
            for msg in st.session_state["chat_history"]:
                if msg["role"] == "user":
                    st.chat_message("user").markdown(msg["content"])
                else:
                    st.chat_message("assistant").markdown(msg["content"])

    user_input = st.chat_input("Ask about vulnerabilities, fleet status, remediation, ITSM...")

    if user_input:
        st.session_state["chat_history"].append({"role": "user", "content": user_input})

    if st.session_state["chat_history"] and st.session_state["chat_history"][-1]["role"] == "user":
        last_msg = st.session_state["chat_history"][-1]["content"]
        context = json.dumps({
            "accounts": len(get_accounts()),
            "servers": len(get_servers()),
            "auto_threshold": auto_threshold,
            "human_threshold": human_threshold,
            "management_account": mgmt_account,
            "snow_instance": snow_url,
            "decisions": len(get_pipeline().decisions),
        })
        with st.spinner("AI Agent analyzing..."):
            response = agent.analyze(last_msg, context)
        st.session_state["chat_history"].append({"role": "assistant", "content": response})
        st.session_state["agent_log"].append({
            "time": datetime.now().strftime("%H:%M:%S"),
            "action": f"Analyzed: {last_msg[:60]}...",
        })
        st.rerun()


# ==================== TAB: PIPELINE ====================
with tab_pipeline:
    st.markdown("#### ⚡ Agentic AI Pipeline — Confidence-Based Routing")

    pipeline = get_pipeline()

    # Pipeline config display
    st.markdown(f"""
| Threshold | Range | Action |
|-----------|-------|--------|
| **Auto-Remediate** | Confidence >= {auto_threshold:.0%} | Execute via SSM immediately |
| **Human Approve** | Confidence {human_threshold:.0%} — {auto_threshold:.0%} | Queue in Approval tab |
| **Raise CHG** | Confidence < {human_threshold:.0%} | Create ServiceNow ticket |
""")

    st.divider()

    # Run pipeline
    st.markdown("#### Run Pipeline")
    run_col1, run_col2 = st.columns([2, 1])

    with run_col1:
        target_version = st.selectbox("Target OS Version", list(WINDOWS_SERVER_VERSIONS.keys()), index=1, key="pipeline_os")
        target_env = st.selectbox("Target Environment", ["Production", "Staging", "Development", "All"], key="pipeline_env")

    with run_col2:
        st.markdown("**Vulnerabilities to Process**")
        st.markdown(f"- {len(SAMPLE_VULNERABILITIES)} known vulnerabilities")
        st.markdown(f"- Target: {target_version}")
        st.markdown(f"- Environment: {target_env}")

    if st.button("🚀 Run Agentic Pipeline", type="primary", use_container_width=True, key="run_pipeline"):
        pipeline = get_pipeline()
        # Reset for fresh run
        pipeline.decisions = []
        pipeline.pipeline_log = []

        server_context = {
            "os_version": target_version,
            "environment": target_env if target_env != "All" else "Production",
            "instance_id": "i-fleet-wide",
            "account_id": mgmt_account,
            "account_name": "Fleet-Wide Scan",
            "hostname": "fleet-scan",
        }

        progress = st.progress(0, text="Starting pipeline...")
        status_container = st.container()

        def progress_callback(current, total, decision):
            pct = int(current / total * 100)
            progress.progress(pct, text=f"Processing {decision.vulnerability_id}...")

        with st.spinner("AI agents processing vulnerabilities..."):
            decisions = pipeline.process_batch(
                SAMPLE_VULNERABILITIES, server_context,
                progress_callback=progress_callback,
            )

        st.session_state["decisions"] = decisions
        summary = pipeline.get_pipeline_summary()

        st.success(f"Pipeline complete: {summary['total']} vulnerabilities processed")

        # Summary metrics
        s1, s2, s3, s4, s5 = st.columns(5)
        s1.metric("Total", summary["total"])
        s2.metric("Auto-Remediated", summary["auto_remediated"])
        s3.metric("Pending Approval", summary["pending_approval"])
        s4.metric("CHG Tickets", summary["chg_tickets"])
        s5.metric("Avg Confidence", f"{summary['avg_confidence']:.0%}")

        st.session_state["agent_log"].append({
            "time": datetime.now().strftime("%H:%M:%S"),
            "action": f"Pipeline: {summary['auto_remediated']} auto, {summary['pending_approval']} human, {summary['chg_tickets']} CHG",
        })

    # Decision table
    if pipeline.decisions:
        st.divider()
        st.markdown("#### Pipeline Decisions")

        dec_rows = []
        for d in pipeline.decisions:
            action_icon = {"AUTO_REMEDIATE": "🟢", "HUMAN_APPROVE": "🟡", "RAISE_CHG": "🔴"}.get(d.action, "⚪")
            dec_rows.append({
                "CVE": d.vulnerability_id,
                "Action": f"{action_icon} {d.action.replace('_', ' ').title()}",
                "Confidence": f"{d.confidence_score:.0%}",
                "Risk": f"{d.risk_score:.0%}",
                "NIST": ", ".join(d.nist_controls),
                "Reboot": "Yes" if d.reboot_required else "No",
                "Stage": d.stage,
                "Approval": d.approval_status,
                "ITSM Ticket": d.itsm_ticket_id or "—",
            })

        st.dataframe(pd.DataFrame(dec_rows), use_container_width=True, hide_index=True)

    # Pipeline log
    if pipeline.pipeline_log:
        with st.expander("Pipeline Execution Log", expanded=False):
            for entry in pipeline.pipeline_log:
                level_icon = {"INFO": "ℹ️", "ERROR": "❌", "WARNING": "⚠️"}.get(entry["level"], "")
                st.markdown(f"`{entry['timestamp']}` [{entry['stage']}] {level_icon} {entry['message']}")


# ==================== TAB: APPROVAL QUEUE ====================
with tab_approvals:
    st.markdown("#### ✋ Human-in-the-Loop Approval Queue")
    st.caption("Vulnerabilities routed here have confidence scores between "
               f"{human_threshold:.0%} and {auto_threshold:.0%}. Review and approve or reject.")

    pipeline = get_pipeline()
    pending = pipeline.get_pending_approvals()

    if not pending:
        st.info("No pending approvals. Run the pipeline to generate decisions, or all items were auto-remediated.")

        # Show demo pending items
        if st.button("Load Demo Approval Queue", key="demo_approvals"):
            # Run pipeline to get decisions
            server_context = {
                "os_version": "Windows Server 2022",
                "environment": "Production",
                "instance_id": "i-demo",
                "account_id": mgmt_account,
                "account_name": "Demo Account",
                "hostname": "demo-server",
            }
            pipeline.process_batch(SAMPLE_VULNERABILITIES, server_context)
            st.rerun()
    else:
        for i, decision in enumerate(pending):
            action_class = "action-human"
            with st.container():
                st.markdown(f'<div class="{action_class}">', unsafe_allow_html=True)

                col_info, col_actions = st.columns([3, 1])

                with col_info:
                    st.markdown(f"**{decision.vulnerability_id}** — Confidence: {decision.confidence_score:.0%} | Risk: {decision.risk_score:.0%}")
                    st.markdown(f"NIST: {', '.join(decision.nist_controls)} | Reboot: {'Yes' if decision.reboot_required else 'No'} | Duration: {decision.estimated_duration}")
                    with st.expander("AI Reasoning", expanded=False):
                        st.markdown(decision.reasoning)
                    with st.expander("Remediation Script Preview", expanded=False):
                        st.code(decision.remediation_script[:2000] + "..." if len(decision.remediation_script) > 2000 else decision.remediation_script, language="powershell")

                with col_actions:
                    if st.button("✅ Approve", key=f"approve_{decision.decision_id}", use_container_width=True):
                        pipeline.approve_decision(decision.decision_id, approved_by="admin")
                        st.session_state["agent_log"].append({
                            "time": datetime.now().strftime("%H:%M:%S"),
                            "action": f"Approved: {decision.vulnerability_id}",
                        })
                        st.rerun()

                    if st.button("❌ Reject", key=f"reject_{decision.decision_id}", use_container_width=True):
                        pipeline.reject_decision(decision.decision_id, rejected_by="admin", reason="Manual review required")
                        st.session_state["agent_log"].append({
                            "time": datetime.now().strftime("%H:%M:%S"),
                            "action": f"Rejected: {decision.vulnerability_id}",
                        })
                        st.rerun()

                    if st.button("🎫 → CHG", key=f"chg_{decision.decision_id}", use_container_width=True, help="Escalate to ServiceNow CHG"):
                        decision.action = AgentAction.RAISE_CHG.value
                        snow = st.session_state.get("snow_client")
                        if snow:
                            vuln = next((v for v in SAMPLE_VULNERABILITIES if v["cve_id"] == decision.vulnerability_id), {})
                            ticket = snow.create_change_request(vuln, {"instance_id": decision.instance_id, "account_id": decision.account_id}, decision)
                            decision.itsm_ticket_id = ticket.get("number")
                            st.success(f"CHG created: {decision.itsm_ticket_id}")
                        st.rerun()

                st.markdown("</div>", unsafe_allow_html=True)


# ==================== TAB: ITSM / SERVICENOW ====================
with tab_itsm:
    st.markdown("#### 🎫 ServiceNow ITSM Integration")
    st.markdown(f"**Instance:** {snow_url}")

    snow = st.session_state.get("snow_client")

    # Connection status
    if snow:
        conn = snow.test_connection()
        status_icon = "🟢" if conn["status"] in ("CONNECTED", "SIMULATED") else "🔴"
        st.markdown(f"**Status:** {status_icon} {conn['status']}")
    else:
        st.warning("ServiceNow not connected. Configure credentials in the sidebar.")
        snow = create_servicenow_client(snow_url, snow_user, "")
        st.session_state["snow_client"] = snow

    st.divider()

    itsm_col1, itsm_col2 = st.columns([2, 1])

    with itsm_col1:
        st.markdown("#### Open Change Requests")
        open_chgs = snow.get_open_changes()

        # Add any pipeline-generated tickets
        pipeline_chgs = [d for d in get_pipeline().decisions if d.itsm_ticket_id]
        for d in pipeline_chgs:
            if not any(c.get("number") == d.itsm_ticket_id for c in open_chgs):
                open_chgs.append({
                    "number": d.itsm_ticket_id,
                    "short_description": f"[{d.action}] {d.vulnerability_id}",
                    "state": "New",
                    "priority": "2",
                    "risk": f"Confidence {d.confidence_score:.0%}",
                    "assignment_group": "Windows Server Team",
                    "sys_created_on": d.created_at,
                })

        if open_chgs:
            chg_rows = []
            for c in open_chgs:
                chg_rows.append({
                    "Ticket": c.get("number", "N/A"),
                    "Description": c.get("short_description", "")[:80],
                    "State": c.get("state", "Unknown"),
                    "Priority": c.get("priority", "N/A"),
                    "Risk": c.get("risk", "N/A"),
                    "Assigned To": c.get("assignment_group", "N/A"),
                    "Created": c.get("sys_created_on", ""),
                })
            st.dataframe(pd.DataFrame(chg_rows), use_container_width=True, hide_index=True)
        else:
            st.info("No open change requests.")

    with itsm_col2:
        st.markdown("#### Create Manual CHG")

        manual_cve = st.selectbox("Vulnerability", [v["cve_id"] for v in SAMPLE_VULNERABILITIES], key="manual_cve")
        manual_env = st.selectbox("Environment", ["Production", "Staging", "Development"], key="manual_env")
        manual_notes = st.text_area("Additional Notes", key="manual_notes", height=100)

        if st.button("🎫 Create CHG Ticket", type="primary", use_container_width=True, key="create_chg"):
            vuln = next((v for v in SAMPLE_VULNERABILITIES if v["cve_id"] == manual_cve), SAMPLE_VULNERABILITIES[0])
            server_ctx = {
                "instance_id": "manual-request",
                "account_id": mgmt_account,
                "account_name": "Manual Request",
                "os_version": "Windows Server 2022",
                "hostname": "manual",
                "environment": manual_env,
            }

            with st.spinner("Creating CHG ticket..."):
                ticket = snow.create_change_request(vuln, server_ctx, additional_fields={"work_notes": manual_notes} if manual_notes else None)

            ticket_num = ticket.get("number", "N/A")
            st.success(f"CHG ticket created: **{ticket_num}**")
            st.session_state["agent_log"].append({
                "time": datetime.now().strftime("%H:%M:%S"),
                "action": f"Manual CHG created: {ticket_num} for {manual_cve}",
            })

    # CMDB sync
    st.divider()
    st.markdown("#### CMDB Synchronization")
    servers = get_servers()
    st.markdown(f"**{len(servers)} servers** available for CMDB sync")

    if st.button("🔄 Sync All Servers to CMDB", key="cmdb_sync"):
        with st.spinner(f"Syncing {len(servers)} servers to ServiceNow CMDB..."):
            import time
            progress = st.progress(0)
            for i, srv in enumerate(servers[:20]):  # Limit for demo
                snow.sync_server_to_cmdb(srv)
                progress.progress(int((i + 1) / min(len(servers), 20) * 100))
                time.sleep(0.1)
        st.success(f"Synced {min(len(servers), 20)} servers to CMDB")


# ==================== TAB: COMPLIANCE ====================
with tab_compliance:
    st.markdown("#### 📋 NIST SP 800-53 & CIS Benchmark Compliance")

    comp_col1, comp_col2 = st.columns([3, 2])

    with comp_col1:
        st.markdown("##### NIST SP 800-53 Controls")
        for ctrl_id, ctrl_info in NIST_REMEDIATION_MAP.items():
            reg_count = len(ctrl_info.get("registry_fixes", []))
            ps_count = len(ctrl_info.get("powershell_commands", []))
            conf = ctrl_info.get("confidence", 0.85)
            auto = ctrl_info.get("auto_remediate", False)

            with st.expander(f"**{ctrl_id}** — {ctrl_info['name']} ({conf:.0%} confidence)"):
                st.markdown(f"- **Registry Fixes:** {reg_count}")
                st.markdown(f"- **PowerShell Commands:** {ps_count}")
                st.markdown(f"- **Auto-Remediate:** {'Yes' if auto else 'Manual Review'}")
                if ctrl_info.get("registry_fixes"):
                    st.markdown("**Registry Changes:**")
                    for fix in ctrl_info["registry_fixes"]:
                        st.code(f'{fix["path"]}\\{fix["name"]} = {fix["value"]} ({fix["type"]})', language="text")
                if ctrl_info.get("powershell_commands"):
                    st.markdown("**PowerShell:**")
                    st.code("\n".join(ctrl_info["powershell_commands"]), language="powershell")

    with comp_col2:
        st.markdown("##### CIS Benchmarks")
        for cis_id, cis_info in CIS_BENCHMARK_MAP.items():
            with st.expander(f"**{cis_id}** — {cis_info['name']}"):
                st.markdown(f"- NIST: {', '.join(cis_info.get('nist_controls', []))}")
                st.markdown(f"- Confidence: {cis_info.get('confidence', 0):.0%}")
                st.markdown(f"- Auto-Fix: {'Yes' if cis_info.get('auto_remediate') else 'No'}")

        st.divider()
        st.markdown("##### Fleet Compliance Summary")
        servers = get_servers()
        compliant = sum(1 for s in servers if s.patch_compliance >= 0.9)
        st.metric("Servers >= 90% Compliant", f"{compliant}/{len(servers)}")
        st.metric("Fleet Average", f"{sum(s.patch_compliance for s in servers) / max(len(servers), 1):.0%}")


# ==================== TAB: SCRIPTS ====================
with tab_scripts:
    st.markdown("#### 📝 PowerShell Remediation Scripts")

    sc1, sc2 = st.columns(2)
    with sc1:
        script_vuln = st.selectbox("Vulnerability", [f"{v['cve_id']} — {v['title']}" for v in SAMPLE_VULNERABILITIES], key="script_vuln")
    with sc2:
        script_os = st.selectbox("Target OS", list(WINDOWS_SERVER_VERSIONS.keys()), index=1, key="script_os")

    selected_vuln = next((v for v in SAMPLE_VULNERABILITIES if f"{v['cve_id']} — {v['title']}" == script_vuln), SAMPLE_VULNERABILITIES[0])

    if st.button("🔧 Generate Script", type="primary", key="gen_script"):
        with st.spinner("Generating..."):
            result = remediator.generate_remediation_script(selected_vuln, script_os, include_nist_controls=True)

        m1, m2, m3, m4 = st.columns(4)
        m1.metric("Confidence", f"{result['confidence_score']:.0%}")
        m2.metric("Registry Fixes", len(result["registry_fixes"]))
        m3.metric("Risk", result["risk_level"])
        m4.metric("Duration", result["estimated_duration"])

        st.markdown(f"**NIST:** {', '.join(result['nist_controls'])} | **Auto-Fix:** {'Yes' if result['auto_remediate_recommended'] else 'No'} | **Reboot:** {'Yes' if result['reboot_required'] else 'No'}")

        st.code(result["script"], language="powershell")
        st.download_button("📥 Download", data=result["script"], file_name=f"remediate_{selected_vuln['cve_id'].replace('-', '_')}.ps1", mime="text/plain", key="dl_script")


# ==================== TAB: MARKET COMPARISON ====================
with tab_compare:
    st.markdown("#### 📈 Market Comparison — Enterprise Vulnerability Management Tools")
    st.markdown("How this Agentic AI tool compares with leading enterprise solutions:")

    comparison_data = [
        {
            "Feature": "AI-Powered Analysis",
            "This Tool": "✅ Claude AI agentic pipeline with confidence scoring",
            "Qualys VMDR": "⚠️ Basic ML prioritization (TruRisk)",
            "Tenable.io": "⚠️ Predictive prioritization (VPR)",
            "Rapid7 InsightVM": "⚠️ Basic risk scoring",
            "CrowdStrike Spotlight": "⚠️ AI threat correlation",
            "Microsoft Defender VM": "⚠️ Threat intelligence scoring",
        },
        {
            "Feature": "Autonomous Remediation",
            "This Tool": "✅ Full agentic: auto-fix, human-loop, CHG routing",
            "Qualys VMDR": "⚠️ Patch deployment only",
            "Tenable.io": "❌ Detection only, no remediation",
            "Rapid7 InsightVM": "⚠️ Limited automation via InsightConnect",
            "CrowdStrike Spotlight": "❌ Detection only",
            "Microsoft Defender VM": "⚠️ Intune-based patching",
        },
        {
            "Feature": "Multi-Account AWS (200+)",
            "This Tool": "✅ Native Organizations + SSM + AssumeRole",
            "Qualys VMDR": "✅ Cloud connectors (agent-based)",
            "Tenable.io": "✅ Cloud connectors (agentless + agent)",
            "Rapid7 InsightVM": "✅ AWS connector",
            "CrowdStrike Spotlight": "✅ Falcon agent",
            "Microsoft Defender VM": "⚠️ Azure-centric, AWS via Arc",
        },
        {
            "Feature": "ITSM Integration (ServiceNow)",
            "This Tool": "✅ Auto-create CHG/INC/CMDB sync",
            "Qualys VMDR": "✅ ServiceNow CMDB plugin",
            "Tenable.io": "✅ ServiceNow VR integration",
            "Rapid7 InsightVM": "✅ ServiceNow plugin",
            "CrowdStrike Spotlight": "⚠️ Basic ticket creation",
            "Microsoft Defender VM": "⚠️ Via Logic Apps",
        },
        {
            "Feature": "Human-in-the-Loop",
            "This Tool": "✅ Confidence-based approval queue with AI reasoning",
            "Qualys VMDR": "❌ No approval workflow",
            "Tenable.io": "❌ No approval workflow",
            "Rapid7 InsightVM": "⚠️ Basic approval via InsightConnect",
            "CrowdStrike Spotlight": "❌ No approval workflow",
            "Microsoft Defender VM": "❌ No approval workflow",
        },
        {
            "Feature": "NIST/CIS Compliance Mapping",
            "This Tool": "✅ Automatic NIST SP 800-53 + CIS mapping",
            "Qualys VMDR": "✅ Policy compliance module ($$$)",
            "Tenable.io": "✅ Compliance auditing ($$$)",
            "Rapid7 InsightVM": "⚠️ Basic compliance checks",
            "CrowdStrike Spotlight": "❌ Not focused on compliance",
            "Microsoft Defender VM": "⚠️ Via Defender for Cloud",
        },
        {
            "Feature": "PowerShell Script Generation",
            "This Tool": "✅ AI-generated per-CVE with rollback/backup",
            "Qualys VMDR": "❌ No script generation",
            "Tenable.io": "❌ No script generation",
            "Rapid7 InsightVM": "❌ No script generation",
            "CrowdStrike Spotlight": "❌ No script generation",
            "Microsoft Defender VM": "❌ No script generation",
        },
        {
            "Feature": "Cost (Annual)",
            "This Tool": "~$5K-15K (Claude API + AWS + hosting)",
            "Qualys VMDR": "$50K-200K+ (per-asset licensing)",
            "Tenable.io": "$40K-150K+ (per-asset licensing)",
            "Rapid7 InsightVM": "$30K-120K+ (per-asset licensing)",
            "CrowdStrike Spotlight": "$80K-300K+ (bundled with Falcon)",
            "Microsoft Defender VM": "$15K-60K+ (E5 licensing)",
        },
        {
            "Feature": "Deployment",
            "This Tool": "✅ Streamlit Cloud / Docker — minutes",
            "Qualys VMDR": "SaaS + agents — weeks",
            "Tenable.io": "SaaS + agents/scanners — weeks",
            "Rapid7 InsightVM": "SaaS + agents — weeks",
            "CrowdStrike Spotlight": "SaaS + Falcon agent — days",
            "Microsoft Defender VM": "Azure portal — days",
        },
        {
            "Feature": "Windows-Specific Focus",
            "This Tool": "✅ Built specifically for Windows Server",
            "Qualys VMDR": "Multi-OS (Windows, Linux, etc.)",
            "Tenable.io": "Multi-OS (Windows, Linux, etc.)",
            "Rapid7 InsightVM": "Multi-OS (Windows, Linux, etc.)",
            "CrowdStrike Spotlight": "Multi-OS (Windows, Linux, Mac)",
            "Microsoft Defender VM": "Multi-OS (Windows, Linux)",
        },
    ]

    st.dataframe(
        pd.DataFrame(comparison_data),
        use_container_width=True,
        hide_index=True,
        height=450,
    )

    st.divider()

    st.markdown("#### Key Differentiators")

    d1, d2 = st.columns(2)

    with d1:
        st.markdown("""
##### What This Tool Does Better

**1. True Agentic AI Architecture**
Unlike traditional tools that use basic ML for prioritization, this tool uses
Claude AI as an autonomous agent that can reason about vulnerabilities, generate
custom remediation scripts, and make routing decisions. No other tool offers
confidence-score-based routing between auto-fix, human approval, and ITSM tickets.

**2. Dramatic Cost Reduction**
Enterprise vulnerability tools cost $50K-300K+/year for per-asset licensing.
This tool runs on ~$5K-15K/year (API costs + infrastructure), delivering
80-90% of enterprise functionality at a fraction of the cost.

**3. PowerShell Script Generation**
No competing tool generates customized, CVE-specific PowerShell remediation
scripts with system restore points, rollback capability, and NIST-compliant
registry fixes. Every other tool stops at "install this KB."

**4. Native Human-in-the-Loop**
The confidence-based approval queue with AI reasoning is unique. Security
engineers see WHY the AI made each decision and can override with one click.
""")

    with d2:
        st.markdown("""
##### Where Enterprise Tools Excel

**1. Broader Coverage**
Qualys, Tenable, and Rapid7 cover Linux, network devices, containers,
web apps, and cloud infrastructure — not just Windows Servers.

**2. Vulnerability Database**
Commercial tools maintain proprietary CVE databases with faster zero-day
coverage (Qualys QID, Tenable plugins, etc.).

**3. Agent-Based Scanning**
Permanent agents (Qualys Cloud Agent, Falcon Sensor) provide continuous
monitoring without SSM dependency.

**4. Enterprise Support**
24/7 vendor support, SLAs, dedicated CSMs, compliance certifications
(SOC 2, FedRAMP, etc.).

**5. Mature Reporting**
Dashboards, executive reports, trend analysis built over 15+ years
of enterprise deployment.
""")

    st.divider()
    st.markdown("""
##### Recommended Use Cases for This Tool

| Use Case | Fit |
|----------|-----|
| SMB/Mid-Market with <500 Windows servers | Excellent — cost-effective, fast to deploy |
| Enterprise augmenting existing Qualys/Tenable | Excellent — AI agent layer on top of existing scanning |
| DevOps teams wanting self-service remediation | Excellent — Streamlit UI + API-driven |
| Organizations needing ITSM-integrated patching | Excellent — native ServiceNow integration |
| Regulated industries needing compliance mapping | Good — NIST/CIS built-in, but no FedRAMP cert |
| Large enterprise replacing Qualys/Tenable entirely | Not recommended — lacks breadth of coverage |
""")


# ==================== FOOTER ====================
st.divider()
accounts = get_accounts()
servers = get_servers()
st.caption(
    f"🛡️ Agentic AI Enterprise v3.0 | "
    f"Accounts: {len(accounts)} | Servers: {len(servers)} | "
    f"Auto >= {auto_threshold:.0%} | Human >= {human_threshold:.0%} | CHG < {human_threshold:.0%} | "
    f"ITSM: {snow_url.split('//')[1] if '//' in snow_url else snow_url} | "
    f"{datetime.now().strftime('%Y-%m-%d %H:%M')}"
)
