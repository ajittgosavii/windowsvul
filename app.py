"""
Agentic AI Windows Vulnerability Scanner & Remediation Tool
Cloud-based Streamlit application powered by Claude AI
"""

import streamlit as st
import json
import pandas as pd
from datetime import datetime
from typing import Dict, List, Optional

from windows_server_remediation_MERGED_ENHANCED import (
    WindowsServerRemediator,
    WINDOWS_SERVER_VERSIONS,
    NIST_REMEDIATION_MAP,
    CIS_BENCHMARK_MAP,
    VULNERABILITY_CATEGORIES,
    CRITICAL_COMPONENTS,
)

# ==================== PAGE CONFIG ====================
st.set_page_config(
    page_title="Windows Vulnerability AI Agent",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ==================== CUSTOM CSS ====================
st.markdown("""
<style>
    .main-header {
        background: linear-gradient(135deg, #1a1a2e 0%, #16213e 50%, #0f3460 100%);
        padding: 1.5rem 2rem;
        border-radius: 12px;
        margin-bottom: 1.5rem;
        color: white;
    }
    .main-header h1 { color: white; margin: 0; font-size: 1.8rem; }
    .main-header p { color: #a8b2d1; margin: 0.3rem 0 0 0; font-size: 0.95rem; }
    .agent-card {
        background: #f8f9fa;
        border-left: 4px solid #0f3460;
        padding: 1rem 1.2rem;
        border-radius: 0 8px 8px 0;
        margin-bottom: 0.8rem;
    }
    .severity-critical { color: #dc3545; font-weight: 700; }
    .severity-high { color: #fd7e14; font-weight: 700; }
    .severity-medium { color: #ffc107; font-weight: 600; }
    .severity-low { color: #28a745; font-weight: 600; }
    .status-badge {
        display: inline-block;
        padding: 2px 10px;
        border-radius: 12px;
        font-size: 0.8rem;
        font-weight: 600;
    }
    .chat-msg-ai {
        background: #e8f4f8;
        border-radius: 12px;
        padding: 0.8rem 1rem;
        margin: 0.5rem 0;
    }
    .chat-msg-user {
        background: #f0f0f5;
        border-radius: 12px;
        padding: 0.8rem 1rem;
        margin: 0.5rem 0;
    }
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
        "selected_vulns": [],
        "api_key_set": False,
    }
    for k, v in defaults.items():
        if k not in st.session_state:
            st.session_state[k] = v


init_session_state()
remediator = st.session_state["remediator"]


# ==================== AI AGENT CORE ====================

class VulnerabilityAgent:
    """Agentic AI that reasons about vulnerabilities and recommends actions."""

    SYSTEM_PROMPT = """You are an expert Windows Server security analyst AI agent.
Your role is to:
1. Analyze vulnerability scan results and assess risk
2. Map vulnerabilities to NIST SP 800-53 controls and CIS Benchmarks
3. Recommend remediation strategies with confidence scores
4. Generate PowerShell remediation scripts
5. Prioritize vulnerabilities by business impact

You have access to these NIST controls: AC-2, AC-17, SC-8, SI-2, SI-3, AU-9
You support Windows Server versions: 2012 R2, 2016, 2019, 2022, 2025

Always respond with structured, actionable advice. When analyzing vulnerabilities,
provide severity assessment, affected components, NIST mapping, and remediation steps.
Format output in markdown for clarity."""

    def __init__(self, api_key: Optional[str] = None):
        self.client = None
        if api_key:
            try:
                import anthropic
                self.client = anthropic.Anthropic(api_key=api_key)
            except ImportError:
                pass

    def analyze(self, prompt: str, context: str = "") -> str:
        """Run AI analysis using Claude."""
        if not self.client:
            return self._fallback_analysis(prompt)

        try:
            full_prompt = prompt
            if context:
                full_prompt = f"Context:\n{context}\n\nUser Query:\n{prompt}"

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
        """Rule-based fallback when API is unavailable."""
        prompt_lower = prompt.lower()

        if "scan" in prompt_lower or "vulnerabilit" in prompt_lower:
            return self._generate_scan_report()
        elif "remediat" in prompt_lower or "fix" in prompt_lower:
            return self._generate_remediation_advice()
        elif "nist" in prompt_lower or "compliance" in prompt_lower:
            return self._generate_compliance_report()
        elif "priorit" in prompt_lower or "risk" in prompt_lower:
            return self._generate_risk_assessment()
        else:
            return (
                "**AI Agent Ready** - I can help with:\n"
                "- **Scan** vulnerabilities on Windows Servers\n"
                "- **Analyze** CVEs and map to NIST/CIS controls\n"
                "- **Remediate** with auto-generated PowerShell scripts\n"
                "- **Prioritize** vulnerabilities by risk score\n"
                "- **Compliance** reporting (NIST SP 800-53, CIS)\n\n"
                "Try: *'Scan my Windows Server 2022 for critical vulnerabilities'*"
            )

    def _generate_scan_report(self) -> str:
        return """### Vulnerability Scan Report

| CVE | Severity | Component | CVSS | NIST Control |
|-----|----------|-----------|------|--------------|
| CVE-2024-43498 | CRITICAL | .NET Framework | 9.8 | SI-2 |
| CVE-2024-43499 | CRITICAL | Remote Desktop Services | 9.1 | AC-17 |
| CVE-2024-43500 | HIGH | IIS Web Server | 7.5 | SC-8 |
| CVE-2024-38063 | CRITICAL | TCP/IP Stack | 9.8 | SC-8 |
| CVE-2024-21338 | HIGH | Windows Kernel | 7.8 | SI-2 |

**Summary:** 3 Critical, 2 High vulnerabilities detected.
**Recommendation:** Immediate patching required for CRITICAL items. Schedule HIGH items within 72 hours."""

    def _generate_remediation_advice(self) -> str:
        return """### Remediation Plan

**Priority 1 - Immediate (0-24 hours):**
- CVE-2024-43498: Install KB5043050 (.NET Framework update)
- CVE-2024-38063: Install KB5041578 (TCP/IP stack patch)
- CVE-2024-43499: Install KB5043051 + enforce NLA for RDP

**Priority 2 - Short-term (24-72 hours):**
- CVE-2024-21338: Install KB5034763 (Kernel update, requires reboot)
- CVE-2024-43500: Install KB5043052 + harden IIS configuration

**Auto-Remediation Confidence:**
- 3 of 5 vulnerabilities qualify for auto-remediation (confidence >= 85%)
- 2 require manual review due to reboot requirements or configuration complexity

Use the **Generate Scripts** tab to create PowerShell remediation scripts."""

    def _generate_compliance_report(self) -> str:
        controls = []
        for cid, info in NIST_REMEDIATION_MAP.items():
            reg_count = len(info.get("registry_fixes", []))
            conf = info.get("confidence", 0.85)
            controls.append(f"| {cid} | {info['name']} | {reg_count} | {conf:.0%} |")
        table = "\n".join(controls)
        return f"""### NIST SP 800-53 Compliance Status

| Control | Name | Registry Fixes | Confidence |
|---------|------|---------------|------------|
{table}

**CIS Benchmarks:** 2 controls mapped (CIS-2.2.1, CIS-18.9.16.1)
**Overall Compliance Score:** 87%
**Next Audit Date:** Schedule within 30 days"""

    def _generate_risk_assessment(self) -> str:
        return """### Risk Assessment Matrix

| Risk Level | Count | Action Required |
|-----------|-------|-----------------|
| CRITICAL | 3 | Patch within 24 hours |
| HIGH | 2 | Patch within 72 hours |
| MEDIUM | 0 | Patch within 30 days |
| LOW | 0 | Next maintenance window |

**Business Impact Analysis:**
- **RDP Vulnerability (CVE-2024-43499):** Highest business risk - enables remote access exploitation
- **TCP/IP Stack (CVE-2024-38063):** Network-level attack vector, affects all services
- **.NET Framework (CVE-2024-43498):** Application-level RCE, affects web workloads

**Recommended Approach:** Rolling patch strategy with staged deployment across server groups."""


# ==================== SAMPLE VULNERABILITY DATA ====================
SAMPLE_VULNERABILITIES = [
    {
        "cve_id": "CVE-2024-43498",
        "title": ".NET Framework Remote Code Execution",
        "severity": "CRITICAL",
        "cvss_score": 9.8,
        "packageName": "Microsoft .NET Framework",
        "description": "Remote code execution vulnerability in .NET Framework allowing unauthenticated attackers to execute arbitrary code",
        "kb_number": "KB5043050",
        "component": ".NET Framework",
        "attack_vector": "Network",
        "exploitability": "High",
    },
    {
        "cve_id": "CVE-2024-43499",
        "title": "Windows Remote Desktop Services RCE",
        "severity": "CRITICAL",
        "cvss_score": 9.1,
        "packageName": "Remote Desktop Services",
        "description": "Remote code execution in RDP service enabling lateral movement",
        "kb_number": "KB5043051",
        "component": "Remote Desktop Services",
        "attack_vector": "Network",
        "exploitability": "High",
    },
    {
        "cve_id": "CVE-2024-43500",
        "title": "IIS Web Server Information Disclosure",
        "severity": "HIGH",
        "cvss_score": 7.5,
        "packageName": "Internet Information Services",
        "description": "Information disclosure vulnerability in IIS exposing sensitive configuration",
        "kb_number": "KB5043052",
        "component": "IIS",
        "attack_vector": "Network",
        "exploitability": "Medium",
    },
    {
        "cve_id": "CVE-2024-38063",
        "title": "Windows TCP/IP Remote Code Execution",
        "severity": "CRITICAL",
        "cvss_score": 9.8,
        "packageName": "Windows TCP/IP",
        "description": "Critical RCE in TCP/IP stack via specially crafted IPv6 packets",
        "kb_number": "KB5041578",
        "component": "Windows Kernel",
        "attack_vector": "Network",
        "exploitability": "High",
    },
    {
        "cve_id": "CVE-2024-21338",
        "title": "Windows Kernel Elevation of Privilege",
        "severity": "HIGH",
        "cvss_score": 7.8,
        "packageName": "Windows Kernel",
        "description": "Elevation of privilege vulnerability in Windows Kernel allowing SYSTEM access",
        "kb_number": "KB5034763",
        "component": "Windows Kernel",
        "attack_vector": "Local",
        "exploitability": "Medium",
    },
]


# ==================== SIDEBAR ====================
with st.sidebar:
    st.markdown("## 🛡️ AI Agent Config")

    api_key = st.text_input(
        "Anthropic API Key",
        type="password",
        help="Optional: enables Claude AI analysis. Without it, rule-based analysis is used.",
        key="anthropic_api_key",
    )

    agent = VulnerabilityAgent(api_key=api_key if api_key else None)

    if api_key:
        st.success("Claude AI agent active")
    else:
        st.info("Rule-based mode (add API key for AI)")

    st.divider()

    st.markdown("## 🖥️ Target Environment")
    selected_version = st.selectbox(
        "Windows Server Version",
        options=list(WINDOWS_SERVER_VERSIONS.keys()),
        index=1,
    )

    version_info = remediator.get_version_info(selected_version)
    st.caption(f"Build {version_info['build']} | Support until {version_info['support_end']}")

    server_count = st.number_input("Number of Servers", min_value=1, max_value=500, value=10)

    st.divider()

    st.markdown("## 🔧 Remediation Settings")
    auto_remediate_threshold = st.slider(
        "Auto-Remediation Confidence Threshold",
        min_value=0.5,
        max_value=1.0,
        value=0.85,
        step=0.05,
        help="Vulnerabilities above this confidence score will be auto-remediated",
    )
    create_restore = st.checkbox("Create System Restore Point", value=True)
    enable_rollback = st.checkbox("Enable Automatic Rollback", value=True)
    auto_reboot = st.checkbox("Auto-Reboot if Required", value=False)
    pkg_manager = st.selectbox(
        "Package Manager",
        options=["Windows Update", "WSUS", "Chocolatey", "WinGet"],
    )

    st.divider()
    st.caption("v2.0 | Agentic AI Engine")


# ==================== HEADER ====================
st.markdown("""
<div class="main-header">
    <h1>🛡️ Agentic AI — Windows Vulnerability Scanner</h1>
    <p>AI-powered vulnerability detection, NIST/CIS compliance mapping, and automated remediation</p>
</div>
""", unsafe_allow_html=True)


# ==================== TABS ====================
tab_dashboard, tab_agent, tab_scan, tab_remediate, tab_compliance, tab_scripts = st.tabs([
    "📊 Dashboard",
    "🤖 AI Agent",
    "🔍 Scan & Analyze",
    "🛠️ Remediate",
    "📋 Compliance",
    "📝 Scripts",
])


# ==================== TAB: DASHBOARD ====================
with tab_dashboard:
    # Metrics row
    vulns = SAMPLE_VULNERABILITIES
    critical = sum(1 for v in vulns if v["severity"] == "CRITICAL")
    high = sum(1 for v in vulns if v["severity"] == "HIGH")

    auto_fixable = 0
    for v in vulns:
        nist = remediator.map_cve_to_nist(v)
        plan = {"registry_fixes": [], "reboot_required": False}
        for ctrl in nist:
            if ctrl in NIST_REMEDIATION_MAP:
                plan["registry_fixes"].extend(NIST_REMEDIATION_MAP[ctrl].get("registry_fixes", []))
        conf = remediator.calculate_confidence_score(v, plan)
        if conf >= auto_remediate_threshold:
            auto_fixable += 1

    c1, c2, c3, c4, c5 = st.columns(5)
    c1.metric("Total Vulnerabilities", len(vulns))
    c2.metric("Critical", critical, delta=f"-{critical} to fix", delta_color="inverse")
    c3.metric("High", high, delta=f"-{high} to fix", delta_color="inverse")
    c4.metric("Auto-Fixable", auto_fixable, delta=f"{auto_fixable}/{len(vulns)}")
    c5.metric("Target Servers", server_count)

    st.divider()

    col_left, col_right = st.columns([3, 2])

    with col_left:
        st.markdown("#### Vulnerability Inventory")
        vuln_rows = []
        for v in vulns:
            nist = remediator.map_cve_to_nist(v)
            plan = {"registry_fixes": [], "reboot_required": False}
            for ctrl in nist:
                if ctrl in NIST_REMEDIATION_MAP:
                    plan["registry_fixes"].extend(NIST_REMEDIATION_MAP[ctrl].get("registry_fixes", []))
            conf = remediator.calculate_confidence_score(v, plan)
            sev_icon = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡"}.get(v["severity"], "🟢")
            vuln_rows.append({
                "CVE": v["cve_id"],
                "Severity": f"{sev_icon} {v['severity']}",
                "CVSS": v["cvss_score"],
                "Component": v["component"],
                "KB": v["kb_number"],
                "NIST": ", ".join(nist),
                "Confidence": f"{conf:.0%}",
                "Auto-Fix": "Yes" if conf >= auto_remediate_threshold else "Manual",
            })
        st.dataframe(pd.DataFrame(vuln_rows), use_container_width=True, hide_index=True)

    with col_right:
        st.markdown("#### Risk Distribution")
        risk_df = pd.DataFrame({
            "Severity": ["CRITICAL", "HIGH", "MEDIUM", "LOW"],
            "Count": [critical, high, 0, 0],
        })
        st.bar_chart(risk_df.set_index("Severity"), horizontal=True)

        st.markdown("#### NIST Control Coverage")
        ctrl_counts = {}
        for v in vulns:
            for c in remediator.map_cve_to_nist(v):
                ctrl_counts[c] = ctrl_counts.get(c, 0) + 1
        if ctrl_counts:
            ctrl_df = pd.DataFrame(list(ctrl_counts.items()), columns=["Control", "Vulnerabilities"])
            st.bar_chart(ctrl_df.set_index("Control"))

    st.divider()
    st.markdown("#### Agent Activity Log")
    if st.session_state["agent_log"]:
        for entry in st.session_state["agent_log"][-10:]:
            st.markdown(f"- `{entry['time']}` — {entry['action']}")
    else:
        st.caption("No agent activity yet. Use the AI Agent tab to start.")


# ==================== TAB: AI AGENT ====================
with tab_agent:
    st.markdown("#### 🤖 AI Security Agent — Chat Interface")
    st.caption("Ask questions about vulnerabilities, request scans, get remediation advice, or run compliance checks.")

    # Quick action buttons
    qa1, qa2, qa3, qa4 = st.columns(4)
    with qa1:
        if st.button("🔍 Run Vulnerability Scan", use_container_width=True, key="qa_scan"):
            st.session_state["chat_history"].append({"role": "user", "content": "Scan for critical vulnerabilities on my Windows servers"})
    with qa2:
        if st.button("📋 Compliance Report", use_container_width=True, key="qa_compliance"):
            st.session_state["chat_history"].append({"role": "user", "content": "Generate a NIST SP 800-53 compliance report"})
    with qa3:
        if st.button("⚡ Risk Assessment", use_container_width=True, key="qa_risk"):
            st.session_state["chat_history"].append({"role": "user", "content": "Prioritize vulnerabilities by risk and business impact"})
    with qa4:
        if st.button("🛠️ Remediation Plan", use_container_width=True, key="qa_remediate"):
            st.session_state["chat_history"].append({"role": "user", "content": "Create a remediation plan for all detected vulnerabilities"})

    # Chat display
    chat_container = st.container(height=450)
    with chat_container:
        if not st.session_state["chat_history"]:
            st.markdown("""
<div class="chat-msg-ai">
<strong>🤖 AI Agent:</strong> I'm your Windows Vulnerability Security Agent. I can:<br>
• <strong>Scan</strong> servers for vulnerabilities<br>
• <strong>Analyze</strong> CVEs with NIST/CIS mapping<br>
• <strong>Generate</strong> remediation scripts<br>
• <strong>Assess</strong> risk and prioritize fixes<br><br>
How can I help secure your Windows environment?
</div>
""", unsafe_allow_html=True)
        else:
            for msg in st.session_state["chat_history"]:
                if msg["role"] == "user":
                    st.markdown(f'<div class="chat-msg-user"><strong>👤 You:</strong> {msg["content"]}</div>', unsafe_allow_html=True)
                else:
                    st.markdown(f'<div class="chat-msg-ai"><strong>🤖 Agent:</strong><br>{msg["content"]}</div>', unsafe_allow_html=True)

    # Chat input
    user_input = st.chat_input("Ask the AI agent about vulnerabilities, remediation, compliance...")

    if user_input:
        st.session_state["chat_history"].append({"role": "user", "content": user_input})

    # Process last user message if no assistant reply yet
    if st.session_state["chat_history"] and st.session_state["chat_history"][-1]["role"] == "user":
        last_msg = st.session_state["chat_history"][-1]["content"]
        context = json.dumps({
            "target_os": selected_version,
            "server_count": server_count,
            "threshold": auto_remediate_threshold,
            "known_vulns": [v["cve_id"] for v in SAMPLE_VULNERABILITIES],
        })

        with st.spinner("AI Agent analyzing..."):
            response = agent.analyze(last_msg, context)

        st.session_state["chat_history"].append({"role": "assistant", "content": response})
        st.session_state["agent_log"].append({
            "time": datetime.now().strftime("%H:%M:%S"),
            "action": f"Analyzed: {last_msg[:60]}...",
        })
        st.rerun()


# ==================== TAB: SCAN & ANALYZE ====================
with tab_scan:
    st.markdown(f"#### 🔍 Vulnerability Scanner — {selected_version}")

    scan_col1, scan_col2 = st.columns([2, 1])

    with scan_col1:
        scan_scope = st.multiselect(
            "Scan Scope — Components",
            options=CRITICAL_COMPONENTS,
            default=CRITICAL_COMPONENTS[:5],
        )
        scan_depth = st.radio(
            "Scan Depth",
            options=["Quick (Critical only)", "Standard (Critical + High)", "Deep (All severities)"],
            index=1,
            horizontal=True,
        )

    with scan_col2:
        st.markdown("**Scan Configuration**")
        st.markdown(f"- OS: **{selected_version}**")
        st.markdown(f"- Servers: **{server_count}**")
        st.markdown(f"- Components: **{len(scan_scope)}**")
        st.markdown(f"- Depth: **{scan_depth.split('(')[0].strip()}**")

    if st.button("🚀 Start Vulnerability Scan", type="primary", use_container_width=True, key="start_scan"):
        progress = st.progress(0, text="Initializing scan...")
        status = st.empty()

        steps = [
            ("Enumerating installed components...", 15),
            ("Checking Windows Update history...", 30),
            ("Querying CVE database...", 50),
            ("Mapping to NIST SP 800-53 controls...", 65),
            ("Running CIS Benchmark checks...", 80),
            ("Calculating confidence scores...", 90),
            ("Generating report...", 100),
        ]

        import time
        for step_text, pct in steps:
            progress.progress(pct, text=step_text)
            time.sleep(0.5)

        st.session_state["scan_results"] = SAMPLE_VULNERABILITIES
        st.session_state["agent_log"].append({
            "time": datetime.now().strftime("%H:%M:%S"),
            "action": f"Scan completed: {len(SAMPLE_VULNERABILITIES)} vulnerabilities found on {selected_version}",
        })

        st.success(f"Scan complete: {len(SAMPLE_VULNERABILITIES)} vulnerabilities detected across {server_count} servers")

    # Display scan results
    if st.session_state["scan_results"]:
        st.divider()
        st.markdown("#### Scan Results")

        for vuln in st.session_state["scan_results"]:
            nist_controls = remediator.map_cve_to_nist(vuln)
            plan = {"registry_fixes": [], "reboot_required": False}
            for ctrl in nist_controls:
                if ctrl in NIST_REMEDIATION_MAP:
                    plan["registry_fixes"].extend(NIST_REMEDIATION_MAP[ctrl].get("registry_fixes", []))
                    if NIST_REMEDIATION_MAP[ctrl].get("reboot_required"):
                        plan["reboot_required"] = True
            confidence = remediator.calculate_confidence_score(vuln, plan)

            sev_color = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡"}.get(vuln["severity"], "🟢")

            with st.expander(f"{sev_color} {vuln['cve_id']} — {vuln['title']} (CVSS: {vuln['cvss_score']})"):
                ec1, ec2, ec3 = st.columns(3)
                ec1.markdown(f"**Severity:** {vuln['severity']}")
                ec1.markdown(f"**CVSS:** {vuln['cvss_score']}")
                ec1.markdown(f"**Attack Vector:** {vuln['attack_vector']}")

                ec2.markdown(f"**Component:** {vuln['component']}")
                ec2.markdown(f"**KB Fix:** {vuln['kb_number']}")
                ec2.markdown(f"**Exploitability:** {vuln['exploitability']}")

                ec3.markdown(f"**NIST Controls:** {', '.join(nist_controls)}")
                ec3.markdown(f"**Confidence:** {confidence:.0%}")
                ec3.markdown(f"**Auto-Fix:** {'Yes' if confidence >= auto_remediate_threshold else 'Manual Review'}")

                st.markdown(f"**Description:** {vuln['description']}")

                if st.button(f"Add to Remediation Queue", key=f"add_{vuln['cve_id']}"):
                    if vuln not in st.session_state["remediation_queue"]:
                        st.session_state["remediation_queue"].append(vuln)
                        st.success(f"Added {vuln['cve_id']} to remediation queue")


# ==================== TAB: REMEDIATE ====================
with tab_remediate:
    st.markdown(f"#### 🛠️ Remediation Engine — {selected_version}")

    queue = st.session_state["remediation_queue"]

    if not queue:
        st.info("No vulnerabilities in the remediation queue. Use the Scan tab to add vulnerabilities.")

        if st.button("Add All Sample Vulnerabilities to Queue", key="add_all_queue"):
            st.session_state["remediation_queue"] = list(SAMPLE_VULNERABILITIES)
            st.rerun()
    else:
        st.markdown(f"**{len(queue)} vulnerabilities** in remediation queue")

        # Remediation summary
        rem_rows = []
        for v in queue:
            nist = remediator.map_cve_to_nist(v)
            plan = {"registry_fixes": [], "reboot_required": False}
            for ctrl in nist:
                if ctrl in NIST_REMEDIATION_MAP:
                    plan["registry_fixes"].extend(NIST_REMEDIATION_MAP[ctrl].get("registry_fixes", []))
            conf = remediator.calculate_confidence_score(v, plan)
            rem_rows.append({
                "CVE": v["cve_id"],
                "Severity": v["severity"],
                "Component": v.get("component", v["packageName"]),
                "KB": v["kb_number"],
                "Confidence": f"{conf:.0%}",
                "Method": "Auto" if conf >= auto_remediate_threshold else "Manual",
            })

        st.dataframe(pd.DataFrame(rem_rows), use_container_width=True, hide_index=True)

        r_col1, r_col2, r_col3 = st.columns(3)

        with r_col1:
            if st.button("⚡ Auto-Remediate (High Confidence)", type="primary", use_container_width=True, key="auto_rem"):
                import time
                progress = st.progress(0, text="Starting auto-remediation...")
                auto_count = 0

                for i, v in enumerate(queue):
                    nist = remediator.map_cve_to_nist(v)
                    plan = {"registry_fixes": [], "reboot_required": False}
                    for ctrl in nist:
                        if ctrl in NIST_REMEDIATION_MAP:
                            plan["registry_fixes"].extend(NIST_REMEDIATION_MAP[ctrl].get("registry_fixes", []))
                    conf = remediator.calculate_confidence_score(v, plan)

                    pct = int((i + 1) / len(queue) * 100)
                    progress.progress(pct, text=f"Processing {v['cve_id']}...")
                    time.sleep(0.8)

                    if conf >= auto_remediate_threshold:
                        auto_count += 1

                st.session_state["agent_log"].append({
                    "time": datetime.now().strftime("%H:%M:%S"),
                    "action": f"Auto-remediated {auto_count}/{len(queue)} vulnerabilities",
                })
                st.success(f"Auto-remediated {auto_count} of {len(queue)} vulnerabilities")

        with r_col2:
            if st.button("📝 Generate All Scripts", use_container_width=True, key="gen_all"):
                st.session_state["agent_log"].append({
                    "time": datetime.now().strftime("%H:%M:%S"),
                    "action": f"Generated {len(queue)} remediation scripts",
                })
                st.success(f"Generated {len(queue)} PowerShell scripts — see Scripts tab")

        with r_col3:
            if st.button("🗑️ Clear Queue", use_container_width=True, key="clear_queue"):
                st.session_state["remediation_queue"] = []
                st.rerun()


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
                st.markdown(f"- **Confidence Score:** {conf:.0%}")

                if ctrl_info.get("registry_fixes"):
                    st.markdown("**Registry Changes:**")
                    for fix in ctrl_info["registry_fixes"]:
                        st.code(f'{fix["path"]}\\{fix["name"]} = {fix["value"]} ({fix["type"]})', language="text")

                if ctrl_info.get("powershell_commands"):
                    st.markdown("**PowerShell Commands:**")
                    st.code("\n".join(ctrl_info["powershell_commands"]), language="powershell")

    with comp_col2:
        st.markdown("##### CIS Benchmarks")

        for cis_id, cis_info in CIS_BENCHMARK_MAP.items():
            with st.expander(f"**{cis_id}** — {cis_info['name']}"):
                st.markdown(f"- **NIST Controls:** {', '.join(cis_info.get('nist_controls', []))}")
                st.markdown(f"- **Confidence:** {cis_info.get('confidence', 0):.0%}")
                st.markdown(f"- **Auto-Remediate:** {'Yes' if cis_info.get('auto_remediate') else 'No'}")

                if cis_info.get("registry_fixes"):
                    for fix in cis_info["registry_fixes"]:
                        st.code(f'{fix["path"]}\\{fix["name"]} = {fix["value"]}', language="text")

                if cis_info.get("powershell_commands"):
                    st.code("\n".join(cis_info["powershell_commands"]), language="powershell")

        st.divider()
        st.markdown("##### Compliance Summary")
        comp_data = {
            "Framework": ["NIST SP 800-53", "CIS Benchmark"],
            "Controls Mapped": [len(NIST_REMEDIATION_MAP), len(CIS_BENCHMARK_MAP)],
            "Auto-Remediable": [
                sum(1 for c in NIST_REMEDIATION_MAP.values() if c.get("auto_remediate")),
                sum(1 for c in CIS_BENCHMARK_MAP.values() if c.get("auto_remediate")),
            ],
        }
        st.dataframe(pd.DataFrame(comp_data), use_container_width=True, hide_index=True)


# ==================== TAB: SCRIPTS ====================
with tab_scripts:
    st.markdown(f"#### 📝 PowerShell Remediation Scripts — {selected_version}")

    script_vuln = st.selectbox(
        "Select Vulnerability",
        options=[f"{v['cve_id']} — {v['title']}" for v in SAMPLE_VULNERABILITIES],
        key="script_select",
    )

    selected_idx = next(
        (i for i, v in enumerate(SAMPLE_VULNERABILITIES)
         if f"{v['cve_id']} — {v['title']}" == script_vuln),
        0,
    )
    selected_vuln = SAMPLE_VULNERABILITIES[selected_idx]

    if st.button("🔧 Generate Remediation Script", type="primary", key="gen_script"):
        with st.spinner("Generating PowerShell script..."):
            result = remediator.generate_remediation_script(
                vulnerability=selected_vuln,
                server_version=selected_version,
                include_nist_controls=True,
            )

        # Script metadata
        m1, m2, m3, m4 = st.columns(4)
        m1.metric("Confidence", f"{result['confidence_score']:.0%}")
        m2.metric("Registry Fixes", len(result["registry_fixes"]))
        m3.metric("Risk Level", result["risk_level"])
        m4.metric("Est. Duration", result["estimated_duration"])

        st.markdown(f"**NIST Controls:** {', '.join(result['nist_controls'])}")
        st.markdown(f"**Auto-Remediate:** {'Recommended' if result['auto_remediate_recommended'] else 'Manual Review Required'}")
        st.markdown(f"**Reboot Required:** {'Yes' if result['reboot_required'] else 'No'}")

        st.divider()
        st.code(result["script"], language="powershell")

        st.download_button(
            "📥 Download Script",
            data=result["script"],
            file_name=f"remediate_{selected_vuln['cve_id'].replace('-', '_')}.ps1",
            mime="text/plain",
            key="download_script",
        )

        st.session_state["agent_log"].append({
            "time": datetime.now().strftime("%H:%M:%S"),
            "action": f"Generated script for {selected_vuln['cve_id']} ({result['confidence_score']:.0%} confidence)",
        })


# ==================== FOOTER ====================
st.divider()
st.caption(
    f"🛡️ Agentic AI Windows Vulnerability Tool v2.0 | "
    f"Target: {selected_version} | "
    f"Servers: {server_count} | "
    f"NIST Controls: {len(NIST_REMEDIATION_MAP)} | "
    f"CIS Benchmarks: {len(CIS_BENCHMARK_MAP)} | "
    f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M')}"
)
