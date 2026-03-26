"""Generate VulnShield AI presentation deck."""

from pptx import Presentation
from pptx.util import Inches, Pt, Emu
from pptx.dml.color import RGBColor
from pptx.enum.text import PP_ALIGN, MSO_ANCHOR
from pptx.enum.shapes import MSO_SHAPE

# Colors
DARK_BG = RGBColor(0x0A, 0x0A, 0x23)
BLUE = RGBColor(0x0F, 0x34, 0x60)
LIGHT_BLUE = RGBColor(0x3B, 0x82, 0xF6)
PURPLE = RGBColor(0x8B, 0x5C, 0xF6)
WHITE = RGBColor(0xFF, 0xFF, 0xFF)
LIGHT_GRAY = RGBColor(0xA8, 0xB2, 0xD1)
GREEN = RGBColor(0x28, 0xA7, 0x45)
RED = RGBColor(0xDC, 0x35, 0x45)
ORANGE = RGBColor(0xFD, 0x7E, 0x14)
YELLOW = RGBColor(0xFF, 0xC1, 0x07)

prs = Presentation()
prs.slide_width = Inches(13.333)
prs.slide_height = Inches(7.5)


def add_dark_bg(slide):
    bg = slide.background
    fill = bg.fill
    fill.solid()
    fill.fore_color.rgb = DARK_BG


def add_title_box(slide, title, subtitle="", y=Inches(0.5)):
    txBox = slide.shapes.add_textbox(Inches(0.8), y, Inches(11.5), Inches(1.2))
    tf = txBox.text_frame
    tf.word_wrap = True
    p = tf.paragraphs[0]
    p.text = title
    p.font.size = Pt(36)
    p.font.bold = True
    p.font.color.rgb = WHITE
    if subtitle:
        p2 = tf.add_paragraph()
        p2.text = subtitle
        p2.font.size = Pt(16)
        p2.font.color.rgb = LIGHT_GRAY


def add_body_text(slide, text, x=Inches(0.8), y=Inches(2.0), width=Inches(11.5), size=Pt(16), color=LIGHT_GRAY):
    txBox = slide.shapes.add_textbox(x, y, width, Inches(5))
    tf = txBox.text_frame
    tf.word_wrap = True
    for i, line in enumerate(text.split("\n")):
        if i == 0:
            p = tf.paragraphs[0]
        else:
            p = tf.add_paragraph()
        p.text = line
        p.font.size = size
        p.font.color.rgb = color
        p.space_after = Pt(6)
    return txBox


def add_table(slide, rows, col_widths, x=Inches(0.8), y=Inches(2.5)):
    table_shape = slide.shapes.add_table(len(rows), len(rows[0]), x, y, sum(col_widths), Inches(0.4) * len(rows))
    table = table_shape.table

    for ci, w in enumerate(col_widths):
        table.columns[ci].width = w

    for ri, row in enumerate(rows):
        for ci, cell_text in enumerate(row):
            cell = table.cell(ri, ci)
            cell.text = cell_text
            for paragraph in cell.text_frame.paragraphs:
                paragraph.font.size = Pt(12)
                if ri == 0:
                    paragraph.font.bold = True
                    paragraph.font.color.rgb = WHITE
                else:
                    paragraph.font.color.rgb = LIGHT_GRAY
            if ri == 0:
                cell.fill.solid()
                cell.fill.fore_color.rgb = BLUE
            else:
                cell.fill.solid()
                cell.fill.fore_color.rgb = RGBColor(0x12, 0x12, 0x30)
    return table_shape


# ==================== SLIDE 1: Title ====================
slide = prs.slides.add_slide(prs.slide_layouts[6])  # Blank
add_dark_bg(slide)
txBox = slide.shapes.add_textbox(Inches(1), Inches(2), Inches(11), Inches(3))
tf = txBox.text_frame
tf.word_wrap = True
p = tf.paragraphs[0]
p.text = "VulnShield AI"
p.font.size = Pt(54)
p.font.bold = True
p.font.color.rgb = WHITE
p.alignment = PP_ALIGN.CENTER

p2 = tf.add_paragraph()
p2.text = "Autonomous AI Security Engineer for Windows Server Vulnerability Management"
p2.font.size = Pt(20)
p2.font.color.rgb = LIGHT_BLUE
p2.alignment = PP_ALIGN.CENTER

p3 = tf.add_paragraph()
p3.text = "\nMulti-Account AWS  |  SSM Patch Manager  |  ServiceNow ITSM  |  Human-in-the-Loop"
p3.font.size = Pt(14)
p3.font.color.rgb = LIGHT_GRAY
p3.alignment = PP_ALIGN.CENTER

p4 = tf.add_paragraph()
p4.text = "\n12 AI Agents  |  Natural Language Policies  |  Perceive-Reason-Act-Learn"
p4.font.size = Pt(14)
p4.font.color.rgb = PURPLE
p4.alignment = PP_ALIGN.CENTER


# ==================== SLIDE 2: The Problem ====================
slide = prs.slides.add_slide(prs.slide_layouts[6])
add_dark_bg(slide)
add_title_box(slide, "The Problem", "Why existing tools fall short")
add_body_text(slide, """Enterprise Windows Server patching is broken:

   10,000+ Windows Servers across 200+ AWS accounts
   New CVEs published daily  -  CISA KEV alerts for active exploits
   Manual triage takes hours  -  patch cycles take weeks
   No AI reasoning  -  just "install this KB"
   Qualys/Tenable: $200K-300K/year  -  still requires manual decisions

The gap: No tool REASONS about whether to patch, who to notify,
or what change ticket to create.  Humans make every decision.

What if an AI agent could do this autonomously, 24/7?""")


# ==================== SLIDE 3: The Solution ====================
slide = prs.slides.add_slide(prs.slide_layouts[6])
add_dark_bg(slide)
add_title_box(slide, "VulnShield AI  -  The Solution", "An autonomous AI security engineer, not a dashboard")
add_body_text(slide, """PERCEIVE    What changed?  (new CVE, compliance drift, new server)
                              NVD, CISA KEV, SSM Patch Manager, EC2 inventory

REASON       What should I do?  (LLM-powered decision making)
                              GPT-4o / Claude analyzes risk, reads policies, checks memory

ACT               Execute the decision
                              SSM Patch Manager, ServiceNow CHG, Slack/Teams, rollback

LEARN           Record outcome, adjust for next time
                              "Last patch on ERP caused outage  -  require approval next time"

REPORT        Notify humans only when needed
                              Proactive alerts, not reactive dashboards""")


# ==================== SLIDE 4: Architecture ====================
slide = prs.slides.add_slide(prs.slide_layouts[6])
add_dark_bg(slide)
add_title_box(slide, "Architecture  -  Hub & Spoke Multi-Account")
add_body_text(slide, """
Hub Account (448549863273)                    Spoke Accounts (200+)

   VulnShield AI Platform                        950766978386 (Cloud Migration)
      Autonomous Agent Loop                     123456789012 (Finance Prod)
      12 AI Agents                                      234567890123 (HR Systems)
      SSM Patch Manager                            345678901234 (ERP Platform)
      ServiceNow ITSM                                ...

         STS AssumeRole                           WindowsVulnScannerRole
         (cross-account)                             in each spoke account

   No agents to install.  SSM Agent is already on every Windows AMI.
   One IAM role per account.  Deploy via CloudFormation StackSets.
   200 accounts onboarded in under 1 hour.""")


# ==================== SLIDE 5: 12 AI Agents ====================
slide = prs.slides.add_slide(prs.slide_layouts[6])
add_dark_bg(slide)
add_title_box(slide, "12 Specialized AI Agents")
rows = [
    ["#", "Agent", "Purpose"],
    ["1", "Discovery Agent", "AWS Organizations + SSM inventory across accounts"],
    ["2", "Analysis Agent", "CVE analysis, NIST mapping, risk scoring (LLM-powered)"],
    ["3", "Decision Agent", "Confidence-based routing: auto / human / CHG"],
    ["4", "Remediation Agent", "SSM Patch Manager execution + PowerShell generation"],
    ["5", "Verification Agent", "Post-remediation validation"],
    ["6", "ITSM Agent", "ServiceNow CHG/INC/CMDB automation"],
    ["7", "Rollback Agent", "Auto-revert failed remediations"],
    ["8", "Notification Agent", "Slack, Teams, Email alerts by severity"],
    ["9", "Reporting Agent", "Executive PDF/HTML reports"],
    ["10", "Scheduling Agent", "Maintenance window enforcement + blackout periods"],
    ["11", "Compliance Drift Agent", "Continuous NIST/CIS baseline monitoring"],
    ["12", "Threat Intel Agent", "NVD, CISA KEV, EPSS enrichment + MITRE ATT&CK"],
]
add_table(slide, rows, [Inches(0.5), Inches(2.5), Inches(8.5)], y=Inches(1.8))


# ==================== SLIDE 6: Confidence Routing ====================
slide = prs.slides.add_slide(prs.slide_layouts[6])
add_dark_bg(slide)
add_title_box(slide, "AI Confidence-Based Routing", "The agent knows when to act and when to ask")
add_body_text(slide, """
   Confidence >= 90%           AUTO-REMEDIATE
      Execute immediately via SSM Patch Manager
      No human involvement needed
      Example: KB security update, well-tested, non-reboot

   Confidence 70-89%           HUMAN APPROVAL
      Queue in Approval Dashboard with AI reasoning
      Human reviews script + reasoning, approves/rejects
      Example: RDP config change on production

   Confidence < 70%              RAISE CHG TICKET
      Auto-create ServiceNow Change Request
      Full description, implementation plan, backout plan, test plan
      Example: Kernel update requiring maintenance window


   The AI doesn't just find vulnerabilities.  It fixes them,
   or knows when to stop and ask.""")


# ==================== SLIDE 7: Natural Language Policies ====================
slide = prs.slides.add_slide(prs.slide_layouts[6])
add_dark_bg(slide)
add_title_box(slide, "Natural Language Policies", "Plain English rules the AI follows  -  no YAML, no code")
rows = [
    ["Policy", "Rule (Plain English)"],
    ["Auto-patch non-prod", "Automatically patch all Dev and Staging servers without approval"],
    ["Production kernel guard", "Kernel updates on Production require human approval, even if confidence > 90%"],
    ["Critical CVE bypass", "CRITICAL CVEs with CVSS >= 9.0 can be patched outside maintenance windows"],
    ["ERP protection", "Any remediation on ERP/SAP servers must create a ServiceNow CHG ticket"],
    ["Stale patch escalation", "Servers unpatched > 30 days: escalate to security lead + create P2 incident"],
    ["Failure response", "Failed remediation: trigger Rollback Agent + create P1 incident"],
    ["Zero-day response", "New CISA KEV entry: scan fleet + notify security team within 15 minutes"],
]
add_table(slide, rows, [Inches(2.5), Inches(9)], y=Inches(1.8))


# ==================== SLIDE 8: Real AWS Demo ====================
slide = prs.slides.add_slide(prs.slide_layouts[6])
add_dark_bg(slide)
add_title_box(slide, "Live Demo  -  Real AWS Servers")
rows = [
    ["Server", "Instance ID", "Account", "Region", "OS", "SSM", "Status"],
    ["FinOps", "i-0e284388d8c8e9b79", "448549863273", "us-west-1", "Win Server 2025", "Online", "Running"],
    ["WAFR", "i-03f775ac21c5bc3fe", "448549863273", "us-west-1", "Win Server 2025", "Online", "Running"],
    ["ML-Server", "i-0d381382940e69845", "448549863273", "us-east-1", "Windows Server", "Offline", "Running"],
    ["FinOps", "i-07d45c3c9b49fdba8", "950766978386", "us-east-1", "Windows Server", "Pending", "Running"],
    ["+ 8 more", "...", "448549863273", "3 regions", "Windows Server", "Offline", "Stopped"],
]
add_table(slide, rows, [Inches(1.2), Inches(2.2), Inches(1.5), Inches(1.2), Inches(1.8), Inches(1), Inches(1)], y=Inches(1.8))

add_body_text(slide, """Real Finding: Both FinOps + WAFR are missing KB5078740 (March 2026 Critical Security Update)
Real Finding: TLS 1.2 is NOT enabled on production servers
Real Finding: RDP (3389), SMB (445), WinRM (5985) ports open""", y=Inches(5), size=Pt(14), color=ORANGE)


# ==================== SLIDE 9: SSM Patch Manager ====================
slide = prs.slides.add_slide(prs.slide_layouts[6])
add_dark_bg(slide)
add_title_box(slide, "SSM Patch Manager Integration", "Production-grade patching  -  not custom scripts")
add_body_text(slide, """
   Custom Baseline:  VulnShield-Critical-Security (pb-0aa04b12d28ff3abc)
      Critical + Security updates,  0-day auto-approval

   Patch Groups:  Tag-based server grouping
      PatchGroup = VulnShield-Critical-Security

   Compliance Scan:  AWS-RunPatchBaseline (Scan operation)
      Real compliance data from AWS, not custom PowerShell

   Patch Install:  AWS-RunPatchBaseline (Install operation)
      With RebootIfNeeded control

   Maintenance Windows:  Real AWS SSM maintenance windows
      Scheduled via cron, enforced by the Scheduling Agent


   This is how AWS recommends enterprise patching.
   The AI adds the reasoning layer on top.""")


# ==================== SLIDE 10: ServiceNow ====================
slide = prs.slides.add_slide(prs.slide_layouts[6])
add_dark_bg(slide)
add_title_box(slide, "ServiceNow ITSM Integration", "Auto-create CHG tickets with full details in 2 seconds")
add_body_text(slide, """
   Change Requests (CHG):
      Auto-created for low-confidence vulnerabilities
      Full description: CVE, NIST controls, affected servers
      Implementation plan (5 steps)
      Backout plan (3 steps)
      Test plan (4 steps)
      Assigned to: Windows Server Team

   Incidents (INC):
      Auto-created for failed remediations or active exploits
      P1 severity for rollback events

   CMDB Sync:
      All Windows servers synced to ServiceNow CMDB
      Updated on every discovery cycle

   Instance: dev218436.service-now.com""")


# ==================== SLIDE 11: Market Comparison ====================
slide = prs.slides.add_slide(prs.slide_layouts[6])
add_dark_bg(slide)
add_title_box(slide, "Market Comparison")
rows = [
    ["Capability", "VulnShield AI", "Qualys VMDR", "Tenable.io", "CrowdStrike", "MS Defender"],
    ["Annual Cost", "$5-15K", "$200K+", "$150K+", "$300K+", "$60K+"],
    ["Truly Agentic AI", "YES", "No", "No", "No", "No"],
    ["Autonomous 24/7", "YES", "No", "No", "No", "No"],
    ["NL Policies", "YES", "No", "No", "No", "No"],
    ["Auto-Remediation", "Confidence-based", "Patch only", "No", "No", "Intune"],
    ["Human-in-Loop", "YES", "No", "No", "No", "No"],
    ["SSM Patch Manager", "Native", "No", "No", "No", "No"],
    ["ServiceNow Auto", "CHG+INC+CMDB", "Plugin", "Plugin", "Basic", "Logic Apps"],
    ["Memory/Learning", "YES", "No", "No", "No", "No"],
    ["Cross-Account", "AssumeRole", "Agent", "Agent", "Agent", "Azure Arc"],
]
add_table(slide, rows, [Inches(1.8), Inches(1.8), Inches(1.8), Inches(1.8), Inches(1.8), Inches(1.8)], y=Inches(1.6))


# ==================== SLIDE 12: ROI ====================
slide = prs.slides.add_slide(prs.slide_layouts[6])
add_dark_bg(slide)
add_title_box(slide, "Return on Investment")
add_body_text(slide, """
   Cost Savings:
      Qualys/Tenable replacement:         $150K - $250K / year
      Manual triage elimination:              $80K - $120K / year  (2 FTE analysts)
      Incident reduction (auto-patch):     $50K - $100K / year
      TOTAL SAVINGS:                             $280K - $470K / year

   VulnShield AI Cost:
      OpenAI API:                                      $2K - $5K / year
      AWS infrastructure:                           $1K - $3K / year
      Streamlit Cloud:                                $0 - $5K / year
      TOTAL COST:                                     $3K - $13K / year

   ROI:  20x - 35x return in year one

   Time Savings:
      Vulnerability triage:                          2 hours  ->  10 seconds
      Change request creation:                 30 minutes  ->  2 seconds
      Cross-account discovery:                 Days  ->  Minutes
      Compliance reporting:                      Hours  ->  Instant""")


# ==================== SLIDE 13: Closing ====================
slide = prs.slides.add_slide(prs.slide_layouts[6])
add_dark_bg(slide)
txBox = slide.shapes.add_textbox(Inches(1), Inches(2), Inches(11), Inches(3))
tf = txBox.text_frame
tf.word_wrap = True
p = tf.paragraphs[0]
p.text = "VulnShield AI"
p.font.size = Pt(48)
p.font.bold = True
p.font.color.rgb = WHITE
p.alignment = PP_ALIGN.CENTER

p2 = tf.add_paragraph()
p2.text = '"An autonomous AI security engineer that monitors, reasons, acts,\nand learns  -  24/7, across your entire Windows fleet."'
p2.font.size = Pt(20)
p2.font.italic = True
p2.font.color.rgb = LIGHT_BLUE
p2.alignment = PP_ALIGN.CENTER

p3 = tf.add_paragraph()
p3.text = "\n12 AI Agents  |  $5K vs $200K  |  7 decisions in 10 seconds"
p3.font.size = Pt(16)
p3.font.color.rgb = PURPLE
p3.alignment = PP_ALIGN.CENTER

p4 = tf.add_paragraph()
p4.text = "\nwinvulmgmt.streamlit.app"
p4.font.size = Pt(14)
p4.font.color.rgb = LIGHT_GRAY
p4.alignment = PP_ALIGN.CENTER


# Save
prs.save("C:/aiprojects/windowsvulnerabilitiies/VulnShield_AI_Presentation.pptx")
print("PPTX saved successfully")
