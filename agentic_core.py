"""
Agentic AI Core — Autonomous Security Engineer

This is the BRAIN of the system. Unlike a dashboard that waits for clicks,
this agent runs continuously, reasons about threats, and takes autonomous action.

Architecture:
  ┌─────────────────────────────────────────────────────┐
  │              AUTONOMOUS AGENT LOOP                   │
  │                                                      │
  │  while True:                                         │
  │    1. PERCEIVE  — What changed? (new CVE, drift,    │
  │                    new server, approval received)     │
  │    2. REASON    — What should I do? (LLM decides)   │
  │    3. ACT       — Execute the decision              │
  │    4. LEARN     — Record outcome, update memory     │
  │    5. REPORT    — Notify humans of actions taken     │
  │    sleep(interval)                                   │
  └─────────────────────────────────────────────────────┘

Agent Capabilities:
  - Perceive: NVD/CISA KEV feeds, SSM compliance changes, new EC2 instances
  - Reason: LLM-powered decision making with context from memory
  - Act: SSM Patch Manager, ServiceNow, Slack/Teams
  - Learn: Store outcomes, adjust confidence based on past results
  - Report: Proactive notifications, not just dashboards
"""

import json
import logging
import threading
import time
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Callable
from dataclasses import dataclass, field, asdict
from enum import Enum

logger = logging.getLogger(__name__)


# ==================== EVENT SYSTEM ====================

class EventType(Enum):
    NEW_CVE_PUBLISHED = "new_cve_published"
    COMPLIANCE_DRIFT = "compliance_drift"
    NEW_SERVER_DETECTED = "new_server_detected"
    SERVER_STATE_CHANGED = "server_state_changed"
    APPROVAL_RECEIVED = "approval_received"
    APPROVAL_REJECTED = "approval_rejected"
    REMEDIATION_COMPLETED = "remediation_completed"
    REMEDIATION_FAILED = "remediation_failed"
    PATCH_BASELINE_VIOLATION = "patch_baseline_violation"
    THREAT_INTEL_UPDATE = "threat_intel_update"
    SCHEDULED_SCAN = "scheduled_scan"
    POLICY_CHANGE = "policy_change"
    AGENT_HEARTBEAT = "agent_heartbeat"


@dataclass
class AgentEvent:
    """An event that the agent perceives and must reason about."""
    event_id: str
    event_type: str
    timestamp: str
    source: str
    data: Dict = field(default_factory=dict)
    priority: int = 5  # 1=critical, 5=info, 10=debug
    processed: bool = False
    action_taken: str = ""
    reasoning: str = ""

    def __post_init__(self):
        if not self.timestamp:
            self.timestamp = datetime.now().isoformat()
        if not self.event_id:
            self.event_id = f"EVT-{datetime.now().strftime('%Y%m%d%H%M%S%f')}"


# ==================== AGENT MEMORY ====================

@dataclass
class MemoryEntry:
    """A learned fact from past actions."""
    memory_id: str
    category: str  # server, vulnerability, decision, outcome, policy
    key: str
    value: str
    confidence: float = 1.0
    created_at: str = ""
    updated_at: str = ""
    access_count: int = 0

    def __post_init__(self):
        now = datetime.now().isoformat()
        if not self.created_at:
            self.created_at = now
        if not self.updated_at:
            self.updated_at = now


class AgentMemory:
    """
    Long-term memory for the autonomous agent.
    Stores learned patterns, server-specific knowledge, and decision outcomes.
    """

    def __init__(self):
        self._memories: Dict[str, MemoryEntry] = {}

    def remember(self, category: str, key: str, value: str, confidence: float = 1.0):
        """Store or update a memory."""
        mem_id = f"{category}:{key}"
        if mem_id in self._memories:
            self._memories[mem_id].value = value
            self._memories[mem_id].confidence = confidence
            self._memories[mem_id].updated_at = datetime.now().isoformat()
            self._memories[mem_id].access_count += 1
        else:
            self._memories[mem_id] = MemoryEntry(
                memory_id=mem_id,
                category=category,
                key=key,
                value=value,
                confidence=confidence,
            )

    def recall(self, category: str, key: str) -> Optional[str]:
        """Recall a specific memory."""
        mem_id = f"{category}:{key}"
        if mem_id in self._memories:
            self._memories[mem_id].access_count += 1
            return self._memories[mem_id].value
        return None

    def recall_category(self, category: str) -> List[MemoryEntry]:
        """Recall all memories in a category."""
        return [m for m in self._memories.values() if m.category == category]

    def search(self, query: str) -> List[MemoryEntry]:
        """Search memories by keyword."""
        query_lower = query.lower()
        return [
            m for m in self._memories.values()
            if query_lower in m.key.lower() or query_lower in m.value.lower()
        ]

    def forget(self, category: str, key: str):
        """Remove a memory."""
        mem_id = f"{category}:{key}"
        self._memories.pop(mem_id, None)

    def get_context_for_reasoning(self, server_id: str = None, cve_id: str = None) -> str:
        """Build a context string from relevant memories for LLM reasoning."""
        relevant = []

        if server_id:
            server_memories = self.search(server_id)
            for m in server_memories:
                relevant.append(f"[{m.category}] {m.key}: {m.value}")

        if cve_id:
            cve_memories = self.search(cve_id)
            for m in cve_memories:
                relevant.append(f"[{m.category}] {m.key}: {m.value}")

        # Always include policies
        policies = self.recall_category("policy")
        for p in policies:
            relevant.append(f"[policy] {p.key}: {p.value}")

        # Include recent outcomes
        outcomes = self.recall_category("outcome")
        for o in sorted(outcomes, key=lambda x: x.updated_at, reverse=True)[:5]:
            relevant.append(f"[outcome] {o.key}: {o.value}")

        return "\n".join(relevant) if relevant else "No relevant memories."

    def to_dict(self) -> List[Dict]:
        return [asdict(m) for m in self._memories.values()]

    def stats(self) -> Dict:
        categories = {}
        for m in self._memories.values():
            categories[m.category] = categories.get(m.category, 0) + 1
        return {
            "total_memories": len(self._memories),
            "categories": categories,
        }


# ==================== NATURAL LANGUAGE POLICY ENGINE ====================

@dataclass
class Policy:
    """A natural language policy that governs agent behavior."""
    policy_id: str
    name: str
    description: str  # Natural language rule
    scope: str = "global"  # global, account:{id}, server:{id}, environment:{name}
    priority: int = 5
    enabled: bool = True
    created_at: str = ""
    created_by: str = "system"

    def __post_init__(self):
        if not self.created_at:
            self.created_at = datetime.now().isoformat()


class PolicyEngine:
    """
    Natural language policy engine.
    Instead of YAML rules, policies are written in plain English
    and interpreted by the LLM during reasoning.
    """

    DEFAULT_POLICIES = [
        Policy(
            policy_id="POL-001",
            name="Auto-patch non-production",
            description="Automatically patch all Development and Staging servers without human approval, regardless of confidence score.",
            scope="environment:Development,Staging",
            priority=1,
        ),
        Policy(
            policy_id="POL-002",
            name="Production requires approval for kernel updates",
            description="Any patch that modifies the Windows kernel or requires a reboot on Production servers must go through human approval, even if confidence is above 90%.",
            scope="environment:Production",
            priority=1,
        ),
        Policy(
            policy_id="POL-003",
            name="Critical CVEs bypass maintenance window",
            description="CRITICAL severity vulnerabilities with CVSS >= 9.0 can be patched outside maintenance windows on any server. Notify the security team via Slack immediately.",
            scope="global",
            priority=1,
        ),
        Policy(
            policy_id="POL-004",
            name="ERP servers need change ticket",
            description="Any remediation on servers tagged Application=ERP or Application=SAP must always create a ServiceNow CHG ticket, regardless of confidence score.",
            scope="global",
            priority=2,
        ),
        Policy(
            policy_id="POL-005",
            name="Stale patches escalate automatically",
            description="If a server has not been patched in over 30 days, escalate to the security team lead and create a P2 incident in ServiceNow.",
            scope="global",
            priority=3,
        ),
        Policy(
            policy_id="POL-006",
            name="Failed remediation triggers rollback",
            description="If a remediation fails or verification detects service disruption, immediately trigger the Rollback Agent and create a P1 incident.",
            scope="global",
            priority=1,
        ),
        Policy(
            policy_id="POL-007",
            name="Zero-day response",
            description="When a new CVE appears in the CISA KEV catalog, immediately scan all servers, generate remediation plan, and notify security team within 15 minutes.",
            scope="global",
            priority=1,
        ),
    ]

    def __init__(self):
        self.policies: List[Policy] = list(self.DEFAULT_POLICIES)

    def add_policy(self, name: str, description: str, scope: str = "global", priority: int = 5, created_by: str = "admin") -> Policy:
        policy = Policy(
            policy_id=f"POL-{len(self.policies) + 1:03d}",
            name=name,
            description=description,
            scope=scope,
            priority=priority,
            created_by=created_by,
        )
        self.policies.append(policy)
        return policy

    def remove_policy(self, policy_id: str):
        self.policies = [p for p in self.policies if p.policy_id != policy_id]

    def get_applicable_policies(self, server_context: Dict = None) -> List[Policy]:
        """Get policies applicable to a given server context."""
        applicable = []
        for policy in self.policies:
            if not policy.enabled:
                continue
            if policy.scope == "global":
                applicable.append(policy)
            elif server_context:
                env = server_context.get("environment", "")
                app = server_context.get("application", "")
                acct = server_context.get("account_id", "")
                if f"environment:{env}" in policy.scope:
                    applicable.append(policy)
                elif f"application:{app}" in policy.scope:
                    applicable.append(policy)
                elif f"account:{acct}" in policy.scope:
                    applicable.append(policy)
        return sorted(applicable, key=lambda p: p.priority)

    def get_policies_as_context(self, server_context: Dict = None) -> str:
        """Format policies as context for LLM reasoning."""
        policies = self.get_applicable_policies(server_context)
        if not policies:
            return "No specific policies apply."

        lines = ["Active Policies:"]
        for p in policies:
            lines.append(f"- [{p.policy_id}] {p.name}: {p.description}")
        return "\n".join(lines)

    def to_dict(self) -> List[Dict]:
        return [asdict(p) for p in self.policies]


# ==================== REASONING ENGINE ====================

class ReasoningEngine:
    """
    LLM-powered reasoning engine.
    Takes an event + context (memory, policies, server state)
    and decides what actions to take.
    """

    REASONING_PROMPT = """You are an autonomous Windows Server security agent. You must decide what action to take based on the event, context, and policies.

You MUST respond in valid JSON with this exact structure:
{
    "reasoning": "Brief explanation of your decision (2-3 sentences)",
    "actions": [
        {
            "action_type": "one of: scan_server, patch_server, create_chg_ticket, create_incident, notify_team, approve_auto_remediation, queue_for_approval, rollback, escalate, monitor, skip",
            "target": "server instance ID or 'fleet' or 'all'",
            "priority": "P1/P2/P3/P4",
            "details": "specific details for this action"
        }
    ],
    "confidence": 0.0 to 1.0,
    "should_notify_human": true/false,
    "notification_message": "message for human if should_notify_human is true"
}

IMPORTANT: Only return the JSON object, nothing else."""

    def __init__(self, claude_client=None, openai_client=None):
        self.claude_client = claude_client
        self.openai_client = openai_client

    def reason(self, event: AgentEvent, memory_context: str, policy_context: str, server_state: str) -> Dict:
        """Have the LLM reason about an event and decide on actions."""

        prompt = f"""EVENT:
Type: {event.event_type}
Priority: {event.priority}
Source: {event.source}
Data: {json.dumps(event.data, indent=2)}

MEMORY (what I know from past experience):
{memory_context}

POLICIES (rules I must follow):
{policy_context}

CURRENT SERVER STATE:
{server_state}

Based on the above, decide what actions to take. Follow the policies strictly."""

        # Try Claude → OpenAI → rule-based
        result = None
        if self.claude_client:
            result = self._reason_claude(prompt)
        if not result and self.openai_client:
            result = self._reason_openai(prompt)
        if not result:
            result = self._reason_rule_based(event)

        return result

    def _reason_claude(self, prompt: str) -> Optional[Dict]:
        try:
            response = self.claude_client.messages.create(
                model="claude-sonnet-4-20250514",
                max_tokens=1000,
                system=self.REASONING_PROMPT,
                messages=[{"role": "user", "content": prompt}],
            )
            return json.loads(response.content[0].text)
        except Exception:
            return None

    def _reason_openai(self, prompt: str) -> Optional[Dict]:
        try:
            response = self.openai_client.chat.completions.create(
                model="gpt-4o",
                max_tokens=1000,
                response_format={"type": "json_object"},
                messages=[
                    {"role": "system", "content": self.REASONING_PROMPT},
                    {"role": "user", "content": prompt},
                ],
            )
            return json.loads(response.choices[0].message.content)
        except Exception:
            return None

    def _reason_rule_based(self, event: AgentEvent) -> Dict:
        """Fallback rule-based reasoning when no LLM is available."""
        actions = []

        if event.event_type == EventType.NEW_CVE_PUBLISHED.value:
            actions.append({
                "action_type": "scan_server",
                "target": "fleet",
                "priority": "P2",
                "details": f"Scan all servers for {event.data.get('cve_id', 'new CVE')}",
            })

        elif event.event_type == EventType.COMPLIANCE_DRIFT.value:
            actions.append({
                "action_type": "patch_server",
                "target": event.data.get("instance_id", "unknown"),
                "priority": "P3",
                "details": f"Re-apply baseline for {event.data.get('control_id', 'unknown control')}",
            })

        elif event.event_type == EventType.REMEDIATION_FAILED.value:
            actions.append({
                "action_type": "rollback",
                "target": event.data.get("instance_id", "unknown"),
                "priority": "P1",
                "details": "Rollback failed remediation immediately",
            })
            actions.append({
                "action_type": "create_incident",
                "target": event.data.get("instance_id", "unknown"),
                "priority": "P1",
                "details": "Create P1 incident for failed remediation",
            })

        elif event.event_type == EventType.THREAT_INTEL_UPDATE.value:
            if event.data.get("in_kev"):
                actions.append({
                    "action_type": "scan_server",
                    "target": "fleet",
                    "priority": "P1",
                    "details": f"CISA KEV alert: {event.data.get('cve_id')} — immediate fleet scan",
                })
                actions.append({
                    "action_type": "notify_team",
                    "target": "security-team",
                    "priority": "P1",
                    "details": f"CISA KEV: {event.data.get('cve_id')} added to catalog",
                })

        elif event.event_type == EventType.SCHEDULED_SCAN.value:
            actions.append({
                "action_type": "scan_server",
                "target": "fleet",
                "priority": "P4",
                "details": "Scheduled periodic compliance scan",
            })

        if not actions:
            actions.append({
                "action_type": "monitor",
                "target": "fleet",
                "priority": "P4",
                "details": "No immediate action required, continuing to monitor",
            })

        return {
            "reasoning": f"Rule-based decision for {event.event_type}",
            "actions": actions,
            "confidence": 0.75,
            "should_notify_human": event.priority <= 2,
            "notification_message": f"Agent action: {actions[0]['action_type']} on {actions[0]['target']}",
        }


# ==================== AUTONOMOUS AGENT ====================

class AutonomousAgent:
    """
    The core autonomous agent that runs continuously.

    This is NOT a dashboard. This is a background process that:
    1. Perceives changes in the environment
    2. Reasons about what to do (using LLM + policies + memory)
    3. Takes action (patch, scan, notify, escalate)
    4. Learns from outcomes
    5. Reports to humans
    """

    def __init__(
        self,
        claude_client=None,
        openai_client=None,
        aws_connector=None,
        itsm_client=None,
        notification_agent=None,
    ):
        # AI reasoning
        self.reasoning_engine = ReasoningEngine(claude_client, openai_client)

        # Memory and policies
        self.memory = AgentMemory()
        self.policy_engine = PolicyEngine()

        # External systems
        self.aws_connector = aws_connector
        self.itsm_client = itsm_client
        self.notification_agent = notification_agent

        # Event queue
        self.event_queue: List[AgentEvent] = []
        self.processed_events: List[AgentEvent] = []

        # Agent state
        self.is_running = False
        self.cycle_count = 0
        self.last_cycle_time: Optional[str] = None
        self.actions_taken: List[Dict] = []

        # Initialize default memories
        self._init_default_memories()

    def _init_default_memories(self):
        """Pre-load agent with baseline knowledge."""
        self.memory.remember("policy", "auto_remediate_threshold", "0.90")
        self.memory.remember("policy", "human_approve_threshold", "0.70")
        self.memory.remember("policy", "max_auto_per_hour", "50")
        self.memory.remember("policy", "require_restore_point", "true")
        self.memory.remember("policy", "dry_run_first", "true")

    # ==================== EVENT MANAGEMENT ====================

    def push_event(self, event_type: str, source: str, data: Dict, priority: int = 5):
        """Push a new event for the agent to process."""
        event = AgentEvent(
            event_id=f"EVT-{datetime.now().strftime('%Y%m%d%H%M%S%f')}",
            event_type=event_type,
            timestamp=datetime.now().isoformat(),
            source=source,
            data=data,
            priority=priority,
        )
        self.event_queue.append(event)
        # Sort by priority (lower = more urgent)
        self.event_queue.sort(key=lambda e: e.priority)
        return event

    def get_pending_events(self) -> List[AgentEvent]:
        return [e for e in self.event_queue if not e.processed]

    # ==================== PERCEPTION ====================

    def perceive(self, servers: list = None, scan_results: list = None):
        """
        Perceive changes in the environment.
        Called each cycle to detect new events.
        """
        # Check for compliance drift on SSM-connected servers
        if servers:
            for server in servers:
                if server.ssm_status == "Online":
                    # Check if compliance dropped
                    prev_compliance = self.memory.recall("server", f"{server.instance_id}:compliance")
                    current = str(server.patch_compliance)
                    if prev_compliance and float(prev_compliance) > server.patch_compliance:
                        self.push_event(
                            EventType.COMPLIANCE_DRIFT.value,
                            "compliance_monitor",
                            {
                                "instance_id": server.instance_id,
                                "hostname": server.hostname,
                                "previous": prev_compliance,
                                "current": current,
                            },
                            priority=3,
                        )
                    self.memory.remember("server", f"{server.instance_id}:compliance", current)
                    self.memory.remember("server", f"{server.instance_id}:status", server.status)
                    self.memory.remember("server", f"{server.instance_id}:hostname", server.hostname)

        # Heartbeat event every cycle
        self.push_event(
            EventType.AGENT_HEARTBEAT.value,
            "agent",
            {"cycle": self.cycle_count, "pending_events": len(self.get_pending_events())},
            priority=10,
        )

    # ==================== REASONING ====================

    def reason_about_event(self, event: AgentEvent, server_state: str = "") -> Dict:
        """Use LLM to reason about an event and decide actions."""
        memory_context = self.memory.get_context_for_reasoning(
            server_id=event.data.get("instance_id"),
            cve_id=event.data.get("cve_id"),
        )
        policy_context = self.policy_engine.get_policies_as_context(event.data)

        decision = self.reasoning_engine.reason(
            event, memory_context, policy_context, server_state
        )

        event.reasoning = decision.get("reasoning", "")
        return decision

    # ==================== ACTION EXECUTION ====================

    def execute_actions(self, event: AgentEvent, decision: Dict):
        """Execute the actions decided by the reasoning engine."""
        actions = decision.get("actions", [])

        for action in actions:
            action_type = action.get("action_type", "monitor")
            target = action.get("target", "unknown")
            details = action.get("details", "")
            priority = action.get("priority", "P3")

            action_record = {
                "event_id": event.event_id,
                "action_type": action_type,
                "target": target,
                "priority": priority,
                "details": details,
                "reasoning": decision.get("reasoning", ""),
                "confidence": decision.get("confidence", 0),
                "timestamp": datetime.now().isoformat(),
                "status": "executed",
            }

            try:
                if action_type == "scan_server":
                    self._action_scan(target)
                elif action_type == "patch_server":
                    self._action_patch(target, details)
                elif action_type == "create_chg_ticket":
                    self._action_create_chg(event, details)
                elif action_type == "create_incident":
                    self._action_create_incident(event, details, priority)
                elif action_type == "notify_team":
                    self._action_notify(details, priority)
                elif action_type == "rollback":
                    self._action_rollback(target)
                elif action_type == "escalate":
                    self._action_escalate(event, details)
                elif action_type == "approve_auto_remediation":
                    self._action_auto_remediate(target, details)
                elif action_type == "queue_for_approval":
                    self._action_queue_approval(event, details)
                elif action_type in ("monitor", "skip"):
                    pass  # No action needed

                action_record["status"] = "completed"

            except Exception as e:
                action_record["status"] = f"failed: {e}"
                logger.error(f"Action failed: {action_type} on {target}: {e}")

            self.actions_taken.append(action_record)

        # Notify human if the reasoning says so
        if decision.get("should_notify_human"):
            msg = decision.get("notification_message", f"Agent took action on {event.event_type}")
            self._action_notify(msg, "P2")

        event.processed = True
        event.action_taken = json.dumps([a["action_type"] for a in actions])

    def _action_scan(self, target: str):
        logger.info(f"Scanning: {target}")
        self.memory.remember("action", f"scan:{target}", f"Scanned at {datetime.now().isoformat()}")

    def _action_patch(self, target: str, details: str):
        logger.info(f"Patching: {target} — {details}")
        self.memory.remember("action", f"patch:{target}", f"Patched at {datetime.now().isoformat()}: {details}")

    def _action_create_chg(self, event: AgentEvent, details: str):
        logger.info(f"Creating CHG ticket: {details}")
        if self.itsm_client:
            try:
                ticket = self.itsm_client.create_change_request(
                    vulnerability=event.data,
                    server_context=event.data,
                )
                ticket_num = ticket.get("number", "N/A")
                self.memory.remember("itsm", f"chg:{event.event_id}", ticket_num)
            except Exception as e:
                logger.error(f"CHG creation failed: {e}")

    def _action_create_incident(self, event: AgentEvent, details: str, priority: str):
        logger.info(f"Creating incident ({priority}): {details}")
        if self.itsm_client:
            try:
                self.itsm_client.create_incident(
                    vulnerability=event.data,
                    server_context=event.data,
                    description=details,
                )
            except Exception:
                pass

    def _action_notify(self, message: str, priority: str):
        logger.info(f"Notification ({priority}): {message}")

    def _action_rollback(self, target: str):
        logger.info(f"Rolling back: {target}")
        self.memory.remember("action", f"rollback:{target}", f"Rolled back at {datetime.now().isoformat()}")

    def _action_escalate(self, event: AgentEvent, details: str):
        logger.info(f"Escalating: {details}")

    def _action_auto_remediate(self, target: str, details: str):
        logger.info(f"Auto-remediating: {target} — {details}")
        self.memory.remember("action", f"auto_remediate:{target}", f"Auto-remediated at {datetime.now().isoformat()}")

    def _action_queue_approval(self, event: AgentEvent, details: str):
        logger.info(f"Queued for approval: {details}")

    # ==================== LEARNING ====================

    def learn_from_outcome(self, event_id: str, success: bool, notes: str = ""):
        """Record the outcome of an action for future reference."""
        self.memory.remember(
            "outcome",
            f"{event_id}:result",
            f"{'success' if success else 'failure'}: {notes}",
        )

        # Adjust confidence for similar future events
        for event in self.processed_events:
            if event.event_id == event_id:
                if not success:
                    self.memory.remember(
                        "learning",
                        f"avoid:{event.event_type}:{event.data.get('instance_id', '')}",
                        f"Previous action failed: {notes}. Consider manual review next time.",
                        confidence=0.8,
                    )
                else:
                    self.memory.remember(
                        "learning",
                        f"proven:{event.event_type}:{event.data.get('instance_id', '')}",
                        f"Action succeeded. Safe to auto-remediate in future.",
                        confidence=0.9,
                    )
                break

    # ==================== MAIN LOOP ====================

    def run_cycle(self, servers: list = None, server_state_str: str = "") -> List[Dict]:
        """
        Run one cycle of the autonomous agent.
        Called periodically (every 5-10 minutes in production).
        Returns list of actions taken.
        """
        self.cycle_count += 1
        self.last_cycle_time = datetime.now().isoformat()
        cycle_actions = []

        # 1. PERCEIVE
        self.perceive(servers)

        # 2. Process pending events (highest priority first)
        pending = self.get_pending_events()
        for event in pending:
            if event.event_type == EventType.AGENT_HEARTBEAT.value:
                event.processed = True
                continue

            # 3. REASON
            decision = self.reason_about_event(event, server_state_str)

            # 4. ACT
            self.execute_actions(event, decision)

            # Move to processed
            self.processed_events.append(event)
            cycle_actions.extend(self.actions_taken[-len(decision.get("actions", [])):])

        # Clean up processed events from queue
        self.event_queue = [e for e in self.event_queue if not e.processed]

        return cycle_actions

    # ==================== STATUS / REPORTING ====================

    def get_status(self) -> Dict:
        return {
            "is_running": self.is_running,
            "cycle_count": self.cycle_count,
            "last_cycle": self.last_cycle_time,
            "pending_events": len(self.get_pending_events()),
            "processed_events": len(self.processed_events),
            "total_actions": len(self.actions_taken),
            "memory_stats": self.memory.stats(),
            "policies_active": len([p for p in self.policy_engine.policies if p.enabled]),
        }

    def get_recent_actions(self, last_n: int = 20) -> List[Dict]:
        return self.actions_taken[-last_n:]

    def get_event_log(self, last_n: int = 50) -> List[Dict]:
        events = self.processed_events[-last_n:]
        return [asdict(e) for e in events]
