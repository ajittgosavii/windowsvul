"""
Scheduling Agent — Maintenance Window Enforcement

Capabilities:
  - Define maintenance windows per account/OU/environment
  - Block auto-remediation outside maintenance windows
  - Queue remediations for next available window
  - Coordinate reboot scheduling across server groups
  - Blackout period management (month-end, holiday freeze)
  - SSM Maintenance Window integration
"""

import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


@dataclass
class MaintenanceWindow:
    """Defines when remediation is allowed."""
    window_id: str
    name: str
    scope: str  # account_id, ou_path, environment, or "global"
    scope_value: str  # e.g., "448549863273", "Production", "*"
    day_of_week: List[int] = field(default_factory=lambda: [5, 6])  # 0=Mon, 6=Sun (Sat, Sun default)
    start_hour: int = 22  # 10 PM
    end_hour: int = 6    # 6 AM
    timezone: str = "UTC"
    enabled: bool = True
    allow_critical_override: bool = True  # CRITICAL vulns can bypass window
    max_reboots_per_window: int = 10


@dataclass
class BlackoutPeriod:
    """Period when NO remediation is allowed."""
    blackout_id: str
    name: str
    start_date: str  # YYYY-MM-DD
    end_date: str
    reason: str
    scope: str = "global"
    allow_critical: bool = False


@dataclass
class ScheduledRemediation:
    """A remediation queued for a future maintenance window."""
    schedule_id: str
    decision_id: str
    vulnerability_id: str
    instance_id: str
    account_id: str
    severity: str
    scheduled_window: str
    scheduled_time: str
    status: str = "QUEUED"  # QUEUED, EXECUTING, COMPLETED, CANCELLED
    created_at: str = ""

    def __post_init__(self):
        if not self.created_at:
            self.created_at = datetime.now().isoformat()


class SchedulingAgent:
    """
    Agent 10: Maintenance window enforcement and remediation scheduling.

    Ensures remediations only execute during approved windows.
    Manages reboot coordination across server groups.
    """

    def __init__(self):
        self.maintenance_windows: List[MaintenanceWindow] = self._default_windows()
        self.blackout_periods: List[BlackoutPeriod] = self._default_blackouts()
        self.scheduled_queue: List[ScheduledRemediation] = []
        self.reboot_schedule: Dict[str, List[str]] = {}  # window_id → [instance_ids]

    def _default_windows(self) -> List[MaintenanceWindow]:
        """Default maintenance windows."""
        return [
            MaintenanceWindow(
                window_id="MW-PROD-WEEKEND",
                name="Production Weekend Window",
                scope="environment",
                scope_value="Production",
                day_of_week=[5, 6],  # Sat, Sun
                start_hour=22,
                end_hour=6,
                allow_critical_override=True,
                max_reboots_per_window=10,
            ),
            MaintenanceWindow(
                window_id="MW-PROD-WEEKDAY",
                name="Production Weekday (Emergency)",
                scope="environment",
                scope_value="Production",
                day_of_week=[0, 1, 2, 3, 4],  # Mon-Fri
                start_hour=2,
                end_hour=5,
                allow_critical_override=True,
                max_reboots_per_window=3,
            ),
            MaintenanceWindow(
                window_id="MW-NONPROD-ANYTIME",
                name="Non-Production Any Time",
                scope="environment",
                scope_value="Development",
                day_of_week=[0, 1, 2, 3, 4, 5, 6],
                start_hour=0,
                end_hour=23,
                allow_critical_override=True,
                max_reboots_per_window=50,
            ),
            MaintenanceWindow(
                window_id="MW-STAGING",
                name="Staging Business Hours",
                scope="environment",
                scope_value="Staging",
                day_of_week=[0, 1, 2, 3, 4],
                start_hour=9,
                end_hour=17,
                allow_critical_override=True,
                max_reboots_per_window=20,
            ),
        ]

    def _default_blackouts(self) -> List[BlackoutPeriod]:
        """Default blackout periods."""
        now = datetime.now()
        return [
            BlackoutPeriod(
                blackout_id="BO-MONTHEND",
                name="Month-End Close",
                start_date=(now.replace(day=28) if now.day < 28 else now).strftime("%Y-%m-%d"),
                end_date=(now.replace(day=28) + timedelta(days=4)).strftime("%Y-%m-%d"),
                reason="Financial month-end processing",
                allow_critical=True,
            ),
            BlackoutPeriod(
                blackout_id="BO-YEAREND",
                name="Year-End Freeze",
                start_date=f"{now.year}-12-15",
                end_date=f"{now.year + 1}-01-05",
                reason="Year-end change freeze",
                allow_critical=True,
            ),
        ]

    def is_in_maintenance_window(
        self,
        server_context: Dict,
        check_time: datetime = None,
    ) -> Tuple[bool, Optional[MaintenanceWindow]]:
        """Check if current time is within an allowed maintenance window."""
        now = check_time or datetime.now()
        environment = server_context.get("environment", "Production")
        account_id = server_context.get("account_id", "")

        # Check blackout periods first
        in_blackout, blackout = self._check_blackout(now)
        if in_blackout:
            logger.info(f"In blackout period: {blackout.name}")
            return False, None

        # Find matching maintenance window
        for window in self.maintenance_windows:
            if not window.enabled:
                continue

            # Check scope match
            if window.scope == "environment" and window.scope_value != environment:
                continue
            if window.scope == "account_id" and window.scope_value != account_id:
                continue

            # Check day of week
            if now.weekday() not in window.day_of_week:
                continue

            # Check time range
            current_hour = now.hour
            if window.start_hour <= window.end_hour:
                # Same day window (e.g., 9-17)
                if window.start_hour <= current_hour < window.end_hour:
                    return True, window
            else:
                # Overnight window (e.g., 22-6)
                if current_hour >= window.start_hour or current_hour < window.end_hour:
                    return True, window

        return False, None

    def _check_blackout(self, check_time: datetime) -> Tuple[bool, Optional[BlackoutPeriod]]:
        """Check if current time is in a blackout period."""
        date_str = check_time.strftime("%Y-%m-%d")
        for blackout in self.blackout_periods:
            if blackout.start_date <= date_str <= blackout.end_date:
                return True, blackout
        return False, None

    def can_remediate(
        self,
        decision,
        server_context: Dict,
    ) -> Tuple[bool, str]:
        """
        Determine if remediation can proceed now.

        Returns (allowed, reason).
        """
        severity = "CRITICAL"  # Extract from decision if available
        for vuln_id in [decision.vulnerability_id]:
            if "critical" in vuln_id.lower():
                severity = "CRITICAL"

        # Check blackout
        in_blackout, blackout = self._check_blackout(datetime.now())
        if in_blackout:
            if severity == "CRITICAL" and blackout.allow_critical:
                return True, f"CRITICAL override during blackout: {blackout.name}"
            return False, f"Blackout period: {blackout.name} ({blackout.reason})"

        # Check maintenance window
        in_window, window = self.is_in_maintenance_window(server_context)

        if in_window:
            return True, f"Within maintenance window: {window.name}"

        # Critical override
        if severity == "CRITICAL":
            for w in self.maintenance_windows:
                if w.allow_critical_override:
                    return True, f"CRITICAL severity override (outside window)"

        # Not in window — schedule for next window
        next_window = self._find_next_window(server_context)
        if next_window:
            return False, f"Outside maintenance window. Next window: {next_window}"

        return False, "No maintenance window configured for this environment"

    def schedule_remediation(self, decision, server_context: Dict) -> ScheduledRemediation:
        """Queue a remediation for the next maintenance window."""
        next_window = self._find_next_window(server_context)

        scheduled = ScheduledRemediation(
            schedule_id=f"SCHED-{datetime.now().strftime('%Y%m%d%H%M%S')}",
            decision_id=decision.decision_id,
            vulnerability_id=decision.vulnerability_id,
            instance_id=decision.instance_id,
            account_id=decision.account_id,
            severity="HIGH",
            scheduled_window=next_window or "Next Available",
            scheduled_time=self._calculate_next_window_time(server_context),
        )

        self.scheduled_queue.append(scheduled)
        logger.info(f"Scheduled {decision.vulnerability_id} for {scheduled.scheduled_time}")
        return scheduled

    def _find_next_window(self, server_context: Dict) -> Optional[str]:
        """Find the name of the next available maintenance window."""
        environment = server_context.get("environment", "Production")
        for window in self.maintenance_windows:
            if window.scope == "environment" and window.scope_value == environment:
                return window.name
        return None

    def _calculate_next_window_time(self, server_context: Dict) -> str:
        """Calculate the next maintenance window start time."""
        environment = server_context.get("environment", "Production")
        now = datetime.now()

        for window in self.maintenance_windows:
            if window.scope == "environment" and window.scope_value == environment:
                # Find next matching day
                for days_ahead in range(1, 8):
                    next_day = now + timedelta(days=days_ahead)
                    if next_day.weekday() in window.day_of_week:
                        next_time = next_day.replace(
                            hour=window.start_hour, minute=0, second=0, microsecond=0
                        )
                        return next_time.isoformat()

        # Default: next Saturday at 10 PM
        days_until_saturday = (5 - now.weekday()) % 7 or 7
        next_sat = now + timedelta(days=days_until_saturday)
        return next_sat.replace(hour=22, minute=0, second=0, microsecond=0).isoformat()

    def get_schedule(self) -> List[Dict]:
        from dataclasses import asdict
        return [asdict(s) for s in self.scheduled_queue]

    def get_windows(self) -> List[Dict]:
        from dataclasses import asdict
        return [asdict(w) for w in self.maintenance_windows]

    def get_blackouts(self) -> List[Dict]:
        from dataclasses import asdict
        return [asdict(b) for b in self.blackout_periods]
