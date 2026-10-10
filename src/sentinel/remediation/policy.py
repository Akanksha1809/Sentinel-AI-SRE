"""Policy: decide whether a proposed action needs human approval, and bound how often
actions can be proposed and executed (threat model T5, T8).

- **Approval.** A runbook marked `approval: required` always needs an approver, no
  matter the source. `policy_auto` runbooks (none ship today; `scale-service` could be
  one for small, same-direction changes) may be auto-approved, but only when every rule
  below also passes; any rule failure falls back to requiring approval.
- **Rate limit.** At most `max_per_incident` action requests total for one incident. A
  flapping investigator or a human mashing "propose" cannot generate unbounded work.
- **Cooldown.** The same runbook cannot be *executed* against the same service again
  within `cooldown_s` of the previous execution attempt starting. Prevents an
  automation loop from hammering the same restart/rollback.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta

from sentinel.remediation.runbooks import Runbook


@dataclass(frozen=True)
class PolicyDecision:
    auto_approve: bool
    reason: str


@dataclass(frozen=True)
class PolicyContext:
    """Facts the policy needs, gathered by the caller (keeps this module DB-free and testable)."""

    existing_requests_for_incident: int
    last_execution_started_at: datetime | None  # for this runbook_id + service, any incident


class PolicyEngine:
    def __init__(
        self, *, max_per_incident: int = 20, cooldown: timedelta = timedelta(minutes=2)
    ) -> None:
        self._max_per_incident = max_per_incident
        self._cooldown = cooldown

    def check_rate_limit(self, ctx: PolicyContext) -> str | None:
        """None if allowed, else the reason it's refused."""
        if ctx.existing_requests_for_incident >= self._max_per_incident:
            return (
                f"incident already has {ctx.existing_requests_for_incident} action "
                f"requests (limit {self._max_per_incident})"
            )
        return None

    def check_cooldown(self, ctx: PolicyContext, now: datetime) -> str | None:
        if ctx.last_execution_started_at is None:
            return None
        elapsed = now - ctx.last_execution_started_at
        if elapsed < self._cooldown:
            remaining = (self._cooldown - elapsed).total_seconds()
            return (
                f"same runbook executed against this service {elapsed.total_seconds():.0f}s "
                f"ago; {remaining:.0f}s of cooldown remain"
            )
        return None

    def decide_approval(
        self, runbook: Runbook, ctx: PolicyContext, now: datetime
    ) -> PolicyDecision:
        if runbook.approval == "required":
            return PolicyDecision(False, "runbook requires approval")
        if blocked := self.check_cooldown(ctx, now):
            return PolicyDecision(False, f"cooldown active, falling back to approval: {blocked}")
        return PolicyDecision(True, "policy_auto runbook, no blocking rule")
