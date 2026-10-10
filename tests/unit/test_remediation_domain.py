"""Action state machine and policy engine: pure logic, no DB."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from sentinel.domain.actions import (
    TERMINAL,
    TRANSITIONS,
    InvalidActionTransitionError,
    check_transition,
)
from sentinel.domain.enums import ActionStatus as S
from sentinel.remediation.policy import PolicyContext, PolicyEngine
from sentinel.remediation.runbooks import Runbook


class TestActionStateMachine:
    @pytest.mark.parametrize(
        ("a", "b"),
        [
            (S.PROPOSED, S.PENDING_APPROVAL),
            (S.PROPOSED, S.APPROVED),
            (S.PROPOSED, S.CANCELLED),
            (S.PENDING_APPROVAL, S.APPROVED),
            (S.PENDING_APPROVAL, S.REJECTED),
            (S.PENDING_APPROVAL, S.EXPIRED),
            (S.APPROVED, S.EXECUTING),
            (S.EXECUTING, S.VERIFYING),
            (S.EXECUTING, S.FAILED),
            (S.VERIFYING, S.SUCCEEDED),
            (S.VERIFYING, S.VERIFICATION_FAILED),
        ],
    )
    def test_allowed(self, a: S, b: S) -> None:
        check_transition(a, b)

    @pytest.mark.parametrize(
        ("a", "b"),
        [
            (S.SUCCEEDED, S.EXECUTING),
            (S.REJECTED, S.APPROVED),
            (S.EXPIRED, S.APPROVED),
            (S.FAILED, S.VERIFYING),
            (S.VERIFICATION_FAILED, S.EXECUTING),
            (S.PENDING_APPROVAL, S.EXECUTING),  # must go through approved first
            (S.PROPOSED, S.VERIFYING),
            (S.APPROVED, S.VERIFYING),  # must execute first
        ],
    )
    def test_rejected(self, a: S, b: S) -> None:
        with pytest.raises(InvalidActionTransitionError):
            check_transition(a, b)

    def test_every_status_has_an_entry(self) -> None:
        assert set(TRANSITIONS) == set(S)

    def test_terminal_states_have_no_outgoing_transitions(self) -> None:
        expected = {
            S.SUCCEEDED,
            S.REJECTED,
            S.EXPIRED,
            S.FAILED,
            S.VERIFICATION_FAILED,
            S.CANCELLED,
        }
        assert expected == TERMINAL
        for s in expected:
            assert TRANSITIONS[s] == frozenset()

    def test_verification_failure_does_not_auto_retry(self) -> None:
        """A failed verification is terminal for *this* request: no transition leads
        back to executing/verifying. A fresh proposal is required (tested via the
        service layer in test_remediation_flow.py)."""
        assert TRANSITIONS[S.VERIFICATION_FAILED] == frozenset()


RUNBOOK_REQUIRED = Runbook.model_validate(
    {
        "id": "restart-service",
        "version": 1,
        "title": "t",
        "description": "d",
        "action": "restart",
        "disruptive": True,
        "approval": "required",
        "parameters": {"service": {"type": "service"}},
        "verification": {
            "settle_s": 1,
            "window_s": 15,
            "interval_s": 5,
            "consecutive": 1,
            "checks": [{"signal": "error_ratio", "op": "lt", "value": 0.01}],
        },
    }
)
RUNBOOK_AUTO = Runbook.model_validate(
    {
        "id": "scale-service",
        "version": 1,
        "title": "t",
        "description": "d",
        "action": "scale",
        "disruptive": False,
        "approval": "policy_auto",
        "parameters": {"service": {"type": "service"}},
        "verification": {
            "settle_s": 1,
            "window_s": 15,
            "interval_s": 5,
            "consecutive": 1,
            "checks": [{"signal": "latency_p95", "op": "lt", "value": 0.3}],
        },
    }
)
NOW = datetime(2026, 10, 9, 12, 0, tzinfo=UTC)


class TestPolicyEngine:
    def test_required_runbook_always_needs_approval(self) -> None:
        policy = PolicyEngine()
        ctx = PolicyContext(existing_requests_for_incident=0, last_execution_started_at=None)
        decision = policy.decide_approval(RUNBOOK_REQUIRED, ctx, NOW)
        assert decision.auto_approve is False

    def test_policy_auto_runbook_is_approved_with_no_cooldown(self) -> None:
        policy = PolicyEngine()
        ctx = PolicyContext(existing_requests_for_incident=0, last_execution_started_at=None)
        decision = policy.decide_approval(RUNBOOK_AUTO, ctx, NOW)
        assert decision.auto_approve is True

    def test_policy_auto_runbook_falls_back_to_approval_during_cooldown(self) -> None:
        policy = PolicyEngine(cooldown=timedelta(minutes=5))
        ctx = PolicyContext(
            existing_requests_for_incident=0, last_execution_started_at=NOW - timedelta(minutes=1)
        )
        decision = policy.decide_approval(RUNBOOK_AUTO, ctx, NOW)
        assert decision.auto_approve is False
        assert "cooldown" in decision.reason

    def test_policy_auto_runbook_approved_after_cooldown_elapses(self) -> None:
        policy = PolicyEngine(cooldown=timedelta(minutes=5))
        ctx = PolicyContext(
            existing_requests_for_incident=0, last_execution_started_at=NOW - timedelta(minutes=6)
        )
        assert policy.decide_approval(RUNBOOK_AUTO, ctx, NOW).auto_approve is True

    def test_rate_limit(self) -> None:
        policy = PolicyEngine(max_per_incident=3)
        assert (
            policy.check_rate_limit(
                PolicyContext(existing_requests_for_incident=2, last_execution_started_at=None)
            )
            is None
        )
        blocked = policy.check_rate_limit(
            PolicyContext(existing_requests_for_incident=3, last_execution_started_at=None)
        )
        assert blocked is not None
        assert "3" in blocked

    def test_required_runbook_ignores_cooldown_entirely(self) -> None:
        """A required-approval runbook is never auto-approved, cooldown or not — a
        human always decides, so the cooldown check (which only gates auto-approval)
        is never even consulted."""
        policy = PolicyEngine(cooldown=timedelta(hours=1))
        ctx = PolicyContext(
            existing_requests_for_incident=0, last_execution_started_at=NOW - timedelta(seconds=1)
        )
        decision = policy.decide_approval(RUNBOOK_REQUIRED, ctx, NOW)
        assert decision.auto_approve is False
        assert decision.reason == "runbook requires approval"
