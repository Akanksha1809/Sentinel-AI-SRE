from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta, timezone
from typing import Any, ClassVar

import pytest

from sentinel.audit import GENESIS, compute_hash
from sentinel.domain.enums import IncidentStatus as S
from sentinel.domain.enums import Role, Severity
from sentinel.domain.incidents import TRANSITIONS, InvalidTransitionError, check_transition
from sentinel.ids import uuid7
from sentinel.security import generate_token, hash_token


class TestStateMachine:
    @pytest.mark.parametrize(
        ("a", "b"),
        [
            (S.OPEN, S.ACKNOWLEDGED),
            (S.ACKNOWLEDGED, S.INVESTIGATING),
            (S.INVESTIGATING, S.REMEDIATING),
            (S.REMEDIATING, S.VERIFYING),
            (S.VERIFYING, S.RESOLVED),
            (S.VERIFYING, S.REMEDIATING),
            (S.RESOLVED, S.OPEN),
            (S.RESOLVED, S.CLOSED),
            (S.OPEN, S.RESOLVED),
        ],
    )
    def test_allowed(self, a: S, b: S) -> None:
        check_transition(a, b)

    @pytest.mark.parametrize(
        ("a", "b"),
        [
            (S.CLOSED, S.OPEN),
            (S.OPEN, S.VERIFYING),
            (S.OPEN, S.CLOSED),
            (S.RESOLVED, S.REMEDIATING),
            (S.ACKNOWLEDGED, S.OPEN),
            (S.OPEN, S.OPEN),
        ],
    )
    def test_rejected(self, a: S, b: S) -> None:
        with pytest.raises(InvalidTransitionError):
            check_transition(a, b)

    def test_every_status_has_an_entry_and_closed_is_terminal(self) -> None:
        assert set(TRANSITIONS) == set(S)
        assert TRANSITIONS[S.CLOSED] == frozenset()

    def test_every_active_state_can_reach_resolved(self) -> None:
        for status in S:
            if status.is_active:
                assert S.RESOLVED in TRANSITIONS[status], status


def test_severity_ordering_and_parsing() -> None:
    assert Severity.max(Severity.WARNING, Severity.CRITICAL) is Severity.CRITICAL
    assert Severity.parse(" Critical ") is Severity.CRITICAL
    assert Severity.parse(None) is Severity.WARNING


def test_role_hierarchy() -> None:
    assert Role.ADMIN.satisfies(Role.APPROVER)
    assert Role.APPROVER.satisfies(Role.RESPONDER)
    assert not Role.RESPONDER.satisfies(Role.APPROVER)
    assert not Role.VIEWER.satisfies(Role.RESPONDER)


def test_uuid7_is_version_7_and_time_ordered() -> None:
    ids = [uuid7() for _ in range(200)]
    assert all(i.version == 7 and i.variant == uuid.RFC_4122 for i in ids)
    timestamps = [i.int >> 80 for i in ids]
    assert timestamps == sorted(timestamps)
    assert len(set(ids)) == 200


def test_tokens_are_random_and_only_hashes_are_comparable() -> None:
    a, b = generate_token(), generate_token()
    assert a != b
    assert a.startswith("snt_")
    assert len(hash_token(a)) == 64
    assert hash_token(a) == hash_token(a)


class TestAuditHash:
    kw: ClassVar[dict[str, Any]] = dict(
        id=uuid.UUID(int=1),
        actor="user:alice",
        action="incident.resolved",
        subject_type="incident",
        subject_id="x",
        correlation_id="c1",
        data={"b": 2, "a": 1},
    )

    def test_deterministic_and_key_order_independent(self) -> None:
        at = datetime(2026, 10, 9, 12, tzinfo=UTC)
        h1 = compute_hash(GENESIS, at=at, **self.kw)  # type: ignore[arg-type]
        h2 = compute_hash(GENESIS, at=at, **{**self.kw, "data": {"a": 1, "b": 2}})  # type: ignore[arg-type]
        assert h1 == h2

    def test_same_instant_in_other_timezone_hashes_identically(self) -> None:
        utc = datetime(2026, 10, 9, 12, tzinfo=UTC)
        ist = utc.astimezone(timezone(timedelta(hours=5, minutes=30)))
        assert compute_hash(GENESIS, at=utc, **self.kw) == compute_hash(GENESIS, at=ist, **self.kw)  # type: ignore[arg-type]

    def test_any_field_change_or_relink_changes_hash(self) -> None:
        at = datetime(2026, 10, 9, 12, tzinfo=UTC)
        base = compute_hash(GENESIS, at=at, **self.kw)  # type: ignore[arg-type]
        assert compute_hash("f" * 64, at=at, **self.kw) != base  # type: ignore[arg-type]
        assert compute_hash(GENESIS, at=at, **{**self.kw, "actor": "user:mallory"}) != base  # type: ignore[arg-type]
