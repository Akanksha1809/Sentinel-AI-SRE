"""Incident lifecycle state machine (docs/data-model.md)."""

from __future__ import annotations

from sentinel.domain.enums import IncidentStatus as S

ACTIVE = (S.OPEN, S.ACKNOWLEDGED, S.INVESTIGATING, S.REMEDIATING, S.VERIFYING)

TRANSITIONS: dict[S, frozenset[S]] = {
    S.OPEN: frozenset({S.ACKNOWLEDGED, S.INVESTIGATING, S.RESOLVED}),
    S.ACKNOWLEDGED: frozenset({S.INVESTIGATING, S.REMEDIATING, S.RESOLVED}),
    S.INVESTIGATING: frozenset({S.REMEDIATING, S.RESOLVED}),
    S.REMEDIATING: frozenset({S.VERIFYING, S.RESOLVED}),
    S.VERIFYING: frozenset({S.RESOLVED, S.REMEDIATING}),  # verification failed -> back
    S.RESOLVED: frozenset({S.OPEN, S.CLOSED}),  # reopen within window, or close
    S.CLOSED: frozenset(),
}


class InvalidTransitionError(ValueError):
    def __init__(self, current: S, target: S) -> None:
        super().__init__(f"cannot transition incident from {current} to {target}")
        self.current = current
        self.target = target


def check_transition(current: S, target: S) -> None:
    if target not in TRANSITIONS[current]:
        raise InvalidTransitionError(current, target)
