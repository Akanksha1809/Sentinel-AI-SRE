"""ActionRequest lifecycle state machine (docs/data-model.md).

    proposed -> pending_approval -> approved -> executing -> verifying -> succeeded
         \\            \\                \\           \\            \\
          -> rejected   -> expired       -> failed     -> failed    -> verification_failed
                                                                           \\
                                                                            -> (new proposal)

A failed verification does **not** retry the same request: a fresh proposal (often
from a follow-up investigation) is required, so every execution is deliberate.
"""

from __future__ import annotations

from sentinel.domain.enums import ActionStatus as S

TRANSITIONS: dict[S, frozenset[S]] = {
    S.PROPOSED: frozenset({S.PENDING_APPROVAL, S.APPROVED, S.CANCELLED}),
    S.PENDING_APPROVAL: frozenset({S.APPROVED, S.REJECTED, S.EXPIRED, S.CANCELLED}),
    S.APPROVED: frozenset({S.EXECUTING, S.CANCELLED}),
    S.EXECUTING: frozenset({S.VERIFYING, S.FAILED}),
    S.VERIFYING: frozenset({S.SUCCEEDED, S.VERIFICATION_FAILED}),
    S.SUCCEEDED: frozenset(),
    S.REJECTED: frozenset(),
    S.EXPIRED: frozenset(),
    S.FAILED: frozenset(),
    S.VERIFICATION_FAILED: frozenset(),
    S.CANCELLED: frozenset(),
}

TERMINAL = frozenset(s for s, targets in TRANSITIONS.items() if not targets)


class InvalidActionTransitionError(ValueError):
    def __init__(self, current: S, target: S) -> None:
        super().__init__(f"cannot transition action from {current} to {target}")
        self.current = current
        self.target = target


def check_transition(current: S, target: S) -> None:
    if target not in TRANSITIONS[current]:
        raise InvalidActionTransitionError(current, target)
