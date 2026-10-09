"""Append-only, hash-chained audit log (threat model T12)."""

from __future__ import annotations

import hashlib
import json
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession

from sentinel.ids import Clock, uuid7
from sentinel.observability.context import correlation_id_var
from sentinel.persistence.models import AuditEvent

GENESIS = "0" * 64
# Arbitrary constant key for pg_advisory_xact_lock: serialises appends so the chain
# can't fork under concurrent transactions.
_AUDIT_LOCK_KEY = 0x5E47_1AE1


def compute_hash(
    prev_hash: str,
    *,
    id: uuid.UUID,
    at: datetime,
    actor: str,
    action: str,
    subject_type: str,
    subject_id: str,
    correlation_id: str | None,
    data: dict[str, Any],
) -> str:
    canonical = json.dumps(
        {
            "prev": prev_hash,
            "id": str(id),
            "at": at.astimezone(UTC).isoformat(),
            "actor": actor,
            "action": action,
            "subject_type": subject_type,
            "subject_id": subject_id,
            "correlation_id": correlation_id,
            "data": data,
        },
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    )
    return hashlib.sha256(canonical.encode()).hexdigest()


class AuditLog:
    def __init__(self, clock: Clock) -> None:
        self._clock = clock

    async def append(
        self,
        session: AsyncSession,
        *,
        actor: str,
        action: str,
        subject_type: str,
        subject_id: str | uuid.UUID,
        data: dict[str, Any] | None = None,
    ) -> AuditEvent:
        """Append within the caller's transaction (commits/rolls back with the change)."""
        await session.execute(text("SELECT pg_advisory_xact_lock(:k)"), {"k": _AUDIT_LOCK_KEY})
        prev = (
            await session.execute(select(AuditEvent.hash).order_by(AuditEvent.seq.desc()).limit(1))
        ).scalar() or GENESIS
        payload = json.loads(json.dumps(data or {}, default=str))  # normalise for hashing
        event = AuditEvent(
            id=uuid7(),
            at=self._clock.now(),
            actor=actor[:120],
            action=action,
            subject_type=subject_type,
            subject_id=str(subject_id),
            correlation_id=correlation_id_var.get(),
            data=payload,
            prev_hash=prev,
        )
        event.hash = compute_hash(
            prev,
            id=event.id,
            at=event.at,
            actor=event.actor,
            action=action,
            subject_type=subject_type,
            subject_id=event.subject_id,
            correlation_id=event.correlation_id,
            data=payload,
        )
        session.add(event)
        await session.flush()
        return event


@dataclass(frozen=True)
class ChainVerification:
    ok: bool
    checked: int
    first_bad_seq: int | None = None
    reason: str | None = None


async def verify_chain(session: AsyncSession, batch: int = 1000) -> ChainVerification:
    prev, checked, last_seq = GENESIS, 0, 0
    while True:
        rows = (
            (
                await session.execute(
                    select(AuditEvent)
                    .where(AuditEvent.seq > last_seq)
                    .order_by(AuditEvent.seq)
                    .limit(batch)
                )
            )
            .scalars()
            .all()
        )
        if not rows:
            return ChainVerification(True, checked)
        for e in rows:
            if e.prev_hash != prev:
                return ChainVerification(False, checked, e.seq, "prev_hash does not link")
            expected = compute_hash(
                prev,
                id=e.id,
                at=e.at,
                actor=e.actor,
                action=e.action,
                subject_type=e.subject_type,
                subject_id=e.subject_id,
                correlation_id=e.correlation_id,
                data=e.data,
            )
            if e.hash != expected:
                return ChainVerification(False, checked, e.seq, "content hash mismatch")
            prev, checked, last_seq = e.hash, checked + 1, e.seq
