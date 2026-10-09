"""Identifier and time primitives (injectable for deterministic tests)."""

from __future__ import annotations

import os
import time
import uuid
from datetime import UTC, datetime, timedelta
from typing import Protocol


def uuid7() -> uuid.UUID:
    """RFC 9562 UUIDv7: 48-bit unix-ms timestamp + random bits, so IDs sort by creation time."""
    ms = time.time_ns() // 1_000_000
    rand = int.from_bytes(os.urandom(10), "big")
    value = (ms & ((1 << 48) - 1)) << 80  # unix_ts_ms (48 bits)
    value |= 0x7 << 76  # version (4 bits)
    value |= ((rand >> 62) & 0xFFF) << 64  # rand_a (12 bits)
    value |= 0b10 << 62  # variant (2 bits)
    value |= rand & ((1 << 62) - 1)  # rand_b (62 bits)
    return uuid.UUID(int=value)


class Clock(Protocol):
    def now(self) -> datetime: ...


class SystemClock:
    def now(self) -> datetime:
        return datetime.now(UTC)


class ManualClock:
    """Deterministic clock for tests and simulations; advance it explicitly."""

    def __init__(self, start: datetime | None = None) -> None:
        self._now = start or datetime(2026, 10, 9, 12, 0, tzinfo=UTC)

    def now(self) -> datetime:
        return self._now

    def advance(self, **delta: float) -> datetime:
        self._now += timedelta(**delta)
        return self._now
