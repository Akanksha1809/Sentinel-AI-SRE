"""Evidence value objects (pure; persisted by evidence.store)."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
from typing import Any


class EvidenceKind(StrEnum):
    METRIC = "metric"  # observation from Prometheus
    LOG = "log"  # observation from Loki
    CHANGE = "change"  # observation from deployment history
    DERIVED = "derived"  # deterministic computation over observations
    GAP = "gap"  # a query that failed or returned no data (honest data gaps)


class Flag(StrEnum):
    POSSIBLE_PROMPT_INJECTION = "possible_prompt_injection"
    REDACTED = "redacted"
    TRUNCATED = "truncated"
    NO_DATA = "no_data"
    PRIMARY = "primary"  # directly related to the alert(s) that opened the incident


@dataclass(frozen=True)
class Point:
    ts: float
    value: float


@dataclass(frozen=True)
class Series:
    labels: dict[str, str]
    points: tuple[Point, ...]

    def values(self) -> list[float]:
        return [p.value for p in self.points]


@dataclass(frozen=True)
class LogLine:
    ts: float
    labels: dict[str, str]
    line: str


@dataclass
class Evidence:
    """One evidence item. `ref` is a stable, human/LLM-citable id within a collection."""

    ref: str
    kind: EvidenceKind
    source: str
    title: str
    summary: str
    query: str | None = None
    data: dict[str, Any] = field(default_factory=dict)
    flags: set[Flag] = field(default_factory=set)


@dataclass
class CollectionResult:
    window_start: datetime
    window_end: datetime
    onset: datetime
    items: list[Evidence]
    errors: list[str]

    @property
    def status(self) -> str:
        if not self.errors:
            return "complete"
        return "partial" if any(i.kind is not EvidenceKind.GAP for i in self.items) else "failed"
