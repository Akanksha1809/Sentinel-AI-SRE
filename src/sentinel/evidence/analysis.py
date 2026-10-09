"""Deterministic derived signals: step-change detection and change correlation.

These are *computations*, labelled `derived`, with their inputs and algorithm recorded,
so a reviewer can check every number. They are not AI output.
"""

from __future__ import annotations

import math
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from statistics import fmean, pstdev

from sentinel.evidence.model import Point


@dataclass(frozen=True)
class StepChange:
    at: datetime
    before: float
    after: float
    delta: float
    significant: bool
    samples_before: int
    samples_after: int

    def describe(self, fmt: Callable[[float], str] = "{:.4g}".format) -> str:
        direction = "rose" if self.delta > 0 else "fell"
        return (
            f"{direction} from {fmt(self.before)} to {fmt(self.after)} "
            f"at {self.at.strftime('%H:%M:%S')}Z"
        )


def detect_step(
    points: list[Point], *, min_segment: int = 3, min_abs_delta: float = 0.0, sigma: float = 3.0
) -> StepChange | None:
    """Single change point that maximises the between-segment mean difference.

    Significant when |after - before| > max(min_abs_delta, sigma * stdev(before)), with a
    small floor so a perfectly flat baseline doesn't make any blip significant.
    """
    points = [p for p in points if math.isfinite(p.value)]  # Prometheus can return NaN
    if len(points) < 2 * min_segment:
        return None
    values = [p.value for p in points]
    best_i, best_score = None, -1.0
    for i in range(min_segment, len(values) - min_segment + 1):
        before, after = values[:i], values[i:]
        score = abs(fmean(after) - fmean(before)) * math.sqrt(len(before) * len(after))
        if score > best_score:
            best_i, best_score = i, score
    if best_i is None:  # unreachable given the length check; explicit, not an assert
        return None
    before, after = values[:best_i], values[best_i:]
    b, a = fmean(before), fmean(after)
    noise = pstdev(before) if len(before) > 1 else 0.0
    threshold = max(min_abs_delta, sigma * noise, 1e-9)
    return StepChange(
        at=datetime.fromtimestamp(points[best_i].ts, UTC),
        before=b,
        after=a,
        delta=a - b,
        significant=abs(a - b) > threshold,
        samples_before=len(before),
        samples_after=len(after),
    )


@dataclass(frozen=True)
class ChangeCandidate:
    deployment_id: str
    service: str
    version: str
    previous_version: str | None
    config_revision: str | None
    previous_config_revision: str | None
    deployed_at: datetime
    change_ref: str | None
    source: str = "deploy"

    @property
    def is_remediation(self) -> bool:
        return self.source == "rollback"


@dataclass(frozen=True)
class CorrelationScore:
    candidate: ChangeCandidate
    score: float
    seconds_before_onset: float
    time_factor: float
    metric_factor: float | None
    log_factor: float | None
    reasons: tuple[str, ...]


TIME_TAU_S = 600.0  # proximity decays with a 10-minute time constant
MAX_AFTER_ONSET_S = 120.0  # a change up to 2 minutes after onset may still be causal (lag)
AFTER_ONSET_TAU_S = 60.0  # ...but is penalised steeply


def score_change(
    candidate: ChangeCandidate,
    onset: datetime,
    *,
    error_share_by_version: dict[str, float] | None,
    error_logs_by_version: dict[str, int] | None,
    error_logs_by_revision: dict[str, int] | None,
) -> CorrelationScore:
    """Score how well a change explains the incident (0..1), with explainable factors.

    - time: exp(-Δ/τ) for changes before onset; changes long after onset score 0.
    - metric: share of 5xx traffic served by the changed version (if measurable).
    - logs: share of error log lines emitted by the changed version/config revision.
    Missing factors are left out and the remaining weights are renormalised.
    """
    delta = (onset - candidate.deployed_at).total_seconds()
    reasons: list[str] = []
    if delta < -MAX_AFTER_ONSET_S:
        time_factor = 0.0
        reasons.append(f"deployed {-delta:.0f}s *after* onset")
    elif delta < 0:
        time_factor = 0.5 * math.exp(delta / AFTER_ONSET_TAU_S)
        reasons.append(f"deployed {-delta:.0f}s after onset (onset estimate may lag)")
    else:
        time_factor = math.exp(-delta / TIME_TAU_S)
        reasons.append(f"deployed {delta:.0f}s before onset")

    def share(counts: dict[str, int] | None, key: str | None) -> float | None:
        if not counts or key is None:
            return None
        total = sum(counts.values())
        return counts.get(key, 0) / total if total else None

    # A measured share of zero is evidence *against* the change, not a missing factor.
    metric_factor = (
        error_share_by_version.get(candidate.version, 0.0) if error_share_by_version else None
    )
    if metric_factor is not None:
        reasons.append(
            f"{metric_factor:.0%} of 5xx responses served by version {candidate.version}"
        )
    log_factor = share(error_logs_by_version, candidate.version)
    config_changed = (
        candidate.config_revision is not None
        and candidate.config_revision != candidate.previous_config_revision
    )
    if config_changed:
        rev_share = share(error_logs_by_revision, candidate.config_revision)
        if rev_share is not None and (log_factor is None or rev_share >= log_factor):
            log_factor = rev_share
            reasons.append(
                f"{rev_share:.0%} of error logs from config revision {candidate.config_revision}"
            )
    if log_factor is not None and not any("error logs" in r for r in reasons):
        reasons.append(f"{log_factor:.0%} of error logs from version {candidate.version}")

    weights = [(0.5, time_factor), (0.3, metric_factor), (0.2, log_factor)]
    present = [(w, f) for w, f in weights if f is not None]
    score = sum(w * f for w, f in present) / sum(w for w, _ in present)
    if time_factor == 0.0:
        score = 0.0  # a change after the problem started cannot have caused it
    return CorrelationScore(
        candidate,
        round(score, 3),
        delta,
        round(time_factor, 3),
        None if metric_factor is None else round(metric_factor, 3),
        None if log_factor is None else round(log_factor, 3),
        tuple(reasons),
    )
