"""Evidence collector: run code-owned queries for an incident and build evidence items.

All queries run concurrently with per-query error isolation. A failed query becomes a
`gap` item: data gaps are evidence too, and the investigation must see them.
"""

from __future__ import annotations

import asyncio
import json
import math
from collections import Counter, defaultdict
from collections.abc import Awaitable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any, TypeVar

import structlog

from sentinel.evidence.analysis import (
    ChangeCandidate,
    StepChange,
    detect_step,
    score_change,
)
from sentinel.evidence.clients import LogSource, MetricsSource
from sentinel.evidence.model import (
    CollectionResult,
    Evidence,
    EvidenceKind,
    Flag,
    LogLine,
    Series,
)
from sentinel.evidence.sanitize import sanitize_line
from sentinel.evidence.templates import (
    ERROR_LOG_RATE_BY_VERSION,
    ERROR_LOGS,
    ERRORS_BY_VERSION,
    METRICS,
    WARNING_LOGS,
    LogTemplate,
    MetricTemplate,
    label_value,
)

log = structlog.get_logger("sentinel.evidence")
T = TypeVar("T")

LOOKBACK = timedelta(minutes=30)
# Onset/step detection only uses data up to shortly after the first alert, so a later
# recovery (e.g. after a rollback) does not dilute the measured change.
DETECTION_TAIL = timedelta(minutes=2)
CHANGE_LOOKBACK = timedelta(minutes=60)
MAX_POINTS = 240
MAX_SAMPLES = 15


@dataclass(frozen=True)
class IncidentContext:
    """What to collect for. `alertnames` are the *focus* alerts (they decide `primary`).

    `focus_at` anchors onset detection and change correlation. It defaults to the first
    alert; when a new kind of alert joins an existing incident, the collection focuses on
    that alert, because one service can have two distinct problems in one incident.
    """

    service: str
    opened_at: datetime
    first_alert_at: datetime
    resolved_at: datetime | None
    alertnames: frozenset[str]
    focus_at: datetime | None = None

    @property
    def anchor(self) -> datetime:
        return self.focus_at or self.first_alert_at


def fmt(value: float, unit: str) -> str:
    if not math.isfinite(value):
        return "n/a"
    return {
        "percent": f"{value * 100:.1f}%",
        "seconds": f"{value * 1000:.0f}ms",
        "rps": f"{value:.2f} req/s",
        "count": f"{value:.0f}",
    }.get(unit, f"{value:.4g}")


def _iso(ts: float) -> str:
    return datetime.fromtimestamp(ts, UTC).isoformat(timespec="seconds")


def _series_json(series: list[Series]) -> list[dict[str, Any]]:
    return [
        {"labels": s.labels, "points": [[p.ts, round(p.value, 6)] for p in s.points]}
        for s in series
    ]


class EvidenceCollector:
    def __init__(self, metrics: MetricsSource, logs: LogSource) -> None:
        self._metrics = metrics
        self._logs = logs

    async def collect(
        self, ctx: IncidentContext, changes: list[ChangeCandidate], now: datetime
    ) -> CollectionResult:
        label_value(ctx.service)  # fail fast on an unsafe service name
        start = min(ctx.first_alert_at, ctx.opened_at) - LOOKBACK
        end = min(now, ctx.resolved_at + timedelta(minutes=10)) if ctx.resolved_at else now
        step = max(15.0, math.ceil((end - start).total_seconds() / MAX_POINTS))
        window_s = max(60, int((end - start).total_seconds()))
        errors: list[str] = []

        async def guarded(name: str, coro: Awaitable[T]) -> T | Exception:
            try:
                return await coro
            except Exception as exc:  # isolated: one failed query must not sink the rest
                errors.append(f"{name}: {exc}")
                log.warning("evidence query failed", query=name, error=str(exc))
                return exc

        svc = ctx.service
        ebv_q = ERRORS_BY_VERSION.format(svc=label_value(svc), window_s=window_s)
        lrv_q = ERROR_LOG_RATE_BY_VERSION.format(svc=label_value(svc))
        task = asyncio.ensure_future
        # Typed tasks, all started before any is awaited, so the queries run concurrently.
        metric_tasks = [
            task(guarded(t.ref, self._metrics.query_range(t.render(svc), start, end, step)))
            for t in METRICS
        ]
        error_logs_t = task(
            guarded(
                ERROR_LOGS.ref,
                self._logs.query_logs(ERROR_LOGS.render(svc), start, end, ERROR_LOGS.limit),
            )
        )
        warning_logs_t = task(
            guarded(
                WARNING_LOGS.ref,
                self._logs.query_logs(WARNING_LOGS.render(svc), start, end, WARNING_LOGS.limit),
            )
        )
        ebv_t = task(guarded("metric.errors_by_version", self._metrics.query_instant(ebv_q, end)))
        lrv_t = task(
            guarded(
                "log.error_rate_by_version", self._logs.query_log_metrics(lrv_q, start, end, step)
            )
        )
        await asyncio.gather(*metric_tasks, error_logs_t, warning_logs_t, ebv_t, lrv_t)
        metric_results = [t.result() for t in metric_tasks]

        items: list[Evidence] = []
        steps: dict[str, StepChange] = {}
        for tpl, res in zip(METRICS, metric_results, strict=True):
            item, step_change = self._metric_item(tpl, res, ctx)
            items.append(item)
            if step_change is not None:
                steps[tpl.ref] = step_change

        onset, onset_item = self._onset(ctx, steps)
        items.append(onset_item)

        items.append(self._log_item(ERROR_LOGS, error_logs_t.result(), ctx))
        items.append(self._log_item(WARNING_LOGS, warning_logs_t.result(), ctx))

        share = self._errors_by_version(ebv_t.result(), ebv_q, items)
        by_version, by_revision = self._log_rate_by_version(lrv_t.result(), lrv_q, items)

        relevant = [c for c in changes if onset - CHANGE_LOOKBACK <= c.deployed_at <= end]
        items.append(self._changes_item(svc, relevant, onset))
        items.append(self._correlation_item(relevant, onset, share, by_version, by_revision))
        return CollectionResult(start, end, onset, items, errors)

    # ------------------------------------------------------------------ metrics
    def _metric_item(
        self, tpl: MetricTemplate, res: list[Series] | Exception, ctx: IncidentContext
    ) -> tuple[Evidence, StepChange | None]:
        query = tpl.render(ctx.service)
        flags = {Flag.PRIMARY} if tpl.primary_for & ctx.alertnames else set()
        if isinstance(res, Exception):
            return Evidence(
                tpl.ref,
                EvidenceKind.GAP,
                "prometheus",
                tpl.title,
                f"Query failed: {res}",
                query,
                {"error": str(res)},
                flags,
            ), None
        if not res or all(not s.points for s in res):
            return Evidence(
                tpl.ref,
                EvidenceKind.METRIC,
                "prometheus",
                tpl.title,
                "No data returned for this window.",
                query,
                {"unit": tpl.unit},
                flags | {Flag.NO_DATA},
            ), None
        best: tuple[StepChange, dict[str, str]] | None = None
        cutoff = (ctx.anchor + DETECTION_TAIL).timestamp()
        for s in res:
            head = [p for p in s.points if p.ts <= cutoff]
            sc = detect_step(head, min_abs_delta=tpl.step_min_delta)
            if sc and sc.significant and (best is None or abs(sc.delta) > abs(best[0].delta)):
                best = (sc, s.labels)
        parts = []
        for s in res[:6]:
            if not s.points:
                continue
            values = s.values()
            who = f"{tpl.group_by}={s.labels.get(tpl.group_by, '?')}: " if tpl.group_by else ""
            parts.append(
                f"{who}now {fmt(values[-1], tpl.unit)} "
                f"(min {fmt(min(values), tpl.unit)}, max {fmt(max(values), tpl.unit)})"
            )
        summary = "; ".join(parts)
        data: dict[str, Any] = {"unit": tpl.unit, "series": _series_json(res)}
        if best:
            sc, labels = best
            who = f" ({tpl.group_by}={labels.get(tpl.group_by)})" if tpl.group_by else ""
            described = sc.describe(lambda v: fmt(v, tpl.unit))
            summary = f"Step change{who}: {described}. {summary}"
            data["step_change"] = {
                "at": sc.at.isoformat(),
                "before": sc.before,
                "after": sc.after,
                "delta": sc.delta,
                "labels": labels,
                "algorithm": "max mean-shift single change point, 3-sigma significance",
            }
        return Evidence(
            tpl.ref, EvidenceKind.METRIC, "prometheus", tpl.title, summary, query, data, flags
        ), best[0] if best else None

    def _onset(
        self, ctx: IncidentContext, steps: dict[str, StepChange]
    ) -> tuple[datetime, Evidence]:
        """Onset = earliest significant step in a primary metric (bounded by first alert)."""
        primary = [
            (ref, sc)
            for ref, sc in steps.items()
            if any(t.ref == ref and t.primary_for & ctx.alertnames for t in METRICS)
            and sc.at <= ctx.anchor + timedelta(minutes=1)
        ]
        if primary:
            ref, sc = min(primary, key=lambda x: x[1].at)
            onset, method = sc.at, f"earliest significant step change in {ref}"
        else:
            onset, method = ctx.anchor, "anchor alert start (no primary step change found)"
        lag = (ctx.anchor - onset).total_seconds()
        return onset, Evidence(
            "derived.onset",
            EvidenceKind.DERIVED,
            "sentinel",
            "Estimated incident onset",
            f"Onset {onset.strftime('%H:%M:%S')}Z via {method}; the anchoring alert fired "
            f"{lag:.0f}s later.",
            None,
            {
                "onset": onset.isoformat(),
                "method": method,
                "first_alert_at": ctx.first_alert_at.isoformat(),
                "anchor_at": ctx.anchor.isoformat(),
                "focus_alertnames": sorted(ctx.alertnames),
            },
        )

    # ------------------------------------------------------------------ logs
    def _log_item(
        self, tpl: LogTemplate, res: list[LogLine] | Exception, ctx: IncidentContext
    ) -> Evidence:
        query = tpl.render(ctx.service)
        flags = {Flag.PRIMARY} if tpl.primary_for & ctx.alertnames else set()
        if isinstance(res, Exception):
            return Evidence(
                tpl.ref,
                EvidenceKind.GAP,
                "loki",
                tpl.title,
                f"Query failed: {res}",
                query,
                {"error": str(res)},
                flags,
            )
        if not res:
            return Evidence(
                tpl.ref,
                EvidenceKind.LOG,
                "loki",
                tpl.title,
                "No matching log lines in this window.",
                query,
                {},
                flags | {Flag.NO_DATA},
            )
        signatures: dict[str, dict[str, Any]] = {}
        samples: list[dict[str, Any]] = []
        suspicious = 0
        for entry in res:
            clean = sanitize_line(entry.line)
            if clean.redacted:
                flags.add(Flag.REDACTED)
            if clean.truncated:
                flags.add(Flag.TRUNCATED)
            if clean.suspicious:
                suspicious += 1
            sig = self._signature(entry.line)
            bucket = signatures.setdefault(
                sig,
                {
                    "signature": sanitize_line(sig, 300).text,
                    "count": 0,
                    "versions": Counter(),
                    "config_revisions": Counter(),
                    "first_seen": entry.ts,
                    "last_seen": entry.ts,
                },
            )
            bucket["count"] += 1
            bucket["versions"][entry.labels.get("version", "?")] += 1
            bucket["config_revisions"][entry.labels.get("config_revision", "?")] += 1
            bucket["first_seen"] = min(bucket["first_seen"], entry.ts)
            bucket["last_seen"] = max(bucket["last_seen"], entry.ts)
            if len(samples) < MAX_SAMPLES:
                samples.append(
                    {
                        "ts": _iso(entry.ts),
                        "line": clean.text,
                        "suspicious": clean.suspicious,
                        "labels": {
                            k: entry.labels[k]
                            for k in ("container", "version", "config_revision", "level")
                            if k in entry.labels
                        },
                    }
                )
        if suspicious:
            flags.add(Flag.POSSIBLE_PROMPT_INJECTION)
        ranked = sorted(signatures.values(), key=lambda b: -b["count"])
        for b in ranked:
            b["versions"] = dict(b["versions"])
            b["config_revisions"] = dict(b["config_revisions"])
            b["first_seen"], b["last_seen"] = _iso(b["first_seen"]), _iso(b["last_seen"])
        top = ranked[0]
        capped = " (capped sample)" if len(res) >= tpl.limit else ""
        summary = (
            f"{len(res)} lines{capped}, {len(ranked)} distinct signature(s). Top: "
            f'"{top["signature"][:160]}" x{top["count"]} '
            f"(versions {top['versions']}, config {top['config_revisions']})."
        )
        if suspicious:
            summary += f" {suspicious} line(s) contain instruction-like text (treated as data)."
        return Evidence(
            tpl.ref,
            EvidenceKind.LOG,
            "loki",
            tpl.title,
            summary,
            query,
            {
                "total_lines": len(res),
                "signatures": ranked[:10],
                "samples": samples,
                "suspicious_lines": suspicious,
            },
            flags,
        )

    @staticmethod
    def _signature(line: str) -> str:
        """Group similar lines: message + final exception line, from the JSON log record."""
        try:
            record = json.loads(line)
        except ValueError:
            return line[:200]
        if not isinstance(record, dict):
            return line[:200]
        msg = str(record.get("msg", ""))[:200]
        exc = str(record.get("exception", "")).strip().splitlines()
        return f"{msg} | {exc[-1][:200]}" if exc else msg

    # ------------------------------------------------------------------ change
    def _errors_by_version(
        self, res: list[Series] | Exception, query: str, items: list[Evidence]
    ) -> dict[str, float] | None:
        if isinstance(res, Exception):
            items.append(
                Evidence(
                    "metric.errors_by_version",
                    EvidenceKind.GAP,
                    "prometheus",
                    "5xx responses by version",
                    f"Query failed: {res}",
                    query,
                )
            )
            return None
        counts = {s.labels.get("version", "?"): s.points[-1].value for s in res if s.points}
        total = sum(counts.values())
        share = {v: c / total for v, c in counts.items()} if total > 0 else None
        summary = (
            "No 5xx responses in the window."
            if not share
            else "5xx responses by version: "
            + ", ".join(
                f"{v}: {c:.0f} ({share[v]:.0%})"
                for v, c in sorted(counts.items(), key=lambda kv: -kv[1])
            )
        )
        items.append(
            Evidence(
                "metric.errors_by_version",
                EvidenceKind.METRIC,
                "prometheus",
                "5xx responses by version (incident window)",
                summary,
                query,
                {"counts": counts, "share": share or {}},
            )
        )
        return share

    def _log_rate_by_version(
        self, res: list[Series] | Exception, query: str, items: list[Evidence]
    ) -> tuple[dict[str, int] | None, dict[str, int] | None]:
        if isinstance(res, Exception):
            items.append(
                Evidence(
                    "log.error_rate_by_version",
                    EvidenceKind.GAP,
                    "loki",
                    "Error log volume by version",
                    f"Query failed: {res}",
                    query,
                )
            )
            return None, None
        by_version: dict[str, int] = defaultdict(int)
        by_revision: dict[str, int] = defaultdict(int)
        for s in res:
            total = int(sum(s.values()))
            by_version[s.labels.get("version", "?")] += total
            by_revision[s.labels.get("config_revision", "?")] += total
        summary = (
            "No error/critical log lines in the window."
            if not by_version
            else "Error/critical log lines: "
            + ", ".join(f"version {v}: {n}" for v, n in sorted(by_version.items()))
            + "; "
            + ", ".join(f"config {r}: {n}" for r, n in sorted(by_revision.items()))
        )
        items.append(
            Evidence(
                "log.error_rate_by_version",
                EvidenceKind.LOG,
                "loki",
                "Error log volume by version/config revision",
                summary,
                query,
                {
                    "by_version": dict(by_version),
                    "by_config_revision": dict(by_revision),
                    "series": _series_json(res),
                },
            )
        )
        return (dict(by_version) or None, dict(by_revision) or None)

    @staticmethod
    def _changes_item(service: str, changes: list[ChangeCandidate], onset: datetime) -> Evidence:
        if not changes:
            return Evidence(
                "change.deployments",
                EvidenceKind.CHANGE,
                "sentinel",
                "Recent deployments",
                f"No deployments recorded for {service} "
                f"in the {CHANGE_LOOKBACK.seconds // 60} minutes before onset.",
                None,
                {"deployments": []},
            )
        lines = []
        for c in sorted(changes, key=lambda c: c.deployed_at):
            rel = (onset - c.deployed_at).total_seconds()
            when = f"{abs(rel):.0f}s {'before' if rel >= 0 else 'after'} onset"
            cfg = (
                f", config {c.previous_config_revision}→{c.config_revision}"
                if c.config_revision != c.previous_config_revision
                else ""
            )
            lines.append(
                f"{c.previous_version or '?'}→{c.version}{cfg} at "
                f"{c.deployed_at.strftime('%H:%M:%S')}Z ({when})"
                + (f" [{c.change_ref}]" if c.change_ref else "")
            )
        return Evidence(
            "change.deployments",
            EvidenceKind.CHANGE,
            "sentinel",
            "Recent deployments",
            "; ".join(lines),
            None,
            {
                "deployments": [
                    {
                        "id": c.deployment_id,
                        "version": c.version,
                        "previous_version": c.previous_version,
                        "config_revision": c.config_revision,
                        "previous_config_revision": c.previous_config_revision,
                        "deployed_at": c.deployed_at.isoformat(),
                        "change_ref": c.change_ref,
                    }
                    for c in changes
                ]
            },
        )

    @staticmethod
    def _correlation_item(
        changes: list[ChangeCandidate],
        onset: datetime,
        share: dict[str, float] | None,
        by_version: dict[str, int] | None,
        by_revision: dict[str, int] | None,
    ) -> Evidence:
        title = "Change correlation (deterministic score)"
        if not changes:
            return Evidence(
                "derived.change_correlation",
                EvidenceKind.DERIVED,
                "sentinel",
                title,
                "No recorded change precedes onset, so a change-induced "
                "cause is not supported by the available change history.",
                None,
                {"scores": []},
            )
        causes = [c for c in changes if not c.is_remediation]
        if not causes:
            return Evidence(
                "derived.change_correlation",
                EvidenceKind.DERIVED,
                "sentinel",
                title,
                "Only remediation changes (rollbacks) in the window; no candidate cause.",
                None,
                {"scores": []},
            )
        scores = sorted(
            (
                score_change(
                    c,
                    onset,
                    error_share_by_version=share,
                    error_logs_by_version=by_version,
                    error_logs_by_revision=by_revision,
                )
                for c in causes
            ),
            key=lambda s: -s.score,
        )
        best = scores[0]
        c = best.candidate
        summary = (
            f"Top candidate: {c.previous_version or '?'}→{c.version}"
            + (f" config {c.config_revision}" if c.config_revision else "")
            + (f" [{c.change_ref}]" if c.change_ref else "")
            + f" score {best.score:.2f} ({'; '.join(best.reasons)})."
        )
        if len(scores) > 1:
            summary += f" Next best score {scores[1].score:.2f}."
        return Evidence(
            "derived.change_correlation",
            EvidenceKind.DERIVED,
            "sentinel",
            title,
            summary,
            None,
            {
                "algorithm": "0.5·exp(-Δt/600s) + 0.3·5xx share + 0.2·error-log "
                "share (renormalised over available factors)",
                "scores": [
                    {
                        "deployment_id": s.candidate.deployment_id,
                        "version": s.candidate.version,
                        "config_revision": s.candidate.config_revision,
                        "score": s.score,
                        "seconds_before_onset": s.seconds_before_onset,
                        "time_factor": s.time_factor,
                        "metric_factor": s.metric_factor,
                        "log_factor": s.log_factor,
                        "reasons": list(s.reasons),
                    }
                    for s in scores
                ],
            },
        )
