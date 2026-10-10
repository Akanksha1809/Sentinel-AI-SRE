"""Pure Markdown assembly for postmortems: no DB, no I/O, fully unit-testable.

The document is a fixed sequence of sections, each wrapped in an HTML-comment marker
(`<!-- section:key:start -->` ... `<!-- section:key:end -->`) so a regenerate can tell
which parts it owns. `GENERATED_SECTIONS` are rebuilt fresh every time; `HUMAN_SECTIONS`
are seeded with a placeholder once and never overwritten by a later regenerate — only
an explicit edit (a PUT of the whole document) changes them.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime
from typing import Any

GENERATED_SECTIONS = ("summary", "impact", "timeline", "root_cause", "evidence", "remediation")
HUMAN_SECTIONS = ("lessons_learned", "follow_ups")
SECTION_ORDER = GENERATED_SECTIONS + HUMAN_SECTIONS
HUMAN_PLACEHOLDERS = {
    "lessons_learned": "_Not yet written. What went well, what didn't, what was lucky?_",
    "follow_ups": "_Not yet written. List concrete, owned, dated follow-up items._",
}
_TITLES = {
    "summary": "Summary",
    "impact": "Impact",
    "timeline": "Timeline",
    "root_cause": "Root Cause",
    "evidence": "Evidence",
    "remediation": "Remediation",
    "lessons_learned": "Lessons Learned",
    "follow_ups": "Follow-ups",
}

_START = re.compile(r"<!--\s*section:(\w+):start\s*-->")
_END_FOR = {k: re.compile(rf"<!--\s*section:{re.escape(k)}:end\s*-->") for k in SECTION_ORDER}


def _fence(key: str, body: str) -> str:
    heading = f"## {_TITLES.get(key, key.replace('_', ' ').title())}"
    return f"<!-- section:{key}:start -->\n{heading}\n\n{body.strip()}\n<!-- section:{key}:end -->"


def extract_sections(markdown: str) -> dict[str, str]:
    """Best-effort: a human who deleted the markers just loses auto-preservation for
    that section on the next regenerate, not an error."""
    found: dict[str, str] = {}
    for m in _START.finditer(markdown):
        key = m.group(1)
        end = _END_FOR.get(key)
        if end is None:
            continue
        end_m = end.search(markdown, m.end())
        if not end_m:
            continue
        body = markdown[m.end() : end_m.start()].strip()
        body = re.sub(r"^##[^\n]*\n+", "", body, count=1)  # drop the re-derivable heading
        found[key] = body
    return found


def build_document(title: str, sections: dict[str, str]) -> str:
    parts = [f"# {title}"]
    for key in SECTION_ORDER:
        parts.append(_fence(key, sections.get(key, HUMAN_PLACEHOLDERS.get(key, ""))))
    return "\n\n".join(parts) + "\n"


def _fmt_duration(seconds: float) -> str:
    seconds = max(0, int(seconds))
    if seconds < 60:
        return f"{seconds}s"
    m, s = divmod(seconds, 60)
    if m < 60:
        return f"{m}m{s:02d}s"
    h, m = divmod(m, 60)
    return f"{h}h{m:02d}m"


@dataclass(frozen=True)
class IncidentFacts:
    short_id: str
    service: str
    environment: str
    title: str
    severity: str
    status: str
    opened_at: datetime
    resolved_at: datetime | None
    resolved_verified: bool
    alertnames: tuple[str, ...]


@dataclass(frozen=True)
class TimelineFact:
    at: datetime
    kind: str
    actor: str
    summary: str


@dataclass(frozen=True)
class HypothesisFact:
    label: str  # e.g. "MOCK provider" or "ollama:qwen2.5-coder:3b"
    statement: str
    confidence: float
    uncited: bool


@dataclass(frozen=True)
class EvidenceFact:
    ref: str
    title: str
    summary: str


@dataclass(frozen=True)
class ActionFact:
    runbook_id: str
    status: str
    parameters: dict[str, Any]
    dry_run: bool
    approver: str | None
    approval_reason: str | None
    execution_outcome: str | None
    verification_passed: bool | None
    verification_samples: int


def render_summary(f: IncidentFacts) -> str:
    verified = "verified" if f.resolved_verified else "**not** independently verified"
    state = (
        f"resolved ({verified})"
        if f.status == "resolved"
        else "closed"
        if f.status == "closed"
        else f"still **{f.status}**"
    )
    alerts = ", ".join(f.alertnames) or "none recorded"
    return (
        f"**{f.short_id}** on `{f.service}` ({f.environment}): {f.title}\n\n"
        f"- Severity: **{f.severity}**\n- Status: {state}\n- Triggering alert(s): {alerts}"
    )


def render_impact(f: IncidentFacts) -> str:
    if f.resolved_at is None:
        return "Incident is still open; duration not yet known."
    duration = (f.resolved_at - f.opened_at).total_seconds()
    return (
        f"- Opened: {f.opened_at.strftime('%Y-%m-%d %H:%M:%S')} UTC\n"
        f"- Resolved: {f.resolved_at.strftime('%Y-%m-%d %H:%M:%S')} UTC\n"
        f"- Duration: **{_fmt_duration(duration)}**"
    )


def render_timeline(events: list[TimelineFact]) -> str:
    if not events:
        return "_No timeline events recorded._"
    return "\n".join(
        f"- `{e.at.strftime('%H:%M:%S')}` **{e.kind}** ({e.actor}) — {e.summary}" for e in events
    )


def render_root_cause(hypotheses: list[HypothesisFact]) -> str:
    if not hypotheses:
        return "_No investigation ran for this incident; root cause not determined by Sentinel._"
    lines = [
        "> The statements below are AI-generated hypotheses, not confirmed facts. "
        "Verify against the Evidence section before treating them as the cause."
    ]
    for h in hypotheses:
        flag = " _(uncited — not supported by the collected evidence)_" if h.uncited else ""
        lines.append(
            f"\n**[AI, {h.label}]** (confidence {h.confidence:.2f}){flag}\n\n{h.statement}"
        )
    return "\n".join(lines)


def render_evidence(items: list[EvidenceFact]) -> str:
    if not items:
        return "_No evidence was collected for this incident._"
    return "\n".join(f"- **{e.title}** (`{e.ref}`): {e.summary}" for e in items)


def render_remediation(actions: list[ActionFact]) -> str:
    if not actions:
        return "_No remediation action was proposed for this incident._"
    lines = []
    for a in actions:
        mode = "dry-run" if a.dry_run else "live"
        line = f"- `{a.runbook_id}` ({mode}) — **{a.status}**"
        if a.approver:
            line += f", approved by {a.approver}" + (
                f' ("{a.approval_reason}")' if a.approval_reason else ""
            )
        if a.execution_outcome:
            line += f"; executed: {a.execution_outcome}"
        if a.verification_passed is not None:
            verdict = "passed" if a.verification_passed else "failed"
            line += f"; verification {verdict} ({a.verification_samples} sample(s))"
        lines.append(line)
    return "\n".join(lines)
