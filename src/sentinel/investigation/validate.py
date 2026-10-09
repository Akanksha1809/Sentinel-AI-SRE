"""Validate untrusted model output before it is stored or shown (threat model T1-T3, T6).

- Schema: strict Pydantic parse with bounded sizes (failure → investigation failed).
- Citations: refs not present in the evidence are dropped and recorded. A hypothesis
  left with no valid citation keeps its text but its confidence is capped at 0.3 and it
  is flagged `uncited`.
- Actions: only catalogue runbooks; parameters must pass the runbook's typed/bounded
  validation and target the incident's service. Rejected suggestions are recorded with
  the reason, never silently dropped and never executable.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from pydantic import ValidationError

from sentinel.investigation.schemas import Hypothesis, InvestigationReport
from sentinel.remediation.runbooks import ParameterError, RunbookCatalog

UNCITED_CONFIDENCE_CAP = 0.3
_DECORATION = re.compile(r"^(?:ref|evidence|id)\s*[:=]\s*", re.IGNORECASE)


def normalise_ref(raw: str) -> str:
    """Strip harmless decoration models add (`ref:x`, `[x]`, quotes, whitespace, case).

    Only used to *find* a ref; the result is accepted only if it exactly matches a ref
    that exists in the evidence.
    """
    text = raw.strip().strip("[](){}<>`'\"").strip()
    return _DECORATION.sub("", text).strip().lower()


class ReportValidationError(ValueError):
    pass


@dataclass
class ValidationOutcome:
    report: InvestigationReport
    dropped_citations: list[str] = field(default_factory=list)
    uncited: list[str] = field(default_factory=list)
    rejected_actions: list[dict[str, Any]] = field(default_factory=list)
    accepted_actions: list[dict[str, Any]] = field(default_factory=list)
    normalised_citations: list[str] = field(default_factory=list)

    def summary(self) -> dict[str, Any]:
        return {
            "dropped_citations": self.dropped_citations,
            "uncited": self.uncited,
            "rejected_actions": self.rejected_actions,
            "accepted_actions": self.accepted_actions,
            "normalised_citations": self.normalised_citations,
        }


def validate_report(
    raw: dict[str, Any], *, evidence_refs: set[str], catalog: RunbookCatalog, service: str
) -> ValidationOutcome:
    try:
        report = InvestigationReport.model_validate(raw)
    except ValidationError as exc:
        first = exc.errors()[0]
        raise ReportValidationError(
            f"model output does not match the schema at {'.'.join(map(str, first['loc']))}: "
            f"{first['msg']}"
        ) from exc

    outcome = ValidationOutcome(report=report)

    def resolve(raw_ref: str) -> str | None:
        if raw_ref in evidence_refs:
            return raw_ref
        normalised = normalise_ref(raw_ref)
        if normalised in evidence_refs:
            outcome.normalised_citations.append(f"{raw_ref!r} -> {normalised}")
            return normalised
        return None

    def check(h: Hypothesis, label: str) -> None:
        resolved = [(r, resolve(r)) for r in h.cited_evidence]
        valid = list(dict.fromkeys(ok for _, ok in resolved if ok))
        outcome.dropped_citations += [f"{label}: {r}" for r, ok in resolved if ok is None]
        h.cited_evidence = valid
        if not valid:
            outcome.uncited.append(label)
            h.confidence = min(h.confidence, UNCITED_CONFIDENCE_CAP)

    check(report.suspected_root_cause, "suspected_root_cause")
    for i, alt in enumerate(report.alternative_hypotheses):
        check(alt, f"alternative_hypotheses[{i}]")

    seen: set[tuple[str, str]] = set()
    for action in report.recommended_actions:
        runbook = catalog.get(action.runbook_id)
        entry: dict[str, Any] = {
            "runbook_id": action.runbook_id[:64],
            "parameters": action.parameters,
        }
        if runbook is None:
            outcome.rejected_actions.append({**entry, "reason": "not in the runbook catalogue"})
            continue
        try:
            params = runbook.validate_parameters(dict(action.parameters), service=service)
        except ParameterError as exc:
            outcome.rejected_actions.append({**entry, "reason": str(exc)})
            continue
        key = (runbook.id, repr(sorted(params.items())))
        if key in seen:
            continue
        seen.add(key)
        cited = [ok for ok in (resolve(r) for r in action.cited_evidence) if ok]
        outcome.accepted_actions.append(
            {
                "runbook_id": runbook.id,
                "runbook_version": runbook.version,
                "runbook_sha256": runbook.sha256,
                "parameters": params,
                "rationale": action.rationale,
                "cited_evidence": cited,
                "disruptive": runbook.disruptive,
                "requires_approval": True,
            }
        )
    return outcome
