"""Investigation input/output contracts.

`InvestigationReport` is the schema the model must satisfy. The same JSON schema is
passed to Ollama's `format` (constrained decoding) and enforced again with Pydantic.
Every field is bounded. Server-side fields (provider, model, validation) are never
taken from model output.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field

REF = r"^[a-z]+\.[a-z0-9_]{1,60}$"


class _Out(BaseModel):
    model_config = ConfigDict(extra="ignore")  # tolerate extra keys; never trust them


class Hypothesis(_Out):
    statement: str = Field(min_length=3, max_length=600)
    confidence: float = Field(ge=0.0, le=1.0)
    cited_evidence: list[str] = Field(default_factory=list, max_length=10)


class AlternativeHypothesis(Hypothesis):
    why_less_likely: str = Field(default="", max_length=400)


class ProposedAction(_Out):
    runbook_id: str = Field(max_length=64)
    parameters: dict[str, str | int] = Field(default_factory=dict, max_length=8)
    rationale: str = Field(default="", max_length=400)
    cited_evidence: list[str] = Field(default_factory=list, max_length=10)


class InvestigationReport(_Out):
    summary: str = Field(min_length=3, max_length=800)
    suspected_root_cause: Hypothesis
    alternative_hypotheses: list[AlternativeHypothesis] = Field(default_factory=list, max_length=4)
    recommended_actions: list[ProposedAction] = Field(default_factory=list, max_length=3)
    next_investigative_steps: list[str] = Field(default_factory=list, max_length=6)
    data_gaps: list[str] = Field(default_factory=list, max_length=6)


def _inline_refs(schema: dict[str, Any]) -> dict[str, Any]:
    """Inline $defs ($ref) so constrained-decoding grammars don't depend on ref support."""
    defs = schema.pop("$defs", {})

    def walk(node: Any) -> Any:
        if isinstance(node, dict):
            if "$ref" in node:
                return walk(dict(defs[node["$ref"].rsplit("/", 1)[-1]]))
            return {k: walk(v) for k, v in node.items() if k != "title"}
        if isinstance(node, list):
            return [walk(v) for v in node]
        return node

    result: dict[str, Any] = walk(schema)
    return result


def report_json_schema(
    evidence_refs: list[str] | None = None, runbook_ids: list[str] | None = None
) -> dict[str, Any]:
    """JSON schema for constrained decoding.

    With `evidence_refs` / `runbook_ids`, citations and runbook ids are `enum`s of the
    values that actually exist for this request, so the model *cannot* emit invented refs
    or off-catalogue runbooks. Validation still re-checks everything (defence in depth).
    """
    schema = _inline_refs(InvestigationReport.model_json_schema())

    def constrain(node: Any) -> None:
        if isinstance(node, dict):
            props = node.get("properties", {})
            if evidence_refs and "cited_evidence" in props:
                props["cited_evidence"]["items"] = {"type": "string", "enum": evidence_refs}
            if runbook_ids and "runbook_id" in props:
                props["runbook_id"] = {"type": "string", "enum": runbook_ids}
            for value in node.values():
                constrain(value)
        elif isinstance(node, list):
            for value in node:
                constrain(value)

    constrain(schema)
    return schema


class EvidenceView(BaseModel):
    """Compact, model-facing view of one evidence item (no raw time series)."""

    ref: str
    kind: str
    title: str
    summary: str
    flags: list[str]
    details: dict[str, Any] = Field(default_factory=dict)


class InvestigationRequest(BaseModel):
    incident: dict[str, Any]
    evidence: list[EvidenceView]
    runbooks: list[dict[str, Any]]
    evidence_status: str
    evidence_errors: list[str]
