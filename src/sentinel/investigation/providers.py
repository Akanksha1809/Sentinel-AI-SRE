"""Investigation providers: a deterministic offline mock and a local Ollama model.

Providers return *raw* JSON-like dicts; nothing they return is trusted until it passes
`investigation.validate`. Neither provider has tools or any path to execution.
"""

from __future__ import annotations

import asyncio
import json
from typing import Any, Protocol

import httpx

from sentinel.investigation.prompt import build_messages
from sentinel.investigation.schemas import EvidenceView, InvestigationRequest, report_json_schema


class ProviderError(RuntimeError):
    pass


class InvestigationProvider(Protocol):
    name: str
    model: str
    is_mock: bool

    async def investigate(self, request: InvestigationRequest) -> dict[str, Any]: ...


class OllamaProvider:
    """Local LLM via Ollama `/api/chat` with JSON-schema constrained decoding."""

    name = "ollama"
    is_mock = False

    def __init__(
        self,
        base_url: str,
        model: str,
        *,
        timeout_s: float = 240.0,
        attempts: int = 2,
        num_ctx: int = 4096,
        seed: int = 7,
        keep_alive: str = "2m",
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self.model = model
        self._attempts = attempts
        self._options = {"temperature": 0, "seed": seed, "num_ctx": num_ctx}
        self._keep_alive = keep_alive  # unload soon after: RAM is scarce on the demo host
        self._client = httpx.AsyncClient(base_url=base_url, timeout=timeout_s, transport=transport)

    async def investigate(self, request: InvestigationRequest) -> dict[str, Any]:
        messages = build_messages(request)
        last: Exception | None = None
        for attempt in range(self._attempts):
            try:
                resp = await self._client.post(
                    "/api/chat",
                    json={
                        "model": self.model,
                        "messages": messages,
                        "stream": False,
                        "format": report_json_schema(
                            [e.ref for e in request.evidence],
                            [str(r["id"]) for r in request.runbooks],
                        ),
                        "options": self._options,
                        "keep_alive": self._keep_alive,
                    },
                )
            except httpx.TimeoutException as exc:
                raise ProviderError(f"ollama timed out after {self._client.timeout.read}s") from exc
            except httpx.TransportError as exc:
                raise ProviderError(f"ollama unreachable: {type(exc).__name__}") from exc
            if resp.status_code != 200:
                raise ProviderError(f"ollama HTTP {resp.status_code}: {resp.text[:200]}")
            body = resp.json()
            content = (body.get("message") or {}).get("content", "")
            try:
                parsed = json.loads(content)
                if not isinstance(parsed, dict):
                    raise ValueError("top-level JSON is not an object")
                parsed["_usage"] = {
                    k: body.get(k) for k in ("total_duration", "prompt_eval_count", "eval_count")
                }
                return parsed
            except ValueError as exc:
                last = exc
                if attempt + 1 < self._attempts:
                    await asyncio.sleep(0)  # bounded retry; temperature 0 + new seed below
                    self._options = {**self._options, "seed": self._options["seed"] + 1}
        raise ProviderError(f"model returned invalid JSON after {self._attempts} attempts: {last}")

    async def health(self) -> dict[str, Any]:
        resp = await self._client.get("/api/tags", timeout=5)
        models = [m.get("name") for m in resp.json().get("models", [])]
        return {"reachable": True, "model_available": self.model in models, "models": models}

    async def aclose(self) -> None:
        await self._client.aclose()


class MockProvider:
    """Deterministic, rule-based investigator for tests and offline demos.

    Its output is clearly labelled MOCK (provider=mock) everywhere it is shown. It
    applies transparent heuristics over the same evidence the LLM sees.
    """

    name = "mock"
    model = "rules-v1"
    is_mock = True

    async def investigate(self, request: InvestigationRequest) -> dict[str, Any]:
        ev = {e.ref: e for e in request.evidence}
        service = str(request.incident.get("service"))
        gaps = [f"{e.ref}: {e.summary}" for e in request.evidence if e.kind == "gap"]
        corr = _top_score(ev.get("derived.change_correlation"))
        mem = ev.get("metric.memory_ratio")
        restarts = ev.get("metric.restarts")
        errors = ev.get("log.errors")
        alertnames = set(request.incident.get("alertnames", []))
        crash_like = bool(alertnames & {"ShopApiCrashLooping", "ShopApiDown"}) or (
            restarts is not None and "Step change" in restarts.summary
        )
        cite = [
            r
            for r in (
                "derived.change_correlation",
                "change.deployments",
                "metric.error_ratio",
                "metric.errors_by_version",
                "log.errors",
                "metric.restarts",
                "derived.onset",
            )
            if r in ev
        ]

        if corr and corr["score"] >= 0.6:
            version_cfg = (
                f"config revision {corr['config_revision']}"
                if crash_like and corr.get("config_revision")
                else f"version {corr['version']}"
            )
            dep = _deployment(ev.get("change.deployments"), corr)
            params: dict[str, str | int] = {"service": service}
            if dep and dep.get("previous_version"):
                params["target_version"] = dep["previous_version"]
            if (
                dep
                and dep.get("previous_config_revision")
                and dep.get("previous_config_revision") != dep.get("config_revision")
            ):
                params["target_config_revision"] = dep["previous_config_revision"]
            confidence = round(min(0.9, corr["score"]), 2)
            report = {
                "summary": (
                    f"[MOCK] Onset follows a change to {version_cfg} "
                    f"(correlation score {corr['score']:.2f}). Errors are concentrated "
                    "in the changed release, which points to a regression it "
                    "introduced."
                ),
                "suspected_root_cause": {
                    "statement": f"The change to {version_cfg} introduced a regression"
                    + (f": {_top_signature(errors)}" if errors else "")
                    + ".",
                    "confidence": confidence,
                    "cited_evidence": cite[:5],
                },
                "alternative_hypotheses": [
                    {
                        "statement": "Coincidental infrastructure or dependency failure.",
                        "confidence": round(max(0.05, 1 - confidence - 0.05), 2),
                        "cited_evidence": [
                            r
                            for r in (
                                "metric.errors_by_version",
                                "derived.change_correlation",
                                "metric.replicas_running",
                            )
                            if r in ev
                        ][:2],
                        "why_less_likely": "Errors are confined to the new release and began "
                        "right after it was deployed.",
                    }
                ],
                "recommended_actions": [
                    {
                        "runbook_id": "rollback-deployment",
                        "parameters": params,
                        "rationale": "Restore the last known-good release/config.",
                        "cited_evidence": cite[:3],
                    }
                ]
                if "target_version" in params
                else [],
                "next_investigative_steps": [
                    "Review the diff of the suspect change.",
                    "Confirm recovery after rollback using the runbook's checks.",
                ],
                "data_gaps": gaps,
            }
        elif mem is not None and "Step change" in mem.summary and "rose" in mem.summary:
            report = {
                "summary": "[MOCK] Container memory grew steadily toward its limit with no "
                "correlated deployment, consistent with a leak or memory "
                "pressure in the running processes.",
                "suspected_root_cause": {
                    "statement": "Unbounded memory growth inside the service process "
                    "(leak or unbounded cache).",
                    "confidence": 0.7,
                    "cited_evidence": [
                        r
                        for r in (
                            "metric.memory_ratio",
                            "change.deployments",
                            "derived.change_correlation",
                            "log.warnings",
                        )
                        if r in ev
                    ],
                },
                "alternative_hypotheses": [
                    {
                        "statement": "A traffic increase raised legitimate memory use.",
                        "confidence": 0.15,
                        "cited_evidence": [r for r in ("metric.request_rate",) if r in ev],
                        "why_less_likely": "Request rate did not rise in proportion.",
                    }
                ],
                "recommended_actions": [
                    {
                        "runbook_id": "restart-service",
                        "parameters": {"service": service},
                        "rationale": "A rolling restart releases leaked memory (mitigation only; "
                        "the underlying leak needs a code fix).",
                        "cited_evidence": [r for r in ("metric.memory_ratio",) if r in ev],
                    }
                ],
                "next_investigative_steps": [
                    "Capture a heap profile before the restart if possible.",
                    "Open a bug for the leak; restart only mitigates it.",
                ],
                "data_gaps": gaps,
            }
        else:
            report = {
                "summary": "[MOCK] The evidence does not support a confident root cause.",
                "suspected_root_cause": {
                    "statement": "Undetermined from the available evidence.",
                    "confidence": 0.2,
                    "cited_evidence": [e.ref for e in request.evidence if "primary" in e.flags][:5],
                },
                "alternative_hypotheses": [],
                "recommended_actions": [],
                "next_investigative_steps": ["Collect fresh evidence and review dashboards."],
                "data_gaps": gaps or ["No strong signal in the collected evidence."],
            }
        return report


def _top_score(view: EvidenceView | None) -> dict[str, Any] | None:
    if view is None:
        return None
    scores = view.details.get("scores") or []
    return scores[0] if scores else None


def _deployment(view: EvidenceView | None, score: dict[str, Any]) -> dict[str, Any] | None:
    if view is None:
        return None
    matches = [
        d
        for d in view.details.get("deployments", [])
        if d.get("version") == score.get("version")
        and d.get("config_revision") == score.get("config_revision")
    ]
    return matches[-1] if matches else None


def _top_signature(view: EvidenceView | None) -> str:
    sigs = (view.details.get("signatures") if view else None) or []
    return str(sigs[0].get("signature", ""))[:160] if sigs else ""
