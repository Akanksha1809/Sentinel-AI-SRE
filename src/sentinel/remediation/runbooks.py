"""Runbook catalogue: version-controlled YAML, schema-validated and content-hashed at load.

Runbooks are the *only* remediation an investigation may recommend. Parameters use a
small set of typed, bounded kinds, so model output can never smuggle in free-form
values. Verification checks reference named signals that code maps to fixed queries.
"""

from __future__ import annotations

import hashlib
import re
from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, model_validator

ParamType = Literal["service", "version", "config_revision", "replica", "replicas"]
Signal = Literal[
    "error_ratio", "latency_p95", "memory_ratio", "replicas_ready_ratio", "restarts_in_window"
]

_PARAM_PATTERNS: dict[str, re.Pattern[str]] = {
    "service": re.compile(r"[a-z0-9][a-z0-9-]{0,63}"),
    "version": re.compile(r"[0-9]+\.[0-9]+\.[0-9]+(-[0-9a-z.]+)?"),
    "config_revision": re.compile(r"r[0-9]{1,4}"),
}
_INT_BOUNDS = {"replica": (1, 5), "replicas": (1, 3)}


class ParameterError(ValueError):
    pass


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class ParameterSpec(_Strict):
    type: ParamType
    required: bool = True
    description: str = ""

    def validate_value(self, name: str, value: Any) -> str | int:
        if self.type in _INT_BOUNDS:
            lo, hi = _INT_BOUNDS[self.type]
            if isinstance(value, bool) or not isinstance(value, int):
                raise ParameterError(f"{name} must be an integer")
            if not lo <= value <= hi:
                raise ParameterError(f"{name} must be within [{lo}, {hi}], got {value}")
            return value
        if not isinstance(value, str) or not _PARAM_PATTERNS[self.type].fullmatch(value):
            raise ParameterError(f"{name} is not a valid {self.type}: {str(value)[:40]!r}")
        return value


class Check(_Strict):
    signal: Signal
    op: Literal["lt", "lte", "gt", "gte", "eq"]
    value: float


class Verification(_Strict):
    settle_s: int = Field(ge=0, le=300)
    window_s: int = Field(ge=15, le=900)
    interval_s: int = Field(ge=5, le=60)
    consecutive: int = Field(ge=1, le=20)
    checks: tuple[Check, ...] = Field(min_length=1)


class Runbook(_Strict):
    id: str = Field(pattern=r"^[a-z][a-z0-9-]{2,63}$")
    version: int = Field(ge=1)
    title: str = Field(max_length=120)
    description: str = Field(max_length=1000)
    action: Literal["restart", "rollback", "scale"]
    disruptive: bool
    approval: Literal["required", "policy_auto"]
    applies_to_alerts: tuple[str, ...] = ()
    parameters: dict[str, ParameterSpec]
    verification: Verification
    sha256: str = ""

    @model_validator(mode="after")
    def _service_param(self) -> Runbook:
        spec = self.parameters.get("service")
        if spec is None or spec.type != "service" or not spec.required:
            raise ValueError("every runbook must take a required `service` parameter")
        if self.disruptive and self.approval != "required":
            raise ValueError("disruptive runbooks must require approval")
        return self

    def validate_parameters(self, params: dict[str, Any], *, service: str) -> dict[str, Any]:
        """Type/bounds-check parameters and pin them to the incident's service."""
        if not isinstance(params, dict):
            raise ParameterError("parameters must be an object")
        unknown = set(params) - set(self.parameters)
        if unknown:
            raise ParameterError(f"unknown parameter(s): {sorted(unknown)}")
        clean: dict[str, Any] = {}
        for name, spec in self.parameters.items():
            if name not in params or params[name] is None:
                if spec.required:
                    raise ParameterError(f"missing required parameter {name}")
                continue
            clean[name] = spec.validate_value(name, params[name])
        if clean["service"] != service:
            raise ParameterError(
                f"runbook may only target the incident's service {service!r}, "
                f"not {clean['service']!r}"
            )
        return clean

    def prompt_view(self) -> dict[str, Any]:
        """What the model is shown: no verification internals, just what it may propose."""
        return {
            "id": self.id,
            "title": self.title,
            "description": self.description,
            "disruptive": self.disruptive,
            "applies_to_alerts": list(self.applies_to_alerts),
            "parameters": {
                n: {"type": p.type, "required": p.required, "description": p.description}
                for n, p in self.parameters.items()
            },
        }


class RunbookCatalog:
    def __init__(self, runbooks: dict[str, Runbook]) -> None:
        self._runbooks = runbooks

    @classmethod
    def load(cls, directory: Path) -> RunbookCatalog:
        books: dict[str, Runbook] = {}
        for path in sorted(directory.glob("*.yaml")):
            raw = path.read_bytes()
            data = yaml.safe_load(raw)
            book = Runbook.model_validate({**data, "sha256": hashlib.sha256(raw).hexdigest()})
            if book.id in books:
                raise ValueError(f"duplicate runbook id {book.id!r} in {path.name}")
            if path.stem != book.id:
                raise ValueError(f"{path.name}: file name must match id {book.id!r}")
            books[book.id] = book
        if not books:
            raise ValueError(f"no runbooks found in {directory}")
        return cls(books)

    def get(self, runbook_id: str) -> Runbook | None:
        return self._runbooks.get(runbook_id)

    def all(self) -> list[Runbook]:
        return list(self._runbooks.values())

    def __contains__(self, runbook_id: object) -> bool:
        return runbook_id in self._runbooks
