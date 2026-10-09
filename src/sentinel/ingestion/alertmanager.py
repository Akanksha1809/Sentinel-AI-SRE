"""Alertmanager webhook (v4) parsing and normalisation.

Alert content is **untrusted input**. Label and annotation text can originate from
application metrics and templated values. Normalisation therefore:
- validates label keys against the Prometheus grammar and drops invalid ones;
- strips control characters and truncates values;
- accepts only a strictly validated `service` value for grouping, with everything
  else mapped to `unknown`.
Normalised text is still treated as data downstream: it is escaped in the UI and
delimited in LLM prompts.
"""

from __future__ import annotations

import re
import unicodedata
from datetime import UTC, datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator

from sentinel.domain.enums import AlertStatus, Severity

MAX_ALERTS = 200
MAX_LABELS = 64
MAX_LABEL_VALUE = 1024
MAX_ANNOTATION_VALUE = 4096
_LABEL_KEY = re.compile(r"^[a-zA-Z_][a-zA-Z0-9_]{0,99}$")
_SAFE_NAME = re.compile(r"^[a-zA-Z0-9_.:-]{1,64}$")
_ZERO_TIME = datetime(1, 1, 1, tzinfo=UTC)


def clean_text(value: Any, limit: int) -> str:
    """Remove control/format characters (keeping \\n and \\t) and truncate."""
    text = str(value)
    text = "".join(ch for ch in text if ch in "\n\t" or unicodedata.category(ch)[0] != "C")
    return text if len(text) <= limit else text[: limit - 1] + "…"


def clean_mapping(raw: dict[str, Any], limit: int) -> dict[str, str]:
    out: dict[str, str] = {}
    for key, value in list(raw.items())[:MAX_LABELS]:
        if isinstance(key, str) and _LABEL_KEY.fullmatch(key):
            out[key] = clean_text(value, limit)
    return out


def safe_name(value: str | None, default: str = "unknown") -> str:
    return value if value and _SAFE_NAME.fullmatch(value) else default


class AMAlert(BaseModel):
    model_config = ConfigDict(extra="ignore")

    status: AlertStatus
    labels: dict[str, Any] = Field(default_factory=dict)
    annotations: dict[str, Any] = Field(default_factory=dict)
    startsAt: datetime  # noqa: N815 (Alertmanager wire format)
    endsAt: datetime | None = None  # noqa: N815
    generatorURL: str = ""  # noqa: N815
    fingerprint: str = Field(pattern=r"^[0-9a-f]{1,32}$")


class AMWebhook(BaseModel):
    model_config = ConfigDict(extra="ignore")

    version: str
    groupKey: str = ""  # noqa: N815
    truncatedAlerts: int = 0  # noqa: N815
    status: AlertStatus
    receiver: str = ""
    externalURL: str = ""  # noqa: N815
    alerts: list[AMAlert] = Field(max_length=MAX_ALERTS)

    @field_validator("version")
    @classmethod
    def _v4(cls, v: str) -> str:
        if v != "4":
            raise ValueError(f"unsupported Alertmanager webhook version {v!r}")
        return v


class NormalizedAlert(BaseModel):
    model_config = ConfigDict(frozen=True)

    fingerprint: str
    status: AlertStatus
    alertname: str
    service: str
    environment: str
    severity: Severity
    summary: str
    labels: dict[str, str]
    annotations: dict[str, str]
    starts_at: datetime
    ends_at: datetime | None
    generator_url: str

    @property
    def dedupe_key(self) -> str:
        """Incident grouping key: one active incident per (environment, service)."""
        return f"{self.environment}/{self.service}"


def normalize(payload: AMWebhook, default_environment: str) -> list[NormalizedAlert]:
    out: list[NormalizedAlert] = []
    for alert in payload.alerts:
        labels = clean_mapping(alert.labels, MAX_LABEL_VALUE)
        annotations = clean_mapping(alert.annotations, MAX_ANNOTATION_VALUE)
        alertname = safe_name(labels.get("alertname"), "UnnamedAlert")
        ends_at = alert.endsAt if alert.endsAt and alert.endsAt > _ZERO_TIME else None
        out.append(
            NormalizedAlert(
                fingerprint=alert.fingerprint,
                status=alert.status,
                alertname=alertname,
                # Platform alerts may only carry `job`; fall back to it for grouping.
                service=safe_name(labels.get("service") or labels.get("job")),
                environment=safe_name(labels.get("environment"), default_environment),
                severity=Severity.parse(labels.get("severity")),
                summary=clean_text(annotations.get("summary") or alertname, 300),
                labels=labels,
                annotations=annotations,
                starts_at=alert.startsAt.astimezone(UTC),
                ends_at=ends_at.astimezone(UTC) if ends_at else None,
                generator_url=clean_text(alert.generatorURL, 2048),
            )
        )
    return out
