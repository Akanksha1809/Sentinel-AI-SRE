# Sentinel — API Contracts (v1)

Base path `/api/v1`. All JSON. Auth: `Authorization: Bearer <token>`. The UI uses a session cookie plus a CSRF header.
Every response carries `X-Correlation-ID`, which echoes the request header if valid or is generated otherwise.
Errors use RFC 9457 `application/problem+json`: `{type, title, status, detail, correlation_id}`.
FastAPI generates the OpenAPI spec at `/api/v1/openapi.json`. The contract tests in Phase 3 snapshot it.

## Health and meta (no auth)

| Method | Path | Response |
|---|---|---|
| GET | `/healthz` | `200 {"status":"ok"}`. Liveness only, no dependencies checked |
| GET | `/readyz` | `200/503 {"status":"ready"/"degraded", "checks":{"database":{ok,latency_ms},"migrations":{ok,head},"runbooks":{ok,count}}}`. Prometheus, Loki, and LLM are reported but **non-blocking** |
| GET | `/metrics` | Prometheus exposition (Sentinel self-metrics) |

## Ingestion

| Method | Path | Role | Body / Response |
|---|---|---|---|
| POST | `/webhooks/alertmanager` | webhook token | Alertmanager webhook v4 payload (≤256 KB) → `202 {"received":n,"new":k,"incidents":[{"id","short_id","created":bool}]}` |
| POST | `/deployments` | `deployer` token (actuator) or admin | `{service, version, previous_version?, config_revision?, deployed_at, deployed_by, change_ref?}` → `201 Deployment`. Idempotent on `(service, version, deployed_at)` |
| GET | `/deployments?service=&since=` | viewer | `[Deployment]` |

## Incidents

| Method | Path | Role | Notes |
|---|---|---|---|
| GET | `/incidents?status=&service=&severity=&limit=&cursor=` | viewer | Paginated `IncidentSummary[]` |
| GET | `/incidents/{id}` | viewer | `IncidentDetail` = incident + alerts + timeline + latest investigation + action requests + telemetry links (Grafana/Prometheus/Loki Explore URLs) |
| POST | `/incidents/{id}/acknowledge` | responder | `{note?}`. Idempotent |
| POST | `/incidents/{id}/resolve` | responder | `{reason}`. Manual; audited; flagged "resolved without verification" |
| POST | `/incidents/{id}/notes` | responder | `{text}` → timeline event |
| GET | `/incidents/{id}/evidence` | viewer | `EvidenceItem[]` (observations + derived) |
| POST | `/incidents/{id}/evidence/refresh` | responder | Enqueues collection → `202 {job_id}` |

## Investigations

| Method | Path | Role | Notes |
|---|---|---|---|
| POST | `/incidents/{id}/investigations` | responder | `{provider?: "mock"\|"ollama"}` → `202 {investigation_id}` |
| GET | `/investigations/{id}` | viewer | `Investigation` |

`InvestigationReport` (the schema the LLM must satisfy; it is also passed to Ollama `format`):

```json
{
  "summary": "string ≤ 600",
  "suspected_root_cause": {"statement": "string", "confidence": 0.0, "cited_evidence": ["ev_…"]},
  "alternative_hypotheses": [{"statement": "string", "confidence": 0.0, "cited_evidence": ["ev_…"], "why_less_likely": "string"}],
  "recommended_actions": [{"runbook_id": "rollback-deployment", "parameters": {"target_version": "1.0.0"}, "rationale": "string", "cited_evidence": ["ev_…"]}],
  "next_investigative_steps": ["string"],
  "data_gaps": ["string"]
}
```

Server-side additions, which the model cannot set: `provider`, `model`, `generated=true`, `is_mock`, `validation: {dropped_citations, rejected_actions}`.

## Remediation

| Method | Path | Role | Notes |
|---|---|---|---|
| GET | `/runbooks` | viewer | Catalogue with id, version, sha256, parameter JSON schema, approval policy |
| GET | `/runbooks/{id}` | viewer | Full definition |
| POST | `/incidents/{id}/actions` | responder | `{runbook_id, parameters, dry_run?}` → `201 ActionRequest` (status from the policy). `422` if parameters fail the schema |
| GET | `/actions/{id}` | viewer | `ActionRequest` + approvals + executions + verifications |
| POST | `/actions/{id}/approve` | approver | `{reason, params_sha256}`. Must match the current params hash, otherwise `409` |
| POST | `/actions/{id}/reject` | approver | `{reason}` |
| POST | `/actions/{id}/cancel` | responder | Only before `executing` |

## Reports and audit

| Method | Path | Role | Notes |
|---|---|---|---|
| GET | `/incidents/{id}/summary` | viewer | Markdown/JSON incident summary |
| POST | `/incidents/{id}/postmortem` | responder | Generate a draft from the timeline + evidence + investigation + actions |
| GET/PUT | `/incidents/{id}/postmortem` | viewer / responder | Read/edit Markdown. `PUT` with `status=final` is audited |
| GET | `/audit?subject_id=&since=` | approver | `AuditEvent[]` |
| GET | `/audit/verify` | admin | `{ok, checked, first_bad_seq?}` |

## Actuator API (internal, called by the Sentinel worker only)

Auth: a bearer token separate from the Sentinel tokens. Every mutating call needs an `Idempotency-Key`.

| Method | Path | Body | Notes |
|---|---|---|---|
| GET | `/v1/fleet` | — | services, replicas, versions, config revisions, restart counts |
| GET | `/v1/releases/{service}` | — | allowlisted versions/config revisions |
| POST | `/v1/actions/restart` | `{service, replica?: "all"\|int, dry_run}` | rolling restart |
| POST | `/v1/actions/rollback` | `{service, target_version, target_config_revision?, dry_run}` | target must be in the catalogue; no-op if already at target (idempotent) |
| POST | `/v1/actions/scale` | `{service, replicas: 1..3, dry_run}` | no-op if already at count |
| POST | `/v1/deploy` | `{service, version, config_revision}` | **demo/fault injection only**, separate token |
| GET | `/v1/sd/targets` | — | Prometheus `http_sd_configs` format |
| GET | `/metrics`, `/healthz`, `/readyz` | — | fleet metrics |

## Web UI routes (server-rendered)

`/` incidents list · `/incidents/{id}` detail (Observations | AI Hypotheses (badge: MOCK / model name) | Actions | Timeline | Telemetry links) · `/actions/{id}` approval page · `/incidents/{id}/postmortem` · `/runbooks` · `/audit` · `/login`.
