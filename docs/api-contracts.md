# Sentinel — API Contracts (v1)

Base path `/api/v1`. All JSON. Auth: `Authorization: Bearer <token>`. The UI uses a session cookie plus a CSRF header.
Every response carries `X-Correlation-ID`, which echoes the request header if valid or is generated otherwise.
Errors use RFC 9457 `application/problem+json`: `{type, title, status, detail, correlation_id}`.
FastAPI generates the OpenAPI spec at `/api/v1/openapi.json`. The contract tests in Phase 3 snapshot it.

## Health and meta (no auth)

| Method | Path | Response |
|---|---|---|
| GET | `/healthz` | `200 {"status":"ok"}`. Liveness only, no dependencies checked |
| GET | `/readyz` | `200/503 {"status":"ready"/"not_ready", "checks":{"database":{ok,latency_ms},"migrations":{ok,current,expected}}}`. As implemented, only the database and migration head gate readiness; Prometheus/Loki/LLM/runbook-catalogue reachability are not (yet) separately reported |
| GET | `/metrics` | Prometheus exposition (Sentinel self-metrics) |

## Ingestion

| Method | Path | Role | Body / Response |
|---|---|---|---|
| POST | `/webhooks/alertmanager` | webhook token | Alertmanager webhook v4 payload (≤256 KB) → `202 {"received":n,"new":k,"incidents":[{"id","short_id","created":bool}]}` |
| POST | `/deployments` | deployer token (actuator) or admin | Actuator `DeploymentEvent` shape → `201` (new) or `200` (replay). Idempotent on `(service, version, config_revision, deployed_at)` |
| GET | `/deployments?service=&since=` | viewer | `[Deployment]` |

## Incidents

| Method | Path | Role | Notes |
|---|---|---|---|
| GET | `/incidents?status=&service=&severity=&active=&limit=&cursor=` | viewer | `{items: IncidentSummary[], next_cursor}`. Newest first; `cursor` is the incident number to continue below |
| GET | `/incidents/{id}` (UUID or `INC-0001`) | viewer | `IncidentDetail` = incident + alerts + timeline + latest investigation + action requests + telemetry links (Grafana/Prometheus/Loki Explore URLs) |
| POST | `/incidents/{id}/acknowledge` | responder | `{note?}`. Idempotent |
| POST | `/incidents/{id}/resolve` | responder | `{reason}`. Manual; audited; `resolved_verified=false` |
| POST | `/incidents/{id}/close` | responder | Only from `resolved` (otherwise 409 with `current_status`) |
| POST | `/incidents/{id}/notes` | responder | `{text}` → timeline event |
| GET | `/incidents/{id}/evidence?collection=` | viewer | Latest (or given) collection: `{status: complete\|partial\|failed, trigger, window_start/end, onset, errors[], items[{ref, kind: metric\|log\|change\|derived\|gap, source, title, summary, query, flags[], data}]}`. 404 until the first collection |
| POST | `/incidents/{id}/evidence/refresh` | responder | `202 {queued, job_id, detail}`; deduplicated per incident (`queued=false` if one is pending/running); audited |

## Investigations

| Method | Path | Role | Notes |
|---|---|---|---|
| POST | `/incidents/{id}/investigations` | responder | `{provider?: "mock"\|"ollama"}` → `202 {queued, job_id, provider, detail}`. 409 if there's no evidence yet or the provider is disabled; deduplicated per incident; audited |
| GET | `/incidents/{id}/investigations` | viewer | `Investigation[]`, newest first |
| GET | `/investigations/{id}` | viewer | `{status, label, provider, model, is_mock, summary, hypotheses[{kind, statement, confidence, cited_evidence, uncited, generated: true}], recommended_actions[] (validated, with runbook version and sha256, requires_approval), rejected_actions[], dropped_citations[], next_investigative_steps, data_gaps, error}` |

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
| GET | `/runbooks` | viewer | Catalogue: id, version, sha256, typed parameters, approval, verification checks |
| GET | `/runbooks/{id}` | viewer | Full definition |
| POST | `/incidents/{ref}/actions` | responder | `{runbook_id, parameters, rationale?}` → `201 ActionRequest` (status from policy: `pending_approval` for every shipped runbook, since all require approval). `dry_run` is **not** client-settable; it is always bound from the server's `SENTINEL_EXECUTION_MODE` at proposal time. `422` if parameters fail the runbook's schema; idempotent by `(incident, runbook, parameters)` — a repeat returns the existing active request unchanged |
| GET | `/incidents/{ref}/actions` | viewer | `ActionRequest[]`, newest first |
| GET | `/actions/{id}` | viewer | `ActionRequest` + `approvals[]` + `executions[]` + `verifications[]` |
| POST | `/actions/{id}/approve` | approver | `{reason?}`. Approves by id, not by resubmitted parameters — nothing for a client to mismatch. Refused with `409` if the action already expired, is in any other non-`pending_approval` state, or the runbook's content changed since proposal (`runbook_sha256` mismatch — a stale/replayed approval) |
| POST | `/actions/{id}/reject` | approver | `{reason}` (required, min 3 chars) |
| POST | `/actions/{id}/cancel` | responder | *Not yet implemented.* The domain state machine supports `cancelled` from any pre-execution state; no route exists yet to trigger it |

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
