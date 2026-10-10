# Sentinel — API Contracts (v1)

Base path `/api/v1`. All JSON. Auth: `Authorization: Bearer <token>`. The UI (Phase 7, below) uses a session cookie plus a CSRF token in a hidden form field — not a header, since the UI has no client-side JavaScript to set one.
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

As implemented, there is no separate `/summary` endpoint — the postmortem's generated
`summary` section (part of the one Markdown document below) already covers that, and a
second endpoint returning the same facts in a different shape had no consumer.

| Method | Path | Role | Notes |
|---|---|---|---|
| POST | `/incidents/{ref}/postmortem` | responder | `201 Postmortem`. Generates (or regenerates) the draft from the timeline + evidence + investigation hypotheses + action history — never a new AI call, only already-stored facts. A regenerate rebuilds the generated sections (`summary`, `impact`, `timeline`, `root_cause`, `evidence`, `remediation`) and preserves the two human-authored ones (`lessons_learned`, `follow_ups`) verbatim. `409` if already finalized |
| GET | `/incidents/{ref}/postmortem` | viewer | `Postmortem`. `404` until the first `POST` |
| PUT | `/incidents/{ref}/postmortem` | responder | `{markdown, finalize?: bool}` → replaces the whole document (not a per-section diff). `finalize: true` locks it — audited, irreversible, further `POST`/`PUT` then `409`. (Deviation from the Phase 1 sketch's `{status: "final"}` body shape; `finalize` reads more clearly as a one-way action than a settable field) |
| GET | `/audit?subject_id=&since=` | approver | `AuditEvent[]` |
| GET | `/audit/verify` | admin | `{ok, checked, first_bad_seq?}` |

`Postmortem`: `{id, incident_id, status: "draft"\|"final", markdown, generated_sections: string[], authored_by, created_at, updated_at, finalized_at, finalized_by}`.

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

## Web UI routes (server-rendered, Phase 7)

Separate auth from the JSON API above: a signed, stateless, HttpOnly `sentinel_session`
cookie (`POST /login` with an existing API token exchanges it for one — there is no
separate password system) rather than a Bearer token. Every mutating route also requires
a hidden `csrf_token` form field (Synchronizer Token Pattern — an HMAC over the session
cookie itself, not stored server-side). See `docs/threat-model.md` T5/T14 for why this
ended up as plain forms with no client-side JavaScript at all, rather than the originally
sketched htmx: `script-src 'none'` in the CSP, stricter than planned, not weaker.

| Method | Path | Role | Notes |
|---|---|---|---|
| GET/POST | `/login` | — | Token → session cookie. `next` carries where to return to (validated to same-origin only) |
| POST | `/logout` | any session | Clears the cookie |
| GET | `/` | viewer | Incident list |
| GET | `/incidents/{ref}` | viewer | Detail: telemetry links, Observations (evidence) vs. AI Hypotheses (MOCK/model badge) split, remediation actions, timeline, plus acknowledge/resolve/evidence-refresh/investigation-request forms for responders |
| POST | `/incidents/{ref}/acknowledge`, `/resolve`, `/notes`, `/evidence/refresh`, `/investigations` | responder | Same effect as the matching JSON endpoint, via a form |
| GET | `/actions/{id}` | viewer | Parameters, rationale, cited evidence, and a runbook-content check (the action's bound `sha256` vs. the catalogue's current one for that runbook id — a mismatch is exactly what makes approval fail with 409, shown before the approver clicks anything); approve/reject forms for approvers |
| POST | `/actions/{id}/approve`, `/reject` | approver | |
| GET | `/incidents/{ref}/postmortem` | viewer | View; generate/edit/finalize forms for responders (locked, read-only once final) |
| POST | `/incidents/{ref}/postmortem/generate`, `/edit`, `/finalize` | responder | |
| GET | `/runbooks` | viewer | Catalogue |
| GET | `/audit` | approver | Audit log |

Every page carries a persistent DRY-RUN/LIVE banner reflecting `SENTINEL_EXECUTION_MODE`.
