# Sentinel — Data Model (PostgreSQL 18)

All tables use `uuid` PKs (UUIDv7, so they sort by time) and `timestamptz` in UTC. JSONB columns are validated by Pydantic before write. Alembic owns all DDL.

```mermaid
erDiagram
    services ||--o{ incidents : has
    services ||--o{ deployments : has
    incidents ||--o{ alerts : groups
    incidents ||--o{ incident_events : timeline
    incidents ||--o{ evidence_items : collects
    incidents ||--o{ investigations : analysed_by
    investigations ||--o{ hypotheses : proposes
    incidents ||--o{ action_requests : remediated_by
    runbook_versions ||--o{ action_requests : instantiates
    action_requests ||--o{ approvals : authorised_by
    action_requests ||--o{ action_executions : attempts
    action_requests ||--o{ verifications : verified_by
    incidents ||--o| postmortems : documented_by
    principals ||--o{ approvals : grants
```

## Tables

| Table | Key columns | Notes |
|---|---|---|
| `services` | `id, name (unique), environment, owner, grafana_dashboard_uid` | Seeded from config |
| `alerts` | `id, fingerprint, status (firing/resolved), alertname, severity, labels jsonb, annotations jsonb, starts_at, ends_at, last_received_at, receive_count, incident_id fk, raw jsonb` | Unique `(fingerprint, starts_at)` gives dedupe; repeated notifications bump `receive_count` |
| `incidents` | `id, short_id (INC-0001), service_id, title, status, severity, opened_at, acknowledged_at, acknowledged_by, mitigated_at, resolved_at, closed_at, dedupe_key, version int` | `version` for optimistic locking. Partial unique index on `dedupe_key WHERE status NOT IN ('resolved','closed')`, so there is only one open incident per service |
| `incident_events` | `id, incident_id, at, kind, actor, summary, data jsonb, correlation_id` | Timeline for the UI and postmortem |
| `deployments` | `id, service_id, version, previous_version, config_revision, deployed_at, deployed_by, source (actuator/api/k8s), change_ref` | Change history for correlation |
| `evidence_items` | `id, incident_id, kind (metric/log/deployment/derived), source, query, range_start, range_end, summary, data jsonb, flags text[], collected_at` | **Observations.** `flags` includes `possible_prompt_injection`, `truncated` |
| `investigations` | `id, incident_id, status (pending/running/succeeded/failed), provider, model, prompt_version, input_hash, started_at, finished_at, error, report jsonb, rejected_suggestions jsonb` | Full validated report stored |
| `hypotheses` | `id, investigation_id, rank, statement, confidence numeric(3,2), cited_evidence uuid[], is_primary bool, generated bool default true` | **AI-generated** |
| `runbook_versions` | `id, runbook_id, version, content_sha256, definition jsonb, loaded_at` | Unique `(runbook_id, version)` |
| `action_requests` | `id, incident_id, runbook_version_id, action_type, parameters jsonb, params_sha256, idempotency_key unique, status, source (ai_recommendation/human/policy), requested_by, dry_run bool, created_at, expires_at` | State machine below |
| `approvals` | `id, action_request_id, principal_id, decision (approved/rejected), reason, params_sha256, runbook_sha256, decided_at` | Binds to the exact parameters and runbook content |
| `action_executions` | `id, action_request_id, attempt, started_at, finished_at, outcome, actuator_response jsonb, error` | One row per bounded retry |
| `verifications` | `id, action_request_id, criteria jsonb, samples jsonb, passed bool, started_at, finished_at` | Measured values are stored |
| `postmortems` | `id, incident_id, status (draft/final), markdown, generated_sections jsonb, authored_by, updated_at` | AI-drafted sections are flagged |
| `principals` | `id, name, role, token_sha256, active, created_at` | Bootstrap admin from secret |
| `jobs` | `id, kind, payload jsonb, status, attempts, max_attempts, run_after, locked_by, locked_at, last_error` | Queue via `SKIP LOCKED` |
| `audit_events` | `seq bigserial, id, at, actor, action, subject_type, subject_id, correlation_id, data jsonb, prev_hash, hash` | Append-only (trigger), hash chain |

## State machines

**Incident**: `open → acknowledged → investigating → remediating → verifying → resolved → closed`.
Also allowed: `any open state → resolved` (manual resolve requires a reason and is audited); `verifying → remediating` (verification failed); `resolved → open` (re-fire within the reopen window, default 10 min).

**ActionRequest**: `proposed → pending_approval → approved → executing → verifying → succeeded`.
Terminal states: `rejected`, `expired`, `failed`, `verification_failed`, `cancelled`, `superseded`. A policy auto-approve transition `proposed → approved` is recorded as `actor=policy:<rule>`.

## Roles (DB)

- `sentinel_migrator`: owns the schema (DDL), used only by `alembic upgrade`.
- `sentinel_app`: DML on all tables except `audit_events` (INSERT/SELECT only). No DDL.
