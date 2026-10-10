# Authoring a runbook

Runbooks are version-controlled YAML files in `runbooks/*.yaml` — not database rows.
`RunbookCatalog.load()` parses every file at startup, validates it against the schema
below (`sentinel.remediation.runbooks`), and computes a SHA-256 hash of the raw file
bytes. That hash is recorded on every `ActionRequest` proposed from the runbook and
re-checked at approval time: if you edit a runbook's YAML after a proposal exists but
before it's approved, the approval is refused (`RunbookChangedError`, 409) rather than
silently approving content the proposer never saw. This is deliberate replay
protection, not a bug — if you hit it while testing, re-propose the action.

## Schema

```yaml
id: restart-service              # ^[a-z][a-z0-9-]{2,63}$, must match the filename's stem
version: 1                       # integer >= 1; bump when you change the runbook's behavior
title: Rolling restart of a service   # <= 120 chars
description: >-                  # <= 1000 chars; shown to the AI investigator and in the UI
  What this does and when to prefer it over alternatives.
action: restart                  # restart | rollback | scale — see "Actions" below
disruptive: true                 # see "disruptive and approval" below
approval: required               # required | policy_auto
applies_to_alerts:                # informational only (not enforced); the mock investigator
  - ShopApiMemoryPressure         # and the UI use it to explain why a runbook was suggested
  - ShopApiHighCPU
parameters:                      # see "Parameters" below
  service:
    type: service
    description: Service to restart (must be the incident's service).
  replica:
    type: replica
    required: false
    description: Restart only this replica number; omit for a rolling restart of all.
verification:                    # see "Verification" below
  settle_s: 20
  window_s: 60
  interval_s: 15
  consecutive: 3
  checks:
    - { signal: memory_ratio, op: lt, value: 0.5 }
    - { signal: error_ratio, op: lt, value: 0.01 }
    - { signal: replicas_ready_ratio, op: gte, value: 1.0 }
```

## Actions

`action` selects which actuator endpoint `ExecutionService` calls
(`src/sentinel/remediation/execution.py`), and therefore which parameters are
required:

| `action` | Actuator call | Required parameters | Optional parameters |
|---|---|---|---|
| `restart` | `POST /v1/actions/restart` | `service` | `replica` (restart one replica instead of a rolling restart of all) |
| `rollback` | `POST /v1/actions/rollback` | `service`, `target_version` | `target_config_revision` (defaults to the current revision if omitted) |
| `scale` | `POST /v1/actions/scale` | `service`, `replicas` | — |

Every runbook **must** declare a required `service` parameter — `Runbook._service_param`
rejects the file at load time otherwise. It must also be typed `type: service` (not
`version`/`config_revision`/etc.) and `required: true` (the default).

## Parameters

Each entry in `parameters` is a name → `{type, required, description}`. `type`
determines both the validation pattern and how `RunbookCatalog`/the UI render it:

| `type` | Validates against | Example |
|---|---|---|
| `service` | `^[a-z0-9][a-z0-9-]{0,63}$` | `shop-api` |
| `version` | `^[0-9]+\.[0-9]+\.[0-9]+(-[0-9a-z.]+)?$` | `1.0.0` |
| `config_revision` | `^r[0-9]{1,4}$` | `r1` |
| `replica` | integer, `1..5` | `2` |
| `replicas` | integer, `1..3` | `2` |

`required` defaults to `true`. A proposed action's parameters are re-validated against
this spec at propose time (`Runbook.validate_parameters`) — unknown parameter names are
rejected outright, and whatever `service` value is supplied must equal the incident's
own service (a runbook can never target a different service than the one that's
actually broken, regardless of who or what proposed it — human, AI, or policy).
Bounds here are the *only* bounds; nothing upstream (the AI investigator, the API) is
trusted to have already checked them.

## `disruptive` and `approval`

- `approval: required` — every shipped runbook today. A human with the `approver` role
  must sign off (`POST /actions/{id}/approve`) before the actuator is ever called.
- `approval: policy_auto` — the `PolicyEngine` may self-approve, gated by a cooldown
  (falls back to requiring approval if the same runbook ran recently on this service)
  and an incident-wide rate limit (`action_max_per_incident`, default 20). **A
  `disruptive: true` runbook cannot use `policy_auto`** — `Runbook._service_param`
  rejects that combination at load time. No shipped runbook uses `policy_auto` yet;
  `scale-service` (non-disruptive, `disruptive: false`) is the natural first candidate
  if you want to add one.

`disruptive` itself isn't otherwise enforced by code today — it's there for the human
(and the AI investigator's prompt) to weigh, and as the gate on `policy_auto` above.

## Verification

After execution, `VerificationService` waits `settle_s` (lets the change take effect —
a rolling restart or container replace isn't instantaneous), then samples every
`interval_s` for up to `window_s`, requiring `consecutive` samples *in a row* where
every check in `checks` passes. A check that can't be measured (empty or erroring
Prometheus query) counts as a **failed** sample, never a pass — recovery is never
reported on the absence of evidence (see `docs/threat-model.md` T11). If `window_s`
runs out without `consecutive` passing samples, the action transitions to
`verification_failed` — a terminal state with **no** automatic retry; a fresh proposal
(same idempotency rule: `sha256(incident|runbook|params)`) is required to try again.

Bounds: `settle_s` 0–300, `window_s` 15–900, `interval_s` 5–60, `consecutive` 1–20, at
least one check.

Each check is `{signal, op, value}`. `op` is one of `lt`, `lte`, `gt`, `gte`, `eq`.
`signal` must be one of the five code-owned signals in
`sentinel.remediation.verifier` — there is no way to supply an arbitrary PromQL
query from a runbook file (by design: see threat model T7, query injection):

| `signal` | Measures |
|---|---|
| `error_ratio` | `service:http_error_ratio:rate30s` for the service |
| `latency_p95` | `service:http_latency_p95:rate1m` for the service |
| `memory_ratio` | `service:container_memory_ratio:max` for the service |
| `replicas_ready_ratio` | running replicas ÷ desired replicas |
| `restarts_in_window` | container restarts in the recent window |

If you need to verify something not on this list, add a new signal to
`sentinel.remediation.verifier` first (with its own PromQL and a unit test —
`tests/unit/test_verifier.py` — covering both the happy path and a missing-data
case), then reference it from a runbook. Do not be tempted to add a free-form
`query:` field to the schema; that reopens exactly the injection surface the fixed
signal list closes.

## Adding a new runbook: checklist

1. Pick an `id` (lowercase, hyphenated) and name the file `runbooks/<id>.yaml` to
   match.
2. Write the schema above. Start from the closest existing runbook
   (`runbooks/restart-service.yaml`, `rollback-deployment.yaml`, or
   `scale-service.yaml`) rather than from scratch.
3. If the action needs a new actuator capability, that's a larger change — the
   actuator's own allowlist (`deploy/actuator/releases.yaml`, the `Runbook.action`
   literal, and `ExecutionService._call`'s dispatch) all need to agree; don't add a
   runbook whose `action` the actuator can't actually perform.
4. Run `uv run pytest tests/unit/test_investigation.py -k TestRunbookCatalog` (and add
   a case there — `test_valid_parameters_pass` and `test_unsafe_runbooks_rejected` are
   the ones to extend) to confirm the file parses and validates. This suite loads the
   real `runbooks/` directory (`RUNBOOKS` in that file), so a new runbook is covered
   by `test_repo_catalog_loads_with_hashes` automatically just by existing.
5. If you want the AI investigator to be able to recommend it, no prompt change is
   needed — `RunbookCatalog.all()` is passed to every investigation automatically;
   the model (or `MockProvider`'s rules) can propose any `id` in the catalogue.
   `MockProvider` itself is rule-based and won't propose a new runbook unless you
   also teach it the matching heuristic in `sentinel.investigation.providers` — it's
   fine to leave a new runbook reachable only via human/manual proposal
   (`POST /incidents/{ref}/actions`) and the real `ollama` provider.
6. Verify live: propose it against a real incident, approve it, and confirm
   `action.executed` and `action.verified`/`action.verification_failed` land exactly
   where you expect in the timeline and audit log.
