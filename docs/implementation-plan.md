# Sentinel — Phased Implementation Plan

Principle: get a **working vertical slice early** (scenario B, end to end, mock provider, dry-run) and then deepen it. Each phase ends with real tests run, failures investigated and fixed, and results recorded in `PROJECT_STATUS.md`. Nothing is marked done without command output to back it.

## Phase 1: Design ✅ (this document set)
Architecture, threat model, data flow, directory layout, API contracts, data model, dependencies, and this plan. Environment inspected and versions verified.

## Phase 2: Target system, instrumentation, and monitoring stack
- `git init`, `pyproject.toml`, lock file, Makefile, `.env.example`, `secrets/` generator script (`make secrets`).
- `services/demo-app` (shop-api): RED metrics, process metrics, JSON logs with correlation IDs, `/healthz`/`/readyz`, bounded chaos endpoints (memory, latency, cpu), build arg `RELEASE_DEFECT`, startup config validation.
- `services/actuator`: fleet model, fixed container template, release catalogue, restart/rollback/scale/deploy, `http_sd`, fleet metrics, dry-run.
- `services/loadgen`: seeded fixed-rate traffic.
- Compose: Postgres, Prometheus (rules: SLIs, burn rates, alerts), Alertmanager, Loki, Alloy, Grafana (provisioned dashboards), socket proxies, health checks, volumes, mem limits.
- **Tests:** unit tests for demo-app/actuator (bounds, allowlist, unmanaged-container refusal); `promtool check rules` + rule unit tests (`promtool test rules`, run via the prom image); `amtool check-config`; Compose policy test (no socket mounts outside proxies; limits set).
- **Exit:** `make up` brings everything up healthy. Injecting each fault manually makes the matching alert fire in Alertmanager (screenshots/commands recorded).

## Phase 3: Ingestion, incident lifecycle, persistence
- Sentinel skeleton: config, DI container, structlog JSON, correlation-ID middleware, `/healthz` `/readyz` `/metrics`, auth/RBAC, problem+json errors.
- SQLAlchemy models, Alembic migrations (incl. audit trigger and DB roles), repositories.
- Alertmanager normaliser, fingerprint dedupe, grouping into incidents, reopen window, state machine, timeline, deployments API, job queue, audit hash chain.
- **Tests:** unit (normaliser, state machine, grouping on a fake clock, hash chain); integration with testcontainers Postgres (migrations up/down, audit trigger, SKIP LOCKED queue); API tests (auth matrix, 401/413/422, idempotent replays).
- **Exit (thin slice):** scenario B fault → real alert → incident visible via the API.

## Phase 4: Evidence gathering
- Prometheus and Loki clients (timeouts, size caps, retries), query templates per alert family, label validation, log sanitiser/redactor/injection flagger, deployment lookup, change-correlation and step-change detection.
- **Tests:** respx-mocked clients, template injection tests, correlation scoring on synthetic series; integration test against the live Compose Prometheus/Loki (marked `integration`).

## Phase 5: AI investigation engine
- `InvestigationProvider` protocol, prompt builder (versioned), `MockProvider` (deterministic rules over evidence, labelled MOCK), `OllamaProvider` (`/api/chat`, JSON-schema `format`, temperature 0, seed, timeout, bounded retry), validator (citations, runbook mapping, rejected suggestions).
- Verify that containers can reach host Ollama (`host.lima.internal:11434` under Colima) without rebinding Ollama off loopback.
- **Tests:** mock provider golden tests for A/B/C, validator tests, prompt-injection tests, Ollama provider tests with recorded responses. An optional live test (`-m ollama`) runs only if Ollama is reachable, and its result is reported honestly.

## Phase 6: Runbooks, approvals, execution, verification
- Runbook YAML schema + loader + hashing; `restart-service`, `rollback-deployment`, `scale-service`.
- Policy engine (approval rules, cooldown, rate limit, 4-eyes), approval binding, executor (idempotency, advisory lock, timeout, bounded retry), HTTP actuator client, dry-run actuator, optional K8s actuator (fake-client tests only unless you approve a dedicated kind cluster).
- Verifier with K-consecutive-sample criteria; empty data counts as a fail.
- **Tests:** full state-machine coverage, parameter-bound tests, replay/expiry/mismatch approvals, verification edge cases.
- **Exit (full slice):** scenario B end to end in live mode: detect → evidence → mock diagnosis → approve → rollback → verified recovery.

## Phase 7: Dashboard UI, reports, postmortems
- Jinja2 + htmx UI: incident list/detail with the Observations vs. AI Hypotheses split, MOCK badge, telemetry deep links, approval page with param diff and DRY-RUN/LIVE banner, audit view.
- Incident summary + postmortem generator (Markdown, AI-drafted sections flagged), edit/finalise.
- **Tests:** template rendering + XSS payload tests, CSRF tests, report golden tests.

## Phase 8: E2E, CI, hardening, docs, demos
- `sentinel-demo` CLI and e2e tests for A, B, and C against the Compose stack (mock provider, live actuator).
- GitHub Actions: ruff, mypy --strict, bandit, pip-audit, secret scan, unit + integration (testcontainers), e2e job on a Compose stack (arm64-independent images).
- Hardening: image digests, non-root users, read-only rootfs, CSP review, threat-model re-check.
- Docs: README, setup, troubleshooting (Colima, Ollama, memory), runbook authoring guide, demo recording instructions (asciinema + screen capture script).

## Test layout and markers

| Marker | Needs | Runs in CI |
|---|---|---|
| (none) / `unit` | nothing | ✅ |
| `integration` | Docker (testcontainers) | ✅ |
| `api` | nothing (TestClient + Postgres container) | ✅ |
| `e2e` | full Compose stack | ✅ (separate job) |
| `ollama` | a running local Ollama | ❌ local only, opt-in |

## Open decisions for you (defaults are in brackets)

1. **Package manager**: [install `uv` via Homebrew; fast and lock-file native] or plain pip + `pip-compile`-style hashed requirements.
2. **Ollama model**: [use the installed `qwen2.5-coder:7b`] or pull a smaller or general-instruct model (a download, which needs your OK).
3. **Kubernetes**: [implement the backend with fake-client tests only] or create a dedicated `sentinel` kind cluster for live K8s demos. The existing `ai-platform-engineer` cluster will not be touched either way.
4. **GitHub**: [local git only until Phase 8] then create a repo and push, only with your explicit approval.

## Changes during implementation
- **Phase 5 pulled the runbook YAML format and loader forward from Phase 6.** Validating model-recommended actions needs the catalogue (IDs and typed parameter schemas). Policy, approvals, execution and verification remain in Phase 6.
- **Phase 5 added focused evidence collection.** When a new kind of alert joins an incident, or an alert reopens one, evidence is anchored on that alert and the incident is re-investigated. This was found live (see PROJECT_STATUS.md).
