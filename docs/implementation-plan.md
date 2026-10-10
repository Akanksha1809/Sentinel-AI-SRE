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

## Phase 6: Runbooks, approvals, execution, verification ✅ (2026-10-09)
- Runbook YAML schema + loader + hashing; `restart-service`, `rollback-deployment`, `scale-service`. *(Built in Phase 5, since validating AI-recommended actions needed the catalogue early.)*
- Policy engine (approval rules, cooldown, rate limit), approval binding (replay-protected on `runbook_sha256`), executor (idempotency, row-level lock in place of a separate advisory lock, per-call timeout via the HTTP client, bounded internal retry), HTTP actuator client, dry-run actuator wrapper.
- Verifier with consecutive-sample criteria; a failed query or empty result counts as a fail.
- **Tests:** full state-machine coverage, policy engine (unit), actuator-client error classification (unit), verifier check evaluation (unit); 13 integration tests on real Postgres covering the full lifecycle, retries, terminal failure, verification failure + fresh re-proposal, rejection, both expiry paths, replay-protection mismatch, rate limit, idempotency, and RBAC.
- **Exit (full slice), live, real actuator, real Prometheus:** scenario B end to end in live mode — detect → evidence → mock diagnosis (auto-proposed) → approve (API, Approver role) → rollback (real actuator call) → **verified recovery (5 real Prometheus samples, incident resolved with `resolved_verified: true`)**. Full run and the two real bugs it surfaced are in `PROJECT_STATUS.md`.
- **Not built:** a `4-eyes` (two-approver) policy rule, and the optional K8s actuator + dedicated `sentinel` kind cluster (decision 3, revisited — see "Open decisions" below and PROJECT_STATUS.md).

## Phase 7: Dashboard UI, reports, postmortems ✅ (2026-10-10)
- Postmortem generator (`sentinel.reports`): pure Markdown assembly from stored facts only — timeline, evidence, investigation hypotheses (labelled `[AI, <provider>]`, never a new model call), remediation history — plus two human-authored sections (Lessons Learned, Follow-ups) that a regenerate preserves verbatim via HTML-comment section markers. `PostmortemService` (generate/edit/finalize, full audit trail) and `POST`/`GET`/`PUT /incidents/{ref}/postmortem`.
- Jinja2 server-rendered UI: incident list/detail (Observations vs. AI Hypotheses split, MOCK/model badge, telemetry deep links), action approval page (parameters plus a runbook-content check — bound `sha256` vs. the current catalogue, since a mismatch is exactly what makes `/approve` return 409), postmortem view/edit/finalize, runbooks, audit, login — all behind a session-cookie auth layer separate from the Bearer-token JSON API. Persistent DRY-RUN/LIVE banner on every page.
- **Deviation from the Phase 1 sketch, recorded here rather than silently dropped:** no htmx, and CSRF is a hidden form field, not a header. Vendoring htmx would mean pulling an unreviewed third-party JS file into the repo with no network access in this environment to fetch or verify it against the no-CDN/no-Node-toolchain constraint already in place; a CSRF *header* can only be set by client-side JavaScript, which htmx would have supplied. Rather than hand-roll an unvendored JS trust problem, the UI uses plain HTML forms, and CSRF uses the classic Synchronizer Token Pattern (a stateless HMAC over the session cookie, rendered as a hidden `csrf_token` input, checked against the form body). Net effect: the UI works with JavaScript disabled, and the CSP ships as `script-src 'none'` rather than `'self'` — stricter than planned, not weaker. See `docs/threat-model.md` T5/T14.
- **Tests:** 24 unit tests on the pure Markdown module (golden rendering + section-marker roundtrip), 12 unit tests on session/CSRF (tamper, expiry, cross-session-token rejection), 8 integration tests on the postmortem API (generate/regenerate-preserves-edits/finalize-locks/RBAC) and 21 integration tests on the web UI (login, CSRF — missing/wrong/cross-session — RBAC per page, an XSS payload in an alert summary confirmed escaped in both the list and detail pages, the full generate→edit→finalize workflow via real form posts, CSP headers present).

## Phase 8: E2E, CI, hardening, docs, demos ✅ (2026-10-10)
- `sentinel.demo` (`sentinel-demo` CLI) and `tests/e2e/`: scenario triggers + a shared polling client (`SentinelDemoClient`) drive the real Compose stack — fault injection via the actuator's demo-only endpoints (`POST /v1/deploy`, `POST /v1/faults/{service}/chaos/{mode}`), then real Alertmanager → incident → mock investigation → human approval → real actuator execution → real Prometheus-verified recovery, for all three scenarios (A: memory leak → `restart-service`; B: bad release → `rollback-deployment`; C: bad config → `rollback-deployment`), mock provider, live actuator (`SENTINEL_EXECUTION_MODE=live`), exactly as planned.
- GitHub Actions: added a `secret-scan` job (gitleaks, against a committed baseline of the 7 known test fixtures — see `.gitleaks-baseline.json`) and an `e2e` job (brings the full Compose stack up in live mode, waits for readiness, runs the e2e suite, dumps logs on failure, always tears down). ruff/mypy/bandit/pip-audit/unit/integration were already wired in Phase 2–3; now 5 jobs total.
- Hardening: every external image (Dockerfile bases, all 7 third-party images in `docker-compose.yml`) pinned `tag@sha256:digest` to the multi-arch manifest-list digest (holds on both amd64 CI and local arm64 — confirmed, not assumed, against `docker manifest inspect`). Non-root users and read-only rootfs were already in place since Phase 2; CSP was built and verified in Phase 7 (`script-src 'none'`); threat model re-checked end to end, Phase 7 and 8 verification sections added (they were missing — Phase 7 had the inline T5/T14 edits but no dated verification log entry).
- Docs: this file, `PROJECT_STATUS.md`, `README.md`, `docs/architecture.md`, `docs/threat-model.md`, `docs/troubleshooting.md` (five new entries from live e2e debugging — see below), plus two new docs: `docs/runbook-authoring.md` and `docs/demo-recording.md` (`scripts/record-demo.sh` wraps `asciinema rec` around `sentinel-demo run`).
- **Not built:** `docs/setup.md` as a separate file — README's existing Quick start section already covers it and a second copy of the same four commands had no reader it would serve that the first doesn't. A Colima/Ollama/memory-specific troubleshooting section was planned as part of Phase 8 but those entries were already added organically in Phases 5–6 (`docs/troubleshooting.md` already has "Ollama investigations are extremely slow", "Containers can't reach Ollama", "High memory use / swapping on an 8 GB Mac"); Phase 8 added five more, specific to e2e/demo scenario chaining.
- **Seven real bugs found live, all fixed** — detail and the live run log in `PROJECT_STATUS.md`:
  1. The actuator's chaos-forwarding endpoint (`_forward_chaos`) let an unhandled `httpx.TransportError` to one momentarily-unreachable replica (right after a deploy replaced it) crash the whole request instead of degrading to a per-replica error — fixed, with a new actuator test (`test_one_unreachable_replica_does_not_fail_the_whole_fan_out`).
  2. `sentinel.demo.scenarios._reset_baseline` only closed `active=True` incidents before triggering the next scenario, but `IncidentService._recently_resolved` reopens on `status == resolved` alone — a resolved-but-not-yet-closed incident from the previous run silently absorbed the next scenario's alert instead of a fresh incident appearing. Fixed to resolve+close any not-yet-`closed` incident.
  3. **`MockProvider` could recommend `rollback-deployment` for an incident no deployment caused** (a genuine investigation-correctness bug, not just a demo-chaining artifact): it checked deployment correlation before any alert-type-specific evidence, with nothing tying the winning candidate to the alert that actually fired. Caught live: a pure `ShopApiMemoryPressure` incident got a rollback recommendation because an unrelated recent deployment scored well on recency alone. Fixed by gating on the candidate runbook's own `applies_to_alerts` (already on the schema, never consulted before `src/sentinel/investigation/providers.py`'s new `_applies_to_alerts`); regression test `test_stale_unrelated_deployment_does_not_outrank_memory_pressure`.
  4. Evidence correlation's 60-minute lookback window (correct for real incidents) separately means scenario C's intrinsically weak signal (a crash-loop produces no "5xx response" metric and very few log lines before each restart — even in isolation it scored 0.435 against the 0.6 threshold) can be outscored by a louder, still-in-window signal from a recently-run scenario B *of the same alert-relevant type*, which bug 3's fix doesn't separate. Not a product bug — the window is correct for real incidents — but it meant the e2e suite had to run scenario C first to be reliable on a shared, reused stack. Documented in `docs/troubleshooting.md`; `tests/e2e/test_scenarios.py`'s module docstring explains the mechanism in full.
  5. `make help`'s own target-listing regex (`[a-zA-Z_-]+`) excluded any target with a digit — `e2e-up`/`test-e2e` silently never printed. Fixed to `[a-zA-Z0-9_-]+`.
  6. **The `e2e` CI job itself, caught only once it actually ran** (no earlier CI job ever executed `docker compose up`, only `build`): `up --build` doesn't rebuild services that reference an image by tag without their own `build:` stanza (`sentinel-api`/`sentinel-worker`/`docker-guard`), so it fell back to a doomed registry pull. Fixed by building explicitly first with the same command the `images` job already runs successfully.
  7. Also only catchable by actually running the stack on a non-Colima host: the socket proxies' hardcoded `user: 65534:991` assumed this project's own VM's `docker.sock` group. GitHub's runner's differs, so the proxies never passed their healthcheck. Fixed by parameterizing to `${DOCKER_SOCK_GID:-991}`, resolved and exported by the CI job; defaults unchanged for local Colima use.

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
3. **Kubernetes**: you chose a dedicated `sentinel` kind cluster for live K8s demos, deferred to land alongside Phase 6. Phase 6 turned out substantial on its own (policy/approvals/execution/verification, with a fully-met live exit criterion on the Docker actuator alone), so the K8s actuator + cluster remain **not built** — a stretch addition on top of 6, not folded into it. The existing `ai-platform-engineer` cluster is never touched either way.
4. **GitHub**: [local git only until Phase 8] then create a repo and push, only with your explicit approval.

## Changes during implementation
- **Phase 5 pulled the runbook YAML format and loader forward from Phase 6.** Validating model-recommended actions needs the catalogue (IDs and typed parameter schemas). Policy, approvals, execution and verification remain in Phase 6.
- **Phase 5 added focused evidence collection.** When a new kind of alert joins an incident, or an alert reopens one, evidence is anchored on that alert and the incident is re-investigated. This was found live (see PROJECT_STATUS.md).
- **Decision 2 revisited (2026-10-09):** the original 7B model took 8–10 minutes per investigation and strained the 8 GB host. Pulled `qwen2.5-coder:3b` alongside it and made it the new default; same quality on a live re-run, ~40s instead of ~9 minutes. Both models remain installed; override with `SENTINEL_OLLAMA_MODEL`. See PROJECT_STATUS.md for the comparison.
- **Phase 6: no "advisory lock" as such.** The plan named one explicitly; the action row is instead locked with `SELECT ... FOR UPDATE` for the `approved`→`executing` window, which gives the same single-writer guarantee using the idiom already established elsewhere in this codebase (`IncidentService.transition`), rather than introducing a second locking mechanism.
- **Phase 6: two real bugs surfaced only by running live**, not by the (necessarily mocked) integration suite — a `NaN`-in-JSON evidence-storage failure, and a PromQL vector-match that silently returned no data for every verification sample. Both are detailed, with fixes and regression tests, in PROJECT_STATUS.md.
