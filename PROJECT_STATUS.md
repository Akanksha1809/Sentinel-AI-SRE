# Sentinel — Project Status

_Resumable work log. Update at the end of every work session. Only record results backed by command output._

## Current phase
**Phase 5: AI investigation. Complete (2026-10-09).** Next: Phase 6 (policy, approvals, restricted execution, recovery verification; dedicated `sentinel` kind cluster).

## Phase checklist
| Phase | Status | Evidence |
|---|---|---|
| 1. Architecture & plan | ✅ 2026-10-09 | `docs/architecture.md`, `docs/threat-model.md`, `docs/data-model.md`, `docs/api-contracts.md`, `docs/implementation-plan.md` |
| 2. Target system + monitoring stack | ✅ 2026-10-09 | See "Phase 2 results" below |
| 3. Ingestion + incidents + persistence | ✅ 2026-10-09 | See "Phase 3 results" below |
| 4. Evidence gathering | ✅ 2026-10-09 | See "Phase 4 results" below |
| 5. AI investigation | ✅ 2026-10-09 | See "Phase 5 results" below |
| 6. Runbooks, approvals, execution, verification (+ dedicated `sentinel` kind cluster) | ⏳ Next (runbook catalogue already done in Phase 5) | |
| 7. UI, reports, postmortems | ⏳ | |
| 8. E2E, CI hardening, docs, demos | ⏳ (basic CI added early in Phase 2) | |

## Decisions (from the user, 2026-10-09)
1. Package manager: **uv** (installed via Homebrew, 0.12.24).
2. LLM: the installed **`qwen2.5-coder:7b`**.
3. Kubernetes: create a **separate `sentinel` kind cluster**. It is deferred to Phase 6, when the K8s backend is built, to save RAM until then. Never touch `kind-ai-platform-engineer`.
4. GitHub: private repo **Akanksha1809/Sentinel-AI-SRE**; push at the end of each phase.

## What exists (Phase 2)
- `services/demo-app` (**shop-api**): RED metrics, JSON logs with request IDs, deterministic faults. Release 1.1.0 nulls prices for products 6–10. Config `POOL_SIZE=0` fails startup. Chaos endpoints (memory, latency, cpu) are bounded, token-protected and self-expiring.
- `services/actuator`: fleet manager (deploy/rollback/restart/scale; catalogue-allowlisted, idempotent, dry-run, per-service lock), fleet metrics, Prometheus `http_sd`, deployment history, separate remediation/fault tokens.
- `actuator.guard` (**docker-guard**): Docker API admission controller in front of the socket proxy.
- `services/loadgen`: seeded fixed-rate traffic (10 rps; about 20% error exposure on release 1.1.0).
- Compose stack: Prometheus (SLI recording rules, burn-rate and saturation alerts), Alertmanager (webhook to Sentinel with a secret-file bearer token), Loki + Alloy, Grafana (generated dashboard), Postgres (ready for Phase 3), two socket proxies.
- Policy tests for Compose security invariants; promtool rule unit tests; basic GitHub Actions CI.

## What exists (Phase 5)
- `runbooks/*.yaml` + `sentinel.remediation.runbooks`: schema-validated, sha256-hashed catalogue (rollback, restart, scale) with typed, bounded parameters and named verification checks (pulled forward from Phase 6).
- `sentinel.investigation`: report schema (bounded); versioned prompt (evidence in one escaped, untrusted-data block); providers `mock` (default, labelled MOCK) and `ollama` (per-request constrained decoding); validator (citations, uncited cap, catalogue/parameter/service checks, recorded rejections, citation normalisation); service (record before call, timeout, failure recorded, never substitute mock).
- Migration 0003: `investigations`, `hypotheses` (`generated CHECK true`; insert-only).
- Auto-investigation after an incident's first evidence, a reopen, or a *new kind of alert*. **Focused evidence:** onset and correlation are anchored on the alert that triggered the collection.
- API: `GET /runbooks[/{id}]`, `POST/GET /incidents/{id}/investigations`, `GET /investigations/{id}` (label, `generated`, `is_mock`, accepted/rejected actions, dropped/normalised citations).
- Compose: `SENTINEL_INVESTIGATION_PROVIDER` (default `mock`), `SENTINEL_OLLAMA_ENABLED`/`_URL` (`host.docker.internal`)/`_MODEL`/`_TIMEOUT_S`.

## Phase 5 results (2026-10-09)
- Lint and strict mypy clean (76 files); unit + policy **290 passed**; integration + API **77 passed**; bandit clean; pip-audit clean; promtool/amtool OK.
- **Live, fully automatic (mock), scenario C:** bad config r2 (CHG-78) at 13:53:24 → INC-0006 **reopened** at 13:54:11 with evidence focused on `ShopApiDown` → evidence at 13:54:28 (onset 13:53:37; 69x `POOL_SIZE` validation failures, all r2; CHG-78 score 0.98 vs CHG-77 0.38) → MOCK investigation recommends `rollback-deployment` to config `r1` (requires approval) → incident `investigating`.
- **Live Ollama (`qwen2.5-coder:7b`, through the stack, container → `host.docker.internal` → host loopback):**
  - Run 1 (507s): identified CHG-78, but cited `ref:change.deployments` (invalid form), so its citations were dropped, it was capped at 0.3, flagged uncited, and recommended no action.
  - Fix: per-request enum-constrained decoding plus citation normalisation.
  - Run 2 (609s): **correct root cause (invalid POOL_SIZE in config r2 / CHG-78), valid citations, confidence 0.95, and recommended `rollback-deployment` to 1.0.0/r1, which passed validation.** Remaining weaknesses: an empty action rationale, and the summary echoes the incident's stale latency title.
- **Performance on this host:** an 8 GB M1 shared with Colima (8 GiB VM) and another project's containers. 7B runs at about 9 prompt / 5 generated tokens/s (normal is about 100+/15–20), so an investigation takes about 10 minutes. The memory starvation degraded the stack and Sentinel **correctly opened incidents** for it (INC-0003..0005: scrape targets down, latency). The mock stays the default; see docs/troubleshooting.md for options.
- Problems found and fixed:
  - **Single-onset flaw:** a config change made 7 minutes after an incident's first alert scored 0 because it came "after onset". Collections now focus on new kinds of alert and on reopening alerts, with regression tests.
  - Hardened during design (not a live finding): a `</evidence>` string in log text could have closed the prompt's data block, so `<` and `>` are escaped (with a test).
  - Citation-format loss in real model output (see above).
  - A fixture confidence value that I had made up during drafting was replaced with the persisted value, noted in its provenance.

## Model swap: qwen2.5-coder:7b → qwen2.5-coder:3b (2026-10-09)
Switched the default Ollama model to the smaller `qwen2.5-coder:3b` (same family, ~1.9 GB vs 4.7 GB), installed alongside the 7B (both still present on disk). Changed in `src/sentinel/config.py` (`ollama_model` default) and the Compose env defaults; `SENTINEL_OLLAMA_MODEL` still overrides either way.
- **Raw generation speed on this host** (`qwen2.5-coder:3b` vs `qwen2.5-coder:7b`): load 11.3s vs 78.7s; prompt eval 90.1 vs 9.0 tok/s; generation 40.8 vs 5.1 tok/s; fully GPU-offloaded at 2.2 GB vs 4.6 GB.
- **Live investigation, same incident shape as the Phase 5 scenario B run** (PR-150, broken 1.1.0 deploy → reopened via `ShopApiHighErrorBurnRate`, focused evidence, onset 26s after deploy, correlation score 0.98): the 3B model finished in **39.6s** (vs 507–609s for the 7B) and on the first try produced a correctly-cited root cause (confidence 0.98, citing `change.deployments` and `derived.change_correlation` in the valid, non-decorated form) and the exact right `rollback-deployment` action (`target_version: 1.0.0, target_config_revision: r1`) — no dropped/normalised citations needed, no empty-rationale or stale-title issues seen with the 7B.
- All 367 tests (290 unit/policy + 77 integration/API) re-run and pass with the new default; lint, strict mypy, bandit, pip-audit and the monitoring config checks are all clean.
- **Self-inflicted finding, not model-specific:** while the 3B investigation was running alongside the whole stack and Colima, Postgres briefly crash-restarted (WAL recovery, back up in ~20s) under host memory pressure, which triggered three transient platform incidents (`SentinelWorkerDown`-type scrape gaps). All resolved automatically without data loss; this is the same class of host-memory-starvation issue noted for the 7B, just smaller in magnitude. The mock provider has no such exposure since it needs no model in memory.
- `qwen2.5-coder:3b` is now the shipped default for the optional `ollama` provider; `mock` remains the overall default (`SENTINEL_INVESTIGATION_PROVIDER=mock`).

## What existed after Phase 4
- `sentinel.evidence`: Prometheus and Loki clients (timeouts, bounded retries for 5xx/transport only, 5 MB cap, series caps); code-owned query templates; log sanitiser (redaction + injection flagging); step-change and change-correlation analysis; collector with per-query isolation (failures become `gap` items).
- Migration 0002: `evidence_collections`, `evidence_items` (INSERT/SELECT only for the app role).
- `sentinel worker` (Compose service `sentinel-worker`): runs `evidence.collect` jobs; queued automatically (deduplicated, 10s delay) and via `POST /incidents/{id}/evidence/refresh`. Metrics on :9101; `SentinelWorkerDown` and `SentinelJobsFailing` alerts.
- `GET /incidents/{id}/evidence`: latest collection, with evidence refs that Phase 5 citations will use.

## Phase 4 results (2026-10-09)
- `make lint typecheck`: clean (mypy --strict, 46 files). Unit + policy: **233 passed**. Integration + API (Postgres 18.6): **71 passed**. bandit clean; pip-audit: no known vulnerabilities; promtool/amtool OK.
- Problems found and fixed while verifying against live data:
  - Loki `| json` filters timed out over 2h windows, so queries now select on the indexed `level` label.
  - The step magnitude was diluted by post-rollback recovery, so detection now uses data only up to 2 minutes after the first alert.
  - Noisy by-version steps: raised the minimum delta.
  - **Correlation bug:** a version with 0% of errors was treated as "unknown", which inflated a rollback's score to 0.71. Zero now counts against the change, and rollbacks are not cause candidates.
  - **Security bug:** `re.match` with `$` accepted trailing newlines in validated names; switched to `fullmatch` everywhere, with regressions added.
  - A non-deterministic "latest collection" on timestamp ties; added an ID tie-breaker.
  - An `assert` in production code replaced.
- **Exit criterion (live):** deploy 1.1.0 (PR-143) at 12:44:27 → INC-0002 opened at 12:46:00 → worker collected 15 items automatically at 12:46:17 (status complete, 0 gaps). Results: onset 12:45:12; error ratio 0.1% → 22.3%; 199 `TypeError` lines, all on 1.1.0; 100% of 5xx on 1.1.0; **top change PR-143, score 0.97**, ahead of the earlier, identical PR-142 deploy because of time decay.

## What existed after Phase 3
- `src/sentinel`: FastAPI API (`sentinel api`), config with file-based secrets, DI container, structlog JSON logs with correlation IDs, Prometheus self-metrics, RFC 9457 errors.
- Postgres schema (Alembic 0001): incidents, alerts, timeline events, deployments, principals, jobs, append-only hash-chained audit. Roles `sentinel_migrator` (DDL) and `sentinel_app` (DML only; INSERT/SELECT on audit).
- Ingestion: Alertmanager v4 webhook (bearer token, 256 KB streaming cap, untrusted-content sanitisation) → dedupe `(fingerprint, startsAt)` → grouping per `environment/service` (advisory lock) → reopen window → severity escalation. All-alerts-resolved does **not** resolve the incident.
- Lifecycle API: list (filters, cursor), detail (alerts, timeline, Grafana/Prometheus/Loki links), acknowledge (idempotent), notes, resolve (flagged unverified), close; state machine enforced (409).
- Deployments API (actuator pushes events with the deployer token; idempotent). Audit list + chain verification.
- Postgres job queue (`SKIP LOCKED`, dedupe, backoff, lease recovery) and worker loop. **No job kinds are enqueued yet**; Phase 4 adds the first handler (evidence collection) and the worker service in Compose.
- Compose: `sentinel-migrate` (one-shot; the only holder of the superuser password) and `sentinel-api` (127.0.0.1:8080). Prometheus scrapes Sentinel; `SentinelDown`/`SentinelWebhookRejections` alerts.

## Phase 3 results (2026-10-09)
- `make lint typecheck`: clean (mypy --strict, 37+ files). `make test-unit`: **175 passed**. `make test-integration` (Postgres 18.6 via testcontainers): **65 passed**. `make security`: bandit clean (all suppressions reviewed and annotated), pip-audit: no known vulnerabilities. `make check-monitoring`: OK (11 alert rules).
- Integration tests prove: app role cannot DDL/UPDATE/DELETE/TRUNCATE audit; the trigger blocks even the owner; superuser tampering is detected by chain verification; 40 concurrent audit appends form one valid chain; 8 concurrent webhook deliveries create exactly one incident; 5 workers claiming 20 jobs never overlap; optimistic-lock conflicts are detected.
- Bugs found by tests and fixed: the app role couldn't read `alembic_version` (readiness would have failed forever in production); a `# nosec` comment had been placed *inside* a migration SQL string (caught in review, before any run).
- **Exit criterion (live, real chain):** deploy 1.1.0 at 12:11:12 → actuator pushed the deployment to Sentinel (12:11:25) → `ShopApiHighErrorBurnRate` → Alertmanager webhook → **INC-0001 opened 12:12:49** (alert, timeline, telemetry links via API). Rollback at 12:13:11 → resolved notification recorded at 12:13:48 with the incident **still open** → manual resolve via API flagged `verified=false`. Audit: 5 events with actors and correlation IDs; chain verifies.

## Phase 2 results (2026-10-09)
- `make lint typecheck test-unit security`: ruff clean, mypy --strict clean (22 files), **137 tests passed**, bandit clean (6 reviewed findings annotated with reasons), pip-audit: no known vulnerabilities.
- `make check-monitoring`: promtool config/rules OK, **all rule unit tests pass**, amtool OK.
- `make up`: all 10 services healthy; Prometheus scrapes both replicas (load split 5.1/4.9 rps); Loki receives logs labelled with version/config_revision/replica (no duplication: 302/301 lines/min at 5 rps each).
- **Live fault scenarios** (timings in `docs/architecture.md` §10). Each alert fired in Alertmanager; remediation through the actuator remediation API; all alerts cleared:
  - A memory: `ShopApiMemoryPressure` +89s; restart; cleared.
  - B broken release: `ShopApiHighErrorBurnRate` +72s at 19.93% errors; rollback; cleared; repeat rollback was a no-op.
  - C crash loop: `ShopApiCrashLooping` +31s, `ShopApiDown` +36s; config rollback; cleared, 0 restarts.
- **Security probe** (threat model "Verification log"): path-only proxy admitted a privileged container create, so docker-guard was added. Re-probe: privileged/bind/exec/pull/network/volume/info/logs all blocked; stopping the unrelated Jenkins container blocked; guard bypass impossible.
- Stack memory measured at 796 MiB. Grafana was at 89% of its 256m limit, so limits were raised (Grafana 384m, Alloy 192m, guard 96m).

## Known issues / notes for next phases
- Rolling restarts cause about 0.9% connection errors (DNS round-robin, no readiness-aware LB). Phase 6 verification must start after the action completes, plus a settle delay.
- Memory chaos allocates about 1.6 MB/s under the 0.5-CPU quota, below the requested 4 MB/s. The alert still fires in about 90s.
- The Docker daemon has dead containers from another project (`docker system df` fails). This is harmless to Sentinel; left untouched.
- `starlette.testclient` emits a deprecation warning recommending `httpx2`; revisit when FastAPI updates its test client.

## How to resume
```bash
make setup      # uv sync --all-packages
make secrets    # idempotent
make images     # shop-api 1.0.0 + 1.1.0, actuator, loadgen
make up         # waits until ready (includes sentinel-migrate + sentinel-api)
make token NAME=alice ROLE=responder   # API token, printed once
make test       # unit + policy + promtool/amtool
```
Inject faults via the actuator with `secrets/fault_token` (`POST /v1/deploy`, `POST /v1/faults/shop-api/chaos/{memory|latency|cpu}`). The Phase 8 demo CLI will wrap this.

## Environment snapshot (2026-10-09)
- macOS arm64, 8 GB RAM, ~22 GB free disk. Python 3.12.15 at `/opt/homebrew/bin/python3.12` (system python is 3.9). uv 0.12.24.
- Colima (vz, 4 CPU/8 GiB) + Docker 29.6.1 + standalone `docker-compose` 5.3.1. Docker socket group in the VM is 991.
- Another project's `ai-platform-engineer-jenkins` + kind cluster (about 4 GB) run in the same VM. Do not modify them.
- Ollama 0.32.0 at `/Applications/Ollama.app` (CLI `/usr/local/bin/ollama`), `qwen2.5-coder:7b`; not running by default.
