# Sentinel — Project Status

_Resumable work log. Update at the end of every work session. Only record results backed by command output._

## Current phase
**Phase 3: Ingestion, incident lifecycle, persistence. Complete (2026-10-09).** Next: Phase 4 (evidence gathering from Prometheus, Loki and deployment history).

## Phase checklist
| Phase | Status | Evidence |
|---|---|---|
| 1. Architecture & plan | ✅ 2026-10-09 | `docs/architecture.md`, `docs/threat-model.md`, `docs/data-model.md`, `docs/api-contracts.md`, `docs/implementation-plan.md` |
| 2. Target system + monitoring stack | ✅ 2026-10-09 | See "Phase 2 results" below |
| 3. Ingestion + incidents + persistence | ✅ 2026-10-09 | See "Phase 3 results" below |
| 4. Evidence gathering | ⏳ Next | |
| 5. AI investigation | ⏳ | |
| 6. Runbooks, approvals, execution, verification (+ dedicated `sentinel` kind cluster) | ⏳ | |
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

## What exists (Phase 3)
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
