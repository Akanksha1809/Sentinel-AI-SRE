# Sentinel: AI SRE & Incident Response Platform

Sentinel detects production-like incidents and correlates metrics and logs with recent changes. It investigates likely root causes with an LLM that is grounded in evidence and has **no tools**, proposes remediation only from an allowlisted runbook catalogue, executes approved actions through a least-privilege actuator, and verifies recovery against measured health signals.

> **Status: Phase 2 of 8 complete.** The instrumented target system, monitoring stack and guarded actuator are running and verified. Sentinel's own incident engine starts in Phase 3. See [PROJECT_STATUS.md](PROJECT_STATUS.md).

## What runs today
| Component | Role |
|---|---|
| **shop-api** | Demo checkout service with deterministic faults: memory pressure, a broken release (1.1.0), a crash-looping config (r2) |
| **actuator** | The only component that can change workloads. Catalogue-allowlisted deploy/rollback/restart/scale; idempotent; dry-run |
| **docker-guard** | Docker API admission controller: blocks privileged/mounted/escalated containers and changes to anything Sentinel doesn't manage |
| **Prometheus / Alertmanager** | SLIs, SLO burn-rate alerts, saturation and crash-loop alerts |
| **Loki / Alloy / Grafana** | Centralised logs (labelled by version and config revision) and a provisioned service dashboard |

## Quick start (macOS/Linux, Docker + uv)
```bash
make setup && make secrets && make images && make up
```
Then open Grafana at http://127.0.0.1:3000 (user `admin`; password in `secrets/grafana_admin_password`), Prometheus at http://127.0.0.1:9090, or Alertmanager at http://127.0.0.1:9093. All ports bind to localhost only.

```bash
make test    # unit + policy tests, promtool rule tests, amtool
make check   # lint, mypy --strict, tests, bandit, pip-audit
make down    # stop (make clean also deletes volumes)
```

## Design documents
- [Architecture](docs/architecture.md): components, data flow, decisions, measured scenario timings
- [Threat model](docs/threat-model.md): including the live Docker boundary probe
- [Data model](docs/data-model.md) and [API contracts](docs/api-contracts.md)
- [Implementation plan](docs/implementation-plan.md)
- [Troubleshooting](docs/troubleshooting.md)
