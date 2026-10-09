# Sentinel — Project Status

_Resumable work log. Update at the end of every work session. Only record results backed by command output._

## Current phase
**Phase 1: Design. Complete; awaiting review before Phase 2.**

## Phase checklist
| Phase | Status | Evidence |
|---|---|---|
| 1. Architecture & plan | ✅ Done (2026-10-09) | `docs/architecture.md`, `docs/threat-model.md`, `docs/data-model.md`, `docs/api-contracts.md`, `docs/implementation-plan.md` |
| 2. Target system + monitoring stack | ⏳ Not started | |
| 3. Ingestion + incidents + persistence | ⏳ | |
| 4. Evidence gathering | ⏳ | |
| 5. AI investigation | ⏳ | |
| 6. Runbooks, approvals, execution, verification | ⏳ | |
| 7. UI, reports, postmortems | ⏳ | |
| 8. E2E, CI, hardening, docs | ⏳ | |

## Environment snapshot (2026-10-09)
- macOS arm64, 8 GB RAM, ~22 GB free disk.
- Python 3.12.15 at `/opt/homebrew/bin/python3.12` (system python is 3.9; do not use it).
- Colima (vz, 4 CPU/8 GiB) + Docker 29.6.1 + standalone `docker-compose` 5.3.1 (use `docker-compose`, not `docker compose`).
- Another project already runs `ai-platform-engineer-jenkins` and a kind cluster (`kind-ai-platform-engineer`), using ~4 GB. Do not modify them.
- Ollama 0.32.0: `/Applications/Ollama.app` (CLI `/usr/local/bin/ollama`), models in `~/.ollama/models`, `qwen2.5-coder:7b` installed. Server was not running at inspection.
- No uv/poetry/node/psql.

## Verification log
- 2026-10-09: `pip install --dry-run` of the full pinned dependency set on Python 3.12 → 94 packages resolved, no conflicts.
- 2026-10-09: Image tags confirmed on Docker Hub / GitHub releases (see `docs/architecture.md` §1).

## Open decisions
See `docs/implementation-plan.md` → "Open decisions for you".

## Next step
Start Phase 2 after the plan is approved.
