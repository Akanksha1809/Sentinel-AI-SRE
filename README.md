# Sentinel: AI SRE & Incident Response Platform

Sentinel detects production-like incidents and correlates metrics and logs with recent changes. It investigates likely root causes with an LLM that is grounded in evidence and has **no tools**, proposes remediation only from an allowlisted runbook catalogue, executes approved actions through a least-privilege actuator, and verifies recovery against measured health signals.

> **Status: Phase 1 (design) complete. No runnable code yet.** See [PROJECT_STATUS.md](PROJECT_STATUS.md).

## Design documents
- [Architecture](docs/architecture.md): environment findings, components, data flow, decisions, directory layout, resource budget
- [Threat model](docs/threat-model.md)
- [Data model](docs/data-model.md)
- [API contracts](docs/api-contracts.md)
- [Implementation plan](docs/implementation-plan.md)
