"""Propose -> approve/reject -> execute -> verify -> resolved, on real Postgres.

Mirrors test_investigation_flow.py's pattern (real app, a Worker fed by hand-rolled
fakes for the actuator and Prometheus). `asyncio.sleep` is patched to be instant in
both the executor's retry backoff and the verifier's settle/interval waits, so real
runbook timings (settle_s/window_s/interval_s from runbooks/*.yaml) are exercised
without the test actually waiting minutes.
"""

from __future__ import annotations

import uuid
from collections.abc import AsyncIterator, Callable
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

import httpx
import pytest
from conftest import ADMIN_TOKEN, RUNBOOKS_DIR, WEBHOOK_TOKEN

from sentinel.evidence.collector import EvidenceCollector
from sentinel.evidence.model import LogLine, Point, Series
from sentinel.evidence.service import JOB_KIND as EVIDENCE_JOB
from sentinel.evidence.service import EvidenceService
from sentinel.investigation.providers import MockProvider
from sentinel.investigation.service import JOB_KIND as INVESTIGATION_JOB
from sentinel.investigation.service import InvestigationService
from sentinel.jobs.worker import Worker
from sentinel.main import bootstrap_admin, create_app
from sentinel.remediation import execution as execution_mod
from sentinel.remediation import verifier as verifier_mod
from sentinel.remediation.actuator_client import (
    ActuatorError,
    ActuatorResult,
    ActuatorUnavailableError,
)
from sentinel.remediation.execution import JOB_KIND as EXECUTE_JOB
from sentinel.remediation.execution import ExecutionService
from sentinel.remediation.policy import PolicyEngine
from sentinel.remediation.runbooks import RunbookCatalog
from sentinel.remediation.service import (
    ActionExpiredError,
    ActionLimitExceededError,
    ActionService,
    RunbookChangedError,
    idempotency_key,
)
from sentinel.remediation.verifier import JOB_KIND as VERIFY_JOB
from sentinel.remediation.verifier import VerificationService

pytestmark = pytest.mark.integration
Factory = Callable[..., dict[str, Any]]
ADMIN = {"Authorization": f"Bearer {ADMIN_TOKEN}"}
HOOK = {"Authorization": f"Bearer {WEBHOOK_TOKEN}"}


@pytest.fixture(autouse=True)
def no_real_waits(monkeypatch: pytest.MonkeyPatch) -> None:
    """Runbooks' real settle_s/window_s/interval_s (and retry backoff) would make this
    test take minutes. A fake monotonic clock that only advances when the verifier's
    own `asyncio.sleep` advances it keeps the real window/interval/consecutive *logic*
    intact (the loop still takes exactly as many ticks as it would for real) while
    every tick is instant."""
    fake_now = [0.0]

    async def instant_sleep(delay: float) -> None:
        fake_now[0] += delay

    monkeypatch.setattr(execution_mod.asyncio, "sleep", instant_sleep)
    monkeypatch.setattr(verifier_mod.asyncio, "sleep", instant_sleep)
    monkeypatch.setattr(verifier_mod.time, "monotonic", lambda: fake_now[0])


class ScenarioB:
    async def query_range(
        self, query: str, start: datetime, end: datetime, step_s: float
    ) -> list[Series]:
        if "error_ratio" in query:
            pts = tuple(
                Point(start.timestamp() + 15 * i, 0.0 if i < 118 else 0.2) for i in range(130)
            )
            return [Series({"service": "shop-api"}, pts)]
        return []

    async def query_instant(self, query: str, at: datetime) -> list[Series]:
        return [Series({"version": "1.1.0"}, (Point(at.timestamp(), 120.0),))]

    async def query_logs(
        self, query: str, start: datetime, end: datetime, limit: int
    ) -> list[LogLine]:
        line = (
            '{"msg": "unhandled error", "exception": "TypeError: unsupported operand '
            "type(s) for *: 'NoneType' and 'int'\"}"
        )
        return [LogLine(end.timestamp(), {"version": "1.1.0", "config_revision": "r1"}, line)]

    async def query_log_metrics(
        self, query: str, start: datetime, end: datetime, step_s: float
    ) -> list[Series]:
        return [
            Series({"version": "1.1.0", "config_revision": "r1"}, (Point(end.timestamp(), 50.0),))
        ]


class FakeVerifyMetrics:
    """Answers every verification query based on which signal it is, for a fixed
    healthy/unhealthy fleet state. The exact query text is Phase 6's own product
    (verifier.py); this only has to recognise it, not replicate it."""

    def __init__(self, healthy: bool) -> None:
        self.healthy = healthy
        self.queries: list[str] = []

    async def query_instant(self, query: str, at: datetime) -> list[Series]:
        self.queries.append(query)
        if "http_error_ratio" in query:
            value = 0.001 if self.healthy else 0.5
        elif "latency_p95" in query:
            value = 0.05 if self.healthy else 1.0
        elif "container_memory_ratio" in query:
            value = 0.1 if self.healthy else 0.95
        elif "replicas_running" in query:
            value = 1.0
        elif "restart_count" in query:
            value = 0.0 if self.healthy else 2.0
        else:
            raise AssertionError(f"unexpected verification query: {query}")
        return [Series({}, (Point(at.timestamp(), value),))]

    async def query_range(self, *a: object, **k: object) -> list[Series]:
        raise NotImplementedError


class FakeActuator:
    """Tracks calls; can be told to fail transiently N times, or fail terminally."""

    def __init__(self, transient_failures: int = 0, terminal: bool = False) -> None:
        self.calls: list[tuple[str, dict[str, Any]]] = []
        self._transient_remaining = transient_failures
        self._terminal = terminal

    def _maybe_fail(self, action: str, params: dict[str, Any]) -> None:
        self.calls.append((action, params))
        if self._terminal:
            raise ActuatorError("unknown target: no such service")
        if self._transient_remaining > 0:
            self._transient_remaining -= 1
            raise ActuatorUnavailableError("actuator unreachable: ConnectError")

    async def restart(
        self, service: str, replica: int | None, *, actor: str, dry_run: bool
    ) -> ActuatorResult:
        self._maybe_fail("restart", {"service": service, "replica": replica})
        return ActuatorResult("restart", service, dry_run, True, [f"restart {service}"], {})

    async def rollback(
        self,
        service: str,
        target_version: str,
        target_config_revision: str | None,
        *,
        actor: str,
        dry_run: bool,
    ) -> ActuatorResult:
        self._maybe_fail("rollback", {"service": service, "target_version": target_version})
        return ActuatorResult(
            "rollback", service, dry_run, True, [f"rollback {service} to {target_version}"], {}
        )

    async def scale(
        self, service: str, replicas: int, *, actor: str, dry_run: bool
    ) -> ActuatorResult:
        self._maybe_fail("scale", {"service": service, "replicas": replicas})
        return ActuatorResult("scale", service, dry_run, True, [f"scale {service}"], {})

    async def aclose(self) -> None:
        pass


@pytest.fixture
async def client(container: Any) -> AsyncIterator[httpx.AsyncClient]:
    await bootstrap_admin(container)
    transport = httpx.ASGITransport(app=create_app(container, run_bootstrap=False))
    async with httpx.AsyncClient(transport=transport, base_url="http://sentinel") as c:
        yield c


def worker(
    container: Any,
    *,
    actuator: FakeActuator | None = None,
    verify_metrics: FakeVerifyMetrics | None = None,
) -> Worker:
    t = ScenarioB()
    evidence = EvidenceService(
        container.sessions,
        container.clock,
        container.incidents,
        EvidenceCollector(t, t),
        container.metrics,
        jobs=container.jobs,
        auto_investigate_with="mock",
    )
    investigations = InvestigationService(
        container.sessions,
        container.clock,
        container.incidents,
        container.audit,
        container.catalog,
        {"mock": MockProvider()},
        container.metrics,
        actions=container.actions,
    )
    handlers = {EVIDENCE_JOB: evidence.handle_job, INVESTIGATION_JOB: investigations.handle_job}
    if actuator is not None:
        execution = ExecutionService(
            container.sessions,
            container.clock,
            container.incidents,
            container.audit,
            actuator,
            container.jobs,
            max_attempts=3,
            backoff_base_s=0.0,
            backoff_max_s=0.0,
        )
        handlers[EXECUTE_JOB] = execution.handle_job
    if verify_metrics is not None:
        verification = VerificationService(
            container.sessions,
            container.clock,
            container.incidents,
            container.catalog,
            container.audit,
            verify_metrics,
        )
        handlers[VERIFY_JOB] = verification.handle_job
    return Worker(container.sessions, container.jobs, handlers)


async def drain(container: Any, clock: Any, w: Worker) -> None:
    clock.advance(seconds=30)
    while await w.run_once() is not None:
        pass


async def deploy_and_alert(
    client: httpx.AsyncClient, am_alert: Factory, am_payload: Factory, container: Any
) -> None:
    deployer = {"Authorization": f"Bearer {container.settings.deployer_token.get_secret_value()}"}
    start = container.clock.now()
    await client.post(
        "/api/v1/deployments",
        headers=deployer,
        json={
            "service": "shop-api",
            "version": "1.1.0",
            "previous_version": "1.0.0",
            "config_revision": "r1",
            "previous_config_revision": "r1",
            "deployed_at": start.isoformat(),
            "deployed_by": "ci",
            "source": "deploy",
            "change_ref": "PR-142",
        },
    )
    await client.post(
        "/api/v1/webhooks/alertmanager", headers=HOOK, json=am_payload(am_alert(starts_at=start))
    )


async def propose_rollback(
    client: httpx.AsyncClient, container: Any, clock: Any, ref: str = "INC-0001"
) -> str:
    """Drive to a pending_approval rollback-deployment action via the real chain."""
    await drain(container, clock, worker(container))
    [action] = (await client.get(f"/api/v1/incidents/{ref}/actions", headers=ADMIN)).json()
    assert action["status"] == "pending_approval"
    assert action["runbook_id"] == "rollback-deployment"
    return str(action["id"])


class TestHappyPathResolvesVerified:
    async def test_approve_execute_verify_resolves_incident(
        self,
        client: httpx.AsyncClient,
        container: Any,
        clock: Any,
        am_alert: Factory,
        am_payload: Factory,
    ) -> None:
        await deploy_and_alert(client, am_alert, am_payload, container)
        action_id = await propose_rollback(client, container, clock)

        r = await client.post(
            f"/api/v1/actions/{action_id}/approve",
            headers=ADMIN,
            json={"reason": "matches the evidence"},
        )
        assert r.status_code == 200
        assert r.json()["status"] == "approved"
        assert r.json()["approvals"][0] == {
            "principal": "user:bootstrap-admin",
            "decision": "approved",
            "reason": "matches the evidence",
            "decided_at": r.json()["approvals"][0]["decided_at"],
        }

        actuator = FakeActuator()
        metrics = FakeVerifyMetrics(healthy=True)
        await drain(container, clock, worker(container, actuator=actuator, verify_metrics=metrics))

        final = (await client.get(f"/api/v1/actions/{action_id}", headers=ADMIN)).json()
        assert final["status"] == "succeeded"
        assert len(final["executions"]) == 1
        assert final["executions"][0]["outcome"] == "changed"
        assert final["verifications"][0]["passed"] is True
        assert actuator.calls == [("rollback", {"service": "shop-api", "target_version": "1.0.0"})]

        incident = (await client.get("/api/v1/incidents/INC-0001", headers=ADMIN)).json()
        assert incident["status"] == "resolved"
        assert incident["resolved_verified"] is True
        kinds = [e["kind"] for e in incident["timeline"]]
        for a, b in [
            ("action.proposed", "action.approved"),
            ("action.approved", "action.executed"),
            ("action.executed", "action.verified"),
        ]:
            assert kinds.index(a) < kinds.index(b)

    async def test_dry_run_mode_is_captured_on_the_action_row(
        self,
        client: httpx.AsyncClient,
        container: Any,
        clock: Any,
        am_alert: Factory,
        am_payload: Factory,
    ) -> None:
        assert container.settings.execution_mode == "dry_run"  # the safe default
        await deploy_and_alert(client, am_alert, am_payload, container)
        action_id = await propose_rollback(client, container, clock)
        proposed = (await client.get(f"/api/v1/actions/{action_id}", headers=ADMIN)).json()
        assert proposed["dry_run"] is True  # bound at proposal time from the global mode
        # The wrapper that actually *enforces* this on the HTTP call is covered by
        # tests/unit/test_actuator_client.py::TestDryRunWrapper.

    async def test_execution_retries_transient_failures_then_succeeds(
        self,
        client: httpx.AsyncClient,
        container: Any,
        clock: Any,
        am_alert: Factory,
        am_payload: Factory,
    ) -> None:
        await deploy_and_alert(client, am_alert, am_payload, container)
        action_id = await propose_rollback(client, container, clock)
        await client.post(f"/api/v1/actions/{action_id}/approve", headers=ADMIN, json={})

        actuator = FakeActuator(transient_failures=2)
        await drain(
            container,
            clock,
            worker(container, actuator=actuator, verify_metrics=FakeVerifyMetrics(healthy=True)),
        )
        final = (await client.get(f"/api/v1/actions/{action_id}", headers=ADMIN)).json()
        assert final["status"] == "succeeded"
        assert [e["outcome"] for e in final["executions"]] == ["error", "error", "changed"]
        assert len(actuator.calls) == 3

    async def test_terminal_actuator_error_fails_without_retry(
        self,
        client: httpx.AsyncClient,
        container: Any,
        clock: Any,
        am_alert: Factory,
        am_payload: Factory,
    ) -> None:
        await deploy_and_alert(client, am_alert, am_payload, container)
        action_id = await propose_rollback(client, container, clock)
        await client.post(f"/api/v1/actions/{action_id}/approve", headers=ADMIN, json={})

        actuator = FakeActuator(terminal=True)
        await drain(container, clock, worker(container, actuator=actuator))
        final = (await client.get(f"/api/v1/actions/{action_id}", headers=ADMIN)).json()
        assert final["status"] == "failed"
        assert len(final["executions"]) == 1  # no retry for a terminal error
        incident = (await client.get("/api/v1/incidents/INC-0001", headers=ADMIN)).json()
        assert incident["status"] == "remediating"  # never reached verifying


class TestVerificationFailure:
    async def test_failed_verification_reopens_remediation_and_allows_a_fresh_proposal(
        self,
        client: httpx.AsyncClient,
        container: Any,
        clock: Any,
        am_alert: Factory,
        am_payload: Factory,
    ) -> None:
        await deploy_and_alert(client, am_alert, am_payload, container)
        action_id = await propose_rollback(client, container, clock)
        await client.post(f"/api/v1/actions/{action_id}/approve", headers=ADMIN, json={})

        await drain(
            container,
            clock,
            worker(
                container, actuator=FakeActuator(), verify_metrics=FakeVerifyMetrics(healthy=False)
            ),
        )
        final = (await client.get(f"/api/v1/actions/{action_id}", headers=ADMIN)).json()
        assert final["status"] == "verification_failed"
        assert final["verifications"][0]["passed"] is False
        incident = (await client.get("/api/v1/incidents/INC-0001", headers=ADMIN)).json()
        assert incident["status"] == "remediating"
        assert incident["resolved_verified"] is False

        # The same runbook/parameters can be proposed again: the old request is
        # terminal, so it does not block a fresh attempt.
        async with container.sessions.begin() as session:
            row, created = await container.actions.propose(
                session,
                incident["id"],
                "rollback-deployment",
                {"service": "shop-api", "target_version": "1.0.0"},
                source="human",
                requested_by="user:test",
            )
        assert created is True
        assert str(row.id) != action_id


class TestRejection:
    async def test_reject_requires_a_reason_and_never_enqueues_execution(
        self,
        client: httpx.AsyncClient,
        container: Any,
        clock: Any,
        am_alert: Factory,
        am_payload: Factory,
    ) -> None:
        await deploy_and_alert(client, am_alert, am_payload, container)
        action_id = await propose_rollback(client, container, clock)

        bad = await client.post(f"/api/v1/actions/{action_id}/reject", headers=ADMIN, json={})
        assert bad.status_code == 422  # reason is required

        r = await client.post(
            f"/api/v1/actions/{action_id}/reject",
            headers=ADMIN,
            json={"reason": "will self-heal, not worth the disruption"},
        )
        assert r.status_code == 200
        assert r.json()["status"] == "rejected"

        async with container.sessions() as session:
            counts = await container.jobs.counts(session)
        assert counts.get("pending", 0) == 0  # no execute job was ever queued

        again = await client.post(f"/api/v1/actions/{action_id}/approve", headers=ADMIN, json={})
        assert again.status_code == 409  # rejected is terminal


async def make_incident(client: httpx.AsyncClient, am_alert: Factory, am_payload: Factory) -> str:
    """An incident with no deploy/evidence: enough for policy/approval tests that
    never need to execute anything."""
    r = await client.post(
        "/api/v1/webhooks/alertmanager", headers=HOOK, json=am_payload(am_alert())
    )
    assert r.status_code == 202
    [iid] = r.json()["incidents"]
    return str(iid["id"])


class TestExpiry:
    async def test_approving_past_expiry_fails_and_marks_the_row_expired(
        self,
        client: httpx.AsyncClient,
        container: Any,
        am_alert: Factory,
        am_payload: Factory,
    ) -> None:
        from sentinel.domain.enums import ActionStatus as S

        iid = uuid.UUID(await make_incident(client, am_alert, am_payload))
        expired_actions = ActionService(
            container.clock,
            container.audit,
            container.incidents,
            container.catalog,
            container.jobs,
            PolicyEngine(),
            expiry=timedelta(seconds=-1),
        )
        async with container.sessions.begin() as session:
            row, created = await expired_actions.propose(
                session,
                iid,
                "restart-service",
                {"service": "shop-api"},
                source="human",
                requested_by="user:test",
            )
        assert created is True
        assert row.status == S.PENDING_APPROVAL.value

        async with container.sessions.begin() as session:
            with pytest.raises(ActionExpiredError):
                await container.actions.approve(session, row.id, "user:test", None)
        async with container.sessions() as session:
            refreshed = await container.actions.get(session, row.id)
        assert refreshed.status == "expired"

        # Once expired, it is a terminal state: rejecting it now is a plain invalid
        # transition, not a fresh "expired" discovery.
        from sentinel.domain.actions import InvalidActionTransitionError

        async with container.sessions.begin() as session:
            with pytest.raises(InvalidActionTransitionError):
                await container.actions.reject(session, row.id, "user:test", "too late")

    async def test_periodic_sweep_expires_without_anyone_deciding(
        self,
        client: httpx.AsyncClient,
        container: Any,
        am_alert: Factory,
        am_payload: Factory,
    ) -> None:
        iid = uuid.UUID(await make_incident(client, am_alert, am_payload))
        expired_actions = ActionService(
            container.clock,
            container.audit,
            container.incidents,
            container.catalog,
            container.jobs,
            PolicyEngine(),
            expiry=timedelta(seconds=-1),
        )
        async with container.sessions.begin() as session:
            await expired_actions.propose(
                session,
                iid,
                "restart-service",
                {"service": "shop-api"},
                source="human",
                requested_by="user:test",
            )
        async with container.sessions.begin() as session:
            swept = await container.actions.expire_stale(session)
        assert swept == 1
        incident = (await client.get("/api/v1/incidents/INC-0001", headers=ADMIN)).json()
        assert incident["timeline"][-1]["kind"] == "action.expired"


class TestRunbookChangedReplayProtection:
    async def test_approval_refused_if_the_runbook_changed_since_proposal(
        self,
        client: httpx.AsyncClient,
        container: Any,
        am_alert: Factory,
        am_payload: Factory,
        tmp_path: Path,
    ) -> None:
        iid = uuid.UUID(await make_incident(client, am_alert, am_payload))
        async with container.sessions.begin() as session:
            row, _ = await container.actions.propose(
                session,
                iid,
                "restart-service",
                {"service": "shop-api"},
                source="human",
                requested_by="user:test",
            )

        # A modified copy of the catalogue (content differs -> different sha256), as
        # if the runbook file had been edited after this action was proposed.
        for path in RUNBOOKS_DIR.glob("*.yaml"):
            text = path.read_text()
            if path.stem == "restart-service":
                text = text.replace("version: 1", "version: 2", 1)
            (tmp_path / path.name).write_text(text)
        drifted_catalog = RunbookCatalog.load(tmp_path)
        drifted_actions = ActionService(
            container.clock,
            container.audit,
            container.incidents,
            drifted_catalog,
            container.jobs,
            PolicyEngine(),
        )

        async with container.sessions.begin() as session:
            with pytest.raises(RunbookChangedError):
                await drifted_actions.approve(session, row.id, "user:test", None)
        async with container.sessions() as session:
            refreshed = await container.actions.get(session, row.id)
        assert refreshed.status == "pending_approval"  # untouched by the refused approval


class TestRateLimit:
    async def test_proposals_beyond_the_limit_are_refused(
        self,
        client: httpx.AsyncClient,
        container: Any,
        am_alert: Factory,
        am_payload: Factory,
    ) -> None:
        iid = uuid.UUID(await make_incident(client, am_alert, am_payload))
        limited = ActionService(
            container.clock,
            container.audit,
            container.incidents,
            container.catalog,
            container.jobs,
            PolicyEngine(max_per_incident=2),
        )
        async with container.sessions.begin() as session:
            for version in ("1.0.1", "1.0.2"):
                _, created = await limited.propose(
                    session,
                    iid,
                    "rollback-deployment",
                    {"service": "shop-api", "target_version": version},
                    source="human",
                    requested_by="user:test",
                )
                assert created is True
        async with container.sessions.begin() as session:
            with pytest.raises(ActionLimitExceededError):
                await limited.propose(
                    session,
                    iid,
                    "rollback-deployment",
                    {"service": "shop-api", "target_version": "1.0.3"},
                    source="human",
                    requested_by="user:test",
                )


class TestIdempotentPropose:
    async def test_identical_proposal_returns_the_same_row(
        self,
        client: httpx.AsyncClient,
        container: Any,
        am_alert: Factory,
        am_payload: Factory,
    ) -> None:
        iid = uuid.UUID(await make_incident(client, am_alert, am_payload))
        params = {"service": "shop-api"}
        async with container.sessions.begin() as session:
            first, created1 = await container.actions.propose(
                session, iid, "restart-service", params, source="human", requested_by="user:a"
            )
        async with container.sessions.begin() as session:
            second, created2 = await container.actions.propose(
                session, iid, "restart-service", params, source="human", requested_by="user:b"
            )
        assert created1 is True
        assert created2 is False
        assert first.id == second.id
        assert idempotency_key(iid, "restart-service", params) == first.idempotency_key


class TestRBAC:
    async def test_viewer_cannot_propose_or_decide(
        self,
        client: httpx.AsyncClient,
        container: Any,
        clock: Any,
        am_alert: Factory,
        am_payload: Factory,
    ) -> None:
        from sentinel.domain.enums import Role
        from sentinel.security import generate_token, upsert_principal

        token = generate_token()
        async with container.sessions.begin() as session:
            await upsert_principal(session, container.clock, "viewer-1", Role.VIEWER, token)
        viewer = {"Authorization": f"Bearer {token}"}

        await deploy_and_alert(client, am_alert, am_payload, container)
        action_id = await propose_rollback(client, container, clock)

        assert (
            await client.post(
                "/api/v1/incidents/INC-0001/actions",
                headers=viewer,
                json={"runbook_id": "restart-service", "parameters": {"service": "shop-api"}},
            )
        ).status_code == 403
        assert (
            await client.post(f"/api/v1/actions/{action_id}/approve", headers=viewer, json={})
        ).status_code == 403
        assert (
            await client.get(f"/api/v1/actions/{action_id}", headers=viewer)
        ).status_code == 200  # viewers can still read

    async def test_responder_can_propose_but_not_approve(
        self,
        client: httpx.AsyncClient,
        container: Any,
        clock: Any,
        am_alert: Factory,
        am_payload: Factory,
    ) -> None:
        from sentinel.domain.enums import Role
        from sentinel.security import generate_token, upsert_principal

        token = generate_token()
        async with container.sessions.begin() as session:
            await upsert_principal(session, container.clock, "responder-1", Role.RESPONDER, token)
        responder = {"Authorization": f"Bearer {token}"}

        await deploy_and_alert(client, am_alert, am_payload, container)
        r = await client.post(
            "/api/v1/incidents/INC-0001/actions",
            headers=responder,
            json={"runbook_id": "restart-service", "parameters": {"service": "shop-api"}},
        )
        assert r.status_code == 201
        action_id = r.json()["id"]
        assert (
            await client.post(f"/api/v1/actions/{action_id}/approve", headers=responder, json={})
        ).status_code == 403
