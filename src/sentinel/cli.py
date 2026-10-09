"""`sentinel` command line.

sentinel api                      run the HTTP API
sentinel db init                  create DB roles (as superuser) and migrate (as migrator)
sentinel token create NAME ROLE   create an API principal; prints the token once
"""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import os
import sys

from sqlalchemy import create_engine
from sqlalchemy.engine import URL


def _cmd_api(_: argparse.Namespace) -> int:
    import uvicorn

    from sentinel.config import load_settings
    from sentinel.container import Container
    from sentinel.main import create_app
    from sentinel.observability.logging import configure_logging

    settings = load_settings()
    configure_logging(settings.log_level, "sentinel-api")
    app = create_app(Container.build(settings))
    uvicorn.run(
        app,
        host="0.0.0.0",  # nosec B104 # noqa: S104 (container network)
        port=settings.port,
        log_config=None,
        access_log=False,
        server_header=False,
        proxy_headers=False,
    )
    return 0


def _cmd_worker(_: argparse.Namespace) -> int:
    import signal

    import structlog
    from prometheus_client import start_http_server

    from sentinel.config import load_settings
    from sentinel.container import Container
    from sentinel.evidence.clients import LokiClient, PrometheusClient
    from sentinel.evidence.collector import EvidenceCollector
    from sentinel.evidence.service import JOB_KIND, EvidenceService
    from sentinel.investigation.providers import (
        InvestigationProvider,
        MockProvider,
        OllamaProvider,
    )
    from sentinel.investigation.service import JOB_KIND as INVESTIGATION_JOB
    from sentinel.investigation.service import InvestigationService
    from sentinel.jobs.worker import Worker
    from sentinel.observability.logging import configure_logging

    settings = load_settings()
    configure_logging(settings.log_level, "sentinel-worker")
    log = structlog.get_logger("sentinel.worker")
    container = Container.build(settings)
    start_http_server(settings.worker_metrics_port, registry=container.metrics.registry)

    async def run() -> None:
        prometheus = PrometheusClient(settings.prometheus_internal_url)
        loki = LokiClient(settings.loki_internal_url, timeout_s=settings.loki_timeout_s)
        evidence = EvidenceService(
            container.sessions,
            container.clock,
            container.incidents,
            EvidenceCollector(prometheus, loki),
            container.metrics,
            jobs=container.jobs,
            auto_investigate_with=settings.investigation_provider
            if settings.auto_investigate
            else None,
        )
        providers: dict[str, InvestigationProvider] = {"mock": MockProvider()}
        ollama: OllamaProvider | None = None
        if settings.ollama_enabled:
            ollama = OllamaProvider(
                settings.ollama_url,
                settings.ollama_model,
                timeout_s=settings.ollama_timeout_s,
                num_ctx=settings.ollama_num_ctx,
            )
            providers["ollama"] = ollama
        investigations = InvestigationService(
            container.sessions,
            container.clock,
            container.incidents,
            container.audit,
            container.catalog,
            providers,
            container.metrics,
            timeout_s=settings.investigation_timeout_s,
        )
        worker = Worker(
            container.sessions,
            container.jobs,
            {JOB_KIND: evidence.handle_job, INVESTIGATION_JOB: investigations.handle_job},
            job_timeout_s=settings.investigation_timeout_s + 60,
        )
        log.info(
            "investigation providers",
            providers=sorted(providers),
            default=settings.investigation_provider,
            auto=settings.auto_investigate,
        )
        stop = asyncio.Event()
        loop = asyncio.get_running_loop()
        for sig in (signal.SIGTERM, signal.SIGINT):
            loop.add_signal_handler(sig, stop.set)

        async def refresh_gauges() -> None:
            while not stop.is_set():
                try:
                    async with container.sessions() as session:
                        counts = await container.jobs.counts(session)
                    for status in ("pending", "running", "done", "failed"):
                        container.metrics.jobs.labels(status).set(counts.get(status, 0))
                except Exception:
                    log.warning("job gauge refresh failed", exc_info=True)
                with contextlib.suppress(TimeoutError):
                    await asyncio.wait_for(stop.wait(), 15)

        try:
            await asyncio.gather(worker.run_forever(stop), refresh_gauges())
        finally:
            await prometheus.aclose()
            await loki.aclose()
            if ollama is not None:
                await ollama.aclose()
            await container.engine.dispose()
            log.info("worker stopped")

    asyncio.run(run())
    return 0


def _cmd_db_init(_: argparse.Namespace) -> int:
    """Superuser credentials are used only here, only for role bootstrap."""
    import structlog

    from sentinel.config import load_settings, read_secret
    from sentinel.observability.logging import configure_logging
    from sentinel.persistence.db import MIGRATOR_ROLE, bootstrap_roles, upgrade

    settings = load_settings()
    configure_logging(settings.log_level, "sentinel-migrate")
    log = structlog.get_logger("sentinel.db")
    names = ("postgres_password", "sentinel_migrator_db_password", "sentinel_app_db_password")
    found = {n: read_secret(n) for n in names}
    if missing := [n for n, v in found.items() if v is None]:
        log.error("missing secrets", missing=missing)
        return 2
    secret = {n: v.get_secret_value() for n, v in found.items() if v is not None}

    def url(user: str, password: str) -> str:
        return URL.create(
            "postgresql+psycopg",
            username=user,
            password=password,
            host=settings.db_host,
            port=settings.db_port,
            database=settings.db_name,
        ).render_as_string(hide_password=False)

    admin_user = os.environ.get("SENTINEL_DB_ADMIN_USER", "sentinel_admin")
    engine = create_engine(
        url(admin_user, secret["postgres_password"]), isolation_level="AUTOCOMMIT"
    )
    with engine.connect() as conn:
        bootstrap_roles(
            conn,
            settings.db_name,
            secret["sentinel_migrator_db_password"],
            secret["sentinel_app_db_password"],
        )
    engine.dispose()
    log.info("roles ready", roles=[MIGRATOR_ROLE, settings.db_user])
    upgrade(url(MIGRATOR_ROLE, secret["sentinel_migrator_db_password"]))
    log.info("migrations applied")
    return 0


def _cmd_token_create(args: argparse.Namespace) -> int:
    from sentinel.config import load_settings
    from sentinel.container import Container
    from sentinel.domain.enums import Role
    from sentinel.security import generate_token, upsert_principal

    container = Container.build(load_settings())
    token = generate_token()

    async def run() -> None:
        async with container.sessions.begin() as session:
            await upsert_principal(session, container.clock, args.name, Role(args.role), token)
            await container.audit.append(
                session,
                actor="cli",
                action="principal.created",
                subject_type="principal",
                subject_id=args.name,
                data={"role": args.role},
            )
        await container.engine.dispose()

    asyncio.run(run())
    print(token)  # shown once; only its SHA-256 is stored
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="sentinel")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("api", help="run the HTTP API").set_defaults(fn=_cmd_api)
    sub.add_parser("worker", help="run the background job worker").set_defaults(fn=_cmd_worker)
    db = sub.add_parser("db").add_subparsers(dest="db_command", required=True)
    db.add_parser("init", help="create roles and run migrations").set_defaults(fn=_cmd_db_init)
    tok = sub.add_parser("token").add_subparsers(dest="token_command", required=True)
    create = tok.add_parser("create", help="create or rotate an API principal")
    create.add_argument("name")
    create.add_argument("role", choices=["viewer", "responder", "approver", "admin"])
    create.set_defaults(fn=_cmd_token_create)
    args = parser.parse_args(argv)
    result: int = args.fn(args)
    return result


if __name__ == "__main__":
    sys.exit(main())
