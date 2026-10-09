"""Actuator entrypoint."""

from __future__ import annotations

import json
import logging
import sys
from datetime import UTC, datetime
from pathlib import Path

import uvicorn

from actuator.app import create_app, make_event_sink
from actuator.catalog import ReleaseCatalog
from actuator.config import Settings, load_secret_files
from actuator.fleet import FleetManager
from actuator.runtime import DockerRuntime

_RESERVED = set(logging.makeLogRecord({}).__dict__) | {"message", "asctime"}


class _Json(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        out = {
            "ts": datetime.fromtimestamp(record.created, UTC).isoformat(timespec="milliseconds"),
            "level": record.levelname.lower(),
            "logger": record.name,
            "msg": record.getMessage(),
            "service": "actuator",
        }
        out.update({k: v for k, v in record.__dict__.items() if k not in _RESERVED})
        if record.exc_info:
            out["exception"] = self.formatException(record.exc_info)
        return json.dumps(out, default=str)


def main() -> int:
    settings = Settings(**load_secret_files(Path("/run/secrets")))
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(_Json())
    logging.basicConfig(level=settings.log_level, handlers=[handler], force=True)

    catalog = ReleaseCatalog.load(settings.catalog_path)
    sink = (
        make_event_sink(settings.sentinel_deployments_url, settings.deployer_token)
        if settings.sentinel_deployments_url
        else None
    )
    fleet = FleetManager(
        catalog,
        DockerRuntime(settings.docker_host, settings.docker_timeout_s),
        settings.target_network,
        settings.chaos_token,
        event_sink=sink,
    )
    app = create_app(
        fleet,
        actuator_token=settings.actuator_token,
        fault_token=settings.fault_token,
        chaos_token=settings.chaos_token,
        poll_interval_s=settings.poll_interval_s,
        reconcile_on_start=settings.reconcile_on_start,
    )
    uvicorn.run(
        app,
        host="0.0.0.0",  # nosec B104 # noqa: S104 (binds inside the container network only)
        port=settings.port,
        log_config=None,
        access_log=False,
        server_header=False,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
