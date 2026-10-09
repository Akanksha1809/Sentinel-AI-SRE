"""Entrypoint. Fails fast (exit 1) on invalid config; this drives the crash-loop scenario."""

from __future__ import annotations

import logging
import os
import sys

import uvicorn
from pydantic import ValidationError

from shop_api.app import create_app
from shop_api.config import Settings
from shop_api.logs import configure_logging


def main() -> int:
    try:
        settings = Settings()
    except ValidationError as exc:
        configure_logging(
            "INFO",
            {
                "service": os.environ.get("SERVICE_NAME", "shop-api"),
                "version": os.environ.get("APP_VERSION", "unknown"),
                "config_revision": os.environ.get("CONFIG_REVISION", "unknown"),
            },
        )
        problems = "; ".join(
            f"{'.'.join(str(p) for p in err['loc']).upper()}: {err['msg']}" for err in exc.errors()
        )
        logging.getLogger("shop_api").critical(
            "config validation failed: %s", problems, extra={"event": "startup_failed"}
        )
        return 1

    configure_logging(
        settings.log_level,
        {
            "service": settings.service_name,
            "version": settings.app_version,
            "config_revision": settings.config_revision,
            "replica": settings.replica,
        },
    )
    uvicorn.run(
        create_app(settings),
        host="0.0.0.0",  # nosec B104 # noqa: S104 (binds inside the container network only)
        port=settings.port,
        log_config=None,
        access_log=False,
        server_header=False,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
