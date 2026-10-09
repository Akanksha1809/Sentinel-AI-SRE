"""Entrypoint: LOADGEN_TARGET, LOADGEN_RPS, LOADGEN_SEED, LOADGEN_METRICS_PORT."""

from __future__ import annotations

import asyncio
import logging
import os
import sys

import httpx
from prometheus_client import CollectorRegistry, start_http_server

from loadgen.core import LoadGenerator, LoadMetrics


async def _main() -> None:
    target = os.environ.get("LOADGEN_TARGET", "http://shop-api:8000")
    rps = float(os.environ.get("LOADGEN_RPS", "10"))
    seed = int(os.environ.get("LOADGEN_SEED", "1337"))
    port = int(os.environ.get("LOADGEN_METRICS_PORT", "9100"))

    registry = CollectorRegistry()
    start_http_server(port, registry=registry)
    # No keep-alive: every request resolves the `shop-api` alias again, so Docker's
    # DNS round-robin spreads load across replicas.
    limits = httpx.Limits(max_keepalive_connections=0, max_connections=100)
    async with httpx.AsyncClient(base_url=target, timeout=5.0, limits=limits) as client:
        logging.getLogger("loadgen").info("starting: target=%s rps=%s seed=%s", target, rps, seed)
        await LoadGenerator(client, LoadMetrics(registry), rps=rps, seed=seed).run()


def main() -> int:
    logging.basicConfig(level="INFO", format='{"level":"%(levelname)s","msg":"%(message)s"}')
    asyncio.run(_main())
    return 0


if __name__ == "__main__":
    sys.exit(main())
