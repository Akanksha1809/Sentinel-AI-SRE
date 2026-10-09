"""Actuator settings. Secrets are read from files in /run/secrets (Compose secrets)."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from pydantic import Field, SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="ACTUATOR_", frozen=True, extra="ignore")

    docker_host: str = "tcp://socket-proxy-rw:2375"
    target_network: str = "sentinel-app"
    catalog_path: Path = Path("/etc/actuator/releases.yaml")
    poll_interval_s: float = Field(default=5.0, ge=1.0, le=60.0)
    docker_timeout_s: int = Field(default=20, ge=1, le=120)
    reconcile_on_start: bool = True

    # Bearer token Sentinel uses for remediation actions.
    actuator_token: SecretStr | None = None
    # Separate token for fault injection / demo deploys. Sentinel never holds it.
    fault_token: SecretStr | None = None
    # Injected into shop-api containers so their chaos endpoints are usable.
    chaos_token: SecretStr | None = None

    # Optional: forward deployment events to Sentinel (available from Phase 3).
    sentinel_deployments_url: str | None = None
    deployer_token: SecretStr | None = None

    port: int = Field(default=8080, ge=1024, le=65535)
    log_level: str = "INFO"


SECRET_FIELDS = ("actuator_token", "fault_token", "chaos_token", "deployer_token")


def load_secret_files(directory: Path) -> dict[str, Any]:
    """Read Compose secrets mounted as /run/secrets/<field_name>. Missing files are skipped."""
    found: dict[str, Any] = {}
    for name in SECRET_FIELDS:
        path = directory / name
        if path.is_file():
            value = path.read_text(encoding="utf-8").strip()
            if value:
                found[name] = SecretStr(value)
    return found
