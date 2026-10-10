"""Sentinel configuration.

Non-secret settings come from `SENTINEL_*` environment variables. Secrets come from
files: Compose secrets mounted at `/run/secrets/<name>`, or paths given via
`SENTINEL_<NAME>_FILE`. Secret values are held as `SecretStr` and are never logged.
"""

from __future__ import annotations

import os
from datetime import timedelta
from pathlib import Path
from typing import Any, Literal

from pydantic import Field, SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict

SECRETS_DIR = Path("/run/secrets")


def read_secret(name: str, secrets_dir: Path = SECRETS_DIR) -> SecretStr | None:
    """Resolve a secret: `SENTINEL_<NAME>_FILE` path first, then `<secrets_dir>/<name>`."""
    override = os.environ.get(f"SENTINEL_{name.upper()}_FILE")
    path = Path(override) if override else secrets_dir / name
    if path.is_file():
        value = path.read_text(encoding="utf-8").strip()
        return SecretStr(value) if value else None
    return None


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="SENTINEL_", frozen=True, extra="ignore")

    environment: str = Field(default="local", pattern=r"^[a-z0-9-]{1,32}$")
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR"] = "INFO"
    port: int = Field(default=8080, ge=1024, le=65535)

    # Database (the password is a secret; everything else is plain config).
    db_host: str = "postgres"
    db_port: int = 5432
    db_name: str = "sentinel"
    db_user: str = "sentinel_app"
    db_pool_size: int = Field(default=5, ge=1, le=50)

    # Incident grouping.
    reopen_window_s: int = Field(default=600, ge=0, le=86_400)
    webhook_max_bytes: int = Field(default=256 * 1024, ge=1024, le=4 * 1024 * 1024)

    # Links rendered in API responses / UI.
    grafana_url: str = "http://localhost:3000"
    # Internal endpoints the worker queries (distinct from the user-facing links).
    prometheus_internal_url: str = "http://prometheus:9090"
    loki_internal_url: str = "http://loki:3100"
    loki_timeout_s: float = Field(default=20.0, gt=0, le=60)
    # Short delay before collecting, so the newest log lines have been shipped.
    evidence_delay_s: int = Field(default=10, ge=0, le=300)
    worker_metrics_port: int = Field(default=9101, ge=1024, le=65535)

    # Investigation. The mock provider is the default: no LLM is required to run Sentinel.
    runbooks_dir: Path = Path("/opt/sentinel/runbooks")
    investigation_provider: Literal["mock", "ollama"] = "mock"
    auto_investigate: bool = True
    investigation_timeout_s: float = Field(default=300.0, gt=0, le=900)
    ollama_enabled: bool = False
    ollama_url: str = "http://host.lima.internal:11434"
    ollama_model: str = Field(default="qwen2.5-coder:3b", pattern=r"^[a-zA-Z0-9._:/-]{1,80}$")
    ollama_timeout_s: float = Field(default=240.0, gt=0, le=900)
    ollama_num_ctx: int = Field(default=4096, ge=2048, le=32768)  # prompt is ~2.7k tokens
    prometheus_url: str = "http://localhost:9090"

    # Remediation (Phase 6). `dry_run` is the default execution mode: the actuator is
    # still called (so plans reflect real fleet state) but every call forces dry_run=true.
    # `live` is an explicit opt-in that lets approved actions actually change the fleet.
    actuator_base_url: str = "http://actuator:8080"
    actuator_timeout_s: float = Field(default=30.0, gt=0, le=120)
    execution_mode: Literal["dry_run", "live"] = "dry_run"
    action_expiry_minutes: int = Field(default=30, ge=1, le=1440)
    action_cooldown_s: int = Field(default=120, ge=0, le=3600)
    action_max_per_incident: int = Field(default=20, ge=1, le=200)
    action_execute_max_attempts: int = Field(default=3, ge=1, le=10)
    action_sweep_interval_s: int = Field(default=30, ge=5, le=300)

    # Secrets (loaded by `load_settings`; may be injected directly in tests).
    db_password: SecretStr | None = None
    webhook_token: SecretStr | None = None
    deployer_token: SecretStr | None = None
    bootstrap_admin_token: SecretStr | None = None
    actuator_token: SecretStr | None = None

    @property
    def reopen_window(self) -> timedelta:
        return timedelta(seconds=self.reopen_window_s)

    @property
    def action_expiry(self) -> timedelta:
        return timedelta(minutes=self.action_expiry_minutes)

    @property
    def action_cooldown(self) -> timedelta:
        return timedelta(seconds=self.action_cooldown_s)

    @property
    def dry_run_default(self) -> bool:
        return self.execution_mode == "dry_run"

    def database_url(self) -> str:
        from sqlalchemy.engine import URL

        return URL.create(
            "postgresql+psycopg",
            username=self.db_user,
            password=self.db_password.get_secret_value() if self.db_password else None,
            host=self.db_host,
            port=self.db_port,
            database=self.db_name,
        ).render_as_string(hide_password=False)


# Maps settings fields to secret *file names* (not secret values).
SECRET_FILES = {  # nosec B105
    "db_password": "sentinel_app_db_password",
    "webhook_token": "alertmanager_webhook_token",
    "deployer_token": "deployer_token",
    "bootstrap_admin_token": "sentinel_admin_token",
    "actuator_token": "actuator_token",
}


def load_settings(secrets_dir: Path = SECRETS_DIR) -> Settings:
    secrets: dict[str, Any] = {}
    for field, filename in SECRET_FILES.items():
        value = read_secret(filename, secrets_dir)
        if value is not None:
            secrets[field] = value
    return Settings(**secrets)
