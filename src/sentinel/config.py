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
    prometheus_url: str = "http://localhost:9090"

    # Secrets (loaded by `load_settings`; may be injected directly in tests).
    db_password: SecretStr | None = None
    webhook_token: SecretStr | None = None
    deployer_token: SecretStr | None = None
    bootstrap_admin_token: SecretStr | None = None

    @property
    def reopen_window(self) -> timedelta:
        return timedelta(seconds=self.reopen_window_s)

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
}


def load_settings(secrets_dir: Path = SECRETS_DIR) -> Settings:
    secrets: dict[str, Any] = {}
    for field, filename in SECRET_FILES.items():
        value = read_secret(filename, secrets_dir)
        if value is not None:
            secrets[field] = value
    return Settings(**secrets)
