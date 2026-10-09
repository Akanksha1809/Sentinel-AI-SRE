"""Runtime configuration.

`pool_size` is validated strictly on purpose: an invalid config revision makes the
process fail fast at startup. That is how demo scenario C produces a crash loop.
"""

from __future__ import annotations

from typing import Literal

from pydantic import Field, SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict

ReleaseDefect = Literal["none", "checkout_null_price"]


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="", frozen=True, extra="ignore")

    service_name: str = Field(default="shop-api", pattern=r"^[a-z0-9-]{1,40}$")
    app_version: str = Field(default="1.0.0", pattern=r"^[0-9A-Za-z.+-]{1,40}$")
    config_revision: str = Field(default="r1", pattern=r"^[a-z0-9-]{1,20}$")
    replica: str = Field(default="1", pattern=r"^[0-9]{1,3}$")

    # Simulated connection pool size: the knob that a bad config revision breaks.
    pool_size: int = Field(default=10, ge=1, le=64)

    # Baked into the image at build time (see Dockerfile build arg RELEASE_DEFECT).
    release_defect: ReleaseDefect = "none"

    # Chaos endpoints are disabled unless a token is configured.
    chaos_token: SecretStr | None = None
    chaos_max_memory_mb: int = Field(default=220, ge=16, le=1024)
    chaos_max_duration_s: int = Field(default=900, ge=1, le=3600)

    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR"] = "INFO"
    port: int = Field(default=8000, ge=1024, le=65535)
