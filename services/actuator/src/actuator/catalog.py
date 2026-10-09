"""Release catalogue: the allowlist of what may run.

The catalogue is the only source of image references and container environment.
API callers can only *select* a version or config revision by name, never supply
an image, command, mount or environment variable.
"""

from __future__ import annotations

import re
from pathlib import Path

import yaml
from pydantic import BaseModel, ConfigDict, Field, model_validator

NAME = r"^[a-z0-9][a-z0-9-]{0,39}$"
VERSION = r"^[0-9]+\.[0-9]+\.[0-9]+(-[0-9a-z.]+)?$"
REVISION = r"^r[0-9]{1,4}$"

# Environment keys a config revision may set. Anything else is rejected at load time.
ALLOWED_CONFIG_KEYS = frozenset({"POOL_SIZE", "LOG_LEVEL"})


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class Release(_Strict):
    image_tag: str = Field(pattern=r"^[0-9A-Za-z._-]{1,64}$")
    notes: str = ""


class Resources(_Strict):
    memory_mb: int = Field(ge=32, le=1024)
    cpus: float = Field(gt=0, le=2)
    pids: int = Field(ge=16, le=1024)


class InitialState(_Strict):
    version: str
    config_revision: str
    replicas: int = Field(ge=1)


class ServiceSpec(_Strict):
    image_repository: str = Field(pattern=r"^[a-z0-9][a-z0-9/_.-]{0,127}$")
    port: int = Field(ge=1024, le=65535)
    min_replicas: int = Field(ge=1)
    max_replicas: int = Field(ge=1, le=5)
    resources: Resources
    initial: InitialState
    releases: dict[str, Release]
    config_revisions: dict[str, dict[str, str]]

    @model_validator(mode="after")
    def _consistent(self) -> ServiceSpec:
        for v in self.releases:
            if not re.fullmatch(VERSION, v):
                raise ValueError(f"invalid version name {v!r}")
        for rev, env in self.config_revisions.items():
            if not re.fullmatch(REVISION, rev):
                raise ValueError(f"invalid config revision name {rev!r}")
            bad = set(env) - ALLOWED_CONFIG_KEYS
            if bad:
                raise ValueError(f"config revision {rev} sets disallowed keys {sorted(bad)}")
        if self.min_replicas > self.max_replicas:
            raise ValueError("min_replicas > max_replicas")
        if self.initial.version not in self.releases:
            raise ValueError("initial.version not in releases")
        if self.initial.config_revision not in self.config_revisions:
            raise ValueError("initial.config_revision not in config_revisions")
        if not self.min_replicas <= self.initial.replicas <= self.max_replicas:
            raise ValueError("initial.replicas out of bounds")
        return self

    def image_for(self, version: str) -> str:
        return f"{self.image_repository}:{self.releases[version].image_tag}"


class ReleaseCatalog(_Strict):
    services: dict[str, ServiceSpec]

    @model_validator(mode="after")
    def _names(self) -> ReleaseCatalog:
        for name in self.services:
            if not re.fullmatch(NAME, name):
                raise ValueError(f"invalid service name {name!r}")
        return self

    @classmethod
    def load(cls, path: Path) -> ReleaseCatalog:
        with path.open(encoding="utf-8") as fh:
            return cls.model_validate(yaml.safe_load(fh))

    def service(self, name: str) -> ServiceSpec:
        try:
            return self.services[name]
        except KeyError:
            raise UnknownTargetError(f"service {name!r} is not managed") from None


class UnknownTargetError(LookupError):
    """Service, version or config revision not in the catalogue."""
