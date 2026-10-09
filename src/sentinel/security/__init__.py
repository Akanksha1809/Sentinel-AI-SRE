"""API authentication: bearer tokens, stored only as SHA-256 hashes, plus hierarchical roles."""

from __future__ import annotations

import hashlib
import hmac
import secrets
from dataclasses import dataclass

from pydantic import SecretStr
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from sentinel.domain.enums import Role
from sentinel.ids import Clock
from sentinel.persistence.models import Principal

TOKEN_PREFIX = "snt_"  # nosec B105 # noqa: S105 (a prefix, not a secret)
BOOTSTRAP_ADMIN = "bootstrap-admin"


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def generate_token() -> str:
    return TOKEN_PREFIX + secrets.token_urlsafe(32)


def constant_time_equals(provided: str | None, expected: SecretStr | None) -> bool:
    if provided is None or expected is None:
        return False
    return hmac.compare_digest(provided.encode(), expected.get_secret_value().encode())


@dataclass(frozen=True)
class Identity:
    name: str
    role: Role

    @property
    def actor(self) -> str:
        return f"user:{self.name}"


async def authenticate(session: AsyncSession, token: str) -> Identity | None:
    # Lookup by hash: the plaintext token is never stored or compared directly.
    principal = (
        await session.execute(
            select(Principal).where(
                Principal.token_sha256 == hash_token(token), Principal.active.is_(True)
            )
        )
    ).scalar_one_or_none()
    return Identity(principal.name, Role(principal.role)) if principal else None


async def upsert_principal(
    session: AsyncSession, clock: Clock, name: str, role: Role, token: str
) -> Principal:
    principal = (
        await session.execute(select(Principal).where(Principal.name == name))
    ).scalar_one_or_none()
    if principal is None:
        principal = Principal(
            name=name, role=role.value, token_sha256=hash_token(token), created_at=clock.now()
        )
        session.add(principal)
    else:
        principal.role, principal.token_sha256, principal.active = (
            role.value,
            hash_token(token),
            True,
        )
    await session.flush()
    return principal
