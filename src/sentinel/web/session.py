"""Stateless, signed UI sessions and CSRF tokens (threat model T5, T14).

No server-side session store: the cookie itself carries `name|role|issued_at`,
authenticated with HMAC-SHA256 under the UI secret, so a session needs nothing in
the database and can't be forged without the secret.

The CSRF token is a second, independent HMAC keyed off the session cookie's own
value. It is rendered into every page that has a mutating form as a hidden
`csrf_token` input (the Synchronizer Token Pattern) and checked against the form
body on every POST — a cross-site form post carries the victim's session cookie
automatically but has no way to read the page it's forging, so it can't produce a
matching token. This needs no client-side JavaScript, which keeps the CSP free of
`script-src` exceptions (see `sentinel.web.csp`).
"""

from __future__ import annotations

import hashlib
import hmac
import time
from dataclasses import dataclass

from sentinel.domain.enums import Role

COOKIE_NAME = "sentinel_session"
CSRF_FIELD = "csrf_token"
SESSION_MAX_AGE_S = 12 * 3600


@dataclass(frozen=True)
class WebIdentity:
    name: str
    role: Role

    @property
    def actor(self) -> str:
        return f"user:{self.name}"


def _sig(secret: str, name: str, role: str, issued_at: int) -> str:
    msg = f"{len(name)}:{name}|{role}|{issued_at}".encode()
    return hmac.new(secret.encode(), msg, hashlib.sha256).hexdigest()


def create_session_cookie(secret: str, name: str, role: Role, *, now: float | None = None) -> str:
    issued_at = int(now if now is not None else time.time())
    sig = _sig(secret, name, role.value, issued_at)
    return f"{issued_at}.{role.value}.{sig}.{name}"


def verify_session_cookie(
    secret: str, cookie: str, *, now: float | None = None, max_age: int = SESSION_MAX_AGE_S
) -> WebIdentity | None:
    try:
        issued_at_s, role_s, sig, name = cookie.split(".", 3)
        issued_at = int(issued_at_s)
        role = Role(role_s)
    except (ValueError, IndexError):
        return None
    now = now if now is not None else time.time()
    if now - issued_at > max_age or issued_at > now + 60:  # +60s clock-skew tolerance
        return None
    expected = _sig(secret, name, role.value, issued_at)
    if not hmac.compare_digest(expected, sig):
        return None
    return WebIdentity(name, role)


def csrf_token_for(secret: str, session_cookie: str) -> str:
    return hmac.new(secret.encode(), session_cookie.encode(), hashlib.sha256).hexdigest()


def verify_csrf(secret: str, session_cookie: str, provided: str | None) -> bool:
    if not provided:
        return False
    return hmac.compare_digest(csrf_token_for(secret, session_cookie), provided)
