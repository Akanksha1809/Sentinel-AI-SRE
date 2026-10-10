"""Stateless signed session cookies and CSRF tokens: pure functions, no I/O."""

from __future__ import annotations

from sentinel.domain.enums import Role
from sentinel.web.session import (
    SESSION_MAX_AGE_S,
    create_session_cookie,
    csrf_token_for,
    verify_csrf,
    verify_session_cookie,
)

SECRET = "test-secret-not-used-anywhere-real"


class TestSessionCookie:
    def test_roundtrip(self) -> None:
        cookie = create_session_cookie(SECRET, "alice", Role.RESPONDER, now=1000.0)
        identity = verify_session_cookie(SECRET, cookie, now=1000.0)
        assert identity is not None
        assert (identity.name, identity.role) == ("alice", Role.RESPONDER)

    def test_name_with_dots_roundtrips(self) -> None:
        cookie = create_session_cookie(SECRET, "alice.smith.jr", Role.VIEWER, now=1000.0)
        identity = verify_session_cookie(SECRET, cookie, now=1000.0)
        assert identity is not None
        assert identity.name == "alice.smith.jr"

    def test_tampered_signature_rejected(self) -> None:
        cookie = create_session_cookie(SECRET, "alice", Role.ADMIN, now=1000.0)
        issued, role, sig, name = cookie.split(".", 3)
        tampered = f"{issued}.{role}.{'f' * len(sig)}.{name}"
        assert verify_session_cookie(SECRET, tampered, now=1000.0) is None

    def test_role_escalation_tamper_rejected(self) -> None:
        """Flipping the role field without the secret must not grant admin."""
        cookie = create_session_cookie(SECRET, "alice", Role.VIEWER, now=1000.0)
        issued, _role, sig, name = cookie.split(".", 3)
        tampered = f"{issued}.admin.{sig}.{name}"
        assert verify_session_cookie(SECRET, tampered, now=1000.0) is None

    def test_wrong_secret_rejected(self) -> None:
        cookie = create_session_cookie(SECRET, "alice", Role.RESPONDER, now=1000.0)
        assert verify_session_cookie("a-different-secret", cookie, now=1000.0) is None

    def test_expired_session_rejected(self) -> None:
        cookie = create_session_cookie(SECRET, "alice", Role.RESPONDER, now=1000.0)
        still_valid = verify_session_cookie(SECRET, cookie, now=1000.0 + SESSION_MAX_AGE_S - 1)
        expired = verify_session_cookie(SECRET, cookie, now=1000.0 + SESSION_MAX_AGE_S + 1)
        assert still_valid is not None
        assert expired is None

    def test_future_issued_at_beyond_skew_rejected(self) -> None:
        cookie = create_session_cookie(SECRET, "alice", Role.RESPONDER, now=10_000.0)
        assert verify_session_cookie(SECRET, cookie, now=1000.0) is None

    def test_malformed_cookie_rejected(self) -> None:
        assert verify_session_cookie(SECRET, "not-a-valid-cookie", now=1000.0) is None
        assert verify_session_cookie(SECRET, "abc.def", now=1000.0) is None
        assert verify_session_cookie(SECRET, "notanumber.viewer.sig.name", now=1000.0) is None
        assert verify_session_cookie(SECRET, "1000.not-a-role.sig.name", now=1000.0) is None


class TestCsrf:
    def test_roundtrip(self) -> None:
        cookie = create_session_cookie(SECRET, "alice", Role.RESPONDER, now=1000.0)
        token = csrf_token_for(SECRET, cookie)
        assert verify_csrf(SECRET, cookie, token) is True

    def test_wrong_token_rejected(self) -> None:
        cookie = create_session_cookie(SECRET, "alice", Role.RESPONDER, now=1000.0)
        assert verify_csrf(SECRET, cookie, "0" * 64) is False

    def test_missing_token_rejected(self) -> None:
        cookie = create_session_cookie(SECRET, "alice", Role.RESPONDER, now=1000.0)
        assert verify_csrf(SECRET, cookie, None) is False
        assert verify_csrf(SECRET, cookie, "") is False

    def test_token_bound_to_its_own_session_only(self) -> None:
        """A token minted for one session must not validate against another."""
        cookie_a = create_session_cookie(SECRET, "alice", Role.RESPONDER, now=1000.0)
        cookie_b = create_session_cookie(SECRET, "bob", Role.RESPONDER, now=1000.0)
        token_a = csrf_token_for(SECRET, cookie_a)
        assert verify_csrf(SECRET, cookie_b, token_a) is False
