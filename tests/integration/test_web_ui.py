"""Server-rendered UI: session cookie auth, CSRF, template escaping, RBAC. Real Postgres.

No JS in this UI (see sentinel.web.session), so every mutating action here is a plain
form POST with a hidden `csrf_token` field — these tests drive it exactly the way a
browser would, scraping the token out of the previous page's HTML.
"""

from __future__ import annotations

import re
from collections.abc import AsyncIterator, Callable
from typing import Any

import httpx
import pytest
from conftest import ADMIN_TOKEN, WEBHOOK_TOKEN

from sentinel.domain.enums import Role
from sentinel.main import bootstrap_admin, create_app
from sentinel.security import generate_token, upsert_principal

pytestmark = pytest.mark.integration
Factory = Callable[..., dict[str, Any]]
HOOK = {"Authorization": f"Bearer {WEBHOOK_TOKEN}"}
_CSRF = re.compile(r'name="csrf_token" value="([^"]+)"')


@pytest.fixture
async def client(container: Any) -> AsyncIterator[httpx.AsyncClient]:
    await bootstrap_admin(container)
    transport = httpx.ASGITransport(app=create_app(container, run_bootstrap=False))
    async with httpx.AsyncClient(
        transport=transport, base_url="http://sentinel", follow_redirects=False
    ) as c:
        yield c


def csrf_from(html: str) -> str:
    m = _CSRF.search(html)
    assert m, "no csrf_token field found in page"
    return m.group(1)


async def login(client: httpx.AsyncClient, token: str) -> None:
    r = await client.post("/login", data={"token": token, "next": "/"})
    assert r.status_code == 303, r.text
    assert r.headers["location"] == "/"


async def open_incident(
    client: httpx.AsyncClient, am_alert: Factory, am_payload: Factory, **alert_kwargs: Any
) -> None:
    r = await client.post(
        "/api/v1/webhooks/alertmanager", headers=HOOK, json=am_payload(am_alert(**alert_kwargs))
    )
    assert r.status_code == 202


class TestLogin:
    async def test_login_page_renders(self, client: httpx.AsyncClient) -> None:
        r = await client.get("/login")
        assert r.status_code == 200
        assert "<form" in r.text
        assert 'name="token"' in r.text

    async def test_invalid_token_shows_error_and_sets_no_cookie(
        self, client: httpx.AsyncClient
    ) -> None:
        r = await client.post("/login", data={"token": "snt_not_a_real_token", "next": "/"})
        assert r.status_code == 200
        assert "invalid or inactive token" in r.text
        assert "sentinel_session" not in r.headers.get("set-cookie", "")

    async def test_valid_token_sets_cookie_and_redirects(self, client: httpx.AsyncClient) -> None:
        r = await client.post("/login", data={"token": ADMIN_TOKEN, "next": "/"})
        assert r.status_code == 303
        cookie = r.headers["set-cookie"]
        assert "sentinel_session=" in cookie
        assert "HttpOnly" in cookie
        assert "samesite=strict" in cookie.lower()

    async def test_open_redirect_via_next_is_rejected(self, client: httpx.AsyncClient) -> None:
        r = await client.post(
            "/login", data={"token": ADMIN_TOKEN, "next": "https://evil.example/steal"}
        )
        assert r.status_code == 303
        assert r.headers["location"] == "/"  # never redirects off-site

    async def test_unauthenticated_page_redirects_to_login(self, client: httpx.AsyncClient) -> None:
        r = await client.get("/")
        assert r.status_code == 303
        assert r.headers["location"].startswith("/login")

    async def test_logout_clears_session(self, client: httpx.AsyncClient) -> None:
        await login(client, ADMIN_TOKEN)
        page = await client.get("/")
        r = await client.post("/logout", data={"csrf_token": csrf_from(page.text)})
        assert r.status_code == 303
        assert r.headers["location"] == "/login"
        again = await client.get("/")
        assert again.status_code == 303  # session cookie is gone


class TestIncidentPages:
    async def test_list_renders_after_login(
        self, client: httpx.AsyncClient, am_alert: Factory, am_payload: Factory
    ) -> None:
        await login(client, ADMIN_TOKEN)
        await open_incident(client, am_alert, am_payload)
        r = await client.get("/")
        assert r.status_code == 200
        assert "INC-0001" in r.text

    async def test_xss_payload_in_alert_summary_is_escaped(
        self, client: httpx.AsyncClient, am_alert: Factory, am_payload: Factory
    ) -> None:
        payload = "<script>alert(1)</script>"
        await login(client, ADMIN_TOKEN)
        await open_incident(client, am_alert, am_payload, summary=payload)

        list_page = await client.get("/")
        assert payload not in list_page.text
        assert "&lt;script&gt;" in list_page.text

        detail = await client.get("/incidents/INC-0001")
        assert payload not in detail.text
        assert "&lt;script&gt;alert(1)&lt;/script&gt;" in detail.text

    async def test_detail_page_shows_evidence_and_ai_hypothesis_sections(
        self, client: httpx.AsyncClient, am_alert: Factory, am_payload: Factory
    ) -> None:
        await login(client, ADMIN_TOKEN)
        await open_incident(client, am_alert, am_payload)
        r = await client.get("/incidents/INC-0001")
        assert r.status_code == 200
        assert "Observations (evidence)" in r.text
        assert "AI Hypotheses" in r.text
        assert "Machine-generated, never a fact" in r.text

    async def test_unknown_incident_is_a_styled_404_not_json(
        self, client: httpx.AsyncClient
    ) -> None:
        await login(client, ADMIN_TOKEN)
        r = await client.get("/incidents/INC-9999")
        assert r.status_code == 404
        assert r.headers["content-type"].startswith("text/html")
        assert "<h1>404" in r.text


class TestCsrf:
    async def test_missing_csrf_token_rejected(
        self, client: httpx.AsyncClient, am_alert: Factory, am_payload: Factory
    ) -> None:
        await login(client, ADMIN_TOKEN)
        await open_incident(client, am_alert, am_payload)
        r = await client.post("/incidents/INC-0001/acknowledge", data={})
        assert r.status_code == 403

    async def test_wrong_csrf_token_rejected(
        self, client: httpx.AsyncClient, am_alert: Factory, am_payload: Factory
    ) -> None:
        await login(client, ADMIN_TOKEN)
        await open_incident(client, am_alert, am_payload)
        r = await client.post("/incidents/INC-0001/acknowledge", data={"csrf_token": "0" * 64})
        assert r.status_code == 403

    async def test_valid_csrf_token_is_accepted(
        self, client: httpx.AsyncClient, am_alert: Factory, am_payload: Factory
    ) -> None:
        await login(client, ADMIN_TOKEN)
        await open_incident(client, am_alert, am_payload)
        page = await client.get("/incidents/INC-0001")
        r = await client.post(
            "/incidents/INC-0001/acknowledge", data={"csrf_token": csrf_from(page.text)}
        )
        assert r.status_code == 303

    async def test_csrf_token_from_a_different_session_is_rejected(
        self, client: httpx.AsyncClient, container: Any, am_alert: Factory, am_payload: Factory
    ) -> None:
        """A token scraped from one user's page must not work on another's session."""
        token = generate_token()
        async with container.sessions.begin() as session:
            await upsert_principal(session, container.clock, "responder-1", Role.RESPONDER, token)

        await login(client, ADMIN_TOKEN)
        await open_incident(client, am_alert, am_payload)
        admin_page = await client.get("/incidents/INC-0001")
        stolen_token = csrf_from(admin_page.text)

        await client.post("/logout", data={"csrf_token": stolen_token})
        await login(client, token)
        r = await client.post("/incidents/INC-0001/acknowledge", data={"csrf_token": stolen_token})
        assert r.status_code == 403


class TestRBAC:
    async def test_viewer_does_not_see_mutating_forms(
        self, client: httpx.AsyncClient, container: Any, am_alert: Factory, am_payload: Factory
    ) -> None:
        token = generate_token()
        async with container.sessions.begin() as session:
            await upsert_principal(session, container.clock, "viewer-1", Role.VIEWER, token)

        await login(client, ADMIN_TOKEN)
        await open_incident(client, am_alert, am_payload)

        await login(client, token)  # overwrites the session cookie with the viewer's
        r = await client.get("/incidents/INC-0001")
        assert r.status_code == 200
        assert "Acknowledge" not in r.text
        assert 'action="/incidents/INC-0001/acknowledge"' not in r.text

    async def test_viewer_cannot_post_acknowledge_even_with_valid_csrf(
        self, client: httpx.AsyncClient, container: Any, am_alert: Factory, am_payload: Factory
    ) -> None:
        token = generate_token()
        async with container.sessions.begin() as session:
            await upsert_principal(session, container.clock, "viewer-2", Role.VIEWER, token)

        await login(client, ADMIN_TOKEN)
        await open_incident(client, am_alert, am_payload)

        await login(client, token)
        page = await client.get("/incidents/INC-0001")
        r = await client.post(
            "/incidents/INC-0001/acknowledge", data={"csrf_token": csrf_from(page.text)}
        )
        assert r.status_code == 403

    async def test_non_approver_cannot_view_audit_page(
        self, client: httpx.AsyncClient, container: Any
    ) -> None:
        token = generate_token()
        async with container.sessions.begin() as session:
            await upsert_principal(session, container.clock, "responder-2", Role.RESPONDER, token)
        await login(client, token)
        r = await client.get("/audit")
        assert r.status_code == 403

    async def test_approver_can_view_audit_page(self, client: httpx.AsyncClient) -> None:
        await login(client, ADMIN_TOKEN)
        r = await client.get("/audit")
        assert r.status_code == 200
        assert "Audit log" in r.text


class TestPostmortemPages:
    async def test_full_generate_edit_finalize_via_forms(
        self, client: httpx.AsyncClient, am_alert: Factory, am_payload: Factory
    ) -> None:
        await login(client, ADMIN_TOKEN)
        await open_incident(client, am_alert, am_payload)

        empty = await client.get("/incidents/INC-0001/postmortem")
        assert "No postmortem has been generated yet" in empty.text
        gen_csrf = csrf_from(empty.text)

        generated = await client.post(
            "/incidents/INC-0001/postmortem/generate", data={"csrf_token": gen_csrf}
        )
        assert generated.status_code == 303

        draft_page = await client.get("/incidents/INC-0001/postmortem")
        assert draft_page.status_code == 200
        assert "<textarea" in draft_page.text
        assert "Not yet written" in draft_page.text

        edit_csrf = csrf_from(draft_page.text)
        edited = await client.post(
            "/incidents/INC-0001/postmortem/edit",
            data={"csrf_token": edit_csrf, "markdown": "# Edited\n\nHand-written."},
        )
        assert edited.status_code == 303

        edited_page = await client.get("/incidents/INC-0001/postmortem")
        assert "Hand-written." in edited_page.text

        finalize_csrf = csrf_from(edited_page.text)
        finalized = await client.post(
            "/incidents/INC-0001/postmortem/finalize",
            data={"csrf_token": finalize_csrf, "confirm": "true"},
        )
        assert finalized.status_code == 303

        final_page = await client.get("/incidents/INC-0001/postmortem")
        assert "final" in final_page.text
        assert "<textarea" not in final_page.text  # locked: no more editing UI


class TestRunbooksPage:
    async def test_runbooks_page_renders_catalogue(self, client: httpx.AsyncClient) -> None:
        await login(client, ADMIN_TOKEN)
        r = await client.get("/runbooks")
        assert r.status_code == 200
        assert "Runbook catalogue" in r.text
        assert "rollback-deployment" in r.text


class TestSecurityHeaders:
    async def test_csp_and_friends_present(self, client: httpx.AsyncClient) -> None:
        await login(client, ADMIN_TOKEN)
        r = await client.get("/")
        assert "script-src 'none'" in r.headers["content-security-policy"]
        assert r.headers["x-frame-options"] == "DENY"
        assert r.headers["x-content-type-options"] == "nosniff"
