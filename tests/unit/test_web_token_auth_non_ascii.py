"""A non-ASCII credential must fail closed as 401, never crash as 500.

``secrets.compare_digest`` raises ``TypeError`` the instant a ``str`` operand
holds a non-ASCII character, so any request whose Bearer header, ``?token=``
value, or bootstrap cookie carried one used to turn the promised clean 401 into
an uncaught 500 with a logged incident. The bootstrap-cookie path is the worst:
its check runs from the cookie-promotion middleware on every request, so one
malformed cookie 500s the whole console rather than a single call.

``web.tokens.tokens_match`` closes that by comparing the UTF-8 encodings, which
keeps the constant-time guarantee while treating a credential that could never
have been minted here as simply wrong. These tests drive every auth entry point
that used the raw ``compare_digest`` through a real app so a regression that
reintroduces the ``str`` comparison fails here instead of in production.

HTTP headers and cookies travel as latin-1 bytes on the wire, so the byte a
hostile client can smuggle into those slots decodes to a code point in
U+0080..U+00FF. The header/cookie cases therefore use a latin-1-representable
credential sent as raw bytes (the test client otherwise refuses to encode it),
which is exactly what the server decodes a malformed request into. The query
path carries percent-encoded UTF-8, so it can (and does) exercise a fuller
Unicode string.
"""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from headless_re_mcp.config import Settings
from headless_re_mcp.core.service import AnalysisService
from headless_re_mcp.web.app import create_app
from headless_re_mcp.web.routes.spa import register_spa_fallback
from headless_re_mcp.web.tokens import tokens_match

TOKEN = "web-token-value-0123456789abcdef"
# latin-1 representable, so it survives header/cookie transport as raw bytes.
NON_ASCII_LATIN1 = "café-münÿ-stål"
# fuller Unicode (mixed scripts) for paths that carry percent-encoded UTF-8.
NON_ASCII_UNICODE = "café-łódź-Ω-😈"


def test_tokens_match_treats_non_ascii_as_a_plain_mismatch() -> None:
    # The whole point: a boolean, never a TypeError, even for code points that
    # secrets.compare_digest would refuse to look at (multi-byte, emoji, etc.).
    assert tokens_match(NON_ASCII_LATIN1, TOKEN) is False
    assert tokens_match(NON_ASCII_UNICODE, TOKEN) is False
    assert tokens_match(TOKEN, NON_ASCII_UNICODE) is False
    assert tokens_match("plain-ascii-wrong", TOKEN) is False
    assert tokens_match(TOKEN, TOKEN) is True


@pytest.fixture
def app_client(tmp_path: Path, monkeypatch: Any) -> tuple[TestClient, FastAPI, AnalysisService]:
    monkeypatch.setenv("HEADLESS_RE_PROVIDER_CONFIG", str(tmp_path / "providers.json"))
    settings = replace(Settings.load(), artifact_root=tmp_path / "artifacts")
    service = AnalysisService(settings)
    app = create_app(service, token=TOKEN, settings=settings)
    return TestClient(app), app, service


def test_legacy_route_rejects_a_non_ascii_bearer_token(app_client: Any) -> None:
    client, _, service = app_client
    try:
        # Send raw latin-1 bytes: that is what a hostile client puts on the wire
        # and what the server decodes back into request.headers.
        raw = ("Bearer " + NON_ASCII_LATIN1).encode("latin-1")
        reply = client.get("/api/meta", headers={"Authorization": raw})
        assert reply.status_code == 401
        assert reply.json()["detail"] == "unauthorized"
    finally:
        service.close_all()


def test_legacy_route_rejects_a_non_ascii_query_token(app_client: Any) -> None:
    client, _, service = app_client
    try:
        reply = client.get("/api/meta", params={"token": NON_ASCII_UNICODE})
        assert reply.status_code == 401
        assert reply.json()["detail"] == "unauthorized"
    finally:
        service.close_all()


def test_bootstrap_cookie_middleware_survives_a_non_ascii_cookie(app_client: Any) -> None:
    """The cookie-promotion middleware runs on every request and iterates the
    registered bootstrap sessions. A populated session set plus a non-ASCII
    cookie is exactly the shape that used to 500 the whole console."""
    client, app, service = app_client
    try:
        # Populate bootstrap_sessions with a real entry so the middleware's
        # `any(... for session_token in sessions)` actually calls the comparison
        # instead of short-circuiting on an empty set.
        primed = client.get("/", params={"token": TOKEN})
        assert primed.status_code == 200
        assert len(app.state.bootstrap_sessions) >= 1

        # Drop the freshly-minted good cookie and send a non-ASCII one as raw
        # bytes on an API route with no Authorization header, so the middleware
        # must compare it against the registered session.
        client.cookies.clear()
        raw_cookie = ("headless_re_bootstrap=" + NON_ASCII_LATIN1).encode("latin-1")
        reply = client.get("/api/meta", headers={"Cookie": raw_cookie})
        assert reply.status_code == 401
        assert reply.json()["detail"] == "unauthorized"
    finally:
        service.close_all()


def test_agent_route_rejects_a_non_ascii_bearer_token(app_client: Any) -> None:
    client, _, service = app_client
    try:
        raw = ("Bearer " + NON_ASCII_LATIN1).encode("latin-1")
        reply = client.get("/api/agent/threads", headers={"Authorization": raw})
        assert reply.status_code == 401
        assert reply.json()["detail"] == "unauthorized"
    finally:
        service.close_all()


def test_spa_fallback_rejects_a_non_ascii_query_token() -> None:
    app = FastAPI()
    register_spa_fallback(app, token=TOKEN)
    client = TestClient(app)
    reply = client.get("/", params={"token": NON_ASCII_UNICODE})
    assert reply.status_code == 401
    assert reply.json()["detail"] == "unauthorized"
