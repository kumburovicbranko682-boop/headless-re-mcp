"""Coverage for the SPA fallback's query-token auth and build-missing guard.

``test_web_console.py`` drives the SPA through the full app, where a middleware
turns ``?token=`` into a cookie before the route sees it. Registering the
fallback on a bare app exercises the route's own ``?token=`` branch and its 503
when the built ``index.html`` is absent.
"""

from __future__ import annotations

import pathlib

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from headless_re_mcp.web.routes.spa import register_spa_fallback

_TOKEN = "spa-token-value-0123456789abcdef"


def _client() -> TestClient:
    app = FastAPI()
    register_spa_fallback(app, token=_TOKEN)
    return TestClient(app)


def test_query_token_authorizes_the_spa_fallback() -> None:
    client = _client()

    ok = client.get("/", params={"token": _TOKEN})
    assert ok.status_code == 200
    assert "<" in ok.text  # served the index document

    denied = client.get("/", params={"token": _TOKEN[:-1] + "X"})
    assert denied.status_code == 401


def test_non_ascii_token_is_a_plain_401_not_a_crash() -> None:
    """A non-ASCII ``?token=`` must be rejected, never raise inside the check.

    ``secrets.compare_digest`` raises ``TypeError`` the moment a ``str`` operand
    carries a non-ASCII code point, and the query value decodes to arbitrary
    Unicode. Comparing raw strings turned a crafted probe into a 500 and a logged
    traceback instead of the promised unauthorized answer; ``tokens_match``
    compares UTF-8 bytes so the probe is an ordinary mismatch. TestClient
    re-raises server exceptions by default, so with the old string compare this
    would surface the TypeError rather than a clean 401. (The Bearer branch runs
    the identical ``tokens_match`` call; httpx refuses to send a non-ASCII header
    value, so it cannot be driven end to end from here.)
    """
    client = _client()

    via_query = client.get("/", params={"token": "café-not-the-token"})
    assert via_query.status_code == 401


def test_missing_spa_build_returns_503(monkeypatch: pytest.MonkeyPatch) -> None:
    client = _client()

    original_is_file = pathlib.Path.is_file

    def fake_is_file(self: pathlib.Path) -> bool:
        # Only the SPA index reads as absent; everything else behaves normally.
        if self.name == "index.html":
            return False
        return original_is_file(self)

    monkeypatch.setattr(pathlib.Path, "is_file", fake_is_file)

    response = client.get("/threads/deep-link", headers={"Authorization": f"Bearer {_TOKEN}"})
    assert response.status_code == 503
    assert "WebUI build missing" in response.json()["detail"]
