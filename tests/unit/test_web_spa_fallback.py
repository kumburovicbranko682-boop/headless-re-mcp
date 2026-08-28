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


def test_a_non_ascii_query_token_is_a_clean_401_not_a_500() -> None:
    """A token with a non-ASCII byte must deny cleanly, not crash the route.

    Starlette decodes the query as UTF-8, so ``?token=%C3%A9...`` reaches the
    route as a non-ASCII str, and ``secrets.compare_digest`` raised ``TypeError``
    on exactly that -- surfacing as a 500 (TestClient re-raises it) instead of
    the 401 a bad credential means. The shared ``tokens_match`` compares UTF-8
    bytes, so the same input is just an unauthorized miss.
    """
    client = _client()

    denied = client.get("/", params={"token": "\u00e9" + _TOKEN[1:]})
    assert denied.status_code == 401


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
