"""web.open/web.navigate must surface the HTTP status of the navigation.

Playwright's page.goto only raises for transport failures; a 4xx/5xx main
document resolves normally. Without the status a navigation onto an error page
reported the same success as a real hit, so the backend now reports the status
the same way the proxy and network-list surfaces already do.
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

from headless_re_mcp.backends.web.client import WebBackend, _response_status


class _Immediate:
    def call(self, work: Any, timeout: float | None = None) -> Any:
        return work()


class _Response:
    def __init__(self, status: int) -> None:
        self.status = status


class _Page:
    def __init__(self, response: Any) -> None:
        self.url = "https://old/"
        self._response = response

    def goto(self, url: str, timeout: float = 0, wait_until: str = "") -> Any:
        del timeout, wait_until
        self.url = url
        return self._response

    def title(self) -> str:
        return "Example"


def _backend_with(monkeypatch: Any, response: Any) -> WebBackend:
    backend = WebBackend()
    page = _Page(response)
    monkeypatch.setattr(backend, "_get", lambda session_id: SimpleNamespace(page=page))
    monkeypatch.setattr(backend, "_runner", lambda handle: _Immediate())
    return backend


def test_navigate_reports_error_status_instead_of_bare_success(monkeypatch: Any) -> None:
    backend = _backend_with(monkeypatch, _Response(404))
    payload = backend.navigate("s", "https://example/missing")
    assert payload["status"] == 404
    assert payload["url"] == "https://example/missing"
    assert payload["title"] == "Example"


def test_navigate_omits_status_when_there_is_no_response(monkeypatch: Any) -> None:
    # about:blank and same-document navigations resolve with no response;
    # an absent status is honest there, a fabricated 200 would not be.
    backend = _backend_with(monkeypatch, None)
    payload = backend.navigate("s", "about:blank")
    assert "status" not in payload


def test_response_status_survives_a_detached_or_non_int_response() -> None:
    class _Broken:
        @property
        def status(self) -> int:
            raise RuntimeError("response detached")

    assert _response_status(_Broken()) is None
    assert _response_status(None) is None
    assert _response_status(SimpleNamespace(status="200")) is None
    assert _response_status(_Response(500)) == 500
