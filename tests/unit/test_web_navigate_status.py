"""web.navigate must disclose the HTTP status of the document it loaded.

page.goto only raises on a transport failure; an HTTP 404 or 500 resolves and
loads the server's error page. Reported as url + title under a successful
envelope, that reads as "the requested page loaded", so a crawl records the
error body as real content. navigate now surfaces the main-document status and
notes a 4xx/5xx.
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

from headless_re_mcp.backends.web.client import WebBackend


class _Immediate:
    def call(self, work: Any, timeout: float | None = None) -> Any:
        return work()


class _Page:
    def __init__(self, response: Any) -> None:
        self.url = "https://old/"
        self._response = response

    def goto(self, url: str, timeout: float = 0, wait_until: str = "") -> Any:
        self.url = url
        return self._response

    def title(self) -> str:
        return "Example"


def _navigate(monkeypatch: Any, response: Any) -> dict[str, Any]:
    backend = WebBackend()
    monkeypatch.setattr(
        backend, "_get", lambda session_id: SimpleNamespace(page=_Page(response))
    )
    monkeypatch.setattr(backend, "_runner", lambda handle: _Immediate())
    return backend.navigate("s", "https://example/app")


def test_navigate_flags_an_http_error_status(monkeypatch: Any) -> None:
    payload = _navigate(monkeypatch, SimpleNamespace(status=404))
    assert payload["status"] == 404
    assert "note" in payload
    assert "404" in payload["note"]
    assert payload["url"] == "https://example/app"


def test_navigate_reports_a_healthy_status_without_a_note(monkeypatch: Any) -> None:
    payload = _navigate(monkeypatch, SimpleNamespace(status=200))
    assert payload["status"] == 200
    assert "note" not in payload


def test_navigate_omits_status_when_the_response_is_absent(monkeypatch: Any) -> None:
    payload = _navigate(monkeypatch, None)
    assert "status" not in payload
    assert "note" not in payload
    assert payload["title"] == "Example"
