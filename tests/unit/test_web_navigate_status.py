"""web.navigate surfaces the HTTP status so an error page is not read as a hit.

Playwright's ``page.goto`` only raises on transport failures; a 4xx/5xx main
document resolves normally, so without reporting the response status a navigation
onto an error page looks identical to a real hit. These tests pin that a status
is reported when the navigation produced a response, that it is omitted (not
faked) when there was none, and cover the ``_response_status`` helper's edges.
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

from headless_re_mcp.backends.web.client import WebBackend, _response_status


class _Immediate:
    def call(self, work: Any, timeout: float | None = None) -> Any:
        return work()


class _Page:
    url = "https://old/"

    def __init__(self, response: Any) -> None:
        self._response = response

    def goto(self, url: str, timeout: float = 0, wait_until: str = "") -> Any:
        self.url = url
        return self._response

    def title(self) -> str:
        return "Example"


def _navigate_with(response: Any, monkeypatch: Any) -> dict[str, Any]:
    backend = WebBackend()
    monkeypatch.setattr(backend, "_get", lambda session_id: SimpleNamespace(page=_Page(response)))
    monkeypatch.setattr(backend, "_runner", lambda handle: _Immediate())
    return backend.navigate("s", "https://example/app")


def test_navigate_reports_an_error_status(monkeypatch: Any) -> None:
    payload = _navigate_with(SimpleNamespace(status=503), monkeypatch)
    assert payload["url"] == "https://example/app"
    assert payload["title"] == "Example"
    assert payload["status"] == 503


def test_navigate_reports_a_success_status(monkeypatch: Any) -> None:
    payload = _navigate_with(SimpleNamespace(status=200), monkeypatch)
    assert payload["status"] == 200


def test_navigate_omits_status_when_there_was_no_response(monkeypatch: Any) -> None:
    # about:blank and same-document navigations return None from goto.
    payload = _navigate_with(None, monkeypatch)
    assert "status" not in payload


def test_response_status_handles_edges() -> None:
    assert _response_status(None) is None
    assert _response_status(SimpleNamespace(status=404)) == 404
    # A non-int status is not trustworthy metadata.
    assert _response_status(SimpleNamespace(status="404")) is None

    class _Raises:
        @property
        def status(self) -> int:
            raise RuntimeError("gone")

    assert _response_status(_Raises()) is None
