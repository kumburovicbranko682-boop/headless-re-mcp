"""web.open / web.navigate refuse anything but http(s) before touching a browser.

Driving a real Chromium at ``file://`` or ``chrome://`` would turn the browser
into a local-file and browser-internals reader whose contents the agent could
then lift out through ``web.dom.snapshot`` or ``web.script.source``. The guard
runs on the agent-supplied string (the transport does no pydantic validation)
and fires before a page is ever loaded.
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest

from headless_re_mcp.backends.web.client import WebBackend, WebError

_REFUSED = [
    "file:///etc/passwd",
    "file://C:/Windows/win.ini",
    "chrome://version",
    "chrome-devtools://devtools/bundled/inspector.html",
    "view-source:https://example.com",
    "filesystem:https://example.com/temporary/x",
    "about:blank",
    "javascript:alert(1)",
    "ftp://example.com/x",
    "/home/user/secret.html",
    "  file:///etc/shadow  ",
]


class _Immediate:
    def call(self, work: Any, timeout: float | None = None) -> Any:
        return work()


class _RecordingPage:
    url = "https://old/"

    def __init__(self) -> None:
        self.goto_calls: list[str] = []

    def goto(self, url: str, timeout: float = 0, wait_until: str = "") -> None:
        self.goto_calls.append(url)
        self.url = url

    def title(self) -> str:
        return "Example"


@pytest.mark.parametrize("url", _REFUSED)
def test_navigate_refuses_non_http_schemes(url: str, monkeypatch: Any) -> None:
    """A refused url is invalid_params and page.goto is never reached."""
    backend = WebBackend()
    page = _RecordingPage()
    monkeypatch.setattr(backend, "_get", lambda session_id: SimpleNamespace(page=page))
    monkeypatch.setattr(backend, "_runner", lambda handle: _Immediate())

    with pytest.raises(WebError) as excinfo:
        backend.navigate("s", url)

    assert excinfo.value.code == "invalid_params"
    assert page.goto_calls == []


@pytest.mark.parametrize(
    "url",
    [
        "http://example.com/app",
        "https://example.com/app",
        "  https://example.com  ",
        "HTTP://EXAMPLE",
        "data:text/html,<html><body>x</body></html>",
    ],
)
def test_navigate_allows_http_https_and_data(url: str, monkeypatch: Any) -> None:
    """http, https and inline data: (opaque origin, no disk reach) pass through."""
    backend = WebBackend()
    page = _RecordingPage()
    monkeypatch.setattr(backend, "_get", lambda session_id: SimpleNamespace(page=page))
    monkeypatch.setattr(backend, "_runner", lambda handle: _Immediate())

    backend.navigate("s", url)

    assert page.goto_calls == [url]


@pytest.mark.parametrize("url", _REFUSED)
def test_open_refuses_non_http_schemes_before_launch(url: str, monkeypatch: Any) -> None:
    """open rejects a bad url before reserving a slot or launching a browser.

    The check sits ahead of the session reservation and the playwright import,
    so a refused open leaves no half-created session behind and never spends the
    cost of starting Chromium.
    """
    backend = WebBackend()
    monkeypatch.setattr(backend, "_check_available", lambda: None)

    def _boom(*args: object, **kwargs: object) -> None:  # pragma: no cover - must not run
        raise AssertionError("a browser must not be launched for a refused url")

    monkeypatch.setattr("playwright.sync_api.sync_playwright", _boom, raising=False)

    with pytest.raises(WebError) as excinfo:
        backend.open("s", url)

    assert excinfo.value.code == "invalid_params"
    assert "s" not in backend._sessions


def test_open_with_empty_url_is_not_a_navigation(monkeypatch: Any) -> None:
    """An empty url means "blank browser" and is not held to the allowlist.

    The guard only fires for a real destination; an empty url must clear it and
    reach the launch path (which then fails for its own reason here, not because
    the scheme check refused an empty string as though it were a bad URL).
    """
    backend = WebBackend()
    monkeypatch.setattr(backend, "_check_available", lambda: None)

    marker = RuntimeError("reached launch")

    def _launch(*args: object, **kwargs: object) -> None:
        raise marker

    monkeypatch.setattr("playwright.sync_api.sync_playwright", _launch, raising=False)

    with pytest.raises(Exception) as excinfo:  # noqa: PT011 - any non-invalid_params is fine
        backend.open("s", "")

    assert not (isinstance(excinfo.value, WebError) and excinfo.value.code == "invalid_params")
