"""web.network_get must not flatten a session failure into a per-request body_error.

Fetching a body runs a CDP call on the session's browser thread. That thread
raises the raw driver error when a body is genuinely unavailable (a redirect, a
cache-evicted body), and network_get keeps returning that as body_error so the
documented shape holds. But the runner itself raises WebError when the session
is closed, wedged, or timed out -- a session-level failure. The broad except
used to swallow that too, so a dead browser read as a healthy session with one
unavailable body and an unattended caller moved on none the wiser. These pin
that a WebError propagates while a raw driver error still becomes body_error.
"""

from __future__ import annotations

from pathlib import Path
from threading import Lock
from typing import Any

import pytest

from headless_re_mcp.backends.web.client import WebBackend, WebError


class _FakeHandle:
    def __init__(self) -> None:
        self.lock = Lock()
        self.requests = {
            "req-1": {"requestId": "req-1", "url": "https://example.com/x", "status": 200}
        }


class _RaisingRunner:
    def __init__(self, exc: BaseException) -> None:
        self._exc = exc

    def call(self, work: Any, *, timeout: float = 60.0) -> Any:
        raise self._exc


def _backend(monkeypatch: pytest.MonkeyPatch, exc: BaseException) -> WebBackend:
    backend = WebBackend()
    handle = _FakeHandle()
    monkeypatch.setattr(backend, "_get", lambda session_id: handle)
    monkeypatch.setattr(backend, "_runner", lambda h: _RaisingRunner(exc))
    return backend


def test_network_get_propagates_a_timed_out_session_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    backend = _backend(monkeypatch, WebError("timeout", "browser did not respond"))
    with pytest.raises(WebError) as info:
        backend.network_get("s", "req-1", tmp_path)
    assert info.value.code == "timeout"


def test_network_get_propagates_a_wedged_session_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    backend = _backend(monkeypatch, WebError("backend_error", "browser is unresponsive"))
    with pytest.raises(WebError) as info:
        backend.network_get("s", "req-1", tmp_path)
    assert info.value.code == "backend_error"


def test_network_get_still_reports_an_unavailable_body_as_body_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # A genuinely unavailable body surfaces as the raw driver error the CDP work
    # raised, not a WebError, so it must still become a per-request body_error.
    backend = _backend(monkeypatch, RuntimeError("No resource with given identifier found"))
    payload = backend.network_get("s", "req-1", tmp_path)
    assert payload["body"] == ""
    assert payload["base64_encoded"] is False
    assert payload["body_truncated"] is False
    assert "No resource with given identifier" in payload["body_error"]
