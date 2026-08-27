"""web.network.get must not mask a dead browser as a per-request body error.

Every read funnels through the session's runner thread; when that thread wedges
(a driver that will never answer) or the session is closed, ``_Runner.call``
raises a ``WebError`` -- ``timeout`` or ``invalid_state``. ``network_get`` used
to fold *every* exception into ``{**entry, "body_error": ...}`` and return an ok
envelope, so a session that can serve nothing looked like a request that simply
had no body, and an unattended agent moved on to the next request instead of
calling ``web.close``. ``script_source`` already re-raises ``WebError`` here;
these pin that ``network_get`` now matches it, while a genuine body-fetch miss
(a redirect/204 with no retained body, an evicted body) stays a soft
``body_error``.
"""

from __future__ import annotations

from pathlib import Path
from threading import Lock
from typing import Any

import pytest

from headless_re_mcp.backends.web.client import WebBackend, WebError


class _RaisingRunner:
    def __init__(self, exc: BaseException) -> None:
        self._exc = exc

    def call(self, work: Any, timeout: float | None = None) -> Any:
        raise self._exc


class _Handle:
    lock = Lock()
    requests = {"r1": {"requestId": "r1", "url": "https://x", "status": 200}}
    cdp = object()


def _backend(monkeypatch: pytest.MonkeyPatch, exc: BaseException) -> WebBackend:
    backend = WebBackend()
    monkeypatch.setattr(backend, "_get", lambda session_id: _Handle())
    monkeypatch.setattr(backend, "_runner", lambda handle: _RaisingRunner(exc))
    return backend


def test_a_wedged_browser_propagates_instead_of_becoming_body_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    backend = _backend(monkeypatch, WebError("timeout", "browser did not respond within 60s"))
    with pytest.raises(WebError) as info:
        backend.network_get("s", "r1", tmp_path)
    assert info.value.code == "timeout"


def test_a_closed_session_propagates_instead_of_becoming_body_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    backend = _backend(monkeypatch, WebError("invalid_state", "web session is closed"))
    with pytest.raises(WebError) as info:
        backend.network_get("s", "r1", tmp_path)
    assert info.value.code == "invalid_state"


def test_a_real_body_fetch_miss_is_still_a_soft_body_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """No retained body (a redirect/204, an evicted body) is expected, not fatal."""
    backend = _backend(monkeypatch, RuntimeError("No resource with given identifier found"))
    payload = backend.network_get("s", "r1", tmp_path)
    assert "body_error" in payload
    assert "No resource" in payload["body_error"]
    # The request summary is preserved so the caller still learns url/status.
    assert payload["url"] == "https://x"
    assert payload["status"] == 200
