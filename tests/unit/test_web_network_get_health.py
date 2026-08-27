"""web.network_get must tell a wedged session apart from a bodyless request.

The CDP body fetch legitimately fails for some requests -- a redirect with no
body, or an entry CDP already dropped from its cache -- and network_get folds
that into a body_error note so the rest of the request record still comes back.
But the same try used to swallow WebError too, so a session whose browser thread
had wedged or timed out was reported as a 200-shaped body_error ("this one
request had no body") instead of the "browser unresponsive; call web.close"
signal an unattended caller needs to recover. script_source already re-raises
WebError; this pins network_get to the same rule.
"""

from __future__ import annotations

import threading
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from headless_re_mcp.backends.web.client import WebBackend, WebError


class _RaisingRunner:
    """Stands in for a runner whose session is wedged/timed out."""

    def __init__(self, error: BaseException) -> None:
        self._error = error

    def call(self, work: Any, timeout: float | None = None) -> Any:
        del work, timeout
        raise self._error


class _InlineRunner:
    """Runs the work on the calling thread, like a healthy runner would."""

    def call(self, work: Any, timeout: float | None = None) -> Any:
        del timeout
        return work()


def _handle_with_one_request() -> SimpleNamespace:
    entry = {"requestId": "req-1", "url": "https://example.test/x", "status": 200}
    return SimpleNamespace(
        lock=threading.RLock(),
        requests={"req-1": entry},
        cdp=SimpleNamespace(),
    )


def test_a_wedged_session_surfaces_as_an_error_not_a_body_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    backend = WebBackend()
    handle = _handle_with_one_request()
    monkeypatch.setattr(backend, "_get", lambda session_id: handle)
    monkeypatch.setattr(
        backend,
        "_runner",
        lambda h: _RaisingRunner(
            WebError("timeout", "browser did not respond within 60s")
        ),
    )

    with pytest.raises(WebError) as caught:
        backend.network_get("s", "req-1", tmp_path)
    assert caught.value.code == "timeout"


def test_a_missing_body_for_one_request_still_degrades_to_body_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    backend = WebBackend()

    class _Cdp:
        def send(self, method: str, params: dict[str, Any]) -> dict[str, Any]:
            del params
            assert method == "Network.getResponseBody"
            # What CDP raises for an entry it no longer has a body for; it is a
            # plain protocol error, not a WebError, so this one request degrades.
            raise ValueError("No resource with given identifier found")

    handle = _handle_with_one_request()
    handle.cdp = _Cdp()
    monkeypatch.setattr(backend, "_get", lambda session_id: handle)
    monkeypatch.setattr(backend, "_runner", lambda h: _InlineRunner())

    result = backend.network_get("s", "req-1", tmp_path)
    assert "body_error" in result
    assert "No resource" in result["body_error"]
    # The rest of the request record still comes back alongside the note.
    assert result["url"] == "https://example.test/x"
    assert result["status"] == 200
