"""Page summaries flag a clipped url/title, like the network capture does.

open / navigate / status / dom.snapshot all bound the page url to 16 KiB and the
title to the metadata cap, exactly as the network capture bounds request urls.
The capture marks such a clip with metadata_truncated; these summaries used to
drop the flag, so a page reached via a long data:/blob: url or a fragment-encoded
SPA state came back with a silently clipped url that read as the whole address.
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

from headless_re_mcp.backends.web.client import (
    _MAX_METADATA_BYTES,
    _MAX_URL_BYTES,
    WebBackend,
    _WebSession,
)

_LONG_URL = "https://example/#" + "a" * (_MAX_URL_BYTES + 64)
_LONG_TITLE = "t" * (_MAX_METADATA_BYTES + 64)


class _Immediate:
    def call(self, work: Any, timeout: float | None = None) -> Any:
        return work()


class _NavPage:
    def __init__(self, title: str = "Example") -> None:
        self.url = "https://old/"
        self._title = title

    def goto(self, url: str, timeout: float = 0, wait_until: str = "") -> None:
        self.url = url

    def title(self) -> str:
        return self._title


class _DomPage:
    def __init__(self, url: str, title: str = "Example") -> None:
        self.url = url
        self._title = title

    def evaluate(self, script: str, cap: int) -> dict[str, Any]:
        del script, cap
        return {"html": "abc", "truncated": False}

    def title(self) -> str:
        return self._title


def _backend(monkeypatch: Any, page: Any) -> WebBackend:
    backend = WebBackend()
    monkeypatch.setattr(backend, "_get", lambda session_id: SimpleNamespace(page=page))
    monkeypatch.setattr(backend, "_runner", lambda handle: _Immediate())
    return backend


def test_navigate_flags_a_clipped_url(monkeypatch: Any) -> None:
    backend = _backend(monkeypatch, _NavPage())
    payload = backend.navigate("s", _LONG_URL)
    assert payload["metadata_truncated"] is True
    assert len(payload["url"].encode("utf-8")) <= _MAX_URL_BYTES


def test_navigate_flags_a_clipped_title(monkeypatch: Any) -> None:
    backend = _backend(monkeypatch, _NavPage(title=_LONG_TITLE))
    payload = backend.navigate("s", "https://example/app")
    assert payload["metadata_truncated"] is True


def test_navigate_does_not_flag_a_short_url_and_title(monkeypatch: Any) -> None:
    backend = _backend(monkeypatch, _NavPage())
    payload = backend.navigate("s", "https://example/app")
    assert "metadata_truncated" not in payload
    assert payload["url"] == "https://example/app"


def test_dom_snapshot_flags_a_clipped_url_separately_from_html(monkeypatch: Any) -> None:
    backend = _backend(monkeypatch, _DomPage(_LONG_URL))
    payload = backend.dom_snapshot("s")
    # The html itself was not cut; only the url was, and the two flags are
    # distinct so neither masks the other.
    assert payload["truncated"] is False
    assert payload["metadata_truncated"] is True


def test_dom_snapshot_does_not_flag_a_short_url(monkeypatch: Any) -> None:
    backend = _backend(monkeypatch, _DomPage("https://example/app"))
    payload = backend.dom_snapshot("s")
    assert "metadata_truncated" not in payload


def test_status_flags_a_clipped_url(monkeypatch: Any) -> None:
    # status reads self._sessions and requires a real _WebSession, so build one
    # around the fake page rather than monkeypatching _get.
    backend = WebBackend()
    session = _WebSession(None, None, None, _DomPage(_LONG_URL), None)
    backend._sessions["s"] = session
    monkeypatch.setattr(backend, "_runner", lambda handle: _Immediate())
    payload = backend.status("s")
    assert payload["open"] is True
    assert payload["metadata_truncated"] is True
