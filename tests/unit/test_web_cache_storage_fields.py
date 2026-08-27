"""web.storage.cache lists a page origin's Cache Storage cache names.

The fake CDP session stands in for Playwright's cdp.send so the origin
derivation, the securityOrigin->storageKey fallback, bounding, sorting and
pagination are what actually get exercised (no browser).
"""

from __future__ import annotations

import ast
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from headless_re_mcp.backends.web.client import (
    _MAX_CACHE_NAMES,
    WebBackend,
    WebError,
)
from headless_re_mcp.tools.web import build_web_tools


def _tool_docstring(name: str) -> str:
    source = Path(build_web_tools.__code__.co_filename).read_text(encoding="utf-8")
    tree = ast.parse(source)
    for node in ast.walk(tree):
        if not isinstance(node, ast.FunctionDef):
            continue
        for decorator in node.decorator_list:
            if not isinstance(decorator, ast.Call):
                continue
            for keyword in decorator.keywords:
                if (
                    keyword.arg == "name"
                    and isinstance(keyword.value, ast.Constant)
                    and keyword.value.value == name
                ):
                    return ast.get_docstring(node) or ""
    return ""


class _Immediate:
    def call(self, work: Any, timeout: float | None = None) -> Any:
        return work()


class _Cdp:
    def __init__(
        self,
        cache_names: list[str] | None = None,
        *,
        security_error: bool = False,
        request_error: bool = False,
    ) -> None:
        self.cache_names = cache_names or []
        self.security_error = security_error
        self.request_error = request_error
        self.calls: list[tuple[str, Any]] = []

    def send(self, method: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        self.calls.append((method, params))
        if method == "CacheStorage.requestCacheNames":
            if self.request_error:
                raise RuntimeError("cache storage unavailable")
            if self.security_error and params and "securityOrigin" in params:
                raise RuntimeError("securityOrigin deprecated; use storageKey")
            return {
                "caches": [
                    {"cacheId": f"id-{n}", "securityOrigin": "https://app.example", "cacheName": n}
                    for n in self.cache_names
                ]
            }
        return {}

    def methods(self) -> list[str]:
        return [m for m, _ in self.calls]


def _backend(monkeypatch: Any, url: str, cdp: _Cdp) -> WebBackend:
    backend = WebBackend()
    monkeypatch.setattr(
        backend,
        "_get",
        lambda session_id: SimpleNamespace(page=SimpleNamespace(url=url), cdp=cdp),
    )
    monkeypatch.setattr(backend, "_runner", lambda handle: _Immediate())
    return backend


def test_cache_storage_lists_sorted_names(monkeypatch: Any) -> None:
    """Cache names come back sorted for the page origin, names only.

    Measured: origin derived from the page URL, names sorted, and no cacheName,
    entries or responses field leaking from the CDP payload.
    """
    cdp = _Cdp(["runtime", "app-shell", "api-v2"])
    payload = _backend(monkeypatch, "https://app.example/home", cdp).cache_storage("s")
    assert payload["origin"] == "https://app.example"
    assert payload["caches"] == ["api-v2", "app-shell", "runtime"]
    assert payload["count"] == 3
    assert payload["total"] == 3
    assert payload["has_more"] is False
    assert payload["scan_capped"] is False
    assert "cacheName" not in payload
    assert "entries" not in payload
    assert "responses" not in payload


def test_cache_storage_opaque_origin_returns_empty_with_note(monkeypatch: Any) -> None:
    """about:blank owns no Cache Storage: empty list, note, and no CDP call."""
    cdp = _Cdp(["should-not-read"])
    payload = _backend(monkeypatch, "about:blank", cdp).cache_storage("s")
    assert payload["origin"] == ""
    assert payload["caches"] == []
    assert payload["total"] == 0
    assert payload["has_more"] is False
    assert "note" in payload
    assert cdp.calls == []


def test_cache_storage_falls_back_to_storage_key(monkeypatch: Any) -> None:
    """A securityOrigin rejection retries with storageKey and still lists."""
    cdp = _Cdp(["c1"], security_error=True)
    payload = _backend(monkeypatch, "https://app.example/", cdp).cache_storage("s")
    assert payload["caches"] == ["c1"]
    request_calls = [p for m, p in cdp.calls if m == "CacheStorage.requestCacheNames"]
    assert any(p and "securityOrigin" in p for p in request_calls)
    assert any(p and "storageKey" in p for p in request_calls)


def test_cache_storage_caps_and_paginates(monkeypatch: Any) -> None:
    """Past the cap scan_capped is true; a small limit pages honestly."""
    names = [f"c{i:04d}" for i in range(_MAX_CACHE_NAMES + 1)]
    backend = _backend(monkeypatch, "https://app.example/", _Cdp(names))
    payload = backend.cache_storage("s", offset=0, limit=10)
    assert payload["total"] == _MAX_CACHE_NAMES
    assert payload["scan_capped"] is True
    assert payload["count"] == 10
    assert payload["has_more"] is True
    nxt = backend.cache_storage("s", offset=10, limit=10)
    assert nxt["offset"] == 10
    assert nxt["caches"][0] != payload["caches"][0]


def test_cache_storage_request_failure_raises(monkeypatch: Any) -> None:
    """When both CDP variants fail, the call surfaces backend_error."""
    cdp = _Cdp(request_error=True)
    backend = _backend(monkeypatch, "https://app.example/", cdp)
    with pytest.raises(WebError) as excinfo:
        backend.cache_storage("s")
    assert excinfo.value.code == "backend_error"


def test_cache_storage_docstring_names_shape() -> None:
    doc = _tool_docstring("web.storage.cache")
    assert "origin" in doc
    assert "caches" in doc
    assert "scan_capped" in doc
    assert "responses" in doc
