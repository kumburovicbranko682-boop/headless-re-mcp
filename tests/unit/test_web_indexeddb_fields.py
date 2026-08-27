"""web.storage.indexeddb lists a page origin's IndexedDB database names.

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
    _MAX_INDEXEDDB_DBS,
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
        db_names: list[str] | None = None,
        *,
        security_error: bool = False,
        request_error: bool = False,
    ) -> None:
        self.db_names = db_names or []
        self.security_error = security_error
        self.request_error = request_error
        self.calls: list[tuple[str, Any]] = []

    def send(self, method: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        self.calls.append((method, params))
        if method in {"IndexedDB.enable", "IndexedDB.disable"}:
            return {}
        if method == "IndexedDB.requestDatabaseNames":
            if self.request_error:
                raise RuntimeError("indexeddb unavailable")
            if self.security_error and params and "securityOrigin" in params:
                raise RuntimeError("securityOrigin deprecated; use storageKey")
            return {"databaseNames": list(self.db_names)}
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


def test_indexeddb_lists_sorted_names_for_origin(monkeypatch: Any) -> None:
    """Names come back sorted for the page origin; enable/disable bracket it.

    Measured: origin derived from the page URL, database names sorted, no
    databaseNames/stores/records field, and the domain is disabled after the
    request even on success.
    """
    cdp = _Cdp(["cache", "appdb", "_meta"])
    payload = _backend(monkeypatch, "https://app.example/dash?x=1", cdp).indexeddb("s")
    assert payload["origin"] == "https://app.example"
    assert payload["databases"] == ["_meta", "appdb", "cache"]
    assert payload["count"] == 3
    assert payload["total"] == 3
    assert payload["has_more"] is False
    assert payload["scan_capped"] is False
    assert "databaseNames" not in payload
    assert "stores" not in payload
    assert "records" not in payload
    assert "IndexedDB.disable" in cdp.methods()


def test_indexeddb_opaque_origin_returns_empty_with_note(monkeypatch: Any) -> None:
    """about:blank owns no IndexedDB: empty list, note, and no CDP call."""
    cdp = _Cdp(["should-not-read"])
    payload = _backend(monkeypatch, "about:blank", cdp).indexeddb("s")
    assert payload["origin"] == ""
    assert payload["databases"] == []
    assert payload["total"] == 0
    assert payload["has_more"] is False
    assert "note" in payload
    assert cdp.calls == []


def test_indexeddb_falls_back_to_storage_key(monkeypatch: Any) -> None:
    """A securityOrigin rejection retries with storageKey and still lists."""
    cdp = _Cdp(["db1"], security_error=True)
    payload = _backend(monkeypatch, "https://app.example/", cdp).indexeddb("s")
    assert payload["databases"] == ["db1"]
    request_calls = [p for m, p in cdp.calls if m == "IndexedDB.requestDatabaseNames"]
    assert any(p and "securityOrigin" in p for p in request_calls)
    assert any(p and "storageKey" in p for p in request_calls)


def test_indexeddb_caps_and_paginates(monkeypatch: Any) -> None:
    """Past the cap scan_capped is true; a small limit pages honestly."""
    names = [f"db{i:04d}" for i in range(_MAX_INDEXEDDB_DBS + 1)]
    backend = _backend(monkeypatch, "https://app.example/", _Cdp(names))
    payload = backend.indexeddb("s", offset=0, limit=10)
    assert payload["total"] == _MAX_INDEXEDDB_DBS
    assert payload["scan_capped"] is True
    assert payload["count"] == 10
    assert payload["has_more"] is True
    nxt = backend.indexeddb("s", offset=10, limit=10)
    assert nxt["offset"] == 10
    assert nxt["databases"][0] != payload["databases"][0]


def test_indexeddb_request_failure_raises(monkeypatch: Any) -> None:
    """When both CDP variants fail, the call surfaces backend_error."""
    cdp = _Cdp(request_error=True)
    backend = _backend(monkeypatch, "https://app.example/", cdp)
    with pytest.raises(WebError) as excinfo:
        backend.indexeddb("s")
    assert excinfo.value.code == "backend_error"
    assert "IndexedDB.disable" in cdp.methods()


def test_indexeddb_docstring_names_shape() -> None:
    doc = _tool_docstring("web.storage.indexeddb")
    assert "origin" in doc
    assert "databases" in doc
    assert "scan_capped" in doc
    assert "records" in doc
